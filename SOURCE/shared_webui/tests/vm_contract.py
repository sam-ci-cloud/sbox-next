"""Real installed HTTPS -> nonroot panel -> root socket -> manager -> core.

Run as root ONLY in a disposable VM with /root/lab-ready. Never targets a VPS.
Reports contain test names and sanitized outcomes, never client credentials.
"""
import hashlib,http.client,json,os,pathlib,ssl,subprocess,sys,time,traceback
import yaml
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file(),'Disposable VM only'
OUT=pathlib.Path(sys.argv[1]);OUT.mkdir(parents=True,exist_ok=True)
cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text())
base=pathlib.Path('/etc/sbox-manager');cli='/usr/local/bin/sbox';results=[]
cookie='';csrf=''
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=180,check=True).stdout
def pid():return run(['systemctl','show','sing-box','-p','MainPID','--value']).strip()
def state():return json.loads((base/'state.json').read_text())
def fp():return (pid(),hashlib.sha256((base/'config.json').read_bytes()).hexdigest(),hashlib.sha256(pathlib.Path('/usr/local/lib/sbox-manager/sing-box').read_bytes()).hexdigest())
def req(path,data=None,status=200,auth=True,method=None,extra=None):
    h={'Host':cfg['origin'].split('://')[1],**(extra or {})}
    if auth:h.update(Cookie=cookie,**{'X-CSRF-Token':csrf})
    if data is not None:h['Content-Type']='application/json'
    c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=180)
    c.request(method or ('POST' if data is not None else 'GET'),path,json.dumps(data) if data is not None else None,h)
    r=c.getresponse();body=r.read();headers=dict(r.getheaders());code=r.status;c.close()
    assert code==status,f'{path.split("/")[:4]}: expected {status}, received {code}: {body[:200]!r}'
    try:value=json.loads(body)
    except ValueError:value=body.decode()
    return value,headers
def api(path,data=None,**kw):return req('/api/v1/'+path,data,**kw)[0]
def test(name,fn):
    start=time.monotonic()
    try:detail=fn();row={'test':name,'status':'PASS','seconds':round(time.monotonic()-start,3),'detail':detail}
    except Exception as e:row={'test':name,'status':'FAIL','seconds':round(time.monotonic()-start,3),'error':str(e)[:1000]}
    results.append(row);(OUT/'vm-contract.json').write_text(json.dumps(results,indent=2)+'\n');print(row['status'],name,flush=True)
    if row['status']=='FAIL':raise RuntimeError(row['error'])
def login():
    global cookie,csrf
    for user in state().get('managed_users',[]):
        if user['name'] in ('VMContract','VMContractRenamed','BrowserClient'):
            p=subprocess.run([cli,'_webui-control','prepare'],input=json.dumps({'kind':'user-revoke','id':user['id'],'data':{}}),capture_output=True,text=True,check=True)
            subprocess.run([cli,'_webui-control','commit'],input=json.dumps({'token':json.loads(p.stdout)['token']}),capture_output=True,text=True,check=True)
    run([cli,'webui','reset-admin'])
    secret=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
    value,headers=req('/api/v1/auth/login',{'username':'admin','password':secret},auth=False)
    cookie=headers['Set-Cookie'].split(';')[0];csrf=value['csrf']
    assert all(x in headers['Set-Cookie'] for x in ['Secure','HttpOnly','SameSite=Strict'])
    api('users',status=428)
    value=api('auth/change-password',{'old':secret,'password':'Lab-verified-password-2026'});csrf=value['csrf']
    assert not api('auth/me')['reset']
def readonly():
    before=(fp(),(base/'state.json').read_bytes())
    for path in ['system/status','system/capabilities','system/performance','inbounds','users','policy','certificates','security/firewall','security/firewall-status','security/bans','security/status','diagnostics/doctor','traffic','logs','audit','api-docs']:
        result=api(path);assert result is not None
    assert before==(fp(),(base/'state.json').read_bytes())
    assert api('diagnostics/doctor')['failures']==0
def negatives():
    for p in ['users','logs','inbounds','client-profiles','certificates']:api(p,auth=False,status=401)
    req('/api/v1/changes/prepare',{'kind':'policy','data':{}},auth=False,extra={'Cookie':cookie},status=403)
    req('/api/v1/users',auth=True,extra={'Origin':'https://evil.test'},status=403)
    req('/api/v1/users',auth=False,extra={'Host':'127.0.0.1'},status=400)
    api('actions',{'action':'exec','arguments':{}},status=400)
    api('notifications',{'enabled':True,'kind':'webhook','url':'https://169.254.169.254/latest'},status=400)
    api('changes/prepare',{'kind':'user-create','data':{'name':'<script>alert(1)</script>'}},status=422)
    api('changes/prepare',{'kind':'user-disable','id':'legacy','data':{}},status=422)
def change(kind,data,ident=None):
    body={'kind':kind,'data':data}
    if ident:body['id']=ident
    p=api('changes/prepare',body);assert p['token'] and p['diff'] is not None
    result=api('changes/commit',{'token':p['token']});assert result['committed'];return p
def policy():
    before=fp();old=api('policy').get('primary','tuic');target='hy2' if old!='hy2' else 'tuic'
    p=change('policy',{'primary':target});assert not p['restart'];assert fp()==before
    assert state()['client_policy']['primary']==target
    change('policy',{'primary':old});assert fp()==before
    change('policy',{'dns':{'global':['https://1.1.1.1/dns-query'],'bootstrap':['1.1.1.1']},'rules':['DOMAIN-SUFFIX,example.test,DIRECT']})
    assert fp()==before
    global_yaml=yaml.safe_load((base/'exports/clmi-global.yaml').read_text());internal=yaml.safe_load((base/'exports/clmi-internal.yaml').read_text())
    assert global_yaml['rules'][0]=='DOMAIN-SUFFIX,example.test,DIRECT'
    assert global_yaml['dns']['nameserver']==['https://1.1.1.1/dns-query']
    assert internal['rules']==['MATCH,🚀 VPN']
    change('policy',{'dns':{},'rules':[]});assert fp()==before
def stale():
    old=api('policy').get('primary','tuic');p=api('changes/prepare',{'kind':'policy','data':{'primary':'hy2' if old!='hy2' else 'tuic'}})
    run([cli,'client-policy','probes','active-only' if not api('policy').get('smart_lazy') else 'continuous'])
    api('changes/commit',{'token':p['token']},status=409)
def create_user():
    before=state()['protocols'];change('user-create',{'name':'VMContract','tags':['vm','verified']})
    user=next(u for u in state()['managed_users'] if u['name']=='VMContract');assert before==state()['protocols']
    cfg_live=json.loads((base/'config.json').read_text());assert len(cfg_live['inbounds'])==5
    for inbound in cfg_live['inbounds']:assert any(u['name']=='user-'+user['id'] for u in inbound['users'])
    run(['/usr/local/lib/sbox-manager/sing-box','check','-c',str(base/'config.json')])
    (OUT/'test-user-id').write_text(user['id'])
def subscriptions():
    ident=(OUT/'test-user-id').read_text();links=api('subscriptions/rotate-token',{'id':ident})['urls']
    before=state()['protocols']
    for profile in ['global','cn','internal']:
        url=links[profile];path='/'+url.split('/',3)[3];body,headers=req(path,auth=False)
        assert headers['Cache-Control']=='no-store';assert headers['Content-Type'].startswith('application/yaml')
        d=yaml.safe_load(body);assert len(d['proxies'])>=5
        assert len(d['proxy-groups'])==4
        if profile=='cn':assert 'GEOSITE,CN,DIRECT' in d['rules']
        if profile=='global':assert 'GEOSITE,CN,DIRECT' not in d['rules']
        if profile=='internal':assert d['rules']==['MATCH,🚀 VPN']
        (OUT/(profile+'.yaml')).write_text(body)
        req(path,auth=False,extra={'If-None-Match':headers['ETag']},status=304)
    api('subscriptions/rotate-token',{'id':ident});req('/'+links['global'].split('/',3)[3],auth=False,status=404)
    assert state()['protocols']==before
    for fmt in ['json','links']:
        value=api('client-profiles/export',{'id':ident,'profile':'global','format':fmt})['content'];assert value
        (OUT/('client.'+fmt)).write_text(value)
    run(['/usr/local/lib/sbox-manager/sing-box','check','-c',str(OUT/'client.json')])
    if pathlib.Path('/usr/local/bin/mihomo').exists():
        for profile in ['global','cn','internal']:run(['/usr/local/bin/mihomo','-t','-d',str(OUT/'mihomo-parser'),'-f',str(OUT/(profile+'.yaml'))])
def disable():
    ident=(OUT/'test-user-id').read_text();before=state()['protocols'];change('user-disable',{},ident)
    assert not next(u for u in state()['managed_users'] if u['id']==ident)['enabled']
    assert not any(u.get('name')=='user-'+ident for i in json.loads((base/'config.json').read_text())['inbounds'] for u in i['users'])
    change('user-edit',{'enabled':True,'name':'VMContractRenamed'},ident);assert before==state()['protocols']
def ports():
    if cfg['variant']=='zgocloud':api('changes/prepare',{'kind':'inbounds','data':{'reality':{'port':24444}}},status=422);return 'Legacy mutation refused'
    old=state()['protocols']['vmess']['port'];change('inbounds',{'vmess':{'port':39444}});assert state()['protocols']['vmess']['port']==39444
    change('inbounds',{'vmess':{'port':old}})
def independence():
    run(['systemctl','stop','sing-box'])
    broken=api('diagnostics/doctor');assert broken['exit_code']!=0 and broken['failures']>0
    assert api('system/status')['service']['ActiveState']!='active'
    run([cli,'restart'])
    assert api('diagnostics/doctor')['exit_code']==0
    before=fp();run([cli,'webui','stop']);assert fp()==before
    run([cli,'webui','start']);time.sleep(2);assert fp()==before
    run([cli,'webui','doctor']);assert fp()==before
    # UID/socket permission checks execute under actual OS identities.
    uid=run(['systemctl','show','sbox-webui','-p','User','--value']).strip();assert uid=='sbox-webui'
    p=subprocess.run(['runuser','-u','nobody','--','python3','-c','import socket; s=socket.socket(socket.AF_UNIX);s.connect("/run/sbox-webui-control/control.sock")'],capture_output=True)
    assert p.returncode!=0
    assert pathlib.Path('/run/sbox-webui-control/control.sock').stat().st_mode&0o777==0o660
test('HTTPS bootstrap force reset and secure cookies',login)
test('Read-only APIs preserve state/config/PID and doctor healthy',readonly)
test('Auth CSRF Host injection SSRF and legacy negative cases',negatives)
test('Policy prepare/commit preserves core PID and config',policy)
test('CLI update invalidates stale WebUI preview',stale)
test('Create independent five-protocol user through manager transaction',create_user)
test('Revocable profile tokens and actual core/client parsers',subscriptions)
test('Disable/rename user preserves original credentials',disable)
test('Port edit adapter and immutable ZGO guard',ports)
test('Panel stop/start/doctor UID and socket isolation',independence)
print('VM CONTRACT COMPLETE',flush=True)
