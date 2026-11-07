"""Exercise original Generic menu/guided customization plus live protocol toggles."""
import hashlib,http.client,json,os,pathlib,ssl,subprocess,sys
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
os.umask(0o077);out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);installer=sys.argv[2];rows=[]
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=240,**kw).stdout
def state():return json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text())
def record(name):rows.append({'test':name,'status':'PASS'});(out/'customization.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',name,flush=True)
original=state();assert not original.get('zgo_legacy_compat');archive=run(['sbox','backup']).strip()
try:
 text=run(['bash',installer],input='0\n',env={**os.environ,'TERM':'xterm'});assert 'WebUI' in text or 'sbox' in text.lower();record('Original no-argument Generic menu opens and exits through option 0')
 answers=['','','','','2','4','www.apple.com','1','/custom-webui-path','y','y','n','y','1','y']
 run(['sbox','configure'],input='\n'.join(answers)+'\n');s=state();assert s['protocols']['reality']['sni']=='www.apple.com';assert s['protocols']['vmess']['path'].lstrip('/')=='custom-webui-path';assert s['protocols']['reality']['short_id']==original['protocols']['reality']['short_id'];assert s.get('managed_users')==original.get('managed_users');assert json.loads(run(['sbox','doctor','--json']))['failures']==0
 record('Original guided CLI accepts custom SNI/WS path and preserves short ID and added users')
 cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());run(['sbox','webui','reset-admin']);pw=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];cookie='';csrf=''
 def req(p,data=None):
  c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=180);c.request('POST' if data is not None else 'GET','/api/v1/'+p,json.dumps(data) if data is not None else None,{'Host':cfg['origin'].split('://')[1],'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf});r=c.getresponse();v=json.loads(r.read());h=dict(r.getheaders());assert r.status==200,(p,r.status,v);c.close();return v,h
 v,h=req('auth/login',{'username':'admin','password':pw});cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=req('auth/change-password',{'old':pw,'password':'Lab-verified-password-2026'})[0]['csrf']
 for enabled in (False,True):
  p=req('changes/prepare',{'kind':'inbounds','data':{'vmess':{'enabled':enabled}}})[0];req('changes/commit',{'token':p['token']});a=req('inbounds')[0];assert a['protocols']['vmess']['enabled']==enabled;assert any(x['type']=='vmess' for x in a['inbounds'])==enabled
 assert state()['protocols']['vmess']['uuid']==original['protocols']['vmess']['uuid'];record('Actual WebUI protocol disable/enable updates state/listeners/API without rotating identity')
finally:
 run(['sbox','restore',archive,'--force']);assert state()['protocols']==original['protocols'];assert state().get('managed_users')==original.get('managed_users');assert json.loads(run(['sbox','doctor','--json']))['failures']==0
record('Original backup restore recovers all customization and users')
