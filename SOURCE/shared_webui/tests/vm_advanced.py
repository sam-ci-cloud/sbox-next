"""Installed API/security/transaction checks in a marked disposable VM only."""
import concurrent.futures,hashlib,http.client,json,os,pathlib,ssl,subprocess,sys,time
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
os.umask(0o077);sys.path.insert(0,'/usr/local/lib/sbox-webui/current/backend')
from common import totp
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());rows=[];cookie='';csrf=''
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=240,**kw).stdout
def sql(code):return run(['runuser','-u','sbox-webui','--','python3','-c',"import sqlite3; d=sqlite3.connect('/var/lib/sbox-webui/panel.db'); "+code+"; d.commit(); d.close()"])
def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']).strip(),hashlib.sha256(pathlib.Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest())
def req(path,data=None,status=200,headers=None,auth=True):
 h={'Host':cfg['origin'].split('://')[1]}
 if auth:h.update({'Cookie':cookie,'X-CSRF-Token':csrf})
 if data is not None:h['Content-Type']='application/json'
 h.update(headers or {});c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=240)
 c.request('POST' if data is not None else 'GET',path,json.dumps(data) if data is not None else None,h);r=c.getresponse();raw=r.read();head=dict(r.getheaders());code=r.status;c.close()
 try:body=json.loads(raw)
 except ValueError:body=raw.decode()
 assert code==status,(path.split('/')[:4],code,status,str(body)[:200]);return body,head
def api(p,d=None,**kw):return req('/api/v1/'+p,d,**kw)[0]
def record(name):rows.append({'test':name,'status':'PASS'});(out/'advanced.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',name,flush=True)
def bootstrap():
 global cookie,csrf
 run(['sbox','webui','reset-admin']);pw=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
 v,h=req('/api/v1/auth/login',{'username':'admin','password':pw},auth=False);cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=api('auth/change-password',{'old':pw,'password':'Lab-verified-password-2026'})['csrf']
before=fp();bootstrap();assert fp()==before
unknown=api('auth/login',{'username':'DOES-NOT-EXIST','password':'bad'},auth=False,status=401);wrong=api('auth/login',{'username':'admin','password':'bad'},auth=False,status=401);assert unknown==wrong
# Clear the first two failed attempts via a successful legitimate login.
v,h=req('/api/v1/auth/login',{'username':'admin','password':'Lab-verified-password-2026'},auth=False);cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf']
for i in range(8):api('auth/login',{'username':'admin','password':'wrong'},auth=False,status=401,headers={'X-Forwarded-For':'198.51.100.'+str(i+1)})
api('auth/login',{'username':'admin','password':'wrong'},auth=False,status=429,headers={'X-Forwarded-For':'203.0.113.90'});bootstrap()
record('Generic credential errors and login throttle ignore forged proxy IP headers')
secret=api('auth/totp/enroll',{})['secret'];api('auth/totp/verify',{'code':'000000'},status=401)
step=int(time.time()//30);recovery=api('auth/totp/verify',{'code':totp(secret,step)})['recovery_codes'];assert len(recovery)==8
api('auth/login',{'username':'admin','password':'Lab-verified-password-2026','code':totp(secret,step)},auth=False,status=401)
v,h=req('/api/v1/auth/login',{'username':'admin','password':'Lab-verified-password-2026','code':recovery[0]},auth=False);oldcookie=cookie;cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];api('auth/logout',{});api('auth/login',{'username':'admin','password':'Lab-verified-password-2026','code':recovery[0]},auth=False,status=401);bootstrap()
record('Real TOTP enrollment verification replay rejection and one-time recovery code')
name='Reader'+str(time.time_ns())[-8:];api('accounts',{'name':name,'password':'Synthetic-reader-password-2026','role':'reader'});admin_cookie,admin_csrf=cookie,csrf
v,h=req('/api/v1/auth/login',{'username':name,'password':'Synthetic-reader-password-2026'},auth=False);cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=api('auth/change-password',{'old':'Synthetic-reader-password-2026','password':'Changed-reader-password-2026'})['csrf'];api('users');api('changes/prepare',{'kind':'policy','data':{}},status=403);api('accounts',status=403);reader_cookie=cookie
cookie,csrf=admin_cookie,admin_csrf;api('accounts',{'name':name,'enabled':False});api('users',headers={'Cookie':reader_cookie},status=401)
record('Reader role cannot mutate or manage other accounts; disabling revokes active session')
token=api('api-tokens',{'name':'AdvancedRead','scope':'read','hours':1})['token'];headers={'Authorization':'Bearer '+token};api('users',headers=headers,auth=False);api('changes/prepare',{'kind':'policy','data':{}},headers=headers,auth=False,status=403);api('auth/change-password',{'old':'Lab-verified-password-2026','password':'Unwanted-password-2026'},headers=headers,auth=False,status=403);sql('d.execute("UPDATE tokens SET expires=0")');api('users',headers=headers,auth=False,status=401)
record('Read-only bearer cannot mutate config or account; expired token returns 401')
sql('d.execute("UPDATE sessions SET seen=0")');api('users',status=401);bootstrap()
record('Expired actual SQLite session rejects authenticated API request')
old=api('policy').get('primary','tuic');p=[api('changes/prepare',{'kind':'policy','data':{'primary':p}}) for p in ('reality','hy2')]
def commit(v):
 try:return req('/api/v1/changes/commit',{'token':v['token']})[0]
 except AssertionError as e:
  assert e.args[0][1]==409,e;return 'conflict'
with concurrent.futures.ThreadPoolExecutor(2) as pool:r=list(pool.map(commit,p))
assert sum(x=='conflict' for x in r)==1;assert fp()==before
p=api('changes/prepare',{'kind':'policy','data':{'primary':old}});api('changes/commit',{'token':p['token']})
record('Simultaneous writes serialize: one commit and one stale conflict, unchanged core')
lock=pathlib.Path('/run/sbox-manager/manager.lock');ready=out/'lock-ready';ready.unlink(missing_ok=True)
proc=subprocess.Popen(['flock',str(lock),'sh','-c','touch "$1"; sleep 3','test',str(ready)])
while not ready.exists():time.sleep(.02)
start=time.monotonic();api('changes/prepare',{'kind':'policy','data':{}},status=409);assert time.monotonic()-start>=.8;proc.wait(timeout=10);api('changes/prepare',{'kind':'policy','data':{}})
record('WebUI prepare respects the CLI flock and returns bounded conflict while held')
for port in [0,65536]:api('changes/prepare',{'kind':'inbounds','data':{'vmess':{'port':port}}},status=422)
for action,args in [('exec',{}),('restart',{'shell':'id'})]:api('actions',{'action':action,'arguments':args},status=400)
req('/api/v1/../../etc/passwd',auth=False,status=400);api('qr',{'text':'x'*2049},status=400);api('changes/prepare',{'kind':'file-upload','data':{'path':'/etc/ssh/sshd_config'}},status=422)
record('Invalid ports, raw commands, unowned uploads and traversal rejected')
# Check that token rotation and alias rename do not affect another token or user.
suffix=str(time.time_ns())[-8:]
name_a,name_b,renamed='AdvancedA'+suffix,'AdvancedB'+suffix,'AdvancedRenamed'+suffix
for name in [name_a,name_b]:
 p=api('changes/prepare',{'kind':'user-create','data':{'name':name}});api('changes/commit',{'token':p['token']})
users={u['name']:u['id'] for u in api('users')};a,b=users[name_a],users[name_b];url_a=api('subscriptions/rotate-token',{'id':a})['urls']['global'];url_b=api('subscriptions/rotate-token',{'id':b})['urls']['global']
path_a='/'+url_a.split('/',3)[3];path_b='/'+url_b.split('/',3)[3];text=req(path_a,auth=False)[0];state=json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text());assert state['protocols']['reality']['private_key'] not in text
api('subscriptions/rotate-token',{'id':b});req(path_a,auth=False);req(path_b,auth=False,status=404)
p=api('changes/prepare',{'kind':'user-edit','id':a,'data':{'name':renamed}});api('changes/commit',{'token':p['token']});req(path_a,auth=False);assert any(u['id']==a and u['name']==renamed for u in api('users'))
p=api('changes/prepare',{'kind':'user-revoke','id':b,'data':{}});api('changes/commit',{'token':p['token']});assert any(u['id']==a for u in api('users'))
record('Independent subscription rotation; alias rename retains token; revoke retains other user')
svg=api('qr',{'text':url_a})['svg'];png=out/'private-qr.png';run(['rsvg-convert','-o',str(png)],input=svg);decoded=run(['zbarimg','--quiet','--raw',str(png)]).strip();assert decoded==url_a;png.unlink()
record('Real generated SVG QR decodes to exactly the private subscription URL')
backups=api('backups')['backups'];api('actions',{'action':'backup','arguments':{}});new=[x for x in api('backups')['backups'] if x['name'] not in {b['name'] for b in backups}];assert new
chosen=new[-1];api('actions',{'action':'restore','arguments':{'name':chosen['name'],'sha256':'0'*64,'confirm_restart':True}},status=409)
api('actions',{'action':'restore','arguments':{'name':chosen['name'],'sha256':chosen['sha256'],'confirm_restart':True}});assert api('diagnostics/doctor')['failures']==0
record('Actual backup, hash-selected restore and stale/tampered selection rejection')
assert api('actions',{'action':'update-preview','arguments':{'version':'1.13.14'}})['version']=='v1.13.14'
api('actions',{'action':'core-update','arguments':{'version':'../../bad','confirm_restart':True}},status=400)
record('Official release preview and malformed core update denial')
# Crash the panel process only, then observe systemd recovery with core stable.
before=fp();run(['systemctl','kill','--signal=KILL','--kill-who=main','sbox-webui']);time.sleep(5)
for i in range(20):
 try:api('system/status');break
 except (OSError,AssertionError):time.sleep(1)
else:raise AssertionError('Panel did not recover')
assert fp()==before
record('Real panel SIGKILL restarts under systemd without changing VPN PID/config')
# Invalid syntactically valid token requests exercise the real subscription limiter.
path='/sub/'+'x'*43+'/global.yaml';codes=[]
for i in range(125):
 try:req(path,auth=False,status=404);codes.append(404)
 except AssertionError as e:
  assert e.args[0][1]==429,e;codes.append(429)
assert 429 in codes
record('Real subscription request flood reaches independent per-IP 429 limit')
print('ADVANCED INSTALLED CONTRACT COMPLETE',flush=True)
