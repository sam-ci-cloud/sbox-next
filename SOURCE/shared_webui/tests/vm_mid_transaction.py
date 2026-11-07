"""Kill the nonroot panel during an actual manager commit, disposable VM only."""
from pathlib import Path
import concurrent.futures,json,os,subprocess,sys,time,http.client,ssl
assert os.geteuid()==0 and Path('/root/lab-ready').is_file();os.umask(0o077)
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());before=json.loads(Path('/etc/sbox-manager/state.json').read_text());cookie=csrf=''
def run(a):return subprocess.run(a,check=True,capture_output=True,text=True,timeout=180).stdout
def req(path,data):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=180);c.request('POST','/api/v1/'+path,json.dumps(data),{'Host':cfg['origin'].split('://')[1],'Cookie':cookie,'X-CSRF-Token':csrf,'Content-Type':'application/json'});r=c.getresponse();b=json.loads(r.read());h=dict(r.getheaders());c.close();assert r.status==200,(r.status,b.get('error'));return b,h
run(['sbox','webui','reset-admin']);pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];v,h=req('auth/login',{'username':'admin','password':pw});cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=req('auth/change-password',{'old':pw,'password':'Mid-transaction-SYNTHETIC-2026'})[0]['csrf']
name='KillCommit'+str(time.time_ns())[-10:];p,_=req('changes/prepare',{'kind':'user-create','data':{'name':name}})
with concurrent.futures.ThreadPoolExecutor(1) as pool:
 future=pool.submit(req,'changes/commit',{'token':p['token']});deadline=time.monotonic()+20;observed=None
 while time.monotonic()<deadline:
  try:
   journal=json.loads(Path('/var/lib/sbox-manager/transaction.json').read_text())
   if journal['phase']=='commit':observed='commit';break
  except (OSError,ValueError):pass
  if future.done():break
  time.sleep(.01)
 assert observed=='commit','A real commit must be observed before injecting SIGKILL'
 run(['systemctl','kill','--signal=KILL','--kill-who=main','sbox-webui'])
 try:future.result(timeout=30)
 except (OSError,AssertionError):pass
for _ in range(40):
 if not Path('/var/lib/sbox-manager/transaction.json').exists():break
 time.sleep(.5)
after=json.loads(Path('/etc/sbox-manager/state.json').read_text());assert after['protocols']==before['protocols'];user=next((u for u in after.get('managed_users',[]) if u['name']==name),None)
assert user and len(user['protocols'])==5;assert json.loads(run(['sbox','doctor','--json']))['failures']==0
for _ in range(30):
 try:run(['sbox','webui','doctor']);break
 except subprocess.CalledProcessError:time.sleep(.5)
else:raise AssertionError('Panel failed to recover')
p=json.loads(run(['sbox','_webui-control','prepare'],input=None)) if False else None
# Remove the test user through the same validated manager transaction.
r=subprocess.run(['sbox','_webui-control','prepare'],input=json.dumps({'kind':'user-revoke','id':user['id'],'data':{}}),capture_output=True,text=True,check=True);token=json.loads(r.stdout)['token'];subprocess.run(['sbox','_webui-control','commit'],input=json.dumps({'token':token}),capture_output=True,text=True,check=True)
assert json.loads(Path('/etc/sbox-manager/state.json').read_text())['protocols']==before['protocols']
(out/'mid-transaction.json').write_text(json.dumps({'status':'PASS','fault_phase':observed,'panel_sigkill':True,'atomic_user_protocols':5,'legacy_identity_unchanged':True,'doctor_failures':0,'panel_recovered':True},indent=2));print('PASS real panel SIGKILL during commit: complete five-protocol user, protected identity, recovery')
