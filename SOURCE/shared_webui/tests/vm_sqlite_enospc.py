"""Actual ENOSPC on panel SQLite filesystem, isolated marked guest only."""
from pathlib import Path
import os,subprocess,json,hashlib,shutil,pwd,time,http.client,ssl,sys,tempfile
assert os.geteuid()==0 and Path('/root/lab-ready').is_file();os.umask(0o077)
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);data=Path('/var/lib/sbox-webui');cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());cookie=csrf='';mounted=False

def run(a,check=True):return subprocess.run(a,check=check,capture_output=True,text=True,timeout=90).stdout

def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']),hashlib.sha256(Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest())
def req(path,body):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=25);c.request('POST','/api/v1/'+path,json.dumps(body),{'Host':cfg['origin'].split('://')[1],'Cookie':cookie,'X-CSRF-Token':csrf,'Content-Type':'application/json'});r=c.getresponse();raw=r.read();h=dict(r.getheaders());code=r.status;c.close();return code,h,json.loads(raw)
def wait():
 for _ in range(60):
  try:
   with __import__('socket').create_connection(('127.0.0.1',cfg['port']),timeout=.3):return
  except OSError:time.sleep(.1)
 raise RuntimeError('Panel not ready')
before=fp();run(['sbox','webui','reset-admin']);pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
with tempfile.TemporaryDirectory(dir='/opt/sbox-lab') as td:
 snapshot=Path(td)/'data';run(['systemctl','stop','sbox-webui']);shutil.copytree(data,snapshot);user=pwd.getpwnam('sbox-webui')
 try:
  run(['mount','-t','tmpfs','-o','size=16m,mode=700,uid='+str(user.pw_uid)+',gid='+str(user.pw_gid),'tmpfs',str(data)]);mounted=True
  for p in snapshot.iterdir():
   if p.is_file():shutil.copy2(p,data/p.name);os.chown(data/p.name,user.pw_uid,user.pw_gid)
  run(['systemctl','reset-failed','sbox-webui']);run(['systemctl','start','sbox-webui']);wait()
  code,h,b=req('auth/login',{'username':'admin','password':pw});assert code==200;cookie=h['Set-Cookie'].split(';')[0];csrf=b['csrf'];code,_,b=req('auth/change-password',{'old':pw,'password':'ENOSPC-synthetic-password-2026'});assert code==200;csrf=b['csrf']
  with (data/'fill').open('wb',buffering=0) as f:
   try:
    while True:f.write(b'x'*4096)
   except OSError as e:assert e.errno==28
  code,_,body=req('accounts',{'name':'MustNotCommit','password':'Must-not-commit-password-2026','role':'reader'});assert code==503,(code,body);assert 'password' not in json.dumps(body).lower();assert fp()==before
  (data/'fill').unlink();assert 'validated' in run(['sbox','webui','doctor'])
 finally:
  run(['systemctl','stop','sbox-webui'],False)
  if mounted:run(['umount',str(data)])
  run(['systemctl','reset-failed','sbox-webui']);run(['systemctl','start','sbox-webui']);wait()
assert fp()==before;run(['sbox','webui','doctor'])
(out/'sqlite-enospc.json').write_text(json.dumps({'status':'PASS','filesystem':'actual full 16MiB tmpfs over disposable panel data; original data restored','write_http':503,'core_pid_config_unchanged':True,'database_integrity_after_space_restored':True},indent=2));print('PASS actual SQLite ENOSPC returns503, core stable, database and panel recovered')
