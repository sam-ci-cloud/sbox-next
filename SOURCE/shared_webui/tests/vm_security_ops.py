"""Installed MFA preservation, archive rejection and 100-client auth pressure."""
from pathlib import Path
import json,os,subprocess,sys,http.client,ssl,socket,time,hashlib,tarfile,io,concurrent.futures
assert os.geteuid()==0 and Path('/root/lab-ready').is_file();os.umask(0o077)
sys.path.insert(0,'/usr/local/lib/sbox-webui/current/backend');from common import totp
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);installer=sys.argv[2];cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());cookie=csrf='';rows=[]
def run(a,**kw):return subprocess.run(a,check=True,capture_output=True,text=True,timeout=180,**kw).stdout
def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']),hashlib.sha256(Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest())
def req(path,data=None,peer='127.0.0.1',auth=True):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],source_address=(peer,0),context=ssl._create_unverified_context(),timeout=30);c.request('POST' if data is not None else 'GET','/api/v1/'+path,json.dumps(data) if data is not None else None,{'Host':cfg['origin'].split('://')[1],'Content-Type':'application/json','Cookie':cookie if auth else '','X-CSRF-Token':csrf if auth else ''});r=c.getresponse();raw=r.read();h=dict(r.getheaders());code=r.status;c.close();return code,h,json.loads(raw)
def record(name,**facts):rows.append({'test':name,'status':'PASS',**facts});(out/'security-ops.json').write_text(json.dumps(rows,indent=2));print('PASS',name,flush=True)
before=fp();run(['sbox','webui','reset-admin']);pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];code,h,b=req('auth/login',{'username':'admin','password':pw},auth=False);assert code==200;cookie=h['Set-Cookie'].split(';')[0];csrf=b['csrf'];pw='Security-operations-synthetic-2026';code,_,b=req('auth/change-password',{'old':Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0],'password':pw});assert code==200;csrf=b['csrf'];code,_,b=req('auth/totp/enroll',{});assert code==200;secret=b['secret'];code,_,b=req('auth/totp/verify',{'code':totp(secret)});assert code==200
fingerprint_code="import sqlite3,hashlib,json;d=sqlite3.connect('/var/lib/sbox-webui/panel.db');print(hashlib.sha256(json.dumps(d.execute(\"SELECT hash,totp,last_totp,recovery FROM accounts WHERE name='admin'\").fetchone()).encode()).hexdigest())"
def mfa_hash():return run(['runuser','-u','sbox-webui','--','python3','-c',fingerprint_code]).strip()
hash0=mfa_hash()
for command in [['bash',installer,'webui','upgrade'],['sbox','webui','rollback'],['bash',installer,'webui','upgrade']]:
 run(command);assert mfa_hash()==hash0;assert req('auth/me')[0]==200;assert fp()==before
record('Panel upgrade rollback upgrade preserves enrolled MFA hash and active session',core_unchanged=True)
# Revoke synthetic MFA/session before the independent load fixture.
run(['sbox','webui','reset-admin']);archive=Path(run(['sbox','backup']).strip())
for kind in ['traversal','symlink']:
 dest=out/(kind+'.tar.gz')
 with tarfile.open(archive) as original,tarfile.open(dest,'w:gz') as target:
  for member in original.getmembers():target.addfile(member,original.extractfile(member) if member.isfile() else None)
  member=tarfile.TarInfo('../SBOX_ESCAPE' if kind=='traversal' else 'evil-link');member.size=1
  if kind=='symlink':member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd';member.size=0;target.addfile(member)
  else:target.addfile(member,io.BytesIO(b'x'))
 r=subprocess.run(['sbox','restore',str(dest),'--force'],capture_output=True,text=True,timeout=180);assert r.returncode!=0;assert fp()==before;dest.unlink()
record('Real valid backup plus appended traversal and symlink entries rejected',core_unchanged=True)
pid=int(run(['systemctl','show','sbox-webui','-p','MainPID','--value']));rss0=int(next(x.split()[1] for x in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if x.startswith('VmRSS:')))
def bad(i):
 try:return req('auth/login',{'username':'unknown-synthetic','password':'bad'},peer='127.0.0.2',auth=False)[0]
 except (OSError,ValueError):return 'bounded-connection-refusal'
with concurrent.futures.ThreadPoolExecutor(100) as pool:codes=list(pool.map(bad,range(100)))
assert all(c in (401,429,'bounded-connection-refusal') for c in codes),codes;assert 429 in codes;assert fp()==before
assert int(run(['systemctl','show','sbox-webui','-p','MainPID','--value']))==pid
rss1=int(next(x.split()[1] for x in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if x.startswith('VmRSS:')));assert rss1<160*1024 and rss1-rss0<100*1024
pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];assert req('auth/login',{'username':'admin','password':pw},peer='127.0.0.3',auth=False)[0]==200
record('100 concurrent bad logins bounded; clean independent peer can sign in',requests=100,counts={str(c):codes.count(c) for c in set(codes)},rss_before_kib=rss0,rss_after_kib=rss1,core_unchanged=True)
