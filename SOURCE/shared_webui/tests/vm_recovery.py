"""Destructive panel recovery checks; marked disposable local VM only."""
import hashlib,http.client,json,os,pathlib,sqlite3,ssl,subprocess,sys,time
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
os.umask(0o077)
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);rows=[]
installer=sys.argv[2]
def run(args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=240)
def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']).stdout.strip(),hashlib.sha256(pathlib.Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest(),hashlib.sha256(json.dumps({k:v for k,v in json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text()).items() if k not in ('updated_at','manager_version')},sort_keys=True).encode()).hexdigest())
def record(name):
 rows.append({'test':name,'status':'PASS'});(out/'recovery.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',name,flush=True)
before=fp()
run(['sbox','webui','rollback']);assert fp()==before;run(['bash',installer,'webui','upgrade']);assert fp()==before
record('Panel asset rollback and final upgrade preserve VPN PID/config/state')
run(['sbox','webui','uninstall']);assert fp()==before
assert run(['systemctl','is-active','--quiet','sbox-webui'],False).returncode!=0
run(['bash',installer,'webui','install']);assert fp()==before
record('Panel-only uninstall/reinstall retains data and preserves VPN')
run(['systemctl','stop','sbox-webui'])
run(['runuser','-u','sbox-webui','--','python3','-c',"import sqlite3; a=sqlite3.connect('/var/lib/sbox-webui/panel.db'); b=sqlite3.connect('/var/lib/sbox-webui/panel.db.before-migration'); a.backup(b); b.close(); a.close()"])
run(['runuser','-u','sbox-webui','--','python3','-c',"from pathlib import Path; p=Path('/var/lib/sbox-webui'); [(p/('panel.db'+s)).unlink(missing_ok=True) for s in ('-wal','-shm')]; (p/'panel.db').write_bytes(b'CORRUPT-DISPOSABLE-TEST-DATABASE')"])
run(['systemctl','start','sbox-webui'],False);time.sleep(3)
assert run(['sbox','webui','doctor'],False).returncode!=0;assert fp()==before
record('Corrupt UI database rejected; VPN remains unchanged')
run(['sbox','webui','recover-db']);time.sleep(2);run(['sbox','webui','doctor']);assert fp()==before
run(['runuser','-u','sbox-webui','--','python3','-c',"import sqlite3; d=sqlite3.connect('/var/lib/sbox-webui/panel.db'); assert d.execute('PRAGMA quick_check').fetchone()[0]=='ok'; assert d.execute('select count(*) from subscriptions').fetchone()[0]==0; assert d.execute('select count(*) from sessions').fetchone()[0]==0; assert d.execute('select count(*) from tokens').fetchone()[0]==0"])
record('Root recovery restores verified SQLite snapshot and revokes all access tokens')
cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());secret=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
def req(path,body,cookie='',csrf=''):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context());c.request('POST','/api/v1/'+path,json.dumps(body),{'Host':cfg['origin'].split('://')[1],'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf});r=c.getresponse();data=json.loads(r.read());headers=dict(r.getheaders());assert r.status==200,(r.status,data);c.close();return data,headers
v,h=req('auth/login',{'username':'admin','password':secret});req('auth/change-password',{'old':secret,'password':'Lab-verified-password-2026'},h['Set-Cookie'].split(';')[0],v['csrf']);assert fp()==before
record('Recovered account forces password reset and signs in over actual HTTPS')
