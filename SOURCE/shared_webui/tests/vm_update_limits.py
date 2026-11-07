"""Real explicit HTTPS core update and panel memory pressure, disposable VM only."""
import hashlib,http.client,json,os,pathlib,ssl,subprocess,sys,time
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file();os.umask(0o077)
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);rows=[];cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());cookie='';csrf=''
def run(args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=1000)
def record(name,**facts):rows.append({'test':name,'status':'PASS',**facts});(out/'update-limits.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',name,flush=True)
def api(p,d=None):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=950);c.request('POST' if d is not None else 'GET','/api/v1/'+p,json.dumps(d) if d is not None else None,{'Host':cfg['origin'].split('://')[1],'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf});r=c.getresponse();v=json.loads(r.read());h=dict(r.getheaders());assert r.status==200,(p,r.status,str(v)[:300]);c.close();return v,h
def pid():return run(['systemctl','show','sing-box','-p','MainPID','--value']).stdout.strip()
run(['sbox','webui','reset-admin']);pw=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];v,h=api('auth/login',{'username':'admin','password':pw});cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=api('auth/change-password',{'old':pw,'password':'Lab-verified-password-2026'})[0]['csrf']
old=json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text());version=old['sing_box']['version'];before=hashlib.sha256(pathlib.Path('/usr/local/lib/sbox-manager/sing-box').read_bytes()).hexdigest();api('actions',{'action':'core-update','arguments':{'version':version,'confirm_restart':True}});after=json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text());assert after['protocols']==old['protocols'] and after['sing_box']['version']==version;assert before==hashlib.sha256(pathlib.Path('/usr/local/lib/sbox-manager/sing-box').read_bytes()).hexdigest();assert api('diagnostics/doctor')[0]['failures']==0
record('Real explicit core update API verifies and installs selected release, preserving identities',version=version,core_sha256=before)
before=pid();facts=run(['systemctl','show','sbox-webui','-p','MemoryMax','-p','MemorySwapMax']).stdout;limits=dict(l.split('=',1) for l in facts.splitlines())
events=pathlib.Path('/sys/fs/cgroup/system.slice/sbox-webui.service/memory.events');start=events.read_text();old_restarts=int(run(['systemctl','show','sbox-webui','-p','NRestarts','--value']).stdout)
try:
 run(['systemctl','set-property','--runtime','sbox-webui.service','MemoryMax=2M','MemorySwapMax=0']);time.sleep(5);assert pid()==before
 result=run(['systemctl','show','sbox-webui','-p','Result','-p','NRestarts','-p','ActiveState']).stdout;oom=events.read_text() if events.exists() else result;new_restarts=int(run(['systemctl','show','sbox-webui','-p','NRestarts','--value']).stdout)
finally:
 run(['systemctl','set-property','--runtime','sbox-webui.service','MemoryMax='+limits['MemoryMax'],'MemorySwapMax='+limits['MemorySwapMax']]);run(['systemctl','reset-failed','sbox-webui']);run(['systemctl','start','sbox-webui']);time.sleep(3)
assert pid()==before;assert api('system/status')[0]['service']['ActiveState']=='active';run(['sbox','webui','doctor'])
assert 'oom' in result.lower() or new_restarts>old_restarts,(result,oom,old_restarts,new_restarts)
record('Real panel memory ceiling isolates OOM/restart from VPN and recovers after restoring limit',observed_service=result.strip(),memory_events=oom.strip(),core_pid_unchanged=True)
