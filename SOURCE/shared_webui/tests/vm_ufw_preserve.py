"""Active pre-existing UFW allowlist preservation in a marked disposable VM."""
import hashlib,json,os,pathlib,subprocess,sys
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file();os.umask(0o077)
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);installer=sys.argv[2]
def run(args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=240).stdout
def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']),hashlib.sha256(pathlib.Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest())
assert 'inactive' in run(['ufw','status']),'Fixture requires initially inactive UFW'
paths=[pathlib.Path(p) for p in ['/etc/ufw/user.rules','/etc/ufw/user6.rules','/etc/default/ufw','/etc/ufw/ufw.conf']];saved={p:(p.read_bytes(),p.stat().st_mode&0o777) for p in paths};ssh={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/etc/ssh').rglob('*') if p.is_file()};facts=run(['systemctl','show','ssh.service','ssh.socket','-p','MainPID','-p','NRestarts'])
try:
 run(['ufw','default','allow','incoming']);run(['ufw','default','allow','outgoing']);run(['ufw','allow','22/tcp']);run(['ufw','allow','from','198.51.100.20','to','any','port','12345','proto','tcp']);run(['ufw','--force','enable']);run(['sbox','firewall','apply']);run(['sbox','security','repair']);before=fp();rules={p:p.read_bytes() for p in paths[:2]};run(['bash',installer,'webui','upgrade']);assert fp()==before;assert all(p.read_bytes()==data for p,data in rules.items());assert 'active' in run(['ufw','status']) and '12345' in run(['ufw','status']);assert {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/etc/ssh').rglob('*') if p.is_file()}==ssh;assert run(['systemctl','show','ssh.service','ssh.socket','-p','MainPID','-p','NRestarts'])==facts
 (out/'ufw-preservation.json').write_text(json.dumps({'status':'PASS','active_ufw_foreign_rule_and_management_allowlist_unchanged':True,'core_pid_config_unchanged':True,'ssh_service_keys_config_unchanged':True,'firewall_scope':'Disposable guest only; no provider change'},indent=2)+'\n');print('PASS active UFW allowlist, VPN PID/config and SSH facts preserved',flush=True)
finally:
 run(['ufw','--force','disable'])
 for p,(data,mode) in saved.items():p.write_bytes(data);p.chmod(mode)
 run(['sbox','firewall','apply']);run(['sbox','security','repair']);assert json.loads(run(['sbox','doctor','--json']))['failures']==0
