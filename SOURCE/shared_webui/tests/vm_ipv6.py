"""Real IPv6 wildcard HTTPS from a guest namespace; no public IPv6 ISP claim."""
from pathlib import Path
import json,subprocess,sys,hashlib,time,os,grp
assert os.geteuid()==0 and Path('/root/lab-ready').is_file()
installer=sys.argv[1];out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True);settings=Path('/etc/sbox-webui/settings.json');saved=settings.read_bytes();cfg=json.loads(saved);ns='panel-v6';rows=[]
def run(a,check=True):return subprocess.run(a,check=check,capture_output=True,text=True,timeout=180)
def fp():return (run(['systemctl','show','sing-box','-p','MainPID','--value']).stdout,hashlib.sha256(Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest())
before=fp()
try:
 cfg['listen']='::';settings.write_text(json.dumps(cfg));run(['bash',installer,'webui','upgrade']);assert fp()==before
 run(['ip','netns','del',ns],False);run(['ip','netns','add',ns]);run(['ip','link','add','p6host','type','veth','peer','name','eth0','netns',ns]);run(['ip','-6','addr','add','fd42:91::1/64','dev','p6host']);run(['ip','link','set','p6host','up'])
 for args in [['ip','link','set','lo','up'],['ip','link','set','eth0','up'],['ip','-6','addr','add','fd42:91::2/64','dev','eth0']]:run(['ip','netns','exec',ns,*args])
 time.sleep(2);resolve=cfg['origin'].split('://')[1]+':[fd42:91::1]'
 p=run(['ip','netns','exec',ns,'curl','--noproxy','*','-fsS','--max-time','15','--resolve',resolve,cfg['origin']+'/'])
 assert 'login-form' in p.stdout
 p=run(['ip','netns','exec',ns,'curl','--noproxy','*','-sS','--max-time','15','--resolve',resolve,'-o','/dev/null','-w','%{http_code}',cfg['origin']+'/api/v1/users']);assert p.stdout=='401'
 run(['ip6tables','-w','5','-C','INPUT','-p','tcp','--dport',str(cfg['port']),'-m','comment','--comment','sbox-webui','-j','ACCEPT']);assert json.loads(settings.read_text())['listen']=='::';assert fp()==before
 rows.append({'id':'IPV6-PUBLIC-LOGIN','status':'PASS','source':'fd42:91::2','host':'fd42:91::1','TLS':'hostname+private lab CA verified, no -k','unauthorized_http':401,'core_unchanged':True,'scope':'Real booted guest IPv6 namespace; global Internet IPv6 not verified'})
finally:
 settings.write_bytes(saved);run(['bash',installer,'webui','upgrade']);run(['ip','netns','del',ns],False);run(['ip','link','del','p6host'],False)
assert fp()==before
(out/'ipv6.json').write_text(json.dumps(rows,indent=2));print('PASS real IPv6 wildcard namespace login, 401, owned firewall, default restored')
