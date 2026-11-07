"""Disposable booted VM public-access packet contracts (no provider claims)."""
from pathlib import Path
import subprocess,json,sys,time,hashlib,ssl,socket,urllib.request
assert Path('/root/lab-ready').is_file()
cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());port=cfg['port'];origin=cfg['origin'];rows=[]
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
def run(args,check=True,timeout=30):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError(' '.join(args[:4])+': '+p.stderr[-150:])
 return p
for i in (1,2):
 ns='panel-client-'+str(i);run(['ip','netns','del',ns],False);run(['ip','netns','add',ns])
 run(['ip','link','add','panel'+str(i),'type','veth','peer','name','eth0','netns',ns]);run(['ip','addr','add',f'10.70.{i}.1/24','dev','panel'+str(i)]);run(['ip','link','set','panel'+str(i),'up'])
 for args in [['ip','addr','add',f'10.70.{i}.2/24','dev','eth0'],['ip','link','set','eth0','up'],['ip','link','set','lo','up'],['ip','route','add','default','via',f'10.70.{i}.1']]:run(['ip','netns','exec',ns,*args])
 test=['curl','--noproxy','*','-fsS','--max-time','8','--resolve',origin.split('://')[1]+f':10.70.{i}.1',origin+'/']
 p=run(['ip','netns','exec',ns,*test],False)
 ok=p.returncode==0 and 'login-form' in p.stdout
 rows.append({'id':'SOURCE-'+str(i),'status':'PASS' if ok else 'FAIL','source':f'10.70.{i}.2','TLS':'private lab CA, hostname+chain verified, no -k','login_html':ok,'error':p.stderr[-250:]})
 # The HTML is public; every sensitive mutating route must still reject.
 if ok:
  paths=[(path,method.upper()) for path,value in json.loads(Path('/usr/local/lib/sbox-webui/current/api-spec/openapi.json').read_text())['paths'].items() for method in value if method in ('post','put','patch','delete') and not any(x in path for x in ('auth/login','auth/logout'))]
  for path,method in paths:
   p=run(['ip','netns','exec',ns,'curl','--noproxy','*','-sS','--max-time','15','--resolve',origin.split('://')[1]+f':10.70.{i}.1','-o','/dev/null','-w','%{http_code}','-X',method,'-H','Content-Type: application/json','-d','{}',origin+path],False)
   # The spec uses /api/v1 paths already.
   rows.append({'id':'UNAUTH-'+str(i)+'-'+method+'-'+path,'status':'PASS' if p.stdout in ('401','403') else 'FAIL','http':p.stdout})
 Path(out/'public.json').write_text(json.dumps(rows,indent=2))
print(json.dumps(rows[:2]))
for i in (1,2):run(['ip','netns','del','panel-client-'+str(i)]);run(['ip','link','del','panel'+str(i)],False)
sys.exit(any(x['status']=='FAIL' for x in rows))
