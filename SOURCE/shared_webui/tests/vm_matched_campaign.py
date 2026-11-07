"""Real installed core + Mihomo traffic in a disposable guest client namespace.
Lab CA, local TLS camouflage target and local routes; no public ISP claim.
Original YAML is never edited. Derived copies are explicit range-edge tests.
"""
from pathlib import Path
import concurrent.futures,hashlib,http.server,json,os,signal,socket,ssl,subprocess,sys,threading,time,yaml,shutil
assert os.geteuid()==0 and Path('/root/lab-ready').is_file()
os.umask(0o077)
source=Path(sys.argv[1]);installer=Path(sys.argv[2]);out=Path(sys.argv[3]);out.mkdir(parents=True,exist_ok=True)
state=json.loads(Path('/etc/sbox-manager/state.json').read_text());domain=state['domain'];sni=state['protocols']['reality']['sni'];ns='sbox-vpn-client';rows=[]
def run(args,check=True,timeout=90,**kw):
 p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=timeout,**kw)
 if check and p.returncode:raise RuntimeError('command '+str(args[:3])+' exit '+str(p.returncode)+': '+p.stderr[-220:])
 return p

def client(*args,**kwargs):return run(['ip','netns','exec',ns,*args],**kwargs)
def snapshot():return {'core_pid':run(['systemctl','show','sing-box','-p','MainPID','--value']).stdout.strip(),'config_sha256':hashlib.sha256(Path('/etc/sbox-manager/config.json').read_bytes()).hexdigest()}
def record(id,ok,**data):
 rows.append({'id':id,'status':'PASS' if ok else 'FAIL',**data});(out/'packets.json').write_text(json.dumps({'scope':'Installed booted KVM guest, real protocol packets; local CA/DNS/camouflage; not public ISP','yaml_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'rows':rows},indent=2));print(('PASS' if ok else 'FAIL'),id,flush=True)
original=source.read_bytes();doc=yaml.safe_load(original);proxies=doc['proxies'];mixed=doc.get('mixed-port') or doc.get('port');ctl=19090;proc=None;children=[];hosts=Path('/etc/hosts').read_bytes();nsdir=Path('/etc/netns')/ns;before=snapshot()
class Target(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  n=4*1024*1024 if self.path=='/payload' else 8*1024*1024 if self.path=='/stream' else 21
  body=b'SBOX-PACKET-ECHO-OK!!\n' if self.path not in ('/payload','/stream') else None
  if body:n=len(body)
  self.send_response(200);self.send_header('Content-Length',str(n));self.end_headers()
  if body:self.wfile.write(body)
  else:
   for _ in range(n//65536):
    self.wfile.write(b'a'*65536)
    if self.path=='/stream':time.sleep(.06)
 def log_message(self,*a):pass

def spawn(args,log):
 f=open(out/log,'w');p=subprocess.Popen([str(x) for x in args],stdout=f,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL);children.append(p);return p

def start_client(data,tag):
 global proc
 if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=8)
 d=out/('client-'+tag);d.mkdir(exist_ok=True);(d/'config.yaml').write_bytes(data);shutil.copyfile('/tmp/Country.mmdb',d/'Country.mmdb')
 # Parser is real; the controller overrides selection only in memory.
 r=run(['/tmp/mihomo','-t','-d',d,'-f',d/'config.yaml'],check=False,timeout=120)
 record('PARSER-'+tag,r.returncode==0)
 if r.returncode:raise RuntimeError('Mihomo parser failed; inspect private client log')
 proc=spawn(['ip','netns','exec',ns,'/tmp/mihomo','-d',d,'-f',d/'config.yaml','-ext-ctl','127.0.0.1:'+str(ctl)],'mihomo-'+tag+'.log')
 for _ in range(100):
  if client('curl','-s','-o','/dev/null','-w','%{http_code}','http://127.0.0.1:'+str(ctl)+'/version',check=False).stdout=='200':break
  if proc.poll() is not None:raise RuntimeError('Mihomo exited')
  time.sleep(.1)
 else:raise RuntimeError('client controller not ready')
 client('curl','-fsS','-X','PATCH','http://127.0.0.1:'+str(ctl)+'/configs','-H','Content-Type: application/json','-d','{"mode":"global"}')

def select(name):client('curl','-fsS','-X','PUT','http://127.0.0.1:'+str(ctl)+'/proxies/GLOBAL','-H','Content-Type: application/json','-d',json.dumps({'name':name}))
def through(name,path='/probe'):
 select(name);t=time.monotonic();p=client('curl','-sS','--noproxy','','--proxy','http://127.0.0.1:'+str(mixed),'--max-time','25','http://198.51.100.10:18080'+path,check=False,timeout=30)
 return {'ok':p.returncode==0 and (len(p.stdout)==4194304 if path=='/payload' else p.stdout=='SBOX-PACKET-ECHO-OK!!\n'),'bytes':len(p.stdout),'seconds':round(time.monotonic()-t,4),'error':p.stderr[-140:]}
def all_nodes(phase):
 for n,p in enumerate(proxies):
  v=through(p['name']);record(phase+'-NODE-'+str(n+1),v.pop('ok'),protocol=p['type'],**v)
try:
 run(['ip','netns','del',ns],False);run(['ip','netns','add',ns]);nsdir.mkdir(parents=True,exist_ok=True)
 run(['ip','link','add','vpnhost','type','veth','peer','name','eth0','netns',ns]);run(['ip','addr','add','10.80.0.1/24','dev','vpnhost']);run(['ip','-6','addr','add','fd42:80::1/64','dev','vpnhost']);run(['ip','link','set','vpnhost','up'])
 for args in [('ip','addr','add','10.80.0.2/24','dev','eth0'),('ip','-6','addr','add','fd42:80::2/64','dev','eth0'),('ip','link','set','eth0','up'),('ip','link','set','lo','up'),('ip','route','add','default','via','10.80.0.1'),('ip','addr','add','203.0.113.80/32','dev','lo')]:client(*args)
 run(['ip','route','add','203.0.113.80/32','via','10.80.0.2']);run(['ip','addr','add','198.51.100.10/32','dev','lo'])
 (nsdir/'hosts').write_text('127.0.0.1 localhost\n10.80.0.1 '+domain+'\n');(nsdir/'resolv.conf').write_text('nameserver 10.0.2.3\n')
 Path('/etc/hosts').write_bytes(hosts+('\n203.0.113.80 '+sni+'\n').encode())
 ca=Path('/opt/sbox-lab/ca');run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+sni,'-keyout',out/'camo.key','-out',out/'camo.csr'])
 (out/'camo.ext').write_text('subjectAltName=DNS:'+sni+'\nextendedKeyUsage=serverAuth\n')
 run(['openssl','x509','-req','-in',out/'camo.csr','-CA',ca/'ca.crt','-CAkey',ca/'ca.key','-CAcreateserial','-days','3','-extfile',out/'camo.ext','-out',out/'camo.crt'])
 spawn(['ip','netns','exec',ns,'openssl','s_server','-accept','203.0.113.80:443','-cert',out/'camo.crt','-key',out/'camo.key','-tls1_3','-www','-quiet'],'camo.log')
 http=http.server.ThreadingHTTPServer(('198.51.100.10',18080),Target);threading.Thread(target=http.serve_forever,daemon=True).start();time.sleep(6)

 # Repeated fresh Mihomo processes: no pooled transport connection survives.
 # curl first-byte latency includes tunnel handshake plus HTTP request/response.
 import statistics,math
 spawn(['python3',str(Path(__file__).parent/'traffic.py'),'server','--target','198.51.100.10'],'traffic-target.log')
 time.sleep(.3)
 def pct(v,q):return sorted(v)[max(0,math.ceil(len(v)*q)-1)]
 perf={'scope':'Real installed core, unchanged credentials and original YAML, shaped namespace; local CA/camouflage, no Internet claim','conditions':{'delay_ms_each_direction':10,'jitter_ms_each_direction':1,'loss_each_direction_percent':0.1,'rate_each_direction':'20mbit','fresh_clients_per_node_per_phase':10,'udp_seconds_per_node_per_phase':8,'phases':['on','off','on-again']},'phases':{},'core_unchanged':False}
 for prefix_,device in [([], 'vpnhost'),(['ip','netns','exec',ns],'eth0')]:
  run(prefix_+['tc','qdisc','replace','dev',device,'root','netem','delay','10ms','1ms','loss','0.1%','rate','20mbit','limit','1000'])
 for phase in ['on','off','on-again']:
  run(['sbox','webui','stop' if phase=='off' else 'start']);results=[]
  for idx,node in enumerate(proxies):
   first=[]
   for sample in range(10):
    start_client(original,phase+'-'+str(idx)+'-'+str(sample));select(node['name'])
    r=client('curl','-fsS','--noproxy','','--proxy','http://127.0.0.1:'+str(mixed),'--max-time','20','-o','/dev/null','-w','%{time_starttransfer}','http://198.51.100.10:18080/probe')
    first.append(float(r.stdout)*1000)
   args=['ip','netns','exec',ns,'python3',str(Path(__file__).parent/'traffic.py'),'client','--target','198.51.100.10','--socks','127.0.0.1','--socks-port',str(doc.get('mixed-port') or doc['socks-port']),'--bytes','1048576','--runs','1','--udp-seconds','8']
   udp=run(args,check=False,timeout=150)
   if udp.returncode not in [0,2]:raise RuntimeError('UDP measurement failed: '+udp.stderr[-200:])
   measured=json.loads(udp.stdout)
   item={'node':idx+1,'protocol':node['type'],'fresh_first_byte_ms':{'samples':first,'p50':statistics.median(first),'p95':pct(first,.95)},'workload':measured}
   results.append(item);record('MATCHED-'+phase+'-NODE-'+str(idx+1),udp.returncode==0,protocol=node['type'])
   perf['phases'][phase]=results;(out/'matched-performance.json').write_text(json.dumps(perf,indent=2))
 perf['core_unchanged']=snapshot()==before and source.read_bytes()==original
 assert perf['core_unchanged']
 (out/'matched-performance.json').write_text(json.dumps(perf,indent=2))
 record('MATCHED-IDENTITY-AND-CORE-UNCHANGED',True)
finally:
 if proc and proc.poll() is None:proc.terminate()
 for p in children:
  if p.poll() is None:p.terminate()
 Path('/etc/hosts').write_bytes(hosts)
 run(['ip','netns','del',ns],False);run(['ip','link','del','vpnhost'],False);run(['ip','route','del','203.0.113.80/32'],False);run(['ip','addr','del','198.51.100.10/32','dev','lo'],False);shutil.rmtree(nsdir,ignore_errors=True)
 run(['sbox','webui','start'],False)
sys.exit(any(x['status']=='FAIL' for x in rows))
