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

 import http.client,sqlite3,secrets,statistics,math
 cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());webdomain=cfg['origin'].split('://')[1].rsplit(':',1)[0];context=ssl.create_default_context();cookie=csrf=''
 class HTTPS(http.client.HTTPSConnection):
  def __init__(self,peer):super().__init__(webdomain,cfg['port'],context=context,timeout=20);self.peer=peer
  def connect(self):self.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',cfg['port']),timeout=20,source_address=(self.peer,0)),server_hostname=webdomain)
 def api(path,data=None,peer='127.0.3.1'):
  c=HTTPS(peer);headers={'Host':cfg['origin'].split('://')[1],'Cookie':cookie,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
  c.request('GET' if data is None else 'POST','/api/v1/'+path,None if data is None else json.dumps(data),headers);r=c.getresponse();raw=r.read();h=dict(r.getheaders());code=r.status;c.close();return code,h,raw
 run(['sbox','webui','reset-admin']);pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
 code,h,data=api('auth/login',{'username':'admin','password':pw});assert code==200;cookie=h['Set-Cookie'].split(';')[0];csrf=json.loads(data)['csrf'];newpw='Private-Log-Probe-'+secrets.token_hex(12)
 code,h,data=api('auth/change-password',{'old':pw,'password':newpw});assert code==200;csrf=json.loads(data)['csrf'];sensitive=[pw,newpw,cookie.split('=',1)[1],csrf]
 badpw='Private-Failed-Login-'+secrets.token_hex(12);code,_,_=api('auth/login',{'username':'admin','password':badpw},peer='127.0.3.2');assert code in [401,429];sensitive.append(badpw)
 start_client(original,'burst');select(proxies[-1]['name']);sink=out/'active-stream.bin';f=sink.open('wb');stream=subprocess.Popen(['ip','netns','exec',ns,'curl','-fsS','--noproxy','','--proxy','http://127.0.0.1:'+str(mixed),'--max-time','40','http://198.51.100.10:18080/stream'],stdout=f,stderr=subprocess.DEVNULL)
 panelpid=int(run(['systemctl','show','sbox-webui','-p','MainPID','--value']).stdout)
 def rss():return int(next(x.split()[1] for x in Path('/proc/'+str(panelpid)+'/status').read_text().splitlines() if x.startswith('VmRSS:')))
 rss0=rss();times=[];codes=[]
 def hit(i):
  t=time.monotonic()
  try:code=api('dashboard',peer='127.0.4.'+str(i%200+1))[0]
  except (OSError,http.client.HTTPException):code='bounded-connection-refusal'
  return (time.monotonic()-t)*1000,code
 with concurrent.futures.ThreadPoolExecutor(100) as pool:
  for ms,code in pool.map(hit,range(400)):times.append(ms);codes.append(code)
 stream.wait(timeout=45);f.close();assert stream.returncode==0 and sink.stat().st_size==8388608;sink.unlink()
 assert all(c in [200,429,503,'bounded-connection-refusal'] for c in codes);assert 200 in codes;assert snapshot()==before;rss1=rss();assert rss1<160*1024 and rss1-rss0<100*1024
 assert int(run(['systemctl','show','sbox-webui','-p','MainPID','--value']).stdout)==panelpid
 record('BURST-100-CONCURRENT-400-REQUESTS',True,counts={str(c):codes.count(c) for c in set(codes)},p50_ms=statistics.median(times),p95_ms=sorted(times)[math.ceil(.95*len(times))-1],rss_before_kib=rss0,rss_after_kib=rss1,active_stream_bytes=8388608,core_unchanged=True)
 assert api('auth/logout',{})[0]==200
 def collect(v):
  if isinstance(v,dict):
   for key,value in v.items():
    if key in ['uuid','password','private_key'] and isinstance(value,str) and len(value)>=12:sensitive.append(value)
    collect(value)
  elif isinstance(v,list):
   for value in v:collect(value)
 collect(state);time.sleep(.3)
 logs=run(['journalctl','--no-pager','-u','sbox-webui','-u','sbox-webui-control','-u','sing-box']).stdout
 db=sqlite3.connect(cfg['database']);audit=json.dumps(db.execute('SELECT actor,event,detail FROM audit').fetchall());db.close();argv=b''
 for path in Path('/proc').glob('[0-9]*/cmdline'):
  try:argv+=path.read_bytes()+b'\n'
  except OSError:pass
 assert not any(secret in logs or secret in audit or secret.encode() in argv for secret in sensitive if len(secret)>=12)
 record('REAL-LOGIN-LOGOUT-SECRETS-ABSENT',True,secret_values_checked=len(set(sensitive)),journal_bytes_checked=len(logs.encode()),audit_bytes_checked=len(audit.encode()),argv_bytes_checked=len(argv),scope='Current boot journal for panel/bridge/core, actual auth lifecycle, audit rows and contemporaneous process argv; no claim about every future operation')
finally:
 if proc and proc.poll() is None:proc.terminate()
 for p in children:
  if p.poll() is None:p.terminate()
 Path('/etc/hosts').write_bytes(hosts)
 run(['ip','netns','del',ns],False);run(['ip','link','del','vpnhost'],False);run(['ip','route','del','203.0.113.80/32'],False);run(['ip','addr','del','198.51.100.10/32','dev','lo'],False);shutil.rmtree(nsdir,ignore_errors=True)
 run(['sbox','webui','start'],False)
sys.exit(any(x['status']=='FAIL' for x in rows))
