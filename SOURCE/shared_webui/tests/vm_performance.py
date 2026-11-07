"""Installed guest: real TLS latency and bounded resource measurement."""
from pathlib import Path
import concurrent.futures,http.client,json,ssl,socket,subprocess,sys,time,statistics,os
assert Path('/root/lab-ready').is_file()
cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text());domain=cfg['origin'].split('://')[1].rsplit(':',1)[0];port=cfg['port'];out=Path(sys.argv[1]);out.parent.mkdir(parents=True,exist_ok=True)
ctx=ssl.create_default_context()
def run(args):return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).strip()
def pid(unit):return int(run(['systemctl','show',unit,'-p','MainPID','--value']))
core=pid('sing-box');tick=os.sysconf('SC_CLK_TCK')
class HTTPS(http.client.HTTPSConnection):
 def __init__(self,peer='127.0.0.1'):super().__init__(domain,port,context=ctx,timeout=60);self.peer=peer
 def connect(self):self.sock=ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=60,source_address=(self.peer,0)),server_hostname=domain)
def req(path,body=None,cookie='',csrf='',peer='127.0.0.1'):
 c=HTTPS(peer);h={'Host':domain+':'+str(port),'Cookie':cookie,'X-CSRF-Token':csrf}
 if body is not None:h['Content-Type']='application/json'
 c.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,h);r=c.getresponse();data=r.read();head=dict(r.getheaders());code=r.status;c.close();return code,head,data

def sample():
 d={}
 for unit in ['sbox-webui','sbox-webui-control','sing-box']:
  p=pid(unit);status=Path('/proc/'+str(p)+'/status').read_text();rss=int(__import__('re').search(r'VmRSS:\s+(\d+)',status)[1]);stat=Path('/proc/'+str(p)+'/stat').read_text().split();d[unit]={'pid':p,'rss_kib':rss,'cpu_ticks':int(stat[13])+int(stat[14])}
 return d
res={'environment':run(['uname','-a']),'os':Path('/etc/os-release').read_text(),'vcpus':os.cpu_count(),'memory_total_kib':int(Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),'manager':run(['sbox','version']),'TLS':'verified private lab CA, not Internet PKI','core_pid_before':core}
ready=[]
for _ in range(3):
 subprocess.run(['systemctl','reset-failed','sbox-webui'],check=True)
 t=time.monotonic();subprocess.run(['systemctl','restart','sbox-webui'],check=True,stdout=subprocess.DEVNULL)
 while True:
  try:
   if req('/')[0]==200:break
  except Exception:pass
  if time.monotonic()-t>40:raise RuntimeError('HTTPS readiness timeout')
  time.sleep(.02)
 ready.append(round((time.monotonic()-t)*1000,2))
res['https_ready_ms']=ready
subprocess.run(['sbox','webui','reset-admin'],check=True,stdout=subprocess.DEVNULL)
pw=Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0]
code,h,b=req('/api/v1/auth/login',{'username':'admin','password':pw});assert code==200
v=json.loads(b);cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];code,h,b=req('/api/v1/auth/change-password',{'old':pw,'password':'Performance-SYNTHETIC-only-2026'},cookie,csrf);assert code==200;csrf=json.loads(b)['csrf']
for concurrency,count in [(1,100),(10,600)]:
 vals=[];errors=[]
 def client(i):
  result=[]
  for _ in range(count//concurrency):
   t=time.monotonic();code,_,b=req('/api/v1/dashboard',cookie=cookie,peer='127.0.1.'+str(i+1));result.append(((time.monotonic()-t)*1000,code))
  return result
 with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
  for group in pool.map(client,range(concurrency)):
   for ms,code in group:vals.append(ms);errors.extend([] if code==200 else [code])
 vals.sort();res['clients_'+str(concurrency)]={'requests':len(vals),'p50_ms':round(statistics.median(vals),2),'p95_ms':round(vals[int(.95*(len(vals)-1))],2),'errors':errors}
res['resource_start']=sample();res['db_bytes']=Path(cfg['database']).stat().st_size;res['core_pid_after']=pid('sing-box');assert res['core_pid_after']==core
out.write_text(json.dumps(res,indent=2));print(json.dumps({k:v for k,v in res.items() if k in ('https_ready_ms','clients_1','clients_10')}),flush=True)
if len(sys.argv)>2:
 idle=int(sys.argv[2]);start=time.monotonic();samples=[{'elapsed':0,'processes':sample()}]
 while time.monotonic()-start<idle:
  time.sleep(min(30,idle-(time.monotonic()-start)));samples.append({'elapsed':round(time.monotonic()-start,1),'processes':sample()});res['idle_samples']=samples;res['idle_seconds']=round(time.monotonic()-start,1);res['core_pid_after_idle']=pid('sing-box');out.write_text(json.dumps(res,indent=2))
 res['idle_cpu_percent']={unit:round((samples[-1]['processes'][unit]['cpu_ticks']-samples[0]['processes'][unit]['cpu_ticks'])/tick/res['idle_seconds']*100,4) for unit in samples[0]['processes']};out.write_text(json.dumps(res,indent=2));print('IDLE COMPLETE',res['idle_seconds'],flush=True)
