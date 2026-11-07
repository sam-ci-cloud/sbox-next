#!/usr/bin/python3
"""Bounded routed dual-stack acceptance; private configs/logs, sanitized JSONL evidence."""
import tempfile,fcntl,re,http.client,secrets
import argparse,copy,hashlib,json,os,socket,struct,subprocess,sys,time,uuid
from pathlib import Path
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'shared_webui/backend'));from export_json import convert
CORE=os.environ.get('SBOX_BENCH_CORE','/usr/local/lib/sbox-manager/sing-box');W=Path('/root/singbox-optimized-campaign');TARGET_PORT=int(os.environ.get('SBOX_BENCH_TARGET_PORT','18080'));UDP_PORT=int(os.environ.get('SBOX_BENCH_UDP_PORT','18081'))
PAYLOAD=hashlib.sha256(b'sbox-public-integrity').digest()*32768
names={'vless':'reality','vmess':'vmess','hysteria2':'hy2','tuic':'tuic','anytls':'anytls'}
def curl(port,target,path='/payload',upload=False,timeout=12):
 fd,name=tempfile.mkstemp(prefix='response-',dir=W/'private');os.close(fd);out=Path(name)
 args=['curl','-sS','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'--max-time',str(timeout),'-o',str(out),'-w','%{json}',target+path]
 if upload:args+=['--data-binary','@'+str(W/'private/upload.bin')]
 start=time.monotonic()
 try:p=subprocess.run(args,capture_output=True,timeout=timeout+3)
 except BaseException:
  out.unlink(missing_ok=True);raise
 try:m=json.loads(p.stdout)
 except ValueError:m={}
 data=out.read_bytes() if out.exists() else b''
 out.unlink(missing_ok=True)
 return p.returncode,data,{'elapsed_ms':round((time.monotonic()-start)*1000,3),'ttfb_ms':round(m.get('time_starttransfer',0)*1000,3),'total_ms':round(m.get('time_total',0)*1000,3),'http':m.get('http_code'),'bytes':len(data),'curl_exit':p.returncode,'error_class':{5:'proxy DNS',6:'destination DNS',7:'TCP connect',28:'timeout',35:'TLS handshake',56:'receive',60:'certificate',97:'SOCKS negotiation'}.get(p.returncode,'none' if p.returncode==0 else 'curl error')}
def udp(port,target):
 c=socket.create_connection(('127.0.0.1',port),timeout=3);c.sendall(b'\x05\x01\x00');assert c.recv(2)==b'\x05\x00'
 c.sendall(b'\x05\x03\x00\x01'+b'\x00'*6);h=c.recv(64);assert h[1]==0
 if h[3]==1:offset=8;addr=socket.inet_ntop(socket.AF_INET,h[4:8])
 elif h[3]==4:offset=20;addr=socket.inet_ntop(socket.AF_INET6,h[4:20])
 else:raise ValueError('Unexpected SOCKS relay address')
 relay=('127.0.0.1' if addr in ('0.0.0.0','::') else addr,struct.unpack('!H',h[offset:offset+2])[0]);u=socket.socket(socket.AF_INET6 if ':' in relay[0] else socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(5)
 addrbody=(b'\x04'+socket.inet_pton(socket.AF_INET6,target)) if ':' in target else b'\x01'+socket.inet_aton(target)
 ok=0;lat=[]
 try:
  for i in range(3):
   data=('sbox-udp-%d'%i).encode();start=time.monotonic();u.sendto(b'\x00\x00\x00'+addrbody+struct.pack('!H',UDP_PORT)+data,relay);r,_=u.recvfrom(65535);ok+=r.endswith(b'echo:'+data);lat.append(round((time.monotonic()-start)*1000,3))
 finally:c.close();u.close()
 return ok==3,lat

def free_port():
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def owns_listener(pid,port):
 inodes=set()
 for table in ('tcp','tcp6'):
  for line in Path('/proc/net/'+table).read_text().splitlines()[1:]:
   fields=line.split()
   if int(fields[1].split(':')[1],16)==port and fields[3]=='0A':inodes.add(fields[9])
 for fd in Path('/proc/'+str(pid)+'/fd').iterdir():
  try:
   link=os.readlink(fd)
   if link.startswith('socket:[') and link[8:-1] in inodes:return True
  except (OSError,FileNotFoundError):pass
 return False

def mihomo_config_barrier(pid,control_port,secret,path):
 # ApplyConfig opens listeners before loadProvider/runtime.GC/OnRunning.
 # An authenticated identical-config PUT returns after that transition;
 # it never dials a VPN or touches an owner's existing client process.
 if not owns_listener(pid,control_port):return False
 conn=http.client.HTTPConnection('127.0.0.1',control_port,timeout=5)
 try:
  conn.request('PUT','/configs?force=false',json.dumps({'path':str(path.resolve())}),{'Content-Type':'application/json','Authorization':'Bearer '+secret})
  response=conn.getresponse();response.read(65536)
  if response.status!=204:raise RuntimeError('Mihomo configuration readiness barrier rejected')
  return True
 finally:conn.close()

def start(engine,proxy,addr,port,work,wrong=False):
 with socket.socket() as guard:
  try:guard.bind(('127.0.0.1',port))
  except OSError as e:raise RuntimeError('client port occupied; refusing unrelated listener') from e
 p=copy.deepcopy(proxy);p['server']=addr
 if wrong:
  if 'uuid' in p:p['uuid']='00000000-0000-4000-8000-000000000000'
  elif 'password' in p:p['password']='negative-control-invalid-password'
 work.mkdir(mode=0o700,parents=True,exist_ok=True)
 work.chmod(0o700)
 if engine=='sing-box':
  o=convert({'proxies':[p]},family_split=False)['outbounds'][0];cfg={'log':{'level':'warn'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':port}],'outbounds':[o],'route':{'final':o['tag']}}
  path=work/'config.json';path.write_text(json.dumps(cfg));cmd=[CORE,'run','-c',str(path)]
 else:
  control_port=free_port()
  while control_port==port:control_port=free_port()
  control_secret=secrets.token_urlsafe(32)
  cfg={'external-controller':'127.0.0.1:'+str(control_port),'secret':control_secret,'mixed-port':port,'bind-address':'127.0.0.1','allow-lan':False,'mode':'rule','ipv6':True,'log-level':'warning','dns':{'enable':False},'proxies':[p],'rules':['MATCH,'+p['name']]}
  path=work/'config.yaml';path.write_text(yaml.safe_dump(cfg));cmd=[str(W/'mihomo'),'-d',str(work),'-f',str(path)]
 interface=os.environ.get('SBOX_BENCH_INTERFACE','')
 if interface:
  if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',interface):raise ValueError('Invalid explicitly selected benchmark interface')
  socket.if_nametoindex(interface)
  if engine=='mihomo':cfg['interface-name']=interface;path.write_text(yaml.safe_dump(cfg))
  else:cfg['outbounds'][0]['bind_interface']=interface;path.write_text(json.dumps(cfg))
 path.chmod(0o600);log=(work/'client.log').open('wb')
 try:proc=subprocess.Popen(cmd,stdout=log,stderr=log)
 except BaseException:log.close();raise
 try:
  for _ in range(50):
   if proc.poll() is not None:raise RuntimeError('client failed to start; see private client.log')
   try:
    with socket.create_connection(('127.0.0.1',port),timeout=.1):
     if owns_listener(proc.pid,port):
      if engine!='mihomo' or mihomo_config_barrier(proc.pid,control_port,control_secret,path):return proc,log
   except OSError:pass
   time.sleep(.05)
  raise RuntimeError('client listener not owned by launched process')
 except BaseException:
  stop(proc,log);raise

def stop(proc,log):
 proc.terminate()
 try:proc.wait(5)
 except subprocess.TimeoutExpired:proc.kill();proc.wait()
 log.close()
def main():
 global W
 a=argparse.ArgumentParser();a.add_argument('--work',type=Path,default=W);a.add_argument('--label',default='baseline');a.add_argument('--peer4',required=True);a.add_argument('--peer6',required=True);a.add_argument('--self4',required=True);a.add_argument('--self6',required=True);a.add_argument('--samples',type=int,default=3);a.add_argument('--large',action='store_true');a.add_argument('--resume-from');a.add_argument('--only-wrong',action='store_true',help='Run only credential rejection; retain valid positive evidence');a.add_argument('--engines',default='sing-box,mihomo');a.add_argument('--protocols',default='reality,vmess,hy2,tuic,anytls');a.add_argument('--families',default='ipv4,ipv6');args=a.parse_args();W=args.work.resolve()
 engines=args.engines.split(',');protocols=args.protocols.split(',');families=args.families.split(',')
 if not set(engines)<=set(['sing-box','mihomo']) or not set(protocols)<=set(names.values()) or not set(families)<=set(['ipv4','ipv6']):a.error('Unknown engine, protocol or address family')
 if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',args.label):a.error('Unsafe evidence label')
 lock=(W/'evidence'/(args.label+'.lock')).open('a')
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:a.error('This evidence label is already running')
 profile=yaml.safe_load((W/'private/server-profile.yaml').read_text());(W/'private/upload.bin').write_bytes(PAYLOAD)
 previous=[json.loads(x) for x in (W/'evidence'/(args.resume_from+'-wan.jsonl')).read_text().splitlines()] if args.resume_from else []
 rows=[];f=(W/'evidence'/(args.label+'-wan.jsonl')).open('w')
 def emit(test,ok,**kv):
  row={'label':args.label,'test':test,'status':'PASS' if ok else 'FAIL',**kv};rows.append(row);f.write(json.dumps(row)+'\n');f.flush();print(json.dumps(row),flush=True)
 for family,addr,target in [('ipv4',args.peer4,args.self4),('ipv6',args.peer6,args.self6)]:
  if family not in families:continue
  base='http://'+('['+target+']' if ':' in target else target)+':'+str(TARGET_PORT)
  for engine in engines:
   for p in profile['proxies']:
    proto=names[p['type']]
    if proto not in protocols:continue
    old=[x for x in previous if x.get('family')==family and x.get('engine')==engine and x.get('protocol')==proto]
    if len(old)>=args.samples+4 and all(x['status']=='PASS' for x in old):continue
    port=free_port();ctx={'family':family,'engine':engine,'protocol':proto};work=W/'private'/args.label/(family+'-'+engine+'-'+proto)
    proc=log=None
    if not args.only_wrong:
     try:
      proc,log=start(engine,p,addr,port,work)
      for i in range(args.samples):
       rc,data,timing=curl(port,base,'/health');emit('cold-health' if i==0 else 'warm-health',rc==0 and data==b'ok',sample=i,**ctx,**timing)
      rc,data,timing=curl(port,base,'/large' if args.large else '/payload');expected=PAYLOAD*16 if args.large else PAYLOAD;emit('download-integrity',rc==0 and data==expected,sha256=hashlib.sha256(data).hexdigest(),**ctx,**timing)
      rc,data,timing=curl(port,base,upload=True)
      try:got=json.loads(data);ok=got=={'bytes':len(PAYLOAD),'sha256':hashlib.sha256(PAYLOAD).hexdigest()}
      except ValueError:ok=False
      emit('upload-integrity',rc==0 and ok,**ctx,**timing)
      try:ok,lat=udp(port,target);emit('udp-echo',ok,datagrams=3,rtt_ms=lat,**ctx)
      except Exception as e:emit('udp-echo',False,error=type(e).__name__,**ctx)
     except Exception as e:emit('client-start',False,error=str(e),**ctx)
     finally:
      if proc:stop(proc,log)
    proc=log=None
    try:
     port=free_port();proc,log=start(engine,p,addr,port,work/'wrong-auth',True);rc,data,timing=curl(port,base,'/health',timeout=4);emit('wrong-credentials',rc!=0 and data!=b'ok',**ctx)
    except Exception as e:emit('wrong-credentials',False,error=str(e),**ctx)
    finally:
     if proc:stop(proc,log)
 f.close();summary={'status':'PASS' if rows and all(x['status']=='PASS' for x in rows) else 'FAIL','rows':len(rows),'failed':[r for r in rows if r['status']=='FAIL'],'core_sha256':hashlib.sha256(Path(CORE).read_bytes()).hexdigest(),'client_mihomo':subprocess.check_output([str(W/'mihomo'),'-v'],text=True).splitlines()[0]};(W/'evidence'/(args.label+'-wan-summary.json')).write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary));return 0 if summary['status']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
