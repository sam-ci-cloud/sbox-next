"""Bounded optional VPS-origin TCP/TLS/DNS/ICMP probes, never remote commands.
DNS answers are pinned and checked before connections. Private/link-local targets
are forbidden; the sole local target is this installation's HTTPS endpoint.
"""
import concurrent.futures,ipaddress,re,socket,ssl,statistics,subprocess,time
from common import require
KINDS=('tcp','tls','dns','icmp','subscription')
def validate(targets):
 require(isinstance(targets,list) and len(targets)<=6,'Configure at most six probes')
 for t in targets:
  require(isinstance(t,dict) and set(t)<= {'kind','host','port','enabled','expected_ips'},'Unknown probe fields')
  if 'expected_ips' in t:
   ips=t['expected_ips'];require(t.get('kind')=='dns' and isinstance(ips,list) and 1<=len(ips)<=8,'Expected DNS addresses require 1–8 public IPs')
   try:valid=all(isinstance(a,str) and ipaddress.ip_address(a).is_global for a in ips)
   except ValueError:valid=False
   require(valid,'Expected DNS addresses must be public IP literals')
  require(t.get('kind') in KINDS and type(t.get('enabled',True)) is bool,'Invalid probe kind')
  require(isinstance(t.get('host'),str) and re.fullmatch(r'[A-Za-z0-9.-]{1,253}',t['host']) and not t['host'].startswith('-'),'Invalid probe hostname')
  require(type(t.get('port',443)) is int and 1<=t.get('port',443)<=65535,'Invalid probe port')
 return targets

def one(target,origin):
 start=time.time();host=target['host'];kind=target['kind'];port=target.get('port',443);result={'target':host,'kind':kind,'port':port,'sampled_at':start,'origin':'this VPS; not end-user path','status':'unavailable','latency_ms':None,'loss_percent':None,'jitter_ms':None}
 try:
  t=time.monotonic();answers=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM);dns_ms=(time.monotonic()-t)*1000;addresses=sorted({a[4][0] for a in answers});require(addresses,'No DNS answers')
  if kind=='subscription':require(host==origin['host'] and port==origin['port'],'Subscription readiness probes use only this installation endpoint');addresses=['127.0.0.1']
  else:require(all(ipaddress.ip_address(a).is_global for a in addresses),'Probe target resolves to a forbidden non-public address')
  result['dns_ms']=round(dns_ms,3)
  if kind=='dns':result.update(status='ok',latency_ms=round(dns_ms,3),answers=addresses,dns_mismatch=bool(target.get('expected_ips') and set(addresses)!=set(target['expected_ips'])));return result
  if kind=='icmp':
   binary='/usr/bin/ping';p=subprocess.run([binary,'-n','-c','3','-W','1','-w','4','--',addresses[0]],capture_output=True,text=True,timeout=5,env={'PATH':'/usr/bin:/bin','LANG':'C'})
   loss=re.search(r'([\d.]+)% packet loss',p.stdout);rtt=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',p.stdout)
   if loss:result['loss_percent']=float(loss[1])
   if rtt:result.update(latency_ms=float(rtt[2]),jitter_ms=float(rtt[4]),jitter_definition='ICMP RTT mdev over 3 replies; not one-way jitter')
   result['status']='ok' if p.returncode==0 else 'loss' if loss else 'unavailable';return result
  values=[];failed=0
  for _ in range(3):
   t=time.monotonic()
   try:
    with socket.create_connection((addresses[0],port),timeout=1.5) as sock:
     if kind in ('tls','subscription'):
      with ssl.create_default_context().wrap_socket(sock,server_hostname=host) as tls:
       if kind=='subscription':
        tls.sendall(('GET /api/v1/health HTTP/1.0\r\nHost: '+host+':'+str(port)+'\r\n\r\n').encode());reply=tls.recv(1024);require(b' 200 ' in reply.split(b'\r\n',1)[0],'HTTPS readiness failed')
    values.append((time.monotonic()-t)*1000)
   except (OSError,ValueError):failed+=1
  result.update(status='ok' if not failed else 'loss',latency_ms=round(statistics.mean(values),3) if values else None,loss_percent=round(failed/3*100,2),jitter_ms=round(statistics.pstdev(values),3) if values else None,jitter_definition='RTT population standard deviation over 3 connection attempts; failure rate is not ICMP packet loss')
 except Exception as e:result['reason']='Probe unavailable or target rejected: '+type(e).__name__
 return result

def collect(targets,origin):
 validate(targets)
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:return list(pool.map(lambda t:one(t,origin),[t for t in targets if t.get('enabled',True)]))
