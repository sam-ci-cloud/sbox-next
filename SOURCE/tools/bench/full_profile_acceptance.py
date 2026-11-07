#!/usr/bin/env python3
"""Real mixed-family generated-profile traffic; synthetic DNS/CA only.
Never patches a global IPv6 flag, node address, destination DNS family or rules.
Only resolver endpoints/local ports and explicit protocol group selection change.
"""
from pathlib import Path
import argparse,base64,copy,hashlib,http.client,http.server,importlib.util,json,os,secrets,shutil,socket,struct,subprocess,sys,threading,time,urllib.parse
import yaml
S=Path(__file__).resolve().parents[2];sys.path[:0]=[str(S/'tests'),str(S/'shared_webui/backend')]
import reality_fixture as fx
from export_json import convert
spec=importlib.util.spec_from_file_location('transport',Path(__file__).with_name('dual_stack_acceptance.py'));b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
PAYLOAD=hashlib.sha256(b'SBOX mixed family exact integrity').digest()*8192
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  self.send_response(200);self.send_header('Content-Length',str(len(PAYLOAD)));self.end_headers();self.wfile.write(PAYLOAD)
 def do_POST(self):
  data=self.rfile.read(int(self.headers['Content-Length']));body=json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
class H6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
class DNS:
 def __init__(self):
  self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.sock.bind(('127.0.0.1',0));self.sock.settimeout(.2);self.port=self.sock.getsockname()[1];self.node=6;self.target=4;self.queries=[];self.stop=False;threading.Thread(target=self.serve,daemon=True).start()
 def serve(self):
  while not self.stop:
   try:p,peer=self.sock.recvfrom(4096)
   except socket.timeout:continue
   except OSError:break
   end=12;labels=[]
   try:
    while p[end]:n=p[end];labels.append(p[end+1:end+1+n].decode());end+=n+1
    end+=1;kind=struct.unpack('!H',p[end:end+2])[0];name='.'.join(labels).lower();family=6 if kind==28 else 4 if kind==1 else 0;self.queries.append({'name':name,'type':kind});has=(name==fx.DOMAIN and family==self.node) or (name=='destination.sbox.test' and family==self.target);body=socket.inet_pton(socket.AF_INET6 if family==6 else socket.AF_INET,'::1' if family==6 else '127.0.0.1') if has else b'';answer=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,1,len(body))+body if body else b'';self.sock.sendto(p[:2]+struct.pack('!HHHHH',0x8180,1,bool(body),0,0)+p[12:end+4]+answer,peer)
   except (ValueError,IndexError,struct.error):continue
 def close(self):self.stop=True;self.sock.close()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--work',type=Path,required=True);ap.add_argument('--mihomo',type=Path,required=True);a=ap.parse_args();w=a.work.resolve();(w/'private').mkdir(parents=True,exist_ok=True,mode=0o700);(w/'evidence').mkdir(exist_ok=True);core=fx.core_binary();dns=DNS();ca,leaves=fx.lab_certificates(w/'private/certs');certs=ca.parent;(certs/'live').mkdir();shutil.copyfile(leaves[fx.DOMAIN][0],certs/'live/fullchain.pem');shutil.copyfile(leaves[fx.DOMAIN][1],certs/'live/privkey.pem');os.environ.update(SSL_CERT_FILE=str(ca),SSL_CERT_DIR=str(certs));h4=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);h6=H6(('::1',0),H)
 for h in [h4,h6]:threading.Thread(target=h.serve_forever,daemon=True).start()
 fp=b.free_port();fl=(w/'private/fallback.log').open('wb');fallback=subprocess.Popen(['openssl','s_server','-quiet','-accept','127.0.0.1:'+str(fp),'-cert',str(leaves[fx.DOMAIN][0]),'-key',str(leaves[fx.DOMAIN][1]),'-www'],stdout=fl,stderr=fl);priv,pub=fx.reality_keypair();rows=[]
 def emit(ok,**kv):rows.append({'status':'NEW_PASS' if ok else 'FAIL',**kv});(w/'evidence/results.json').write_text(json.dumps(rows,indent=2))
 try:
  for inbound,egress in [('ipv6','ipv4'),('ipv4','ipv6')]:
   mode_query_start=len(dns.queries);dns.node=6 if inbound=='ipv6' else 4;dns.target=6 if egress=='ipv6' else 4;state=fx.self_hosted(fx.base_state(priv,pub),port=fp);state['server'].update(mode=inbound,scope='internal',ipv4='127.0.0.1',ipv6='::1',listen='::1' if inbound=='ipv6' else '0.0.0.0',policies={'inbound':inbound,'egress':egress,'dns':egress,'client':inbound})
   for p in state['protocols'].values():p.update(enabled=True,port=b.free_port())
   out=fx.render(state,cert_dir=str(certs));server=json.loads((out/'server.json').read_text());server['dns']['servers']=[{'type':'udp','tag':'sbox-local','server':'127.0.0.1','server_port':dns.port}];sp=w/'private'/('server-'+inbound+'.json');sp.write_text(json.dumps(server));sl=sp.with_suffix('.log').open('wb');proc=subprocess.Popen([str(core),'run','-c',str(sp)],stdout=sl,stderr=sl)
   try:
    for _ in range(100):
     if proc.poll() is not None:raise RuntimeError('Server stopped; inspect private log')
     try:
      with socket.create_connection(('::1' if inbound=='ipv6' else '127.0.0.1',state['protocols']['reality']['port']),timeout=.1):break
     except OSError:time.sleep(.03)
    original=yaml.safe_load((out/'mihomo-internal.yaml').read_text());target='http://destination.sbox.test:'+str(h6.server_port if egress=='ipv6' else h4.server_port)
    for engine in ['mihomo','sing-box']:
     for node in original['proxies']:
      d=w/'private'/inbound/engine/node['type'];d.mkdir(parents=True);port=b.free_port();ctl=b.free_port();secret=secrets.token_urlsafe(24)
      if engine=='mihomo':
       cfg=copy.deepcopy(original);cfg.update({'mixed-port':port,'external-controller':'127.0.0.1:'+str(ctl),'secret':secret,'geo-auto-update':False,'profile':{'store-selected':False}});cfg['dns'].update({'listen':'127.0.0.1:'+str(b.free_port()),'default-nameserver':['127.0.0.1:'+str(dns.port)],'nameserver':['udp://127.0.0.1:'+str(dns.port)],'proxy-server-nameserver':['udp://127.0.0.1:'+str(dns.port)]})
       for g in cfg['proxy-groups']:
        if g['type'] in ('url-test','fallback'):g.update(lazy=True,interval=0)
       path=d/'config.yaml';path.write_text(yaml.safe_dump(cfg,allow_unicode=True));cmd=[str(a.mihomo.resolve()),'-d',str(d),'-f',str(path)]
      else:
       cfg=convert(original,family_split=False);cfg['inbounds'][0]['listen_port']=port;cfg['dns']['servers']=[{'type':'udp','tag':'sbox-client-local','server':'127.0.0.1','server_port':dns.port}];cfg['route']['final']=node['name'];path=d/'client.json';path.write_text(json.dumps(cfg));cmd=[str(core),'run','-c',str(path)]
      path.chmod(0o600);cl=(d/'client.log').open('wb');client=subprocess.Popen(cmd,stdout=cl,stderr=cl);start=len(dns.queries)
      try:
       ready=False
       for _ in range(100):
        if client.poll() is not None:raise RuntimeError('Client stopped; inspect private log')
        try:
         with socket.create_connection(('127.0.0.1',port),timeout=.1):
          if b.owns_listener(client.pid,port) and (engine!='mihomo' or b.mihomo_config_barrier(client.pid,ctl,secret,path)):ready=True;break
        except (OSError,http.client.HTTPException):pass
        time.sleep(.03)
       if not ready:raise RuntimeError('Application readiness not reached')
       if engine=='mihomo':
        for group,selected in [('🔒 LOCK',node['name']),('🚀 VPN','🔒 LOCK')]:
         c=http.client.HTTPConnection('127.0.0.1',ctl,timeout=3);c.request('PUT','/proxies/'+urllib.parse.quote(group,safe=''),json.dumps({'name':selected}),{'Authorization':'Bearer '+secret,'Content-Type':'application/json'});r=c.getresponse();r.read();assert r.status==204;r.close();c.close()
       def request(upload=False):return subprocess.run(['curl','-q','-sS','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'--max-time','8',target]+(['--data-binary','@'+str(w/'private/upload.bin')] if upload else []),capture_output=True,timeout=10)
       (w/'private/upload.bin').write_bytes(PAYLOAD);r=request();emit(r.returncode==0 and r.stdout==PAYLOAD,inbound=inbound,egress=egress,engine=engine,protocol=node['type'],test='256KiB-download',curl_exit=r.returncode)
       r=request(True)
       try:ok=json.loads(r.stdout)=={'bytes':len(PAYLOAD),'sha256':hashlib.sha256(PAYLOAD).hexdigest()}
       except ValueError:ok=False
       emit(r.returncode==0 and ok,inbound=inbound,egress=egress,engine=engine,protocol=node['type'],test='256KiB-upload',curl_exit=r.returncode)
       emit(any(q['name']=='destination.sbox.test' for q in dns.queries[mode_query_start:]),inbound=inbound,egress=egress,engine=engine,protocol=node['type'],test='destination-DNS-observed-or-shared-core-cache')
      finally:b.stop(client,cl)
   finally:
    (w/'evidence'/('dns-'+inbound+'.json')).write_text(json.dumps(dns.queries[mode_query_start:],indent=2));b.stop(proc,sl)
 finally:
  b.stop(fallback,fl);dns.close()
  for h in [h4,h6]:h.shutdown();h.server_close()
 report={'scope':'Isolated loopback mixed-family full generated INTERNAL Mihomo/native JSON; node hostname only-one-family and opposite-family destination hostname. No host DNS/TUN/firewall modifications.','core_sha256':hashlib.file_digest(core.open('rb'),'sha256').hexdigest(),'engine':subprocess.check_output([str(a.mihomo.resolve()),'-v'],text=True).splitlines()[0],'passed':sum(r['status']=='NEW_PASS' for r in rows),'failed':sum(r['status']=='FAIL' for r in rows),'rows':rows};(w/'evidence/summary.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k!='rows'}));return bool(report['failed'])
if __name__=='__main__':sys.exit(main())
