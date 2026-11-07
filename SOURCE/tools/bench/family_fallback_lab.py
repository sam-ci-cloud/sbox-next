#!/usr/bin/env python3
"""Run ONLY inside a disposable isolated network namespace.
Requires root, loopback up and a namespace-local IPv6 SYN drop rule for port18080.
It neither creates host firewall rules nor changes kernel defaults.
"""
import argparse,hashlib,http.server,json,socket,struct,subprocess,tempfile,threading,time,statistics
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--core',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();assert hashlib.file_digest(a.core.open('rb'),'sha256').hexdigest()=='565bbe3a43ea7a0908e5929fc1720b9ccc7479a4ba4e45e56f3f93ac2b9b43d0'
 class H(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
 target=http.server.ThreadingHTTPServer(('127.0.0.1',18080),H);threading.Thread(target=target.serve_forever,daemon=True).start();dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',19053));dns.settimeout(.2);stop=threading.Event()
 def serve():
  while not stop.is_set():
   try:packet,peer=dns.recvfrom(4096)
   except socket.timeout:continue
   end=12
   while packet[end]:end+=packet[end]+1
   end+=1;kind=struct.unpack('!H',packet[end:end+2])[0];question=packet[12:end+4];body=socket.inet_pton(socket.AF_INET,'127.0.0.1') if kind==1 else socket.inet_pton(socket.AF_INET6,'::1') if kind==28 else b'';answer=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(body))+body if body else b'';dns.sendto(packet[:2]+struct.pack('!HHHHH',0x8180,1,1 if body else 0,0,0)+question+answer,peer)
 threading.Thread(target=serve,daemon=True).start();rows=[]
 try:
  with tempfile.TemporaryDirectory() as td:
   w=Path(td)
   for strategy in ['prefer_ipv6','prefer_ipv4']:
    for iteration,delay in enumerate([300,150,300,150]):
     config={'log':{'level':'error'},'dns':{'servers':[{'type':'udp','tag':'fixture','server':'127.0.0.1','server_port':19053}]},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':10880}],'outbounds':[{'type':'direct','tag':'direct','domain_resolver':{'server':'fixture','strategy':strategy},'fallback_delay':str(delay)+'ms'}],'route':{'final':'direct'}};p=w/'config.json';p.write_text(json.dumps(config));log=(w/'core.log').open('wb');core=subprocess.Popen([str(a.core),'run','-c',str(p)],stdout=log,stderr=log)
     try:
      for _ in range(100):
       if core.poll() is not None:raise RuntimeError((w/'core.log').read_text()[-1000:])
       try:
        with socket.create_connection(('127.0.0.1',10880),timeout=.1):break
       except OSError:time.sleep(.02)
      for sample in range(3):
       start=time.monotonic();result=subprocess.run(['curl','-q','-sS','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','3','http://latency.sbox.test:18080/'],capture_output=True,timeout=5);elapsed=(time.monotonic()-start)*1000;rows.append({'strategy':strategy,'fallback_delay_ms':delay,'iteration':iteration,'sample':sample,'elapsed_ms':round(elapsed,3),'status':'NEW_PASS' if result.returncode==0 and result.stdout==b'ok' else 'FAIL'})
     finally:core.terminate();core.wait(3);log.close()
  summary=[]
  for strategy in ['prefer_ipv6','prefer_ipv4']:
   for delay in [300,150]:
    values=[r['elapsed_ms'] for r in rows if r['strategy']==strategy and r['fallback_delay_ms']==delay and r['status']=='NEW_PASS'];summary.append({'strategy':strategy,'fallback_delay_ms':delay,'samples':len(values),'median_ms':statistics.median(values) if values else None})
  report={'scope':'ABAB controlled IPv6 SYN blackhole versus healthy IPv4 preference; isolated namespace only; HTTP through actual frozen core, no WAN RTT claim','rows':rows,'summary':summary,'core_sha256':'565bbe3a43ea7a0908e5929fc1720b9ccc7479a4ba4e45e56f3f93ac2b9b43d0'};a.output.write_text(json.dumps(report,indent=2)+'\n');assert all(r['status']=='NEW_PASS' for r in rows);print(json.dumps(summary))
 finally:stop.set();target.shutdown();target.server_close();dns.close()
if __name__=='__main__':main()
