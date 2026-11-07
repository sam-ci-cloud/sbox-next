#!/usr/bin/env python3
"""Capped HTTP+SOCKS5 TCP/UDP workload against a private lab/allowlisted endpoint."""
import argparse,http.server,ipaddress,json,math,socket,struct,threading,time,statistics,urllib.parse

def recv(s,n):
    b=b''
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:raise EOFError('short response')
        b+=c
    return b

def socks(host,port,target,tport,udp=False):
    s=socket.create_connection((host,port),timeout=8);s.settimeout(8)
    s.sendall(b'\x05\x01\x00');assert recv(s,2)==b'\x05\x00'
    s.sendall(b'\x05'+(b'\x03' if udp else b'\x01')+b'\x00\x01'+socket.inet_aton(target)+struct.pack('!H',tport))
    h=recv(s,4);assert h[:2]==b'\x05\x00',repr(h)
    addr=socket.inet_ntoa(recv(s,4)) if h[3]==1 else socket.inet_ntop(socket.AF_INET6,recv(s,16))
    port=struct.unpack('!H',recv(s,2))[0]
    return s,(addr,port)

def pct(values,q):
    if not values:return None
    return sorted(values)[max(0,math.ceil(q*len(values))-1)]

def server(host,port,udpport,allow_clients=''):
    allowed={str(ipaddress.ip_address(ip)) for ip in allow_clients.split(',') if ip}
    address=ipaddress.ip_address(host)
    if address.is_unspecified or (not address.is_private and not address.is_loopback and not allowed):raise ValueError('bind a private/loopback address or supply --allow-client IP[,IP]')
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_GET(self):
            path=urllib.parse.urlparse(self.path);n=int(urllib.parse.parse_qs(path.query).get('bytes',['0'])[0]);n=min(max(n,0),64*1024*1024)
            self.send_response(204 if path.path=='/204' else 200);self.send_header('Content-Length',str(n));self.end_headers()
            data=b'x'*65536
            while n:
                b=data[:min(n,len(data))];self.wfile.write(b);n-=len(b)
        def do_POST(self):
            n=int(self.headers.get('Content-Length',0)); assert 0<=n<=64*1024*1024
            read=0
            while read<n:
                b=self.rfile.read(min(65536,n-read))
                if not b:raise EOFError()
                read+=len(b)
            body=str(read).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def udp():
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((host,udpport))
        while True:
            b,a=s.recvfrom(4096)
            if not allowed or a[0] in allowed:s.sendto(b,a)
    class AllowedServer(http.server.ThreadingHTTPServer):
        request_queue_size=256
        daemon_threads=True
        def verify_request(self,request,client_address):return not allowed or client_address[0] in allowed
    threading.Thread(target=udp,daemon=True).start();AllowedServer((host,port),Handler).serve_forever()

def workload(a):
    def connect():
        if a.socks:return socks(a.socks,a.socks_port,a.target,a.port)[0]
        return socket.create_connection((a.target,a.port),timeout=8)
    def request(n=0,upload=False):
        start=time.monotonic();s=connect();connected=time.monotonic();s.settimeout(15)
        req=(f'POST /upload HTTP/1.0\r\nHost: lab\r\nContent-Length: {n}\r\n\r\n' if upload else f'GET /download?bytes={n} HTTP/1.0\r\nHost: lab\r\n\r\n').encode();s.sendall(req)
        if upload:
            data=b'x'*65536;remain=n
            while remain:
                b=data[:min(remain,len(data))];s.sendall(b);remain-=len(b)
        first=None;buf=bytearray()
        while True:
            b=s.recv(65536)
            if not b:break
            if first is None:first=time.monotonic()
            buf.extend(b)
        s.close();end=time.monotonic();head,body=bytes(buf).split(b'\r\n\r\n',1)
        assert head.startswith(b'HTTP/1.0 200')
        if upload:assert int(body)==n
        else:assert len(body)==n,(len(body),n)
        return {'seconds':end-start,'connect_ms':1000*(connected-start),'ttfb_ms':1000*(first-start),'mbps':n*8/(end-start)/1e6,'bytes':n}
    browse=[request() for _ in range(12)]
    downloads=[request(a.bytes) for _ in range(a.runs)];uploads=[request(a.bytes,True) for _ in range(a.runs)]
    if a.socks:
        control,relay=socks(a.socks,a.socks_port,'0.0.0.0',0,True)
        if relay[0] in ('0.0.0.0','::'):relay=(a.socks,relay[1])
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.settimeout(.1)
        header=b'\x00\x00\x00\x01'+socket.inet_aton(a.target)+struct.pack('!H',a.udp_port)
    else:control=None;udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.settimeout(.1);relay=(a.target,a.udp_port);header=b''
    latencies=[];received_times=[];seen=set();sent={};send_errors=[];udp_start=time.monotonic();end=udp_start+a.udp_seconds
    def send():
        start=time.monotonic();seq=0
        while time.monotonic()<end:
            sent[seq]=time.monotonic()
            try:udp.sendto(header+struct.pack('!I',seq)+b'x'*156,relay)
            except OSError as e:send_errors.append({'sequence':seq,'errno':e.errno})
            seq+=1;time.sleep(max(0,start+seq/50-time.monotonic()))
    thread=threading.Thread(target=send);thread.start()
    # TCP concurrent load and voice-like UDP share the shaped link.
    load_result=[]
    def load():
        try:load_result.append(request(a.bytes))
        except Exception as e:load_result.append({'error':str(e)})
    load_thread=threading.Thread(target=load);load_thread.start()
    while time.monotonic()<end+1:
        try:
            b=udp.recv(4096);seq=struct.unpack('!I',b[-160:-156])[0]
            if seq in sent and seq not in seen:latencies.append(1000*(time.monotonic()-sent[seq]));received_times.append(time.monotonic());seen.add(seq)
        except socket.timeout:pass
    thread.join();load_thread.join();udp.close()
    if control:control.close()
    if not latencies:raise RuntimeError('UDP relay delivered no packets')
    return {'source':'VM-shaped-veth','target':a.target,'runs':a.runs,'bytes_per_transfer':a.bytes,'download_runs':downloads,'upload_runs':uploads,'browsing':{'connect_p50_ms':statistics.median(x['connect_ms'] for x in browse),'ttfb_p95_ms':pct([x['ttfb_ms'] for x in browse],.95)},'udp_under_tcp_load':{'attempted':len(sent),'sent':len(sent)-len(send_errors),'send_errors':len(send_errors),'max_receive_gap_ms':1000*max([received_times[0]-udp_start,max(0,end-received_times[-1])]+[y-x for x,y in zip(received_times,received_times[1:])]),'terminal_gap_seconds':max(0,end-received_times[-1]),'quality_gate':{'delivery_fraction_at_least_90_percent':len(seen)>=.9*len(sent),'terminal_gap_under_2_seconds':max(0,end-received_times[-1])<2},'received':len(seen),'loss_percent':100*(len(sent)-len(seen))/len(sent),'rtt_p50_ms':statistics.median(latencies),'rtt_p95_ms':pct(latencies,.95),'jitter_mean_abs_ms':statistics.mean(abs(x-y) for x,y in zip(latencies,latencies[1:])) if len(latencies)>1 else 0},'concurrent_download':load_result}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['server','client']);p.add_argument('--target',default='10.78.0.1');p.add_argument('--port',type=int,default=18081);p.add_argument('--udp-port',type=int,default=18082);p.add_argument('--allow-client',default='');p.add_argument('--socks');p.add_argument('--socks-port',type=int,default=17890);p.add_argument('--bytes',type=int,default=4*1024*1024);p.add_argument('--runs',type=int,default=3);p.add_argument('--udp-seconds',type=float,default=6)
    a=p.parse_args();assert 1<=a.runs<=20 and 0<a.bytes<=64*1024*1024 and 0<a.udp_seconds<=3600
    if a.action=='server':server(a.target,a.port,a.udp_port,a.allow_client)
    else:
        result=workload(a);print(json.dumps(result,indent=2))
        if not all(result['udp_under_tcp_load']['quality_gate'].values()):raise SystemExit(2)
