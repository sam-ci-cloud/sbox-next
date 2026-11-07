"""Real large journal and local-only HTTPS alerts in a marked disposable VM.
The public IP is routed only to a private network namespace, never the Internet.
"""
import hashlib,http.client,json,os,pathlib,signal,ssl,subprocess,sys,time
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
os.umask(0o077);out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);rows=[];cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());cookie='';csrf='';server=None;oldhosts=pathlib.Path('/etc/hosts').read_text();ca=pathlib.Path('/usr/local/share/ca-certificates/sbox-notify-disposable.crt')
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=180,**kw).stdout
def pid(unit='sing-box'):return run(['systemctl','show',unit,'-p','MainPID','--value']).strip()
def req(p,data=None,status=200):
 c=http.client.HTTPSConnection('127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=180);c.request('POST' if data is not None else 'GET','/api/v1/'+p,json.dumps(data) if data is not None else None,{'Host':cfg['origin'].split('://')[1],'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf});r=c.getresponse();v=json.loads(r.read());h=dict(r.getheaders());assert r.status==status,(p,r.status,str(v)[:300]);c.close();return v,h
def api(p,d=None,**kw):return req(p,d,**kw)[0]
def record(name,**facts):rows.append({'test':name,'status':'PASS',**facts});(out/'observability.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',name,flush=True)
run(['runuser','-u','sbox-webui','--','python3','-c',"import sqlite3;d=sqlite3.connect('/var/lib/sbox-webui/panel.db');d.execute(\"DELETE FROM settings WHERE key IN ('notification-last','alert-silence-until')\");d.execute('DELETE FROM alerts');d.commit()"]);(out/'events.jsonl').unlink(missing_ok=True)
run(['sbox','webui','reset-admin']);pw=pathlib.Path('/etc/sbox-webui/bootstrap-admin.txt').read_text().split('Password: ')[1].splitlines()[0];v,h=req('auth/login',{'username':'admin','password':pw});cookie=h['Set-Cookie'].split(';')[0];csrf=v['csrf'];csrf=api('auth/change-password',{'old':pw,'password':'Lab-verified-password-2026'})['csrf'];before=pid()
# Put a test-only logger in the core cgroup so journald attributes its genuine
# entries to the service. No core source/config/PID is changed.
code="""import os,time
from pathlib import Path
Path('/sys/fs/cgroup/system.slice/sing-box.service/cgroup.procs').write_text(str(os.getpid()))
from systemd import journal
time.sleep(31) # respect the existing per-service journal rate window
for i in range(600):
 journal.send(MESSAGE='SBOX_LAB_BOUNDED_LOG_HISTORY '+str(i)+' '+('x'*22000),PRIORITY='4')
 if i%100==0:time.sleep(.01)
time.sleep(31)
for i in range(200):journal.send(MESSAGE='SBOX_LAB_BOUNDED_LOG_TAIL '+str(i)+' password=SYNTHETIC_LOG_SECRET '+('x'*2048),PRIORITY='4')
"""
run(['python3','-c',code]);run(['journalctl','--sync']);history=run(['journalctl','--no-pager','-u','sing-box.service','-o','cat']);size=len(history.encode());assert size>10*1024*1024
logs=api('logs');assert len(logs['text'].splitlines())<=200 and len(json.dumps(logs).encode())<1048576 and 'SYNTHETIC_LOG_SECRET' not in logs['text'];assert pid()==before
record('Actual journal over 10 MiB yields bounded redacted API tail without core restart',journal_bytes=size,returned_lines=len(logs['text'].splitlines()),returned_bytes=len(json.dumps(logs).encode()))
archive=run(['sbox','backup']).strip();state=json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text());domain=state['domain'];legacy=state['protocols']
def cert(name,hostname,days):
 key=out/(name+'.key');pem=out/(name+'.pem');csr=out/(name+'.csr');ext=out/(name+'.ext');ext.write_text('subjectAltName=DNS:'+hostname+'\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n');run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+hostname,'-keyout',str(key),'-out',str(csr)]);run(['openssl','x509','-req','-in',str(csr),'-CA',str(out/'ca.crt'),'-CAkey',str(out/'ca.key'),'-CAcreateserial','-days',str(days),'-extfile',str(ext),'-out',str(pem)]);pem.write_bytes(pem.read_bytes()+(out/'ca.crt').read_bytes());return pem,key
try:
 run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','20','-subj','/CN=SBOX DISPOSABLE ALERT LAB ONLY','-keyout',str(out/'ca.key'),'-out',str(out/'ca.crt')]);ca.write_bytes((out/'ca.crt').read_bytes());ca.chmod(0o644);run(['update-ca-certificates']);pem,key=cert('receiver','alerts.sbox.test',10)
 run(['ip','netns','add','sbox-notify']);run(['ip','link','add','nfhost','type','veth','peer','name','nfpeer']);run(['ip','link','set','nfpeer','netns','sbox-notify']);run(['ip','addr','add','198.19.102.1/30','dev','nfhost']);run(['ip','link','set','nfhost','up']);run(['ip','-n','sbox-notify','addr','add','198.19.102.2/30','dev','nfpeer']);run(['ip','-n','sbox-notify','link','set','nfpeer','up']);run(['ip','-n','sbox-notify','link','set','lo','up']);run(['ip','-n','sbox-notify','addr','add','1.1.1.2/32','dev','lo']);run(['ip','-n','sbox-notify','route','add','default','via','198.19.102.1']);run(['ip','route','add','1.1.1.2/32','via','198.19.102.2','dev','nfhost']);pathlib.Path('/etc/hosts').write_text(oldhosts+'\n1.1.1.2 alerts.sbox.test\n')
 receiver=out/'receiver.py';receiver.write_text("""import http.server,ssl,json,pathlib,sys
out=pathlib.Path(sys.argv[1]);events=out/'events.jsonl'
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_POST(self):
  data=self.rfile.read(int(self.headers['Content-Length']));json.loads(data)
  with events.open('a') as f:f.write(data.decode()+'\\n')
  self.send_response(204);self.end_headers()
s=http.server.HTTPServer(('1.1.1.2',443),Handler);c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(out/'receiver.pem',out/'receiver.key');s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
""")
 server=subprocess.Popen(['ip','netns','exec','sbox-notify','python3',str(receiver),str(out)],stdout=subprocess.DEVNULL,stderr=(out/'receiver.log').open('w'));time.sleep(.5)
 api('notifications',{'enabled':True,'kind':'webhook','url':'https://alerts.sbox.test/webhook/SYNTHETIC-NOT-A-REAL-TOKEN'});assert api('notifications/test',{})['sent'];api('notifications/test',{},status=429)
 record('Real HTTPS webhook with verified hostname and public-IP pinning; duplicate returns 429',destination_scope='Public-IP alias routed solely to a private disposable namespace; zero external delivery')
 pem,key=cert('expiring-vpn',domain,10);run(['sbox','certificate','--cert','existing','--cert-path',str(pem),'--key-path',str(key),'--yes']);assert json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text())['protocols']==legacy
 # Copy/reload panel TLS only; repeat unchanged refresh must keep both PIDs.
 run(['python3','/usr/local/lib/sbox-webui/current/backend/install.py','refresh-certificate']);time.sleep(2);pids=(pid(),pid('sbox-webui'));run(['python3','/usr/local/lib/sbox-webui/current/backend/install.py','refresh-certificate']);assert pids==(pid(),pid('sbox-webui'))
 record('Changed trusted certificate pair validates; unchanged panel refresh restarts neither service')
 expected=ssl.cert_time_to_seconds(run(['openssl','x509','-in',str(pem),'-enddate','-noout']).split('=',1)[1].strip());api('changes/prepare',{'kind':'policy','data':{}});run(['systemctl','stop','sing-box']);start=time.monotonic()
 while time.monotonic()-start<70:
  events=[json.loads(x) for x in (out/'events.jsonl').read_text().splitlines()]
  kinds={e.get('event') for e in events}
  if {'alert:core.down:opened','alert:cert.expiry:opened'}<=kinds:break
  time.sleep(1)
 else:raise AssertionError('Sampler alerts were not delivered to local receiver')
 expiry=next(e for e in events if e.get('event')=='alert:cert.expiry:opened');assert domain in expiry['detail']['detail'] and time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(expected)) in expiry['detail']['detail'];assert api('certificates')['expires_at']==expected
 record('Real core stop triggers alert; real expiring certificate alert has exact date and target',events=sorted(kinds))
finally:
 subprocess.run(['systemctl','start','sing-box'],capture_output=True)
 try:api('notifications',{'enabled':False})
 except Exception:pass
 run(['sbox','restore',archive,'--force']);run(['python3','/usr/local/lib/sbox-webui/current/backend/install.py','refresh-certificate']);assert json.loads(pathlib.Path('/etc/sbox-manager/state.json').read_text())['protocols']==legacy
 if server:server.terminate();server.wait(timeout=10)
 pathlib.Path('/etc/hosts').write_text(oldhosts);subprocess.run(['ip','route','del','1.1.1.2/32'],capture_output=True);subprocess.run(['ip','netns','del','sbox-notify'],capture_output=True);subprocess.run(['ip','link','del','nfhost'],capture_output=True);ca.unlink(missing_ok=True);run(['update-ca-certificates'])
record('Receiver/routes/trust fixture removed; original VPN and identities restored')
