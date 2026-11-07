"""Cold-client end-to-end transport setup + first HTTP timing, local VM only.
Each sample uses a new client process: QUIC/TLS transport cannot be reused.
These timings include proxy/HTTP work and are not isolated crypto handshake time.
"""
import copy,hashlib,http.server,json,os,pathlib,socketserver,statistics,subprocess,sys,threading,time,yaml
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file();os.umask(0o077)
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);ns='sbox-cold';iface='sc-host';addr='198.19.103.1';rows=[]
def run(args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=60).stdout
def pid():return run(['systemctl','show','sing-box','-p','MainPID','--value']).strip()
class Target(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):self.send_response(200);self.send_header('Content-Length','10');self.end_headers();self.wfile.write(b'COLD-OKAY\n')
class HTTP(socketserver.TCPServer):allow_reuse_address=True
before=pid();run(['ip','netns','add',ns]);run(['ip','link','add',iface,'type','veth','peer','name','sc-peer']);run(['ip','link','set','sc-peer','netns',ns]);run(['ip','addr','add',addr+'/24','dev',iface]);run(['ip','link','set',iface,'up']);run(['ip','-n',ns,'addr','add','198.19.103.2/24','dev','sc-peer']);run(['ip','-n',ns,'link','set','sc-peer','up']);run(['ip','-n',ns,'link','set','lo','up']);run(['ip','-n',ns,'route','add','default','via',addr]);server=HTTP((addr,18080),Target);threading.Thread(target=server.serve_forever,daemon=True).start();data=yaml.safe_load(pathlib.Path('/etc/sbox-manager/exports/mihomo-global.yaml').read_text())
try:
 for enabled in (False,True):
  run(['systemctl','start' if enabled else 'stop','sbox-webui','sbox-webui-control']);assert pid()==before
  for p in data['proxies']:
   times=[]
   for i in range(10):
    cfg={'mixed-port':17891,'allow-lan':False,'mode':'rule','log-level':'warning','dns':{'enable':False},'hosts':{p['server']:addr},'proxies':[p],'rules':['MATCH,'+p['name']]};path=out/'private-client.yaml';path.write_text(yaml.safe_dump(cfg,allow_unicode=True));log=(out/'private-client.log').open('w');client=subprocess.Popen(['ip','netns','exec',ns,'mihomo','-d',str(out/'client-data'),'-f',str(path)],stdout=log,stderr=log)
    try:
     time.sleep(.2);t=time.monotonic();r=subprocess.run(['ip','netns','exec',ns,'/usr/bin/curl','-fsS','--proxy','http://127.0.0.1:17891','--noproxy','','--max-time','20','http://'+addr+':18080/'],capture_output=True,text=True,timeout=23);elapsed=time.monotonic()-t;assert r.returncode==0 and r.stdout=='COLD-OKAY\n',(p['type'],r.returncode);times.append(elapsed)
    finally:client.terminate();client.wait(timeout=10);log.close()
   values=sorted(times);rows.append({'panel_running':enabled,'protocol':p['type'],'range_alias':'range' in p['name'].lower(),'samples_seconds':times,'p50_seconds':statistics.median(times),'p95_seconds':values[round(.95*(len(values)-1))]});print('PASS',enabled,p['type'],'alias' if 'range' in p['name'].lower() else '',flush=True);(out/'cold-connect.json').write_text(json.dumps({'core_pid_unchanged':True,'measurement':'Fresh process per sample; end-to-end transport setup plus first HTTP, not isolated crypto handshake','results':rows},indent=2)+'\n')
finally:
 run(['systemctl','start','sbox-webui-control','sbox-webui']);server.shutdown();server.server_close();subprocess.run(['ip','netns','del',ns],capture_output=True);subprocess.run(['ip','link','del',iface],capture_output=True)
assert pid()==before
