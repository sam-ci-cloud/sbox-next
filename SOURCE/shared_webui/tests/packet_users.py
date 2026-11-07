"""Real network namespace/Mihomo transport checks against installed sing-box.

No WAN/ISP or public certificate claim. Client YAML identities are unchanged;
only the test client's DNS answer is pinned to the disposable VM veth address.
"""
import http.server,json,os,pathlib,socketserver,subprocess,sys,threading,time,urllib.request
import yaml
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file(),'Disposable VM only'
out=pathlib.Path(sys.argv[1]);out.mkdir(exist_ok=True,parents=True)
source=pathlib.Path(sys.argv[2]);label=sys.argv[3] if len(sys.argv)>3 else 'new-user'
ns='sbox-packet';iface='sw-host';addr='198.19.100.1'
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=60,**kw)
subprocess.run(['ip','netns','del',ns],capture_output=True);subprocess.run(['ip','link','del',iface],capture_output=True)
run(['ip','netns','add',ns]);run(['ip','link','add',iface,'type','veth','peer','name','sw-peer']);run(['ip','link','set','sw-peer','netns',ns]);run(['ip','addr','add',addr+'/24','dev',iface]);run(['ip','link','set',iface,'up'])
run(['ip','netns','exec',ns,'ip','link','set','lo','up']);run(['ip','netns','exec',ns,'ip','link','set','sw-peer','up']);run(['ip','netns','exec',ns,'ip','addr','add','198.19.100.2/24','dev','sw-peer']);run(['ip','netns','exec',ns,'ip','route','add','default','via',addr])
class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'SBOX-REAL-PACKET-OK\n';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*a):pass
class TargetServer(socketserver.TCPServer):allow_reuse_address=True
target=TargetServer((addr,18080),Target);threading.Thread(target=target.serve_forever,daemon=True).start()
fixture=source.read_bytes();data=yaml.safe_load(fixture)
domains={p['server'] for p in data['proxies']}
data['hosts']={**data.get('hosts',{}),**{domain:addr for domain in domains}}
data['dns']={'enable':False};data['mode']='global';data['mixed-port']=17890;data['external-controller']='127.0.0.1:19091';data['allow-lan']=False;data['log-level']='warning'
data['proxy-groups']=[{'name':'GLOBAL','type':'select','proxies':[p['name'] for p in data['proxies']]}]
data['rules']=['MATCH,GLOBAL'];data.pop('rule-providers',None);data.pop('geox-url',None)
(out/'packet-client.yaml').write_text(yaml.safe_dump(data,allow_unicode=True,sort_keys=False));(out/'packet-client.yaml').chmod(0o600)
log=(out/'mihomo-private.log').open('w');client=subprocess.Popen(['ip','netns','exec',ns,'mihomo','-d',str(out/'client-data'),'-f',str(out/'packet-client.yaml')],stdout=log,stderr=subprocess.STDOUT)
rows=[]
try:
    time.sleep(3)
    for p in data['proxies']:
        request=json.dumps({'name':p['name']})
        run(['ip','netns','exec',ns,'/usr/bin/curl','-fsS','-X','PUT','http://127.0.0.1:19091/proxies/GLOBAL','-H','Content-Type: application/json','--data-binary',request])
        t=time.monotonic();r=subprocess.run(['ip','netns','exec',ns,'/usr/bin/curl','-fsS','--proxy','http://127.0.0.1:17890','--noproxy','','--max-time','20','http://'+addr+':18080/probe'],capture_output=True,text=True,timeout=25)
        row={'protocol':p['type'],'alias':bool('range' in p['name'].lower()),'status':'PASS' if r.returncode==0 and r.stdout=='SBOX-REAL-PACKET-OK\n' else 'FAIL','elapsed_seconds':round(time.monotonic()-t,4),'exit_code':r.returncode}
        rows.append(row);print(json.dumps(row),flush=True)
    assert source.read_bytes()==fixture,'Source fixture changed'
finally:
    client.terminate()
    try:client.wait(timeout=5)
    except subprocess.TimeoutExpired:client.kill();client.wait()
    log.close();target.shutdown();target.server_close()
    subprocess.run(['ip','netns','del',ns],capture_output=True);subprocess.run(['ip','link','del',iface],capture_output=True)
    (out/(label+'-packets.json')).write_text(json.dumps(rows,indent=2)+'\n')
expected='FAIL' if len(sys.argv)>4 and sys.argv[4]=='expect-rejected' else 'PASS'
sys.exit(0 if rows and all(r['status']==expected for r in rows) else 1)
