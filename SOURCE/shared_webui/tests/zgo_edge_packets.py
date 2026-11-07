"""Encrypted HY2/TUIC traffic through all four exact original range edges."""
import copy,hashlib,json,os,pathlib,subprocess,time,yaml
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
root=pathlib.Path('/opt/zgo-lab');fixture=pathlib.Path('/home/ubuntu/current/tests/ZgoCloud-Original-Reference.yaml');before=hashlib.sha256(fixture.read_bytes()).hexdigest();d=yaml.safe_load(fixture.read_text());proxies=[]
for proto,ports in [('hysteria2',(36494,46493)),('tuic',(21518,31517))]:
 source=next(x for x in d['proxies'] if x['type']==proto)
 for port in ports:
  p=copy.deepcopy(source);p['name']=proto+'-'+str(port);p['server']='10.210.0.1';p['port']=port
  for k in ('ports','port-hopping','hop-interval'):p.pop(k,None)
  proxies.append(p)
cfg={'mixed-port':19990,'external-controller':'127.0.0.1:19991','allow-lan':False,'mode':'global','log-level':'warning','dns':{'enable':False},'proxies':proxies,'proxy-groups':[{'name':'GLOBAL','type':'select','proxies':[p['name'] for p in proxies]}],'rules':['MATCH,GLOBAL']};path=root/'private-edges.yaml';path.write_text(yaml.safe_dump(cfg,allow_unicode=True));path.chmod(0o600);log=(root/'edge-client.log').open('w');client=subprocess.Popen(['ip','netns','exec','zgo-client','mihomo','-d',str(root/'edge-client'),'-f',str(path)],stdout=log,stderr=log);rows=[]
try:
 time.sleep(2)
 for p in proxies:
  subprocess.run(['ip','netns','exec','zgo-client','/usr/bin/curl','-fsS','-X','PUT','http://127.0.0.1:19991/proxies/GLOBAL','-H','Content-Type: application/json','--data-binary',json.dumps({'name':p['name']})],check=True,capture_output=True)
  r=subprocess.run(['ip','netns','exec','zgo-client','/usr/bin/curl','-fsS','--proxy','http://127.0.0.1:19990','--noproxy','','--max-time','20','http://10.210.0.1:18080/probe'],capture_output=True,text=True,timeout=25);ok=r.returncode==0 and r.stdout=='ZGO-LAB-PROTOCOL-OK\n';rows.append({'protocol':p['type'],'exact_port':p['port'],'status':'PASS' if ok else 'FAIL'});print(json.dumps(rows[-1]),flush=True)
 assert hashlib.sha256(fixture.read_bytes()).hexdigest()==before
finally:
 client.terminate();client.wait(timeout=10);log.close();(root/'edge-packets.json').write_text(json.dumps(rows,indent=2)+'\n')
assert len(rows)==4 and all(x['status']=='PASS' for x in rows)
