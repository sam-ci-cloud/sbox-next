"""Real installed Mihomo: verified HTTPS HEAD statuses and controlled switching.
Local delay-injected HTTP CONNECT fixtures are not physical VPN/device tests.
"""
import contextlib,http.client,http.server,importlib.util,json,os,secrets,selectors,shutil,socket,socketserver,ssl,subprocess,tempfile,threading,time,unittest,urllib.parse
from pathlib import Path
import yaml
import reality_fixture as fx
if os.environ.get('SBOX_TEST_STATE'):
 _state_tool=fx.state_tool
 def _old_state(*args,**kwargs):
  args=list(args)
  if len(args)>3:args[3]=Path(os.environ['SBOX_TEST_STATE'])
  else:kwargs['helper']=Path(os.environ['SBOX_TEST_STATE'])
  return _state_tool(*args,**kwargs)
 fx.state_tool=_old_state
spec=importlib.util.spec_from_file_location('b',fx.ROOT/'tools/bench/dual_stack_acceptance.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
@contextlib.contextmanager
def fixture(groups,delays,host_status=204):
 binary=os.environ.get('SBOX_TEST_MIHOMO') or shutil.which('verge-mihomo')
 if not binary:raise unittest.SkipTest('Matching native Mihomo unavailable; actual probe test NOT_RUN')
 with tempfile.TemporaryDirectory() as td:
  w=Path(td);ca,leaves=fx.lab_certificates(w/'certs',hostnames=('localhost',));requests=[]
  class Target(http.server.BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def log_message(self,*args):pass
   def do_HEAD(self):
    requests.append(self.path);code=int(self.path.rsplit('/',1)[-1]) if self.path.rsplit('/',1)[-1].isdigit() else host_status;time.sleep(.003);self.send_response(code)
    if code==302:self.send_header('Location','https://localhost:'+str(self.server.server_port)+'/redirected-200')
    self.send_header('Content-Length','0');self.end_headers()
  target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(*map(str,leaves['localhost']));target.socket=ctx.wrap_socket(target.socket,server_side=True);threading.Thread(target=target.serve_forever,daemon=True).start();nodes=[];servers=[]
  class Connect(http.server.BaseHTTPRequestHandler):
   def log_message(self,*a):pass
   def do_CONNECT(self):
    delay=delays[self.server.label]
    if delay is None:self.close_connection=True;return
    time.sleep(delay);remote=socket.create_connection(('127.0.0.1',target.server_port),timeout=2)
    try:
     self.send_response(200,'Connection Established');self.end_headers();self.wfile.flush()
     with selectors.DefaultSelector() as poll:
      poll.register(self.connection,selectors.EVENT_READ,remote);poll.register(remote,selectors.EVENT_READ,self.connection)
      while True:
       events=poll.select(2)
       if not events:break
       for key,_ in events:
        data=key.fileobj.recv(65536)
        if not data:return
        key.data.sendall(data)
    except (OSError,ssl.SSLError):pass
    finally:remote.close();self.close_connection=True
  for label in delays:
   server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Connect);server.label=label;threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server);nodes.append({'name':label,'type':'http','server':'127.0.0.1','port':server.server_port})
  control=b.free_port();port=b.free_port();secret=secrets.token_urlsafe(24);url='https://localhost:'+str(target.server_port)
  cfg={'mixed-port':port,'external-controller':'127.0.0.1:'+str(control),'secret':secret,'ipv6':False,'log-level':'error','proxies':nodes,'proxy-groups':groups(url),'rules':['MATCH,DIRECT'],'dns':{'enable':False}};path=w/'config.yaml';path.write_text(yaml.safe_dump(cfg));log=(w/'mihomo.log').open('wb');process=subprocess.Popen([binary,'-d',str(w),'-f',str(path)],stdout=log,stderr=log,env={**os.environ,'SSL_CERT_FILE':str(ca),'SSL_CERT_DIR':str(w/'certs')})
  def api(path):
   conn=http.client.HTTPConnection('127.0.0.1',control,timeout=5)
   try:conn.request('GET',path,headers={'Authorization':'Bearer '+secret});response=conn.getresponse();data=response.read();assert response.status==200,(response.status,data[:200]);return json.loads(data)
   finally:conn.close()
  try:
   ready=False
   for _ in range(100):
    if process.poll() is not None:raise AssertionError('Mihomo exited: '+(w/'mihomo.log').read_text()[-1000:])
    try:
     if b.owns_listener(process.pid,control) and b.mihomo_config_barrier(process.pid,control,secret,path):ready=True;break
    except OSError:pass
    time.sleep(.02)
   assert ready,'Owned Mihomo controller did not become ready'
   yield api,url,requests,cfg
  finally:
   b.stop(process,log)
   for server in servers+[target]:server.shutdown();server.server_close()
@unittest.skipUnless(os.environ.get('SBOX_TEST_MIHOMO') or shutil.which('verge-mihomo'), 'Native Mihomo unavailable; actual probe tests NOT_RUN')
class MihomoProbePolicy(unittest.TestCase):
 def test_generated_expected_status_and_redirects_in_actual_core(self):
  for status,path,alive in [('200','200',True),('204','200',False),('200/204','204',True),('200/204','302',False),('200/204','503',False)]:
   with self.subTest(expected=status,response=path):
    def groups(base):
     s=fx.base_state();s['client_policy']={'probe_url':base+'/'+path,'expected_status':status};doc=yaml.safe_load((fx.render(s)/'mihomo-global.yaml').read_text());result=[]
     for g in doc['proxy-groups']:
      if g['type'] in ('url-test','fallback'):result.append({**g,'proxies':['node'],'interval':0})
     return result
    with fixture(groups,{'node':0}) as (api,url,requests,cfg):
     for group in cfg['proxy-groups']:
      name=urllib.parse.quote(group['name'],safe='');api('/group/'+name+'/delay?'+urllib.parse.urlencode({'url':group['url'],'timeout':2000,'expected':group['expected-status']}));info=api('/proxies/node');self.assertEqual(info['extra'][group['url']]['alive'],alive);self.assertEqual(api('/group/'+name)['expectedStatus'],status)
     self.assertTrue(requests);self.assertFalse(any('redirected-' in x for x in requests))
 def test_real_tolerance_selection_and_fallback_are_independent(self):
  for tolerance in [50,120]:
   with self.subTest(tolerance=tolerance):
    delays={'first':.25,'current':.025,'challenger':.16}
    def groups(url):return [{'name':'Smart','type':'url-test','url':url+'/204','expected-status':'204','interval':0,'lazy':False,'tolerance':tolerance,'proxies':list(delays)},{'name':'Fallback','type':'fallback','url':url+'/204','expected-status':'204','interval':0,'lazy':False,'proxies':['current','challenger','first']}]
    with fixture(groups,delays) as (api,url,_,cfg):
     def sample(group='Smart'):
      api('/group/'+group+'/delay?'+urllib.parse.urlencode({'url':url+'/204','timeout':2000,'expected':'204'}));return api('/group/'+group)['now']
     self.assertEqual(sample(),'current');delays.update(current=.08,challenger=.06);self.assertEqual(sample(),'current','20ms jitter should not switch the retained second candidate');delays.update(current=.15,challenger=.06);self.assertEqual(sample(),'challenger' if tolerance==50 else 'current');self.assertEqual(sample('Fallback'),'current','Fallback is ordered, not latency-selected')
 def test_installed_core_first_candidate_exception_is_documented(self):
  # Upstream1.19.33 considers the retained first proxy absent when walking
  # proxies[1:]. Record the actual limitation, not a universal tolerance promise.
  delays={'first':.025,'second':.16}
  def groups(url):return [{'name':'Smart','type':'url-test','url':url+'/204','expected-status':'204','interval':0,'lazy':False,'tolerance':120,'proxies':list(delays)}]
  with fixture(groups,delays) as (api,url,_,_):
   def sample():api('/group/Smart/delay?'+urllib.parse.urlencode({'url':url+'/204','timeout':2000,'expected':'204'}));return api('/group/Smart')['now']
   self.assertEqual(sample(),'first');delays.update(first=.08,second=.06);self.assertEqual(sample(),'second','Installed1.19.33 first-candidate retention exception changed; review documented limitation')
if __name__=='__main__':unittest.main(verbosity=2)
