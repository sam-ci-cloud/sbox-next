"""A real Mihomo listener can be open while its forwarding tunnel is suspended."""
import http.server,importlib.util,json,os,shutil,socket,tempfile,threading,time,unittest,urllib.parse
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('bench',Path(os.environ.get('SBOX_TEST_BENCH',str(ROOT/'tools/bench/dual_stack_acceptance.py'))));b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
class StartupReady(unittest.TestCase):
 def test_socket_ownership_is_not_application_readiness(self):
  binary=os.environ.get('SBOX_TEST_MIHOMO') or shutil.which('verge-mihomo')
  if not binary:self.skipTest('Actual Mihomo CLI unavailable; readiness integration NOT_RUN')
  entered=threading.Event();release=threading.Event();done=threading.Event();result={}
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*a):pass
   def do_CONNECT(self):
    self.send_response(200,'Connection Established');self.end_headers();self.wfile.flush()
    size=0
    while True:
     line=self.rfile.readline(8193);size+=len(line)
     if line in (b'\r\n',b'\n',b'') or size>8192:break
    body=b'proxy-ready';self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body);self.wfile.flush();self.close_connection=True
   def do_GET(self):
    if urllib.parse.urlsplit(self.path).path=='/provider.yaml':
     entered.set();release.wait(8);body=f'proxies: [{{name: unused, type: http, server: 127.0.0.1, port: {self.server.server_port}}}]\n'.encode()
    else:body=b'proxy-ready'
    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  with tempfile.TemporaryDirectory() as directory:
   w=Path(directory);(w/'private').mkdir();(w/'mihomo').symlink_to(Path(binary).resolve());b.W=w;server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();port=b.free_port();dump=b.yaml.safe_dump
   def config(doc,*args,**kwargs):
    return dump({**doc,'proxy-providers':{'slow':{'type':'http','proxy':'DIRECT','url':f'http://127.0.0.1:{server.server_port}/provider.yaml','path':'slow.yaml','interval':3600,'health-check':{'enable':False}}}},*args,**kwargs)
   def start():
    try:result['process'],result['log']=b.start('mihomo',{'name':'probe','type':'http','server':'127.0.0.1','port':server.server_port},'127.0.0.1',port,w/'private/client')
    except BaseException as error:result['error']=error
    finally:done.set()
   worker=threading.Thread(target=start,daemon=True)
   try:
    with patch.object(b.yaml,'safe_dump',side_effect=config):
     worker.start()
     if not entered.wait(5):
      detail=(w/'private/client/client.log').read_text(errors='replace')[-1400:] if (w/'private/client/client.log').exists() else str(result.get('error'))
      self.fail('Slow provider was not reached: '+detail)
     premature=done.wait(.15)
     early=None
     if premature and 'process' in result:
      rc,data,timing=b.curl(port,'http://192.0.2.123','/probe',timeout=2);early={'curl_exit':rc,'data_received':len(data),'timing':timing}
     release.set();worker.join(8)
     if 'error' in result:raise result['error']
     self.assertFalse(premature,'Client returned ready while Mihomo was suspended: '+json.dumps(early))
     self.assertTrue(done.is_set());rc,data,_=b.curl(port,'http://192.0.2.123','/probe');self.assertEqual((rc,data),(0,b'proxy-ready'))
   finally:
    release.set();worker.join(8)
    if result.get('process'):b.stop(result['process'],result['log'])
    server.shutdown();server.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
