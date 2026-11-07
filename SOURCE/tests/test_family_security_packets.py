"""Real isolated packets for IPv4-mapped policy bypass; synthetic local CA/identity."""
import http.server,importlib.util,json,os,shutil,socket,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'));import reality_fixture as fx
import yaml
spec=importlib.util.spec_from_file_location('transport',ROOT/'tools/bench/dual_stack_acceptance.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
class HTTP6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
class MappedSecurity(unittest.TestCase):
 def test_mapped_literal_has_no_policy_bypass(self):
  self.mihomo=os.environ.get('SBOX_TEST_MIHOMO') or shutil.which('verge-mihomo')
  if not self.mihomo:self.skipTest('Matching Mihomo CLI unavailable; packet test NOT_RUN')
  with tempfile.TemporaryDirectory() as temp:
   w=Path(temp);(w/'private').mkdir();b.W=w;(w/'mihomo').symlink_to(Path(self.mihomo).resolve());cert=w/'certs';ca,leaves=fx.lab_certificates(cert);(cert/'live').mkdir();shutil.copy2(leaves[fx.DOMAIN][0],cert/'live/fullchain.pem');shutil.copy2(leaves[fx.DOMAIN][1],cert/'live/privkey.pem')
   old_env={k:os.environ.get(k) for k in ['SSL_CERT_FILE','SSL_CERT_DIR']};os.environ['SSL_CERT_FILE']=str(ca);os.environ['SSL_CERT_DIR']=str(cert)
   h4=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);h6=HTTP6(('::1',0),Handler)
   for h in [h4,h6]:threading.Thread(target=h.serve_forever,daemon=True).start()
   fport=b.free_port();f=(w/'fallback.log').open('wb');fallback=subprocess.Popen(['openssl','s_server','-quiet','-accept','127.0.0.1:'+str(fport),'-cert',str(leaves[fx.DOMAIN][0]),'-key',str(leaves[fx.DOMAIN][1]),'-www'],stdout=f,stderr=f)
   key,pub=fx.reality_keypair()
   try:
    for mode,private_block,expect in [('preserve',False,True),('preserve',True,False),('ipv6',False,False)]:
     with self.subTest(mode=mode,block_private=private_block):
      state=fx.self_hosted(fx.base_state(key,pub,reality_port=b.free_port()),port=fport);state['security']['block_private']=private_block;state['server'].update(scope='internal',mode=mode,ipv6='::1',listen='::1' if mode=='ipv6' else '0.0.0.0');out=fx.render(state,cert_dir=str(cert));log=(w/(mode+str(private_block)+'.log')).open('wb');server=subprocess.Popen([str(fx.core_binary()),'run','-c',str(out/'server.json')],stdout=log,stderr=log);client=clog=None
      try:
       addr='::1' if mode=='ipv6' else '127.0.0.1'
       for _ in range(100):
        try:
         with socket.create_connection((addr,state['protocols']['reality']['port']),timeout=.1):break
        except OSError:time.sleep(.02)
       p=yaml.safe_load((out/'mihomo-global.yaml').read_text())['proxies'][0];port=b.free_port();client,clog=b.start('mihomo',p,addr,port,w/'private'/(mode+str(private_block)))
       rc,data,_=b.curl(port,f'http://[::ffff:127.0.0.1]:{h4.server_port}','/health',timeout=2);self.assertEqual(rc==0 and data==b'ok',expect)
       if mode=='ipv6':
        rc,data,_=b.curl(port,f'http://[::1]:{h6.server_port}','/health');self.assertEqual((rc,data),(0,b'ok'))
      finally:
       if client:b.stop(client,clog)
       b.stop(server,log)
   finally:
    b.stop(fallback,f)
    for h in [h4,h6]:h.shutdown();h.server_close()
    for k,v in old_env.items():
     if v is None:os.environ.pop(k,None)
     else:os.environ[k]=v
if __name__=='__main__':unittest.main(verbosity=2)
