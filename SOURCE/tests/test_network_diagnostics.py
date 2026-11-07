"""Actual local HTTPS diagnostics and privacy/bounds validation."""
import http.server,importlib.util,os,ssl,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
import reality_fixture as fx
spec=importlib.util.spec_from_file_location('performance',fx.ROOT/'src/performance.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class NetworkDiagnostics(unittest.TestCase):
 def test_forbidden_target_forms_and_bounds(self):
  for target in ['http://example.com/','https://u:p@example.com/','https://example.com/?token=x','https://example.com/#x','https://example.com:99999/']:
   with self.subTest(target=target),self.assertRaises(ValueError):p.network_report(target,allow_private=True)
  for count in [0,6,True]:
   with self.assertRaises(ValueError):p.network_report('https://example.com/',samples=count,allow_private=True)
 def test_private_target_requires_explicit_operator_option(self):
  with patch.object(p,'run',return_value={'stdout':'["127.0.0.1"]'}),self.assertRaises(ValueError):p.network_report('https://localhost/')
 def test_socks_hostname_resolution_is_remote_and_not_locally_blocked_by_fake_ip(self):
  calls=[]
  def run(args,timeout=8):
   calls.append(args)
   if args[0]=='curl':return {'status':'ok','rc':0,'stdout':'{"exitcode":0,"http_code":204,"num_connects":1}\n{"exitcode":0,"http_code":204,"num_connects":0}\n'}
   return {'status':'ok','rc':0,'stdout':'test'}
  with patch.object(p,'run',side_effect=run):report=p.network_report('https://example.com/',samples=1,socks_port=1080)
  self.assertFalse(any(call[0]=='python3' for call in calls));self.assertTrue(all(r['probe_status']=='success' for r in report['rows']));self.assertIn('remote',report['dns_location'])
 def test_actual_direct_tls_warm_reuse_and_probe_status(self):
  class H(http.server.BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def log_message(self,*a):pass
   def do_HEAD(self):self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
  with tempfile.TemporaryDirectory() as td:
   ca,leaves=fx.lab_certificates(Path(td),hostnames=('localhost',));server=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(*map(str,leaves['localhost']));server.socket=ctx.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
   try:
    with patch.dict(os.environ,{'CURL_CA_BUNDLE':str(ca)}):report=p.network_report('https://localhost:'+str(server.server_port)+'/private-path-not-reported',samples=1,allow_private=True,expected_status='200')
    self.assertEqual(len(report['rows']),2);self.assertTrue(all(r['probe_status']=='success' and r['http_status']==200 for r in report['rows']));self.assertTrue(report['rows'][1]['connection_reused']);self.assertFalse(report['changes_applied']);self.assertNotIn('private-path',str(report))
   finally:server.shutdown();server.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
