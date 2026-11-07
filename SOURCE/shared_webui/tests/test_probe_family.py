"""Loopback panel diagnostics follow listener family without arbitrary dials."""
from pathlib import Path
import sys,socket,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from server import App
class Probes(unittest.TestCase):
 def test_ipv6_loopback_listener_is_not_reported_as_ipv4_down(self):
  with socket.socket(socket.AF_INET6) as s:
   s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.bind(('::1',0));s.listen();app=object.__new__(App);result=app.probe({'network':'tcp','type':'vless','tls':True,'listen':'::1','port':s.getsockname()[1]},'cloud.sbox.test');self.assertEqual(result['status'],'ok',result)
 def test_public_explicit_address_is_not_an_arbitrary_probe_destination(self):
  app=object.__new__(App)
  with patch('server.socket.create_connection') as connect:
   result=app.probe({'network':'tcp','type':'vless','listen':'2001:db8::1','port':443},'cloud.sbox.test');self.assertEqual(result['status'],'not-probed');connect.assert_not_called()
if __name__=='__main__':unittest.main(verbosity=2)
