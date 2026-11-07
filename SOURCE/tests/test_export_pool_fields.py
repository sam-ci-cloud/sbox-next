"""sing-box JSON export of client connection-pool fields (sing-mux and AnyTLS sessions).
Both clients share the upstream semantics, so every field maps 1:1 or the export is refused."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared_webui/backend'))
from export_json import convert
VM={'name':'v','type':'vmess','server':'example.com','port':443,'uuid':'00000000-0000-4000-8000-000000000000','network':'ws','tls':True,'ws-opts':{'path':'/x'}}
AN={'name':'a','type':'anytls','server':'example.com','port':443,'password':'p'*16,'sni':'example.com','client-fingerprint':'chrome'}
def one(p):return convert({'proxies':[p]})['outbounds'][0]
class PoolFields(unittest.TestCase):
 def test_sing_mux_pool_maps(self):
  o=one({**VM,'smux':{'enabled':True,'protocol':'h2mux','max-connections':1,'min-streams':0}})
  self.assertEqual(o['multiplex'],{'enabled':True,'protocol':'h2mux','max_connections':1,'min_streams':0})
 def test_sing_mux_pool_refuses_non_integers(self):
  for bad in ({'max-connections':True},{'max-connections':'1'},{'min-streams':-1},{'max-streams':2000},{'brutal-opts':{}}):
   with self.subTest(bad=bad),self.assertRaises(ValueError):one({**VM,'smux':{'enabled':True,**bad}})
 def test_anytls_session_pool_maps(self):
  o=one({**AN,'min-idle-session':1,'idle-session-timeout':120,'idle-session-check-interval':30})
  self.assertEqual((o['min_idle_session'],o['idle_session_timeout'],o['idle_session_check_interval']),(1,'120s','30s'))
 def test_anytls_absent_fields_stay_absent(self):
  o=one(AN);self.assertFalse({'min_idle_session','idle_session_timeout','idle_session_check_interval'}&set(o))
 def test_anytls_session_fields_refused(self):
  for bad in ({'min-idle-session':'1'},{'idle-session-timeout':-5},{'idle-session-timeout':1.5}):
   with self.subTest(bad=bad),self.assertRaises(ValueError):one({**AN,**bad})
  with self.assertRaises(ValueError):one({**VM,'min-idle-session':1})
if __name__=='__main__':unittest.main(verbosity=2)
