#!/usr/bin/env python3
"""Generated node DNS must bootstrap without a public IPv4 route."""
import ipaddress,sys,unittest,urllib.parse,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import reality_fixture as fx
import yaml

def ipv6_endpoint(value):
 try:
  host=urllib.parse.urlsplit(value).hostname if '://' in value else value
  return ipaddress.ip_address(host).version==6
 except (ValueError,TypeError):return False
class DualStackDNS(unittest.TestCase):
 def test_default_bootstrap_and_node_resolution_support_ipv6_only(self):
  doc=yaml.safe_load((fx.render(fx.base_state())/'mihomo-global.yaml').read_text())
  for key in ['default-nameserver','proxy-server-nameserver','nameserver']:
   with self.subTest(key=key):self.assertTrue(any(ipv6_endpoint(x) for x in doc['dns'][key]),key+' has no literal IPv6 endpoint')
  self.assertIs(doc.get('ipv6'),True)
 def test_server_tfo_must_not_enable_lazy_client_dialing(self):
  state=fx.base_state();state['protocols']['reality']['tcp_fast_open']=True
  out=fx.render(state);doc=yaml.safe_load((out/'mihomo-global.yaml').read_text())
  node=next(p for p in doc['proxies'] if p['type']=='vless')
  self.assertIsNot(node.get('tfo'),True,'Mihomo lazy TFO connection defeats address-family fallback')
  server=json.loads((out/'server.json').read_text())
  self.assertTrue(next(p for p in server['inbounds'] if p['type']=='vless')['tcp_fast_open'])
 def test_owner_resolver_overrides_remain_exact(self):
  state=fx.base_state();state['client_policy']['dns']={'bootstrap':['9.9.9.9'],'global':['https://dns.quad9.net/dns-query'],'proxy':['9.9.9.9']}
  doc=yaml.safe_load((fx.render(state)/'mihomo-global.yaml').read_text())
  for key,field in [('bootstrap','default-nameserver'),('global','nameserver'),('proxy','proxy-server-nameserver')]:self.assertEqual(doc['dns'][field],state['client_policy']['dns'][key])
if __name__=='__main__':unittest.main()
