import json,subprocess,sys,unittest,ipaddress
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import reality_fixture as fx
import yaml
sys.path.insert(0,str(fx.ROOT/'shared_webui'))
from backend.export_json import convert
class DeploymentFamily(unittest.TestCase):
 def state(self,mode):
  s=fx.base_state();s['server'].update(scope='internal',mode=mode,ipv4='192.0.2.1',ipv6='2001:db8::1',listen={'ipv4':'0.0.0.0','dual':'::','ipv6':'2001:db8::1'}[mode]);return s
 def test_legacy_preserves_rendered_behavior(self):
  s=fx.base_state();a=fx.render(s);before=(a/'server.json').read_bytes();s['server']['mode']='preserve';b=fx.render(s);self.assertEqual(before,(b/'server.json').read_bytes())
 def test_modes_reach_core_and_client(self):
  for mode,strategy in [('ipv4','ipv4_only'),('ipv6','ipv6_only'),('dual','prefer_ipv4')]:
   with self.subTest(mode=mode):
    out=fx.render(self.state(mode));server=json.loads((out/'server.json').read_text());doc=yaml.safe_load((out/'mihomo-global.yaml').read_text())
    self.assertEqual(server['route']['default_domain_resolver']['strategy'],strategy)
    self.assertTrue(all(p['ip-version']=={'ipv4':'ipv4','ipv6':'ipv6','dual':'dual'}[mode] for p in doc['proxies']))
    for p in doc['proxies']:self.assertIsNot(p.get('tfo'),True)
    client=convert(doc);(out/'client.json').write_text(json.dumps(client))
    for path in [out/'server.json',out/'client.json']:
     r=subprocess.run([str(fx.core_binary()),'check','-c',str(path)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
    if mode!='dual':
     self.assertEqual(server['route']['rules'][0],{'ip_version':6 if mode=='ipv4' else 4,'action':'reject'})
     for field in ['default-nameserver','proxy-server-nameserver']:
      for x in doc['dns'][field]:
       try:self.assertEqual(ipaddress.ip_address(x).version,4 if mode=='ipv4' else 6)
       except ValueError:pass
 def test_ipv6_only_refuses_dual_stack_wildcard(self):
  s=self.state('ipv6');s['server']['listen']='::'
  with self.assertRaises(AssertionError):fx.render(s)
 def test_ipv4_mapped_ipv6_listener_rejected(self):
  s=self.state('ipv6');s['server']['listen']=s['server']['ipv6']='::ffff:192.0.2.1'
  with self.assertRaises(AssertionError):fx.render(s)
 def test_explicit_dual_requires_saved_families(self):
  for field in ['ipv4','ipv6']:
   s=self.state('dual');s['server'][field]=''
   with self.assertRaises(AssertionError):fx.render(s)
 def test_unknown_mode_rejected(self):
  s=fx.base_state();s['server']['mode']='auto-magic'
  with self.assertRaises(AssertionError):fx.render(s)
if __name__=='__main__':unittest.main(verbosity=2)
