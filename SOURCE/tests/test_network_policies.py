"""Independent dimensions, old preserve semantics and real core config acceptance."""
import os,copy,json,subprocess,unittest
from pathlib import Path
import reality_fixture as fx
if os.environ.get('SBOX_TEST_STATE'):
 _state_tool=fx.state_tool
 def _old_state(*args,**kwargs):
  args=list(args)
  if len(args)>3:args[3]=Path(os.environ['SBOX_TEST_STATE'])
  else:kwargs['helper']=Path(os.environ['SBOX_TEST_STATE'])
  return _state_tool(*args,**kwargs)
 fx.state_tool=_old_state
import yaml
class NetworkPolicies(unittest.TestCase):
 def state(self,inbound='ipv4',egress='dual',dns='dual',client='ipv4'):
  s=fx.base_state();s['server'].update(mode='ipv4',scope='internal',ipv4='192.0.2.1',ipv6='2001:db8::1',listen={'ipv4':'0.0.0.0','dual':'::','ipv6':'2001:db8::1'}[inbound],policies=dict(inbound=inbound,egress=egress,dns=dns,client=client));return s
 def test_supported_independent_dimensions_reach_actual_core(self):
  cases=[('ipv4','dual','dual','ipv4'),('dual','ipv4','ipv4','ipv4'),('ipv6','dual','dual','ipv6'),('dual','prefer_ipv6','dual','dual'),('dual','prefer_ipv4','dual','dual'),('dual','dual','prefer_ipv6','dual')]
  for values in cases:
   with self.subTest(policies=values):
    out=fx.render(self.state(*values));server=json.loads((out/'server.json').read_text());doc=yaml.safe_load((out/'mihomo-global.yaml').read_text());self.assertEqual(server['inbounds'][0]['listen'],self.state(*values)['server']['listen']);self.assertEqual(doc['proxies'][0]['ip-version'],values[3]);self.assertEqual(doc['ipv6'],values[1]!='ipv4');result=subprocess.run([str(fx.core_binary()),'check','-c',str(out/'server.json')],capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
    if values[1].startswith('prefer_'):self.assertEqual(server['outbounds'][0]['domain_resolver']['strategy'],values[1])
 def test_conflicting_and_partial_policies_rejected(self):
  for fields in [dict(inbound='ipv4',egress='ipv4',dns='ipv6',client='ipv4'),dict(inbound='ipv4',egress='dual',dns='dual',client='dual'),dict(inbound='dual',egress='prefer_ipv6',dns='prefer_ipv4',client='dual'),{'egress':'dual'}]:
   s=self.state();s['server']['policies']=fields;self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
 def test_explicit_measured_egress_fallback_delay(self):
  s=self.state('dual','prefer_ipv6','dual','dual');s['server']['fallback_delay_ms']=150;out=fx.render(s);cfg=json.loads((out/'server.json').read_text());self.assertEqual(cfg['outbounds'][0].get('fallback_delay'),'150ms');result=subprocess.run([str(fx.core_binary()),'check','-c',str(out/'server.json')],capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
 def test_fallback_bounds_and_single_family_noop_refused(self):
  for value in [0,99,1001,True,'150']:
   s=self.state();s['server']['fallback_delay_ms']=value;self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
  s=self.state('ipv4','ipv4','ipv4','ipv4');s['server']['fallback_delay_ms']=150;self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
 def test_legacy_preserve_does_not_gain_egress_restrictions(self):
  s=fx.base_state();before=fx.render(s);s['server']['mode']='preserve';after=fx.render(s)
  for name in ['server.json','mihomo-global.yaml','mihomo-cn.yaml','mihomo-internal.yaml','links.txt']:self.assertEqual((before/name).read_bytes(),(after/name).read_bytes())
 def test_tolerance_and_status_defaults_preserve_existing_settings(self):
  s=fx.base_state()
  for tolerance in [10,50,120,300]:
   s['client_policy']={'smart_tolerance_ms':tolerance,'expected_status':'200/204'};doc=yaml.safe_load((fx.render(s)/'mihomo-global.yaml').read_text());groups={g['type']:g for g in doc['proxy-groups']};self.assertEqual(groups['url-test']['tolerance'],tolerance);self.assertNotIn('tolerance',groups['fallback']);self.assertEqual(groups['fallback']['expected-status'],'200/204')
  for bad in [0,9,301,True,'50',50.5]:
   s['client_policy']={'smart_tolerance_ms':bad};self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
 def test_strict_uri_endpoint_is_literal_and_keeps_tls_sni(self):
  for mode,address in [('ipv4','192.0.2.1'),('ipv6','2001:db8::1')]:
   s=self.state(mode,mode,mode,mode);out=fx.render(s);links=(out/'links.txt').read_text();self.assertIn('@'+('['+address+']' if mode=='ipv6' else address)+':',links);self.assertIn('sni='+s['protocols']['reality']['sni'],links)
if __name__=='__main__':unittest.main(verbosity=2)
