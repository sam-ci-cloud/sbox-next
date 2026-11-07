"""Behavioral reproductions for v1.5.0 independent audit findings."""
import ast,ipaddress,json,re,subprocess,sys,unittest,tempfile,os
from pathlib import Path
import reality_fixture as fx
import yaml
class AuditNetwork(unittest.TestCase):
 def state(self,address='2606:4700:4700::1111',scope=None):
  s=fx.base_state();s['server'].update(mode='ipv6',ipv6=address,listen=address)
  if scope:s['server']['scope']=scope
  return s
 def test_public_ipv6_rejects_unqualified_nonpublic_addresses(self):
  for addr in ['::1','fe80::1','fc00::1']:
   with self.subTest(address=addr):self.assertNotEqual(fx.state_tool('validate',self.state(addr)).returncode,0)
 def test_internal_ipv6_is_explicitly_supported(self):
  for addr in ['::1','fc00::1']:
   with self.subTest(address=addr):self.assertEqual(fx.state_tool('validate',self.state(addr,'internal')).returncode,0)
 def test_internal_link_local_requires_interface(self):
  s=self.state('fe80::1','internal');self.assertNotEqual(fx.state_tool('validate',s).returncode,0);s['server']['interface']='eth0';self.assertEqual(fx.state_tool('validate',s).returncode,0)
 def test_global_ipv6_and_bad_special_addresses(self):
  self.assertEqual(fx.state_tool('validate',self.state()).returncode,0)
  for addr in ['::','ff02::1','::ffff:192.0.2.1']:
   self.assertNotEqual(fx.state_tool('validate',self.state(addr,'internal')).returncode,0)
 def test_custom_probe_expected_status_reaches_both_groups(self):
  s=fx.base_state();s['client_policy']={'probe_url':'https://example.com/','expected_status':'200'};doc=yaml.safe_load((fx.render(s)/'mihomo-global.yaml').read_text());groups=[x for x in doc['proxy-groups'] if x['type'] in ('url-test','fallback')];self.assertEqual([x['expected-status'] for x in groups],['200','200'])
 def test_bad_probe_status_and_sensitive_url_rejected(self):
  for key,value in [('expected_status','200-999'),('expected_status',True),('expected_status','302'),('probe_url','https://example.com/?token=private')]:
   s=fx.base_state();s['client_policy']={key:value};self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
 def test_malformed_probe_hostname_and_empty_userinfo_rejected(self):
  for url in ['https://@example.com/','https://example.com%40evil/','https://./','https://bad..example/','https://[::]/']:
   s=fx.base_state();s['client_policy']={'probe_url':url};self.assertNotEqual(fx.state_tool('validate',s).returncode,0)
 def assess(self,server,records,assigned=()):
  tree=ast.parse((fx.ROOT/'src/state.py').read_text());names={'fail','require','assess_endpoints'};module=ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]);env={'ipaddress':ipaddress,'re':re};exec(compile(module,'state.py','exec'),env);return env['assess_endpoints']('example.com',server,records,list(assigned))
 def test_dns_missing_mismatched_and_multiple_addresses(self):
  for mode,key,address in [('ipv4','ipv4','8.8.8.8'),('ipv6','ipv6','2606:4700:4700::1111')]:
   server={'mode':mode,key:address};assigned=[{'interface':'eth0','address':address}]
   for observed in [[],['1.1.1.1'],[address,'1.1.1.1']]:self.assertEqual(self.assess(server,{key:observed},assigned)['status'],'FAIL')
   self.assertEqual(self.assess(server,{key:[address]},assigned)['status'],'PASS')
 def test_dual_requires_both_and_ipv6_assignment_scope(self):
  server={'mode':'dual','ipv4':'8.8.8.8','ipv6':'2606:4700:4700::1111'};records={'ipv4':['8.8.8.8'],'ipv6':['2606:4700:4700::1111']};assigned=[{'interface':'eth0','address':server['ipv6']}]
  self.assertEqual(self.assess(server,records,assigned)['status'],'PASS');self.assertEqual(self.assess(server,{'ipv4':records['ipv4']},assigned)['status'],'FAIL');self.assertEqual(self.assess(server,records)['status'],'FAIL');server['interface']='eth1';self.assertEqual(self.assess(server,records,assigned)['status'],'FAIL')
 def test_ipv6_dns_matching_is_canonical(self):
  address='2606:4700:4700::1111';server={'mode':'ipv6','ipv6':'2606:4700:4700:0:0:0:0:1111'};self.assertEqual(self.assess(server,{'ipv6':[address]},[{'interface':'eth0','address':address}])['status'],'PASS')
 def test_legacy_and_explicit_transitional_override(self):
  self.assertEqual(self.assess({'mode':'preserve'},{})['status'],'PASS')
  report=self.assess({'mode':'ipv4','ipv4':'8.8.8.8','endpoint_override':'Planned DNS transition; independently tested endpoint'},{});self.assertEqual(report['status'],'PASS');self.assertTrue(report['override']);self.assertTrue(report['warnings'])
 def test_shell_dns_gate_uses_actual_helper(self):
  source=(fx.ROOT/'src/manager.sh').read_text();function=re.search(r'^check_domain_dns\(\) \{.*?^\}\n',source,re.M|re.S)[0]
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'dig';p.write_text('#!/bin/bash\nif [[ "$*" == *" A "* ]]; then echo "${TEST_DNS_A:-}"; fi\n');p.chmod(0o755)
   helper=fx.ROOT/'src/state.py'
   script='set -eu\nRUNTIME_DIR="$1"; helper="$2"; warn(){ :; }; die(){ exit 2; }; state_tool(){ "$PYTHON" "$helper" "$1" "$2" "" /tmp 1.5.0 2 1.12.0; };\n'+function+'\ncheck_domain_dns example.com 8.8.8.8 "" ipv4 public\n'
   for answer,ok in [('8.8.8.8',True),('1.1.1.1',False),('',False)]:
    result=subprocess.run(['bash','-c',script,'test',d,str(helper)],capture_output=True,text=True,env={**os.environ,'PATH':d+':'+os.environ['PATH'],'TEST_DNS_A':answer,'PYTHON':sys.executable});self.assertEqual(result.returncode==0,ok,result.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
