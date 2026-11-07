import re,subprocess,unittest
from pathlib import Path
SOURCE=(Path(__file__).resolve().parents[1]/'src/manager.sh').read_text()
class FamilyPrompt(unittest.TestCase):
 def choose(self,current,ipv6,existing):
  function=re.search(r'^choose_listen\(\) \{.*?^\}\n',SOURCE,re.M|re.S)[0]
  script='set -eu\nprompt_choice(){ printf "%s\\n" "$2"; }; die(){ exit 2; };\n'+function+'\nchoose_listen "$1" "$2" "$3"\n'
  r=subprocess.run(['bash','-c',script,'test',current,ipv6,existing],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr);return r.stdout.strip()
 def test_legacy_ipv4_default_keeps_existing_policy(self):self.assertEqual(self.choose('0.0.0.0','','true'),'preserve')
 def test_legacy_dual_default_keeps_existing_policy(self):self.assertEqual(self.choose('::','2001:db8::1','true'),'preserve')
 def test_plan_policy_interpolations_are_valid_jq(self):
  lines=[line.strip().rstrip(',') for line in SOURCE.splitlines() if 'Network policy' in line and '.server.mode' in line]
  self.assertEqual(len(lines),2)
  for line in lines:
   result=subprocess.run(['jq','-r',line],input='{"server":{}}',capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr);self.assertIn('preserve',result.stdout)
 def test_client_policy_status_and_tolerance_jq(self):
  body=SOURCE[SOURCE.index('client_policy_command()'):]
  expression=re.search(r"jq -r '(.*?)' \"\$STATE_FILE\"",body,re.S)[1]
  result=subprocess.run(['jq','-r',expression],input='{"client_policy":{"smart_tolerance_ms":50,"expected_status":"200"}}',capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr);self.assertIn('50ms',result.stdout);self.assertIn('200 (HEAD; redirects rejected)',result.stdout)
 def test_new_install_defaults_to_ipv4(self):self.assertEqual(self.choose('0.0.0.0','','false'),'0.0.0.0')
if __name__=='__main__':unittest.main(verbosity=2)
