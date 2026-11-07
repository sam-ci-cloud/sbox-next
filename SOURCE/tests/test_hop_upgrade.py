"""An unchanged owned hopping range must survive transient outbound UDP sockets."""
import pathlib,re,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Hop(unittest.TestCase):
 def call(self,current,candidate):
  text=(ROOT/'src/manager.sh').read_text();fn=re.search(r'^assert_candidate_ports_free\(\) \{\n.*?^\}',text,re.M|re.S)[0]
  script='''STATE_FILE=current
singbox_main_pid() { echo 123; }
enabled_transport_rows() { :; }
state_exists() { return 0; }
port_in_use() { return 1; }
udp_range_conflict() { echo 46003; }
die() { echo "$*" >&2; exit 1; }
jq() { if [ "${@: -1}" = current ];then echo CURRENT;else echo CANDIDATE;fi; }
'''.replace('CURRENT',current).replace('CANDIDATE',candidate)
  return subprocess.run(['bash','-c',script+fn+'\nassert_candidate_ports_free candidate'],capture_output=True,text=True)
 def test_existing_hop_range_does_not_reclaim_ports(self):self.assertEqual(self.call('36494:46493','36494:46493').returncode,0)
 def test_new_hop_range_still_refuses_foreign_listener(self):self.assertNotEqual(self.call('','36494:46493').returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
