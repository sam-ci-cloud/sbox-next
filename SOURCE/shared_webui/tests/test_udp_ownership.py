"""Existing core outbound UDP sockets must not reject unrelated managed changes."""
import re,subprocess,sys,unittest
from pathlib import Path
root=Path(sys.argv.pop(1)).resolve();source=(root/'src/manager.sh').read_text();fn=re.search(r'^udp_range_conflict\(\) \{\n.*?^\}',source,re.M|re.S)[0]
class Ownership(unittest.TestCase):
 def run_shell(self,rows,args):
  fake='ss() { cat <<\'SOCKET_ROWS\'\n'+rows+'\nSOCKET_ROWS\n}\n';return subprocess.run(['bash','-c',fn+'\n'+fake+'udp_range_conflict '+args],capture_output=True,text=True)
 def test_existing_core_outbound_socket_is_not_a_foreign_listener(self):
  row='UNCONN 0 0 0.0.0.0:41814 0.0.0.0:* users:(("sing-box",pid=123,fd=12))';r=self.run_shell(row,'40000:49999 123');self.assertEqual(r.returncode,1,r.stdout)
 def test_foreign_socket_still_rejected(self):
  row='UNCONN 0 0 0.0.0.0:41815 0.0.0.0:* users:(("other",pid=456,fd=12))';r=self.run_shell(row,'40000:49999 123');self.assertEqual(r.returncode,0);self.assertEqual(r.stdout.strip(),'41815')
 def test_fresh_install_does_not_exempt_any_existing_socket(self):
  row='UNCONN 0 0 0.0.0.0:41814 0.0.0.0:* users:(("sing-box",pid=123,fd=12))';r=self.run_shell(row,'40000:49999');self.assertEqual(r.returncode,0)
if __name__=='__main__':unittest.main()
