"""Core runs as sboxmgr under UMask=0077; root policy must remain group-readable."""
import os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import root_json
class Permissions(unittest.TestCase):
 def test_policy_group_readable_under_restrictive_umask(self):
  if os.geteuid()!=0:self.skipTest('FD chown needs root; run inside disposable guest')
  with tempfile.TemporaryDirectory() as d:
   old=os.umask(0o077)
   try:
    p=Path(d)/'policy.json';root_json(p,{'blocked':[]},os.getgid());self.assertEqual(p.stat().st_mode&0o777,0o640)
   finally:os.umask(old)
if __name__=='__main__':unittest.main()
