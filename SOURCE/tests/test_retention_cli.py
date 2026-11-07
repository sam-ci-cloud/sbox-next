"""Invoke the generated CLI parser with harmless operation stubs, not text matching."""
import subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));import build
class RetentionCLI(unittest.TestCase):
 def invoke(self,*args):
  manager=build.integrate((ROOT/'src/manager.sh').read_text(),'universal').decode();manager=manager.rsplit('main "$@"',1)[0]
  stubs='''
state_exists(){ return 1; }
need_root(){ :; }
require_installed(){ :; }
acquire_lock(){ :; }
guard_no_pending_transaction(){ :; }
write_retention_helper(){ printf 'import sys\\nprint("RETENTION_PARSED",*sys.argv[1:])\\n'; }
main "$@"
'''
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'manager.sh';p.write_text(manager+stubs);return subprocess.run(['bash',str(p),*args],capture_output=True,text=True)
 def test_new_retention_arguments_reach_the_guarded_dispatch(self):
  r=self.invoke('backup','retention','--keep-backups','1');self.assertEqual(r.returncode,0,r.stderr);self.assertIn('RETENTION_PARSED',r.stdout);self.assertIn('--keep-backups 1',r.stdout)
 def test_unknown_backup_argument_is_still_rejected(self):
  r=self.invoke('backup','unexpected');self.assertNotEqual(r.returncode,0);self.assertNotIn('RETENTION_PARSED',r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
