"""Both CLI lanes must retain the correct snapshot through Bash dynamic scope."""
from pathlib import Path
import os,subprocess,tempfile,unittest
SOURCE=Path(os.environ.get('SBOX_MANAGER_ROOT',Path(__file__).resolve().parents[2]))/'src/manager.sh'
class Preparation(unittest.TestCase):
 def test_callee_local_snap_cannot_redirect_rollback(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);s=SOURCE.read_text().removesuffix('main "$@"\n')
   for prefix in ('/etc/','/usr/local/','/var/','/run/'):s=s.replace(prefix,td+prefix)
   f=p/'functions';f.write_text(s);(p/'run/sbox-manager').mkdir(parents=True)
   body='''source "$FUNCTIONS"
echo '{}' > "$FIXTURE/state"
acquire_lock() { :; }; guard_no_pending_transaction() { :; }; firewall_preflight_file() { :; }
security_apply_mode() { echo pending; }; security_preflight_for_apply() { :; }; assert_candidate_ports_free() { :; }
snapshot_runtime() { mkdir -p "$1"; }
materialize_certificate_plan() { local snap="$FIXTURE/WRONG-CALLEE-LOCAL"; die INJECTED_PRECOMMIT_FAILURE; }
rollback_transaction_verified() { echo "$1" > "$FIXTURE/rollback-pointer"; [[ "$1" == */prepared.* ]]; }
clear_txn_journal() { rm -f "$TXN_JOURNAL"; }
apply_planned_candidate "$FIXTURE/state" '' test "$FIXTURE/plan"
'''
   r=subprocess.run(['bash','-c',body],capture_output=True,text=True,env={**os.environ,'FUNCTIONS':str(f),'FIXTURE':td})
   self.assertNotEqual(r.returncode,0)
   self.assertIn('/prepared.',(p/'rollback-pointer').read_text())
   self.assertFalse((p/'var/lib/sbox-manager/transaction.json').exists())
if __name__=='__main__':unittest.main(verbosity=2)
