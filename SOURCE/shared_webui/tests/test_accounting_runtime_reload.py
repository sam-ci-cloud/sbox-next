"""Enabling an active service does not load newly staged code or sandbox paths."""
from pathlib import Path
import os,subprocess,tempfile,unittest
SOURCE=Path(__file__).parents[1]/'privileged-bridge/manager_extension.sh'
class Reload(unittest.TestCase):
 def test_restart_failure_and_degraded_reconcile_cannot_report_ready(self):
  text=SOURCE.read_text();body=text[text.index('accounting_start_ready()'):text.index('accounting_enable()')]
  for mode in ('restart-failure','degraded'):
   script='''die(){ exit 1; };sleep(){ :; }
systemctl(){ [ "$MODE" != restart-failure ] || [ "$1" != restart ]; }
python3(){ echo '{"status":"degraded"}'; }
   # This fixture only needs jq to fail; reading stdin can hang when the
   # parent runner keeps its inherited input pipe open.
   jq(){ return 1; }
'''+body+'\naccounting_start_ready\n'
   with self.subTest(mode=mode):
    result=subprocess.run(['bash','-c',script],env={**os.environ,'MODE':mode},capture_output=True,text=True,timeout=10)
    self.assertNotEqual(result.returncode,0,'Failed collector refresh was accepted')
 def test_matching_upgrade_loads_staged_runtime_without_restarting_vpn(self):
  text=SOURCE.read_text();start=text.index('accounting_start_ready()' if 'accounting_start_ready()' in text else 'accounting_enable()');body=text[start:text.index('accounting_command()',start)]
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);(base/'loaded').write_text('previous');(base/'staged').write_text('current');(base/'usage.db').write_bytes(b'unchanged durable accounting')
   script='''need_root(){ :; }; require_installed(){ :; }; acquire_lock(){ :; }; guard_no_pending_transaction(){ :; }
die(){ exit 1; }
jq(){ if [ "$1" = -r ]; then echo same-core; else return 0; fi; }
python3(){ echo '{"status":"ready"}'; }
systemctl(){
 case "$*" in
  *sing-box.service*) echo unexpected > "$FIXTURE/vpn-restarted"; return 1;;
  'restart sbox-accounting.service') cp "$FIXTURE/staged" "$FIXTURE/loaded";;
 esac
 return 0
}
'''+body+'\naccounting_enable\n'
   env={**os.environ,'FIXTURE':str(base),'STATE_FILE':str(base/'state.json')}
   result=subprocess.run(['bash','-c',script],env=env,capture_output=True,text=True,timeout=10)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((base/'loaded').read_text(),'current','Active collector kept its previous code/sandbox after staging')
   self.assertFalse((base/'vpn-restarted').exists());self.assertEqual((base/'usage.db').read_bytes(),b'unchanged durable accounting')
if __name__=='__main__':unittest.main()
