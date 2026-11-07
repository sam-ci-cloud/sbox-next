"""A protected external source cannot break unrelated UI changes or bypass trust."""
from pathlib import Path
import json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class Reuse(unittest.TestCase):
 def call(self,flag=True,changed=None,source_valid=False,active_valid=True):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);state={'domain':'vpn.example.test','certificate':{'mode':'existing','source_fullchain':'/root/external.pem','source_key':'/root/external.key','insecure':False}};(root/'current').write_text(json.dumps(state));candidate=json.loads(json.dumps(state))
   if changed=='domain':candidate['domain']='different.example.test'
   if changed=='certificate':candidate['certificate']['source_key']='/root/new-key'
   (root/'candidate').write_text(json.dumps(candidate))
   helper=(ROOT/'src/certificate_reuse.sh').read_text()
   script='''state_exists() { test -s "$STATE_FILE"; }
certificate_pair_ok() { [ "$SOURCE_VALID" = true ]; }
resolve_service_certificate() { EFFECTIVE_CERT=/managed/live/fullchain.pem;EFFECTIVE_KEY=/managed/live/privkey.pem;[ "$ACTIVE_VALID" = true ]; }
'''+helper+'\nselect_candidate_certificate "$CANDIDATE" || exit 42\nprintf "%s\\n" "$EFFECTIVE_CERT"\n'
   return subprocess.run(['bash','-c',script],env={**os.environ,'STATE_FILE':str(root/'current'),'CANDIDATE':str(root/'candidate'),'SBOX_REUSE_MANAGED_CERT':str(flag).lower(),'SOURCE_VALID':str(source_valid).lower(),'ACTIVE_VALID':str(active_valid).lower()},capture_output=True,text=True)
 def test_unchanged_protected_source_uses_valid_active_managed_pair(self):
  p=self.call();self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout.strip(),'/managed/live/fullchain.pem')
 def test_normal_explicit_certificate_operations_do_not_fallback(self):self.assertNotEqual(self.call(flag=False).returncode,0)
 def test_changed_domain_or_certificate_plan_is_refused(self):
  for changed in ('domain','certificate'):
   with self.subTest(changed=changed):self.assertNotEqual(self.call(changed=changed).returncode,0)
 def test_invalid_active_pair_is_refused(self):self.assertNotEqual(self.call(active_valid=False).returncode,0)
 def test_readable_valid_requested_source_still_wins(self):
  p=self.call(source_valid=True);self.assertEqual(p.returncode,0);self.assertEqual(p.stdout.strip(),'/root/external.pem')
if __name__=='__main__':unittest.main(verbosity=2)
