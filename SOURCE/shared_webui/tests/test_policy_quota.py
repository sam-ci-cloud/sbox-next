"""Quota metadata must cross the policy journal without permitting core drift."""
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
root=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('policy',root/'src/policy.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Policy(unittest.TestCase):
 def test_metadata_only_preserves_core_invariant(self):
  before={'schema':2,'managed_users':[{'id':'a'*32,'protocols':{'tuic':{'uuid':'unchanged'}}}],'accounting':{'enabled':True,'port':25001,'core_sha256':'a'*64,'poll_seconds':2,'failure_policy':'open'}}
  after=json.loads(json.dumps(before));after['managed_users'][0]['quota']={'quota_bytes':1000};after['managed_users'][0]['portal']={'password_hash':'hashed'};after['accounting']['poll_seconds']=3
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.write_text(json.dumps(before));b.write_text(json.dumps(after));self.assertEqual(module.server_state(a),module.server_state(b))
   after['managed_users'][0]['protocols']['tuic']['uuid']='changed';b.write_text(json.dumps(after));self.assertNotEqual(module.server_state(a),module.server_state(b))
if __name__=='__main__':unittest.main()
