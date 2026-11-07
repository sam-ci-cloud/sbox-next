import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import reality_fixture as fx
spec=importlib.util.spec_from_file_location('scope',fx.ROOT/'tools/set_deployment_scope.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ScopeAnnotation(unittest.TestCase):
 def test_only_context_changes_and_protected_is_refused(self):
  s=fx.base_state();result=m.prepare(s,'internal');result['server'].pop('scope');self.assertEqual(result,s);s['zgo_legacy_compat']=True
  with self.assertRaises(ValueError):m.prepare(s,'internal')
 def test_offline_preview_of_previously_unqualified_private_ipv6(self):
  s=fx.base_state();s['server'].update(mode='ipv6',ipv6='fc00::1',listen='fc00::1')
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory)/'state.json';p.write_text(json.dumps(s));before=p.read_bytes();r=subprocess.run([sys.executable,str(fx.ROOT/'tools/set_deployment_scope.py'),'--state',str(p),'--scope','internal'],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(json.loads(r.stdout)['apply']);self.assertEqual(p.read_bytes(),before);self.assertNotIn(s['protocols']['reality']['uuid'],r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
