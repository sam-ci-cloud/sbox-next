"""APT inventory is cached, bounded and never installs/refreshes packages."""
import importlib.util,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('performance',Path(__file__).resolve().parents[1]/'src/performance.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Updates(unittest.TestCase):
 def test_security_normal_and_reboot_are_truthful(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'var/run').mkdir(parents=True);(root/'var/run/reboot-required').touch()
   sample={'status':'ok','stdout':'Inst openssl [1] (2 Ubuntu:26.10/stonking-security [amd64])\nInst test [1] (2 Ubuntu:26.10/stonking-updates [amd64])\n'}
   with patch.object(p,'run',return_value=sample) as run:
    r=p.os_updates(root);self.assertEqual(r['security_updates'],1);self.assertEqual(r['other_updates'],1);self.assertTrue(r['reboot_required']);self.assertEqual(run.call_args.args[0],['apt-get','-s','-o','Debug::NoLocking=1','upgrade']);self.assertLessEqual(run.call_args.kwargs['timeout'],4)
 def test_timeout_is_unknown_not_zero_updates(self):
  with patch.object(p,'run',return_value={'status':'timeout'}):
   r=p.os_updates();self.assertIsNone(r['security_updates']);self.assertIsNone(r['other_updates']);self.assertEqual(r['status'],'timeout')
if __name__=='__main__':unittest.main(verbosity=2)
