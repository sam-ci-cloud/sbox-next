import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runner',ROOT/'tools/test.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
class RunnerCLI(unittest.TestCase):
 def test_selection_is_explicit_and_deduplicated(self):
  paths=runner.select_suites(['test_test_runner','tests/test_test_runner.py'])
  self.assertEqual([p.name for p in paths],['test_test_runner.py'])
 def test_unknown_selection_fails_instead_of_running_all(self):
  with self.assertRaises(ValueError):runner.select_suites(['no_such_suite'])
 def test_listing_does_not_build_or_execute(self):
  self.assertEqual(runner.main(['--list','--suite','test_test_runner']),0)
 def test_invalid_timeout_rejected(self):
  with self.assertRaises(SystemExit):runner.parse_args(['--timeout','0'])
 def test_skip_build_requires_valid_build(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(RuntimeError):runner.require_build(Path(d))
if __name__=='__main__':unittest.main(verbosity=2)
