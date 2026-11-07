"""Negative controls prevent a successful exit from replacing executed tests."""
from pathlib import Path
import importlib.util
import json
import os
import sys
import unittest

spec = importlib.util.spec_from_file_location('sbox_test_runner', Path(__file__).resolve().parents[1] / 'tools/test.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerEvidence(unittest.TestCase):
    def assess(self, output, code=0):
        return runner.assess_output('tests/test_example.py', code, output)

    def test_empty_success_fails(self):
        self.assertEqual(self.assess('')['status'], 'failed')

    def test_zero_discovered_tests_fail(self):
        self.assertEqual(self.assess('Ran 0 tests in 0.000s\n\nOK\n')['status'], 'failed')

    def test_failure_text_cannot_be_hidden_by_success_exit(self):
        self.assertEqual(self.assess('Ran 1 test in 0.001s\nFAILED (failures=1)\n')['status'], 'failed')

    def test_nonzero_exit_overrides_an_ok_report(self):
        self.assertEqual(self.assess('Ran 1 test in 0.001s\nOK\n', 1)['status'], 'failed')

    def test_skips_are_not_counted_as_executed(self):
        result = self.assess('Ran 3 tests in 0.001s\nOK (skipped=1)\n')
        self.assertEqual((result['status'], result['executed_checks'], result['skipped']), ('passed', 2, 1))

    def test_all_skipped_is_not_a_pass(self):
        result = self.assess('Ran 2 tests in 0.001s\nOK (skipped=2)\n')
        self.assertEqual(result['status'], 'skipped')
        self.assertEqual(runner.summarize([result], complete=True)['status'], 'failed')

    def test_duplicate_or_invalid_reports_fail(self):
        for output in ['Ran 1 test in 0.1s\nOK (skipped=2)\n', 'Ran 1 test in 0.1s\nOK\nRan 1 test in 0.1s\nOK\n']:
            with self.subTest(output=output):
                self.assertEqual(self.assess(output)['status'], 'failed')

    def test_archive_assertions_must_be_nonempty_unique_and_complete(self):
        valid = {'runtime_sha256': 'a' * 64, 'results': [{'test': str(i), 'status': 'PASS'} for i in range(8)]}
        result = runner.assess_output('tests/test_assets.py', 0, json.dumps(valid))
        self.assertEqual((result['status'], result['script_checks']), ('passed', 8))
        for checks in [[], valid['results'][:1], [valid['results'][0]] * 8]:
            with self.subTest(checks=checks):
                self.assertEqual(runner.assess_output('tests/test_assets.py', 0, json.dumps({**valid, 'results': checks}))['status'], 'failed')

    def test_actual_unittest_process_executes(self):
        source = "import unittest\nclass T(unittest.TestCase):\n def test_real(self): self.assertEqual(2+2,4)\nunittest.main()"
        code, output = runner.run_process([sys.executable, '-c', source], os.environ.copy(), timeout=10)
        self.assertEqual(self.assess(output, code)['status'], 'passed')

    def test_timeout_is_not_a_pass(self):
        code, output = runner.run_process([sys.executable, '-c', 'import time;time.sleep(10)'], os.environ.copy(), timeout=0.2)
        self.assertEqual(code, 124)
        self.assertEqual(self.assess(output, code)['status'], 'failed')

    def test_incomplete_progress_is_never_a_completed_pass(self):
        good = self.assess('Ran 1 test in 0.001s\nOK\n')
        self.assertEqual(runner.summarize([good])['status'], 'running')
        self.assertFalse(runner.summarize([good])['complete'])
        self.assertEqual(runner.summarize([good], complete=True)['status'], 'passed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
