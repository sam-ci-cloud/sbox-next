"""Manager output is returned intact up to the bound and refused (never cut off) beyond it: a complete
sing-box profile with offline rule sets is ~300 KB and was served truncated at 256 KiB before."""
import os, sys, tempfile, unittest
from pathlib import Path
sys.path[:0] = [str(Path(__file__).resolve().parents[1] / p) for p in ('backend', 'privileged-bridge')]
import bridge
from common import Problem


class OutputBound(unittest.TestCase):
    def run_with(self, size):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / 'emit.sh'; script.write_text('#!/bin/sh\nhead -c %d /dev/zero | tr "\\0" x\n' % size); script.chmod(0o700)
            control = bridge.Control.__new__(bridge.Control); control.manager = '/nonexistent/sbox'
            return control.run([str(script)])

    def test_large_export_is_returned_intact(self):
        out = self.run_with(330000)
        self.assertEqual(len(out), 330000, 'no silent truncation (a CN complete profile is ~300 KB)')

    def test_beyond_bound_fails_closed(self):
        with self.assertRaises(Problem) as e:
            self.run_with(bridge.MAX_OUTPUT + 1)
        self.assertEqual(e.exception.status, 507)

    def test_bound_fits_the_server_control_limit(self):
        # JSON escaping of ASCII output adds little; the server refuses responses above 1 MiB.
        self.assertLessEqual(bridge.MAX_OUTPUT, 1048576 - 65536)


if __name__ == '__main__':
    unittest.main()
