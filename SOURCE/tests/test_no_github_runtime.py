#!/usr/bin/env python3
"""The shipped tree, generated installer and (with the owner unlock) the
decrypted ZgoCloud manager contain no runtime GitHub/mirror dependency."""
import os, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / 'tools/scan_runtime_github.py'


def run(*extra):
    return subprocess.run([sys.executable, str(SCANNER), '--root', str(ROOT), *extra], capture_output=True, text=True, timeout=300)


class NoGitHubRuntime(unittest.TestCase):
    def test_source_tree_and_generated_installer(self):
        r = run('--installer', str(ROOT / 'install.sh'))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('"status": "PASS"', r.stdout)

    def test_decrypted_zgocloud_manager(self):
        unlock = os.environ.get('SBOX_ZGO_UNLOCK_FILE')
        if not unlock:
            self.skipTest('Owner unlock not supplied (set SBOX_ZGO_UNLOCK_FILE); ZgoCloud plaintext scan NOT RUN')
        r = run('--unlock-file', unlock)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('"zgocloud_plaintext_scanned": true', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
