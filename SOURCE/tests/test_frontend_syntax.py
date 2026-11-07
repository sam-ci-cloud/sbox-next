#!/usr/bin/env python3
"""Every shipped frontend script parses, and the assembled frontend matches its sources.

Regression: a duplicated `let` in the core-update handler made app.js fail to
parse, which left the whole admin shell hidden; only a browser run noticed.
"""
import shutil, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FrontendSyntax(unittest.TestCase):
    def test_assembled_frontend_matches_sources(self):
        r = subprocess.run([sys.executable, str(ROOT / 'shared_webui/tools/build_frontend.py'), '--check'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_shipped_script_parses(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js not installed; JavaScript parse check NOT RUN')
        scripts = sorted((ROOT / 'shared_webui/frontend').glob('*.js')) + sorted((ROOT / 'src/fallback-web/site').rglob('*.js'))
        self.assertTrue(scripts)
        for path in scripts:
            with self.subTest(script=path.name):
                r = subprocess.run([node, '--check', str(path)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_duplicate_declaration_is_detected(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js not installed; negative control NOT RUN')
        r = subprocess.run([node, '--check', '-'], input='async function f(){ let preview = 1;\n let preview; }\n', capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
