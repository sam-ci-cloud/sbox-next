"""A restore declined through --yes defaults must not report success (VALIDATION.md 1.8.1 drill)."""
import re, subprocess, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def function(name):
    text = (ROOT / 'src/manager.sh').read_text()
    m = re.search(r'^%s\(\) \{\n.*?^\}\n' % re.escape(name), text, re.S | re.M)
    return m.group(0)


class RestoreDeclined(unittest.TestCase):
    def run_case(self, assume_defaults):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td) / 'restored', Path(td) / 'temp'; a.mkdir(); b.mkdir()
            script = ('set -Eeuo pipefail\nRED=; RESET=\ndie() { printf "[ERROR] %%s\\n" "$*" >&2; exit 1; }\nASSUME_DEFAULTS=%s\n%s'
                      'restore() { restore_declined "%s" "%s"; return 0; }\nrestore\necho after\n') % (assume_defaults, function('restore_declined'), a, b)
            r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
            return r, a.exists(), b.exists()

    def test_yes_defaults_fail_and_clean_up(self):
        r, a, b = self.run_case('true')
        self.assertEqual(r.returncode, 1); self.assertIn('Restore not performed', r.stderr); self.assertIn('--force', r.stderr)
        self.assertNotIn('after', r.stdout); self.assertFalse(a or b, 'staging removed')

    def test_interactive_no_is_a_clean_cancel(self):
        r, a, b = self.run_case('false')
        self.assertEqual(r.returncode, 0); self.assertIn('Cancelled.', r.stdout); self.assertFalse(a or b)

    def test_restore_prompt_uses_the_helper(self):
        self.assertIn("|| { restore_declined \"${restored_dir:-}\" \"$temp\"; return 0; }", (ROOT / 'src/manager.sh').read_text())


if __name__ == '__main__':
    unittest.main()
