"""Guard the clean publication tree and its content-addressed bootstrap pin."""
import json, re, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'SOURCE/tools'))
from identity import canonical, foreign_reference
CANONICAL = canonical(ROOT / 'SOURCE')


class References(unittest.TestCase):
    def test_no_other_repository_reference_in_public_tree(self):
        found = []
        for p in ROOT.rglob('*'):
            if p.is_file() and not p.is_symlink() and not {'.git', '.build', '__pycache__', 'node_modules'}.intersection(p.parts):
                if foreign_reference(p.read_bytes().decode('latin-1'), CANONICAL):
                    found.append(p.relative_to(ROOT).as_posix())
        self.assertEqual(found, [], 'Repository identity violations: ' + repr(found))

    def test_exact_content_addressed_bootstrap_pin(self):
        d = json.loads((ROOT / 'PUBLIC_PAYLOAD.json').read_text()); s = (ROOT / 'install.sh').read_text()
        self.assertNotIn('version', d)
        self.assertEqual(d['tag'], 'pkg-' + d['sha256'][:16])
        self.assertEqual(d['url'], f"https://github.com/{CANONICAL}/releases/download/{d['tag']}/SING-BOX.tar.gz")
        self.assertEqual(d['bootstrap_url'], f'https://raw.githubusercontent.com/{CANONICAL}/main/install.sh')
        self.assertIn(f"SBOX_SHA256='{d['sha256']}'", s); self.assertIn(f"SBOX_URL='{d['url']}'", s)
        self.assertNotRegex(s, r'(?i)SBOX \d+\.\d+\.\d+|/v\d+\.\d+\.\d+/')
        self.assertRegex(s, r'exec env --default-signal=.* bash "\$SBOX_STAGE/SING-BOX/install.sh"')


if __name__ == '__main__':
    unittest.main(verbosity=2)
