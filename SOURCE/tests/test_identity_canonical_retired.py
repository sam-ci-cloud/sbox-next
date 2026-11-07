"""A canonical repository name that equals a retired predecessor name is allowed only as the
canonical owner/name; the same name under another owner and every other retired name stay banned.
Synthetic names only (public files never contain real retired names)."""
import hashlib, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import identity

H = lambda word: hashlib.sha256(word.encode()).hexdigest()
REPO, RETIRED = 'example-owner/reused-name', (H('reused-name'), H('other-oldname'))


class CanonicalRetired(unittest.TestCase):
    def test_canonical_allowed_predecessors_refused(self):
        ref = lambda text: identity.foreign_reference(text, REPO, RETIRED)
        self.assertIsNone(ref('https://github.com/example-owner/reused-name/releases'))
        self.assertIsNone(ref('install reused-name'))
        self.assertEqual(ref('https://github.com/another-owner/reused-name'), 'retired repository name')
        self.assertEqual(ref('https://github.com/example-owner/other-oldname'), 'reference to a repository other than the canonical one')
        self.assertEqual(ref('see other-oldname notes'), 'retired repository name')

    def test_real_canonical_is_accepted(self):
        repo = identity.canonical(Path(__file__).resolve().parents[1])
        self.assertIsNone(identity.foreign_reference('https://github.com/%s/releases' % repo, repo))


if __name__ == '__main__':
    unittest.main()
