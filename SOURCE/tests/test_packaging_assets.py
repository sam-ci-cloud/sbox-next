"""Git deliberately omits generated core assets; transferred source must retain them."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import make_standalone as package


class RequiredAssets(unittest.TestCase):
    def test_git_tracked_source_omits_core_but_transfer_includes_verified_asset(self):
        paths=[p for p in package.tracked_files(ROOT) if p.relative_to(ROOT).as_posix()!='assets/sing-box-accounting.gz']
        with patch.object(package,'tracked_files',return_value=paths):
            files=package.collect([])
        blob=files['source/assets/sing-box-accounting.gz'][0]
        self.assertEqual(hashlib.sha256(blob).hexdigest(),json.loads((ROOT/'BUILD.json').read_text())['core_gzip_sha256'])

    def test_missing_or_tampered_generated_asset_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'assets').mkdir()
            (root/'BUILD.json').write_text(json.dumps({'core_gzip_sha256':hashlib.sha256(b'expected').hexdigest()}))
            with self.assertRaises(SystemExit):package.required_core_asset(root)
            (root/'assets/sing-box-accounting.gz').write_bytes(b'wrong')
            with self.assertRaises(SystemExit):package.required_core_asset(root)
            (root/'assets/sing-box-accounting.gz').write_bytes(b'expected')
            self.assertEqual(package.required_core_asset(root),b'expected')


if __name__=='__main__':unittest.main(verbosity=2)
