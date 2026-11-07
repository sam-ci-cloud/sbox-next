"""Each current product identity must fail closed when changed independently."""
from pathlib import Path
import sys,json,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'SOURCE/tools'))
from check_versions import check
V=json.loads((ROOT/'SOURCE/VERSION.json').read_text())['version']
class Identity(unittest.TestCase):
 def test_current_identity(self):self.assertTrue(check(ROOT)['passed'])
 def test_each_version_mismatch_is_rejected(self):
  replacements={
   'SOURCE/src/manager.sh':lambda t:t.replace('MANAGER_VERSION="'+V+'"','MANAGER_VERSION="0.0.0"'),
   'SOURCE/shared_webui/backend/common.py':lambda t:t.replace("VERSION = '"+V+"'","VERSION = '0.0.0'"),
   'SOURCE/shared_webui/frontend/app.js':lambda t:t.replace('const PRODUCT_VERSION="'+V+'"','const PRODUCT_VERSION="0.0.0"'),
   'SOURCE/assets/release.json':lambda t:t.replace(V,'0.0.0'),
   'SOURCE/assets/zgocloud.json':lambda t:t.replace(V,'0.0.0'),
   'PROVENANCE.json':lambda t:t.replace(V,'0.0.0'),
   'SOURCE/BUILD.json':lambda t:t.replace(V,'0.0.0'),
   'PUBLIC_PAYLOAD.json':lambda t:t.replace('pkg-','pkg-0'),
   'SOURCE/package-lock.json':lambda t:t.replace('"version": "'+V+'"','"version": "0.0.0"',1),
   'SBOM.json':lambda t:t.replace(V,'0.0.0'),
   'README.md':lambda t:t.replace('# SBOX','# SBOX 0.0.0',1)}
  original=Path.read_text
  for name,change in replacements.items():
   with self.subTest(file=name):
    target=ROOT/name;before=original(target);self.assertNotEqual(change(before),before)
    def altered(path,*args,**kwargs):return change(before) if path==target else original(path,*args,**kwargs)
    with patch.object(Path,'read_text',altered):self.assertFalse(check(ROOT)['passed'],name)
if __name__=='__main__':unittest.main(verbosity=2)
