"""Adversarial primitives for the encrypted full verifier; real kit checked at delivery.
A toy checksum-only directory must not be called a complete owner delivery.
"""
import hashlib,importlib.util,io,tarfile,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('delivery',Path(__file__).resolve().parents[1]/'tools/verify_full_delivery.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class Verifier(unittest.TestCase):
 def files(self):
  files={'example':b'owned-fixture'};files['SHA256SUMS']=(hashlib.sha256(files['example']).hexdigest()+'  example\n').encode();return files
 def test_complete_manifest_and_tampered_missing_or_extra_members(self):
  files=self.files();self.assertEqual(d.manifest(files),1)
  for broken in [{**files,'example':b'changed'},{'SHA256SUMS':files['SHA256SUMS']},{**files,'extra':b'unlisted'}]:
   with self.subTest(members=list(broken)),self.assertRaises(ValueError):d.manifest(broken)
 def test_path_traversal_and_duplicate_manifest_entries_fail(self):
  for name in ['../escape','/absolute','folder/../escape','folder//file','folder\\file']:
   with self.subTest(name=name),self.assertRaises(ValueError):d.safe(name)
  files=self.files();files['SHA256SUMS']*=2
  with self.assertRaises(ValueError):d.manifest(files)
 def test_tar_links_devices_and_traversal_fail_before_extraction(self):
  for name,kind in [('../escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('device',tarfile.CHRTYPE)]:
   buf=io.BytesIO()
   with tarfile.open(fileobj=buf,mode='w') as t:i=tarfile.TarInfo(name);i.type=kind;i.linkname='target';t.addfile(i)
   with self.subTest(name=name),self.assertRaises(ValueError):d.tar_files(buf.getvalue())
 def test_checksum_only_tree_is_not_a_complete_owner_delivery(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   for n,b in self.files().items():(root/n).write_bytes(b)
   with self.assertRaises((KeyError,ValueError)):d.verify(root,root/'absent-owner-key')
 def test_nested_manifest_must_be_listed(self):
  # Regression for the original owner ZIP: two nested SHA256SUMS files were unlisted.
  files=self.files();files['sub/SHA256SUMS']=b'x'
  with self.assertRaisesRegex(ValueError,'cover every file'):d.manifest(files)
  files['SHA256SUMS']+=(hashlib.sha256(b'x').hexdigest()+'  sub/SHA256SUMS\n').encode();self.assertEqual(d.manifest(files),2)
 def test_version_named_top_level_entry_is_rejected(self):
  import re
  self.assertTrue(re.search(r'(?i)(^|[^0-9])v?\d+\.\d+\.\d+','SBOX-1.2.3-SOURCE.zip'))
  self.assertFalse(re.search(r'(?i)(^|[^0-9])v?\d+\.\d+\.\d+','PACKAGE'))
if __name__=='__main__':unittest.main(verbosity=2)
