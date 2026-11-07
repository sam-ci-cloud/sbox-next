import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('resolver',ROOT/'shared_webui/backend/core_resolver.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class SecurityPolicy(unittest.TestCase):
 def test_legacy_cache_is_not_security_qualified(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'sing-box').write_bytes(b'old compiler core');m={'version':'1.14.4','architecture':'linux-amd64','sha256':r.sha(root/'sing-box'),'patch_sha256':r.sha(r.PATCH),'tests_passed':True,'coverage':{p:True for p in r.PROTOCOLS}};(root/'provenance.json').write_text(json.dumps(m));self.assertIsNone(r.verified_cached(root,'v1.14.4','amd64'))
 def test_module_versions_order_without_downgrading_future_versions(self):
  for newer,older in [('v1.90.0','v1.83.2'),('v0.58.1','v0.58.1-0.20261009181718-2f1f834330b2'),('v0.0.0-20260719225207-c76316d4aa82','v0.0.0-20260220084031-5adc3eb26f91')]:self.assertTrue(r.module_version_at_least(newer,older));self.assertFalse(r.module_version_at_least(older,newer))
 def test_security_manifest_requires_both_scans(self):
  m={'security_policy':r.SECURITY_POLICY,'security_scans':{'modules':0,'binary':0}};self.assertTrue(r.security_qualified(m));m['security_scans']['modules']=1;self.assertFalse(r.security_qualified(m));self.assertFalse(r.security_qualified({}))
 def test_compression_advisory_floors_raise_vulnerable_graph(self):
  # GO-2026-6888 fixed in brotli v1.2.7; GO-2026-6865 fixed in klauspost/compress v1.20.2.
  self.assertTrue(r.module_version_at_least(r.SECURITY_FLOORS['github.com/andybalholm/brotli'],'v1.2.7'))
  self.assertTrue(r.module_version_at_least(r.SECURITY_FLOORS['github.com/klauspost/compress'],'v1.20.2'))
  graph=''.join(json.dumps({'Path':p,'Version':v}) for p,v in [('github.com/andybalholm/brotli','v1.1.0'),('github.com/klauspost/compress','v1.19.1'),('golang.org/x/net','v0.62.0')])
  calls=[]
  with patch.object(r.subprocess,'check_output',return_value=graph),patch.object(r,'run',side_effect=lambda cmd,**kw:calls.append(cmd)):
   updates=r.apply_security_floors(Path('.'),'go',{},None)
  self.assertEqual(sorted(updates),['github.com/andybalholm/brotli@v1.2.7','github.com/klauspost/compress@v1.20.2'])
  self.assertEqual(calls[0][:2],['go','get'])
  fixed=''.join(json.dumps({'Path':p,'Version':v}) for p,v in [('github.com/andybalholm/brotli','v1.2.8'),('github.com/klauspost/compress','v1.20.2')])
  with patch.object(r.subprocess,'check_output',return_value=fixed),patch.object(r,'run') as run:
   self.assertEqual(r.apply_security_floors(Path('.'),'go',{},None),[]);run.assert_not_called()
 def test_old_compiler_cache_cannot_be_selected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);old=root/'toolchain/go/bin/go';old.parent.mkdir(parents=True);old.write_text('old compiler')
   with patch.object(r.shutil,'which',return_value=None),patch.object(r,'get',side_effect=ValueError('test network blocked')):
    with self.assertRaises(ValueError):r.toolchain(root)
if __name__=='__main__':unittest.main(verbosity=2)
