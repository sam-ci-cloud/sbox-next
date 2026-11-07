#!/usr/bin/env python3
"""Semantic selection, cache tamper and fail-closed accounting core resolution."""
from pathlib import Path
import importlib.util, json, tempfile, unittest, sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('resolver',ROOT/'shared_webui/backend/core_resolver.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
_real_seed = r.seed_bundled
class DynamicCore(unittest.TestCase):
 def setUp(self):
  seed=patch.object(r,'seed_bundled',return_value=None);seed.start();self.addCleanup(seed.stop)
 def test_bundled_tested_core_seeds_verified_cache_without_compiler(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);binary=d/'bundled';binary.write_bytes(b'tested-bundled-core');cache=d/'cache';cache.mkdir()
   m={'version':'1.14.2','architecture':'linux-amd64','sha256':r.sha(binary),'patch_sha256':r.sha(r.PATCH),'security_policy':r.SECURITY_POLICY,'security_scans':{'modules':0,'binary':0},'tests_passed':True,'coverage':{p:True for p in r.PROTOCOLS}}
   manifest=d/'core_manifest.json';manifest.write_text(json.dumps(m))
   _real_seed(cache,'amd64',manifest,binary)
   self.assertEqual(r.verified_cached(cache/'core-v1.14.2-amd64','1.14.2','amd64'),m)

 def test_semantic_stable_selection_filters_prereleases(self):
  values=['v1.13.9','v1.13.21','v1.14.0-beta.9','v1.14.0','v1.14.4','v1.14.4','garbage']
  self.assertEqual(r.candidates(values,'latest'),['v1.14.4','v1.14.0','v1.13.21','v1.13.9'])
  self.assertEqual(r.candidates(values,'beta')[2],'v1.14.0-beta.9')
  self.assertEqual(r.candidates(values,'1.13.21'),['v1.13.21'])
 def test_invalid_exact_version_cannot_be_command_or_path(self):
  for v in ['../x','1.2.3;touch x','latest;true','v1.2','1.2.3\n']:
   with self.subTest(v=v),self.assertRaises(ValueError):r.candidates([],v)
 def test_failure_preserves_existing_output(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);out=d/'live-core';out.write_bytes(b'last-good')
   with patch.object(r,'get',return_value=b'v1.14.4\nv1.13.21\n'),patch.object(r,'toolchain',return_value='go'),patch.object(r.shutil,'which',return_value='/usr/bin/git'),patch.object(r,'build',side_effect=ValueError('incompatible patch')):
    with self.assertRaises(ValueError):r.resolve('latest',out,d/'cache')
   self.assertEqual(out.read_bytes(),b'last-good')
   self.assertEqual(len(json.loads((d/'cache/last-resolution.json').read_text())['attempts']),2)
 def test_compatible_fallback_records_rejections_and_digest(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);binary=d/'compiled';binary.write_bytes(b'compiled-accounting')
   m={'version':'1.13.21','sha256':r.sha(binary),'tests_passed':True}
   with patch.object(r,'get',return_value=b'v1.14.4\nv1.13.21\n'),patch.object(r,'toolchain',return_value='go'),patch.object(r.shutil,'which',return_value='/usr/bin/git'),patch.object(r,'build',side_effect=[ValueError('patch rejected'),(binary,m)]):
    self.assertEqual(r.resolve('latest',d/'out',d/'cache'),m)
   report=json.loads((d/'cache/last-resolution.json').read_text());self.assertEqual(report['status'],'resolved');self.assertEqual(len(report['attempts']),1)
   self.assertEqual((d/'out').read_bytes(),binary.read_bytes())
 def test_cache_requires_actual_binary_digest_patch_and_coverage(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);binary=d/'sing-box';binary.write_bytes(b'core')
   m={'version':'1.13.21','architecture':'linux-amd64','sha256':r.sha(binary),'patch_sha256':r.sha(r.PATCH),'security_policy':r.SECURITY_POLICY,'security_scans':{'modules':0,'binary':0},'tests_passed':True,'coverage':{p:True for p in r.PROTOCOLS}}
   (d/'provenance.json').write_text(json.dumps(m));self.assertEqual(r.verified_cached(d,'v1.13.21','amd64'),m)
   binary.write_bytes(b'tampered');self.assertIsNone(r.verified_cached(d,'v1.13.21','amd64'))
 def test_exact_cached_version_needs_no_metadata_network(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);cache=d/'cache';root=cache/'core-v1.13.21-amd64';root.mkdir(parents=True);binary=root/'sing-box';binary.write_bytes(b'known-good')
   m={'version':'1.13.21','architecture':'linux-amd64','sha256':r.sha(binary),'patch_sha256':r.sha(r.PATCH),'security_policy':r.SECURITY_POLICY,'security_scans':{'modules':0,'binary':0},'tests_passed':True,'coverage':{p:True for p in r.PROTOCOLS}}
   (root/'provenance.json').write_text(json.dumps(m))
   with patch.object(r,'get',side_effect=AssertionError('network must not run')),patch.object(r,'toolchain',side_effect=AssertionError('compiler unnecessary')),patch.object(r.shutil,'which',return_value='/usr/bin/git'):
    self.assertEqual(r.resolve('1.13.21',d/'out',cache),m)

 def test_symlink_cache_refused(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);(d/'real').mkdir();(d/'alias').symlink_to(d/'real',target_is_directory=True)
   with self.assertRaises(ValueError):r.secure_cache(d/'alias')
 def test_preview_validates_requests_and_explains_unbuilt_versions(self):
  with tempfile.TemporaryDirectory() as td:
   for request in ['latest','beta','1.14.2']:
    value=r.preview(request,Path(td));self.assertTrue(value['build_required']);self.assertIsNone(value['sha256'])
   with self.assertRaises(ValueError):r.preview('../arbitrary',Path(td))

 def test_no_version_freeze_in_state_or_accounting_activation(self):
  for path in ['src/state.py','shared_webui/backend/state_validation.inc','shared_webui/backend/accounting_install.py']:
   self.assertNotIn("state['sing_box']['version']=='1.13.14'",(ROOT/path).read_text(),path)
 def test_manager_dispatches_dynamic_sources(self):
  s=(ROOT/'src/core_source.sh').read_text()
  self.assertIn('core_resolver.py',s)
  self.assertNotIn('Online core download is not available',s)
if __name__=='__main__':unittest.main(verbosity=2)
