"""Offline documentation and local-delivery integrity regressions."""
from pathlib import Path
import hashlib, json, tempfile, unittest
from check_docs import anchors, check_link, distribution, markdown_links, validate
from pin_release import check as pin_check, main as pin_main, sync_tree

from identity import canonical
CANONICAL = canonical()

class OfflineDocumentationGate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.doc=self.root/'README.md'
        self.doc.write_text('# Start\n');(self.root/'guide.md').write_text('# Same\n## Same\n## 日本語 guide\n')
        self.assets=self.root/'assets';self.assets.mkdir();self.raw=b'#!/bin/sh\nexit 0\n';(self.root/'install.sh').write_bytes(self.raw)
        digest=hashlib.sha256(self.raw).hexdigest();(self.root/'BUILD.json').write_text('{}\n')
        release={'version':'1.1.1','installer_sha256':digest,'installer_bytes':len(self.raw),'components':{}}
        (self.assets/'release.json').write_text(json.dumps(release));(self.assets/'distribution.json').write_text(json.dumps({'schema':1,'channel':'candidate','version':'1.1.1','installer_sha256':digest,'installer_bytes':len(self.raw)}))
        (self.root/'install.sh.sha256').write_text(digest+'  install.sh\n')
    def tearDown(self):self.temp.cleanup()
    def test_local_file_and_duplicate_unicode_anchors(self):
        check_link(self.root,self.doc,'guide.md#same-1');check_link(self.root,self.doc,'guide.md#日本語-guide')
    def test_missing_local_file_fails(self):
        with self.assertRaisesRegex(AssertionError,'missing'):check_link(self.root,self.doc,'deleted.md')
    def test_missing_anchor_fails(self):
        with self.assertRaisesRegex(AssertionError,'anchor'):check_link(self.root,self.doc,'guide.md#missing')
    def test_escape_from_delivery_fails(self):
        with self.assertRaises(AssertionError):check_link(self.root,self.doc,'../outside.md')
    def standalone_docs(self,readme):
        from check_docs import REQUIRED
        for name in REQUIRED:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('# Guide\n\n```bash\ncd /root/SING-BOX\nbash install.sh\n```\n')
        (self.root/'README.md').write_text(readme)
        for d in ('src','shared_webui','core-source','assets','tools','tests','THIRD_PARTY_LICENSES'):
            (self.root/d).mkdir(exist_ok=True);(self.root/d/'README.md').write_text('# x\n')
    def test_standalone_entrypoint_documented(self):
        self.standalone_docs('# SBOX\n\n```bash\ncd /root/SING-BOX\nbash install.sh\n```\n');validate(self.root)
    def test_ignored_build_cache_is_outside_public_documentation_scan(self):
        self.standalone_docs('# SBOX\n\ncd /root/SING-BOX\nbash install.sh\n')
        cache=self.root/'__pycache__';cache.mkdir();(cache/'negative-fixture.pyc').write_text('https://github.com/'+CANONICAL.split('/')[0]+'/other-repo')
        validate(self.root)
    def test_retired_installer_layout_is_rejected(self):
        self.standalone_docs('# SBOX\n\ncd /root/SING-BOX\nbash install.sh\nsudo bash installer/install.sh\n')
        with self.assertRaisesRegex(AssertionError,'Retired installer'):validate(self.root)
    def test_missing_standalone_entrypoint_is_rejected(self):
        self.standalone_docs('# SBOX\n')
        with self.assertRaisesRegex(AssertionError,'Standalone package command missing'):validate(self.root)
    def test_inactive_project_repository_link_is_rejected(self):
        with self.assertRaisesRegex(AssertionError,'Inactive product repository'):check_link(self.root,self.doc,'https://github.com/'+CANONICAL.split('/')[0]+'/other-repo'+'/releases')
    def test_unrelated_upstream_link_remains_valid_without_fetch(self):
        check_link(self.root,self.doc,'https://github.com/SagerNet/sing-box/tree/v1.13.14')
    def test_reference_links_require_definition(self):
        self.assertIn('guide.md#same',markdown_links('[guide][g]\n\n[g]: guide.md#same\n'))
        with self.assertRaisesRegex(AssertionError,'Undefined'):markdown_links('[guide][missing]')
    def test_fenced_fake_heading_is_not_anchor(self):self.assertEqual(anchors('# Real\n```bash\n# Fake\n```\n'),{'real'})
    def test_distribution_verifies_only_included_installer(self):
        data=distribution(self.root);self.assertEqual(data['version'],'1.1.1');self.assertNotIn('source_commit',data);self.assertNotIn('repository',data)
    def test_distribution_rejects_repository_or_commit_dependency(self):
        path=self.assets/'distribution.json';data=json.loads(path.read_text())
        for key,value in [('repository','example-owner/other-repo'),('source_commit','a'*40)]:
            with self.subTest(key=key):
                path.write_text(json.dumps({**data,key:value}))
                with self.assertRaisesRegex(AssertionError,'repository or commit'):distribution(self.root)
        path.write_text(json.dumps(data))
    def test_distribution_rejects_bad_channel_and_schema(self):
        path=self.assets/'distribution.json';data=json.loads(path.read_text())
        for key,value in [('channel','guaranteed'),('schema',True)]:
            with self.subTest(key=key):
                path.write_text(json.dumps({**data,key:value}))
                with self.assertRaises(AssertionError):distribution(self.root)
    def test_distribution_rejects_tampered_installer_and_sidecar(self):
        (self.root/'install.sh').write_bytes(b'tampered')
        with self.assertRaisesRegex(AssertionError,'metadata mismatch'):distribution(self.root)
    def test_local_sync_refreshes_hashes_and_check_detects_drift(self):
        (self.root/'install.sh').write_bytes(b'#!/bin/sh\necho new\n');sync_tree(self.root)
        self.assertEqual(pin_check(self.root),[])
        (self.root/'install.sh.sha256').write_text('0'*64+'  install.sh\n')
        self.assertTrue(pin_check(self.root))
    def test_legacy_git_commit_pinning_is_disabled(self):
        with self.assertRaises(SystemExit):pin_main(['--root',str(self.root),'--commit','a'*40])
    def test_validate_requires_complete_delivery_docs(self):
        with self.assertRaisesRegex(AssertionError,'Required documentation'):validate(self.root)

if __name__=='__main__':unittest.main(verbosity=2)
