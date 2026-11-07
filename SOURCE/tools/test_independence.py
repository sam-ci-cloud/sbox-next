#!/usr/bin/env python3
"""Adversarial cases for nested release-artifact independence inspection.

Fixtures use neutral names only: `example-owner/current-repo` is the canonical
repository and `legacy-fixture-repo` is registered as retired by digest.
"""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from verify_independence import IndependenceError, Scanner, scan_tree
import identity

CANONICAL = "example-owner/current-repo"
RETIRED = hashlib.sha256(b"legacy-fixture-repo").hexdigest()


def scanner():
    return Scanner(CANONICAL, {RETIRED})


class IndependenceTests(unittest.TestCase):
    def old_url(self):
        return ("https://raw.githubusercontent.com/" + "example-owner/" + "other-repo/main/install.sh").encode()

    def assert_denied(self, data):
        with self.assertRaises(IndependenceError):
            scanner().scan("fixture", data)

    def test_other_repository_of_same_owner_is_denied(self):
        self.assert_denied(self.old_url())
        self.assert_denied(b'{"repository":"example-owner/other-repo"}')
        self.assert_denied(b"git@github.com:example-owner/other-repo.git")
        self.assert_denied(b"https://api.github.com/repos/example-owner/Current-Repo-old/releases")

    def test_encoded_url_and_json_slashes(self):
        self.assert_denied(self.old_url().replace(b"other", b"%256fther"))
        self.assert_denied(self.old_url().replace(b"/", b"\\/"))
        self.assert_denied(b"\x7fELF\0" + self.old_url().replace(b"other", b"%6fther") + b"\0")

    def test_retired_name_without_owner_is_denied(self):
        for text in (b"cp legacy-fixture-repo-installer.sh /tmp", b"name=LEGACY_FIXTURE_REPO", b"x legacy-fixture-repo"):
            with self.subTest(text=text):
                self.assert_denied(text)

    def test_canonical_repository_and_upstream_are_allowed(self):
        scanner().scan("fixture", b"https://github.com/example-owner/current-repo/releases/download/pkg-0123456789abcdef/SING-BOX.tar.gz\n")
        scanner().scan("fixture", b"git clone https://github.com/example-owner/current-repo.git\n")
        scanner().scan("fixture", b"https://github.com/SagerNet/sing-box\nlegacy-fixture-report\n")

    def test_published_digests_are_not_generic_words(self):
        for word in ("sbox", "singbox", "sing-box", "sbox", "install", "fixture"):
            self.assertIsNone(identity.retired_name(word + " x"), word)

    def test_canonical_is_read_from_version_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "VERSION.json").write_text(json.dumps({"repository": CANONICAL}))
            self.assertEqual(identity.canonical(root), CANONICAL)
            (root / "VERSION.json").write_text(json.dumps({"repository": "no-slash"}))
            with self.assertRaises(identity.IdentityError):
                identity.canonical(root)

    def test_gzip_and_zip_are_inspected(self):
        self.assert_denied(gzip.compress(self.old_url()))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("source/loader.sh", self.old_url())
        self.assert_denied(stream.getvalue())

    def test_embedded_manager_and_web_archive_are_inspected(self):
        encoded = base64.b64encode(gzip.compress(self.old_url()))
        self.assert_denied(b"<<'SBOX_GENERIC_PAYLOAD'\n" + encoded + b"\nSBOX_GENERIC_PAYLOAD\n")
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("backend/loader.py")
            member.size = len(self.old_url())
            archive.addfile(member, io.BytesIO(self.old_url()))
        encoded = base64.b64encode(gzip.compress(stream.getvalue()))
        self.assert_denied(b"blob=base64.b64decode('" + encoded + b"',validate=True)")

    def test_lfs_pointer_is_rejected(self):
        with self.assertRaisesRegex(IndependenceError, "LFS"):
            scanner().scan("fixture", b"version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 10\n")

    def test_vps_acceptance_uses_authorized_nodes_and_verified_host_keys(self):
        script=(Path(__file__).resolve().parents[1]/'tools/vps_acceptance.sh').read_text()
        self.assertNotIn('api.ipify.org',script)
        self.assertNotIn('StrictHostKeyChecking=no',script)
        self.assertIn('StrictHostKeyChecking=accept-new',script)

    def test_standalone_source_tree_scans_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('offline source fixture\n')
            (root / 'VERSION.json').write_text(json.dumps({'repository': CANONICAL}))
            self.assertGreater(scan_tree(root).objects, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
