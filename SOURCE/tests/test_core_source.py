#!/usr/bin/env python3
"""Local core imports and the explicit missing-resolver failure path.

Runs the real obtain_core/pinned_core_file/validate_tarball functions extracted
from the built Universal manager against synthetic local fixtures. A curl/wget
stub records any network attempt; every case asserts that none happened.
"""
import base64, gzip, hashlib, io, json, os, re, shutil, subprocess, tarfile, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILT = Path(os.environ.get('SBOX_MANAGER_ROOT', ROOT / '.build')) / 'src/manager.sh'
HELPERS = ['valid_version', 'version_ge', 'version_lt', 'core_minimum_ok', 'binary_version', 'detect_arch', 'trim', 'yes_no',
           'valid_sha256', 'core_expected_sha256', 'pinned_core_file', 'validate_tarball', 'core_archive_version', 'core_resolve_build', 'obtain_core']


def manager_text():
    if not BUILT.is_file():
        subprocess.run(['python3', str(ROOT / 'tools/build.py')], check=True, stdout=subprocess.DEVNULL)
    return BUILT.read_text()


def extract(text, name):
    m = re.search(r'^' + re.escape(name) + r'\(\) \{.*?^\}\n', text, re.M | re.S) or \
        re.search(r'^' + re.escape(name) + r'\(\) \{[^\n]*\}\n', text, re.M)
    if not m:
        raise AssertionError('function missing from built manager: ' + name)
    return m.group(0)


def fake_core(path, version, pad=0):
    # A shell "binary" that reports a version. Optional random padding makes
    # archives exceed the real-size structural minimum.
    body = '#!/bin/sh\necho "sing-box version %s"\nexit 0\n' % version
    if pad:
        body += '#' + base64.b64encode(os.urandom(pad)).decode() + '\n'
    Path(path).write_text(body)
    Path(path).chmod(0o755)


class CoreSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = manager_text()
        cls.text = text
        consts = ['ACCOUNTING_CORE_CANDIDATE', 'ACCOUNTING_CORE_MANIFEST', 'CORE_HELP_TEXT']
        lines = [m.group(0) for c in consts for m in [re.search(r'^' + c + r'=.*$', text, re.M)]]
        cls.lib = '\n'.join(lines) + '\n' + ''.join(extract(text, n) for n in HELPERS)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sbox-core-test-'))
        self.bin = self.tmp / 'bin'; self.bin.mkdir()
        self.netlog = self.tmp / 'network.log'
        for tool in ('curl', 'wget'):
            stub = self.bin / tool
            stub.write_text('#!/bin/sh\necho "%s $*" >> %s\nexit 99\n' % (tool, self.netlog))
            stub.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_core(self, source, digest='', env=None, assume='false', force='false', candidate=None, manifest=None):
        out = self.tmp / 'out' / 'sing-box'
        out.parent.mkdir(exist_ok=True)
        for stale in (out, out.parent / 'sing-box.version'):
            stale.unlink(missing_ok=True)
        script = f'''set -Eeuo pipefail
log() {{ echo "LOG $*" >&2; }}; warn() {{ echo "WARN $*" >&2; }}; die() {{ echo "DIE $*" >&2; exit 3; }}
exec_mktemp_dir() {{ mktemp -d "{self.tmp}/stage.XXXXXX"; }}
ASSUME_DEFAULTS={assume}; ASSUME_FORCE={force}; MIN_SINGBOX_VERSION=1.12.0
{self.lib}
ACCOUNTING_CORE_CANDIDATE="{candidate or self.tmp / 'no-candidate'}"
ACCOUNTING_CORE_MANIFEST="{manifest or self.tmp / 'no-manifest.json'}"
obtain_core "$1" "$2" "$3" </dev/null
'''
        e = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp),
             'SBOX_CORE_RESOLVER': str(self.tmp/'missing-resolver.py')}
        e.update(env or {})
        r = subprocess.run(['bash', '-c', script, 'core-test', source, str(out), digest], capture_output=True, text=True, env=e, timeout=60)
        self.assertFalse(self.netlog.exists(), 'network tool invoked: ' + (self.netlog.read_text() if self.netlog.exists() else ''))
        return r, out

    def test_built_manager_has_no_network_core_source(self):
        for fragment in ('api.github.com', 'github.com/SagerNet/sing-box/releases', 'ghproxy', 'gh-proxy', 'ghfast',
                         'download_binary', 'CN_PROXY_PREFIXES', 'release_api_url', 'SBOX_ALLOW_UNVERIFIED_MIRROR'):
            self.assertNotIn(fragment, self.text)
        self.assertEqual(self.text.count('# BEGIN SBOX LOCAL CORE SOURCE'), 1)

    def test_online_channels_are_refused_without_network(self):
        for request in ('latest', 'stable', 'beta', 'prerelease'):
            with self.subTest(request=request):
                r, out = self.run_core(request)
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertIn('resolver is not installed', r.stderr)
                self.assertFalse(out.exists())

    def test_installer_supplied_pinned_core(self):
        core = self.tmp / 'sing-box-accounting'; fake_core(core, '1.13.14')
        for request in ('pinned', '', str(core), '1.13.14'):
            with self.subTest(request=request):
                r, out = self.run_core(request, env={'SBOX_ACCOUNTING_CORE_SOURCE': str(core)})
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual((out.parent / 'sing-box.version').read_text().strip(), '1.13.14')
                self.assertNotIn('WARN', r.stderr)

    def test_retained_pinned_core_is_authenticated_by_manifest(self):
        core = self.tmp / 'core-candidate'; fake_core(core, '1.13.14')
        good = self.tmp / 'manifest.json'
        good.write_text(json.dumps({'sha256': hashlib.sha256(core.read_bytes()).hexdigest(), 'version': '1.13.14'}))
        r, _ = self.run_core('pinned', candidate=core, manifest=good)
        self.assertEqual(r.returncode, 0, r.stderr)
        bad = self.tmp / 'bad.json'; bad.write_text(json.dumps({'sha256': '0' * 64}))
        r, out = self.run_core('pinned', candidate=core, manifest=bad)
        self.assertEqual(r.returncode, 3); self.assertIn('No verified pinned core', r.stderr); self.assertFalse(out.exists())

    def test_other_versions_are_not_downloaded(self):
        core = self.tmp / 'sing-box-accounting'; fake_core(core, '1.13.14')
        r, out = self.run_core('1.14.0', env={'SBOX_ACCOUNTING_CORE_SOURCE': str(core)})
        self.assertEqual(r.returncode, 3); self.assertIn('resolver is not installed', r.stderr); self.assertFalse(out.exists())
        r, _ = self.run_core('1.13.14')
        self.assertEqual(r.returncode, 3); self.assertIn('resolver is not installed', r.stderr)

    def test_local_binary_digest_argument_sidecar_and_mismatch(self):
        core = self.tmp / 'my-core'; fake_core(core, '1.13.20')
        digest = hashlib.sha256(core.read_bytes()).hexdigest()
        r, out = self.run_core(str(core), digest)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('SHA-256 verified', r.stderr)
        r, out = self.run_core(str(core), digest.upper())
        self.assertEqual(r.returncode, 0, r.stderr)
        r, out = self.run_core(str(core), 'f' * 64)
        self.assertEqual(r.returncode, 3); self.assertIn('SHA-256 mismatch', r.stderr); self.assertFalse(out.exists())
        r, out = self.run_core(str(core), 'not-a-digest')
        self.assertEqual(r.returncode, 3); self.assertIn('64 hexadecimal', r.stderr)
        (self.tmp / 'my-core.sha256').write_text(digest + '  my-core\n')
        r, out = self.run_core(str(core), assume='true')
        self.assertEqual(r.returncode, 0, r.stderr)
        (self.tmp / 'my-core.sha256').write_text('garbage\n')
        r, out = self.run_core(str(core), assume='true')
        self.assertEqual(r.returncode, 3); self.assertIn('Invalid SHA-256 sidecar', r.stderr)
        r, out = self.run_core(str(core), env={'SBOX_CORE_SHA256': digest}, assume='true')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unattended_unverified_binary_needs_digest_or_force(self):
        core = self.tmp / 'my-core'; fake_core(core, '1.13.20')
        r, out = self.run_core(str(core), assume='true')
        self.assertEqual(r.returncode, 3); self.assertIn('requires --sha256', r.stderr); self.assertFalse(out.exists())
        r, out = self.run_core(str(core), assume='true', force='true')
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('Observed SHA-256', r.stderr)

    def make_archive(self, version, member=None, binary_version=None, name=None):
        core = self.tmp / 'payload'; fake_core(core, binary_version or version, pad=1500000)
        archive = self.tmp / (name or f'sing-box-{version}-linux-amd64.tar.gz')
        with tarfile.open(archive, 'w:gz') as tf:
            tf.add(core, arcname=member or f'sing-box-{version}-linux-amd64/sing-box')
        return archive

    def test_upstream_archive_requires_digest_and_valid_structure(self):
        archive = self.make_archive('1.13.20')
        r, out = self.run_core(str(archive))
        self.assertEqual(r.returncode, 3); self.assertIn('must be authenticated', r.stderr)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        r, out = self.run_core(str(archive), digest)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((out.parent / 'sing-box.version').read_text().strip(), '1.13.20')
        self.assertEqual(list(self.tmp.glob('stage.*')), [], 'staging directory left behind')

    def test_hostile_or_mismatched_archives_are_rejected(self):
        cases = {
            'traversal': self.make_archive('1.13.21', member='../sing-box-1.13.21-linux-amd64/sing-box'),
            'wrong member': self.make_archive('1.13.22', member='other/sing-box'),
            'version mismatch': self.make_archive('1.13.23', binary_version='1.13.99'),
            'bad name': self.make_archive('1.13.24', name='core.tar.gz'),
        }
        for label, archive in cases.items():
            with self.subTest(case=label):
                r, out = self.run_core(str(archive), hashlib.sha256(archive.read_bytes()).hexdigest())
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertFalse(out.exists())

    def test_old_core_is_rejected(self):
        core = self.tmp / 'old-core'; fake_core(core, '1.11.0')
        r, out = self.run_core(str(core), hashlib.sha256(core.read_bytes()).hexdigest())
        self.assertEqual(r.returncode, 3); self.assertIn('older than the required minimum', r.stderr); self.assertFalse(out.exists())

    def test_relative_and_missing_paths(self):
        r, _ = self.run_core('relative/path')
        self.assertEqual(r.returncode, 3)
        r, _ = self.run_core('/does/not/exist', 'a' * 64)
        self.assertEqual(r.returncode, 3); self.assertIn('does not exist', r.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
