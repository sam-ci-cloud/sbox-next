#!/usr/bin/env python3
"""Standalone SING-BOX.tar.gz: deterministic layout and entrypoint safety gates.

Builds the package twice from a temporary copy of this tree, compares bytes,
extracts it and drives install.sh/verify.sh/preflight through their refusal
paths. Mutating commands are only exercised up to the point where the wrapper
must stop (non-root, tampered package, bad certificate inputs), so the test is
safe on any workstation or CI container.
"""
import hashlib, json, os, shutil, subprocess, sys, tarfile, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def staging_dir():
    """Disk-backed staging when /tmp is a small tmpfs (1 GiB VPS: ~470 MiB).

    The suite holds two built packages, an extracted copy and per-case tamper
    copies; on a small tmpfs the package's own verify step then fails with
    ENOSPC, which is an environment artefact rather than a product result.
    """
    tmp = Path(tempfile.gettempdir())
    if shutil.disk_usage(tmp).free < 1536 * 2**20 and Path('/var/tmp').is_dir() and shutil.disk_usage('/var/tmp').free > shutil.disk_usage(tmp).free:
        return '/var/tmp'
    return None


def sh(args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=600, **kw)


class StandalonePackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / 'install.sh').is_file():
            subprocess.run([sys.executable, str(ROOT / 'tools/build.py')], check=True, stdout=subprocess.DEVNULL)
        # Remove tamper copies after each case so small VPS tmpfs stays bounded.
        cls.tmp = Path(tempfile.mkdtemp(prefix='sbox-standalone-', dir=staging_dir()))
        cls.tmp.chmod(0o755)  # the unprivileged-user cases must traverse it
        cls.tree = cls.tmp / 'tree'
        shutil.copytree(ROOT, cls.tree, ignore=shutil.ignore_patterns('.git', '.build', '.cache', '__pycache__', 'dist', 'node_modules'))
        r = sh([sys.executable, cls.tree / 'tools/pin_release.py', '--sync-tree'])
        assert r.returncode == 0, r.stderr
        doc = cls.tmp / 'doc.md'; doc.write_text('# placeholder\n')
        outs = []
        for n in (1, 2):
            out = cls.tmp / f'out{n}'
            r = sh([sys.executable, cls.tree / 'tools/make_standalone.py', '--output', out, '--doc', f'INSTALLATION-GUIDE.md={doc}'])
            assert r.returncode == 0, r.stderr + r.stdout
            outs.append(out / 'SING-BOX.tar.gz')
        cls.archives = outs
        cls.root = cls.tmp / 'x'
        cls.root.mkdir()
        with tarfile.open(outs[0]) as tf:
            tf.extractall(cls.root, filter='data')
        cls.pkg = cls.root / 'SING-BOX'
        cls.nobody = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups'] if os.geteuid() == 0 and shutil.which('setpriv') else []

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def fresh(self):
        """A private extracted copy that a test may tamper with."""
        d = Path(tempfile.mkdtemp(prefix='sbox-pkg-', dir=self.tmp))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copytree(self.pkg, d / 'SING-BOX')
        os.chmod(d, 0o755)
        for p in [d / 'SING-BOX', *(d / 'SING-BOX').rglob('*')]:
            os.chmod(p, (p.stat().st_mode | 0o555) if p.is_dir() else (p.stat().st_mode | 0o444))
        return d / 'SING-BOX'

    def test_build_is_deterministic(self):
        a, b = (hashlib.sha256(p.read_bytes()).hexdigest() for p in self.archives)
        self.assertEqual(a, b)

    def test_layout_single_top_directory_with_entrypoint(self):
        with tarfile.open(self.archives[0]) as tf:
            names = tf.getnames()
            self.assertTrue(all(n == 'SING-BOX' or n.startswith('SING-BOX/') for n in names))
            self.assertTrue(all(m.isfile() or m.isdir() for m in tf.getmembers()))
        for rel in ('install.sh', 'verify.sh', 'upgrade.sh', 'rollback.sh', 'recover.sh', 'uninstall.sh', 'manifest.json',
                    'SHA256SUMS', 'bin/sbox-installer.sh', 'licenses/LICENSE', 'source/src/manager.sh', 'source/tests',
                    'source/core-source/sing-box/go.sum', 'source/assets/sing-box-accounting.gz', 'source/assets/zgocloud.enc'):
            self.assertTrue((self.pkg / rel).exists(), rel)
        self.assertTrue(os.access(self.pkg / 'install.sh', os.X_OK))
        manifest = json.loads((self.pkg / 'manifest.json').read_text())
        installer = (self.pkg / 'bin/sbox-installer.sh').read_bytes()
        self.assertEqual(manifest['installer']['sha256'], hashlib.sha256(installer).hexdigest())
        self.assertIn('not used', manifest['network']['github'])

    def test_source_manifest_and_package_manifest_verify(self):
        self.assertEqual(sh(['sha256sum', '--check', '--strict', '--quiet', 'SHA256SUMS'], cwd=self.pkg).returncode, 0)
        self.assertEqual(sh(['sha256sum', '--check', '--strict', '--quiet', 'SHA256SUMS'], cwd=self.pkg / 'source').returncode, 0)

    def test_help_and_read_only_verify_as_unprivileged_user(self):
        pkg = self.fresh()
        r = sh(self.nobody + ['bash', pkg / 'install.sh', 'help'])
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('preflight', r.stdout)
        r = sh(self.nobody + ['bash', pkg / 'verify.sh', 'generic'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('files verified', r.stderr); self.assertIn('integrity passed', r.stderr)

    def test_tampered_file_is_refused_before_anything_runs(self):
        pkg = self.fresh()
        target = pkg / 'bin/sbox-installer.sh'
        data = bytearray(target.read_bytes()); data[-10] ^= 1; target.write_bytes(bytes(data))
        r = sh(['bash', pkg / 'install.sh', 'install', 'generic', '--yes'])
        self.assertNotEqual(r.returncode, 0); self.assertIn('checksum verification failed', r.stderr)
        self.assertNotIn('Preflight', r.stderr)

    def test_missing_or_extra_executable_and_symlink_are_refused(self):
        pkg = self.fresh(); (pkg / 'source/README.md').unlink()
        r = sh(['bash', pkg / 'verify.sh']); self.assertNotEqual(r.returncode, 0); self.assertIn('checksum verification failed', r.stderr)
        pkg = self.fresh(); (pkg / 'bin/extra.sh').write_text('echo hi\n')
        r = sh(['bash', pkg / 'verify.sh']); self.assertNotEqual(r.returncode, 0); self.assertIn('Unexpected executable', r.stderr)
        pkg = self.fresh(); (pkg / 'docs/link').symlink_to('/etc/passwd')
        r = sh(['bash', pkg / 'verify.sh']); self.assertNotEqual(r.returncode, 0); self.assertIn('symbolic links', r.stderr)

    def test_preflight_is_read_only_and_reports_blockers(self):
        pkg = self.fresh()
        bad_cert = self.tmp / 'bad.pem'; bad_cert.write_text('not a certificate\n')
        key = self.tmp / 'k.pem'; key.write_text('x'); key.chmod(0o644)
        r = sh(self.nobody + ['bash', pkg / 'install.sh', 'preflight', 'generic', '--cert', 'existing', '--cert-path', bad_cert,
                              '--key-path', key, '--domain', 'vpn.example.test'])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('[FAIL] Root is required', r.stderr)
        self.assertIn('nothing was changed', r.stderr)

    def test_free_space_check_does_not_depend_on_df_options(self):
        # Ubuntu 26.10 ships uutils df without -m; the preflight must still
        # measure free space (regression: reported "have unknown" and refused).
        pkg = self.fresh()
        shim = self.tmp / 'uutils-shim'; shim.mkdir(exist_ok=True); shim.chmod(0o755)
        df = shim / 'df'; df.write_text('#!/bin/sh\ncase " $* " in *" -m "*|*" -Pm "*) echo "error: unexpected argument -m" >&2; exit 1;; esac\nexec /usr/bin/df "$@"\n'); df.chmod(0o755)
        r = sh(self.nobody + ['env', f'PATH={shim}:/usr/sbin:/usr/bin:/sbin:/bin', 'bash', pkg / 'install.sh', 'preflight', 'generic'])
        self.assertRegex(r.stderr, r'\[PASS\] Free space for /usr/local and /var: \d+ MiB')
        self.assertRegex(r.stderr, r'\[PASS\] Free space on /tmp: \d+ MiB')
        self.assertNotIn('have unknown', r.stderr)

    def test_install_as_non_root_stops_in_preflight(self):
        if not self.nobody and os.geteuid() == 0:
            self.skipTest('setpriv unavailable to drop root')
        pkg = self.fresh()
        r = sh(self.nobody + ['bash', pkg / 'install.sh', 'install', 'generic', '--yes'])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Preflight found', r.stderr); self.assertNotIn('Verified generic', r.stderr)

    def test_unknown_commands_and_variants_fail(self):
        pkg = self.fresh()
        for args in (['bogus'], ['install', 'nope'], ['verify', 'generic', 'extra'], ['upgrade', 'generic', 'x']):
            with self.subTest(args=args):
                self.assertNotEqual(sh(self.nobody + ['bash', pkg / 'install.sh', *args]).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
