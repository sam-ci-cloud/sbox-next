#!/usr/bin/env python3
"""Deterministic standalone SING-BOX.tar.gz (one SING-BOX/ directory, install.sh at its root).

  python3 tools/make_standalone.py --output DIR [--doc NAME=PATH ...] [--epoch N]

Layout:
  SING-BOX/install.sh verify.sh upgrade.sh rollback.sh recover.sh uninstall.sh
  SING-BOX/manifest.json SHA256SUMS README.md
  SING-BOX/bin/sbox-installer.sh   generated all-in-one installer (manager, WebUI,
                                   pinned accounting core, sealed ZgoCloud envelope)
  SING-BOX/docs/                   installation guide, test report, security review
  SING-BOX/licenses/               LICENSE, NOTICE, third-party licenses
  SING-BOX/source/                 complete corresponding source, tests and tools
                                   (rebuild bin/ with: cd source && python3 tools/build.py)

Requires a freshly built install.sh (tools/build.py) whose digest matches
assets/release.json. Members are sorted, owned by root:root, mtime fixed and
gzip-compressed without a timestamp, so equal inputs give equal bytes.
"""
import argparse, gzip, hashlib, io, json, stat, sys, tarfile
from pathlib import Path, PurePosixPath
sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_files import is_public, tracked_files  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TOP = 'SING-BOX'
EPOCH = 1793404800  # 2026-10-31T00:00:00Z (not in the future for any time zone on 2026-11-01)
SCRIPTS = ('install.sh', 'verify.sh', 'upgrade.sh', 'rollback.sh', 'recover.sh', 'uninstall.sh', 'performance.sh')
SOURCE_EXCLUDE = {'install.sh'}  # generated; shipped once as bin/sbox-installer.sh


def sha(b):
    return hashlib.sha256(b).hexdigest()


def required_core_asset(root=ROOT):
    path=root/'assets/sing-box-accounting.gz'
    if not path.is_file() or path.is_symlink():
        raise SystemExit('Missing generated accounting core: run tools/bootstrap_core.py')
    data=path.read_bytes()
    if sha(data)!=json.loads((root/'BUILD.json').read_text())['core_gzip_sha256']:
        raise SystemExit('Generated accounting core differs from BUILD.json')
    return data



def collect(docs):
    files = {}

    def add(name, data, mode=0o644):
        p = PurePosixPath(name)
        assert not p.is_absolute() and '..' not in p.parts and name not in files, name
        files[name] = (data, mode)

    release = json.loads((ROOT / 'assets/release.json').read_text())
    installer = (ROOT / 'install.sh').read_bytes()
    if sha(installer) != release['installer_sha256'] or len(installer) != release['installer_bytes']:
        raise SystemExit('install.sh does not match assets/release.json; run tools/build.py and tools/pin_release.py --sync-tree')
    build = json.loads((ROOT / 'BUILD.json').read_text())
    for name in SCRIPTS:
        add(name, (ROOT / 'package' / name).read_bytes(), 0o755)
    add('README.md', (ROOT / 'package/README.md').read_bytes())
    add('bin/sbox-installer.sh', installer, 0o755)
    for spec in docs:
        name, _, path = spec.partition('=')
        add('docs/' + name, Path(path).read_bytes())
    add('licenses/LICENSE', (ROOT / 'LICENSE').read_bytes())
    add('licenses/NOTICE', (ROOT / 'NOTICE').read_bytes())
    add('licenses/LICENSE.sing-box', (ROOT / 'core-source/LICENSE.sing-box').read_bytes())
    for path in sorted((ROOT / 'THIRD_PARTY_LICENSES').rglob('*')):
        if path.is_file():
            add('licenses/third-party/' + path.relative_to(ROOT / 'THIRD_PARTY_LICENSES').as_posix(), path.read_bytes())
    source = {}
    for path in tracked_files(ROOT):
        name = path.relative_to(ROOT).as_posix()
        if not is_public(name) or name in SOURCE_EXCLUDE or name == 'SHA256SUMS' or path.is_symlink():
            continue
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        source[name] = (path.read_bytes(), mode)
    source['assets/sing-box-accounting.gz'] = (required_core_asset(ROOT), 0o644)
    source['SHA256SUMS'] = (''.join(sha(d) + '  ' + n + '\n' for n, (d, _) in sorted(source.items())).encode(), 0o644)
    for name, (data, mode) in source.items():
        add('source/' + name, data, mode)
    distribution = json.loads((ROOT / 'assets/distribution.json').read_text())
    manifest = {
        'name': TOP, 'product': 'SBOX', 'version': release['version'], 'channel': distribution['channel'],
        'products': release['products'], 'architecture': release['architecture'], 'supported_systems': release['supported_systems'],
        'entrypoint': 'install.sh',
        'installer': {'path': 'bin/sbox-installer.sh', 'sha256': sha(installer), 'bytes': len(installer)},
        'components': build, 'original_zgocloud_yaml_sha256': release['original_zgocloud_yaml_sha256'],
        'network': {
            'github': 'not used: no GitHub repository, API, Release, raw, Actions, Gist, Pages or mirror access',
            'core_updates': 'tested patched core embedded; explicit dynamic source builds use Go proxy/sumdb, go.dev toolchain, api.osv.dev and vuln.go.dev security gates; never unpatched upstream binaries',
            'uses': ['configured apt distribution repositories (apt-get update/install)',
                     'ACME CA (Let\'s Encrypt by default) when certbot-http01/certbot-dns-cloudflare is selected',
                     'Cloudflare API only with certbot-dns-cloudflare',
                     'public IP discovery (api.ipify.org, checkip.amazonaws.com, 4.ipw.cn; IPv6: api64.ipify.org, ipv6.icanhazip.com, 6.ipw.cn) only when --ipv4/--ipv6 are not given',
                     'DNS and time synchronisation of the host'],
        },
        'layout': {'install.sh': 'entrypoint: package verification, read-only preflight, then the installer',
                   'bin/': 'generated all-in-one installer', 'docs/': 'installation guide, test report, security review',
                   'licenses/': 'GPL-3.0 and third-party licenses', 'source/': 'complete corresponding source, tests and build tools'},
    }
    add('manifest.json', (json.dumps(manifest, indent=2, sort_keys=False) + '\n').encode())
    sums = ''.join(sha(d) + '  ' + n + '\n' for n, (d, _) in sorted(files.items())).encode()
    files['SHA256SUMS'] = (sums, 0o644)
    return files


def tar_bytes(files, epoch):
    buf = io.BytesIO()
    dirs = set()
    for name in files:
        parts = PurePosixPath(name).parts[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add('/'.join(parts[:i]))
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tf:
        def info(name, kind, mode, size=0):
            ti = tarfile.TarInfo(TOP + ('/' + name if name else ''))
            ti.type = kind; ti.mode = mode; ti.size = size; ti.mtime = epoch
            ti.uid = ti.gid = 0; ti.uname = ti.gname = 'root'
            return ti
        tf.addfile(info('', tarfile.DIRTYPE, 0o755))
        for name in sorted(dirs | set(files)):
            if name in files:
                data, mode = files[name]
                tf.addfile(info(name, tarfile.REGTYPE, mode, len(data)), io.BytesIO(data))
            else:
                tf.addfile(info(name, tarfile.DIRTYPE, 0o755))
    raw = buf.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=out, compresslevel=9, mtime=0) as gz:
        gz.write(raw)
    return out.getvalue()


def verify(blob, files):
    """Re-read the archive: one top directory, no links/devices/traversal, exact bytes and modes."""
    seen = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as tf:
        for m in tf.getmembers():
            p = PurePosixPath(m.name)
            assert p.parts[0] == TOP and '..' not in p.parts and not p.is_absolute(), m.name
            assert m.isfile() or m.isdir(), 'non-regular member ' + m.name
            assert m.uid == 0 and m.gid == 0 and not m.mode & (stat.S_ISUID | stat.S_ISGID | 0o002), m.name
            if m.isfile():
                rel = '/'.join(p.parts[1:])
                assert rel not in seen, 'duplicate ' + rel
                seen[rel] = (tf.extractfile(m).read(), m.mode)
    assert seen.keys() == files.keys(), 'member set differs'
    for name, (data, mode) in files.items():
        assert seen[name] == (data, mode), name
    assert 'install.sh' in seen and 'bin/sbox-installer.sh' in seen


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--doc', action='append', default=[], help='NAME=PATH added under SING-BOX/docs/')
    ap.add_argument('--epoch', type=int, default=EPOCH)
    a = ap.parse_args()
    files = collect(a.doc)
    blob = tar_bytes(files, a.epoch)
    verify(blob, files)
    a.output.mkdir(parents=True, exist_ok=True)
    (a.output / 'SING-BOX.tar.gz').write_bytes(blob)
    print(json.dumps({'archive': str(a.output / 'SING-BOX.tar.gz'), 'sha256': sha(blob), 'bytes': len(blob),
                      'files': len(files), 'status': 'PASS'}, indent=2))


if __name__ == '__main__':
    main()
