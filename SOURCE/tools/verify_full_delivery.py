#!/usr/bin/env python3
"""Offline verifier for the owner's single FULL-DELIVERY.zip (no version numbers).

Usage:
  python3 verify_full_delivery.py FULL-DELIVERY.zip [--key-file OWNER-KEY.txt]
  python3 verify_full_delivery.py EXTRACTED/FULL-DELIVERY  [--key-file ...]

Checks (each one fails closed):
  1. SHA256SUMS lists every other file exactly once, nested manifests included.
  2. DELIVERY.json identity: repository, commit, package and bootstrap digests.
  3. SOURCE_HISTORY.bundle clones with a HEAD equal to the delivered commit, and its
     tree is byte-identical to SOURCE/.
  4. PACKAGE/SING-BOX.tar.gz matches the bootstrap pin, has a complete inner
     manifest and carries exactly the delivered source.
  5. No reference to any repository other than the canonical one, in files, nested
     archives, embedded payloads and every object of the Git history.
  6. With --key-file: the private owner envelope authenticates, and none of its
     passwords/unlock literals appear in any public part.
Requires Python 3.11+, git and openssl. Secrets are never printed.
"""
import argparse, base64, gzip, hashlib, hmac, io, json, os, re, stat, subprocess, sys, tarfile, tempfile, zipfile
from pathlib import Path, PurePosixPath


def sha(b):
    return hashlib.sha256(b).hexdigest()


def safe(name):
    p = PurePosixPath(name)
    if (not name or p.is_absolute() or '..' in p.parts or '\\' in name or any(c in name for c in '\x00\r\n')
            or any(x in ('', '.', '..') for x in name.rstrip('/').split('/'))):
        raise ValueError('Unsafe archive member')
    return p


def tar_files(raw):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as t:
        total = 0
        for m in t:
            name = m.name.removeprefix('./'); safe(name)
            if m.isdir():
                continue
            if not m.isfile() or name in files:
                raise ValueError('Nonregular/duplicate tar member')
            total += m.size
            if total > 3 * 1024 ** 3:
                raise ValueError('Oversized tar payload')
            files[name] = t.extractfile(m).read()
    return files


def manifest(files, native=False):
    """Every file except the manifest itself is listed exactly once with its digest."""
    seen = set()
    for line in files['SHA256SUMS'].decode().splitlines():
        digest, name = line.split('  ', 1)
        if native:
            name = name.removeprefix('./')
        safe(name)
        if (not re.fullmatch('[0-9a-f]{64}', digest) or name in seen or name == 'SHA256SUMS'
                or name not in files or sha(files[name]) != digest):
            raise ValueError('Manifest mismatch: ' + name)
        seen.add(name)
    if seen != set(files) - {'SHA256SUMS'}:
        raise ValueError('Manifest does not cover every file')
    return len(seen)


def decrypt(raw, key):
    if raw[:8] != b'SBOXETM1' or len(raw) < 104:
        raise ValueError('Invalid private envelope')
    salt, tag, cipher = raw[8:40], raw[40:72], raw[72:]
    mac = hashlib.pbkdf2_hmac('sha256', key, salt, 400000, 32)
    if not hmac.compare_digest(tag, hmac.new(mac, raw[:40] + cipher, hashlib.sha256).digest()):
        raise ValueError('Private authentication failed')
    r, w = os.pipe(); os.write(w, key + b'\n'); os.close(w)
    try:
        out = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '400000', '-md', 'sha256',
                              '-pass', 'fd:' + str(r)], input=cipher, pass_fds=(r,), capture_output=True, check=True)
    finally:
        os.close(r)
    return gzip.decompress(out.stdout)


def identity_module(root):
    sys.path.insert(0, str(root / 'SOURCE/SOURCE/tools'))
    import identity  # the delivered policy itself
    return identity


def expand(label, data, depth=0):
    """Yield (label, bytes) for data and every nested gzip/zip/tar/embedded payload."""
    yield label, data
    if depth > 8:
        return
    if data[:2] == b'\x1f\x8b':
        try:
            yield from expand(label + '::gz', gzip.decompress(data), depth + 1); return
        except (OSError, EOFError):
            return
    if data[:4] == b'PK\x03\x04':
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for i in z.infolist():
                if not i.is_dir():
                    yield from expand(label + '::' + i.filename, z.read(i), depth + 1)
        return
    if len(data) > 262 and data[257:262] == b'ustar':
        for name, body in tar_files(data).items():
            yield from expand(label + '::' + name, body, depth + 1)
        return
    for marker in (b'GENERIC', b'CORE'):
        for m in re.finditer(rb"<<'SBOX_" + marker + rb"_PAYLOAD'\r?\n([A-Za-z0-9+/=\r\n]+)\r?\nSBOX_" + marker + rb"_PAYLOAD", data):
            yield from expand(label + '::embedded', base64.b64decode(re.sub(rb'\s', b'', m[1])), depth + 1)
    for m in re.finditer(rb"blob=base64\.b64decode\('([A-Za-z0-9+/=]+)',validate=True\)", data):
        yield from expand(label + '::web-assets', base64.b64decode(m[1]), depth + 1)


def text_of(data):
    if b'\0' in data:
        return '\n'.join(m[0].decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{6,}', data))
    return data.decode('latin-1').replace('\\/', '/')


def verify(root, key_file=None):
    root = Path(root).resolve(); files = {}
    for p in root.rglob('*'):
        if p.is_symlink():
            raise ValueError('Symlink in extracted delivery')
        if p.is_file():
            files[p.relative_to(root).as_posix()] = p.read_bytes()
    count = manifest(files)
    nested = sorted(n for n in files if n.endswith('/SHA256SUMS'))
    meta = json.loads(files['DELIVERY.json'])
    for key in ('repository', 'commit', 'package_sha256', 'bootstrap_sha256'):
        if key not in meta:
            raise ValueError('DELIVERY.json missing ' + key)
    if any(re.search(r'(?i)(^|[^0-9])v?\d+\.\d+\.\d+', n.split('/')[0]) for n in files):
        raise ValueError('Version-numbered top-level delivery entry')
    src = {n[len('SOURCE/'):]: b for n, b in files.items() if n.startswith('SOURCE/')}
    ident = identity_module(root)
    canonical = json.loads(src['SOURCE/VERSION.json'])['repository']
    if canonical != meta['repository']:
        raise ValueError('Repository identity differs between DELIVERY.json and source')
    pin = json.loads(src['PUBLIC_PAYLOAD.json'])
    package = files['PACKAGE/SING-BOX.tar.gz']
    if not (sha(package) == meta['package_sha256'] == pin['sha256'] and len(package) == pin['bytes']
            and pin['tag'] == 'pkg-' + pin['sha256'][:16]):
        raise ValueError('Package digest does not match the bootstrap pin')
    if sha(src['install.sh']) != meta['bootstrap_sha256'] or files['PACKAGE/install.sh'] != src['install.sh']:
        raise ValueError('Bootstrap script mismatch')
    if ("SBOX_SHA256='%s'" % pin['sha256']) not in src['install.sh'].decode() or pin['url'] not in src['install.sh'].decode():
        raise ValueError('Bootstrap does not pin the delivered package')
    pkg = {n.removeprefix('SING-BOX/'): b for n, b in tar_files(package).items()}
    package_count = manifest(pkg)
    product = {n[len('SOURCE/'):]: b for n, b in src.items() if n.startswith('SOURCE/')}
    for name, data in product.items():
        if name != 'install.sh' and pkg.get('source/' + name) != data:
            raise ValueError('Source/package mismatch: ' + name)
    # Git history: HEAD present, equal to the delivered commit, tree identical to SOURCE/.
    with tempfile.TemporaryDirectory() as temp:
        clone = Path(temp) / 'git'
        r = subprocess.run(['git', 'clone', '--quiet', str(root / 'SOURCE_HISTORY.bundle'), str(clone)], capture_output=True)
        if r.returncode:
            raise ValueError('History bundle does not clone')
        git = lambda *a: subprocess.check_output(['git', '-C', str(clone), *a])
        head = subprocess.run(['git', '-C', str(clone), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        if head.returncode or head.stdout.strip() != meta['commit']:
            raise ValueError('History bundle HEAD missing or not the delivered commit')
        listed = set(git('ls-tree', '-r', '--name-only', '-z', 'HEAD').decode().split('\0')) - {''}
        if listed != set(src):
            raise ValueError('History tree and SOURCE/ differ')
        for name in listed:
            if git('show', 'HEAD:' + name) != src[name]:
                raise ValueError('History content differs: ' + name)
        history = [('git:messages', git('log', '--all', '--format=%an%n%ae%n%cn%n%ce%n%B'))]
        objects = git('rev-list', '--objects', '--all').decode().split('\n')
        for row in filter(None, objects):
            oid = row.split(' ', 1)[0]
            if git('cat-file', '-t', oid).strip() == b'blob':
                history.append(('git:' + oid, git('cat-file', 'blob', oid)))
        commits = len(git('rev-list', '--all').split())
    public = {n: b for n, b in files.items() if not n.startswith('OWNER_PRIVATE/')}
    scanned = 0
    for label, data in list(public.items()) + history:
        for inner_label, inner in expand(label, data):
            scanned += 1
            if ident.foreign_reference(text_of(inner), canonical):
                raise ValueError('Repository identity violation in ' + inner_label.split('::')[0])
    secrets_checked = 'NOT_RUN (no --key-file)'
    if key_file:
        key = Path(key_file).read_bytes().strip()
        private = tar_files(decrypt(files['OWNER_PRIVATE/OWNER_PRIVATE.sboxetm'], key))
        manifest(private)
        secrets = [v['password'].encode() for v in json.loads(private['ACCESS/access.json']).values()]
        secrets.append(private['PROTECTED_COMPATIBILITY/ZgoCloud-UNLOCK.txt'].splitlines()[0].strip())
        secrets.append(key)
        for label, data in list(public.items()) + history:
            for inner_label, inner in expand(label, data):
                if any(s and s in inner for s in secrets):
                    raise ValueError('Private secret in public part: ' + inner_label.split('::')[0])
        secrets_checked = 'PASS (%d private literals absent from all public parts)' % len(secrets)
    return {'status': 'PASS', 'repository': canonical, 'commit': meta['commit'], 'manifest_entries': count,
            'nested_manifests_covered': nested, 'package_sha256': meta['package_sha256'],
            'package_manifest_entries': package_count, 'history_commits': commits,
            'objects_scanned_for_identity': scanned, 'secrets': secrets_checked,
            'scope': 'Offline integrity, identity and history correspondence; live VPS results are in EVIDENCE/'}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root', type=Path); ap.add_argument('--key-file', type=Path); ap.add_argument('--report', type=Path)
    a = ap.parse_args()
    try:
        if a.root.is_file():
            if a.root.name != 'FULL-DELIVERY.zip':
                raise ValueError('The delivery file must be named FULL-DELIVERY.zip')
            with tempfile.TemporaryDirectory() as temp, zipfile.ZipFile(a.root) as z:
                names = [i.filename for i in z.infolist()]
                if len(names) != len(set(names)) or len(names) > 20000 or sum(i.file_size for i in z.infolist()) > 4 * 1024 ** 3:
                    raise ValueError('Duplicate or oversized ZIP members')
                roots = set()
                for i in z.infolist():
                    roots.add(safe(i.filename).parts[0])
                    if stat.S_ISLNK(i.external_attr >> 16):
                        raise ValueError('Symlink in ZIP')
                if roots != {'FULL-DELIVERY'} or z.testzip() is not None:
                    raise ValueError('ZIP must contain one FULL-DELIVERY/ root and pass CRC checks')
                z.extractall(temp)
                result = verify(Path(temp) / 'FULL-DELIVERY', a.key_file)
                result['zip_sha256'] = hashlib.file_digest(a.root.open('rb'), 'sha256').hexdigest()
        else:
            result = verify(a.root, a.key_file)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as e:
        print(json.dumps({'status': 'FAIL', 'error': str(e)}, indent=2)); sys.exit(1)
    if a.report:
        a.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
