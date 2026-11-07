#!/usr/bin/env python3
"""Owner-only: refresh the sealed ZgoCloud manager with current shared source.

Decrypts the committed envelope with the private unlock, verifies the sealed
manager digest and the original six-node YAML digest, re-integrates the shared
components (core source, WebUI, helpers) with tools/build.py, proves that every
protected identity value and the original YAML survive unchanged, then seals the
result with fresh randomness. Private inputs stay outside the source tree and no
private text is printed.

  python3 tools/reseal_zgo.py --unlock-file /private/ZgoCloud-UNLOCK.txt
"""
import argparse, base64, gzip, hashlib, hmac, json, os, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import ROOT, integrate, packed, sha  # noqa: E402
import core_migration  # noqa: E402
import yaml  # noqa: E402

FORMAT = 'SBOXETM1: AES-256-CBC/PBKDF2-SHA256 + encrypt-then-HMAC-SHA256, independent salt, 400000 iterations each'
YAML_RE = re.compile(r"zgo_write_original_yaml\(\) \{\n  base64 -d > \"\$1\" <<'SBOX_ORIGINAL_YAML_BASE64'\n(.*?)\nSBOX_ORIGINAL_YAML_BASE64\n", re.S)
# High-entropy literals (UUIDs, keys, passwords, short IDs) that make up the
# protected identity. Generated integration data is excluded below.
TOKEN_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_\-+/]{16,}={0,2}')


# Reviewed help-text rewrite: usage examples name the package entrypoint, never a
# legacy artifact file name. Applied to both the migration reference and the
# result, so it can only change these example lines.
HELP_EXAMPLE_RE = re.compile(r'sudo bash \./[A-Za-z0-9_-]+-installer\.sh install ')


def rewrite_help(text):
    return HELP_EXAMPLE_RE.sub('sudo bash ./install.sh install ', text)


def secret_from(path):
    data = Path(path).read_bytes().splitlines()
    if not data or len(data[0]) < 32:
        raise SystemExit('Unlock file must contain at least 32 characters on its first line')
    return data[0]


def decrypt(envelope, secret):
    if envelope[:8] != b'SBOXETM1' or len(envelope) < 104:
        raise SystemExit('Invalid encrypted envelope')
    salt, tag, cipher = envelope[8:40], envelope[40:72], envelope[72:]
    key = hashlib.pbkdf2_hmac('sha256', secret, salt, 400000, 32)
    if not hmac.compare_digest(tag, hmac.new(key, envelope[:40] + cipher, 'sha256').digest()):
        raise SystemExit('Incorrect unlock or damaged envelope')
    r, w = os.pipe(); os.write(w, secret + b'\n'); os.close(w)
    try:
        p = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '400000', '-md', 'sha256', '-pass', f'fd:{r}'],
                           pass_fds=(r,), input=cipher, capture_output=True, check=True)
    finally:
        os.close(r)
    return gzip.decompress(p.stdout)


def encrypt(plain, secret):
    salt = os.urandom(32)
    r, w = os.pipe(); os.write(w, secret + b'\n'); os.close(w)
    try:
        p = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '400000', '-md', 'sha256', '-pass', f'fd:{r}'],
                           pass_fds=(r,), input=packed(plain), capture_output=True, check=True)
    finally:
        os.close(r)
    header = b'SBOXETM1' + salt
    key = hashlib.pbkdf2_hmac('sha256', secret, salt, 400000, 32)
    return header + hmac.new(key, header + p.stdout, 'sha256').digest() + p.stdout


def identity_tokens(text):
    if '# BEGIN SHARED WEBUI INTEGRATION' in text:
        text = text[:text.index('# BEGIN SHARED WEBUI INTEGRATION')]
    text = YAML_RE.sub('', text)
    text = re.sub(r'MANAGER_BUILD_ID="[^"]+"', '', text)
    return set(TOKEN_RE.findall(text))


def strip_yaml(text):
    return YAML_RE.sub('', text)


def identity_values(document):
    values = set()
    for node in yaml.safe_load(document)['proxies']:
        def walk(value, key=''):
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(v, k)
            elif isinstance(value, list):
                for v in value:
                    walk(v, key)
            elif key in ('uuid', 'password', 'public-key', 'short-id', 'servername', 'sni', 'server', 'path', 'ports') and len(str(value)) >= 6:
                values.add(str(value))
        walk(node)
    if len(values) < 6:
        raise SystemExit('Original document has too few identity values to verify')
    return values


def original_yaml(text):
    m = YAML_RE.search(text)
    if not m:
        raise SystemExit('Original six-node document hook missing from the sealed manager')
    return base64.b64decode(m.group(1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--unlock-file', type=Path, required=True)
    ap.add_argument('--check-only', action='store_true', help='verify and report without writing assets')
    a = ap.parse_args()
    if a.unlock_file.resolve().is_relative_to(ROOT):
        raise SystemExit('Private unlock must be outside the source tree')
    secret = secret_from(a.unlock_file)
    meta = json.loads((ROOT / 'assets/zgocloud.json').read_text())
    release = json.loads((ROOT / 'assets/release.json').read_text())
    old = decrypt((ROOT / 'assets/zgocloud.enc').read_bytes(), secret)
    if sha(old) != meta['manager_sha256']:
        raise SystemExit('Sealed manager digest does not match assets/zgocloud.json')
    yaml_before = original_yaml(old.decode())
    if hashlib.sha256(yaml_before).hexdigest() != release['original_zgocloud_yaml_sha256']:
        raise SystemExit('Original six-node YAML digest mismatch')
    new_text = rewrite_help(integrate(old.decode(), 'zgocloud').decode())
    new = new_text.encode()
    if original_yaml(new_text) != yaml_before:
        raise SystemExit('Original six-node YAML changed during integration')
    # Every literal of the sealed manager must survive, except literals that only
    # the exact, fail-closed core-source migration removes (network download code).
    reference = rewrite_help(core_migration.migrate(old.decode()))
    removed_by_migration = identity_tokens(old.decode()) - identity_tokens(reference)
    missing = identity_tokens(reference) - identity_tokens(new_text)
    if missing:
        raise SystemExit(f'{len(missing)} protected literal(s) would be lost; refusing to seal')
    # The six-node credentials themselves: each value occurs exactly as often
    # outside the original document as before.
    identity = identity_values(yaml_before)
    for value in identity:
        if strip_yaml(old.decode()).count(value) != strip_yaml(new_text).count(value):
            raise SystemExit('A protected six-node identity value changed; refusing to seal')
    subprocess.run(['bash', '-n', '/dev/stdin'], input=new, check=True)
    report = {'old_manager_sha256': sha(old), 'new_manager_sha256': sha(new),
              'original_yaml_sha256': hashlib.sha256(yaml_before).hexdigest(),
              'literals_checked': len(identity_tokens(old.decode())), 'literals_lost': 0,
              'six_node_identity_values_checked': len(identity),
              'removed_network_literals': len(removed_by_migration), 'changed': sha(old) != sha(new)}
    if not a.check_only and sha(old) != sha(new):
        envelope = encrypt(new, secret)
        if decrypt(envelope, secret) != new:
            raise SystemExit('Round-trip verification of the new envelope failed')
        (ROOT / 'assets/zgocloud.enc').write_bytes(envelope)
        (ROOT / 'assets/zgocloud.json').write_text(json.dumps({'format': FORMAT, 'version':release['products']['zgocloud'], 'manager_sha256': sha(new)}, sort_keys=True, indent=2) + '\n')
        report['envelope_sha256'] = hashlib.sha256(envelope).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
