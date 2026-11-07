#!/usr/bin/env python3
"""Fail if any runtime path of SBOX depends on GitHub or a GitHub mirror.

Scans every file that is installed or executed on a VPS (installer template,
manager, helpers, fallback website, WebUI backend/bridge/frontend, release
metadata, standalone package entrypoints) plus the generated installer with all
embedded payloads decoded (Universal manager, WebUI asset archive, Personal
Cloud bundle). With --unlock-file the protected ZgoCloud manager is decrypted
in memory and scanned too; its text is never printed.

Documentation and user-facing text may not link to GitHub either, except the
explicit upstream-provenance allowlist below (corresponding-source notices).
Developer tests and the upstream Go source tree (import paths) are out of scope.

Exit status 0 = no finding. Findings print file labels only.
"""
import ast, argparse, base64, gzip, hashlib, hmac, io, json, os, re, subprocess, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = re.compile(
    r'(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)*(?:github\.com|githubusercontent\.com|github\.io|githubassets\.com|githubapp\.com|ghcr\.io)(?![A-Za-z0-9-])'
    r'|(?<![A-Za-z0-9.-])(?:ghproxy\.[a-z]{2,}|gh-proxy\.com|ghfast\.top|mirror\.ghproxy\.com|hub\.fastgit\.[a-z]+|kgithub\.com)'
    r'|cdn\.jsdelivr\.net/gh/|fastly\.jsdelivr\.net/gh/|testingcf\.jsdelivr\.net/gh/', re.I)
GIT_OP = re.compile(r'\bgit\s+(?:clone|fetch|pull|push|remote\s+add|ls-remote|submodule\s+update)\b')
# Only the canonical repository (VERSION.json) may be named; see tools/identity.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from identity import canonical, foreign_reference  # noqa: E402
CANONICAL = canonical(ROOT)
# Static upstream provenance (GPL corresponding-source notices), not fetched.
ALLOWED_DOC_URLS = {'https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/dialer/tfo.go', 'https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/v2.5.9', 'https://github.com/SagerNet/sing-box/tree/v1.13.14', 'https://github.com/SagerNet/sing-box/tree/v1.14.2', 'https://github.com/SagerNet/sing-box/tree/v1.14.4'}
ALLOWED_DOC_URLS |= {'https://github.com/' + CANONICAL, 'https://raw.githubusercontent.com/' + CANONICAL + '/main/install.sh'}
RUNTIME_GLOBS = ['src/**/*', 'shared_webui/backend/**/*', 'shared_webui/privileged-bridge/**/*', 'shared_webui/frontend/**/*',
                 'shared_webui/frontend-src/**/*', 'shared_webui/api-spec/**/*', 'assets/*.json', 'package/**/*']
DOC_GLOBS = ['*.md', 'docs/**/*.md', 'examples/**/*', 'shared_webui/*.md', 'assets/*.md', 'src/**/*.md', 'package/**/*.md']


class Finding(Exception):
    pass


def text_of(data):
    if b'\0' in data:
        return '\n'.join(m[0].decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{6,}', data))
    return data.decode('utf-8', 'replace')


def check(label, data, docs=False, findings=None):
    text = text_of(data).replace('\\/', '/')
    if docs:
        for url in ALLOWED_DOC_URLS:
            text = text.replace(url, '')
    # A Go module name and Go patch import paths are source provenance, not
    # destination hosts. Only their exact reviewed syntactic sites are exempt.
    if label.endswith('backend/core_resolver.py'):
        text = re.sub(r"(?m)^MODULE = 'github\.com/sagernet/sing-box'$", "MODULE = '<verified-Go-proxy-module>'", text)
    if label.endswith('backend/core_resolver.py'):
        # Security floors are Go proxy module coordinates, not HTTP endpoints.
        # Exempt only literal dictionary keys at this exact assignment.
        try:
            tree = ast.parse(text)
            for node in tree.body:
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SECURITY_FLOORS' for t in node.targets) and isinstance(node.value, ast.Dict):
                    lines = text.splitlines(keepends=True)
                    for key in sorted(node.value.keys, key=lambda x:(x.lineno,x.col_offset), reverse=True):
                        if isinstance(key, ast.Constant) and isinstance(key.value,str) and re.fullmatch(r'github\.com/[A-Za-z0-9_./-]+',key.value):
                            assert key.lineno == key.end_lineno
                            line=lines[key.lineno-1];lines[key.lineno-1]=line[:key.col_offset]+repr('<Go-proxy-module>')+line[key.end_col_offset:]
                    text=''.join(lines)
        except (SyntaxError, AssertionError):
            pass # malformed runtime source remains subject to the host gate
    if label.endswith('backend/core-patches/accounting.patch'):
        text = re.sub(r'(?m)^([+ ]\s*(?:[A-Za-z]+ )?)"github\.com/[A-Za-z0-9_./-]+"$', r'\1"<Go-module-import>"', text)
    hits = ['host' for _ in HOST.finditer(text)]
    if not docs and GIT_OP.search(text):
        hits.append('git-remote-operation')
    if foreign_reference(text, CANONICAL):
        hits.append('retired-project')
    if hits:
        findings.append(f'{label}: {",".join(sorted(set(hits)))}')
    return text


def embedded(label, data, findings, depth=0):
    """Decode installer/manager payloads and scan their contents too."""
    if depth > 4:
        return
    for marker in ('GENERIC', 'CORE', 'ZGO'):
        for m in re.finditer(rb"<<'SBOX_" + marker.encode() + rb"_PAYLOAD'\r?\n([A-Za-z0-9+/=\r\n]+)\r?\nSBOX_" + marker.encode() + rb"_PAYLOAD", data):
            raw = base64.b64decode(re.sub(rb'\s', b'', m[1]))
            if marker == 'GENERIC':
                manager = gzip.decompress(raw)
                check(label + '::manager', manager, findings=findings)
                embedded(label + '::manager', manager, findings, depth + 1)
            # CORE is the upstream-derived binary (Go import paths are not
            # network operations); ZGO is ciphertext and scanned via --unlock-file.
    for m in re.finditer(rb"blob=base64\.b64decode\('([A-Za-z0-9+/=]+)',validate=True\)", data):
        tar_bytes = gzip.decompress(base64.b64decode(m[1]))
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            for member in tf.getmembers():
                if member.isfile():
                    check(label + '::webui/' + member.name, tf.extractfile(member).read(), findings=findings)
    for m in re.finditer(rb"<<'SBOX_FALLBACK_WEB_BUNDLE'\n([A-Za-z0-9+/=\n]+)\nSBOX_FALLBACK_WEB_BUNDLE", data):
        tar_bytes = gzip.decompress(base64.b64decode(re.sub(rb'\s', b'', m[1])))
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            for member in tf.getmembers():
                if member.isfile():
                    check(label + '::personal-cloud/' + member.name, tf.extractfile(member).read(), findings=findings)


def decrypt_zgo(root, unlock):
    secret = Path(unlock).read_bytes().splitlines()[0]
    data = (root / 'assets/zgocloud.enc').read_bytes()
    salt, tag, cipher = data[8:40], data[40:72], data[72:]
    key = hashlib.pbkdf2_hmac('sha256', secret, salt, 400000, 32)
    if data[:8] != b'SBOXETM1' or not hmac.compare_digest(tag, hmac.new(key, data[:40] + cipher, 'sha256').digest()):
        raise SystemExit('ZgoCloud envelope authentication failed')
    r, w = os.pipe(); os.write(w, secret + b'\n'); os.close(w)
    try:
        p = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '400000', '-md', 'sha256', '-pass', f'fd:{r}'],
                           pass_fds=(r,), input=cipher, capture_output=True, check=True)
    finally:
        os.close(r)
    return gzip.decompress(p.stdout)


def files(root, globs):
    out = set()
    for pattern in globs:
        out.update(p for p in root.glob(pattern) if p.is_file() and '__pycache__' not in p.parts and not p.is_symlink())
    return sorted(out)


def scan(root, installers=(), unlock=None):
    findings = []
    count = 0
    for path in files(root, RUNTIME_GLOBS):
        data = path.read_bytes()
        check(str(path.relative_to(root)), data, findings=findings); count += 1
    for path in files(root, DOC_GLOBS):
        check(str(path.relative_to(root)), path.read_bytes(), docs=True, findings=findings); count += 1
    for installer in installers:
        data = Path(installer).read_bytes()
        check(Path(installer).name, data, findings=findings)
        embedded(Path(installer).name, data, findings); count += 1
    if unlock:
        manager = decrypt_zgo(root, unlock)
        check('zgocloud-manager(decrypted)', manager, findings=findings)
        embedded('zgocloud-manager(decrypted)', manager, findings); count += 1
    return count, findings


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', type=Path, default=ROOT)
    ap.add_argument('--installer', action='append', default=[], help='generated installer(s) to decode and scan')
    ap.add_argument('--unlock-file', help='private ZgoCloud unlock; decrypts the envelope in memory')
    a = ap.parse_args()
    count, findings = scan(a.root.resolve(), a.installer, a.unlock_file)
    if findings:
        print('FAIL runtime GitHub/retired-repository dependency:\n  ' + '\n  '.join(findings))
        return 1
    print(json.dumps({'status': 'PASS', 'scanned_objects': count, 'zgocloud_plaintext_scanned': bool(a.unlock_file),
                      'installers': [Path(i).name for i in a.installer]}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
