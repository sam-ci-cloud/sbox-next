#!/usr/bin/env python3
"""Public project gates. These focused checks are not a comprehensive audit."""
from pathlib import Path, PurePosixPath
import argparse, ast, base64, gzip, hashlib, io, json, re, shutil, subprocess, tarfile
from urllib.parse import unquote, urlsplit

from public_files import tracked_files
ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.build', '.cache', '__pycache__', 'dist', '.venv', 'node_modules'}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def run(*args):
    subprocess.run(list(args), cwd=ROOT, check=True)

def source_files():
    return tracked_files(ROOT)

def documentation():
    from check_docs import validate
    validate(ROOT)


def integrity():
    manifest = json.loads((ROOT / 'BUILD.json').read_text())
    release = json.loads((ROOT / 'assets/release.json').read_text())
    script = (ROOT / 'install.sh').read_bytes()
    assert sha(script) == release['installer_sha256'] and len(script) == release['installer_bytes']
    assert (ROOT / 'install.sh.sha256').read_text() == sha(script) + '  install.sh\n'
    assert release['components'] == manifest
    payloads = {}
    for key in ('GENERIC', 'ZGO', 'CORE'):
        payloads[key] = base64.b64decode(re.search(rb"<<'SBOX_" + key.encode() + rb"_PAYLOAD'\n(.*?)\nSBOX_" + key.encode() + rb'_PAYLOAD', script, re.S)[1])
    assert sha(payloads['GENERIC']) == manifest['generic_gzip_sha256']
    manager = gzip.decompress(payloads['GENERIC'])
    assert sha(manager) == manifest['generic_manager_sha256']
    assert f'MANAGER_VERSION="{release["products"]["universal"]}"'.encode() in manager

    # Verify the actual Personal Cloud payload embedded in the generated
    # Universal installer, not just the source manager used by unit tests.
    payload_match = re.search(
        rb"fallback_web_bundle\(\) \{\n  cat <<'SBOX_FALLBACK_WEB_BUNDLE'\n(.*?)\nSBOX_FALLBACK_WEB_BUNDLE\n\}",
        manager, re.S)
    digest_match = re.search(rb'FALLBACK_WEB_BUNDLE_SHA256="([0-9a-f]{64})"', manager)
    assert payload_match and digest_match, 'Universal installer is missing its Personal Cloud bundle'
    fallback_blob = base64.b64decode(payload_match.group(1))
    assert sha(fallback_blob) == digest_match.group(1).decode(), 'Personal Cloud bundle digest mismatch'
    with tarfile.open(fileobj=io.BytesIO(fallback_blob), mode='r:gz') as archive:
        fallback_files = {}
        for member in archive:
            path = PurePosixPath(member.name)
            assert member.isfile() and not path.is_absolute() and '..' not in path.parts and str(path) == member.name
            assert member.name not in fallback_files
            fallback_files[member.name] = archive.extractfile(member).read()
    fallback_manifest = json.loads(fallback_files.pop('MANIFEST.json'))
    assert fallback_manifest == {name: sha(data) for name, data in fallback_files.items()}
    expected_fallback = {'server.py': (ROOT / 'src/fallback-web/server.py').read_bytes()}
    expected_fallback.update({
        'site/' + str(path.relative_to(ROOT / 'src/fallback-web/site')): path.read_bytes()
        for path in sorted((ROOT / 'src/fallback-web/site').rglob('*')) if path.is_file()
    })
    assert fallback_files == expected_fallback, 'Embedded Personal Cloud files differ from the reviewed source tree'
    for required in ('server.py', 'site/index.html', 'site/files/index.html', 'site/media/index.html', 'site/about/index.html'):
        assert fallback_files.get(required), f'Embedded Personal Cloud bundle is missing {required}'
    assert payloads['ZGO'] == (ROOT / 'assets/zgocloud.enc').read_bytes()
    assert sha(payloads['ZGO']) == manifest['zgo_envelope_sha256']
    assert json.loads((ROOT / 'assets/zgocloud.json').read_text())['manager_sha256'] == manifest['zgo_manager_sha256']
    assert payloads['CORE'] == (ROOT / 'assets/sing-box-accounting.gz').read_bytes()
    assert sha(payloads['CORE']) == manifest['core_gzip_sha256']
    assert sha(gzip.decompress(payloads['CORE'])) == manifest['core_sha256']
    assert json.loads((ROOT / 'shared_webui/backend/core_manifest.json').read_text())['sha256'] == manifest['core_sha256']
    assert b'raw.githubusercontent.com/' + b'retired-owner/' + b'retired-repository' not in script + manager
    assert b'gist.githubusercontent.com' not in script + manager
    blob = base64.b64decode(re.search(rb"blob=base64.b64decode\('([^']+)'", manager)[1])
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        content = {}
        for member in archive:
            path = PurePosixPath(member.name)
            assert member.isfile() and not path.is_absolute() and '..' not in path.parts and str(path) == member.name
            assert member.name not in content
            content[member.name] = archive.extractfile(member).read()
        embedded = json.loads(content.pop('MANIFEST.json'))
        assert embedded == {name: sha(data) for name, data in content.items()}
    assert b'GNU GENERAL PUBLIC LICENSE' in (ROOT / 'LICENSE').read_bytes()
    assert (ROOT / 'core-source/LICENSE.sing-box').read_bytes() == (ROOT / 'core-source/sing-box/LICENSE').read_bytes()
    for notice in json.loads((ROOT / 'THIRD_PARTY_LICENSES/MANIFEST.json').read_text()):
        assert sha((ROOT / 'THIRD_PARTY_LICENSES' / notice['saved']).read_bytes()) == notice['sha256']
    provenance = json.loads((ROOT / 'core-source/BUILD_PROVENANCE.json').read_text())
    assert provenance['sha256'] == manifest['core_sha256']
    assert sha((ROOT / 'core-source/sing-box/go.sum').read_bytes()) == provenance['go_sum_sha256']
    print(f'PASS embedded integrity, {len(content)} safe application files, corresponding-source pins and license')

def focused_scan(data, name):
    patterns = [rb'gh[pousr]_[A-Za-z0-9]{36,}', rb'github_pat_[A-Za-z0-9_]{50,}', rb'AKIA[0-9A-Z]{16}']
    for pattern in patterns:
        assert not re.search(pattern, data), f'credential pattern in {name}; inspect privately'

def hygiene(history=False):
    paths = source_files()
    for p in paths:
        relative = p.relative_to(ROOT)
        assert not any(x.lower() in {'private', 'handoff', 'evidence', 'node_modules'} for x in relative.parts), str(relative)
        assert not p.is_symlink(), f'Unreviewed symlink: {relative}'
        assert not any(x in p.name for x in ('.private', '.sqlite', '.db-wal', '.db-shm')), str(relative)
        focused_scan(p.read_bytes(), str(relative))
    count = 0
    if history:
        rows = subprocess.check_output(['git', 'rev-list', '--objects', '--all'], cwd=ROOT, text=True).splitlines()
        for row in rows:
            oid, _, name = row.partition(' ')
            if subprocess.check_output(['git', 'cat-file', '-t', oid], cwd=ROOT).strip() == b'blob':
                focused_scan(subprocess.check_output(['git', 'cat-file', 'blob', oid], cwd=ROOT), name)
                count += 1
    print(f'PASS focused public hygiene: {len(paths)} files, {count} history blobs; owner-reference scan is separate')

def syntax():
    paths = source_files()
    for p in paths:
        if p.suffix == '.py':
            ast.parse(p.read_text(), filename=str(p))
    run('python3', 'shared_webui/tools/build_frontend.py', '--check')
    for name in ('install.sh', 'src/install.template.sh', 'src/manager.sh', 'src/certificate_reuse.sh', 'shared_webui/privileged-bridge/manager_extension.sh', 'core-source/build.sh'):
        run('bash', '-n', name)
    assert shutil.which('node'), 'Node is needed for frontend syntax validation'
    for p in sorted((ROOT / 'shared_webui/frontend').glob('*.js')):
        run('node', '--check', str(p))
    assert shutil.which('shellcheck'), 'ShellCheck is needed for supported source validation'
    # Runtime manager includes generated Python/asset writers; error-level lint is
    # the inherited supported gate. Local/style warnings are not hidden by inline disables.
    run('shellcheck', '-s', 'bash', '-S', 'error', '.build/src/manager.sh', 'src/install.template.sh', 'src/certificate_reuse.sh')
    print('PASS Python AST, Bash syntax, frontend JS syntax/parity and supported ShellCheck error gate')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--verify-build', action='store_true')
    ap.add_argument('--history', action='store_true')
    args = ap.parse_args()
    before = {name: (ROOT / name).read_bytes() for name in ('install.sh', 'BUILD.json')}
    run('python3', 'tools/build.py')
    if args.verify_build:
        for name, data in before.items():
            assert (ROOT / name).read_bytes() == data, f'Deterministic build mismatch: {name}'
        print('PASS clean source-to-installer byte equality')
    integrity()
    documentation()
    hygiene(args.history)
    syntax()

if __name__ == '__main__':
    main()
