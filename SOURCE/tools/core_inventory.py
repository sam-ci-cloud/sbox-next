#!/usr/bin/env python3
"""Regenerate the accounting-core inventory after a corresponding-source update.

Run after core-source/build.sh has produced core-source/sing-box-accounting with
the pinned toolchain (it leaves the Go module cache in core-source/.cache or
$SBOX_CORE_BUILD_CACHE). Writes, deterministically:

  core-source/MANIFEST.json            SHA-256 of every corresponding-source file
  core-source/SBOM.json                resolved module graph, sums, linked set, notices
  core-source/REQUIRED_MODULE_ZIPS.json  module ZIPs linked into the core
  THIRD_PARTY_LICENSES/                notices of every module with cached sources
  THIRD_PARTY_LICENSES/MANIFEST.json   saved-name -> SHA-256 map

No network access is needed beyond what build.sh already downloaded.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'core-source'
TREE = CORE / 'sing-box'
NOTICES = ROOT / 'THIRD_PARTY_LICENSES'
KEEP = {'Go-LICENSE', 'README.md'}
LICENSE_RE = re.compile(r'^(LICEN[CS]E|COPYING|NOTICE|PATENTS|UNLICENSE)([._-].*)?$', re.I)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def go_env():
    cache = Path(os.environ.get('SBOX_CORE_BUILD_CACHE', CORE / '.cache'))
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOPROXY='off',
               GOPATH=str(cache / 'gopath'), GOCACHE=str(cache / 'gocache'), GOENV='off')
    env['PATH'] = str(cache / 'go/bin') + os.pathsep + env['PATH']
    return env


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + '\n')


def main():
    version = json.loads((ROOT / 'shared_webui/backend/core_manifest.json').read_text())['version']
    binary = CORE / 'sing-box-accounting'
    if not binary.is_file():
        raise SystemExit('Build core-source/sing-box-accounting with core-source/build.sh first')
    env = go_env()

    files = {}
    for p in sorted(TREE.rglob('*')):
        if p.is_file():
            files[str(p.relative_to(TREE))] = sha(p.read_bytes())
    write_json(CORE / 'MANIFEST.json', {'version': version, 'files': files})

    sums = {}
    for line in (TREE / 'go.sum').read_text().splitlines():
        mod, ver, h = line.split()
        key = 'go_mod_sum' if ver.endswith('/go.mod') else 'sum'
        sums.setdefault((mod, ver.removesuffix('/go.mod')), {})[key] = h

    linked = {}
    out = subprocess.run(['go', 'version', '-m', str(binary)], capture_output=True, text=True, check=True, env=env).stdout
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == 'dep':
            linked[parts[1]] = parts[2]
        elif parts and parts[0] == '=>':
            linked[parts[1]] = parts[2]

    raw = subprocess.run(['go', 'list', '-m', '-e', '-json', 'all'], cwd=TREE, capture_output=True, text=True, check=True, env=env).stdout
    decoder, idx, graph = json.JSONDecoder(), 0, []
    while idx < len(raw):
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        if idx >= len(raw):
            break
        obj, idx = decoder.raw_decode(raw, idx)
        graph.append(obj)

    for p in NOTICES.iterdir():
        if p.name not in KEEP:
            p.unlink()
    notices, modules, required = [], [], []
    for m in graph:
        if m.get('Main'):
            continue
        mod, ver = m['Path'], m.get('Version', '')
        directory = Path(m['Dir']) if m.get('Dir') else None
        license_files = sorted(f.name for f in directory.iterdir() if f.is_file() and LICENSE_RE.match(f.name)) if directory and directory.is_dir() else []
        for name in license_files:
            data = (directory / name).read_bytes()
            saved = f"{mod.replace('/', '_')}_{ver}_{name}"
            (NOTICES / saved).write_bytes(data)
            notices.append({'module_file': f'{mod}@{ver}/{name}', 'saved': saved, 'sha256': sha(data)})
        is_linked = linked.get(mod) == ver
        if is_linked:
            escaped = re.sub(r'[A-Z]', lambda c: '!' + c.group(0).lower(), mod)
            required.append(f'{escaped}/@v/{ver}.zip')
        s = sums.get((mod, ver), {})
        modules.append({'module': mod, 'version': ver, 'sum': s.get('sum'), 'go_mod_sum': s.get('go_mod_sum'),
                        'license_files': license_files, 'linked_in_embedded_core': is_linked})
    modules.sort(key=lambda x: (x['module'], x['version']))
    notices.sort(key=lambda x: x['saved'])
    write_json(NOTICES / 'MANIFEST.json', notices)
    write_json(CORE / 'REQUIRED_MODULE_ZIPS.json', sorted(required))
    missing_linked = [m['module'] for m in modules if m['linked_in_embedded_core'] and not m['license_files']]
    write_json(CORE / 'SBOM.json', {
        'format': f'SBOX Go module inventory {version}', 'core_version': version, 'modules': modules,
        'missing_cached_license_count': sum(1 for m in modules if not m['license_files']),
        'missing_linked_license_count': len(missing_linked), 'linked_module_count': sum(m['linked_in_embedded_core'] for m in modules)})
    print(f'PASS core inventory {version}: {len(files)} source files, {len(modules)} modules, '
          f'{sum(m["linked_in_embedded_core"] for m in modules)} linked, {len(notices)} notices, '
          f'{len(missing_linked)} linked without a notice')
    if missing_linked:
        print('Linked modules without a cached notice: ' + ', '.join(missing_linked), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
