#!/usr/bin/env python3
"""Build verified compatible accounting cores from checksum-database verified Go modules.

No upstream binary is accepted. Each resolved candidate must apply the bundled
accounting patch cleanly, pass its real Go tests, compile and report the accounting
build tag. An incompatible release is retained as evidence and the resolver tries
older releases in semantic order. Nothing running is replaced by this module.
"""
from pathlib import Path
import argparse, calendar, contextlib, fcntl, gzip, hashlib, json, os, platform, re
import shutil, subprocess, sys, tarfile, tempfile, time, urllib.request

MODULE = 'github.com/sagernet/sing-box'
PROXY = 'https://proxy.golang.org'
VERSION = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$')
PATCH = Path(__file__).with_name('core-patches') / 'accounting.patch'
TOOLCHAIN_VERSION = 'go1.27.3'  # Compiler validated with this accounting patch.
SECURITY_FLOORS = {
    # GO-2026-6888 (brotli decoder allocation DoS) and GO-2026-6865 (fse/huff0 panic);
    # reached through uTLS certificate decompression, OpenConnect and tailscale zstdframe.
    'github.com/andybalholm/brotli':'v1.2.7', 'github.com/klauspost/compress':'v1.20.2',
    'github.com/go-chi/chi/v5':'v5.4.0', 'github.com/go-jose/go-jose/v4':'v4.1.6',
    'github.com/insomniacslk/dhcp':'v0.0.0-20260719225207-c76316d4aa82',
    'golang.org/x/crypto':'v0.58.1-0.20261009181718-2f1f834330b2',
    'golang.org/x/mod':'v0.41.0', 'golang.org/x/net':'v0.62.0',
    'golang.org/x/text':'v0.43.0', 'google.golang.org/grpc':'v1.83.2',
}
SCANNER_VERSION = 'v1.9.0'
SECURITY_POLICY = hashlib.sha256(json.dumps({'revision':2,'compiler':TOOLCHAIN_VERSION,'floors':SECURITY_FLOORS,'scanner':SCANNER_VERSION},sort_keys=True).encode()).hexdigest()
PROTOCOLS = ('reality', 'vmess', 'hy2', 'tuic', 'anytls')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def version_key(value):
    m = VERSION.fullmatch(value)
    if not m: raise ValueError('Invalid exact version')
    major, minor, patch, stage, number = m.groups()
    return (int(major), int(minor), int(patch), {'alpha': 0, 'beta': 1, 'rc': 2, None: 3}[stage], int(number or 0))


def candidates(versions, request):
    if request not in ('latest', 'stable', 'beta', 'prerelease'):
        version_key(request)
        return ['v' + request.removeprefix('v')]
    prerelease = request in ('beta', 'prerelease')
    selected = [v for v in versions if VERSION.fullmatch(v) and version_key(v) >= (1, 12, 0, 3, 0)
                and (prerelease or '-' not in v)]
    return sorted(set(selected), key=version_key, reverse=True)


def get(url, limit=4 * 1024 * 1024):
    if not url.startswith(('https://proxy.golang.org/', 'https://go.dev/', 'https://dl.google.com/')):
        raise ValueError('Untrusted download origin')
    with urllib.request.urlopen(url, timeout=40) as response:
        data = response.read(limit + 1)
    if len(data) > limit: raise ValueError('Download exceeds limit')
    return data


def atomic_json(path, data):
    path = Path(path); temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n'); temp.chmod(0o600)
    with temp.open('rb') as f: os.fsync(f.fileno())
    temp.replace(path)


def secure_cache(path):
    path = Path(path).absolute()
    # Reject aliases and writable parents before privileged source/build execution.
    for parent in [path, *path.parents]:
        if parent.exists() and (parent.is_symlink() or (parent.stat().st_uid not in (0, os.geteuid()))
                                 or (parent.stat().st_mode & (0o022 if os.geteuid() == 0 else 0o002) and not parent.stat().st_mode & 0o1000)):
            raise ValueError('Unsafe core cache namespace')
    path.mkdir(parents=True, exist_ok=True, mode=0o700); path.chmod(0o700)
    return path


def toolchain(cache):
    existing = shutil.which('go')
    if existing and subprocess.check_output([existing, 'version'], text=True).split()[2:3] == [TOOLCHAIN_VERSION]: return existing
    go = cache / 'toolchains' / TOOLCHAIN_VERSION / 'go/bin/go'
    if go.is_file():
        if subprocess.check_output([str(go),'version'],text=True).split()[2:3] != [TOOLCHAIN_VERSION]:
            raise ValueError('Cached compiler identity does not match the security policy')
        return str(go)
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch or platform.system() != 'Linux': raise ValueError('Unsupported build architecture')
    releases = json.loads(get('https://go.dev/dl/?mode=json&include=all'))
    release = next(r for r in releases if r['version'] == TOOLCHAIN_VERSION)
    item = next(f for f in release['files'] if f['os'] == 'linux' and f['arch'] == arch and f['kind'] == 'archive')
    data = get('https://go.dev/dl/' + item['filename'], 150 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != item['sha256']: raise ValueError('Go toolchain checksum mismatch')
    dest = cache / 'toolchains' / TOOLCHAIN_VERSION; dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = dest / 'go.tar.gz'; archive.write_bytes(data)
    # Official Go tarballs contain regular files/directories only.
    with tarfile.open(archive) as tf:
        for m in tf:
            if not (m.isfile() or m.isdir()) or Path(m.name).is_absolute() or '..' in Path(m.name).parts:
                raise ValueError('Unsafe toolchain archive')
        tf.extractall(dest, filter='data')
    archive.unlink(); atomic_json(dest / 'provenance.json', item)
    return str(go)


def run(args, *, cwd, env, log, timeout=1800):
    p = subprocess.run(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    if p.returncode: raise ValueError(f'{Path(args[0]).name} {args[1]} failed (exit {p.returncode}); see candidate build.log')


def security_qualified(manifest):
    scans = manifest.get('security_scans', {})
    return (manifest.get('security_policy') == SECURITY_POLICY and isinstance(scans, dict)
            and all(type(scans.get(k)) is int and scans[k] == 0 for k in ('modules', 'binary')))


def module_version_at_least(value, floor):
    def parse(text):
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.*)?', text)
        if not match: raise ValueError('Invalid Go module version')
        return tuple(map(int, match.groups()[:3])), match[4]
    a, ap = parse(value); b, bp = parse(floor)
    if a != b: return a > b
    if ap is None: return True
    if bp is None: return False
    def identifiers(text):
        return tuple((0, int(x)) if x.isdigit() else (1, x) for x in text.split('.'))
    return identifiers(ap) >= identifiers(bp)


def apply_security_floors(source, go, env, log):
    raw = subprocess.check_output([go, 'list', '-m', '-json', 'all'], cwd=source, env=env, text=True)
    decoder = json.JSONDecoder(); versions = {}
    while raw.strip():
        item, n = decoder.raw_decode(raw.lstrip()); raw = raw.lstrip()[n:]
        if item.get('Version'): versions[item['Path']] = item['Version']
    updates = [module+'@'+floor for module, floor in SECURITY_FLOORS.items()
               if module in versions and not module_version_at_least(versions[module], floor)]
    if updates:
        run([go, 'get', *updates], cwd=source, env={**env, 'GOFLAGS':'-mod=mod'}, log=log)
    return updates


def audit_source_and_binary(source, binary, cache, go, env, log):
    queries = []; inside = False
    for line in (source / 'go.mod').read_text().splitlines():
        if line.startswith('require ('): inside=True; continue
        if inside and line==')': inside=False; continue
        match = re.match(r'\s*(\S+)\s+(v\S+)', line if inside else line.removeprefix('require '))
        if match: queries.append({'package':{'ecosystem':'Go','name':match[1]},'version':match[2]})
    request=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response: report=json.load(response)
    if len(report.get('results',[])) != len(queries): raise ValueError('Incomplete module security response')
    bad=[r for r in report['results'] if r.get('vulns') or r.get('next_page_token')]
    atomic_json(binary.parent/'module-security.json',{'queries':queries,**report})
    if bad: raise ValueError('Module vulnerability findings; current core retained')
    tools=cache/'security-tools'; tools.mkdir(mode=0o700,exist_ok=True)
    run([go,'install','golang.org/x/vuln/cmd/govulncheck@'+SCANNER_VERSION],cwd=cache,env={**env,'GOFLAGS':'-mod=mod','GOBIN':str(tools.resolve())},log=log)
    result=subprocess.run([str(tools/'govulncheck'),'-mode=binary','-json',str(binary)],cwd=source,env=env,capture_output=True,text=True,timeout=300)
    if result.returncode: raise ValueError('Binary vulnerability scan failed; current core retained')
    (binary.parent/'binary-security.jsonl').write_text(result.stdout)
    raw=result.stdout; decoder=json.JSONDecoder(); findings=[]; messages=0; binary_config=False
    while raw.strip():
        item,n=decoder.raw_decode(raw.lstrip());raw=raw.lstrip()[n:];messages+=1
        if 'finding' in item:findings.append(item['finding'])
        if item.get('config',{}).get('scan_mode')=='binary' and item['config'].get('scanner_name')=='govulncheck':binary_config=True
    if not messages or not binary_config or findings: raise ValueError('Binary vulnerability findings or empty report; current core retained')
    return {'modules':0,'binary':0,'declared_modules_scanned':len(queries),'scanner':SCANNER_VERSION,
            'scope':'OSV declared module versions and compiled Go vulnerability findings'}


def verified_cached(root, version, arch):
    manifest = root / 'provenance.json'; binary = root / 'sing-box'
    if not manifest.is_file() or not binary.is_file(): return None
    m = json.loads(manifest.read_text())
    if (m.get('version') != version.removeprefix('v') or m.get('architecture') != 'linux-' + arch
            or not security_qualified(m)
            or m.get('patch_sha256') != sha(PATCH) or m.get('tests_passed') is not True
            or m.get('sha256') != sha(binary) or not all(m.get('coverage', {}).get(p) is True for p in PROTOCOLS)):
        return None
    return m


def build(cache, version, go, arch):
    root = cache / ('core-' + version + '-' + arch)
    root.mkdir(mode=0o700, exist_ok=True)
    manifest = verified_cached(root, version, arch)
    if manifest: return root / 'sing-box', manifest
    env = {**os.environ, 'GOPATH': str(cache / 'gopath'), 'GOCACHE': str(cache / 'gocache'),
           'GOPROXY': PROXY, 'GOSUMDB': 'sum.golang.org', 'GOTOOLCHAIN': 'local',
           'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '0', 'GOFLAGS': '-mod=readonly',
           'GONOSUMDB': '', 'GOPRIVATE': '', 'GONOPROXY': '', 'GOINSECURE': '', 'GOENV': 'off'}
    module = subprocess.run([go, 'mod', 'download', '-json', MODULE + '@' + version], cwd=cache,
                            env=env, capture_output=True, text=True, timeout=300)
    m = json.loads(module.stdout)
    if module.returncode or 'Error' in m or not m.get('Sum', '').startswith('h1:') or not m.get('GoModSum', '').startswith('h1:'):
        raise ValueError('Verified upstream module download failed')
    source = root / 'source'
    if source.exists(): shutil.rmtree(source)
    shutil.copytree(m['Dir'], source)
    for p in [source, *source.rglob('*')]:
        if p.is_symlink(): raise ValueError('Symlink in module source')
        p.chmod(p.stat().st_mode | 0o200)
    # git apply never needs repository metadata or any remote.
    with (root / 'build.log').open('w') as log:
        run(['git', 'apply', '--check', str(PATCH.resolve())], cwd=source, env=env, log=log, timeout=30)
        run(['git', 'apply', str(PATCH.resolve())], cwd=source, env=env, log=log, timeout=30)
        security_updates = apply_security_floors(source,go,env,log)
        tags = (source / 'release/DEFAULT_BUILD_TAGS').read_text().strip() + ',with_purego,with_v2ray_api,with_sbox_accounting'
        # Native execution is necessary for tests: cross compilation is not acceptance.
        run([go, 'test', '-p', '2', '-tags', tags, '-ldflags', (source / 'release/LDFLAGS').read_text().strip(), './experimental/v2rayapi'], cwd=source, env=env, log=log)
        run([go, 'mod', 'verify'], cwd=source, env=env, log=log)
        ldflags = (source / 'release/LDFLAGS').read_text().strip() + ' -X ' + MODULE + '/constant.Version=' + version.removeprefix('v') + ' -s -w -buildid='
        run([go, 'build', '-p', '2', '-trimpath', '-buildvcs=false', '-tags', tags, '-ldflags', ldflags,
             '-o', str((root / 'sing-box').resolve()), './cmd/sing-box'], cwd=source, env=env, log=log)
    binary = root / 'sing-box'; binary.chmod(0o700)
    with (root/'build.log').open('a') as log:
        security_scans=audit_source_and_binary(source,binary,cache,go,env,log)
    identity = subprocess.check_output([str(binary), 'version'], text=True, timeout=15)
    if 'sing-box version ' + version.removeprefix('v') not in identity or 'with_sbox_accounting' not in identity:
        binary.unlink(); raise ValueError('Built core identity/capability mismatch')
    manifest = {'security_policy':SECURITY_POLICY,'security_scans':security_scans,'security_updates':security_updates,
                'source_go_mod_sha256':sha(source/'go.mod'),'source_go_sum_sha256':sha(source/'go.sum'),
                'coverage_scope':'compiled accounting hooks and accounting Go tests; release packet acceptance is a separate gate',
                'version': version.removeprefix('v'), 'architecture': 'linux-' + arch, 'sha256': sha(binary),
                'patch_sha256': sha(PATCH), 'module_sum': m['Sum'], 'go_mod_sum': m['GoModSum'],
                'go_version': subprocess.check_output([go, 'version'], text=True).strip(), 'tags': tags,
                'tests_passed': True, 'coverage': {p: True for p in PROTOCOLS},
                'built_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    atomic_json(root / 'provenance.json', manifest)
    return binary, manifest


def seed_bundled(cache, arch, manifest_path=Path('/usr/local/lib/sbox-accounting/current/core_manifest.json'), binary=Path('/usr/local/lib/sbox-accounting/core-candidate')):
    if manifest_path.is_file() and binary.is_file() and not binary.is_symlink():
        m = json.loads(manifest_path.read_text())
        if (m.get('architecture') == 'linux-' + arch and m.get('tests_passed') is True
                and security_qualified(m) and m.get('patch_sha256') == sha(PATCH) and m.get('sha256') == sha(binary)):
            version_key(m['version'])
            root = cache / ('core-v' + m['version'] + '-' + arch); root.mkdir(mode=0o700, exist_ok=True)
            if not verified_cached(root, m['version'], arch):
                shutil.copyfile(binary, root / 'sing-box'); (root / 'sing-box').chmod(0o700)
                atomic_json(root / 'provenance.json', m)
    catalog = PATCH.with_name('compatibility.json')
    if catalog.is_file():
        m = json.loads(catalog.read_text())
        observed = calendar.timegm(time.strptime(m['observed_at_utc'], '%Y-%m-%dT%H:%M:%SZ'))
        if m.get('patch_sha256') == sha(PATCH) and m.get('security_policy') == SECURITY_POLICY and 0 <= time.time() - observed < 86400:
            for item in m.get('rejected', []):
                version_key(item['version'])
                root = cache / ('core-' + item['version'] + '-' + arch); root.mkdir(mode=0o700, exist_ok=True)
                rejected = root / 'rejected.json'
                if not rejected.exists(): atomic_json(rejected, {**item, 'patch_sha256': m['patch_sha256']})


def ensure_git():
    if shutil.which('git'): return
    if os.geteuid() != 0: raise ValueError('git is needed to apply the accounting patch')
    subprocess.run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', '-o', 'Acquire::Retries=2',
                    'install', '-y', '--no-install-recommends', 'git'], check=True, timeout=600,
                   stdout=sys.stderr, stderr=sys.stderr, stdin=subprocess.DEVNULL,
                   env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'})
    if not shutil.which('git'): raise ValueError('Distribution git installation failed')


def resolve(request, output, cache, limit=16):
    cache = secure_cache(cache)
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch: raise ValueError('Unsupported core architecture')
    with (cache / 'resolver.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        seed_bundled(cache, arch)
        report = {'request': request, 'attempts': [], 'status': 'failed'}
        try:
            meta = cache / 'versions.json'
            if request not in ('latest', 'stable', 'beta', 'prerelease'):
                selected = candidates([], request)
            else:
                if meta.is_file() and time.time() - meta.stat().st_mtime < 3600:
                    versions = json.loads(meta.read_text())
                else:
                    versions = get(PROXY + '/' + MODULE + '/@v/list').decode().splitlines()
                    atomic_json(meta, versions)
                selected = candidates(versions, request)
            if not selected: raise ValueError('No eligible versions found')
            go = None
            for version in selected[:limit]:
                try:
                    candidate_root = cache / ('core-' + version + '-' + arch)
                    cached = verified_cached(candidate_root, version, arch)
                    rejected = candidate_root / 'rejected.json'
                    if not cached and rejected.is_file():
                        previous = json.loads(rejected.read_text())
                        if previous.get('patch_sha256') == sha(PATCH) and previous.get('security_policy') == SECURITY_POLICY and time.time() - rejected.stat().st_mtime < 86400:
                            raise ValueError('Cached incompatible accounting patch: ' + previous.get('error', 'build rejected'))
                    if cached:
                        binary, manifest = candidate_root / 'sing-box', cached
                    else:
                        ensure_git()
                        if go is None: go = toolchain(cache)
                        binary, manifest = build(cache, version, go, arch)
                    output = Path(output).absolute(); output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    temp = output.with_name(output.name + '.tmp'); shutil.copyfile(binary, temp); temp.chmod(0o700); temp.replace(output)
                    atomic_json(str(output) + '.provenance.json', manifest)
                    Path(str(output) + '.version').write_text(manifest['version'] + '\n')
                    report.update(status='resolved', resolved=manifest)
                    if report['attempts']: print('Compatibility fallback: newer candidates failed; keeping their build evidence.', file=sys.stderr)
                    print(json.dumps(manifest, sort_keys=True), file=sys.stderr)
                    return manifest
                except (ValueError, subprocess.SubprocessError, OSError) as exc:
                    report['attempts'].append({'version': version, 'error': str(exc)})
                    rejected_root = cache / ('core-' + version + '-' + arch)
                    rejected_root.mkdir(mode=0o700, exist_ok=True)
                    atomic_json(rejected_root / 'rejected.json', {'version': version, 'patch_sha256': sha(PATCH), 'security_policy':SECURITY_POLICY,'error': str(exc)})
                    print(f'Accounting compatibility rejected {version}: {exc}', file=sys.stderr)
            raise ValueError('No tested compatible core resolved; the running core has not been changed')
        finally:
            atomic_json(cache / 'last-resolution.json', report)


def preview(request, cache=Path('/var/cache/sbox-core')):
    if request not in ('latest', 'stable', 'beta', 'prerelease'):
        version_key(request)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        root = Path(cache) / ('core-v' + request.removeprefix('v') + '-' + str(arch))
        m = verified_cached(root, request, arch)
        if m:
            return {**m, 'published_at': None, 'changelog': '', 'source': 'Verified cached accounting source build',
                    'warning': 'Configuration checks and a recoverable transaction run before replacement.'}
        rejected = root / 'rejected.json'
        if rejected.is_file():
            m = json.loads(rejected.read_text())
            if m.get('patch_sha256') == sha(PATCH) and m.get('security_policy') == SECURITY_POLICY and time.time() - rejected.stat().st_mtime < 86400:
                raise ValueError('This version failed accounting compatibility; the running core is retained.')
    return {'version': request, 'sha256': None, 'published_at': None, 'changelog': '', 'build_required': True,
            'source': 'Verified compatible accounting source build; version and digest are reported after resolution',
            'warning': 'Building can take several minutes and requires build tools, disk and memory. Incompatibility keeps the current core.'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('request'); ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cache', type=Path, default=Path('/var/cache/sbox-core'))
    args = ap.parse_args()
    try: resolve(args.request, args.output, args.cache)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print('Core resolution failed: ' + str(e), file=sys.stderr); return 1
    return 0

if __name__ == '__main__': sys.exit(main())
