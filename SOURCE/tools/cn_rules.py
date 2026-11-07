#!/usr/bin/env python3
"""Offline mainland-China rule data for the Complete sing-box profile (no runtime downloads).

  build  --apnic FILE --dlc TARBALL --dlc-commit SHA [--out PATH]
         Deterministic snapshot from two pinned, archived inputs:
           * APNIC delegated statistics (CN allocations/assignments, IPv4+IPv6). Conditions of use:
             freely available for download and use; APNIC accepts no liability; allocation country
             is not an authoritative statement of where an address is in use.
           * v2fly domain-list-community, category `cn` with includes (MIT licence).
  verify [--out PATH]   structure, sorting and plausibility checks (used by tests/CI)

The generated file is committed; generated profiles embed it as inline rule sets, so no client ever
contacts a third-party host for rule data. Refresh it at release time and record the new inputs."""
import argparse, datetime, hashlib, ipaddress, io, json, re, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / 'shared_webui/backend/cn_rules.json'
APNIC_URL = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
DLC_URL = 'https://github.com/v2fly/domain-list-community/tree/{commit}'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def apnic_cn(path, minimum=(1000, 500)):
    v4, v6, stamp = [], [], None
    for line in open(path, encoding='ascii', errors='strict'):
        parts = line.strip().split('|')
        if len(parts) >= 6 and parts[0] == '2' and parts[1] == 'apnic':
            stamp = parts[2]  # version|registry|serial|records|startdate|enddate|UTCoffset
        if len(parts) < 7 or parts[1] != 'CN' or parts[6] not in ('allocated', 'assigned'):
            continue
        if parts[2] == 'ipv4':
            first = ipaddress.IPv4Address(parts[3]); v4 += ipaddress.summarize_address_range(first, first + int(parts[4]) - 1)
        elif parts[2] == 'ipv6':
            v6.append(ipaddress.IPv6Network('%s/%s' % (parts[3], parts[4])))
    v4, v6 = list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6))
    if len(v4) < minimum[0] or len(v6) < minimum[1]:
        raise SystemExit('APNIC input looks truncated (%d IPv4, %d IPv6 CN prefixes)' % (len(v4), len(v6)))
    return [str(n) for n in v4] + [str(n) for n in v6], stamp


def dlc_cn(tarball, minimum=1000):
    files = {}
    with tarfile.open(tarball) as tar:
        for member in tar.getmembers():
            parts = member.name.split('/')
            if member.isfile() and len(parts) == 3 and parts[1] == 'data':
                files[parts[2]] = tar.extractfile(member).read().decode('utf-8')
            if member.isfile() and len(parts) == 2 and parts[1] == 'LICENSE':
                licence = tar.extractfile(member).read().decode('utf-8')
    if not licence.startswith('MIT License'):
        raise SystemExit('Unexpected domain-list-community licence')
    out = {'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set()}

    def entries(name, stack=()):
        if name in stack:
            raise SystemExit('include loop at ' + name)
        for raw in files[name].splitlines():
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            tokens = line.split()
            value, attrs = tokens[0], {t[1:] for t in tokens[1:] if t.startswith('@')}
            if value.startswith('include:'):
                want = {t[1:] for t in tokens[1:] if t.startswith('@') and not t.startswith('@-')}
                drop = {t[2:] for t in tokens[1:] if t.startswith('@-')}
                for kind, item, item_attrs in entries(value[8:], stack + (name,)):
                    if want and not want <= item_attrs: continue
                    if drop & item_attrs: continue
                    yield kind, item, item_attrs
                continue
            kind, _, item = value.rpartition(':')
            yield {'': 'domain_suffix', 'domain': 'domain_suffix', 'full': 'domain', 'keyword': 'domain_keyword', 'regexp': 'domain_regex'}[kind], item, attrs

    for kind, item, _ in entries('cn'):
        if kind == 'domain_regex':
            re.compile(item)
        out[kind].add(item.lower() if kind != 'domain_regex' else item)
    if len(out['domain_suffix']) < minimum:
        raise SystemExit('domain-list-community input looks truncated')
    return {k: sorted(v) for k, v in out.items() if v}


def build(args):
    ip_cidr, stamp = apnic_cn(args.apnic)
    domains = dlc_cn(args.dlc)
    if not re.fullmatch(r'[0-9a-f]{40}', args.dlc_commit):
        raise SystemExit('--dlc-commit must be a full commit SHA')
    data = {'schema': 1, 'snapshot': datetime.datetime.strptime(stamp, '%Y%m%d').strftime('%Y-%m-%d') if stamp else None,
            # Provenance without URLs: the shipped data file must not name any download host
            # (tests/test_no_github_runtime.py); the source locations are in this tool and the docs.
            'sources': {'apnic': {'name': 'APNIC delegated statistics (delegated-apnic-latest)', 'sha256': sha256(args.apnic), 'licence': 'APNIC conditions of use: free to download and use; no liability; allocation country is not proof of location'},
                        'domain_list_community': {'name': 'v2fly domain-list-community', 'commit': args.dlc_commit, 'archive_sha256': sha256(args.dlc), 'category': 'cn', 'licence': 'MIT'}},
            'domain': domains, 'ip_cidr': ip_cidr}
    text = json.dumps(data, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n'
    Path(args.out).write_text(text, encoding='utf-8')
    print(json.dumps({'out': str(args.out), 'bytes': len(text), 'ip_cidr': len(ip_cidr), **{k: len(v) for k, v in domains.items()}}))


def verify(path=DEFAULT_OUT):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    assert data['schema'] == 1 and data['snapshot']
    assert set(data['sources']) == {'apnic', 'domain_list_community'}
    assert '://' not in json.dumps(data['sources']), 'no download locations in the shipped file'
    nets = [ipaddress.ip_network(n) for n in data['ip_cidr']]
    assert len(nets) > 1000 and all(not n.is_private for n in nets), 'CN prefixes must be public'
    assert data['domain']['domain_suffix'] == sorted(data['domain']['domain_suffix']) and 'cn' in data['domain']['domain_suffix']
    for rx in data['domain'].get('domain_regex', []):
        re.compile(rx)
    assert not any('/' in d or ' ' in d for v in data['domain'].values() for d in v if not d.startswith('^')), 'plain names only'
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build'); b.add_argument('--apnic', required=True); b.add_argument('--dlc', required=True); b.add_argument('--dlc-commit', required=True); b.add_argument('--out', default=DEFAULT_OUT)
    v = sub.add_parser('verify'); v.add_argument('--out', default=DEFAULT_OUT)
    args = ap.parse_args()
    if args.cmd == 'build':
        build(args)
    else:
        d = verify(args.out); print(json.dumps({'snapshot': d['snapshot'], 'ip_cidr': len(d['ip_cidr']), **{k: len(x) for k, x in d['domain'].items()}}))


if __name__ == '__main__':
    main()
