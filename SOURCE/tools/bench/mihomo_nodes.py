#!/usr/bin/env python3
"""Per-node acceptance of a Mihomo client profile with the real Mihomo core.

For every proxy in a Mihomo YAML (for example the original six-node protected
profile, read unmodified), start Mihomo with only that proxy and measure, through
its local mixed port, against a bench target (tools/bench/target):

  auth          first request after start, and a wrong-credential negative control
  small         N fresh proxied requests (TTFB distribution)
  dl8m / up8m   8 MiB download / upload, SHA-256 verified end to end
  udp           UDP echo through SOCKS5 UDP ASSOCIATE (loss, RTT)
  dns           DNS A over UDP through the proxy

The profile's DNS, groups and rules are not used. Mihomo resolves server names
with its own resolver (it ignores /etc/hosts), so an isolated lab must pass
--map HOST=IP: only the dial address changes; TLS SNI/servername stay the
profile's (pinned to HOST where the profile relied on the server name). Run the
client behind an egress guard for any production address. Set SSL_CERT_FILE to
add a lab CA. Output: one CSV row per sample plus a JSON summary.

usage: mihomo_nodes.py PROFILE.yaml --mihomo /path/to/mihomo --target IP --out DIR
"""
import argparse
import copy
import csv
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from client_bench import curl, dns_query, expected_sha, block, udp_echo, pct  # noqa: E402



def wrong(proxy):
    bad = copy.deepcopy(proxy)
    if 'uuid' in bad:
        bad['uuid'] = '00000000-0000-4000-8000-000000000000'
    if 'password' in bad:
        bad['password'] = 'sbox-wrong-' + hashlib.sha256(str(bad['password']).encode()).hexdigest()[:16]
    if bad.get('type') == 'vless':
        bad['uuid'] = '00000000-0000-4000-8000-000000000000'
    return bad


def run_node(binary, proxy, port, workdir, name):
    cfg = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False, 'mode': 'rule',
           'log-level': 'warning', 'ipv6': True, 'dns': {'enable': False},
           'proxies': [proxy], 'rules': ['MATCH,' + proxy['name']]}
    d = os.path.join(workdir, name)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, 'config.yaml')
    with open(path, 'w') as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    os.chmod(path, 0o600)
    log = open(os.path.join(d, 'mihomo.log'), 'wb')
    proc = subprocess.Popen([binary, '-d', d, '-f', path], stdout=log, stderr=log)
    time.sleep(2.0)
    return proc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('profile')
    ap.add_argument('--mihomo', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--target-port', type=int, default=18080)
    ap.add_argument('--udp-port', type=int, default=18081)
    ap.add_argument('--small-n', type=int, default=20)
    ap.add_argument('--rounds', type=int, default=1)
    ap.add_argument('--label', default='')
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27990)
    ap.add_argument('--map', action='append', default=[], metavar='HOST=IP', help='dial IP for a server name (isolated lab)')
    a = ap.parse_args()
    profile = yaml.safe_load(open(a.profile))
    proxies = profile.get('proxies', [])
    mapping = dict(m.split('=', 1) for m in a.map)
    for p in proxies:
        host = p.get('server')
        if host in mapping:
            if p.get('type') in ('vmess', 'vless', 'trojan') and p.get('tls') and not p.get('servername'):
                p['servername'] = host
            if p.get('type') in ('hysteria2', 'tuic', 'anytls') and not p.get('sni'):
                p['sni'] = host
            p['server'] = mapping[host]
    os.makedirs(a.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix='mihomo-nodes-', dir=a.out)
    version = subprocess.run([a.mihomo, '-v'], capture_output=True, text=True).stdout.split('\n')[0]
    target = 'http://%s:%d' % ('[%s]' % a.target if ':' in a.target else a.target, a.target_port)
    up = os.path.join(work, 'up8m.bin')
    with open(up, 'wb') as f:
        b = block(3)
        for _ in range(8):
            f.write(b)
    cols = ['timestamp_utc', 'label', 'round', 'node', 'type', 'server_port', 'test', 'ttfb_ms', 'total_ms',
            'throughput_mbps', 'sha256_ok', 'udp_loss_pct', 'udp_rtt_ms', 'status', 'error', 'client_version']
    fh = open(os.path.join(a.out, 'node-samples.csv'), 'a', newline='')
    w = csv.DictWriter(fh, cols)
    if fh.tell() == 0:
        w.writeheader()
    rows = []

    def emit(rnd, p, test, **kv):
        row = {c: '' for c in cols}
        row.update(timestamp_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), label=a.label, round=rnd,
                   node=p['name'], type=p['type'], server_port=p.get('ports') or p.get('port'), test=test,
                   client_version=version)
        row.update({k: (round(v, 3) if isinstance(v, float) else v) for k, v in kv.items() if k in cols})
        w.writerow(row)
        fh.flush()
        rows.append(row)

    for idx, proxy in enumerate(proxies):
        port = a.port + idx * 2
        bad = run_node(a.mihomo, wrong(proxy), port + 1, work, 'wrong-%d' % idx)
        try:
            alive = bad.poll() is None
            r, err = curl(port + 1, target + '/204', timeout=10)
            ok = alive and (r is None or r['code'] != 204)
            emit(0, proxy, 'auth_wrong_credential', status='PASS' if ok else 'FAIL',
                 error='' if ok else ('client did not start' if not alive else (err or 'wrong credential carried traffic')))
        finally:
            bad.terminate()
            bad.wait()
        for rnd in range(1, a.rounds + 1):
            proc = run_node(a.mihomo, proxy, port, work, 'node-%d' % idx)
            try:
                if proc.poll() is not None:
                    emit(rnd, proxy, 'start', status='FAIL', error='mihomo exited; see node log')
                    continue
                r, err = curl(port, target + '/204', timeout=20)
                emit(rnd, proxy, 'auth', status='PASS' if r and r['code'] == 204 else 'FAIL', error=err or '',
                     **({'ttfb_ms': r['ttfb_ms'], 'total_ms': r['total_ms']} if r else {}))
                for _ in range(a.small_n):
                    r, err = curl(port, target + '/204', timeout=20)
                    emit(rnd, proxy, 'small', status='PASS' if r and r['code'] == 204 else 'FAIL', error=err or '',
                         **({'ttfb_ms': r['ttfb_ms'], 'total_ms': r['total_ms']} if r else {}))
                out = os.path.join(work, 'dl.bin')
                r, err = curl(port, target + '/bytes?n=%d&seed=1' % (8 << 20), out=out, timeout=180)
                ok = bool(r) and r['bytes'] == 8 << 20 and hashlib.sha256(open(out, 'rb').read()).hexdigest() == expected_sha(8 << 20, 1)
                emit(rnd, proxy, 'dl8m', sha256_ok=ok, status='PASS' if ok else 'FAIL', error=err or '',
                     **({'ttfb_ms': r['ttfb_ms'], 'total_ms': r['total_ms'],
                         'throughput_mbps': 8 * r['bytes'] / max(1e-6, (r['total_ms'] - r['ttfb_ms']) / 1000) / 1e6} if r else {}))
                res_path = os.path.join(work, 'up.json')
                r, err = curl(port, target + '/upload', out=res_path, data=up, timeout=180)
                ok = False
                if r and r['code'] == 200:
                    res = json.load(open(res_path))
                    ok = res.get('sha256') == expected_sha(8 << 20, 3) and res.get('bytes') == 8 << 20
                emit(rnd, proxy, 'up8m', sha256_ok=ok, status='PASS' if ok else 'FAIL', error=err or '',
                     **({'total_ms': r['total_ms'], 'throughput_mbps': 8 * (8 << 20) / max(1e-6, (r['total_ms'] - r['connect_ms']) / 1000) / 1e6} if r else {}))
                try:
                    res = udp_echo(port, a.target, a.udp_port, 100, 0.02)
                    emit(rnd, proxy, 'udp', udp_loss_pct=res['udp_loss_pct'], udp_rtt_ms=res['udp_rtt_ms'] or '',
                         status='PASS' if res['udp_loss_pct'] < 5 else 'FAIL')
                except Exception as e:
                    emit(rnd, proxy, 'udp', status='FAIL', error=str(e)[:200])
                try:
                    ms, rcode, an = dns_query(port, 'www.google.com', 1)
                    emit(rnd, proxy, 'dns', ttfb_ms=ms, status='PASS' if rcode == 0 and an else 'FAIL')
                except Exception as e:
                    emit(rnd, proxy, 'dns', status='FAIL', error=str(e)[:200])
            finally:
                proc.terminate()
                proc.wait()
    fh.close()
    summary = {}
    for p in proxies:
        sel = [r for r in rows if r['node'] == p['name']]
        small = [float(r['ttfb_ms']) for r in sel if r['test'] == 'small' and r['ttfb_ms'] != '']
        summary[p['name']] = {
            'type': p['type'], 'port': p.get('port'), 'ports': p.get('ports'),
            'tests': {t: '%d/%d' % (sum(r['status'] == 'PASS' for r in sel if r['test'] == t), sum(1 for r in sel if r['test'] == t))
                      for t in sorted({r['test'] for r in sel})},
            'small_p50': pct(small, 50), 'small_p95': pct(small, 95),
            'dl8m_mbps': statistics.median([float(r['throughput_mbps']) for r in sel if r['test'] == 'dl8m' and r['throughput_mbps'] != ''] or [0]),
            'all_pass': all(r['status'] == 'PASS' for r in sel)}
    json.dump({'label': a.label, 'client': version, 'nodes': summary}, open(os.path.join(a.out, 'node-summary.json'), 'w'), indent=1, ensure_ascii=False)
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    for f in os.listdir(work):
        if f.endswith('.bin'):
            os.unlink(os.path.join(work, f))
    return 0 if all(v['all_pass'] for v in summary.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
