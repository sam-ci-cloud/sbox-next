#!/usr/bin/env python3
"""Connection churn, soak and conntrack pressure from an authorized client host.

  churn   WORKERS parallel loops over the selected protocols for SECONDS: each
          iteration opens a fresh proxied request (/204) and every 10th one an
          8 MiB SHA-verified download; reports totals, failures and latency.
  soak    like churn with 1 worker and a pause between iterations, appending one
          JSON line per iteration to OUT (resumable evidence for long runs).
  udpflood SERVER_IP PORT FLOWS: sends one datagram from FLOWS distinct source
          ports (fills conntrack); run churn at the same time to see the effect.

usage: stress_client.py churn ENDPOINTS TARGET_IP --workers 16 --seconds 300 [--protocols ...]
       stress_client.py soak ENDPOINTS TARGET_IP --seconds 86400 --pause 20 --out FILE
       stress_client.py udpflood SERVER_IP PORT FLOWS
"""
import argparse
import hashlib
import json
import os
import socket
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client_bench as cb  # noqa: E402

PROTOS = ['reality', 'vmess', 'hy2', 'tuic', 'anytls']


def run_iteration(port, target, i, work, worker=0):
    if i % 10 == 9:
        # One file per worker: concurrent workers must not share a download target.
        out = os.path.join(work, 'dl-%d-%d.bin' % (port, worker))
        r, e = cb.curl(port, 'http://%s:18080/bytes?n=%d&seed=1' % (target, 8 << 20), out=out, timeout=120)
        ok = bool(r) and r['bytes'] == 8 << 20 and hashlib.sha256(open(out, 'rb').read()).hexdigest() == cb.expected_sha(8 << 20, 1)
        return ok, (r or {}).get('ttfb_ms'), e
    r, e = cb.curl(port, 'http://%s:18080/204' % target, timeout=20)
    return bool(r) and r['code'] == 204, (r or {}).get('ttfb_ms'), e


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', choices=['churn', 'soak', 'udpflood'])
    ap.add_argument('a')
    ap.add_argument('b')
    ap.add_argument('c', nargs='?')
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--seconds', type=int, default=300)
    ap.add_argument('--pause', type=float, default=0)
    ap.add_argument('--protocols', default=','.join(PROTOS))
    ap.add_argument('--out', default='/root/stress.jsonl')
    ap.add_argument('--binary', default='/usr/local/lib/sbox-manager/sing-box')
    ap.add_argument('--base-port', type=int, default=29000, help='first local mixed port (one per protocol)')
    a = ap.parse_args()
    if a.mode == 'udpflood':
        ip, port, flows = a.a, int(a.b), int(a.c)
        socks = []
        sent = 0
        for _ in range(flows):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('0.0.0.0', 0))
            s.sendto(os.urandom(64), (ip, port))
            socks.append(s)
            sent += 1
            if len(socks) >= 900:
                for x in socks:
                    x.close()
                socks = []
        for x in socks:
            x.close()
        print(json.dumps({'udpflood_sent_distinct_flows': sent, 'target': '%s:%d' % (ip, port)}))
        return
    endpoints = json.load(open(a.a))
    target = a.b
    protos = [p for p in a.protocols.split(',') if p in endpoints['protocols']]
    work = os.path.dirname(os.path.abspath(a.out))
    client = cb.Client(a.binary, cb.client_config(endpoints, protos, a.base_port), work, 'stress-%d' % a.base_port)
    client.start([a.base_port + i for i in range(len(protos))])
    stop = time.time() + a.seconds
    lock = threading.Lock()
    stats = {p: {'ok': 0, 'fail': 0, 'ttfb': [], 'errors': {}} for p in protos}
    fh = open(a.out, 'a') if a.mode == 'soak' else None

    def worker(w):
        i = 0
        while time.time() < stop:
            p = protos[(w + i) % len(protos)]
            ok, ttfb, err = run_iteration(a.base_port + protos.index(p), target, i, work, w)
            with lock:
                s = stats[p]
                s['ok' if ok else 'fail'] += 1
                if ttfb:
                    s['ttfb'].append(ttfb)
                if not ok:
                    key = (err or ('sha/size mismatch' if i % 10 == 9 else 'non-204 response'))[:60]
                    s['errors'][key] = s['errors'].get(key, 0) + 1
                if fh:
                    fh.write(json.dumps({'t': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'protocol': p, 'ok': ok, 'ttfb_ms': ttfb, 'error': None if ok else (err or '')[:80]}) + '\n')
                    fh.flush()
            i += 1
            if client.proc.poll() is not None:
                return
            if a.pause:
                time.sleep(a.pause)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(1 if a.mode == 'soak' else a.workers)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    alive = client.proc.poll() is None
    client.stop()
    summary = {'mode': a.mode, 'workers': len(threads), 'seconds': a.seconds, 'client_alive': alive}
    for p, s in stats.items():
        v = sorted(s['ttfb'])
        summary[p] = {'ok': s['ok'], 'fail': s['fail'], 'p50': cb.pct(v, 50), 'p95': cb.pct(v, 95), 'p99': cb.pct(v, 99), 'errors': s['errors']}
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
