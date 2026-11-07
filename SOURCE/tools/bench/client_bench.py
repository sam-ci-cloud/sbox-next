#!/usr/bin/env python3
"""SBOX end-to-end protocol benchmark client (runs on an authorized client VPS).

Builds a sing-box client config with one local SOCKS/mixed inbound per protocol
from an endpoints JSON (server_endpoints.py), starts the client core, and measures
real authenticated traffic through each protocol to a bench target
(tools/bench/target) and to a public URL. Every sample is one CSV row.

Workloads (selectable with --tests):
  auth     cold first request after client start, plus a wrong-credential negative control
  small    N fresh proxied HTTP requests (new proxy stream/connection each); TTFB distribution
  web      N proxied HTTPS requests to a public 204 URL (real-site TTFB)
  dl8m     8 MiB download, SHA-256 verified
  up8m     8 MiB upload, server-side SHA-256 verified
  bulk     large download (default 128 MiB), SHA-256 verified, Mbps
  udp      UDP echo through SOCKS5 UDP ASSOCIATE: loss, RTT, jitter
  dns      DNS A/AAAA over UDP through the proxy, cold (unique name) and warm
  concurrent  P parallel 8 MiB downloads (default 4), aggregate Mbps
  loaded   small-request latency while a bulk download runs on the same protocol
"""
import argparse
import base64
import csv
import hashlib
import json
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid as uuidlib

ORDER = ['reality', 'vmess', 'hy2', 'tuic', 'anytls']
COLUMNS = ['timestamp_utc', 'trial_id', 'round', 'host', 'variant', 'protocol', 'test', 'target',
           'client_name', 'client_version', 'core_binary_sha', 'bytes', 'sha256_ok', 'connect_ms',
           'ttfb_ms', 'total_ms', 'throughput_mbps', 'udp_sent', 'udp_recv', 'udp_loss_pct',
           'udp_rtt_ms', 'udp_jitter_ms', 'status', 'error']
BLOCK = 1 << 20


def block(seed):
    out = bytearray(BLOCK)
    x = (seed * 0x9E3779B97F4A7C15 + 1) & 0xFFFFFFFFFFFFFFFF
    for i in range(0, BLOCK, 8):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into('<Q', out, i, x)
    return bytes(out)


_BLOCKS = {}


def expected_sha(n, seed):
    b = _BLOCKS.setdefault(seed, block(seed))
    h = hashlib.sha256()
    full, rest = divmod(n, BLOCK)
    for _ in range(full):
        h.update(b)
    h.update(b[:rest])
    return h.hexdigest()


def outbound(kind, ep, host, wrong=False):
    tag = kind
    sni = ep.get('sni')
    bad = (lambda v: str(uuidlib.uuid4()) if wrong else v)
    if kind == 'reality':
        return {'type': 'vless', 'tag': tag, 'server': host, 'server_port': ep['port'], 'uuid': bad(ep['uuid']),
                'flow': ep.get('flow') or '', 'tls': {'enabled': True, 'server_name': sni,
                'utls': {'enabled': True, 'fingerprint': ep.get('fingerprint', 'chrome')},
                'reality': {'enabled': True, 'public_key': ep['public_key'], 'short_id': ep['short_id']}}}
    if kind == 'vmess':
        return {'type': 'vmess', 'tag': tag, 'server': host, 'server_port': ep['port'], 'uuid': bad(ep['uuid']),
                'security': 'auto', 'alter_id': 0,
                'tls': {'enabled': bool(ep.get('tls', True)), 'server_name': sni},
                'transport': {'type': 'ws', 'path': '/' + ep['path'].lstrip('/'), 'headers': {'Host': sni}}}
    if kind == 'hy2':
        out = {'type': 'hysteria2', 'tag': tag, 'server': host, 'server_port': ep['port'],
               'password': bad(ep['password']), 'tls': {'enabled': True, 'server_name': sni, 'alpn': ['h3']}}
        if ep.get('hop_range'):
            out['server_ports'] = [ep['hop_range'].replace('-', ':')]
            out['hop_interval'] = '30s'
        return out
    if kind == 'tuic':
        return {'type': 'tuic', 'tag': tag, 'server': host, 'server_port': ep['port'], 'uuid': ep['uuid'],
                'password': bad(ep['password']), 'congestion_control': ep.get('congestion_control', 'bbr'),
                'udp_relay_mode': 'native', 'tls': {'enabled': True, 'server_name': sni, 'alpn': ['h3']}}
    if kind == 'anytls':
        return {'type': 'anytls', 'tag': tag, 'server': host, 'server_port': ep['port'],
                'password': bad(ep['password']), 'tls': {'enabled': True, 'server_name': sni,
                'utls': {'enabled': True, 'fingerprint': 'chrome'}}}
    raise ValueError(kind)


def client_config(endpoints, protocols, base_port, wrong=False, ca=None, tfo=False, ws_early=0):
    host = endpoints['host']
    inbounds, outbounds, rules = [], [], []
    for i, kind in enumerate(protocols):
        ep = endpoints['protocols'][kind]
        inbounds.append({'type': 'mixed', 'tag': 'in-' + kind, 'listen': '127.0.0.1', 'listen_port': base_port + i})
        ob = outbound(kind, ep, host, wrong)
        if ca and kind != 'reality':
            ob['tls']['certificate_path'] = ca
        # sing-box rejects tcp_fast_open on AnyTLS outbounds.
        if tfo and kind in ('reality', 'vmess'):
            ob['tcp_fast_open'] = True
        if kind == 'vmess' and (ws_early or ep.get('max_early_data')):
            ob['transport']['max_early_data'] = ws_early or ep['max_early_data']
            ob['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
        outbounds.append(ob)
        rules.append({'inbound': ['in-' + kind], 'action': 'route', 'outbound': kind})
    outbounds.append({'type': 'direct', 'tag': 'direct'})
    return {'log': {'level': 'warn', 'timestamp': True},
            'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
            'inbounds': inbounds, 'outbounds': outbounds,
            'route': {'rules': rules, 'final': 'direct', 'default_domain_resolver': 'local'}}


class Client:
    def __init__(self, binary, config, workdir, name='client'):
        self.path = os.path.join(workdir, name + '.json')
        with open(self.path, 'w') as f:
            json.dump(config, f, indent=1)
        os.chmod(self.path, 0o600)
        self.log = open(os.path.join(workdir, name + '.log'), 'ab')
        self.binary = binary
        self.proc = None

    def start(self, ports):
        self.proc = subprocess.Popen([self.binary, 'run', '-c', self.path], stdout=self.log, stderr=self.log)
        deadline = time.time() + 10
        for port in ports:
            while time.time() < deadline:
                try:
                    socket.create_connection(('127.0.0.1', port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


def curl(port, url, out='/dev/null', data=None, timeout=60, extra=()):
    fmt = '%{time_connect} %{time_starttransfer} %{time_total} %{size_download} %{http_code} %{size_upload}'
    cmd = ['curl', '-sS', '-o', out, '-w', fmt, '--max-time', str(timeout), '--proxy',
           'socks5h://127.0.0.1:%d' % port, *extra]
    if data is not None:
        cmd += ['--data-binary', '@' + data, '-H', 'Content-Type: application/octet-stream']
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True)
    parts = p.stdout.split()
    if p.returncode or len(parts) < 6:
        return None, (p.stderr.strip() or 'curl exit %d' % p.returncode)[-300:]
    c, s, t, size, code, up = parts[:6]
    return {'connect_ms': float(c) * 1000, 'ttfb_ms': float(s) * 1000, 'total_ms': float(t) * 1000,
            'bytes': int(float(size)), 'code': int(code), 'upload': int(float(up))}, None


def socks_udp_associate(port):
    tcp = socket.create_connection(('127.0.0.1', port), 5)
    tcp.sendall(b'\x05\x01\x00')
    if tcp.recv(2) != b'\x05\x00':
        raise OSError('socks auth refused')
    tcp.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('>H', 0))
    rep = tcp.recv(10)
    if len(rep) < 10 or rep[1] != 0:
        raise OSError('UDP ASSOCIATE refused')
    relay = (socket.inet_ntoa(rep[4:8]), struct.unpack('>H', rep[8:10])[0])
    if relay[0] == '0.0.0.0':
        relay = ('127.0.0.1', relay[1])
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return tcp, udp, relay


def socks_udp_header(host, port):
    if ':' in host:
        return b'\x00\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, host) + struct.pack('>H', port)
    try:
        return b'\x00\x00\x00\x01' + socket.inet_aton(host) + struct.pack('>H', port)
    except OSError:
        name = host.encode()
        return b'\x00\x00\x00\x03' + bytes([len(name)]) + name + struct.pack('>H', port)


def udp_echo(port, host, uport, count, interval, size=200):
    tcp, udp, relay = socks_udp_associate(port)
    hdr = socks_udp_header(host, uport)
    udp.settimeout(0.05)
    sent, rtts, recv = {}, {}, set()
    try:
        deadline_end = None
        for seq in range(count):
            payload = struct.pack('>Id', seq, time.time()).ljust(size, b'x')
            udp.sendto(hdr + payload, relay)
            sent[seq] = time.time()
            end = time.time() + interval
            while time.time() < end:
                _drain(udp, hdr, rtts, recv)
        deadline_end = time.time() + 2
        while time.time() < deadline_end and len(recv) < count:
            _drain(udp, hdr, rtts, recv)
    finally:
        udp.close()
        tcp.close()
    ordered = [rtts[s] for s in sorted(rtts)]
    jitter = statistics.mean(abs(a - b) for a, b in zip(ordered, ordered[1:])) if len(ordered) > 2 else None
    return {'udp_sent': count, 'udp_recv': len(recv), 'udp_loss_pct': 100.0 * (count - len(recv)) / count,
            'udp_rtt_ms': statistics.median(ordered) if ordered else None, 'udp_jitter_ms': jitter,
            'rtts': ordered}


def _drain(udp, hdr, rtts, recv):
    try:
        data, _ = udp.recvfrom(4096)
    except (socket.timeout, BlockingIOError):
        return
    # The relay may rewrite the address header (IPv4 vs domain); the payload is
    # always the trailing fixed-size datagram we sent.
    body = data[-200:]
    seq, ts = struct.unpack('>Id', body[:12])
    if seq not in recv:
        recv.add(seq)
        rtts[seq] = (time.time() - ts) * 1000


def dns_query(port, name, qtype, server='1.1.1.1'):
    tcp, udp, relay = socks_udp_associate(port)
    try:
        tid = random.randint(0, 65535)
        q = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
        q += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('>HH', qtype, 1)
        udp.settimeout(5)
        start = time.time()
        udp.sendto(socks_udp_header(server, 53) + q, relay)
        data, _ = udp.recvfrom(4096)
        ms = (time.time() - start) * 1000
        idx = data.find(struct.pack('>H', tid))
        msg = data[idx:]
        rcode = msg[3] & 15
        ancount = struct.unpack('>H', msg[6:8])[0]
        return ms, rcode, ancount
    finally:
        udp.close()
        tcp.close()


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('endpoints')
    ap.add_argument('--binary', default='/usr/local/lib/sbox-manager/sing-box')
    ap.add_argument('--target', required=True, help='bench target host (IP) reachable from the server')
    ap.add_argument('--target-port', type=int, default=18080)
    ap.add_argument('--udp-port', type=int, default=18081)
    ap.add_argument('--web-url', default='https://www.gstatic.com/generate_204')
    ap.add_argument('--protocols', default=','.join(ORDER))
    ap.add_argument('--tests', default='auth,small,web,dl8m,up8m,bulk,udp,dns,concurrent,loaded')
    ap.add_argument('--rounds', type=int, default=5)
    ap.add_argument('--small-n', type=int, default=40)
    ap.add_argument('--bulk-bytes', type=int, default=128 << 20)
    ap.add_argument('--parallel', type=int, default=4)
    ap.add_argument('--host-label', default='')
    ap.add_argument('--variant', default='')
    ap.add_argument('--ca', help='extra CA file for TLS protocols (isolated lab only)')
    ap.add_argument('--out', required=True)
    ap.add_argument('--base-port', type=int, default=21080)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--tfo', action='store_true', help='enable TCP Fast Open on TCP protocol dials')
    ap.add_argument('--ws-early-data', type=int, default=0, help='VMess WS early data bytes (Sec-WebSocket-Protocol)')
    a = ap.parse_args()

    endpoints = json.load(open(a.endpoints))
    protocols = [p for p in a.protocols.split(',') if p in endpoints['protocols']]
    tests = a.tests.split(',')
    os.makedirs(a.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix='sbox-bench-', dir=a.out)
    binsha = hashlib.sha256(open(a.binary, 'rb').read()).hexdigest()
    version = subprocess.run([a.binary, 'version'], capture_output=True, text=True).stdout.split('\n')[0]
    rng = random.Random(a.seed or None)
    ports = {k: a.base_port + i for i, k in enumerate(protocols)}
    target = 'http://%s:%d' % ('[%s]' % a.target if ':' in a.target else a.target, a.target_port)
    upfile = os.path.join(work, 'up8m.bin')
    with open(upfile, 'wb') as f:
        b = block(3)
        for _ in range(8):
            f.write(b)
    up_sha = expected_sha(8 << 20, 3)
    rows = []
    csv_path = os.path.join(a.out, 'samples.csv')
    new = not os.path.exists(csv_path)
    fh = open(csv_path, 'a', newline='')
    writer = csv.DictWriter(fh, COLUMNS)
    if new:
        writer.writeheader()
    trial = [0]

    def emit(rnd, kind, test, **kv):
        trial[0] += 1
        row = {c: '' for c in COLUMNS}
        row.update(timestamp_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), trial_id=trial[0], round=rnd,
                   host=a.host_label, variant=a.variant, protocol=kind, test=test, target=kv.pop('target', target),
                   client_name='sing-box', client_version=version, core_binary_sha=binsha)
        for k, v in kv.items():
            if k in row:
                row[k] = round(v, 3) if isinstance(v, float) else v
        writer.writerow(row)
        fh.flush()
        rows.append(row)

    def mbps(nbytes, ms):
        return 8 * nbytes / (ms / 1000) / 1e6 if ms else 0.0

    # Negative control: wrong credentials must not carry traffic.
    if 'auth' in tests:
        bad = Client(a.binary, client_config(endpoints, protocols, a.base_port + 50, wrong=True, ca=a.ca), work, 'wrong')
        bad.start([a.base_port + 50 + i for i in range(len(protocols))])
        try:
            alive = bad.proc is not None and bad.proc.poll() is None
            for i, kind in enumerate(protocols):
                r, err = curl(a.base_port + 50 + i, target + '/204', timeout=8)
                # A dead local client must not make the negative control pass.
                ok = alive and bad.proc.poll() is None and (r is None or r['code'] != 204)
                if not alive:
                    err = 'wrong-credential client failed to start'
                emit(0, kind, 'auth_wrong_credential', status='PASS' if ok else 'FAIL',
                     error='' if ok else (err or 'wrong credential carried traffic'), **({} if r is None else
                     {'ttfb_ms': r['ttfb_ms']}))
        finally:
            bad.stop()

    client = Client(a.binary, client_config(endpoints, protocols, a.base_port, ca=a.ca, tfo=a.tfo, ws_early=a.ws_early_data), work)
    for rnd in range(1, a.rounds + 1):
        client.start(list(ports.values()))
        if client.proc.poll() is not None:
            raise SystemExit('client core exited at start; see %s' % client.log.name)
        order = protocols[:]
        rng.shuffle(order)
        for kind in order:
            port = ports[kind]
            if 'auth' in tests:
                r, err = curl(port, target + '/204', timeout=20)
                emit(rnd, kind, 'auth_cold', status='PASS' if r and r['code'] == 204 else 'FAIL', error=err or '',
                     **({k: r[k] for k in ('connect_ms', 'ttfb_ms', 'total_ms')} if r else {}))
            if 'small' in tests:
                for _ in range(a.small_n):
                    r, err = curl(port, target + '/204', timeout=20)
                    emit(rnd, kind, 'small', status='PASS' if r and r['code'] == 204 else 'FAIL', error=err or '',
                         **({k: r[k] for k in ('connect_ms', 'ttfb_ms', 'total_ms')} if r else {}))
            if 'web' in tests:
                for _ in range(max(5, a.small_n // 4)):
                    r, err = curl(port, a.web_url, timeout=20)
                    emit(rnd, kind, 'web', target=a.web_url, status='PASS' if r and r['code'] in (200, 204) else 'FAIL',
                         error=err or '', **({k: r[k] for k in ('connect_ms', 'ttfb_ms', 'total_ms')} if r else {}))
            if 'dl8m' in tests:
                out = os.path.join(work, 'dl.bin')
                r, err = curl(port, target + '/bytes?n=%d&seed=1' % (8 << 20), out=out, timeout=120)
                ok = bool(r) and r['bytes'] == 8 << 20 and hashlib.sha256(open(out, 'rb').read()).hexdigest() == expected_sha(8 << 20, 1)
                emit(rnd, kind, 'dl8m', bytes=r['bytes'] if r else 0, sha256_ok=ok, status='PASS' if ok else 'FAIL',
                     error=err or '', **({'ttfb_ms': r['ttfb_ms'], 'total_ms': r['total_ms'],
                     'throughput_mbps': mbps(r['bytes'], r['total_ms'] - r['ttfb_ms'])} if r else {}))
            if 'up8m' in tests:
                out = os.path.join(work, 'up.json')
                r, err = curl(port, target + '/upload', out=out, data=upfile, timeout=120)
                ok = False
                if r and r['code'] == 200:
                    res = json.load(open(out))
                    ok = res.get('sha256') == up_sha and res.get('bytes') == 8 << 20
                emit(rnd, kind, 'up8m', bytes=r['upload'] if r else 0, sha256_ok=ok, status='PASS' if ok else 'FAIL',
                     error=err or '', **({'total_ms': r['total_ms'], 'throughput_mbps': mbps(8 << 20, r['total_ms'] - r['connect_ms'])} if r else {}))
            if 'bulk' in tests:
                out = os.path.join(work, 'bulk.bin')
                r, err = curl(port, target + '/bytes?n=%d&seed=2' % a.bulk_bytes, out=out, timeout=300)
                ok = bool(r) and r['bytes'] == a.bulk_bytes and hashlib.sha256(open(out, 'rb').read()).hexdigest() == expected_sha(a.bulk_bytes, 2)
                emit(rnd, kind, 'bulk', bytes=r['bytes'] if r else 0, sha256_ok=ok, status='PASS' if ok else 'FAIL',
                     error=err or '', **({'ttfb_ms': r['ttfb_ms'], 'total_ms': r['total_ms'],
                     'throughput_mbps': mbps(r['bytes'], r['total_ms'] - r['ttfb_ms'])} if r else {}))
                os.unlink(out) if os.path.exists(out) else None
            if 'udp' in tests:
                try:
                    res = udp_echo(port, a.target, a.udp_port, 150, 0.02)
                    res.pop('rtts')
                    emit(rnd, kind, 'udp', status='PASS' if res['udp_loss_pct'] < 5 else 'FAIL', **res)
                except Exception as e:
                    emit(rnd, kind, 'udp', status='FAIL', error=str(e)[:300])
            if 'dns' in tests:
                for label, name in (('dns_cold', 'sbox-%s.example.com' % uuidlib.uuid4().hex[:12]),
                                    ('dns_warm', 'www.google.com'), ('dns_warm', 'www.google.com')):
                    for qtype, qn in ((1, 'A'), (28, 'AAAA')):
                        try:
                            ms, rcode, an = dns_query(port, name, qtype)
                            # A unique cold name has no records: NXDOMAIN or NODATA both prove a
                            # full resolver round trip through the proxy.
                            ok = (rcode in (0, 3)) if label == 'dns_cold' else (rcode == 0 and an > 0)
                            emit(rnd, kind, label + '_' + qn, target='1.1.1.1:53/' + name, ttfb_ms=ms,
                                 status='PASS' if ok else 'FAIL', error='' if ok else 'rcode=%d an=%d' % (rcode, an))
                        except Exception as e:
                            emit(rnd, kind, label + '_' + qn, target='1.1.1.1:53/' + name, status='FAIL', error=str(e)[:300])
            if 'concurrent' in tests:
                results = [None] * a.parallel
                def one(i):
                    o = os.path.join(work, 'par%d.bin' % i)
                    results[i] = curl(port, target + '/bytes?n=%d&seed=1' % (8 << 20), out=o, timeout=180)
                start = time.time()
                ths = [threading.Thread(target=one, args=(i,)) for i in range(a.parallel)]
                [t.start() for t in ths]
                [t.join() for t in ths]
                wall = (time.time() - start) * 1000
                want = expected_sha(8 << 20, 1)
                good = 0
                for i, (r, _err) in enumerate(results):
                    path = os.path.join(work, 'par%d.bin' % i)
                    if r and r['bytes'] == 8 << 20 and hashlib.sha256(open(path, 'rb').read()).hexdigest() == want:
                        good += 1
                emit(rnd, kind, 'concurrent%d' % a.parallel, bytes=(8 << 20) * good, sha256_ok=good == a.parallel,
                     total_ms=wall, throughput_mbps=mbps((8 << 20) * good, wall),
                     status='PASS' if good == a.parallel else 'FAIL')
            if 'loaded' in tests:
                bg = subprocess.Popen(['curl', '-s', '-o', '/dev/null', '--max-time', '25', '--proxy',
                                       'socks5h://127.0.0.1:%d' % port, target + '/bytes?n=%d&seed=2' % (512 << 20)])
                time.sleep(1.5)
                for _ in range(10):
                    r, err = curl(port, target + '/204', timeout=20)
                    emit(rnd, kind, 'loaded_small', status='PASS' if r and r['code'] == 204 else 'FAIL', error=err or '',
                         **({k: r[k] for k in ('connect_ms', 'ttfb_ms', 'total_ms')} if r else {}))
                bg.terminate()
                bg.wait()
        client.stop()
        time.sleep(1)
    fh.close()

    summary = {}
    for kind in protocols:
        for test in sorted({r['test'] for r in rows if r['protocol'] == kind}):
            sel = [r for r in rows if r['protocol'] == kind and r['test'] == test]
            vals = [float(r['ttfb_ms']) for r in sel if r['ttfb_ms'] != '']
            thr = [float(r['throughput_mbps']) for r in sel if r['throughput_mbps'] != '']
            summary['%s/%s' % (kind, test)] = {
                'n': len(sel), 'pass': sum(r['status'] == 'PASS' for r in sel),
                'ttfb_p50': pct(vals, 50), 'ttfb_p95': pct(vals, 95), 'ttfb_p99': pct(vals, 99),
                'ttfb_stdev': statistics.pstdev(vals) if len(vals) > 1 else None,
                'mbps_median': statistics.median(thr) if thr else None,
                'mbps_min': min(thr) if thr else None, 'mbps_max': max(thr) if thr else None}
    json.dump({'host': a.host_label, 'variant': a.variant, 'client_version': version, 'core_binary_sha': binsha,
               'protocols': protocols, 'rounds': a.rounds, 'summary': summary},
              open(os.path.join(a.out, 'summary-%s-%s.json' % (a.host_label, a.variant)), 'w'), indent=1)
    print(json.dumps(summary, indent=1))
    for f in os.listdir(work):
        if f.endswith('.bin'):
            os.unlink(os.path.join(work, f))


if __name__ == '__main__':
    main()
