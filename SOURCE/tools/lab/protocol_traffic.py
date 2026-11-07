#!/usr/bin/env python3
"""LAB ONLY: real client traffic for all five transports against an installed SBOX.

Run as root inside a disposable lab machine (tools/lab/docker_lab.sh). A separate
network namespace runs the pinned sing-box core as the *client* (no third-party
client download), connects to the installed server over a veth link and fetches
data from a local target through each transport. Checks per protocol:

  tcp        1 MiB HTTP download, SHA-256 compared end to end
  udp        SOCKS5 UDP ASSOCIATE echo round trip (3 datagrams)
  wrong-auth a client with a wrong UUID/password/key must NOT get data
  restart    traffic again after `systemctl restart sing-box`

With --accounting it also creates managed users through the real manager
transaction, measures per-user accounting, enforces an exact quota boundary,
resets it and checks there is no cross-user leakage. Output: JSON on stdout and
OUTDIR/protocol-traffic.json. No credentials are written to the report.

  python3 protocol_traffic.py OUTDIR --ca /root/lab/ca.crt [--accounting]
"""
import argparse, hashlib, http.server, json, os, shutil, socket, socketserver, struct, subprocess, sys, threading, time, uuid
from pathlib import Path

NS = 'sbox-cli'
HOST_IF, PEER_IF = 'sbx-host', 'sbx-peer'
SERVER_IP, CLIENT_IP = '198.19.100.1', '198.19.100.2'
TARGET_TCP, TARGET_UDP = 18080, 18081
PAYLOAD = hashlib.sha256(b'sbox').digest() * (1048576 // 32)  # deterministic 1 MiB
CORE = '/usr/local/lib/sbox-manager/sing-box'
PROTOCOLS = ['reality', 'vmess', 'hy2', 'tuic', 'anytls']
rows = []


def run(args, check=True, timeout=60, **kw):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, **kw)
    if check and p.returncode:
        raise RuntimeError(f'{args[:3]} exit {p.returncode}: {p.stderr[-400:]}')
    return p


def record(test, protocol, ok, **facts):
    row = {'test': test, 'protocol': protocol, 'status': 'PASS' if ok else 'FAIL', **facts}
    rows.append(row)
    print(json.dumps(row), flush=True)
    return ok


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length', str(len(PAYLOAD))); self.end_headers(); self.wfile.write(PAYLOAD)

    def log_message(self, *a):
        pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_IP, TARGET_UDP))
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(b'echo:' + data, addr)


def netns_up():
    run(['ip', 'netns', 'del', NS], check=False); run(['ip', 'link', 'del', HOST_IF], check=False)
    run(['ip', 'netns', 'add', NS])
    run(['ip', 'link', 'add', HOST_IF, 'type', 'veth', 'peer', 'name', PEER_IF])
    run(['ip', 'link', 'set', PEER_IF, 'netns', NS])
    run(['ip', 'addr', 'add', SERVER_IP + '/24', 'dev', HOST_IF]); run(['ip', 'link', 'set', HOST_IF, 'up'])
    for a in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'link', 'set', PEER_IF, 'up'],
              ['ip', 'addr', 'add', CLIENT_IP + '/24', 'dev', PEER_IF], ['ip', 'route', 'add', 'default', 'via', SERVER_IP]):
        run(['ip', 'netns', 'exec', NS] + a)


def netns_down():
    run(['ip', 'netns', 'del', NS], check=False); run(['ip', 'link', 'del', HOST_IF], check=False)


def outbound(state, protocol, creds, ca, wrong=False):
    p = state['protocols'][protocol]
    domain = state['domain']
    bad = lambda v: (str(uuid.uuid4()) if '-' in str(v) else 'wrong-' + str(v)[:12]) if wrong else v
    tls = {'enabled': True, 'server_name': domain, 'certificate_path': ca}
    if protocol == 'reality':
        o = {'type': 'vless', 'server': SERVER_IP, 'server_port': p['port'], 'uuid': bad(creds['uuid']), 'flow': 'xtls-rprx-vision',
             'tls': {'enabled': True, 'server_name': p['sni'], 'utls': {'enabled': True, 'fingerprint': p.get('fingerprint') or 'chrome'},
                     'reality': {'enabled': True, 'public_key': p['public_key'], 'short_id': p['short_id']}}}
    elif protocol == 'vmess':
        o = {'type': 'vmess', 'server': SERVER_IP, 'server_port': p['port'], 'uuid': bad(creds['uuid']), 'security': 'auto',
             'transport': {'type': 'ws', 'path': p['path'], 'headers': {'Host': domain}}, 'tls': tls}
    elif protocol == 'hy2':
        o = {'type': 'hysteria2', 'server': SERVER_IP, 'server_port': p['port'], 'password': bad(creds['password']), 'tls': {**tls, 'alpn': ['h3']}}
    elif protocol == 'tuic':
        o = {'type': 'tuic', 'server': SERVER_IP, 'server_port': p['port'], 'uuid': bad(creds['uuid']), 'password': creds['password'],
             'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'tls': {**tls, 'alpn': ['h3']}}
    else:
        o = {'type': 'anytls', 'server': SERVER_IP, 'server_port': p['port'], 'password': bad(creds['password']), 'tls': tls}
    o['tag'] = protocol
    return o


def legacy_creds(state, protocol):
    p = state['protocols'][protocol]
    return {k: p[k] for k in ('uuid', 'password') if k in p}


class Client:
    def __init__(self, workdir, state, cred_for, ca, wrong=False):
        self.dir = Path(workdir); self.dir.mkdir(parents=True, exist_ok=True)
        self.ports = {}
        inbounds, outbounds, rules = [], [], []
        for i, protocol in enumerate(PROTOCOLS):
            if not state['protocols'].get(protocol, {}).get('enabled') or cred_for(protocol) is None:
                continue
            port = 21080 + i + (10 if wrong else 0)
            self.ports[protocol] = port
            inbounds.append({'type': 'mixed', 'tag': 'in-' + protocol, 'listen': '127.0.0.1', 'listen_port': port})
            outbounds.append(outbound(state, protocol, cred_for(protocol), ca, wrong))
            rules.append({'inbound': ['in-' + protocol], 'outbound': protocol})
        config = {'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': outbounds + [{'type': 'direct', 'tag': 'direct'}],
                  'route': {'rules': rules, 'final': 'direct'}}
        path = self.dir / 'client.json'
        path.write_text(json.dumps(config)); path.chmod(0o600)
        run(['ip', 'netns', 'exec', NS, CORE, 'check', '-c', path])
        self.log = (self.dir / 'client.log').open('w')
        self.proc = subprocess.Popen(['ip', 'netns', 'exec', NS, CORE, 'run', '-c', str(path)], stdout=self.log, stderr=subprocess.STDOUT)
        time.sleep(2)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def fetch(port, timeout=25):
    p = subprocess.run(['ip', 'netns', 'exec', NS, 'curl', '-sS', '--noproxy', '', '--socks5', f'127.0.0.1:{port}', '--max-time', str(timeout),
                        f'http://{SERVER_IP}:{TARGET_TCP}/payload', '-o', '-'], capture_output=True, timeout=timeout + 5)
    return p.returncode, hashlib.sha256(p.stdout).hexdigest() if p.stdout else '', len(p.stdout)


UDP_PROBE = r'''
import socket,struct,sys
port=int(sys.argv[1]);target=sys.argv[2];tport=int(sys.argv[3])
c=socket.create_connection(('127.0.0.1',port),timeout=10)
c.sendall(b'\x05\x01\x00');assert c.recv(2)==b'\x05\x00'
c.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00');h=c.recv(10);assert h[1]==0,h
relay=(socket.inet_ntoa(h[4:8]) if h[4:8]!=b'\x00\x00\x00\x00' else '127.0.0.1',struct.unpack('!H',h[8:10])[0])
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(8);ok=0
for i in range(3):
    msg=b'sbox-udp-%d'%i
    u.sendto(b'\x00\x00\x00\x01'+socket.inet_aton(target)+struct.pack('!H',tport)+msg,relay)
    data,_=u.recvfrom(65535)
    ok+=data[10:]==b'echo:'+msg
print(ok)
'''


def udp(port):
    p = subprocess.run(['ip', 'netns', 'exec', NS, sys.executable, '-c', UDP_PROBE, str(port), SERVER_IP, str(TARGET_UDP)],
                       capture_output=True, text=True, timeout=40)
    return p.stdout.strip() == '3', (p.stderr.strip().splitlines() or [''])[-1][:160]


def control(op, payload):
    p = subprocess.run(['/usr/local/bin/sbox', '_webui-control', op], input=json.dumps(payload), capture_output=True, text=True, timeout=300)
    if p.returncode:
        raise RuntimeError(f'_webui-control {op}: {p.stderr[-500:]}')
    return json.loads(p.stdout)


def change(request):
    return control('commit', {'token': control('prepare', request)['token']})


def usage(uid):
    p = run(['/usr/local/bin/sbox', 'quota', 'show', uid])
    user = json.loads(p.stdout)['users'][0]
    return user['usage']


def used_bytes(view):
    for key in ('used_bytes', 'period_used_bytes', 'total_bytes', 'used'):
        if isinstance(view.get(key), int):
            return view[key]
    raise KeyError('usage view has no byte counter: ' + ','.join(sorted(view)))


def wait_listeners(s, limit=45):
    # Readiness, not a fixed sleep: every enabled transport must be listening
    # (TCP for REALITY/VMess/AnyTLS, UDP for Hysteria2/TUIC) before re-testing.
    want = {('tcp' if p in ('reality', 'vmess', 'anytls') else 'udp', s['protocols'][p]['port'])
            for p in PROTOCOLS if s['protocols'].get(p, {}).get('enabled')}
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        seen = set()
        for proto, flag in (('tcp', '-ltnH'), ('udp', '-lunH')):
            for line in run(['ss', flag]).stdout.splitlines():
                local = line.split()[3] if len(line.split()) > 3 else ''
                port = local.rsplit(':', 1)[-1]
                if port.isdigit():
                    seen.add((proto, int(port)))
        if want <= seen:
            time.sleep(1)
            return True
        time.sleep(0.5)
    return False


def state():
    return json.loads(Path('/etc/sbox-manager/state.json').read_text())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('outdir'); ap.add_argument('--ca', required=True); ap.add_argument('--accounting', action='store_true')
    a = ap.parse_args()
    assert os.geteuid() == 0, 'root lab only'
    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)
    work = Path('/run/sbox-traffic-lab'); shutil.rmtree(work, ignore_errors=True); work.mkdir(mode=0o700)
    netns_up()
    srv = TCPServer((SERVER_IP, TARGET_TCP), Target); threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()
    want = hashlib.sha256(PAYLOAD).hexdigest()
    clients = []
    try:
        s = state()
        good = Client(work / 'legacy', s, lambda p: legacy_creds(s, p), a.ca); clients.append(good)
        for protocol, port in good.ports.items():
            code, digest, size = fetch(port)
            record('tcp-1MiB', protocol, code == 0 and digest == want, bytes=size, curl_exit=code)
            ok, detail = udp(port)
            record('udp-echo', protocol, ok, detail='' if ok else detail)
        # UDP port hopping: the provider-facing range is NAT-redirected to the
        # real listener. Test the first, middle and last port of each range.
        for protocol in ('hy2', 'tuic'):
            spec = s['protocols'].get(protocol, {}).get('udp_range') or ''
            if not s['protocols'].get(protocol, {}).get('enabled') or ':' not in spec:
                continue
            lo, hi = (int(x) for x in spec.split(':'))
            for hop in (lo, (lo + hi) // 2, hi):
                hs = json.loads(json.dumps(s)); hs['protocols'][protocol]['port'] = hop
                hc = Client(work / f'hop-{protocol}-{hop}', hs, lambda p, _p=protocol: legacy_creds(s, p) if p == _p else None, a.ca)
                code, digest, size = fetch(hc.ports[protocol])
                record('udp-hop-range-port', protocol, code == 0 and digest == want, port=hop, range=spec)
                hc.close()
        bad = Client(work / 'wrong', s, lambda p: legacy_creds(s, p), a.ca, wrong=True); clients.append(bad)
        for protocol, port in bad.ports.items():
            code, digest, size = fetch(port, timeout=10)
            record('wrong-auth-refused', protocol, digest != want, curl_exit=code, bytes=size)
        bad.close(); clients.remove(bad)
        before = run(['systemctl', 'show', 'sing-box', '-p', 'MainPID', '--value']).stdout.strip()
        run(['systemctl', 'restart', 'sing-box'], timeout=120)
        record('listeners-ready-after-restart', 'all', wait_listeners(s), seconds_limit=45)
        after = run(['systemctl', 'show', 'sing-box', '-p', 'MainPID', '--value']).stdout.strip()
        for protocol, port in good.ports.items():
            # The client keeps its pre-restart session: QUIC transports (Hysteria2,
            # TUIC) only notice the dead session after a timeout, so the client is
            # given up to three attempts. Attempts used are reported, not hidden.
            for attempt in (1, 2, 3):
                code, digest, size = fetch(port)
                if code == 0 and digest == want:
                    break
            record('tcp-after-restart', protocol, code == 0 and digest == want and before != after, bytes=size, attempts=attempt)
        good.close(); clients.remove(good)

        if a.accounting:
            names = ['lab-acct-a-' + uuid.uuid4().hex[:6], 'lab-acct-b-' + uuid.uuid4().hex[:6]]
            for name in names:
                change({'kind': 'user-create', 'data': {'name': name, 'protocols': PROTOCOLS}})
            s = state()
            users = [next(u for u in s['managed_users'] if u['name'] == n) for n in names]
            ua, ub = users
            b0 = used_bytes(usage(ub['id']))
            client = Client(work / 'user-a', s, lambda p: ua['protocols'].get(p), a.ca); clients.append(client)
            start = used_bytes(usage(ua['id']))
            for protocol, port in client.ports.items():
                code, digest, _ = fetch(port)
                record('managed-user-tcp', protocol, code == 0 and digest == want)
            time.sleep(8)
            measured = used_bytes(usage(ua['id'])) - start
            expected = len(PAYLOAD) * len(client.ports)
            record('accounting-counts-user-bytes', 'all', expected <= measured <= expected * 1.25, measured_bytes=measured, payload_bytes=expected)
            record('accounting-no-cross-user-leak', 'all', used_bytes(usage(ub['id'])) == b0)
            current = used_bytes(usage(ua['id']))
            limit = current + 4096
            change({'kind': 'quota', 'id': ua['id'], 'data': {'action': 'set', 'quota_bytes': limit, 'period': 'none'}})
            time.sleep(6)
            fetch(client.ports['reality'])  # crosses the boundary
            time.sleep(8)
            blocked = [fetch(port, timeout=10)[1] != want for port in client.ports.values()]
            record('quota-blocks-at-limit', 'all', all(blocked), limit_bytes=limit, blocked=sum(blocked), protocols=len(blocked))
            change({'kind': 'quota', 'id': ua['id'], 'data': {'action': 'reset'}})
            time.sleep(8)
            restored = [fetch(port)[1] == want for port in client.ports.values()]
            record('quota-reset-restores', 'all', all(restored), restored=sum(restored))
            client.close(); clients.remove(client)
            other = Client(work / 'user-b', s, lambda p: ub['protocols'].get(p), a.ca); clients.append(other)
            code, digest, _ = fetch(other.ports['hy2'])
            record('other-user-unaffected', 'hy2', code == 0 and digest == want)
            other.close(); clients.remove(other)
            for u in users:
                change({'kind': 'user-revoke', 'id': u['id'], 'data': {}})
            record('lab-users-revoked', 'all', not any(u['name'] in names for u in state().get('managed_users', [])))
    finally:
        for c in clients:
            c.close()
        srv.shutdown(); netns_down(); shutil.rmtree(work, ignore_errors=True)
    summary = {'scope': 'Local disposable systemd lab: real sing-box client in a separate network namespace; lab CA; no public network claim',
               'passed': sum(r['status'] == 'PASS' for r in rows), 'failed': sum(r['status'] == 'FAIL' for r in rows), 'rows': rows}
    (out / 'protocol-traffic.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: summary[k] for k in ('passed', 'failed')}))
    return 0 if summary['failed'] == 0 and summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
