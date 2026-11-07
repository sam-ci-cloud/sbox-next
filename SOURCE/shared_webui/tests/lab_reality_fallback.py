#!/usr/bin/env python3
"""Isolated REALITY handshake-target lab: remote AND self-hosted modes. LAB ONLY.

    sudo python3 shared_webui/tests/lab_reality_fallback.py OUTDIR [--browser]

Re-executes itself inside a fresh network + mount namespace (`unshare -n -m`)
that contains only a loopback interface, so no packet can leave the host and
no public website is contacted. /etc/hosts is replaced only inside that mount
namespace. Certificates come from a throw-away lab CA created per run; they
are never installed or trusted outside this process. The real pinned core
(assets/sing-box-accounting.gz), the real state renderer (src/state.py) and
the real Personal Cloud server/site (src/fallback-web) are used.

Proves, per mode:
  self-hosted  (a) an ordinary TLS/browser request with the owner SNI reaching
                   the public REALITY port receives the full Personal Cloud
                   site and the owner-domain (lab CA) certificate;
               (b) an authenticated REALITY client built from the EXPORTED
                   client profile still proxies traffic;
               (c) a client with the wrong REALITY key does not get a tunnel;
               (d) the website listens on loopback only and refuses 0.0.0.0.
  remote       (a) ordinary TLS is relayed to the (lab) remote handshake target;
               (b) the authenticated REALITY client still works;
               (c) rendered config/profiles equal the base-commit renderer.
Writes OUTDIR/reality-lab.json. NOT live/public network acceptance.
"""
import fcntl
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
import reality_fixture as fx  # noqa: E402

SERVER = ROOT / 'src/fallback-web/server.py'
SITE = ROOT / 'src/fallback-web/site'
RPORT = 10443  # public REALITY port inside the lab namespace
REMOTE_TARGET = r'''
import socket,ssl,sys,threading
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(sys.argv[1],sys.argv[2])
srv=socket.create_server(('127.0.0.3',443))
def serve(c):
    try:
        with ctx.wrap_socket(c,server_side=True) as t:
            t.settimeout(10);t.recv(65536);body=b'LAB REMOTE HANDSHAKE TARGET (stands in for a public website; offline lab only)'
            t.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s'%(len(body),body))
            t.settimeout(2);t.unwrap()
    except Exception:pass
while True:
    c,_=srv.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
'''
MARKER = b'<meta name="generator" content="sbox-personal-cloud">'


def bring_up_loopback():
    s = socket.socket()
    ifr = struct.pack('16sH', b'lo', 0)
    flags = struct.unpack('16sH', fcntl.ioctl(s, 0x8913, ifr)[:18])[1]
    fcntl.ioctl(s, 0x8914, struct.pack('16sH', b'lo', flags | 1))
    s.close()


def interfaces():
    # if_nameindex() asks the kernel for THIS network namespace (sysfs may
    # still show the host's devices because it is not remounted).
    return sorted(name for _, name in socket.if_nameindex())


def wait_port(port, host='127.0.0.1', timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def https_get(port, sni, path, cafile, host='127.0.0.1'):
    ctx = ssl.create_default_context(cafile=str(cafile))
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            peer = tls.getpeercert()
            serial = peer.get('serialNumber')
            tls.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: lab-browser\r\n\r\n' % (path, sni)).encode())
            data = b''
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    return head.split(b'\r\n', 1)[0].decode(), body, serial, dict(x[0] for x in peer['subject'])['commonName']


def cert_serial(path):
    out = subprocess.run(['openssl', 'x509', '-in', str(path), '-noout', '-serial'], capture_output=True, text=True, check=True).stdout
    return out.strip().split('=', 1)[1]


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'REALITY-TUNNEL-OK ' + self.path.encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


def socks_get(port, target_port):
    """Minimal SOCKS5 CONNECT + HTTP GET through the sing-box client."""
    with socket.create_connection(('127.0.0.1', port), timeout=8) as s:
        s.sendall(b'\x05\x01\x00'); assert s.recv(2) == b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('>H', target_port))
        reply = s.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            return None
        s.sendall(b'GET /through-reality HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
        data = b''
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data


def client_config(profile, server_port, public_key=None, socks=1080):
    p = profile
    return {'log': {'level': 'warn'},
            'inbounds': [{'type': 'mixed', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': socks}],
            'outbounds': [{'type': 'vless', 'tag': 'proxy', 'server': p['server'], 'server_port': server_port, 'uuid': p['uuid'], 'flow': p['flow'],
                           'tls': {'enabled': True, 'server_name': p['servername'], 'utls': {'enabled': True, 'fingerprint': p['client-fingerprint']},
                                   'reality': {'enabled': True, 'public_key': public_key or p['reality-opts']['public-key'], 'short_id': p['reality-opts']['short-id']}}}],
            'route': {'final': 'proxy'}}


def start(args, log):
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)


def run_mode(mode, out, rows, browser):
    import yaml
    core = fx.core_binary()
    priv, pub = fx.reality_keypair()
    state = fx.base_state(priv, pub, reality_port=RPORT)
    if mode == 'self-hosted':
        state = fx.self_hosted(state, port=8443)
    rendered = fx.render(state)
    config = json.loads((rendered / 'server.json').read_text())
    profile = next(p for p in yaml.safe_load((rendered / 'mihomo.yaml').read_text())['proxies'] if p.get('type') == 'vless')
    procs, logs = [], out / ('logs-' + mode)
    logs.mkdir(parents=True, exist_ok=True)

    def check(name, ok, detail=''):
        rows.append({'mode': mode, 'check': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        print(('PASS ' if ok else 'FAIL ') + mode + ': ' + name + (' — ' + detail if detail else ''), flush=True)
        return ok

    try:
        target = http.server.ThreadingHTTPServer(('127.0.0.1', 9000), Target)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        if mode == 'self-hosted':
            site_cert, site_key = LEAVES[fx.DOMAIN]
            procs.append(start(['python3', '-I', '-B', str(SERVER), '--listen', '127.0.0.1', '--port', '8443', '--hostname', fx.DOMAIN,
                                '--root', str(SITE), '--cert', str(site_cert), '--key', str(site_key), '--quiet'], (logs / 'website.log').open('w')))
            check('Personal Cloud website started on 127.0.0.1:8443', wait_port(8443))
            check('handshake target rendered as loopback website', config['inbounds'][0]['tls']['reality']['handshake'] == {'server': '127.0.0.1', 'server_port': 8443}, json.dumps(config['inbounds'][0]['tls']['reality']['handshake']))
            check('REALITY server_name and exported client SNI are the owner hostname', config['inbounds'][0]['tls']['server_name'] == fx.DOMAIN == profile['servername'])
        else:
            remote_cert, remote_key = LEAVES[fx.REMOTE_SNI]
            # Threaded lab TLS target: REALITY dials its handshake target for
            # every connection, so a single-threaded server would serialise them.
            procs.append(start([sys.executable, '-I', '-c', REMOTE_TARGET, str(remote_cert), str(remote_key)], (logs / 'remote-target.log').open('w')))
            check('lab remote handshake target started (127.0.0.3:443, lab hosts only)', wait_port(443, '127.0.0.3'))
            check('handshake target rendered as remote SNI:443 (unchanged behaviour)', config['inbounds'][0]['tls']['reality']['handshake'] == {'server': fx.REMOTE_SNI, 'server_port': 443})
            base = fx.render(state, helper=BASE_HELPER) if BASE_HELPER else None
            if base:
                same = all((rendered / n).read_bytes() == (base / n).read_bytes() for n in sorted(os.listdir(base)))
                check('remote-mode config and every exported profile byte-identical to base-commit renderer', same, ', '.join(sorted(os.listdir(base))))
        (logs / 'server.json').write_text(json.dumps(config, indent=1))
        r = subprocess.run([str(core), 'check', '-c', str(logs / 'server.json')], capture_output=True, text=True)
        check('pinned core accepts the rendered server config', r.returncode == 0, r.stderr.strip()[:200])
        procs.append(start([str(core), 'run', '-c', str(logs / 'server.json')], (logs / 'sing-box-server.log').open('w')))
        check('REALITY inbound listening on TCP %d (namespace loopback)' % RPORT, wait_port(RPORT))
        time.sleep(0.5)

        # (a) ordinary TLS / browser request to the public REALITY port.
        if mode == 'self-hosted':
            pages = {}
            for page in ('/', '/files/', '/media/', '/about/', '/library/documents/welcome.txt'):
                status, body, serial, cn = https_get(RPORT, fx.DOMAIN, page, CA)
                pages[page] = (status, len(body), MARKER in body or page.endswith('.txt'))
            serial_ok = serial.upper() == cert_serial(LEAVES[fx.DOMAIN][0]).upper()
            check('ordinary TLS to the REALITY port with owner SNI is verified against the lab CA and presents the owner-domain website certificate', serial_ok and cn == fx.DOMAIN, 'CN=%s serial=%s' % (cn, serial))
            check('all Personal Cloud pages served through REALITY (Home, Files, Media, About, a download)', all(v[0].endswith('200 OK') and v[2] for v in pages.values()), json.dumps(pages))
            status, body, _, _ = https_get(RPORT, fx.DOMAIN, '/../../etc/passwd', CA)
            check('traversal through the relay is refused', ' 404 ' in status + ' ' and b'root:' not in body, status)
        else:
            status, body, serial, cn = https_get(RPORT, fx.REMOTE_SNI, '/', CA)
            check('ordinary TLS to the REALITY port is relayed to the lab remote target (its own lab certificate)', cn == fx.REMOTE_SNI and serial.upper() == cert_serial(LEAVES[fx.REMOTE_SNI][0]).upper(), 'CN=%s' % cn)

        # (b) authenticated REALITY client from the exported profile.
        client = logs / 'client.json'
        client.write_text(json.dumps(client_config(profile, RPORT)))
        procs.append(start([str(core), 'run', '-c', str(client)], (logs / 'sing-box-client.log').open('w')))
        wait_port(1080)
        data = None
        for _ in range(20):
            data = socks_get(1080, 9000)
            if data and b'REALITY-TUNNEL-OK' in data:
                break
            time.sleep(0.3)
        check('authenticated REALITY client (exported profile, %s) proxies traffic' % profile['client-fingerprint'], bool(data) and b'REALITY-TUNNEL-OK /through-reality' in data, (data or b'')[-60:].decode('latin-1'))

        # (c) negative control: wrong REALITY public key.
        _, other_pub = fx.reality_keypair()
        bad = logs / 'client-wrong-key.json'
        bad.write_text(json.dumps(client_config(profile, RPORT, public_key=other_pub, socks=1081)))
        procs.append(start([str(core), 'run', '-c', str(bad)], (logs / 'sing-box-client-wrong-key.log').open('w')))
        wait_port(1081)
        data = None
        try:
            data = socks_get(1081, 9000)
        except OSError:
            data = None
        check('negative control: wrong REALITY key gets no tunnel', not data or b'REALITY-TUNNEL-OK' not in data)

        if mode == 'self-hosted':
            import importlib.util
            spec = importlib.util.spec_from_file_location('fallback_server', SERVER)
            mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            addrs = mod.listeners_on_port(8443)
            check('website listener is loopback-only (procfs)', addrs == ['127.0.0.1'], ','.join(addrs))
            r = subprocess.run(['python3', '-I', '-B', str(SERVER), '--listen', '0.0.0.0', '--port', '8444', '--hostname', fx.DOMAIN, '--cert', str(LEAVES[fx.DOMAIN][0]), '--key', str(LEAVES[fx.DOMAIN][1])], capture_output=True, text=True, timeout=10)
            check('website refuses a public bind (0.0.0.0)', r.returncode == 2 and 'refused' in r.stderr, r.stderr.strip())
            env = {**os.environ, 'SSL_CERT_FILE': str(CA)}
            r = subprocess.run(['python3', '-I', '-B', str(SERVER), '--check', '--compact', '--hostname', fx.DOMAIN, '--port', '8443', '--connect-port', str(RPORT), '--connect-host', '127.0.0.1'], capture_output=True, text=True, env=env, timeout=30)
            check('manager health check (relay path via the REALITY port) passes', r.returncode == 0, r.stdout.strip()[:300])
            if browser:
                spki = subprocess.run('openssl x509 -in %s -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64' % LEAVES[fx.DOMAIN][0], shell=True, capture_output=True, text=True).stdout.strip()
                r = subprocess.run(['node', str(Path(__file__).with_name('lab_reality_browser.cjs')), spki, str(out), str(RPORT)], capture_output=True, text=True, timeout=180)
                check('Chromium through the REALITY port renders every Personal Cloud page (SPKI-pinned lab cert, no certificate bypass)', r.returncode == 0, (r.stdout + r.stderr).strip()[-300:])
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, 15)
            except ProcessLookupError:
                pass
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, 9)
        target.shutdown(); target.server_close()


def inside(out, browser):
    global CA, LEAVES, BASE_HELPER
    bring_up_loopback()
    rows = []
    rows.append({'mode': 'namespace', 'check': 'only loopback interface present', 'status': 'PASS' if interfaces() == ['lo'] else 'FAIL', 'detail': ','.join(interfaces())})
    hosts = out / 'lab-hosts'
    hosts.write_text('127.0.0.1 localhost\n127.0.0.1 %s\n127.0.0.3 %s\n' % (fx.DOMAIN, fx.REMOTE_SNI))
    subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
    CA, LEAVES = fx.lab_certificates(out / 'lab-pki', (fx.DOMAIN, fx.REMOTE_SNI))
    BASE_HELPER = Path(os.environ['SBOX_BASE_STATE_HELPER']) if os.environ.get('SBOX_BASE_STATE_HELPER') else None
    for mode in ('remote', 'self-hosted'):
        run_mode(mode, out, rows, browser)
    report = {'lab': 'isolated network namespace, loopback only, lab CA', 'not_live_evidence': True, 'rows': rows,
              'passed': sum(r['status'] == 'PASS' for r in rows), 'failed': sum(r['status'] != 'PASS' for r in rows)}
    (out / 'reality-lab.json').write_text(json.dumps(report, indent=1))
    print(json.dumps({k: report[k] for k in ('passed', 'failed')}))
    return 0 if report['failed'] == 0 else 1


def main():
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('/tmp/sbox-reality-lab')
    out.mkdir(parents=True, exist_ok=True)
    browser = '--browser' in sys.argv
    if os.environ.get('SBOX_REALITY_LAB_NS') != '1':
        if os.geteuid() != 0:
            print('NOT RUN: root is required to create an isolated network namespace'); return 77
        env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
        env['SBOX_REALITY_LAB_NS'] = '1'
        return subprocess.run(['unshare', '-n', '-m', '--propagation', 'private', sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env=env).returncode
    return inside(out, browser)


if __name__ == '__main__':
    sys.exit(main())
