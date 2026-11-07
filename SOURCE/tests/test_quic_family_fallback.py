"""Hysteria2/TUIC address-family fallback and the bootstrap address fallback in the generated sing-box
profiles, with the real pinned core.

sing-box binds a QUIC (UDP) socket to the first resolved address and never tries the other family
(common/dialer/resolve.go: ListenPacket -> N.ListenSerial; a UDP listen always succeeds). The exporter
therefore emits one candidate per family inside a URL-test group that keeps the node's tag.

Deterministic local lab: the server listens on ::1 only; a stub resolver answers A=127.0.0.1 and
AAAA=::1 for the server name; the node prefers IPv4, so the preferred family is dead. Certificate
verification stays on (lab CA, server_name = the domain). Not Internet evidence."""
import copy, http.server, json, shutil, socket, socketserver, struct, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path
import yaml
import reality_fixture as fx
sys.path.insert(0, str(fx.ROOT / 'shared_webui/backend'))
from export_json import convert, convert_full

HAVE_V6 = socket.has_ipv6
try:
    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).bind(('::1', 0))
except OSError:
    HAVE_V6 = False


def free_port(family=socket.AF_INET, kind=socket.SOCK_STREAM, host='127.0.0.1'):
    with socket.socket(family, kind) as s:
        s.bind((host, 0)); return s.getsockname()[1]


class StubDNS(socketserver.ThreadingUDPServer):
    """A=127.0.0.1, AAAA=::1 for every name (test resolver only)."""
    def __init__(self):
        super().__init__(('127.0.0.1', 0), self.Handler)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            qid, flags, qd = struct.unpack('!HHH', data[:6])
            i = 12
            while data[i]: i += data[i] + 1
            qtype = struct.unpack('!H', data[i + 1:i + 3])[0]
            question = data[12:i + 5]
            answers = b''
            if qtype == 1: answers = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('127.0.0.1')
            if qtype == 28: answers = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 30, 16) + socket.inet_pton(socket.AF_INET6, '::1')
            sock.sendto(struct.pack('!HHHHHH', qid, 0x8180, 1, 1 if answers else 0, 0, 0) + question + answers, self.client_address)


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'' if self.path == '/generate_204' else b'sbox-family-ok'
        self.send_response(204 if not body else 200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


@unittest.skipUnless(HAVE_V6, 'IPv6 loopback unavailable')
class QuicFamilyFallback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = Path(tempfile.mkdtemp(prefix='sbox-family-'))
        cert = cls.td / 'certs'; cls.ca, leaves = fx.lab_certificates(cert); (cert / 'live').mkdir()
        shutil.copy2(leaves[fx.DOMAIN][0], cert / 'live/fullchain.pem'); shutil.copy2(leaves[fx.DOMAIN][1], cert / 'live/privkey.pem')
        private, public = fx.reality_keypair(); state = fx.trusted_certificate(fx.base_state(private, public))
        cls.ports = {}
        for key, p in state['protocols'].items():
            p['enabled'] = key in ('hy2', 'tuic', 'anytls')
            if p['enabled']:
                kind = socket.SOCK_STREAM if key == 'anytls' else socket.SOCK_DGRAM
                p['port'] = cls.ports[key] = free_port(socket.AF_INET6, kind, '::1')
        out = fx.render(state, cert_dir=str(cert))
        server = json.loads((out / 'server.json').read_text())
        for inbound in server['inbounds']:
            inbound['listen'] = '::1'  # IPv4 is the dead family
        (cls.td / 'server.json').write_text(json.dumps(server))
        cls.doc = yaml.safe_load((out / 'mihomo-global.yaml').read_text())
        cls.dns = StubDNS(); threading.Thread(target=cls.dns.serve_forever, daemon=True).start()
        cls.web = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target); threading.Thread(target=cls.web.serve_forever, daemon=True).start()
        cls.server = subprocess.Popen([str(fx.core_binary()), 'run', '-c', str(cls.td / 'server.json')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cls.td)
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate(); cls.server.wait(5)
        cls.dns.shutdown(); cls.web.shutdown(); shutil.rmtree(cls.td, ignore_errors=True)

    def client(self, node, split, addresses=None, dns_dead=False):
        doc = copy.deepcopy(self.doc)
        for p in doc['proxies']:
            p['ip-version'] = 'ipv4-prefer'
        for g in doc['proxy-groups']:
            if g.get('url'): g['url'] = 'http://127.0.0.1:%d/generate_204' % self.web.server_address[1]
        cfg = convert_full(doc, 'global', addresses=addresses) if split else convert(doc, family_split=False)
        for o in cfg['outbounds']:
            if 'tls' in o: o['tls']['certificate_path'] = str(self.ca)
        port = free_port()
        cfg['inbounds'] = [{'type': 'mixed', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port}]
        dns_port = free_port(socket.AF_INET, socket.SOCK_DGRAM) if dns_dead else self.dns.server_address[1]  # nothing listens there
        cfg['dns'] = {'servers': [{'type': 'udp', 'tag': 'sbox-client-local', 'server': '127.0.0.1', 'server_port': dns_port}]}
        tag = next(p['name'] for p in doc['proxies'] if p['type'] == node)
        cfg['route'] = {'final': tag, 'default_domain_resolver': 'sbox-client-local'}
        path = self.td / ('client-%s-%s-%s-%s.json' % (node, split, bool(addresses), dns_dead)); path.write_text(json.dumps(cfg))
        check = subprocess.run([str(fx.core_binary()), 'check', '-c', str(path)], capture_output=True, text=True, cwd=self.td)
        self.assertEqual(check.returncode, 0, check.stderr)
        return cfg, path, port, tag

    def reach(self, path, port, seconds):
        # cwd: the complete profile enables sing-box's cache file (cache.db); keep it out of the tree
        proc = subprocess.Popen([str(fx.core_binary()), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=self.td)
        start = time.monotonic()
        try:
            time.sleep(0.5)
            while time.monotonic() - start < seconds:
                r = subprocess.run(['curl', '-sS', '--noproxy', '', '-x', 'http://127.0.0.1:%d' % port, '-m', '4',
                                    'http://127.0.0.1:%d/ok' % self.web.server_address[1]], capture_output=True, text=True)
                if r.stdout == 'sbox-family-ok':
                    return round(time.monotonic() - start, 1)
                time.sleep(0.5)
            return None
        finally:
            proc.terminate(); proc.wait(5)

    def test_candidates_keep_tag_sni_and_verification(self):
        full = convert_full(self.doc, 'global')
        for node in ('hysteria2', 'tuic'):
            tag = next(p['name'] for p in self.doc['proxies'] if p['type'] == node)
            group = next(o for o in full['outbounds'] if o['tag'] == tag)
            self.assertEqual(group['type'], 'urltest')
            members = [o for o in full['outbounds'] if o['tag'] in group['outbounds']]
            self.assertEqual([m['domain_resolver']['strategy'] for m in members], ['ipv4_only', 'ipv6_only'])
            for m in members:
                self.assertEqual(m['server'], fx.DOMAIN); self.assertEqual(m['tls']['server_name'], fx.DOMAIN); self.assertFalse(m['tls']['insecure'])
        smart = next(o for o in full['outbounds'] if o['type'] == 'urltest' and 'Smart' in o['tag'])
        self.assertTrue(all(any(o['tag'] == m for o in full['outbounds']) for m in smart['outbounds']), 'Smart Auto members resolve')

    def test_no_split_for_strict_family_or_literal_address(self):
        doc = copy.deepcopy(self.doc)
        for p in doc['proxies']: p['ip-version'] = 'ipv4'
        self.assertFalse(any('·' in o['tag'] for o in convert(doc)['outbounds']))
        doc = copy.deepcopy(self.doc)
        for p in doc['proxies']: p['server'] = '192.0.2.10'
        self.assertFalse(any('·' in o['tag'] for o in convert(doc)['outbounds']))

    def test_dead_preferred_family_recovers_through_the_other_family(self):
        results = {}
        for node in ('hysteria2', 'tuic'):
            _, before, port, _ = self.client(node, split=False)
            results[node + ':single'] = self.reach(before, port, 12)
            _, after, port, _ = self.client(node, split=True)
            results[node + ':family-group'] = self.reach(after, port, 30)
        print(json.dumps(results))
        for node in ('hysteria2', 'tuic'):
            self.assertIsNone(results[node + ':single'], 'single outbound stays on the dead IPv4 family (upstream behaviour)')
            self.assertIsNotNone(results[node + ':family-group'], node + ' recovers through IPv6')

    def test_address_candidates_keep_sni_and_verification(self):
        full = convert_full(self.doc, 'global', addresses={'ipv4': '192.0.2.10', 'ipv6': '2001:db8::10'})
        for node in ('hysteria2', 'anytls'):
            tag = next(p['name'] for p in self.doc['proxies'] if p['type'] == node)
            group = next(o for o in full['outbounds'] if o['tag'] == tag)
            literal = [o for o in full['outbounds'] if o['tag'] in group['outbounds'] and o['tag'].endswith('address')]
            self.assertEqual(sorted(o['server'] for o in literal), ['192.0.2.10', '2001:db8::10'])
            for o in literal:
                self.assertEqual(o['tls']['server_name'], fx.DOMAIN); self.assertFalse(o['tls']['insecure']); self.assertNotIn('domain_resolver', o)

    def test_failing_resolver_recovers_through_published_addresses(self):
        results = {}
        for node in ('hysteria2', 'anytls'):
            _, before, port, _ = self.client(node, split=True, dns_dead=True)
            results[node + ':name-only'] = self.reach(before, port, 12)
            _, after, port, _ = self.client(node, split=True, addresses={'ipv4': '127.0.0.1', 'ipv6': '::1'}, dns_dead=True)
            results[node + ':with-addresses'] = self.reach(after, port, 30)
        print(json.dumps(results))
        for node in ('hysteria2', 'anytls'):
            self.assertIsNone(results[node + ':name-only'], 'no resolver, no address: cannot connect')
            self.assertIsNotNone(results[node + ':with-addresses'], node + ' connects through its published address')


if __name__ == '__main__':
    unittest.main(verbosity=2)
