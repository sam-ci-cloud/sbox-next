"""Server "block private destinations" must hold for domain names too.

Old behaviour: the generated route was only `{"ip_is_private": true, "action": "reject"}`.
A domain destination is not resolved before rule matching, so the IP rule could not
match and the request fell through to `direct`; the direct outbound then resolved the
name and connected to e.g. 127.0.0.1.  `ip_is_private` also does not cover shared /
carrier-grade space 100.64.0.0/10 (used by some cloud metadata services).

These tests render the real server.json for every network mode and run the pinned
core with it.  Only the inbound (a local SOCKS port) and the DNS server definition
(a fixed `hosts` table instead of the system resolver) are substituted; every route
rule, outbound and resolver reference is exactly what the generator produced.
"""
import copy, json, re, socket, struct, subprocess, tempfile, threading, time, unittest
import http.server
from pathlib import Path
import reality_fixture as fx

LOOPBACK_MARK = b'PRIVATE-LISTENER-REACHED'

HOSTS = {
    'loop4.policy.test': ['127.0.0.1'],
    'loop6.policy.test': ['::1'],
    'mapped.policy.test': ['::ffff:127.0.0.1'],
    'rfc1918.policy.test': ['10.255.255.1'],
    'metadata.policy.test': ['169.254.169.254'],
    'cgnat.policy.test': ['100.100.100.200'],
    'ula.policy.test': ['fd00::1'],
    'linklocal6.policy.test': ['fe80::1'],
    'mixed-public-first.policy.test': ['192.0.2.10', '127.0.0.1'],
    'mixed-a-aaaa.policy.test': ['192.0.2.10', '::1'],
    'public.policy.test': ['192.0.2.10', '2001:db8::10'],
}
PRIVATE_DOMAINS = [d for d in HOSTS if not d.startswith('public')]
PRIVATE_LITERALS = ['127.0.0.1', '::1', '10.255.255.1', '169.254.169.254', '100.64.0.1',
                    '100.100.100.200', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '0.0.0.1', '198.18.0.1']

MODES = {
    'preserve': None,
    'ipv4': {'inbound': 'ipv4', 'egress': 'ipv4', 'dns': 'ipv4', 'client': 'ipv4'},
    'dual': {'inbound': 'dual', 'egress': 'dual', 'dns': 'dual', 'client': 'dual'},
    'ipv6': {'inbound': 'ipv6', 'egress': 'ipv6', 'dns': 'ipv6', 'client': 'ipv6'},
    'prefer_ipv6': {'inbound': 'dual', 'egress': 'prefer_ipv6', 'dns': 'dual', 'client': 'dual'},
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(LOOPBACK_MARK)

    def log_message(self, *args):
        pass


class _Server6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def state_for(mode, block_private=True, optimistic=False, udp_prefer_ipv6=False):
    s = fx.trusted_certificate(fx.base_state())
    s['sing_box']['version'] = '1.14.4'
    s['security']['block_private'] = block_private
    if MODES[mode] is not None:
        inbound = MODES[mode]['inbound']
        listen = {'ipv4': '0.0.0.0', 'ipv6': '2001:db8::10', 'dual': '::'}[inbound]
        s['server'].update(mode=inbound, scope='internal', ipv4='192.0.2.10', ipv6='2001:db8::10', listen=listen,
                           policies=copy.deepcopy(MODES[mode]))
    if optimistic:
        s['server_dns'] = {'optimistic': True}
    if udp_prefer_ipv6:
        s['server']['udp_egress'] = {'prefer_ipv6': True}
    return s


def render_server(state):
    out = fx.render(state)
    path = out / 'server.json'
    r = subprocess.run([str(fx.core_binary()), 'check', '-c', str(path)], capture_output=True, text=True)
    if r.returncode:
        raise AssertionError('generated server.json rejected by core: ' + r.stderr)
    return json.loads(path.read_text())


class Harness:
    """Run the generated policy in the pinned core behind a local SOCKS inbound."""

    def __init__(self, server_config, hosts=HOSTS, dial_hosts=None):
        self.port = _free_port()
        self.http_port = _free_port()
        self.servers = [http.server.ThreadingHTTPServer(('127.0.0.1', self.http_port), _Handler)]
        try:
            self.servers.append(_Server6(('::1', self.http_port), _Handler))
        except OSError:
            pass
        for srv in self.servers:
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cfg = copy.deepcopy(server_config)
        cfg['log'] = {'level': 'debug', 'timestamp': False}
        cfg['inbounds'] = [{'type': 'socks', 'tag': 'test-in', 'listen': '127.0.0.1', 'listen_port': self.port}]
        cfg.pop('experimental', None)
        servers = cfg.setdefault('dns', {}).setdefault('servers', [])
        tags = [srv['tag'] for srv in servers] or ['sbox-local']
        cfg['dns']['servers'] = [{'type': 'hosts', 'tag': tag, 'predefined': hosts} for tag in tags]
        # Configs without a DNS block resolve through the system resolver; stand in for it.
        cfg['route'].setdefault('default_domain_resolver', tags[0])
        if dial_hosts is not None:
            # Simulate a name whose answer changes between policy check and dial
            # (DNS rebinding): outbounds resolve through a different table.
            cfg['dns']['servers'].append({'type': 'hosts', 'tag': 'rebind', 'predefined': dial_hosts})
            for ob in cfg['outbounds']:
                ob['domain_resolver'] = {'server': 'rebind'}
            cfg['route']['default_domain_resolver'] = {'server': 'rebind'}
        for ob in cfg['outbounds']:
            ob['connect_timeout'] = '2s'
        self.dir = tempfile.TemporaryDirectory(prefix='sbox-private-policy-')
        path = Path(self.dir.name) / 'c.json'
        path.write_text(json.dumps(cfg))
        chk = subprocess.run([str(fx.core_binary()), 'check', '-c', str(path)], capture_output=True, text=True)
        if chk.returncode:
            raise AssertionError(chk.stderr)
        self.log = open(Path(self.dir.name) / 'core.log', 'w+')
        self.proc = subprocess.Popen([str(fx.core_binary()), 'run', '-c', str(path)], stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.2).close(); break
            except OSError:
                time.sleep(0.05)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for srv in self.servers:
            srv.shutdown()
        self.log.close(); self.dir.cleanup()

    def request(self, host, port=None):
        """Return (dialed_by_core, reached_private_listener)."""
        port = port or self.http_port
        self.log.flush(); start = self.log.tell()
        s = socket.create_connection(('127.0.0.1', self.port), 5); s.settimeout(6)
        s.sendall(b'\x05\x01\x00'); s.recv(2)
        for family, atyp in ((socket.AF_INET, b'\x01'), (socket.AF_INET6, b'\x04')):
            try:
                addr = atyp + socket.inet_pton(family, host); break
            except OSError:
                continue
        else:
            addr = b'\x03' + bytes([len(host)]) + host.encode()
        s.sendall(b'\x05\x01\x00' + addr + struct.pack('!H', port))
        reached = False
        try:
            reply = s.recv(262)
            if len(reply) > 1 and reply[1] == 0:
                s.sendall(b'GET / HTTP/1.0\r\nHost: x\r\n\r\n')
                body = b''
                while LOOPBACK_MARK not in body:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                reached = LOOPBACK_MARK in body
        except OSError:
            pass
        s.close()
        dial_line = re.compile(r'outbound/direct\[[^\]]+\]: outbound (?:packet )?connection to')
        deadline = time.monotonic() + (0.3 if not reached else 2.0)
        while True:
            self.log.flush(); self.log.seek(start); segment = self.log.read(); self.log.seek(0, 2)
            dialed = bool(dial_line.search(segment))
            if dialed or time.monotonic() > deadline:
                return dialed, reached
            time.sleep(0.05)


class GeneratedRuleShape(unittest.TestCase):
    def test_resolve_precedes_every_ip_rule_in_all_modes(self):
        for mode in MODES:
            for optimistic in (False, True):
                with self.subTest(mode=mode, optimistic=optimistic):
                    rules = render_server(state_for(mode, optimistic=optimistic))['route']['rules']
                    self.assertEqual(rules[0]['action'], 'resolve', rules)
                    self.assertTrue(rules[0].get('disable_optimistic_cache'), rules[0])
                    first_ip_rule = min(i for i, r in enumerate(rules) if 'ip_is_private' in r or 'ip_cidr' in r or 'ip_version' in r)
                    self.assertGreater(first_ip_rule, 0)
                    private = [r for r in rules if r.get('ip_is_private')]
                    self.assertEqual(private, [{'ip_is_private': True, 'action': 'reject'}])
                    cidrs = [c for r in rules if r.get('action') == 'reject' for c in r.get('ip_cidr', [])]
                    self.assertIn('100.64.0.0/10', cidrs)

    def test_family_strategy_is_applied_to_security_resolve(self):
        expected = {'ipv4': 'ipv4_only', 'ipv6': 'ipv6_only'}
        for mode, strategy in expected.items():
            with self.subTest(mode=mode):
                rules = render_server(state_for(mode))['route']['rules']
                self.assertEqual(rules[0].get('strategy'), strategy)

    def test_disabled_policy_adds_no_resolve_or_reject(self):
        rules = render_server(state_for('preserve', block_private=False))['route']['rules']
        self.assertFalse([r for r in rules if r.get('action') in ('resolve',) or 'ip_is_private' in r or 'ip_cidr' in r])


class RealCorePrivateDestinations(unittest.TestCase):
    def run_matrix(self, mode, **kw):
        h = Harness(render_server(state_for(mode, **kw)))
        try:
            for host in PRIVATE_DOMAINS + PRIVATE_LITERALS:
                with self.subTest(mode=mode, destination=host, **kw):
                    dialed, reached = h.request(host)
                    self.assertFalse(reached, 'private listener reached through ' + host)
                    if mode == 'ipv4' and host == 'mixed-a-aaaa.policy.test':
                        # IPv4-only egress resolves A records only: the private AAAA (::1)
                        # is never a candidate, the public A may be dialled.
                        continue
                    self.assertFalse(dialed, 'core dialled private destination ' + host)
            if mode != 'ipv6':
                with self.subTest(mode=mode, destination='public.policy.test'):
                    dialed, _ = h.request('public.policy.test', 80)
                    self.assertTrue(dialed, 'public destination must still be dialled')
        finally:
            h.close()

    def test_preserve(self):
        self.run_matrix('preserve')

    def test_ipv4(self):
        self.run_matrix('ipv4')

    def test_dual(self):
        self.run_matrix('dual')

    def test_ipv6(self):
        self.run_matrix('ipv6')

    def test_prefer_ipv6_with_optimistic_cache_and_udp6(self):
        self.run_matrix('prefer_ipv6', optimistic=True, udp_prefer_ipv6=True)

    def test_answer_change_between_check_and_dial_cannot_reach_private(self):
        # Policy resolution says "public", the outbound's own resolver would say loopback.
        hosts = dict(HOSTS, **{'rebind.policy.test': ['192.0.2.10']})
        dial = {'rebind.policy.test': ['127.0.0.1']}
        h = Harness(render_server(state_for('dual')), hosts=hosts, dial_hosts=dial)
        try:
            dialed, reached = h.request('rebind.policy.test')
            self.assertFalse(reached, 'rebinding reached the private listener')
        finally:
            h.close()

    def test_unresolvable_name_is_not_dialled(self):
        h = Harness(render_server(state_for('dual')))
        try:
            dialed, reached = h.request('nxdomain.policy.test')
            self.assertFalse(dialed or reached)
        finally:
            h.close()

    def test_disabled_policy_keeps_private_access(self):
        h = Harness(render_server(state_for('preserve', block_private=False)))
        try:
            dialed, reached = h.request('loop4.policy.test')
            self.assertTrue(dialed and reached, 'block_private=false must keep owner-allowed private access')
        finally:
            h.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
