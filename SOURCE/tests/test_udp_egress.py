"""Opt-in UDP egress controls for providers that filter UDP (D7, 1.8.0).

Evidence (2026-11-05, VPS-A, BitsFlowCloud): inbound IPv4 UDP whose *source* port is
< 10000 is dropped upstream of the VM (tcpdump: replies leave the peer, never reach eth0).
QUIC/HTTP3 replies (source 443) therefore never arrive over IPv4; IPv6 is unaffected.
1.7.1 has no way to steer proxied UDP to IPv6 or to make QUIC fail fast so clients use TCP.
"""
import copy, json, subprocess, sys, unittest
import reality_fixture as fx
sys.path[:0] = [str(fx.ROOT / 'shared_webui/backend')]
from network_policy import patch_state


class UdpEgress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private, public = fx.reality_keypair()
        s = fx.trusted_certificate(fx.base_state(private, public))
        s['sing_box']['version'] = '1.14.4'
        s['server'].update(mode='dual', scope='internal', ipv4='192.0.2.10', ipv6='2001:db8::10', listen='::',
                           policies={'inbound': 'dual', 'egress': 'dual', 'dns': 'dual', 'client': 'dual'})
        cls.base = s

    def render(self, mutate=None):
        s = copy.deepcopy(self.base)
        if mutate:
            mutate(s)
        out = fx.render(s)
        cfg = json.loads((out / 'server.json').read_text())
        r = subprocess.run([str(fx.core_binary()), 'check', '-c', str(out / 'server.json')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return cfg

    def test_absent_is_unchanged(self):
        cfg = self.render()
        self.assertEqual([o['tag'] for o in cfg['outbounds']], ['direct'])
        self.assertFalse([r for r in cfg['route']['rules'] if r.get('network') == ['udp']])

    def test_prefer_ipv6_routes_udp_to_v6_preferring_outbound(self):
        cfg = self.render(lambda s: s['server'].update(udp_egress={'prefer_ipv6': True}))
        udp6 = next(o for o in cfg['outbounds'] if o['tag'] == 'direct-udp6')
        self.assertEqual(udp6['type'], 'direct')
        self.assertEqual(udp6['domain_resolver']['strategy'], 'prefer_ipv6')
        rule = next(r for r in cfg['route']['rules'] if r.get('outbound') == 'direct-udp6')
        self.assertEqual(rule['network'], ['udp'])
        self.assertEqual(cfg['route']['final'], 'direct')            # TCP untouched

    def test_reject_quic_precedes_udp6_and_security_rules_stay_first(self):
        def m(s):
            s['server']['udp_egress'] = {'prefer_ipv6': True, 'reject_quic': True}
            s['security']['block_private'] = True
        rules = self.render(m)['route']['rules']
        # Security resolve first, then the private-destination reject (SEC-01).
        self.assertEqual(rules[0]['action'], 'resolve')
        self.assertEqual(rules[1], {'ip_is_private': True, 'action': 'reject'})
        p = next(i for i, r in enumerate(rules) if r.get('ip_cidr') and r.get('action') == 'reject')
        q = next(i for i, r in enumerate(rules) if r.get('port') == [443] and r.get('action') == 'reject')
        u = next(i for i, r in enumerate(rules) if r.get('outbound') == 'direct-udp6')
        self.assertEqual(rules[q]['network'], ['udp'])
        self.assertLess(p, q)
        self.assertLess(q, u)

    def test_invalid_refused(self):
        bad = [{'prefer_ipv6': 'yes'}, {'reject_quic': 1}, {'unknown': True}, [],
               ]
        for b in bad:
            with self.subTest(b=b), self.assertRaises(Exception):
                s = copy.deepcopy(self.base); s['server']['udp_egress'] = b; fx.render(s)
        s = copy.deepcopy(self.base)
        s['server']['policies'] = {'inbound': 'dual', 'egress': 'ipv4', 'dns': 'ipv4', 'client': 'dual'}
        s['server']['udp_egress'] = {'prefer_ipv6': True}
        with self.assertRaises(Exception):
            fx.render(s)                                              # cannot prefer IPv6 when egress is IPv4-only

    def test_webui_network_patch_accepts_and_preserves(self):
        after = patch_state(self.base, {'udp_egress': {'reject_quic': True}})
        self.assertEqual(after['server']['udp_egress'], {'reject_quic': True})
        for k in ('policies', 'ipv4', 'ipv6', 'listen', 'mode'):
            self.assertEqual(after['server'][k], self.base['server'][k])


if __name__ == '__main__':
    unittest.main(verbosity=2)
