"""Full sing-box profile (Export Center 'singbox' format): rendered from the real generated
Mihomo profiles, validated by the real core, and the basic SOCKS bundle stays unchanged."""
import copy, json, subprocess, sys, tempfile, unittest
from pathlib import Path
import yaml
import reality_fixture as fx
sys.path.insert(0, str(fx.ROOT / 'shared_webui/backend'))
from export_json import convert, convert_full


class FullProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private, public = fx.reality_keypair()
        state = fx.trusted_certificate(fx.base_state(private, public))
        for p in state['protocols'].values():
            p['enabled'] = True
        state['protocols']['vmess']['multiplex'] = True
        cls.out = fx.render(state)

    def doc(self, profile):
        return yaml.safe_load((self.out / f'mihomo-{profile}.yaml').read_text())

    def check(self, config):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'client.json'; path.write_text(json.dumps(config))
            r = subprocess.run([str(fx.core_binary()), 'check', '-c', str(path)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_profile_is_accepted_by_the_core(self):
        for profile in ('global', 'internal'):
            with self.subTest(profile=profile):
                self.check(convert_full(self.doc(profile), profile))

    def test_structure_tun_mixed_dns_and_groups(self):
        full = convert_full(self.doc('global'), 'global')
        self.assertEqual([i['type'] for i in full['inbounds']], ['tun', 'mixed'])
        tun = full['inbounds'][0]
        self.assertTrue(tun['auto_route'] and tun['strict_route']); self.assertNotIn('stack', tun, 'stack is deprecated from sing-box 1.15')
        self.assertTrue(full['route']['auto_detect_interface'])
        tags = {o['tag'] for o in full['outbounds']}
        self.assertEqual(full['route']['final'], full['dns']['servers'][0]['detour']); self.assertIn(full['route']['final'], tags)
        self.assertIn({'protocol': 'dns', 'action': 'hijack-dns'}, full['route']['rules'])
        self.assertIn({'ip_is_private': True, 'outbound': 'direct'}, full['route']['rules'])
        self.assertTrue(any(o['type'] == 'urltest' for o in full['outbounds']), 'Smart Auto')
        self.assertFalse(any(o['type'] == 'fallback' for o in full['outbounds']), 'no fake Mihomo fallback group')
        vm = next(o for o in full['outbounds'] if o['type'] == 'vmess')
        self.assertEqual(vm['multiplex']['max_connections'], 1, 'VMess pool mapping preserved')

    def test_profile_semantics(self):
        internal = convert_full(self.doc('internal'), 'internal')
        self.assertNotIn({'ip_is_private': True, 'outbound': 'direct'}, internal['route']['rules'], 'everything through the VPN')
        self.assertNotIn('rule_set', internal['route'])
        for profile in ('global', 'cn', 'internal'):
            text = json.dumps(convert_full(self.doc(profile), profile))
            self.assertNotIn('githubusercontent', text); self.assertNotIn('"remote"', text, 'no rule data download')

    def test_cn_profile_uses_offline_rule_sets_and_cn_resolver(self):
        cn = convert_full(self.doc('cn'), 'cn'); self.check(cn)
        sets = {r['tag']: r for r in cn['route']['rule_set']}
        self.assertEqual(set(sets), {'sbox-cn-domain', 'sbox-cn-ip'}); self.assertTrue(all(r['type'] == 'inline' for r in sets.values()))
        self.assertGreater(len(sets['sbox-cn-ip']['rules'][0]['ip_cidr']), 1000); self.assertIn('cn', sets['sbox-cn-domain']['rules'][0]['domain_suffix'])
        rules = cn['route']['rules']
        self.assertLess(rules.index({'ip_is_private': True, 'outbound': 'direct'}), rules.index({'rule_set': ['sbox-cn-domain'], 'outbound': 'direct'}))
        self.assertLess(rules.index({'rule_set': ['sbox-cn-domain'], 'outbound': 'direct'}), rules.index({'rule_set': ['sbox-cn-ip'], 'outbound': 'direct'}))
        servers = {x['tag']: x for x in cn['dns']['servers']}
        self.assertNotIn('detour', servers['dns-cn'], 'CN names resolved directly, as Mihomo nameserver-policy geosite:cn')
        self.assertIn({'rule_set': ['sbox-cn-domain'], 'server': 'dns-cn'}, cn['dns']['rules'])
        self.assertEqual(cn['route']['final'], convert_full(self.doc('global'), 'global')['route']['final'], 'unmatched traffic still uses the VPN, never GLOBAL substitution')
        doc = self.doc('cn'); doc['rules'].insert(0, 'GEOSITE,GOOGLE,DIRECT')
        with self.assertRaises(ValueError):
            convert_full(doc, 'cn')

    def test_remote_dns_through_vpn_bootstrap_from_device(self):
        for profile in ('global', 'internal'):
            full = convert_full(self.doc(profile), profile); servers = {x['tag']: x for x in full['dns']['servers']}
            self.assertEqual(servers['sbox-client-local'], {'type': 'local', 'tag': 'sbox-client-local'})
            self.assertEqual(servers['dns-remote']['detour'], full['route']['final'], 'remote DNS goes through the VPN')
            import ipaddress; ipaddress.ip_address(servers['dns-remote']['server'])
        doc = self.doc('global'); doc['dns']['nameserver'] = ['https://dns.example.test/dns-query']
        self.assertEqual(next(x for x in convert_full(doc, 'global')['dns']['servers'] if x['tag'] == 'dns-remote')['domain_resolver'], 'sbox-client-local')

    def test_basic_socks_bundle_is_unchanged(self):
        doc = self.doc('global'); basic = convert(copy.deepcopy(doc))
        self.assertEqual(basic['inbounds'], [{'type': 'socks', 'tag': 'socks-in', 'listen': '127.0.0.1', 'listen_port': 1080}])
        self.assertNotIn('route', {k: v for k, v in basic.items() if k == 'route' and 'rules' in v})
        self.check(basic)

    def test_custom_rules_follow_the_mihomo_profile_in_order(self):
        private, public = fx.reality_keypair()
        state = fx.trusted_certificate(fx.base_state(private, public))
        state['client_policy'] = {'primary': 'tuic', 'rule_precedence': 'lan_first',
                                  'rules': ['DOMAIN-SUFFIX,example.org,DIRECT', 'DOMAIN-KEYWORD,tracker,REJECT', 'IP-CIDR,203.0.113.0/24,🚀 VPN,no-resolve']}
        out = fx.render(state)
        doc = yaml.safe_load((out / 'mihomo-global.yaml').read_text())
        full = convert_full(doc, 'global'); rules = full['route']['rules'][2:]
        self.assertEqual(rules[0], {'domain_suffix': ['lan'], 'outbound': 'direct'}, 'local network first (lan_first)')
        self.assertIn({'ip_is_private': True, 'outbound': 'direct'}, rules[:3])
        self.assertEqual(rules[3:], [{'domain_suffix': ['example.org'], 'outbound': 'direct'}, {'domain_keyword': ['tracker'], 'action': 'reject'},
                                     {'ip_cidr': ['203.0.113.0/24'], 'outbound': full['route']['final']}])
        self.check(full)
        internal = convert_full(yaml.safe_load((out / 'mihomo-internal.yaml').read_text()), 'internal')
        self.assertEqual(internal['route']['rules'], [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'}], 'internal: no bypass, no custom rules (same as Mihomo)')
        doc['rules'].insert(0, 'GEOSITE,GOOGLE,DIRECT')
        with self.assertRaises(ValueError):
            convert_full(doc, 'global')

    def test_unknown_profile_refused(self):
        with self.assertRaises(ValueError):
            convert_full(self.doc('global'), 'everything')


if __name__ == '__main__':
    unittest.main(verbosity=2)
