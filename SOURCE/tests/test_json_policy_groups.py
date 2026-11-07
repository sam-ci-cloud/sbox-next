"""sing-box JSON must carry the same client policy semantics as the Mihomo YAML (D2, 1.8.0).

Fail-first: 1.7.1 exported only raw outbounds and routed everything to the first one,
so sing-box users silently had no Smart Auto, no LOCK selector and no failover.
"""
import copy, json, subprocess, sys, tempfile, unittest
from pathlib import Path
import yaml
import reality_fixture as fx
sys.path[:0] = [str(fx.ROOT / 'shared_webui/backend')]
import export_json
from export_json import convert
UNSUPPORTED_GROUP_NOTE = getattr(export_json, 'UNSUPPORTED_GROUP_NOTE', '')

SMART, ANTI, LOCK, VPN = '🧠 Smart Auto', '🛡 Anti-Block Auto', '🔒 LOCK', '🚀 VPN'


class JsonPolicyGroups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private, public = fx.reality_keypair()
        s = fx.trusted_certificate(fx.base_state(private, public))
        s['sing_box']['version'] = '1.14.4'
        for p in s['protocols'].values():
            p['enabled'] = True
        s['client_policy']['smart_tolerance_ms'] = 75
        cls.state = s
        cls.doc = yaml.safe_load((fx.render(s) / 'mihomo-global.yaml').read_text())
        cls.out = convert(cls.doc)

    def group(self, tag):
        for o in self.out['outbounds']:
            if o['tag'] == tag:
                return o
        self.fail('missing outbound %r' % tag)

    def test_smart_auto_is_native_urltest_with_same_parameters(self):
        y = next(g for g in self.doc['proxy-groups'] if g['name'] == SMART)
        j = self.group(SMART)
        self.assertEqual(j['type'], 'urltest')
        self.assertEqual(j['outbounds'], y['proxies'])          # same members, same order
        self.assertEqual(j['url'], y['url'])
        self.assertEqual(j['interval'], '%ds' % y['interval'])
        self.assertEqual(j['tolerance'], 75)                    # flows from state, not hard-coded
        self.assertEqual(j['tolerance'], y['tolerance'])

    def test_lock_is_selector_with_same_default(self):
        y = next(g for g in self.doc['proxy-groups'] if g['name'] == LOCK)
        j = self.group(LOCK)
        self.assertEqual(j['type'], 'selector')
        self.assertEqual(j['outbounds'], y['proxies'])
        self.assertEqual(j['default'], y['default-selected'])

    def test_vpn_selector_is_route_final_and_anti_block_mapped_honestly(self):
        j = self.group(VPN)
        self.assertEqual(self.out['route']['final'], VPN)
        self.assertEqual(j['type'], 'selector')
        # sing-box has no first-alive "fallback" group: Anti-Block cannot be emitted.
        self.assertNotIn(ANTI, [o['tag'] for o in self.out['outbounds']])
        self.assertNotIn(ANTI, j['outbounds'])
        self.assertEqual(j['outbounds'], [SMART, LOCK])
        # YAML default is Anti-Block; the honest sing-box substitute is Smart Auto.
        self.assertEqual(j['default'], SMART)
        self.assertIn('fallback', UNSUPPORTED_GROUP_NOTE)

    def test_every_member_resolves_to_an_outbound(self):
        tags = {o['tag'] for o in self.out['outbounds']}
        for o in self.out['outbounds']:
            for member in o.get('outbounds', []):
                self.assertIn(member, tags)
        self.assertIn(self.out['route']['final'], tags)

    def test_real_core_accepts_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'client.json'
            p.write_text(json.dumps(self.out, ensure_ascii=False))
            r = subprocess.run([str(fx.core_binary()), 'check', '-c', str(p)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_document_without_groups_still_converts(self):
        # Older inputs (no proxy-groups) keep the 1.7.1 behaviour rather than failing.
        bare = {'proxies': copy.deepcopy(self.doc['proxies'])}
        out = convert(bare)
        self.assertEqual(out['route']['final'], out['outbounds'][0]['tag'])

    def test_unknown_group_type_is_refused_not_dropped(self):
        doc = copy.deepcopy(self.doc)
        # load-balance/fallback are known Mihomo types without an equivalent: omitted (test_export_unmappable_groups.py)
        doc['proxy-groups'].append({'name': 'weird', 'type': 'relay', 'proxies': [doc['proxies'][0]['name']]})
        with self.assertRaises(ValueError):
            convert(doc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
