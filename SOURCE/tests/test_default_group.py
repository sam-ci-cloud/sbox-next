"""Client default policy group is an explicit, validated choice (D1, 1.8.0).

Fail-first: 1.7.1 hard-codes the VPN selector default to Anti-Block Auto (a priority
fallback, TUIC first). On routes where UDP is slow (measured 2026-11-05: VPS-B from HK,
TUIC ~242 ms vs REALITY ~166 ms) default clients pay the slower path although Smart Auto
would measure it. Owners must be able to choose, and changing it must not erase any other
advanced client setting.
"""
import copy, json, subprocess, sys, unittest
import yaml
import reality_fixture as fx
sys.path[:0] = [str(fx.ROOT / 'shared_webui/backend'), str(fx.ROOT / 'shared_webui/privileged-bridge')]
from export_json import convert

SMART, ANTI, VPN = '🧠 Smart Auto', '🛡 Anti-Block Auto', '🚀 VPN'


def vpn(doc):
    return next(g for g in doc['proxy-groups'] if g['name'] == VPN)


class DefaultGroup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private, public = fx.reality_keypair()
        s = fx.trusted_certificate(fx.base_state(private, public))
        for p in s['protocols'].values():
            p['enabled'] = True
        cls.base = s

    def render(self, **policy):
        s = copy.deepcopy(self.base)
        s['client_policy'].update(policy)
        out = fx.render(s)
        return out, {name: yaml.safe_load((out / f'mihomo-{name}.yaml').read_text()) for name in ('global', 'cn', 'internal')}

    def test_missing_key_preserves_1_7_1_default(self):
        _, docs = self.render()
        for doc in docs.values():
            self.assertEqual(vpn(doc)['default-selected'], ANTI)

    def test_smart_default_in_every_profile_and_json(self):
        _, docs = self.render(default_group='smart')
        for name, doc in docs.items():
            with self.subTest(profile=name):
                self.assertEqual(vpn(doc)['default-selected'], SMART)
                # all three policies are still offered; only the default changes
                self.assertEqual(vpn(doc)['proxies'], [ANTI, SMART, '🔒 LOCK'])
        self.assertEqual(next(o for o in convert(docs['global'])['outbounds'] if o['tag'] == VPN)['default'], SMART)

    def test_explicit_anti_block(self):
        _, docs = self.render(default_group='anti_block')
        self.assertEqual(vpn(docs['global'])['default-selected'], ANTI)

    def test_invalid_value_refused(self):
        s = copy.deepcopy(self.base)
        s['client_policy']['default_group'] = 'fastest'
        with self.assertRaises(Exception):
            fx.render(s)

    def test_summary_reports_default_group(self):
        out, _ = self.render(default_group='smart')
        summary = json.loads((out / 'summary.json').read_text())
        self.assertEqual(summary['client_policy']['default_group'], SMART)

    def test_changing_default_keeps_other_advanced_settings(self):
        advanced = dict(primary='reality', smart_tolerance_ms=45, smart_lazy=True, expected_status='200/204')
        _, before = self.render(**advanced)
        _, after = self.render(default_group='smart', **advanced)
        for name in before:
            b, a = before[name], after[name]
            gb = {g['name']: g for g in b['proxy-groups']}; ga = {g['name']: g for g in a['proxy-groups']}
            self.assertEqual(ga[SMART]['tolerance'], 45)
            self.assertIs(ga[SMART]['lazy'], True)
            self.assertEqual(str(ga[SMART]['expected-status']), '200/204')
            self.assertEqual(ga[ANTI]['proxies'], gb[ANTI]['proxies'])      # priority order (reality first) intact
            self.assertTrue(ga[ANTI]['proxies'][0].startswith('vless-reality'))
            self.assertEqual(a['dns'], b['dns']); self.assertEqual(a['rules'], b['rules']); self.assertEqual(a['proxies'], b['proxies'])
            # the ONLY difference is the VPN default
            gb[VPN] = dict(gb[VPN], **{'default-selected': SMART})
            self.assertEqual(ga, gb)

    def manager_bundle_check(self, out):
        """Run the manager's own validate_client_bundle() Python, extracted verbatim."""
        text = (fx.ROOT / 'src/manager.sh').read_text()
        start = text.index('validate_client_bundle() {')
        body = text[text.index("<<'PY'\n", start) + len("<<'PY'\n"):text.index('\nPY\n', start)]
        files = ['mihomo.yaml', 'clmi.yaml', 'mihomo-global.yaml', 'mihomo-cn.yaml', 'mihomo-internal.yaml',
                 'clmi-global.yaml', 'clmi-cn.yaml', 'clmi-internal.yaml', 'internal.yaml']
        return subprocess.run([sys.executable, '-c', body] + [str(out / f) for f in files], capture_output=True, text=True)

    def test_manager_bundle_validator_accepts_both_defaults(self):
        for choice in ('anti_block', 'smart'):
            with self.subTest(default_group=choice):
                out, _ = self.render(default_group=choice)
                r = self.manager_bundle_check(out)
                self.assertEqual(r.returncode, 0, r.stderr[-600:])

    def test_manager_bundle_validator_still_rejects_raw_node_default(self):
        out, docs = self.render(default_group='smart')
        for name in ('mihomo-global.yaml', 'clmi-global.yaml', 'mihomo.yaml', 'clmi.yaml'):
            doc = yaml.safe_load((out / name).read_text())
            vpn(doc)['default-selected'] = doc['proxies'][0]['name']   # a raw node is never a valid VPN default
            (out / name).write_text(yaml.safe_dump(doc, allow_unicode=True))
        self.assertNotEqual(self.manager_bundle_check(out).returncode, 0)

    def test_controller_accepts_and_validates_default_group(self):
        from controller import candidate
        state = copy.deepcopy(self.base)
        state['client_policy'].update(primary='hy2', smart_tolerance_ms=60, smart_lazy=True)
        for variant in ('universal', 'zgocloud'):
            with self.subTest(variant=variant):
                after = candidate(state, {'kind': 'policy', 'data': {'default_group': 'smart'}}, variant)
                self.assertEqual(after['client_policy']['default_group'], 'smart')
                # unrelated advanced settings survive a one-field UI save
                for k in ('primary', 'smart_tolerance_ms', 'smart_lazy'):
                    self.assertEqual(after['client_policy'][k], state['client_policy'][k])
                with self.assertRaises(Exception):
                    candidate(state, {'kind': 'policy', 'data': {'default_group': 'fastest'}}, variant)
                with self.assertRaises(Exception):
                    candidate(state, {'kind': 'policy', 'data': {'default_group': True}}, variant)


if __name__ == '__main__':
    unittest.main(verbosity=2)
