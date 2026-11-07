"""Custom client rules vs "local network goes direct" must be an explicit, tested choice.

Old behaviour: GLOBAL/CN profiles always put custom rules BEFORE the built-in LAN
DIRECT rules, so a broad custom VPN/REJECT rule silently captured local-network
traffic (printers, routers, NAS) with no setting to prevent it.

Contract: `client_policy.rule_precedence`:
  lan_first    -> LAN DIRECT rules first, then custom rules (new installs)
  custom_first -> custom rules may override LAN (legacy; also used when absent so
                  existing installs render byte-for-byte as before)
INTERNAL keeps no LAN bypass and no custom rules in both modes.
"""
import copy, sys, unittest
import yaml
import reality_fixture as fx

LAN = ['DOMAIN-SUFFIX,lan,DIRECT', 'DOMAIN-SUFFIX,local,DIRECT', 'GEOIP,LAN,DIRECT,no-resolve']
CUSTOM = ['IP-CIDR,0.0.0.0/1,🚀 VPN', 'DOMAIN-SUFFIX,example.com,DIRECT']


def rules(state, profile):
    return yaml.safe_load((fx.render(state) / ('mihomo-%s.yaml' % profile)).read_text())['rules']


class RulePrecedence(unittest.TestCase):
    def state(self, precedence=None):
        s = fx.trusted_certificate(fx.base_state())
        s['client_policy'] = {'primary': 'reality', 'rules': list(CUSTOM)}
        if precedence:
            s['client_policy']['rule_precedence'] = precedence
        return s

    def test_lan_first_puts_lan_rules_before_custom(self):
        for profile in ('global', 'cn'):
            with self.subTest(profile=profile):
                r = rules(self.state('lan_first'), profile)
                self.assertEqual(r[:3], LAN)
                self.assertEqual(r[3:5], CUSTOM)
                self.assertTrue(r[-1].startswith('MATCH,'))

    def test_custom_first_keeps_override(self):
        r = rules(self.state('custom_first'), 'global')
        self.assertEqual(r[:2], CUSTOM)
        self.assertEqual(r[2:5], LAN)

    def test_absent_field_is_legacy_byte_identical(self):
        base = self.state()
        with_field = copy.deepcopy(base); with_field['client_policy']['rule_precedence'] = 'custom_first'
        legacy = (fx.render(base) / 'mihomo-global.yaml').read_text()
        explicit = (fx.render(with_field) / 'mihomo-global.yaml').read_text()
        self.assertEqual(legacy, explicit)

    def test_internal_unchanged_in_both_modes(self):
        for p in ('lan_first', 'custom_first'):
            with self.subTest(precedence=p):
                r = rules(self.state(p), 'internal')
                self.assertFalse([x for x in r if x in LAN or x in CUSTOM])

    def test_invalid_value_refused(self):
        s = self.state('sometimes')
        self.assertNotEqual(fx.state_tool('validate', s).returncode, 0)

    def test_new_install_default_is_lan_first(self):
        manager = (fx.ROOT / 'src/manager.sh').read_text()
        self.assertIn('''old_client_policy='{"primary":"tuic","rule_precedence":"lan_first"}\'''', manager)

    def test_webui_controller_accepts_and_validates(self):
        sys.path[:0] = [str(fx.ROOT / 'shared_webui/privileged-bridge')]
        src = (fx.ROOT / 'shared_webui/privileged-bridge/controller.py').read_text()
        self.assertIn("'rule_precedence'", src)
        js = (fx.ROOT / 'shared_webui/frontend-src/js/40-policy.js').read_text()
        self.assertIn("select('rule_precedence'", js)
        ev = (fx.ROOT / 'shared_webui/frontend-src/js/90-events.js').read_text()
        self.assertIn('rule_precedence: d.rule_precedence', ev)


if __name__ == '__main__':
    unittest.main(verbosity=2)
