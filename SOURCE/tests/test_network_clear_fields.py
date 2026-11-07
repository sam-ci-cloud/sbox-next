"""Clearing a network exception must really remove it (UI-01).

Old behaviour: the Web UI dropped an empty "DNS override explanation" and an empty
"bind interface" from the request, and the backend merged only received keys, so a
previously saved override (which turns DNS preflight errors into warnings) and a
bind interface could never be revoked from the UI.

Contract: key omitted -> unchanged; explicit "" or null on a clearable field -> the
persisted key is removed; other values -> replaced.  The rendered server config must
reflect the removal (no bind_interface on any inbound).
"""
import copy, json, sys, unittest
import reality_fixture as fx
sys.path[:0] = [str(fx.ROOT / 'shared_webui/backend')]
import network_policy
from network_policy import patch_state
CLEARABLE = getattr(network_policy, 'CLEARABLE', ('endpoint_override', 'interface', 'fallback_delay_ms', 'udp_egress'))

FRONTEND = fx.ROOT / 'shared_webui/frontend-src/js/41-network.js'


class ClearNetworkFields(unittest.TestCase):
    def setUp(self):
        s = fx.trusted_certificate(fx.base_state())
        s['sing_box']['version'] = '1.14.4'
        s['server'].update(mode='dual', scope='internal', ipv4='192.0.2.10', ipv6='2001:db8::10', listen='::',
                           policies={'inbound': 'dual', 'egress': 'dual', 'dns': 'dual', 'client': 'dual'},
                           endpoint_override='planned DNS move to new provider', interface='lo',
                           fallback_delay_ms=300, udp_egress={'reject_quic': True})
        self.state = s

    def test_empty_string_removes_override_and_interface(self):
        after = patch_state(self.state, {'endpoint_override': '', 'interface': ''})
        self.assertNotIn('endpoint_override', after['server'])
        self.assertNotIn('interface', after['server'])

    def test_null_removes_clearable_fields(self):
        after = patch_state(self.state, {k: None for k in CLEARABLE})
        for key in CLEARABLE:
            self.assertNotIn(key, after['server'], key)

    def test_omitted_fields_are_unchanged(self):
        after = patch_state(self.state, {'scope': 'internal'})
        for key in ('endpoint_override', 'interface', 'fallback_delay_ms', 'udp_egress'):
            self.assertEqual(after['server'][key], self.state['server'][key])

    def test_replacement_still_works(self):
        after = patch_state(self.state, {'endpoint_override': 'another explanation text', 'interface': 'eth9'})
        self.assertEqual(after['server']['endpoint_override'], 'another explanation text')
        self.assertEqual(after['server']['interface'], 'eth9')

    def test_non_clearable_field_cannot_be_blanked_by_null(self):
        with self.assertRaises(ValueError):
            patch_state(self.state, {'ipv4': None})

    def test_rendered_config_drops_bind_interface_after_clear(self):
        s = copy.deepcopy(self.state)
        s['server'].pop('endpoint_override')
        s['server'].pop('fallback_delay_ms')
        before = json.loads((fx.render(s) / 'server.json').read_text())
        self.assertTrue(all(i.get('bind_interface') == 'lo' for i in before['inbounds']))
        after = patch_state(s, {'interface': ''})
        cfg = json.loads((fx.render(after) / 'server.json').read_text())
        self.assertFalse([i for i in cfg['inbounds'] if 'bind_interface' in i])

    def test_frontend_sends_explicit_empty_values(self):
        js = FRONTEND.read_text()
        submit = js[js.index('async function submitNetwork'):]
        submit = submit[:submit.index('\n}\n')]
        self.assertNotIn('delete d.endpoint_override', submit)
        self.assertNotIn("if(v.interface.trim())", submit)
        self.assertIn('d.interface=v.interface.trim()', submit)


if __name__ == '__main__':
    unittest.main(verbosity=2)
