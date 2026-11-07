"""A selected listener interface must be valid for every family it serves.

Old behaviour: with `server.interface` set, every VPN inbound gets `bind_interface`,
but the endpoint preflight only checked that the IPv6 address sits on that interface.
IPv4 was never checked, so an IPv4 (or dual) node could be bound to an interface that
cannot carry its IPv4 traffic, or to an interface that does not exist, and preflight
still said PASS.  Multi-NIC hosts with IPv4 and IPv6 on different NICs were affected.
"""
import ast, ipaddress, re, unittest
import reality_fixture as fx

V4 = '8.8.8.8'
V6 = '2606:4700:4700::1111'


def assess(server, records, assigned):
    tree = ast.parse((fx.ROOT / 'src/state.py').read_text())
    names = {'fail', 'require', 'assess_endpoints'}
    module = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
    env = {'ipaddress': ipaddress, 're': re}
    exec(compile(module, 'state.py', 'exec'), env)
    return env['assess_endpoints']('example.com', server, records, list(assigned))


class InterfacePreflight(unittest.TestCase):
    def test_ipv4_on_other_interface_fails(self):
        r = assess({'mode': 'ipv4', 'ipv4': V4, 'interface': 'eth1'}, {'ipv4': [V4]},
                   [{'interface': 'eth0', 'address': V4}, {'interface': 'eth1', 'address': '2001:db8::5'}])
        self.assertEqual(r['status'], 'FAIL', r)
        self.assertTrue(any('IPv4' in e and 'interface' in e for e in r['errors']), r['errors'])

    def test_ipv4_on_selected_interface_passes(self):
        r = assess({'mode': 'ipv4', 'ipv4': V4, 'interface': 'eth1'}, {'ipv4': [V4]},
                   [{'interface': 'eth1', 'address': V4}])
        self.assertEqual(r['status'], 'PASS', r)

    def test_nat_ipv4_needs_some_ipv4_on_selected_interface(self):
        ok = assess({'mode': 'ipv4', 'ipv4': V4, 'interface': 'eth1'}, {'ipv4': [V4]},
                    [{'interface': 'eth1', 'address': '10.0.0.5'}])
        self.assertEqual(ok['status'], 'PASS', ok)
        self.assertTrue(any('NAT' in w for w in ok['warnings']))
        bad = assess({'mode': 'ipv4', 'ipv4': V4, 'interface': 'eth1'}, {'ipv4': [V4]},
                     [{'interface': 'eth0', 'address': '10.0.0.5'}, {'interface': 'eth1', 'address': '2001:db8::5'}])
        self.assertEqual(bad['status'], 'FAIL', bad)

    def test_unknown_interface_fails(self):
        r = assess({'mode': 'ipv4', 'ipv4': V4, 'interface': 'nope0'}, {'ipv4': [V4]},
                   [{'interface': 'eth0', 'address': V4}])
        self.assertEqual(r['status'], 'FAIL', r)

    def test_dual_split_nics_cannot_share_one_bind_interface(self):
        server = {'mode': 'dual', 'ipv4': V4, 'ipv6': V6, 'interface': 'eth1'}
        records = {'ipv4': [V4], 'ipv6': [V6]}
        r = assess(server, records, [{'interface': 'eth0', 'address': V4}, {'interface': 'eth1', 'address': V6}])
        self.assertEqual(r['status'], 'FAIL', r)
        same = assess(server, records, [{'interface': 'eth1', 'address': V4}, {'interface': 'eth1', 'address': V6}])
        self.assertEqual(same['status'], 'PASS', same)

    def test_no_interface_keeps_previous_behaviour(self):
        r = assess({'mode': 'dual', 'ipv4': V4, 'ipv6': V6}, {'ipv4': [V4], 'ipv6': [V6]},
                   [{'interface': 'eth0', 'address': V4}, {'interface': 'eth1', 'address': V6}])
        self.assertEqual(r['status'], 'PASS', r)


if __name__ == '__main__':
    unittest.main(verbosity=2)
