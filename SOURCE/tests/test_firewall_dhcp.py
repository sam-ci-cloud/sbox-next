"""Default-drop must not break address renewal (DHCPv4 / DHCPv6) or IPv6 autoconfiguration.

Old behaviour: the generated input chain accepted only established/related traffic,
ICMP/ICMPv6 essentials and service ports.  DHCPv6 requests go to the multicast group
ff02::1:2, so conntrack cannot pair the server's link-local unicast reply (UDP 547 ->
546) and default-drop discarded it; DHCPv4 replies from a relay or a different server
address (UDP 67 -> 68) were likewise dropped.  Lease renewal could then fail later
and take the host offline.  Hosts using SLAAC/static addressing are unaffected.
"""
import importlib.util, pathlib, re, unittest
import test_hardening_generator as base

hard = base.hard


class FirewallDhcp(unittest.TestCase):
    def ruleset(self):
        return hard.render(base.T.c(base.T()))

    def test_dhcpv6_reply_from_link_local_server_is_accepted(self):
        rules = self.ruleset()
        self.assertRegex(rules, r'ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept')

    def test_dhcpv4_reply_is_accepted(self):
        self.assertRegex(self.ruleset(), r'udp sport 67 udp dport 68 accept')

    def test_dhcp_rules_precede_default_drop_and_follow_invalid_drop(self):
        rules = self.ruleset()
        invalid = rules.index('ct state invalid counter drop')
        drop = rules.index('counter comment "default-drop"')
        for needle in ('udp sport 547 udp dport 546 accept', 'udp sport 67 udp dport 68 accept'):
            self.assertLess(rules.index(needle), drop)
            self.assertGreater(rules.index(needle), invalid)

    def test_slaac_router_advert_and_pmtud_still_allowed(self):
        rules = self.ruleset()
        for t in ('nd-router-advert', 'nd-neighbor-solicit', 'nd-neighbor-advert', 'packet-too-big'):
            self.assertIn(t, rules)

    def test_dhcp_ports_are_not_opened_to_the_internet_on_ipv6(self):
        # Only link-local DHCPv6 servers; no global source can reach UDP 546.
        self.assertNotRegex(self.ruleset(), r'(?m)^\s*udp sport 547 udp dport 546 accept')


if __name__ == '__main__':
    unittest.main(verbosity=2)
