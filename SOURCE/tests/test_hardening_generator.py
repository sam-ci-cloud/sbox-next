"""Unit tests for sbox-hardening.py (no root, no nft needed)."""
import importlib.util, pathlib, unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("hard", HERE.parent / "src" / "hardening.py")
hard = importlib.util.module_from_spec(spec); spec.loader.exec_module(hard)

# Verbatim structure of VPS-A's live iptables-save (2026-11-05 inventory; no secrets)
SAVE4 = """*filter
:INPUT ACCEPT [715:224502]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:SBOX_INPUT - [0:0]
-A INPUT -j SBOX_INPUT
-A INPUT -p tcp -m tcp --dport 9443 -m comment --comment sbox-webui -j ACCEPT
-A SBOX_INPUT -p tcp -m tcp --dport 61949 -m comment --comment "sbox:anytls" -j ACCEPT
-A SBOX_INPUT -p udp -m udp --dport 443 -m comment --comment "sbox:hy2" -j ACCEPT
-A SBOX_INPUT -p tcp -m tcp --dport 443 -m comment --comment "sbox:reality" -j ACCEPT
-A SBOX_INPUT -p udp -m udp --dport 47852 -m comment --comment "sbox:tuic" -j ACCEPT
-A SBOX_INPUT -p tcp -m tcp --dport 38683 -m comment --comment "sbox:vmess" -j ACCEPT
-A SBOX_INPUT -p tcp -m tcp --dport 80 -m comment --comment "sbox:http01" -j ACCEPT
-A SBOX_INPUT -j RETURN
COMMIT
"""
SAVE6 = SAVE4.replace("-A INPUT -p tcp -m tcp --dport 9443 -m comment --comment sbox-webui -j ACCEPT\n", "")
SSHD = "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\npermitrootlogin yes\n"


class T(unittest.TestCase):
    def c(self, s4=SAVE4, s6=SAVE6, sshd=SSHD, cfg=None):
        return hard.collect(s4, s6, sshd, cfg or {})

    def test_openssh_capitalized_effective_port(self):
        # OpenSSH on the Ubuntu 26.10 lab emits canonical capitalized keys.
        c = self.c(sshd="Port 22\nListenAddress [::]:22\n")
        self.assertIn("22", c["tcp"])
        self.assertEqual(c["ssh"], [22])

    def test_live_vps_a_ports(self):
        c = self.c()
        self.assertEqual(sorted(c["tcp"], key=int), ["22", "80", "443", "9443", "38683", "61949"])
        self.assertEqual(sorted(c["udp"], key=int), ["443", "47852"])
        self.assertEqual(c["ssh"], [22])

    def test_render_has_safety_rules(self):
        r = hard.render(self.c())
        for must in ('iif "lo" accept', "ct state established,related accept", "nd-neighbor-solicit",
                     "nd-router-advert", "packet-too-big", "tcp dport @tcp_allow accept",
                     "udp dport @udp_allow accept", "policy drop", "priority filter + 10"):
            self.assertIn(must, r)
        # atomic replace pattern
        self.assertTrue(r.startswith("table inet sbox_hardening {}\ndelete table inet sbox_hardening\n"))
        # never touches SBOX-owned tables
        for forbidden in ("sbox_guard", "SBOX_INPUT", "flush ruleset", "table ip filter", "table ip6 filter"):
            self.assertNotIn(forbidden, r)

    def test_ssh_always_allowed_even_if_nonstandard(self):
        c = self.c(sshd="port 2222\nport 22\n")
        self.assertIn("2222", c["tcp"]); self.assertIn("22", c["tcp"])

    def test_refuse_without_sshd_port(self):
        with self.assertRaises(hard.Refuse):
            self.c(sshd="permitrootlogin yes\n")

    def test_refuse_without_sbox_rules(self):
        empty = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        with self.assertRaises(hard.Refuse):
            self.c(s4=empty, s6=empty)

    def test_foreign_input_rules_not_mirrored(self):
        s4 = SAVE4.replace("-A INPUT -j SBOX_INPUT\n",
                           "-A INPUT -j SBOX_INPUT\n-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT\n"
                           "-A INPUT -p tcp -m tcp --dport 6379 -m comment --comment other -j ACCEPT\n")
        c = self.c(s4=s4)
        self.assertNotIn("3306", c["tcp"]); self.assertNotIn("6379", c["tcp"])

    def test_hy2_port_hop_range(self):
        s4 = SAVE4.replace("-A SBOX_INPUT -j RETURN",
                           '-A SBOX_INPUT -p udp -m udp --dport 20000:20100 -m comment --comment "sbox:hy2-hop" -j ACCEPT\n-A SBOX_INPUT -j RETURN')
        c = self.c(s4=s4)
        self.assertIn("20000-20100", c["udp"])
        self.assertIn("20000-20100", hard.render(c))

    def test_ipv6_only_rules_are_merged(self):
        s6 = SAVE6.replace("-A SBOX_INPUT -j RETURN",
                           '-A SBOX_INPUT -p tcp -m tcp --dport 50000 -m comment --comment "sbox:test6" -j ACCEPT\n-A SBOX_INPUT -j RETURN')
        self.assertIn("50000", self.c(s6=s6)["tcp"])

    def test_webui_restriction(self):
        c = self.c(cfg={"restrict_webui_to": ["203.0.113.4", "2001:db8::/48"]})
        self.assertNotIn("9443", c["tcp"])
        r = hard.render(c)
        self.assertIn("ip saddr @webui_src4 tcp dport { 9443 } accept", r)
        self.assertIn("ip6 saddr @webui_src6 tcp dport { 9443 } accept", r)
        self.assertIn("203.0.113.4/32", r)

    def test_invalid_port_refused(self):
        s4 = SAVE4.replace("--dport 61949", "--dport 70000")
        with self.assertRaises(hard.Refuse):
            self.c(s4=s4)

    def test_notrack_only_udp_protocol_ports(self):
        r = hard.render(self.c())
        self.assertIn("udp dport @udp_allow notrack", r)
        self.assertNotIn("tcp dport @tcp_allow notrack", r)
        r2 = hard.render(self.c(cfg={"notrack_udp": False}))
        self.assertNotIn("notrack", r2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
