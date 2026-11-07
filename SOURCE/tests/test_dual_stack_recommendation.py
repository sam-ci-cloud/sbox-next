"""Fresh installs recommend dual stack when a working public IPv6 was detected (D3, 1.8.0).

Fail-first: 1.7.1 defaults the listen prompt to IPv4-only even when detect_public_ipv6()
proved outbound IPv6 works. Live 1.4.1 hosts ended up IPv4-only although both have
working global IPv6 (2026-11-05: peer IPv6 TCP to every protocol port refused, 20/20).
Upgrades never change the network policy silently; they only say dual stack is available.
"""
import re, subprocess, unittest
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / 'src/manager.sh').read_text()


class DualStackRecommendation(unittest.TestCase):
    def choose(self, current, ipv6, existing, probed):
        function = re.search(r'^choose_listen\(\) \{.*?^\}\n', SOURCE, re.M | re.S)[0]
        script = 'set -eu\nprompt_choice(){ printf "%s\\n" "$2"; }; die(){ exit 2; };\n' + function + '\nchoose_listen "$1" "$2" "$3" "$4"\n'
        r = subprocess.run(['bash', '-c', script, 'test', current, ipv6, existing, probed], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip(), r.stderr

    def test_fresh_with_probed_ipv6_defaults_to_dual(self):
        out, err = self.choose('0.0.0.0', '2001:db8::1', 'false', 'true')
        self.assertEqual(out, '::')
        self.assertIn('dual stack is recommended', err.lower())

    def test_fresh_with_typed_but_unprobed_ipv6_stays_ipv4(self):
        self.assertEqual(self.choose('0.0.0.0', '2001:db8::1', 'false', 'false')[0], '0.0.0.0')

    def test_fresh_without_ipv6_stays_ipv4(self):
        self.assertEqual(self.choose('0.0.0.0', '', 'false', 'true')[0], '0.0.0.0')

    def test_upgrade_preserves_policy_but_says_dual_is_available(self):
        out, err = self.choose('0.0.0.0', '2001:db8::1', 'true', 'true')
        self.assertEqual(out, 'preserve')
        self.assertIn('ipv6 clients cannot connect', err.lower())

    def test_upgrade_already_dual_has_no_nag(self):
        out, err = self.choose('::', '2001:db8::1', 'true', 'true')
        self.assertEqual(out, 'preserve')
        self.assertNotIn('ipv6 clients cannot connect', err.lower())

    def test_call_site_passes_probe_result(self):
        # install/upgrade path (the network reconfigure command passes existing=true and no probe: no default change)
        lines = [l for l in SOURCE.splitlines() if 'listen="$(choose_listen ' in l and '"$has_old"' in l]
        self.assertEqual(len(lines), 1, lines)
        # 4th argument is the probe result: true only when the chosen IPv6 is the detected one
        self.assertIn('"$has_old" "$([ -n "$detected6" ] && [ "$ipv6" = "$detected6" ] && echo true || echo false)"', lines[0])

if __name__ == '__main__':
    unittest.main(verbosity=2)
