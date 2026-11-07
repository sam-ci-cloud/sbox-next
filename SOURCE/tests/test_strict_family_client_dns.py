"""Strict IPv4-only / IPv6-only client profiles must not depend on hostname resolvers.

Old behaviour: the family filter removed literal resolvers of the other family but kept
every hostname endpoint (e.g. https://doh.pub/dns-query, https://dns.alidns.com/...).
Such an endpoint is itself resolved and may be dialled over either family, so the
"strict" profile was not strict: on an IPv6-only device the CN resolvers could be
unreachable, and on an IPv4-only setup a dual-stack DoH host might still be tried
over IPv6.  ECS/answer filtering does not control the transport family.

Contract: in client mode ipv4/ipv6 every resolver in every DNS field is a literal of
that family.  Built-in hostname DoH is replaced by literal equivalents; a user-supplied
hostname resolver is refused with an actionable error.  Dual mode is unchanged.
"""
import copy, ipaddress, unittest, urllib.parse
import yaml
import reality_fixture as fx

FIELDS = ('nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver')


def host_of(endpoint):
    return urllib.parse.urlsplit(endpoint).hostname if '://' in endpoint else endpoint.split('#')[0]


def state(family):
    s = fx.trusted_certificate(fx.base_state())
    s['sing_box']['version'] = '1.14.4'
    if family == 'dual':
        s['server'].update(mode='dual', scope='internal', ipv4='192.0.2.10', ipv6='2001:db8::10', listen='::',
                           policies={'inbound': 'dual', 'egress': 'dual', 'dns': 'dual', 'client': 'dual'})
    elif family == 'ipv4':
        s['server'].update(mode='ipv4', scope='internal', ipv4='192.0.2.10', listen='0.0.0.0',
                           policies=dict.fromkeys(('inbound', 'egress', 'dns', 'client'), 'ipv4'))
    else:
        s['server'].update(mode='ipv6', scope='internal', ipv6='2001:db8::10', listen='2001:db8::10',
                           policies=dict.fromkeys(('inbound', 'egress', 'dns', 'client'), 'ipv6'))
    return s


def dns_sections(s):
    out = fx.render(s)
    docs = {}
    for name in ('mihomo-global.yaml', 'mihomo-cn.yaml', 'mihomo-internal.yaml'):
        path = out / name
        if path.exists():
            docs[name] = yaml.safe_load(path.read_text())['dns']
    return docs


def all_resolvers(dns):
    for field in FIELDS:
        for e in dns.get(field, []):
            yield field, e
    for name, values in (dns.get('nameserver-policy') or {}).items():
        for e in (values if isinstance(values, list) else [values]):
            yield 'nameserver-policy:' + name, e


class StrictFamilyClientDns(unittest.TestCase):
    def test_strict_modes_use_only_family_literals(self):
        for family, version in (('ipv4', 4), ('ipv6', 6)):
            docs = dns_sections(state(family))
            self.assertIn('mihomo-cn.yaml', docs)
            for name, dns in docs.items():
                for field, endpoint in all_resolvers(dns):
                    with self.subTest(family=family, profile=name, field=field, endpoint=endpoint):
                        try:
                            ip = ipaddress.ip_address(host_of(endpoint))
                        except ValueError:
                            self.fail('hostname resolver kept in strict %s profile: %s' % (family, endpoint))
                        self.assertEqual(ip.version, version)

    def test_strict_cn_profile_keeps_cn_resolvers(self):
        for family in ('ipv4', 'ipv6'):
            dns = dns_sections(state(family))['mihomo-cn.yaml']
            with self.subTest(family=family):
                self.assertTrue(dns['nameserver-policy']['geosite:cn'])
                self.assertTrue(dns['direct-nameserver'])

    def test_no_ipv6_literal_doh_for_services_without_ipv6_certificates(self):
        # Verified 2026-11-05: AliDNS certificate has IPv4 SANs only (curl exit 60 on [2400:3200::1]).
        for dns in dns_sections(state('ipv6')).values():
            for field, endpoint in all_resolvers(dns):
                with self.subTest(field=field, endpoint=endpoint):
                    self.assertFalse(endpoint.startswith('https://[2400:3200') or endpoint.startswith('https://[2402:4e00'))

    def test_unencrypted_dns_only_for_cn_direct_domains(self):
        for name, dns in dns_sections(state('ipv6')).items():
            for field, endpoint in all_resolvers(dns):
                if '://' not in endpoint:
                    with self.subTest(profile=name, field=field, endpoint=endpoint):
                        # default-nameserver is Mihomo's plain-IP bootstrap list by design.
                        self.assertIn(field, ('default-nameserver', 'direct-nameserver', 'nameserver-policy:geosite:cn'))

    def test_dual_mode_unchanged(self):
        dns = dns_sections(state('dual'))['mihomo-cn.yaml']
        self.assertIn('https://doh.pub/dns-query', dns['nameserver-policy']['geosite:cn'])

    def test_user_hostname_resolver_refused_in_strict_mode(self):
        s = state('ipv6')
        s.setdefault('client_policy', {})['dns'] = {'global': ['https://dns.example.net/dns-query', 'https://[2606:4700:4700::1111]/dns-query']}
        r = fx.state_tool('render', s, '/tmp/unused-out')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('literal', (r.stdout + r.stderr).lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)
