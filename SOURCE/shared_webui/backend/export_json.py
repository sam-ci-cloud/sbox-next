"""Translate the proven manager's Mihomo nodes into sing-box outbound JSON.

DNS/routing client behavior stays in the YAML profiles. JSON is a minimal
SOCKS client bundle; this distinction is explicit in the UI/docs.

Every Mihomo field is either mapped, deliberately ignored with a documented
reason, or rejected. Unknown fields fail the export instead of being silently
dropped (for example, a Hysteria2 port-hopping range must never disappear).

Policy groups (1.8.0): Mihomo ``url-test`` maps to sing-box ``urltest`` (url,
interval, tolerance) and ``select`` maps to ``selector``. sing-box has no
first-alive ``fallback`` group, so such a group (Anti-Block Auto) is omitted,
references to it are removed, and a selector that defaulted to it defaults to
the first remaining member (Smart Auto). Mihomo ``timeout``,
``max-failed-times`` and ``expected-status`` have no sing-box urltest field and
fall back to the core's built-in behaviour. Any other group type is refused.
"""
import json
import re
import sys
import yaml

TYPES = {'vless': 'vless', 'vmess': 'vmess', 'hysteria2': 'hysteria2', 'tuic': 'tuic', 'anytls': 'anytls'}
# Mihomo keys that have no sing-box outbound equivalent and do not change the
# connection identity. 'udp' is implicit in sing-box for these protocols.
IGNORED = {'udp', 'fast-open', 'tfo'}
MAPPED = {'name', 'type', 'server', 'port', 'uuid', 'password', 'flow', 'tls', 'servername', 'sni', 'client-fingerprint', 'skip-cert-verify',
          'reality-opts', 'alterId', 'cipher', 'network', 'ws-opts', 'alpn', 'ports', 'hop-interval', 'udp-relay-mode', 'congestion-controller', 'reduce-rtt', 'ip-version', 'smux',
          'idle-session-check-interval', 'idle-session-timeout', 'min-idle-session'}
UNSUPPORTED_GROUP_NOTE = ('sing-box has no first-alive "fallback" group; Anti-Block Auto is not exported to '
                          'sing-box JSON and its selector default becomes Smart Auto. Use the Mihomo YAML profile '
                          'for Anti-Block Auto. urltest probe timeout/max-failed-times use sing-box defaults.')
# Mihomo group keys that sing-box urltest/selector cannot express; documented above, never silently semantic.
GROUP_IGNORED = {'timeout', 'max-failed-times', 'expected-status', 'lazy'}


UNMAPPED_GROUPS = ('fallback', 'load-balance')


def convert_groups(groups, proxy_tags):
    """Return (outbounds, final_tag) for Mihomo proxy-groups, or ([], None) when absent."""
    if not groups:
        return [], None
    # Mihomo first-alive fallback and load-balance groups have no sing-box equivalent: they are
    # omitted (never imitated) and removed from the groups that reference them.
    dropped = {g['name'] for g in groups if g.get('type') in UNMAPPED_GROUPS}
    # Mihomo's built-in DIRECT has an exact sing-box equivalent (a direct outbound tagged DIRECT,
    # added by convert()); other built-ins (REJECT, PASS, ...) stay refused.
    known = set(proxy_tags) | {g['name'] for g in groups if g['name'] not in dropped} | {'DIRECT'}
    out = []
    for g in groups:
        kind, name = g.get('type'), g.get('name')
        if kind in UNMAPPED_GROUPS:
            continue
        members = [m for m in g.get('proxies', []) if m not in dropped]
        missing = [m for m in members if m not in known]
        if missing:
            raise ValueError('Group %s references unknown member(s): %s' % (name, ', '.join(missing)))
        if not members:
            raise ValueError('Group %s has no exportable members' % name)
        if kind == 'url-test':
            unknown = sorted(set(g) - {'name', 'type', 'proxies', 'url', 'interval', 'tolerance'} - GROUP_IGNORED)
            if unknown:
                raise ValueError('Group %s has field(s) this exporter cannot represent: %s' % (name, ', '.join(unknown)))
            o = {'type': 'urltest', 'tag': name, 'outbounds': members}
            if 'url' in g: o['url'] = g['url']
            if 'interval' in g: o['interval'] = '%ds' % int(g['interval'])
            if 'tolerance' in g:
                tol = int(g['tolerance'])
                if not 0 <= tol <= 65535:
                    raise ValueError('Group %s tolerance out of range' % name)
                o['tolerance'] = tol
        elif kind == 'select':
            unknown = sorted(set(g) - {'name', 'type', 'proxies', 'default-selected'})
            if unknown:
                raise ValueError('Group %s has field(s) this exporter cannot represent: %s' % (name, ', '.join(unknown)))
            o = {'type': 'selector', 'tag': name, 'outbounds': members}
            default = g.get('default-selected')
            o['default'] = default if default in members else members[0]
        else:
            raise ValueError('Group %s type %r has no sing-box equivalent' % (name, kind))
        out.append(o)
    if not out:
        return [], None
    # The final route is the outermost group: the one no other group references.
    referenced = {m for o in out for m in o['outbounds']}
    roots = [o['tag'] for o in out if o['tag'] not in referenced]
    return out, (roots[-1] if roots else out[-1]['tag'])


QUIC_TYPES = ('hysteria2', 'tuic')
FAMILY_LABEL = {'ipv4': 'IPv4', 'ipv6': 'IPv6'}


def _is_domain(host):
    import ipaddress as _ip
    try:
        _ip.ip_address(str(host).strip('[]'))
        return False
    except ValueError:
        return True


def node_candidates(o, version, url, addresses, quic):
    """Candidates for one node, kept behind a URL-test group that keeps the node's tag (so Smart
    Auto, LOCK and saved selections are unchanged). All candidates use the same TLS server name and
    certificate verification; only how the server address is found differs.

    * QUIC (Hysteria2/TUIC): sing-box binds a UDP socket to the FIRST resolved address and never
      tries the other family (common/dialer/resolve.go ListenPacket -> N.ListenSerial: a UDP listen
      always succeeds), so a dual-stack name becomes one candidate per family (ipv4_only/ipv6_only).
    * Bootstrap fallback: the server's own published addresses (the same ones the Export Center
      offers as endpoints) as literal candidates, so a slow, failing or poisoned local resolver
      cannot block the VPN. Bounded: only this server's addresses; no extra resolver, no stored history.
    """
    families = {'ipv4': ('ipv4',), 'ipv6': ('ipv6',)}.get(version, ('ipv6', 'ipv4') if version == 'ipv6-prefer' else ('ipv4', 'ipv6'))
    nodes = []
    if quic and len(families) == 2:
        for family in families:
            c = json.loads(json.dumps(o)); c['tag'] = '%s · %s' % (o['tag'], FAMILY_LABEL[family])
            c['domain_resolver'] = {'server': 'sbox-client-local', 'strategy': family + '_only'}
            nodes.append(c)
    else:
        c = json.loads(json.dumps(o)); c['tag'] = '%s · name' % o['tag']; nodes.append(c)
    for family in families:
        address = (addresses or {}).get(family)
        if address:
            c = json.loads(json.dumps(o)); c['tag'] = '%s · %s address' % (o['tag'], FAMILY_LABEL[family])
            c['server'] = address; c.pop('domain_resolver', None)
            nodes.append(c)
    if len(nodes) == 1:
        return [o], None
    group = {'type': 'urltest', 'tag': o['tag'], 'outbounds': [c['tag'] for c in nodes], 'interval': '60s', 'tolerance': 150}
    if url:
        group['url'] = url
    return nodes, group


def convert(document, family_split=True, addresses=None):
    out, tags, family_groups = [], [], []
    probe_url = next((g.get('url') for g in document.get('proxy-groups') or [] if g.get('type') == 'url-test' and g.get('url')), None)
    for p in document['proxies']:
        if p.get('type') not in TYPES:
            raise ValueError('Unsupported proxy type for sing-box JSON: %r' % p.get('type'))
        unknown = sorted(set(p) - MAPPED - IGNORED)
        if unknown:
            raise ValueError('Proxy %s has field(s) this exporter cannot represent: %s' % (p.get('name'), ', '.join(unknown)))
        t = TYPES[p['type']]
        o = dict(type=t, tag=p['name'], server=p['server'], server_port=p['port'])
        if 'ip-version' in p:
            strategies = {'ipv4': 'ipv4_only', 'ipv6': 'ipv6_only', 'dual': 'prefer_ipv4', 'ipv4-prefer': 'prefer_ipv4', 'ipv6-prefer': 'prefer_ipv6'}
            if p['ip-version'] not in strategies:
                raise ValueError('Unsupported proxy address family')
            o['domain_resolver'] = {'server': 'sbox-client-local', 'strategy': strategies[p['ip-version']]}
        for key in ('uuid', 'password', 'flow'):
            if key in p: o[key] = p[key]
        if t == 'vmess':
            o['security'] = p.get('cipher', 'auto'); o['alter_id'] = p.get('alterId', 0)
        if p.get('tls') or t in ('hysteria2', 'tuic', 'anytls'):
            tls = {'enabled': True, 'server_name': p.get('servername') or p.get('sni') or p['server'], 'insecure': bool(p.get('skip-cert-verify', False))}
            if 'alpn' in p: tls['alpn'] = p['alpn']
            if 'reality-opts' in p:
                tls['reality'] = {'enabled': True, 'public_key': p['reality-opts']['public-key'], 'short_id': p['reality-opts'].get('short-id', '')}
            if 'reality-opts' in p or 'client-fingerprint' in p:
                tls['utls'] = {'enabled': True, 'fingerprint': p.get('client-fingerprint', 'chrome')}
            o['tls'] = tls
        if p.get('network') == 'ws':
            ws = p.get('ws-opts', {})
            unknown_ws = sorted(set(ws) - {'path', 'headers', 'max-early-data', 'early-data-header-name'})
            if unknown_ws:
                raise ValueError('Proxy %s ws-opts field(s) cannot be represented: %s' % (p['name'], ', '.join(unknown_ws)))
            o['transport'] = {'type': 'ws', 'path': ws.get('path', '/'), 'headers': ws.get('headers', {})}
            if 'max-early-data' in ws:
                o['transport']['max_early_data'] = int(ws['max-early-data'])
                o['transport']['early_data_header_name'] = ws.get('early-data-header-name', 'Sec-WebSocket-Protocol')
        elif p.get('network') not in (None, 'tcp'):
            raise ValueError('Proxy %s network %r is not supported by this exporter' % (p['name'], p['network']))
        if t == 'hysteria2' and 'ports' in p:
            ranges = []
            for part in str(p['ports']).split(','):
                m = re.fullmatch(r'\s*(\d{1,5})(?:-(\d{1,5}))?\s*', part)
                if not m:
                    raise ValueError('Invalid Hysteria2 port-hopping range: %r' % p['ports'])
                lo, hi = int(m[1]), int(m[2] or m[1])
                if not (1 <= lo <= hi <= 65535):
                    raise ValueError('Invalid Hysteria2 port-hopping range: %r' % p['ports'])
                ranges.append('%d:%d' % (lo, hi))
            o['server_ports'] = ranges
            if 'hop-interval' in p:
                o['hop_interval'] = '%ss' % int(p['hop-interval'])
        if 'smux' in p:
            # sing-mux: Mihomo smux and sing-box multiplex share the wire protocol.
            # Pool fields share sing-mux semantics in both clients (Mihomo smux -> sing-mux
            # Options); integers only, so a typo can never be dropped silently.
            mux = p['smux']
            pool = {'max-connections': 'max_connections', 'min-streams': 'min_streams', 'max-streams': 'max_streams'}
            if not (isinstance(mux, dict) and set(mux) <= {'enabled', 'protocol'} | set(pool) and mux.get('protocol', 'h2mux') in ('h2mux', 'smux', 'yamux')
                    and all(type(mux[k]) is int and 0 <= mux[k] <= 1024 for k in pool if k in mux)):
                raise ValueError('Proxy %s smux settings cannot be represented' % p['name'])
            if mux.get('enabled') is True:
                o['multiplex'] = {'enabled': True, 'protocol': mux.get('protocol', 'h2mux')}
                o['multiplex'].update({pool[k]: mux[k] for k in pool if k in mux})
        if t == 'anytls':
            # AnyTLS session pool (same sing-anytls semantics in both clients); seconds / count.
            for key, field, unit in (('idle-session-check-interval', 'idle_session_check_interval', 's'),
                                     ('idle-session-timeout', 'idle_session_timeout', 's'), ('min-idle-session', 'min_idle_session', '')):
                if key in p:
                    if type(p[key]) is not int or not 0 <= p[key] <= 86400:
                        raise ValueError('Proxy %s %s cannot be represented' % (p['name'], key))
                    o[field] = '%d%s' % (p[key], unit) if unit else p[key]
        elif any(k in p for k in ('idle-session-check-interval', 'idle-session-timeout', 'min-idle-session')):
            raise ValueError('Proxy %s has AnyTLS session fields on a %s node' % (p['name'], t))
        if t == 'tuic':
            o['congestion_control'] = p.get('congestion-controller', 'bbr')
            o['udp_relay_mode'] = p.get('udp-relay-mode', 'native')
            o['zero_rtt_handshake'] = bool(p.get('reduce-rtt', False))
        # Range nodes are aliases of the direct outbound; do not invent a listener.
        version = p.get('ip-version', 'dual')
        if family_split and _is_domain(o['server']) and version in ('dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer'):
            nodes, group = node_candidates(o, version, probe_url, addresses, t in QUIC_TYPES)
            out.extend(nodes); tags.append(o['tag'])
            if group: family_groups.append(group)
        else:
            out.append(o); tags.append(o['tag'])
    if not out:
        raise ValueError('Profile contains no proxies')
    groups, final = convert_groups(document.get('proxy-groups'), tags)
    groups = family_groups + groups
    if any('DIRECT' in g.get('outbounds', []) for g in groups):
        groups.append({'type': 'direct', 'tag': 'DIRECT'})
    result = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'socks', 'tag': 'socks-in', 'listen': '127.0.0.1', 'listen_port': 1080}],
            # Nodes stay first (1.7.1 consumers index outbounds[0]); route.final names the policy explicitly.
            'outbounds': out + groups, 'route': {'final': final or tags[0]}}
    if any('domain_resolver' in o for o in out):
        result['dns'] = {'servers': [{'type': 'local', 'tag': 'sbox-client-local'}]}
    return result


# --------------------------------------------------------------------------------------------
# Full sing-box profile (1.10+ syntax, verified with the pinned 1.14.4 client): the same nodes and
# groups as the basic bundle plus DNS, routing for the selected profile, a TUN inbound for sing-box
# apps and a local mixed proxy. Mihomo first-alive fallback has no sing-box equivalent (see above).
# Remote resolver comes from the profile's own DNS list (through the VPN); bootstrap uses the device
# resolver. sing-box uses one server per role where Mihomo races several.
# Mainland-China-direct: sing-box 1.12+ has no built-in GeoSite/GeoIP data and SBOX never makes generated
# profiles download rule data, so the Mihomo GEOSITE,CN / GEOIP,CN rules map to inline rule sets from the
# committed, pinned snapshot shared_webui/backend/cn_rules.json (tools/cn_rules.py; APNIC + v2fly `cn`).
PROFILE_KINDS = ('global', 'cn', 'internal')


def dns_server(value, tag, detour=None):
    """Mihomo nameserver entry -> sing-box server. Literal-address DoH/plain DNS need no lookup;
    a hostname DoH server is resolved through the literal bootstrap resolver (sbox-client-local)."""
    import ipaddress as _ip
    import urllib.parse as _up
    text = str(value)
    if '://' in text:
        u = _up.urlsplit(text)
        if u.scheme != 'https' or not u.hostname:
            return None
        server = {'type': 'https', 'tag': tag, 'server': u.hostname}
        try:
            _ip.ip_address(u.hostname)
        except ValueError:
            server['domain_resolver'] = 'sbox-client-local'
            server['tls'] = {'enabled': True, 'server_name': u.hostname}
        if u.path and u.path != '/dns-query':
            server['path'] = u.path
    else:
        try:
            _ip.ip_address(text)
        except ValueError:
            return None
        server = {'type': 'udp', 'tag': tag, 'server': text}
    if detour:
        server['detour'] = detour
    return server


def first_server(values, tag, detour=None):
    for value in values or []:
        server = dns_server(value, tag, detour)
        if server:
            return server
    raise ValueError('Profile has no literal-address resolver for %s' % tag)


CN_RULE_SETS = {('GEOSITE', 'CN'): 'sbox-cn-domain', ('GEOIP', 'CN'): 'sbox-cn-ip'}


def cn_rule_sets():
    """Inline rule sets from the committed, pinned snapshot (tools/cn_rules.py): nothing is downloaded."""
    import os
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cn_rules.json'), encoding='utf-8') as stream:
        data = json.load(stream)
    return [{'type': 'inline', 'tag': 'sbox-cn-domain', 'rules': [data['domain']]},
            {'type': 'inline', 'tag': 'sbox-cn-ip', 'rules': [{'ip_cidr': data['ip_cidr']}]}]


RULE_MATCH = {'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr'}


def mihomo_route_rules(document, tags):
    """Mihomo rule list (everything before MATCH) -> equivalent sing-box route rules.
    Anything that has no exact sing-box equivalent is refused rather than silently dropped."""
    out = []
    for rule in document.get('rules') or []:
        parts = [x.strip() for x in str(rule).split(',')]
        if parts[0] == 'MATCH':
            break
        if len(parts) < 3:
            raise ValueError('Unsupported routing rule: %s' % parts[0])
        kind, value, target = parts[0], parts[1], parts[2]
        if kind == 'GEOIP' and value.upper() == 'LAN':
            match = {'ip_is_private': True}
        elif (kind, value.upper()) in CN_RULE_SETS:
            match = {'rule_set': [CN_RULE_SETS[(kind, value.upper())]]}
        elif kind in RULE_MATCH:
            match = {RULE_MATCH[kind]: [value]}
        else:
            raise ValueError('Routing rule type %s has no offline sing-box equivalent' % kind)
        if target == 'DIRECT':
            match['outbound'] = 'direct'
        elif target == 'REJECT':
            match['action'] = 'reject'
        elif target in tags:
            match['outbound'] = target
        else:
            raise ValueError('Routing rule target %s is not an outbound' % target)
        out.append(match)
    return out


def convert_full(document, kind, addresses=None):
    if kind not in PROFILE_KINDS:
        raise ValueError('Unknown routing profile %r' % kind)
    base = convert(document, addresses=addresses)
    final = base['route']['final']
    dns = document.get('dns') or {}
    families = {p.get('ip-version') for p in document['proxies']}
    strategy = {'ipv4': 'ipv4_only', 'ipv6': 'ipv6_only'}.get(families.pop() if len(families) == 1 else None)
    # Remote lookups: encrypted, through the VPN. Bootstrap (the VPN server name, local names): the
    # device's own resolver, as in the basic bundle. A single fixed public resolver here proved fragile
    # (lab: Alibaba DoH timed out from Los Angeles; sing-box cannot race several like Mihomo does).
    servers = [first_server(dns.get('nameserver'), 'dns-remote', final), {'type': 'local', 'tag': 'sbox-client-local'}]
    outbounds = base['outbounds'] + [{'type': 'direct', 'tag': 'direct'}]
    # Routing is derived from the generated Mihomo rules, in the same order, so the local-network
    # bypass, the administrator's custom rules and their precedence match the Mihomo profile exactly.
    route_rules = [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'}] + mihomo_route_rules(document, {o['tag'] for o in outbounds})
    dns_rules = [{'domain_suffix': ['lan', 'local'], 'server': 'sbox-client-local'}] if any(r.get('outbound') == 'direct' and r.get('domain_suffix') in (['lan'], ['local']) for r in route_rules) else []
    for o in outbounds:
        if 'domain_resolver' in o:
            o['domain_resolver']['server'] = 'sbox-client-local'
    result = {'log': {'level': 'warn'},
              'dns': {'servers': servers, 'rules': dns_rules, 'final': 'dns-remote'},
              'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], 'auto_route': True, 'strict_route': True},
                           {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080}],
              'outbounds': outbounds,
              'route': {'rules': route_rules, 'final': final, 'auto_detect_interface': True, 'default_domain_resolver': 'sbox-client-local'},
              'experimental': {'cache_file': {'enabled': True}}}
    used = {t for r in route_rules for t in r.get('rule_set', [])}
    if used:
        result['route']['rule_set'] = [r for r in cn_rule_sets() if r['tag'] in used]
        if 'sbox-cn-domain' in used:
            # Mainland-China names use the profile's CN resolver directly (Mihomo nameserver-policy geosite:cn).
            policy = (dns.get('nameserver-policy') or {}).get('geosite:cn') or dns.get('direct-nameserver')
            result['dns']['servers'].append(first_server(policy, 'dns-cn'))
            result['dns'].setdefault('rules', []).append({'rule_set': ['sbox-cn-domain'], 'server': 'dns-cn'})
    if strategy:
        result['dns']['strategy'] = strategy
    if not dns_rules:
        del result['dns']['rules']
    return result


def published_addresses(state_path):
    """The server's own published VPN addresses (Export Center endpoint choices) by family."""
    import network_policy
    with open(state_path, encoding='utf-8') as stream:
        state = json.load(stream)
    if state.get('server', {}).get('export_endpoint') not in (None, 'auto', 'domain'):
        return None  # a literal endpoint was chosen; the profile already uses it
    return {c['id']: c['address'] for c in network_policy.endpoint_options(state)['choices'] if c['id'] in ('ipv4', 'ipv6') and c.get('address')}


if __name__ == '__main__':
    # export_json.py FILE                               -> basic SOCKS bundle
    # export_json.py --full PROFILE FILE                -> full sing-box profile
    # either form may start with --addresses-from STATE (bootstrap address candidates)
    try:
        args, addresses = sys.argv[1:], None
        if args[:1] == ['--addresses-from']:
            addresses, args = published_addresses(args[1]), args[2:]
        if args[0] == '--full':
            with open(args[2], encoding='utf-8') as stream:
                result = convert_full(yaml.safe_load(stream), args[1], addresses=addresses)
        else:
            with open(args[0], encoding='utf-8') as stream:
                result = convert(yaml.safe_load(stream), addresses=addresses)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('sing-box JSON export refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, ensure_ascii=False, indent=2))
