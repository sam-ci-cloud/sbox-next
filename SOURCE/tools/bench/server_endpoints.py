#!/usr/bin/env python3
"""Print the client endpoints of an installed SBOX server for the benchmark harness.

Runs as root on the server. Reads the rendered core config and state; prints JSON
with per-protocol endpoint parameters for one core user name (default: every
inbound's first user, i.e. the installer identity). Output contains credentials:
keep it on private test hosts only.

usage: server_endpoints.py [--user NAME] [--host HOSTNAME]
"""
import argparse
import json

CONFIG = '/etc/sbox-manager/config.json'
STATE = '/etc/sbox-manager/state.json'

KIND = {'vless': 'reality', 'vmess': 'vmess', 'hysteria2': 'hy2', 'tuic': 'tuic', 'anytls': 'anytls'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--user', help='core user name, or user-<id> for a managed user; default installer identity')
    ap.add_argument('--host', help='server address clients dial; default state domain')
    a = ap.parse_args()
    config = json.load(open(CONFIG))
    state = json.load(open(STATE))
    host = a.host or state.get('domain') or state['server']['ipv4']
    out = {'host': host, 'domain': state.get('domain'), 'ipv4': state['server'].get('ipv4'),
           'manager_version': state.get('manager_version'), 'protocols': {}}
    for inbound in config.get('inbounds', []):
        kind = KIND.get(inbound.get('type'))
        if not kind:
            continue
        users = inbound.get('users', [])
        # Managed users appear once per inbound as user-<id>@<protocol>.
        user = next((u for u in users if a.user is None or u.get('name') in (a.user, '%s@%s' % (a.user, kind))), None)
        if user is None:
            continue
        tls = inbound.get('tls', {})
        entry = {'port': inbound['listen_port'], 'user': user.get('name')}
        if kind == 'reality':
            proto = state['protocols']['reality']
            entry.update(uuid=user['uuid'], flow=user.get('flow', ''), sni=tls.get('server_name'),
                         public_key=proto['public_key'], short_id=tls['reality']['short_id'][0],
                         fingerprint=proto.get('fingerprint', 'chrome'))
        elif kind == 'vmess':
            entry.update(uuid=user['uuid'], path=inbound.get('transport', {}).get('path', ''),
                         max_early_data=inbound.get('transport', {}).get('max_early_data', 0),
                         sni=state['protocols']['vmess'].get('sni') or state.get('domain'),
                         tls=bool(tls.get('enabled')))
        elif kind == 'hy2':
            entry.update(password=user['password'], sni=state.get('domain'),
                         hop_range=state['protocols'].get('hy2', {}).get('udp_range', ''))
        elif kind == 'tuic':
            entry.update(uuid=user['uuid'], password=user['password'], sni=state.get('domain'),
                         congestion_control=inbound.get('congestion_control', 'cubic'))
        elif kind == 'anytls':
            entry.update(password=user['password'], sni=state.get('domain'))
        out['protocols'][kind] = entry
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
