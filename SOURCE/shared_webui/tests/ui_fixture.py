"""UI test fixture for the privileged bridge. FIXTURE ONLY - NOT VPN EVIDENCE.

The real HTTPS server, SQLite store, sessions, CSRF, reauthentication and
controller candidate code are used unchanged. Only the root bridge is replaced
by this in-memory object so browser/layout/accessibility checks can run without
a VPN. Every payload carries ``fixture: true`` so screenshots cannot be mistaken
for a deployed server. Credentials are synthetic and generated per process.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import uuid

ROOT = Path(os.environ.get('SBOX_WEBUI_ROOT', Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'privileged-bridge'))
from common import Problem, PROTOCOLS, capabilities, require  # noqa: E402
import controller  # noqa: E402


def _host_overview():
    """Read real host procfs values so resource cards show plausible numbers."""
    mem = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, rest = line.partition(':')
        mem[key] = int(rest.split()[0]) * 1024
    st = os.statvfs('/')
    net = {}
    for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
        iface, fields = line.split(':')
        fields = fields.split()
        if iface.strip() != 'lo':
            net[iface.strip()] = {'rx': int(fields[0]), 'tx': int(fields[8])}
    cpu = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
    load = [float(x) for x in Path('/proc/loadavg').read_text().split()[:3]]
    return mem, st, net, cpu, load


class FixtureControl:
    def __init__(self, variant='universal', users=0, protected_name=None, core='1.13.14'):
        self.variant = variant
        self.lock = threading.Lock()
        self.core = core
        self.service_state = 'active'
        self.listening = {p: True for p in PROTOCOLS}
        self.cert_expires = time.time() + 63 * 86400
        self.calls = []
        self.fail_next = {}
        self.delay = {}
        enabled = {p: True for p in PROTOCOLS}
        ports = {'reality': 443, 'vmess': 50344, 'hy2': 443, 'tuic': 48385, 'anytls': 64303} if variant == 'zgocloud' else {'reality': 24443, 'vmess': 28443, 'hy2': 25443, 'tuic': 26443, 'anytls': 27443}
        self.state = {
            'fixture': True,
            'server':{'mode':'preserve','listen':'0.0.0.0','ipv4':'192.0.2.1','ipv6':'2001:db8::1','scope':'internal'},
            'domain': 'zgo.example.test' if variant == 'zgocloud' else 'vpn.example.test',
            'zgo_legacy_compat': variant == 'zgocloud',
            'sing_box': {'version': core},
            'certificate': {'mode': 'certbot-http01', 'source_fullchain': '/fixture/fullchain.pem'},
            'protocols': {p: {'enabled': enabled[p], 'port': ports[p], 'uuid': str(uuid.uuid4()), 'password': secrets.token_urlsafe(24)} for p in PROTOCOLS},
            'client_policy': {'primary': 'tuic', 'smart_lazy': True, 'probe_url': 'https://www.gstatic.com/generate_204'},
            'managed_users': [],
        }
        self.state['protocols']['hy2']['udp_range'] = '36494:46493' if variant == 'zgocloud' else '40000:40099'
        self.state['protocols']['tuic']['udp_range'] = '21518:31517' if variant == 'zgocloud' else ''
        self.protected_name = protected_name
        self.changes = {}
        self.version = 1
        self.previous_cpu = None
        for i in range(users):
            self.state['managed_users'].append(self._user('client-%04d' % (i + 1), enabled=(i % 7 != 3), tags=(['family'] if i % 3 == 0 else ['team'] if i % 3 == 1 else [])))

    def _user(self, name, enabled=True, tags=()):
        return {'id': uuid.uuid4().hex, 'name': name, 'enabled': enabled, 'tags': list(tags),
                'protocols': {p: {'uuid': str(uuid.uuid4()), 'password': secrets.token_urlsafe(32)} for p in PROTOCOLS if self.state['protocols'][p]['enabled']}}

    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.state, sort_keys=True).encode()).hexdigest()

    # -- bridge ops -------------------------------------------------------
    def __call__(self, op, data=None):
        data = data or {}
        self.calls.append(op)
        if op in self.delay:
            time.sleep(self.delay[op])
        if op in self.fail_next:
            status, message = self.fail_next.pop(op)
            raise Problem(status, message)
        handler = getattr(self, 'op_' + op.replace('-', '_'), None)
        require(handler is not None, 'Operation is not allowlisted', 400)
        with self.lock:
            return handler(data)

    def op_overview(self, data):
        mem, st, net, cpu, load = _host_overview()
        cpu_percent = None
        if self.previous_cpu:
            total = sum(cpu[:8]) - sum(self.previous_cpu[:8])
            idle = cpu[3] + cpu[4] - self.previous_cpu[3] - self.previous_cpu[4]
            if total > 0:
                cpu_percent = round(100 * (total - idle) / total, 2)
        self.previous_cpu = cpu
        active = self.service_state == 'active'
        return dict(fixture=True, sampled_at=time.time(), source='FIXTURE: host procfs values; service state simulated',
                    service={'ActiveState': self.service_state, 'SubState': 'running' if active else 'dead', 'MainPID': '4242' if active else '0',
                             'ExecMainStartTimestamp': 'Sat 2026-10-24 08:00:00 UTC', 'MemoryCurrent': '31457280', 'CPUUsageNSec': '9000000000', 'NRestarts': '0'},
                    core_version=self.core if active else None, expected_core_version=self.state['sing_box']['version'],
                    uptime_seconds=float(Path('/proc/uptime').read_text().split()[0]), cpu_ticks=cpu, cpu_percent=cpu_percent, load_average=load,
                    cpu_count=os.cpu_count(),
                    recent_errors={'count': 0 if active else 3, 'window': 'last hour, capped at 200 journal entries', 'source': 'journalctl priority err'},
                    renewal_timers={'certbot.timer': {'ActiveState': 'active', 'NextElapseUSecRealtime': 'Sun 2026-10-25 03:12:00 UTC'},
                                    'sbox-webui-certificate.timer': {'ActiveState': 'active', 'NextElapseUSecRealtime': ''}},
                    last_validated_check=None,
                    memory_total_bytes=mem['MemTotal'], memory_available_bytes=mem['MemAvailable'], core_rss_bytes=31457280,
                    disk_used_bytes=(st.f_blocks - st.f_bfree) * st.f_frsize, disk_total_bytes=st.f_blocks * st.f_frsize,
                    disk_available_bytes=st.f_bavail * st.f_frsize, network=net,
                    pending_transaction=False,
                    external_reachability='unavailable: requires a client/ISP packet check',
                    capabilities=capabilities(self.state['sing_box']['version'], self.variant))

    # -- synthetic accounting (FIXTURE ONLY) ---------------------------------
    # Real plan preview, quota calendar and history axis code; only the byte
    # counts are synthetic and every payload carries ``fixture: true``.
    def _quota(self, index):
        presets = [{'quota_bytes': 100 * 10**9}, {'quota_bytes': 50 * 10**9, 'period': 'weekly', 'reset_day': 1}, {'quota_bytes': 0, 'period': 'none'},
                   {'quota_bytes': 500 * 10**9, 'timezone': 'Europe/London'}, {'quota_bytes': 100 * 1024**3, 'expires_at': int(time.time()) + 40 * 86400}, {'quota_bytes': 10 * 10**9, 'period': 'daily'}]
        q = {'period': 'monthly', 'timezone': 'Asia/Hong_Kong', 'reset_day': 1}
        q.update(presets[index % len(presets)])
        return q

    def _usage(self, user, index):
        from quota_models import quota_plan, quota_boundaries, quota_status
        user.setdefault('quota', self._quota(index))
        plan = quota_plan(user['quota']); now = time.time()
        used = None if index % 11 == 7 else int((plan['quota_bytes'] or 80 * 10**9) * ((index * 37) % 105) / 100)
        start, end = quota_boundaries(now, plan)
        up = None if used is None else used // 6
        return {'fixture': True, 'used_bytes': used, 'upload_bytes': up, 'download_bytes': None if used is None else used - up,
                'lifetime_up_bytes': up, 'lifetime_down_bytes': None if used is None else used - up,
                'quota_bytes': plan['quota_bytes'], 'remaining_bytes': max(0, plan['quota_bytes'] - used) if plan['quota_bytes'] and used is not None else None,
                'unlimited': not plan['quota_bytes'], 'status': quota_status(user, used, now), 'freshness': 'fresh' if used is not None else 'stale',
                'sampled_at': now - 5, 'next_reset': end, 'period_start': start, 'expires_at': plan['expires_at'], 'collection_gap': False, 'reset_seq': 0,
                'timezone': plan['timezone'], 'history': []}

    def op_accounting_summary(self, data):
        rows = []
        for i, user in enumerate(self.state['managed_users']):
            usage = self._usage(user, i)
            rows.append({'id': user['id'], 'name': user['name'], 'usage': usage, 'plan': user['quota'], 'portal': {}})
        health = {'status': 'ready', 'sampled_at': time.time() - 5, 'poll_seconds': 2, 'fixture': True}
        return {'fixture': True, 'enabled': True, 'health': health, 'users': rows, 'legacy': {'used_bytes': 0, 'status': 'protected_legacy'},
                'legacy_note': 'FIXTURE', 'policy': {'poll_seconds': 2, 'failure_policy': 'fail-closed'}, 'events': []}

    def op_quota_preview(self, data):
        from plan_input import preview
        return preview(data)

    def _find(self, ident):
        # Same validation order as the real bridge: malformed ids are 400, unknown ids 404.
        import re as _re
        require(isinstance(ident, str) and _re.fullmatch('[a-f0-9]{32}', ident or '') is not None, 'Invalid usage selection', 400)
        for i, user in enumerate(self.state['managed_users']):
            if user['id'] == ident:
                return i, user
        raise Problem(404, 'Unknown user')

    def op_accounting_user(self, data):
        from quota_models import quota_plan
        i, user = self._find(data.get('id'))
        usage = self._usage(user, i)
        return {'fixture': True, 'id': user['id'], 'name': user['name'], 'usage': usage, 'plan': quota_plan(user['quota']),
                'protocol_totals': [{'protocol': p, 'upload_bytes': 10**8 * (n + 1), 'download_bytes': 7 * 10**8 * (n + 1)} for n, p in enumerate(user['protocols'])],
                'portal': {}}

    def op_accounting_history(self, data):
        from usage_history import selection, axis
        i, user = self._find(data.get('id'))
        chosen = selection(data.get('selection') or {}, user.get('quota', {}).get('timezone', 'Asia/Hong_Kong'), time.time())
        rows = []
        for n, (point, left, right, label) in enumerate(axis(chosen)):
            if n < 3:
                up = down = None; state = 'before_collection'
            elif n % 9 == 4:
                up = down = None; state = 'unobserved'
            elif n % 13 == 6:
                up = 0; down = 0; state = 'recorded'
            else:
                up = 2 * 10**6 * (1 + (n * 7) % 13); down = 9 * 10**6 * (1 + (n * 5) % 17); state = 'partial' if n % 17 == 8 else 'recorded'
            rows.append(dict(time=point, start=left, end=right, label=label, up=up, down=down, state=state, observed_seconds=0))
        known = [r for r in rows if r['up'] is not None]
        return {**chosen, 'fixture': True, 'buckets': rows, 'totals': {'upload_bytes': sum(r['up'] for r in known) if known else None,
                'download_bytes': sum(r['down'] for r in known) if known else None}, 'incomplete': True,
                'collection_started_at': rows[3]['start'] if len(rows) > 3 else None, 'sampled_at': time.time(), 'source': 'FIXTURE synthetic history',
                'retention': {'days': 90, 'hourly_days': 7, 'local_day_bins_days': 90}, 'legacy_utc_daily': [], 'legacy_note': '', 'totals_note': ''}

    def op_webui_guard(self, data):
        return {'fixture': True, 'guard': {'state': 'unknown', 'fixture': True}}

    def op_capabilities(self, data):
        return capabilities(self.state['sing_box']['version'], self.variant)

    def op_version(self, data):
        return {'manager_version': '2026.10.24.2-fixture', 'manager_build_id': 'b-fixture', 'core_version': self.core, 'expected_core_version': self.state['sing_box']['version'], 'variant': self.variant, 'fixture': True}

    def op_certificate(self, data):
        return {'domain': self.state['domain'], 'mode': self.state['certificate']['mode'], 'expires_at': self.cert_expires, 'starts_at': self.cert_expires - 90 * 86400,
                'issuer': 'C = US, O = FIXTURE, CN = Fixture CA (not public)', 'source': 'FIXTURE certificate; not a public-chain reachability proof', 'sampled_at': time.time(), 'fixture': True}

    def op_inbounds(self, data):
        tags = {'reality': ('reality-in', 'vless', 'tcp'), 'vmess': ('vmess-ws-in', 'vmess', 'tcp'), 'hy2': ('hy2-in', 'hysteria2', 'udp'), 'tuic': ('tuic-in', 'tuic', 'udp'), 'anytls': ('anytls-in', 'anytls', 'tcp')}
        rows = []
        for p, (tag, kind, net) in tags.items():
            v = self.state['protocols'][p]
            if not v['enabled']:
                continue
            users = [u for u in self.state['managed_users'] if u['enabled'] and p in u['protocols']]
            rows.append(dict(id=tag, type=kind, listen='::', port=v['port'], network=net, tls=p != 'reality' or True, transport='ws' if p == 'vmess' else 'native',
                             user_count=1 + len(users), user_names=['Original shared identity'] + [u['name'] for u in users[:5]], protected=self.variant == 'zgocloud',
                             listening=self.listening.get(p, False) and self.service_state == 'active'))
        aliases = [dict(kind='NAT alias', protocol=n, range=self.state['protocols'][n]['udp_range'], target_port=self.state['protocols'][n]['port'], network='udp')
                   for n in ('hy2', 'tuic') if self.state['protocols'][n].get('udp_range') and self.state['protocols'][n]['enabled']]
        return dict(inbounds=rows, aliases=aliases, source='FIXTURE inbound inventory', sampled_at=time.time(),
                    protocols={p: {'enabled': v['enabled'], 'port': v['port']} for p, v in self.state['protocols'].items()}, fixture=True)

    def op_users(self, data):
        rows = [dict(id='legacy', name=self.protected_name or ('Legacy shared identity' if self.variant == 'zgocloud' else 'Original installer identity'),
                     protected=True, enabled=True, tags=[], protocols=[p for p in PROTOCOLS if self.state['protocols'][p]['enabled']])]
        rows.extend({'id': u['id'], 'name': u['name'], 'enabled': u['enabled'], 'tags': u['tags'], 'protocols': list(u['protocols'])} for u in self.state['managed_users'])
        return rows

    def op_endpoints(self,data):
        from network_policy import endpoint_options
        return endpoint_options(self.state)

    def op_network(self,data):
        from network_policy import effective,endpoint_options
        s=self.state['server']
        return {'server':s,'domain':self.state['domain'],'effective':effective(s),'addresses':[{'interface':'fixture0','address':v,'family':f,'global_unicast':True,'usable':True,'scope':'global'} for f,v in [(4,s['ipv4']),(6,s['ipv6'])]],'routes':{'ipv4':[{'dev':'fixture0'}],'ipv6':[{'dev':'fixture0'}]},'endpoint_preflight':{'families':{'ipv4':{'records':[s['ipv4']]},'ipv6':{'records':[s['ipv6']]}},'errors':[],'warnings':[]},'endpoints':endpoint_options(self.state),'https':{'listen':'0.0.0.0','port':9443,'origin':'https://panel.sbox.test:9443'},'fixture':True}

    def op_policy(self, data):
        return self.state.get('client_policy', {'primary': 'tuic'})

    def op_firewall(self, data):
        # Same JSON shapes as the real managers' `firewall ports json`.
        rows = [{'name': p, 'protocol': 'udp' if p in ('hy2', 'tuic') else 'tcp', 'port': v['port']} for p, v in self.state['protocols'].items() if v['enabled']]
        if self.variant == 'zgocloud':
            hops = [{'name': n, 'range': self.state['protocols'][n]['udp_range'], 'main_port': self.state['protocols'][n]['port']} for n in ('hy2', 'tuic') if self.state['protocols'][n].get('udp_range')]
            return {'protocol_ports': rows, 'udp_hop_ranges': hops}
        hy2 = self.state['protocols']['hy2']
        return {'protocol_ports': rows, 'hysteria2_hop_range': {'protocol': 'udp', 'range': hy2['udp_range']} if hy2.get('udp_range') and hy2['enabled'] else None}

    def op_firewall_status(self, data):
        return {'text': 'FIXTURE: owned nft table inet sbox_manager present; SSH port 22 allowed', 'fixture': True}

    def op_bans(self, data):
        return {'text': 'FIXTURE: no active bans', 'fixture': True}

    def op_security(self, data):
        return {'text': 'FIXTURE: Fail2Ban jail sbox-sshd active', 'fixture': True}

    def op_performance(self, data):
        return {'fixture': True, 'note': 'FIXTURE performance inventory'}

    def op_backups(self, data):
        return {'backups': [{'name': 'sbox-backup-20261024-080000.tar.gz', 'bytes': 18234, 'created': time.time() - 3600, 'sha256': '0' * 64}]}

    def op_logs(self, data):
        search = data.get('search', '')
        lines = ['FIXTURE sing-box started', 'FIXTURE inbound/vless[reality-in]: tcp server started at [::]:443', 'FIXTURE <img src=x onerror=alert(1)> log escaping probe']
        return {'text': '\n'.join(l for l in lines if search.casefold() in l.casefold()), 'sampled_at': time.time(), 'limit': 200, 'fixture': True}

    def op_doctor(self, data):
        active = self.service_state == 'active'
        checks = [
            {'status': 'ok', 'label': 'runtime directory recreated and writable'},
            {'status': 'ok', 'label': 'no interrupted transaction pending recovery (run: sbox recover)'},
            {'status': 'ok', 'label': 'state schema and values'},
            {'status': 'ok', 'label': 'sing-box server config'},
            {'status': 'ok' if active else 'fail', 'label': 'service active'},
            {'status': 'ok', 'label': 'firewall helper active'},
            {'status': 'ok', 'label': 'SSH Fail2Ban and early IPv4/IPv6 guard (security setup required after policy upgrade)'},
            {'status': 'ok', 'label': 'firewall rules'},
        ] + [{'status': 'ok' if active and self.listening.get(p) else 'fail', 'label': '%s listener %s/%s owned by sing-box' % (p, v['port'], 'udp' if p in ('hy2', 'tuic') else 'tcp')} for p, v in self.state['protocols'].items() if v['enabled']] + [
            {'status': 'ok', 'label': 'certificate currently valid'},
            {'status': 'ok', 'label': 'TLS server certificate chain and EKU trusted'},
            {'status': 'warn' if self.cert_expires < time.time() + 7 * 86400 else 'ok', 'label': 'certificate valid for more than 7 days'},
            {'status': 'info', 'label': 'systemd NRestarts=0 MemoryCurrent=31457280'},
        ]
        failures = sum(1 for c in checks if c['status'] == 'fail')
        return {'failures': failures, 'warnings': sum(1 for c in checks if c['status'] == 'warn'), 'checks': checks, 'required_ports': self.op_firewall({}), 'exit_code': 1 if failures else 0, 'sampled_at': time.time(), 'fixture': True}

    def op_change_preview(self, data):
        change = self.changes.get(data.get('token'))
        require(change is not None, 'Unknown or consumed preview', 404)
        return {'kind': change['request']['kind'], 'expires_at': change['created'] + 600}

    def op_prepare(self, data):
        # Real controller candidate + preview summary code path.
        state = copy.deepcopy(self.state)
        state.pop('fixture', None)
        result = controller.candidate(state, data, self.variant)
        if hasattr(controller, 'preview'):
            preview = controller.preview(state, result, data, self.variant)
        else:  # baseline controller (pre-2026.10.25) has no structured preview
            preview = {'diff': 'FIXTURE diff', 'restart': data.get('kind') != 'policy', 'warning': 'Core changes restart sing-box and interrupt active connections.'}
        token = secrets.token_hex(32)
        self.changes[token] = {'request': data, 'state': result, 'before': self.fingerprint(), 'created': time.time()}
        preview.update(token=token, expires_at=int(time.time()) + 600)
        return preview

    def op_commit(self, data):
        change = self.changes.pop(data.get('token'), None)
        require(change is not None, 'Unknown or consumed change token', 422)
        require(change['before'] == self.fingerprint(), 'State changed since preview; prepare again', 409)
        change['state']['fixture'] = True
        self.state = change['state']
        self.version += 1
        return {'committed': True, 'kind': change['request']['kind'], 'committed_at': time.time(), 'state_fingerprint': self.fingerprint()[:16],
                'service_active': self.service_state == 'active', 'restarted': change['request']['kind'] != 'policy', 'fixture': True}

    def op_export(self, data):
        name = 'legacy' if data['id'] == 'legacy' else next(u['name'] for u in self.state['managed_users'] if u['id'] == data['id'])
        if data['format'] == 'links':
            host = {'ipv4': '192.0.2.10', 'ipv6': '[2001:db8::10]'}.get(data.get('endpoint', 'auto'), 'vpn.example.test')
            # Synthetic single-node URIs (RFC 5737/3849 documentation addresses), one per protocol.
            return {'content': '\n'.join([
                'vless://00000000-0000-4000-8000-000000000001@%s:443?security=reality&sni=www.example.test#vless-%s' % (host, name),
                'vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MtZml4dHVyZSJ9',
                'hysteria2://fixture-password@%s:8443/?sni=vpn.example.test#hysteria2-%s' % (host, name),
                'tuic://00000000-0000-4000-8000-000000000002:fixture@%s:9443?alpn=h3#tuic5-%s' % (host, name),
                'anytls://fixture-password@%s:10443?sni=vpn.example.test#anytls-%s' % (host, name)]) + '\n'}
        return {'content': '# FIXTURE export for %s (%s, %s, %s)\nproxies: []\n' % (name, data['profile'], data['format'], data.get('endpoint', 'auto'))}

    def _action(self, name):
        return {'text': 'FIXTURE action %s completed' % name, 'fixture': True}

    def op_backup(self, data):
        return self._action('backup')

    def op_firewall_apply(self, data):
        return self._action('firewall-apply')

    def op_security_repair(self, data):
        return self._action('security-repair')

    def op_renew_test(self, data):
        return self._action('renew-test')

    def op_unban(self, data):
        return self._action('unban')

    def op_restart(self, data):
        return self._action('restart')

    def op_recover(self, data):
        return self._action('recover')

    def op_update_preview(self, data):
        return {'version': 'v' + data['version'], 'published_at': None, 'changelog': 'FIXTURE changelog', 'source': 'fixture', 'warning': 'fixture'}
