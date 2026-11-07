"""Pure, unit-testable monitoring logic: host rate series, dashboard summary,
deduplicated alert rules, guided doctor layers and protocol health.

Nothing here invents a measurement. Every value carries its source and the
time it was sampled; anything that was not measured is reported as
``unknown`` with the reason.
"""
import math
import hashlib
import re
import time

VIRTUAL_PREFIXES = ('lo', 'veth', 'docker', 'br-', 'virbr', 'ifb', 'dummy', 'cni', 'flannel', 'kube', 'vnet', 'tap')
STALE_AFTER = 120  # seconds: a sample older than this is shown as stale


def selected_range(query, now=None):
    """Bound a named live window or explicit UTC epoch range to retained history."""
    now = time.time() if now is None else now
    window = query.get('window', '1h')
    presets = {'1h':3600, '6h':21600, '24h':86400, '7d':604800, '30d':2592000}
    if window in presets:
        if set(query) - {'window'}: raise ValueError('Unexpected range fields')
        return presets[window], now
    if window != 'custom' or set(query) != {'window','start','end'}:
        raise ValueError('Invalid monitoring range')
    start, end = float(query['start']), float(query['end'])
    if not all(math.isfinite(v) for v in (start,end)) or not now-30*86400 <= start < end <= now+5:
        raise ValueError('Custom range must be within the last 30 days')
    return end-start, end


def physical_interfaces(network):
    """Host interfaces counted in host-wide rates (virtual bridges/veth excluded
    to avoid double counting forwarded container traffic)."""
    return sorted(n for n in (network or {}) if not n.startswith(VIRTUAL_PREFIXES))


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return ordered[lo] if lo == hi else ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def rate_series(samples, window_seconds=3600, now=None, expected_interval=30):
    """Host receive/transmit rates from cumulative counter deltas.

    * A counter that decreases (interface reset, driver reload, reboot) never
      produces a negative or huge rate: that interval is dropped and counted.
    * A gap longer than 3.5 x the sampling interval is a gap, not a flat line.
    * Points are bucketed for long windows (5 min for 24 h, 1 h for 7 d).
      Gaps split buckets so observations on either side are never joined.
    * Latest rate and age always refer to the actual last measured interval,
      independently of the chart's aggregation window.
    """
    now = now or time.time()
    samples = [s for s in samples if s.get('sampled_at') and s['sampled_at'] >= now - window_seconds and isinstance(s.get('network'), dict)]
    samples.sort(key=lambda s: s['sampled_at'])
    raw, resets, gaps, used = [], 0, 0, set()
    for prev, cur in zip(samples, samples[1:]):
        dt = cur['sampled_at'] - prev['sampled_at']
        if dt <= 0:
            continue
        effective_interval=max(expected_interval,600 if cur['sampled_at']<now-86400 else 30,3600 if cur['sampled_at']<now-7*86400 else 30)
        if dt > effective_interval * 3.5:
            gaps += 1
            raw.append({'t': cur['sampled_at'], 'gap': True})
            continue
        if cur.get('uptime_seconds') is not None and prev.get('uptime_seconds') is not None and cur['uptime_seconds'] + 1 < prev['uptime_seconds']:
            resets += 1  # host rebooted between samples
            continue
        rx = tx = 0
        counted = False
        reset_here = False
        for name in physical_interfaces(cur['network']):
            a, b = prev['network'].get(name), cur['network'].get(name)
            if not a or not b:
                continue
            if b['rx'] < a['rx'] or b['tx'] < a['tx']:
                reset_here = True
                continue
            rx += b['rx'] - a['rx']; tx += b['tx'] - a['tx']; counted = True; used.add(name)
        if reset_here:
            resets += 1
        if counted:
            raw.append({'t': cur['sampled_at'], 'rx_bps': rx / dt, 'tx_bps': tx / dt})
    bucket = 0 if window_seconds <= 3600 else 300 if window_seconds <= 86400 else 3600
    points = raw
    if bucket:
        points = []

        def append_group(group):
            if group:
                count = group['count']
                # Place the average within its observed times, not at a bucket
                # centre that can fall beyond a gap or even in the future.
                points.append({'t': group['t'] / count,
                               'rx_bps': group['rx'] / count,
                               'tx_bps': group['tx'] / count})

        group = None
        for p in raw:
            if p.get('gap'):
                append_group(group)
                group = None
                points.append(p)
                continue
            key = int(p['t'] // bucket * bucket)
            if group is None or group['bucket'] != key:
                append_group(group)
                group = {'bucket': key, 't': 0, 'rx': 0, 'tx': 0, 'count': 0}
            group['t'] += p['t']
            group['rx'] += p['rx_bps']
            group['tx'] += p['tx_bps']
            group['count'] += 1
        append_group(group)
    values = [p for p in points if not p.get('gap')]
    rx_values = [p['rx_bps'] for p in values]; tx_values = [p['tx_bps'] for p in values]
    latest = next((p for p in reversed(raw) if not p.get('gap')), None)
    return {
        'window_seconds': window_seconds, 'start': now - window_seconds, 'end': now,
        'bucket_seconds': bucket or expected_interval, 'points': points,
        'samples': len(samples), 'resets_dropped': resets, 'gaps': gaps, 'interfaces': sorted(used),
        'latest': latest, 'latest_age_seconds': (now - latest['t']) if latest else None,
        'stats': {'rx_p50': percentile(rx_values, .5), 'rx_p95': percentile(rx_values, .95), 'rx_max': max(rx_values) if rx_values else None,
                  'tx_p50': percentile(tx_values, .5), 'tx_p95': percentile(tx_values, .95), 'tx_max': max(tx_values) if tx_values else None},
        'unit': 'bytes per second (host-wide, all listed interfaces, includes non-VPN traffic)',
        'source': 'Linux /proc/net/dev cumulative counters sampled by the panel; counter decreases and reboots are dropped, not interpolated',
    }


def _age_status(sampled_at, now):
    if not sampled_at:
        return 'unknown'
    return 'stale' if now - sampled_at > STALE_AFTER else 'fresh'


def _days(seconds):
    return None if seconds is None else seconds / 86400


def dashboard(overview, certificate, inbounds=None, alerts=(), last_change=None, rates=None, panel=None, now=None):
    """Human-oriented, source-labelled overview. Raw payloads stay available
    separately under ``advanced``."""
    now = now or time.time()
    svc = overview.get('service') or {}
    active = svc.get('ActiveState') == 'active'
    sampled = overview.get('sampled_at')
    freshness = _age_status(sampled, now)
    core_version = overview.get('core_version')
    expected = overview.get('expected_core_version')
    tiles = []

    def tile(key, label, status, value, detail, source, sampled_at=None):
        tiles.append({'key': key, 'label': label, 'status': status, 'value': value, 'detail': detail, 'source': source, 'sampled_at': sampled_at or sampled})

    if freshness == 'stale':
        core_status = 'unknown'
    else:
        core_status = 'ok' if active else 'error'
    tile('core', 'VPN core', core_status, 'Running' if active else (svc.get('ActiveState') or 'unknown').capitalize(),
         {'pid': svc.get('MainPID'), 'sub_state': svc.get('SubState'), 'since': svc.get('ExecMainStartTimestamp'), 'version': core_version, 'expected_version': expected,
          'version_matches': (core_version == expected) if core_version and expected else None, 'restarts': svc.get('NRestarts')},
         'systemd sing-box.service + sing-box version')
    family = overview.get('deployment_family') or {}
    if family:
        tile('network', 'Network mode', 'info', 'advanced' if family.get('policies') else family.get('mode', 'preserve'), family,
             'saved deployment policy; OS addresses are independent')
    panel = panel or {}
    tile('panel', 'Admin panel', 'ok', 'Serving', {'version': panel.get('version'), 'uptime_seconds': panel.get('uptime_seconds'), 'pid': panel.get('pid')},
         'this panel process (separate from the VPN core)', now)
    cert = certificate or {}
    expires = cert.get('expires_at')
    if expires:
        days = _days(expires - now)
        cert_status = 'error' if days < 3 else 'warning' if days < 14 else 'ok'
        cert_value = ('Expired' if days < 0 else '%d days left' % math.floor(days))
    else:
        days, cert_status, cert_value = None, ('unknown' if cert.get('mode') not in (None, 'none') else 'ok'), ('Not used' if cert.get('mode') in (None, 'none') else 'Unknown')
    timers = overview.get('renewal_timers') or {}
    certbot = timers.get('certbot.timer') or {}
    renewal = 'not-required' if cert.get('mode') not in ('certbot-http01', 'certbot-dns-cloudflare') else ('scheduled' if certbot.get('ActiveState') == 'active' else 'unavailable')
    tile('certificate', 'Certificate', cert_status, cert_value,
         {'domain': cert.get('domain'), 'issuer': cert.get('issuer'), 'expires_at': expires, 'days_left': days, 'mode': cert.get('mode'),
          'renewal': renewal, 'next_renewal_check': certbot.get('NextElapseUSecRealtime') or None,
          'public_trust': 'not verified from the Internet by this panel'}, cert.get('source') or 'openssl x509', cert.get('sampled_at'))
    if inbounds is not None:
        rows = inbounds.get('inbounds', [])
        missing = [r['id'] for r in rows if not r.get('listening')]
        tile('listeners', 'Listeners', 'unknown' if not active else ('error' if missing else 'ok'),
             '%d of %d listening' % (len(rows) - len(missing), len(rows)), {'missing': missing, 'aliases': inbounds.get('aliases', [])},
             'ss local socket inventory (local only)', inbounds.get('sampled_at'))
    tile('external', 'Internet reachability', 'unknown', 'Not tested',
         {'reason': 'A server cannot prove that clients on other networks can reach it. Test from a real client on mobile data and home broadband.'},
         'no external probe configured')
    mem_total, mem_avail = overview.get('memory_total_bytes'), overview.get('memory_available_bytes')
    disk_total, disk_avail = overview.get('disk_total_bytes'), overview.get('disk_available_bytes')
    resources = {
        'cpu': {'percent': overview.get('cpu_percent'), 'load_average': overview.get('load_average'), 'cpus': overview.get('cpu_count'),
                'source': '/proc/stat delta between two samples (host-wide)'},
        'memory': {'used_bytes': (mem_total - mem_avail) if mem_total and mem_avail is not None else None, 'total_bytes': mem_total, 'available_bytes': mem_avail,
                   'core_rss_bytes': overview.get('core_rss_bytes'), 'source': '/proc/meminfo MemAvailable (host-wide)'},
        'disk': {'used_bytes': (disk_total - disk_avail) if disk_total and disk_avail is not None else None, 'total_bytes': disk_total, 'available_bytes': disk_avail,
                 'source': 'statvfs of /etc/sbox-manager filesystem'},
        'uptime_seconds': overview.get('uptime_seconds'),
    }
    open_alerts = [a for a in alerts if a.get('resolved_at') is None]
    worst = 'ok'
    for t in tiles:
        if t['key'] == 'external':
            continue
        if t['status'] == 'error':
            worst = 'error'
        elif t['status'] in ('warning', 'unknown') and worst == 'ok':
            worst = 'warning'
    if any(a['severity'] == 'critical' for a in open_alerts):
        worst = 'error'
    elif open_alerts and worst == 'ok':
        worst = 'warning'
    return {
        'status': worst, 'sampled_at': sampled, 'freshness': freshness, 'tiles': tiles, 'resources': resources,
        'traffic': rates, 'alerts': open_alerts[:8], 'alert_count': len(open_alerts),
        'last_change': last_change, 'last_validation': overview.get('last_validated_check'),
        'recent_errors': overview.get('recent_errors'), 'pending_transaction': overview.get('pending_transaction'),
        'notes': ['Host counters include all services and are not per-user VPN accounting.',
                  'Local checks do not prove Internet, ISP or mobile-network reachability.'],
        'source': overview.get('source'), 'fixture': bool(overview.get('fixture')),
    }


def evaluate_alerts(overview, certificate, inbounds, login_failures, doctor=None, now=None):
    """Return (family_keys_evaluated, active) where active maps key ->
    (severity, title, detail, source). Keys of an evaluated family that are
    absent from ``active`` are resolved by the caller."""
    now = now or time.time()
    active, families = {}, {'core', 'cert', 'disk', 'memory', 'errors', 'txn', 'auth', 'version'}
    svc = overview.get('service') or {}
    if svc.get('ActiveState') != 'active':
        active['core.down'] = ('critical', 'VPN core is not running', 'sing-box.service state: %s/%s' % (svc.get('ActiveState'), svc.get('SubState')), 'systemd')
    elif overview.get('core_version') and overview.get('expected_core_version') and overview['core_version'] != overview['expected_core_version']:
        active['version.drift'] = ('warning', 'Core version differs from the managed version', 'running %s, state expects %s' % (overview['core_version'], overview['expected_core_version']), 'sing-box version + manager state')
    errors = (overview.get('recent_errors') or {}).get('count') or 0
    if errors >= 20:
        active['errors.burst'] = ('warning', 'Many VPN core errors in the last hour', '%d error entries (capped at 200)' % errors, 'journalctl -p err')
    cert = certificate or {}
    if cert.get('expires_at'):
        days = (cert['expires_at'] - now) / 86400
        if days < 0:
            active['cert.expiry'] = ('critical', 'Certificate has expired', '%s expired %s days ago' % (cert.get('domain'), int(-days)), 'openssl x509')
        elif days < 3:
            active['cert.expiry'] = ('critical', 'Certificate expires within 3 days', '%s: %.1f days left' % (cert.get('domain'), days), 'openssl x509')
        elif days < 14:
            active['cert.expiry'] = ('warning', 'Certificate expires within 14 days', '%s: %.0f days left; check ACME renewal' % (cert.get('domain'), days), 'openssl x509')
    if 'cert.expiry' in active:
        severity,title,detail,source=active['cert.expiry']
        deadline=time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(cert['expires_at']))
        active['cert.expiry']=(severity,title,detail+'; expires '+deadline,source)
    if cert.get('mode') in ('certbot-http01', 'certbot-dns-cloudflare'):
        timer = ((overview.get('renewal_timers') or {}).get('certbot.timer') or {}).get('ActiveState')
        if timer != 'active':
            active['cert.timer'] = ('warning', 'Automatic certificate renewal timer is not active', 'certbot.timer: %s' % (timer or 'unknown'), 'systemctl show certbot.timer')
    total, avail = overview.get('disk_total_bytes'), overview.get('disk_available_bytes')
    if total and avail is not None:
        free = avail / total
        if free < 0.05:
            active['disk.space'] = ('critical', 'Disk almost full', '%.1f%% free' % (free * 100), 'statvfs')
        elif free < 0.10:
            active['disk.space'] = ('warning', 'Disk space low', '%.1f%% free' % (free * 100), 'statvfs')
    mt, ma = overview.get('memory_total_bytes'), overview.get('memory_available_bytes')
    if mt and ma is not None and ma / mt < 0.10:
        active['memory.low'] = ('warning', 'Available memory low', '%.1f%% available' % (ma / mt * 100), '/proc/meminfo')
    if overview.get('pending_transaction'):
        active['txn.pending'] = ('warning', 'An interrupted change awaits recovery', 'Run "sbox recover" or use System → Recover transaction', 'manager transaction journal')
    if login_failures >= 10:
        active['auth.failures'] = ('warning', 'Repeated failed sign-ins', '%d failed sign-in or re-authentication attempts in 15 minutes' % login_failures, 'panel audit log')
    if inbounds is not None and svc.get('ActiveState') == 'active':
        families.add('listener')
        for row in inbounds.get('inbounds', []):
            if not row.get('listening'):
                active['listener.' + row['id']] = ('critical', 'Listener missing: %s port %s/%s' % (row['type'], row['port'], row['network']),
                                                   'Enabled inbound is not listening locally', 'ss socket inventory')
    if doctor is not None:
        families.add('doctor')
        failed = [c['label'] for c in doctor.get('checks', []) if c.get('status') == 'fail']
        firewall = [l for l in failed if 'firewall' in l.lower() or 'nat' in l.lower()]
        if firewall:
            active['doctor.firewall'] = ('warning', 'Firewall or NAT rules differ from the managed state', '; '.join(firewall)[:500], 'manager doctor --json')
        others = [l for l in failed if l not in firewall]
        if others:
            active['doctor.failures'] = ('warning', 'Doctor reported %d failing check(s)' % len(others), '; '.join(others)[:500], 'manager doctor --json')
    families.add('probe')
    for row in overview.get('probes',[]):
        if not row.get('target') or now-row.get('sampled_at',0)>180:continue
        ident=hashlib.sha256((str(row.get('kind'))+':'+row['target']+':'+str(row.get('port',443))).encode()).hexdigest()[:16]
        source='Optional network probe originating on this VPS; not the end-user Internet path'
        if row.get('status')=='unavailable':active['probe.'+ident+'.unavailable']=('warning','Network probe unavailable',row['target']+'; '+row.get('reason','No result'),source)
        if row.get('latency_ms') is not None and row['latency_ms']>250:active['probe.'+ident+'.latency']=('warning','Network probe latency above 250 ms',row['target']+': '+str(row['latency_ms'])+' ms',source)
        if row.get('loss_percent') is not None and row['loss_percent']>=10:active['probe.'+ident+'.loss']=('warning','Network probe loss/failure rate at least 10%',row['target']+': '+str(row['loss_percent'])+'%; TCP/TLS measures connection failures, ICMP measures packet loss',source)
        if row.get('dns_mismatch'):active['probe.'+ident+'.dns']=('warning','DNS answers differ from configured expected public IPs',row['target']+'; inspect Monitoring probe results',source)
    return families, active


DOCTOR_LAYERS = [
    # (layer, pattern, likely cause, next action, CLI)
    ('Manager', r'runtime directory|manager|helpers|public sbox CLI', 'Manager files or helpers changed outside a transaction.', 'Repair the installation from the standalone installer or run the CLI repair.', 'sudo sbox repair'),
    ('Transaction', r'interrupted transaction', 'A previous change stopped part-way.', 'Recover the journalled transaction before making other changes.', 'sudo sbox recover'),
    ('Configuration', r'state schema|server JSON|sing-box server config|Mihomo|links export|certificate requirement rule', 'The stored configuration failed validation.', 'Inspect the failing item, then restore the last backup if it was edited by hand.', 'sudo sbox doctor'),
    ('Service', r'service active|service enabled|PID/restart|systemd NRestarts|sing-box is not active', 'The VPN core is stopped, crashing or not enabled for reboot.', 'Read the core log, fix the reported error, then restart the core.', 'sudo journalctl -u sing-box -n 80'),
    ('Firewall & NAT', r'firewall', 'Owned firewall/NAT rules are missing or the firewall helper is not running.', 'Reconcile the owned rules. Provider security groups must be checked in the provider console.', 'sudo sbox firewall apply'),
    ('SSH guard', r'SSH|Fail2Ban|jail', 'Fail2Ban or the SSH guard is not active.', 'Repair the SSH guard. This does not restart SSH.', 'sudo sbox security repair'),
    ('Listeners', r'listener', 'An enabled inbound is not listening; another process may hold the port.', 'Check which process owns the port, then restart the core.', 'sudo ss -lntup'),
    ('TLS certificate', r'certificate|TLS', 'The certificate is missing, expired, not trusted or does not cover the domain.', 'Check DNS and port 80 for ACME, then renew the certificate.', 'sudo sbox renew-test'),
    ('Logs', r'fatal|OOM|log signatures', 'The core logged fatal or resource errors.', 'Read the log entries and check memory and file-descriptor limits.', 'sudo journalctl -u sing-box --since -1h'),
]


def guided_doctor(raw):
    """Group manager doctor checks into layers with likely cause/next action."""
    layers = {}
    for check in raw.get('checks', []):
        label = check.get('label', '')
        for layer, pattern, cause, action, cli in DOCTOR_LAYERS:
            if re.search(pattern, label, re.I):
                break
        else:
            layer, cause, action, cli = 'Other', 'See the check label.', 'Run the full doctor from a root shell.', 'sudo sbox doctor'
        entry = layers.setdefault(layer, {'layer': layer, 'status': 'ok', 'checks': [], 'likely_cause': None, 'next_action': None, 'cli': cli})
        entry['checks'].append({'status': check.get('status'), 'label': label})
        if check.get('status') == 'fail':
            entry['status'] = 'error'; entry['likely_cause'] = cause; entry['next_action'] = action
        elif check.get('status') == 'warn' and entry['status'] == 'ok':
            entry['status'] = 'warning'; entry['likely_cause'] = cause; entry['next_action'] = action
    order = [l[0] for l in DOCTOR_LAYERS] + ['Other']
    result = sorted(layers.values(), key=lambda e: order.index(e['layer']))
    result.append({'layer': 'Provider network', 'status': 'unknown', 'checks': [{'status': 'info', 'label': 'Provider security group / upstream firewall cannot be read from inside the server'}],
                   'likely_cause': None, 'next_action': 'Confirm the required ports below are allowed in the provider console, then test from a real client.', 'cli': None})
    result.append({'layer': 'DNS / CA / ISP', 'status': 'unknown', 'checks': [{'status': 'info', 'label': 'Public DNS, CA reachability and ISP filtering are external and were not tested'}],
                   'likely_cause': None, 'next_action': 'Use Certificates → Readiness for DNS answers; test clients on mobile data and home broadband.', 'cli': None})
    return {'layers': result, 'failures': raw.get('failures'), 'warnings': raw.get('warnings'), 'required_ports': raw.get('required_ports'),
            'sampled_at': raw.get('sampled_at'), 'exit_code': raw.get('exit_code'), 'mutating': False,
            'note': 'Doctor only reads state. It never changes SSH, firewall or the VPN core.'}


def protocol_health(inbounds, certificate, probes, now=None):
    now = now or time.time()
    cert = certificate or {}
    cert_ok = bool(cert.get('expires_at') and cert['expires_at'] > now)
    rows = []
    for row in inbounds.get('inbounds', []):
        probe = (probes or {}).get(row['id'])
        tls_kind = 'REALITY (camouflage target is external)' if row['type'] == 'vless' else ('TLS' if row.get('tls') else 'none')
        rows.append({
            'id': row['id'], 'type': row['type'], 'port': row['port'], 'network': row['network'], 'transport': row.get('transport'),
            'listening': row.get('listening'), 'users': row.get('user_count'), 'tls': tls_kind,
            'certificate': None if row['type'] == 'vless' else ('valid' if cert_ok else 'invalid-or-unknown'),
            'local_probe': probe or {'status': 'not-run', 'detail': 'Run a local probe to check this listener'},
            'external_probe': {'status': 'not-run', 'detail': 'No client on another network has tested this port'},
        })
    aliases = []
    for alias in inbounds.get('aliases', []):
        target = next((r for r in rows if r['network'] == 'udp' and r['port'] == alias['target_port']), None)
        aliases.append({**alias, 'target_listening': target['listening'] if target else None,
                        'note': 'NAT alias to the inbound above, not a separate listener. Rule presence is checked by Doctor; packet delivery from the Internet is not tested here.'})
    return {'protocols': rows, 'aliases': aliases, 'sampled_at': inbounds.get('sampled_at'),
            'source': 'manager configuration + ss socket inventory + optional local probe (loopback only)'}


def accounting_health(value, health, now=None):
    """A running VPN is not proof that usage and quotas are being collected."""
    now = time.time() if now is None else now
    health = health if isinstance(health, dict) else {}
    stamp = health.get('sampled_at')
    poll = health.get('poll_seconds', 2)
    if type(poll) not in (int, float) or not 0 < poll <= 3600:
        poll = 2
    fresh = type(stamp) in (int, float) and -1 <= now - stamp <= max(15, poll * 3)
    ready = health.get('status') == 'ready' and fresh
    reason = health.get('reason') or ('Usage collector heartbeat is stale' if not fresh else 'Usage collector is unavailable')
    value['tiles'].append({'key': 'accounting', 'label': 'Usage tracking', 'status': 'ok' if ready else 'warning',
                           'value': 'Collecting' if ready else 'Needs attention',
                           'detail': {'reason': '' if ready else reason, 'sampled_at': stamp,
                                      'note': 'Quotas are enforced periodically; the configured failure policy is unchanged.'},
                           'source': 'authenticated accounting collector heartbeat', 'sampled_at': stamp})
    if not ready and value['status'] == 'ok':
        value['status'] = 'warning'
    return value
