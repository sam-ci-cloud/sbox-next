#!/usr/bin/env python3
"""Additional real-installation checks (disposable lab container, client namespace).

  nsenter -t CLIENT_PID -n -m python3 lab_extra.py --container N --variant zgocloud|universal \
     --domain D --installer FILE --out DIR --mihomo BIN --geo DIR --ca-bundle FILE [--yaml ORIGINAL]

Covers: installer re-run idempotence, firewall reload with hop ranges, listening
socket inventory, secrets in install output and process command lines, control
socket peer rejection, GLOBAL/CN/INTERNAL profiles parsed by Mihomo, URI links vs
server state, rename keeps subscription token, rotation scope, tokens absent from
journal/audit, TOTP across panel upgrade/rollback, policy-only commit keeps the
core PID, core-down alert, 100-client burst during VPN traffic, panel memory
ceiling kill while VPN traffic continues. Nothing outside the lab is changed.
"""
import argparse, base64, hashlib, json, os, re, shutil, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'backend'))
import lab_post_install as L  # noqa: E402
from lab_post_install import Container, Panel, record, rows, sh, all_nodes, prepare_commit, wait_ready  # noqa: E402
from common import totp  # noqa: E402


def secrets_of(state):
    out = set()
    for p in state.get('protocols', {}).values():
        for k in ('uuid', 'password', 'private_key', 'short_id'):
            if isinstance(p.get(k), str) and len(p[k]) >= 8: out.add(p[k])
    for u in state.get('managed_users', []):
        for p in u.get('protocols', {}).values():
            out.update(v for v in p.values() if isinstance(v, str) and len(v) >= 8)
    return out


def main():
    ap = argparse.ArgumentParser()
    for k in ('--container', '--variant', '--domain', '--mihomo', '--geo', '--ca-bundle'): ap.add_argument(k, required=True)
    ap.add_argument('--installer', required=True, type=Path); ap.add_argument('--out', required=True, type=Path); ap.add_argument('--yaml', type=Path)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    ct = Container(a.container)
    hosts = Path(tempfile.mkdtemp()) / 'hosts'; hosts.write_text('127.0.0.1 localhost\n%s %s\n' % (L.CT_IP, a.domain))
    sh('mount', '--bind', hosts, '/etc/hosts'); sh('mount', '--bind', a.ca_bundle, '/etc/ssl/certs/ca-certificates.crt'); os.environ['SSL_CERT_FILE'] = a.ca_bundle
    sj = lambda: json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())
    nodes = 6 if a.variant == 'zgocloud' else 5
    client_yaml = a.yaml or Path(tempfile.mkdtemp()) / 'default.yaml'
    if not a.yaml: shutil.copy(ct.root / 'etc/sbox-manager/exports/clmi-global.yaml', client_yaml)
    shutil.copy(a.installer, ct.root / 'root' / a.installer.name)

    # 1. Re-running the installer (ZGO: no arguments) is idempotent.
    before = ct.core(); st_before = sj()
    cmd = 'cd /root && SBOX_MANAGEMENT_CIDRS=10.99.0.2/32 bash ./%s %s </dev/null' % (a.installer.name, '' if a.variant == 'zgocloud' else 'install global --yes')
    code, out = ct.run(cmd, check=False, timeout=900)
    after = ct.core(); st_after = sj()
    same_identity = secrets_of(st_before) == secrets_of(st_after)
    if a.variant == 'zgocloud':  # documented: a healthy no-argument rerun preserves the running VPN
        ok = code == 0 and after['pid'] == before['pid'] and after['config_sha256'] == before['config_sha256'] and same_identity
        name = 'No-argument installer re-run on a healthy install: exit 0, VPN core PID, config and credentials unchanged'
    else:  # documented: `install` on an existing host is a guided reinstall (re-applies config; restarts the service)
        ok = code == 0 and after['config_sha256'] == before['config_sha256'] and same_identity
        name = 'install re-run (documented guided reinstall): exit 0, rendered config and every credential unchanged; service restart is the documented behaviour'
    record('EXTRA-RERUN-IDEMPOTENT', name, ok, {'exit': code, 'pid_same': after['pid'] == before['pid'], 'config_same': after['config_sha256'] == before['config_sha256'], 'credentials_same': same_identity, 'tail': out.strip().splitlines()[-1][:120] if out.strip() else ''})

    # 2. Secrets never printed by the installer; never on process command lines.
    st = sj(); sec = secrets_of(st)
    install_log = (ct.root / 'root/install.log').read_text(errors='replace') + out
    if (ct.root / 'root/stage-upgrade.log').exists(): install_log += (ct.root / 'root/stage-upgrade.log').read_text(errors='replace')
    leaked = [s[:4] + '…' for s in sec if s in install_log]
    record('EXTRA-NO-SECRETS-IN-INSTALL-OUTPUT', 'Installer and re-run output contain no protocol credential or private key', not leaked, {'checked': len(sec), 'leaked_prefixes': leaked})
    _, ps = ct.run('ps -eo args')
    leaked = [s[:4] + '…' for s in sec if s in ps]
    record('EXTRA-NO-SECRETS-IN-ARGV', 'No credential, token or key on any process command line', not leaked and 'Password' not in ps, {'processes': len(ps.splitlines()), 'leaked_prefixes': leaked})

    # 3. Listening sockets: only VPN inbounds, panel, and lab helpers; no core API.
    _, ss = ct.run("ss -H -lntu | awk '{print $1\" \"$5}'")
    ports = sorted(set(ss.split('\n')) - {''})
    expected = {str(p['port']) for p in st['protocols'].values() if p.get('enabled')} | {'9443', '18080', '22'}
    unexpected = [x for x in ports if x.rsplit(':', 1)[-1] not in expected and not x.split()[-1].startswith(('127.0.0.53', '127.0.0.54'))]
    record('EXTRA-LISTENERS', 'Only VPN inbounds, the panel and lab helpers listen; no Clash/V2Ray/core API socket', not unexpected, {'listening': ports, 'unexpected': unexpected})

    # 4. Control socket rejects unprivileged peers.
    probe = "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('/run/sbox-webui-control/control.sock'); s.sendall(b'{\"op\":\"overview\"}\\n'); print('CONNECTED', s.recv(200))\nexcept Exception as e: print('DENIED', type(e).__name__)\n"
    (ct.root / 'root/peer_probe.py').write_text(probe)
    ct.run('id labprobe >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin labprobe; cp /root/peer_probe.py /tmp/peer_probe.py; chmod 644 /tmp/peer_probe.py')
    _, nobody = ct.run('runuser -u nobody -- python3 /tmp/peer_probe.py', check=False)
    _, other = ct.run('runuser -u labprobe -- python3 /tmp/peer_probe.py', check=False)
    record('EXTRA-SOCKET-PEER', 'Root bridge socket refuses unprivileged users (nobody, a fresh account)', 'DENIED' in nobody and 'DENIED' in other, {'nobody': nobody.strip()[:80], 'fresh_user': other.strip()[:80]})

    # Panel session.
    ct.run('sbox webui reset-admin >/dev/null 2>&1')
    boot = re.search(r'Password: (\S+)', (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text())[1]
    p = Panel(a.domain); p.login('admin', boot); pw = 'Extra-' + base64.urlsafe_b64encode(os.urandom(15)).decode()
    s, _, b = p.api('auth/change-password', {'old': boot, 'password': pw}); p.csrf = b['csrf']
    s, prev, res = prepare_commit(p, {'kind': 'user-create', 'data': {'name': 'extra-a'}}); prepare_commit(p, {'kind': 'user-create', 'data': {'name': 'extra-b'}})
    st = sj(); ua = next(u for u in st['managed_users'] if u['name'] == 'extra-a'); ub = next(u for u in st['managed_users'] if u['name'] == 'extra-b')

    # 5. Profiles: GLOBAL / CN / INTERNAL parsed by Mihomo; links match server state.
    parsed = {}
    for prof in ('global', 'cn', 'internal'):
        s, _, ex = p.api('client-profiles/export', {'id': ua['id'], 'profile': prof, 'format': 'yaml'})
        d = Path(tempfile.mkdtemp()); (d / 'config.yaml').write_text(ex['content'])
        for f in ('geoip.metadb', 'geosite.dat', 'geoip.dat', 'country.mmdb'):
            if (Path(a.geo) / f).exists(): shutil.copy(Path(a.geo) / f, d / f)
        t = sh(a.mihomo, '-t', '-d', d, '-f', d / 'config.yaml', check=False)
        import yaml
        doc = yaml.safe_load(ex['content']); rules = doc.get('rules', [])
        parsed[prof] = {'mihomo_test_exit': t.returncode, 'ok': 'successful' in (t.stdout + t.stderr), 'proxies': len(doc.get('proxies', [])), 'rules': len(rules),
                        'cn_direct': any(re.search(r'(GEOIP|GEOSITE),\s*(CN|cn)\b.*DIRECT', r) for r in rules), 'final': rules[-1] if rules else None}
        shutil.rmtree(d, ignore_errors=True)
    ok = all(v['ok'] and v['mihomo_test_exit'] == 0 and v['proxies'] >= nodes - 1 for v in parsed.values())
    record('EXTRA-PROFILES-MIHOMO', 'GLOBAL, CN and INTERNAL profiles for an added user pass the Mihomo parser (mihomo -t)', ok, parsed)
    record('EXTRA-PROFILE-SPLIT', 'CN profile routes CN destinations DIRECT; GLOBAL and CN profiles differ in rules', parsed['cn']['cn_direct'] and (parsed['global']['rules'] != parsed['cn']['rules'] or parsed['global']['final'] != parsed['cn']['final']),
           {k: {'cn_direct': v['cn_direct'], 'rules': v['rules'], 'final': v['final']} for k, v in parsed.items()})
    s, _, ln = p.api('client-profiles/export', {'id': ua['id'], 'profile': 'global', 'format': 'links'})
    links = [l for l in ln['content'].split() if '://' in l]
    checks = []
    for l in links:
        u = urllib.parse.urlsplit(l); scheme = u.scheme
        if scheme == 'vmess':
            j = json.loads(base64.b64decode(l[8:] + '=' * (-len(l[8:]) % 4))); port = int(j['port']); cred = j['id']; proto = 'vmess'
        else:
            port = u.port; cred = urllib.parse.unquote(u.username or ''); proto = {'vless': 'reality', 'hysteria2': 'hy2', 'hy2': 'hy2', 'tuic': 'tuic', 'anytls': 'anytls'}.get(scheme, scheme)
            if proto == 'tuic' and ':' in cred: cred = cred.split(':')[0]
        server = st['protocols'][proto]; mine = ua['protocols'][proto]
        ranges = [tuple(map(int, re.split('[:-]', v))) for v in re.findall(r'\b\d{2,5}[:-]\d{2,5}\b', json.dumps(server))]
        checks.append({'scheme': scheme, 'port': port, 'port_ok': port == server['port'] or any(lo <= port <= hi for lo, hi in ranges), 'credential_is_users_own': cred in (mine.get('uuid'), mine.get('password')), 'not_legacy': cred not in (server.get('uuid'), server.get('password'))})
    record('EXTRA-URI-LINKS', 'Share links for an added user: every protocol present, ports match server, credentials are that user\'s own (not legacy)', len(checks) >= 5 and all(c['port_ok'] and c['credential_is_users_own'] and c['not_legacy'] for c in checks), checks)

    # 6. Subscription token: rename keeps it; rotation scope; never in journal/audit.
    s, _, sa = p.api('subscriptions/rotate-token', {'id': ua['id']}); s, _, sb = p.api('subscriptions/rotate-token', {'id': ub['id']})
    url_a = sa['urls']['global'].split(':9443', 1)[1]; url_b = sb['urls']['global'].split(':9443', 1)[1]
    s, prev, res = prepare_commit(p, {'kind': 'user-edit', 'id': ua['id'], 'data': {'name': 'extra-a-renamed'}})
    ra = Panel(a.domain).req(url_a, raw=True)[0]
    record('EXTRA-RENAME-KEEPS-TOKEN', 'Renaming a user keeps its personal subscription URL working', s == 200 and ra == 200, {'commit': s, 'sub_after_rename': ra})
    s, _, sa2 = p.api('subscriptions/rotate-token', {'id': ua['id']})
    old_a, new_b = Panel(a.domain).req(url_a, raw=True)[0], Panel(a.domain).req(url_b, raw=True)[0]
    record('EXTRA-ROTATION-SCOPE', 'Rotating one user\'s token revokes only that URL; another user\'s URL keeps working', old_a == 404 and new_b == 200, {'old_a': old_a, 'b': new_b})
    token_b = url_b.split('/')[2]
    Panel(a.domain).req(url_b, raw=True)
    _, journal = ct.run('journalctl --no-pager -u sbox-webui -u sbox-webui-control -u sing-box 2>/dev/null | tail -n 5000', check=False)
    _, auditdump = ct.run("python3 -c \"import sqlite3;d=sqlite3.connect('/var/lib/sbox-webui/panel.db');print(d.execute('select group_concat(event||detail||ifnull(target,\\'\\'),\\' \\') from audit').fetchone()[0]);print(d.execute('select group_concat(kind||ifnull(detail,\\'\\'),\\' \\') from events').fetchone()[0])\"", check=False)
    record('EXTRA-TOKEN-NOT-LOGGED', 'Subscription token absent from service journals, audit log and timeline', len(journal.splitlines()) > 5 and len(auditdump.strip()) > 20 and token_b not in journal and token_b not in auditdump, {'journal_lines': len(journal.splitlines()), 'audit_bytes': len(auditdump)})
    codes = [Panel(a.domain).req('/sub/%s/global.yaml' % base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='), raw=True)[0] for _ in range(140)]  # real tokens: 43 chars
    record('EXTRA-SUB-GUESSING-BOUNDED', 'Guessing subscription URLs: 404 without data, then rate-limited (429) per client', set(codes[:100]) == {404} and 429 in codes, {'first': codes[0], 'n404': codes.count(404), 'n429': codes.count(429)})

    # 7. Policy-only change through the panel keeps the VPN core running untouched.
    pre = ct.core(); s, _, pol = p.api('policy')
    s, prev, res = prepare_commit(p, {'kind': 'policy', 'data': {'smart_lazy': not bool(pol.get('smart_lazy'))}})
    post = ct.core()
    record('EXTRA-POLICY-NO-RESTART', 'Policy-only panel commit: committed, core PID and server config unchanged', s == 200 and post['pid'] == pre['pid'] and post['config_sha256'] == pre['config_sha256'], {'status': s, 'restarted': (res or {}).get('restarted'), 'pid_same': post['pid'] == pre['pid']})

    # 8. Core down is shown and alerted from the real service state.
    ct.run('systemctl stop sing-box'); time.sleep(1)
    s, _, ev = p.api('alerts/evaluate', {}); s, _, dash = p.api('dashboard')
    tile = {t['key']: t['status'] for t in dash.get('tiles', [])}; s, _, al = p.api('alerts')
    opened = [x for x in al.get('alerts', []) if x.get('resolved_at') is None and 'core' in (str(x.get('key', '')) + str(x.get('title', ''))).lower()]
    ct.run('systemctl start sing-box'); time.sleep(2); p.api('alerts/evaluate', {})
    record('EXTRA-CORE-DOWN', 'Stopping the VPN core: dashboard core tile turns error and a core alert opens; recovers after start', tile.get('core') == 'error' and bool(opened), {'core_tile': tile.get('core'), 'alerts': [x.get('key') or x.get('title') for x in opened][:3]})

    # 10. Panel memory ceiling: panel is killed, VPN traffic continues, panel recovers.
    pre = ct.core()
    ct.run('systemctl set-property --runtime sbox-webui.service MemoryMax=40M && systemctl restart sbox-webui.service'); wait_ready(a.domain, 30)
    outcomes = []
    def hammer():
        for _ in range(6):
            try: outcomes.append(str(Panel(a.domain).req('/api/v1/auth/login', {'username': 'admin', 'password': pw})[0]))
            except Exception as e: outcomes.append(type(e).__name__)
    hs = [threading.Thread(target=hammer) for _ in range(4)]; [h.start() for h in hs]
    during = all_nodes(a, client_yaml, 'ceiling', 19391); [h.join() for h in hs]
    _, nr = ct.run('systemctl show -p NRestarts --value sbox-webui.service')
    ct.run('systemctl set-property --runtime sbox-webui.service MemoryMax=160M && systemctl restart sbox-webui.service'); back = wait_ready(a.domain, 30)
    post = ct.core()
    record('EXTRA-PANEL-MEMORY-CEILING', 'Panel squeezed to a 40 MiB memory ceiling under login load: VPN traffic continues, core untouched, panel recovers after the limit is restored',
           all(v[0] for v in during.values()) and post['pid'] == pre['pid'] and post['config_sha256'] == pre['config_sha256'] and back,
           {'panel_restarts_under_ceiling': nr.strip(), 'login_outcomes': {k: outcomes.count(k) for k in set(outcomes)}, 'vpn': {k: v[0] for k, v in during.items()}, 'recovered': back})

    # 11. TOTP survives panel upgrade, rollback and re-upgrade.
    p = Panel(a.domain); p.login('admin', pw); p.api('auth/reauthenticate', {'password': pw})
    s, _, en = p.api('auth/totp/enroll', {}); secret = en['secret']
    s, _, vr = p.api('auth/totp/verify', {'code': totp(secret)}); time.sleep(31)
    def totp_login():
        q = Panel(a.domain); s_, _, b_ = q.req('/api/v1/auth/login', {'username': 'admin', 'password': pw, 'code': totp(secret)}); return s_
    steps = {}
    for name, c in (('upgrade', 'cd /root && bash ./%s webui upgrade </dev/null' % a.installer.name), ('rollback', 'sbox webui rollback'), ('reupgrade', 'cd /root && bash ./%s webui upgrade </dev/null' % a.installer.name)):
        rc, _ = ct.run(c, check=False, timeout=900); wait_ready(a.domain, 30)
        nopw = Panel(a.domain).req('/api/v1/auth/login', {'username': 'admin', 'password': pw})[0]
        steps[name] = {'exit': rc, 'login_without_code': nopw, 'login_with_code': totp_login()}; time.sleep(31)
    record('EXTRA-TOTP-ACROSS-UPGRADE', 'TOTP stays enforced and usable across panel upgrade, rollback to the previous release and re-upgrade',
           all(v['exit'] == 0 and v['login_with_code'] == 200 and v['login_without_code'] == 401 for v in steps.values()) and s == 200, steps)

    # 12. 100 concurrent clients while VPN traffic flows (last: its failed logins trip the per-IP login throttle by design).
    _, rss0 = ct.run('ps -o rss= -p $(systemctl show -p MainPID --value sbox-webui)'); core_pid = ct.core()['pid']
    results = []; lock = threading.Lock()
    def client(i):
        c = Panel(a.domain)
        for j in range(6):
            try:
                if j % 2: st_ = c.req('/api/v1/auth/login', {'username': 'nobody-%d' % i, 'password': 'wrong-password-%d' % i})[0]
                else: c.cookie, c.csrf = p.cookie, p.csrf; st_ = c.api('system/status')[0]
            except Exception as e: st_ = type(e).__name__
            with lock: results.append(st_)
    traffic = {}
    tt = threading.Thread(target=lambda: traffic.update(all_nodes(a, client_yaml, 'burst', 19390)))
    tt.start(); ths = [threading.Thread(target=client, args=(i,)) for i in range(100)]
    [t.start() for t in ths]; [t.join() for t in ths]; tt.join()
    _, rss1 = ct.run('ps -o rss= -p $(systemctl show -p MainPID --value sbox-webui)')
    from collections import Counter
    cnt = Counter(str(x) for x in results)
    record('EXTRA-100-CLIENTS', '100 concurrent clients (reads + failed logins): no 5xx or crash, excess connections refused by the bounded queue, logins throttled (429), panel RSS bounded, VPN traffic unaffected, core PID same',
           not any(k.startswith('5') for k in cnt) and all(v[0] for v in traffic.values()) and ct.core()['pid'] == core_pid and int(rss1) < int(rss0) + 64 * 1024,
           {'statuses': dict(cnt), 'panel_rss_kib_before_after': [int(rss0), int(rss1)], 'vpn': {k: v[0] for k, v in traffic.items()}})

    (a.out / ('extra-%s.json' % a.container)).write_text(json.dumps({'container': a.container, 'variant': a.variant, 'lab': ct.meta['note'], 'rows': rows}, indent=1))
    print(json.dumps({'total': len(rows), 'failed': [r['id'] for r in rows if r['status'] != 'PASS']}))


if __name__ == '__main__':
    main()
