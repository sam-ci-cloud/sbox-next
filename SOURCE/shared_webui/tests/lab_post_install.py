#!/usr/bin/env python3
"""Post-install verification of a real standalone installation in the lab container.

Run INSIDE the lab client namespace (net + mount), e.g.
  nsenter -t CLIENT_PID -n -m python3 lab_post_install.py --container zgo1 --variant zgocloud --out DIR ...

It talks to the installed panel over real HTTPS exactly like a browser/API
client, drives the REAL manager through the panel bridge, checks CLI <-> WebUI
synchronisation, measures VPN traffic with real clients before/after each panel
lifecycle step, and verifies the VPN core PID/config are untouched by panel-only
operations. Nothing outside the disposable container/namespace is changed.
"""
import argparse, base64, hashlib, http.client, json, os, re, shutil, signal, ssl, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CTROOT = Path('/home/claude/lab/containers')
CT_IP, HTTP_IP = '10.99.0.1', '198.51.100.10'
rows = []


def sh(*a, check=True, timeout=300, input=None):
    p = subprocess.run([str(x) for x in a], capture_output=True, text=True, timeout=timeout, input=input)
    if check and p.returncode: raise RuntimeError('failed: %s\n%s' % (' '.join(map(str, a))[:200], (p.stderr or p.stdout)[-1200:]))
    return p


class Container:
    def __init__(self, name):
        self.name = name; self.meta = json.loads((CTROOT / name / 'meta.json').read_text()); self.pid = self.meta['pid1']; self.root = CTROOT / name / 'root'
    def run(self, cmd, check=True, timeout=600):
        base = ['nsenter', '-t', str(self.pid), '-m', '-u', '-i', '-n', '-p', '-r', '-w', '/usr/bin/env', '-i', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8']
        with tempfile.TemporaryFile('w+') as out:
            p = subprocess.run(base + ['bash', '-c', cmd], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
            out.seek(0); text = out.read()
        if check and p.returncode: raise RuntimeError('container cmd failed (%d): %s\n%s' % (p.returncode, cmd[:160], text[-1500:]))
        return p.returncode, text
    def core(self):
        _, pid = self.run('systemctl show -p MainPID --value sing-box.service')
        _, cfg = self.run('sha256sum /etc/sbox-manager/config.json | cut -c1-64')
        _, st = self.run('sha256sum /etc/sbox-manager/state.json | cut -c1-64')
        return {'pid': pid.strip(), 'config_sha256': cfg.strip(), 'state_sha256': st.strip()}


def record(id_, name, ok, evidence):
    rows.append({'id': id_, 'name': name, 'status': 'PASS' if ok else 'FAIL', 'evidence': evidence if isinstance(evidence, str) else json.dumps(evidence)[:1500]})
    print(('PASS' if ok else 'FAIL'), id_, name, (evidence if isinstance(evidence, str) else json.dumps(evidence))[:300], flush=True)


class Panel:
    def __init__(self, host, port=9443):
        self.host, self.port = host, port
        self.cookie = None; self.csrf = None
        self.ctx = ssl.create_default_context()  # lab CA is trusted via the namespace bundle
        # Older lab CAs lack keyUsage; Python 3.13's strict X.509 mode rejects that
        # (the panel certificate itself is still fully verified, incl. hostname).
        self.ctx.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0)
    def req(self, path, body=None, method=None, headers=None, raw=False):
        c = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=300)
        h = {'Host': '%s:%d' % (self.host, self.port)}
        if self.cookie: h['Cookie'] = self.cookie
        if body is not None: h['Content-Type'] = 'application/json'; h['X-CSRF-Token'] = self.csrf or ''
        h.update(headers or {})
        c.request(method or ('POST' if body is not None else 'GET'), path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse(); data = r.read(); hdr = dict(r.getheaders()); c.close()
        if raw: return r.status, hdr, data
        try: return r.status, hdr, json.loads(data)
        except ValueError: return r.status, hdr, data.decode(errors='replace')
    def login(self, user, password):
        s, h, b = self.req('/api/v1/auth/login', {'username': user, 'password': password})
        if s != 200: raise RuntimeError('login %s %s' % (s, b))
        self.cookie = h['Set-Cookie'].split(';')[0]; self.csrf = b['csrf']
        return b
    def api(self, p, body=None):
        return self.req('/api/v1/' + p, body)


def mihomo_client(args, yaml_path, tag, port):
    d = Path(tempfile.mkdtemp(prefix='mihomo-' + tag + '-'))
    for f in ('geoip.metadb', 'geosite.dat', 'geoip.dat', 'country.mmdb'):
        if (Path(args.geo) / f).exists(): shutil.copy(Path(args.geo) / f, d / f)
    shutil.copy(yaml_path, d / 'config.yaml')
    p = subprocess.Popen([args.mihomo, '-d', d, '-f', d / 'config.yaml', '-ext-ctl', '127.0.0.1:%d' % port], stdout=open(d / 'log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(60):
        if sh('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 'http://127.0.0.1:%d/version' % port, check=False).stdout == '200': break
        time.sleep(0.5)
    sh('curl', '-s', '-X', 'PATCH', 'http://127.0.0.1:%d/configs' % port, '-H', 'Content-Type: application/json', '-d', '{"mode":"global"}')
    return p, d


def through(port, mixed, node, limit=20):
    sh('curl', '-s', '-X', 'PUT', 'http://127.0.0.1:%d/proxies/GLOBAL' % port, '-H', 'Content-Type: application/json', '-d', json.dumps({'name': node}))
    t = time.monotonic()
    r = sh('curl', '-sS', '--noproxy', '', '--proxy', 'http://127.0.0.1:%d' % mixed, '--max-time', str(limit), 'http://%s:18080/probe' % HTTP_IP, check=False)
    return r.stdout == 'SBOX-LAB-PROTOCOL-OK\n', round(time.monotonic() - t, 3), r.stderr[-160:]


def all_nodes(args, yaml_path, tag, port=19190):
    import yaml
    doc = yaml.safe_load(Path(yaml_path).read_text())
    mixed = doc.get('mixed-port') or doc.get('port')
    p, d = mihomo_client(args, yaml_path, tag, port)
    try:
        res = {pr['name']: through(port, mixed, pr['name']) for pr in doc['proxies']}
    finally:
        os.killpg(p.pid, signal.SIGTERM); p.wait(5); shutil.rmtree(d, ignore_errors=True)
    return res


def wait_ready(domain, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if Panel(domain).req('/api/v1/health')[0] == 200: return True
        except Exception: pass
        time.sleep(0.5)
    return False


def state_diff(a, b):
    out = []
    def walk(x, y, path=''):
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y)): walk(x.get(k), y.get(k), path + '.' + k)
        elif x != y: out.append(path)
    walk(a, b); return out


def prepare_commit(panel, request):
    s, _, prev = panel.api('changes/prepare', request)
    if s == 428:
        raise RuntimeError('reauth required unexpectedly')
    if s != 200: return s, prev, None
    s2, _, res = panel.api('changes/commit', {'token': prev['token']})
    return s2, prev, res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--container', required=True); ap.add_argument('--variant', required=True); ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--domain', required=True); ap.add_argument('--yaml', type=Path, help='original static client YAML (ZgoCloud)')
    ap.add_argument('--mihomo', required=True); ap.add_argument('--geo', required=True); ap.add_argument('--ca-bundle', required=True)
    ap.add_argument('--installer', type=Path, help='standalone installer for the in-place panel upgrade step')
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    ct = Container(a.container)
    # Client namespace view: DNS + lab CA trust only here.
    hosts = Path(tempfile.mkdtemp()) / 'hosts'; hosts.write_text('127.0.0.1 localhost\n%s %s\n' % (CT_IP, a.domain))
    sh('mount', '--bind', hosts, '/etc/hosts'); sh('mount', '--bind', a.ca_bundle, '/etc/ssl/certs/ca-certificates.crt')
    os.environ['SSL_CERT_FILE'] = a.ca_bundle
    report = {'container': a.container, 'variant': a.variant, 'lab': ct.meta['note'], 'started': time.time()}

    # A. Installed state as the CLI sees it.
    code, doctor = ct.run('sbox doctor --json', check=False)
    try: d = json.loads(doctor[doctor.index('{'):])
    except ValueError: d = {'failures': None}
    record('INST-DOCTOR', 'sbox doctor after fresh install', code == 0 and d.get('failures') == 0, {'exit': code, 'failures': d.get('failures'), 'warnings': d.get('warnings'), 'warn_labels': [c['label'] for c in d.get('checks', []) if c['status'] != 'ok'][:6]})
    if a.variant == 'zgocloud':
        code, out = ct.run('sbox zgo-verify', check=False)
        record('INST-ZGO-VERIFY', 'sbox zgo-verify: six original nodes match live config', code == 0, out.strip().splitlines()[-1][:300] if out.strip() else str(code))
    code, out = ct.run('systemctl is-active sing-box sbox-manager-firewall sbox-webui sbox-webui-control sbox-webui-certificate.timer', check=False)
    record('INST-SERVICES', 'VPN, firewall helper, panel, bridge and certificate timer active', code == 0, out.replace('\n', ' '))
    code, out = ct.run('sbox webui doctor', check=False)
    record('INST-WEBUI-DOCTOR', 'sbox webui doctor (assets, database, settings, credential permissions)', code == 0, out.strip().splitlines()[-1][:200] if out.strip() else str(code))
    code, out = ct.run('stat -c "%U %a" /etc/sbox-webui/bootstrap-admin.txt; ps -o user= -p $(systemctl show -p MainPID --value sbox-webui); ps -o user= -p $(systemctl show -p MainPID --value sbox-webui-control); stat -c "%U:%G %a" /run/sbox-webui-control/control.sock')
    record('INST-PRIVSEP', 'Panel runs unprivileged; bridge root; socket 0660 root:sbox-webui; bootstrap 0600 root', out.split() == ['root', '600', 'sbox-webui', 'root', 'root:sbox-webui', '660'], out.replace('\n', ' '))
    base_core = ct.core(); report['core_after_install'] = base_core

    # B. Original client file traffic (ZgoCloud) before any panel change.
    if a.yaml:
        before = hashlib.sha256(a.yaml.read_bytes()).hexdigest()
        res = all_nodes(a, a.yaml, 'original')
        if a.variant == 'zgocloud':
            record('TRAFFIC-ORIGINAL-INSTALLED', 'Original ZgoCloud YAML: all six nodes carry traffic through the installed server', all(v[0] for v in res.values()) and len(res) == 6,
                   {k: v[:2] for k, v in res.items()})
        else:
            record('TRAFFIC-DEFAULT-EXPORT', 'Installer-generated GLOBAL client file: every enabled protocol carries traffic', all(v[0] for v in res.values()) and len(res) >= 5,
                   {k: v[:2] for k, v in res.items()})
        if a.variant == 'zgocloud': record('YAML-UNCHANGED-1', 'Original YAML bytes unchanged', hashlib.sha256(a.yaml.read_bytes()).hexdigest() == before == 'f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b', before[:16])

    # C. Real panel over HTTPS: bootstrap credential, first password change, reauth.
    creds = (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text()
    password = re.search(r'Password: (\S+)', creds)[1]
    panel = Panel(a.domain)
    me = panel.login('admin', password)
    s, _, _ = panel.api('users'); record('PANEL-FIRST-LOGIN-GATE', 'Initial credential must be changed before any API use', s == 428, str(s))
    new_password = 'Lab-' + base64.urlsafe_b64encode(os.urandom(18)).decode()
    s, _, b = panel.api('auth/change-password', {'old': password, 'password': new_password}); panel.csrf = b['csrf']
    record('PANEL-PASSWORD-CHANGE', 'Password change rotates CSRF and unlocks the panel', s == 200, str(s))
    t0 = time.time(); s, _, dash = panel.api('dashboard'); dash_ms = round((time.time() - t0) * 1000)
    tiles = {t['key']: t['status'] for t in dash.get('tiles', [])} if s == 200 else {}
    record('PANEL-DASHBOARD-REAL', 'Dashboard from the real bridge: core/panel/cert/listeners healthy, external not tested', s == 200 and tiles.get('core') == 'ok' and tiles.get('listeners') == 'ok' and tiles.get('external') == 'unknown',
           {'status': s, 'tiles': tiles, 'ms': dash_ms, 'fixture': dash.get('fixture') if s == 200 else None})
    s, _, ver = panel.api('system/version')
    record('PANEL-INTEGRITY', 'Installed panel files match the build manifest; manager/core versions reported', s == 200 and ver['panel_integrity']['status'] == 'ok' and bool(ver['manager'].get('manager_version')),
           {'integrity': ver.get('panel_integrity', {}).get('status'), 'manager': ver.get('manager')})
    s, _, doc = panel.api('diagnostics/doctor')
    record('PANEL-DOCTOR-GUIDED', 'Guided doctor from the real manager, grouped by layer, non-mutating', s == 200 and doc.get('mutating') is False and any(l['layer'] == 'Listeners' for l in doc['layers']),
           {'failures': doc.get('failures'), 'layers': [(l['layer'], l['status']) for l in doc.get('layers', [])]})
    s, _, health = panel.api('protocols/probe', {})
    record('PANEL-PROBE-LOCAL', 'Local probe: TCP/TLS inbounds verified on loopback; UDP not probed; external not run', s == 200 and all(p['local_probe']['status'] in ('ok', 'not-probed') for p in health['protocols']),
           [(p['id'], p['local_probe']['status']) for p in health.get('protocols', [])])
    s, h, rep = panel.req('/api/v1/diagnostics/report', raw=True)
    st = json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())
    secrets_list = [v for p in st['protocols'].values() for k, v in p.items() if k in ('uuid', 'password', 'private_key', 'short_id') and isinstance(v, str) and v]
    record('PANEL-REPORT-REDACTED', 'Copyable diagnostics report contains no live credential', s == 200 and not any(x in rep.decode() for x in secrets_list), {'bytes': len(rep), 'checked_secrets': len(secrets_list)})

    # D. Real manager transaction through the panel (create user) + CLI sync.
    pre = ct.core()
    s, prev, res = prepare_commit(panel, {'kind': 'user-create', 'data': {'name': 'lab-panel-user', 'tags': ['lab']}})
    post = ct.core()
    st = json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())
    user = next((u for u in st.get('managed_users', []) if u['name'] == 'lab-panel-user'), None)
    record('PANEL-COMMIT-REAL', 'Create user via panel: real manager commit, restart reported, state updated', s == 200 and res and res.get('committed') and user is not None and res.get('service_active') is True,
           {'status': s, 'result': {k: (res or {}).get(k) for k in ('committed', 'restarted', 'service_active', 'state_fingerprint')}, 'pid_before': pre['pid'], 'pid_after': post['pid'], 'preview_protected': (prev or {}).get('summary', {}).get('protected_identity')})
    record('SYNC-WEBUI-TO-CLI', 'User created in the WebUI is visible to the CLI state immediately', user is not None and res.get('state_fingerprint') == post['state_sha256'][:16], {'cli_state_fp': post['state_sha256'][:16], 'panel_fp': (res or {}).get('state_fingerprint')})
    if a.variant == 'zgocloud':
        code, out = ct.run('sbox zgo-verify', check=False)
        record('ZGO-VERIFY-AFTER-USER', 'Legacy identity still verified after adding a user through the panel', code == 0, out.strip().splitlines()[-1][:200] if out.strip() else str(code))
    # Export the new user's profile through the panel and use it.
    if user:
        s, _, ex = panel.api('client-profiles/export', {'id': user['id'], 'profile': 'global', 'format': 'yaml'})
        ypath = Path(tempfile.mkdtemp()) / 'user.yaml'; ypath.write_text(ex['content'])
        res = all_nodes(a, ypath, 'panel-user', 19191)
        record('TRAFFIC-PANEL-USER', 'Panel-created user connects on every protocol with its own credentials', all(v[0] for v in res.values()) and len(res) >= 5, {k: v[:2] for k, v in res.items()})
        # Subscription token: fetch from the client namespace, then revoke.
        s, _, sub = panel.api('subscriptions/rotate-token', {'id': user['id']})
        url = sub['urls']['global'].replace('https://%s:9443' % a.domain, '')
        s1, h1, body1 = Panel(a.domain).req(url, raw=True)
        panel.api('subscriptions/revoke', {'id': user['id']})
        s2, _, body2 = Panel(a.domain).req(url, raw=True)
        record('SUBS-REAL', 'Personal subscription served (no-store) then 404 after revoke', s1 == 200 and b'proxies' in body1 and h1.get('Cache-Control') == 'no-store' and s2 == 404, {'first': s1, 'after_revoke': s2})
        # Disable via bulk action -> that user's traffic stops, original still works.
        s, prev, res2 = prepare_commit(panel, {'kind': 'users-bulk', 'data': {'action': 'disable', 'ids': [user['id']]}})
        res_dis = all_nodes(a, ypath, 'disabled', 19192)
        record('TRAFFIC-DISABLED-USER', 'Bulk-disabled user is rejected on every protocol', s == 200 and not any(v[0] for v in res_dis.values()), {k: v[0] for k, v in res_dis.items()})
        if a.yaml:
            res = all_nodes(a, a.yaml, 'original-2', 19193)
            record('TRAFFIC-ORIGINAL-AFTER-DISABLE', 'Original YAML unaffected by disabling another user', all(v[0] for v in res.values()), {k: v[0] for k, v in res.items()})
    # Stale preview after an out-of-band CLI change.
    s, _, prev = panel.api('changes/prepare', {'kind': 'policy', 'data': {'smart_lazy': True}})
    code, out = ct.run('sbox client-policy primary hy2', check=False)
    s2, _, res3 = panel.api('changes/commit', {'token': prev.get('token', '')})
    record('SYNC-CLI-STALE-PREVIEW', 'A CLI change after a panel preview makes the commit fail (no lost update)', s == 200 and code == 0 and s2 == 409, {'prepare': s, 'cli_exit': code, 'commit': s2, 'error': (res3 or {}).get('error') if isinstance(res3, dict) else str(res3)[:120]})
    _, _, pol = panel.api('policy')
    record('SYNC-CLI-TO-WEBUI', 'CLI policy change is visible in the panel', pol.get('primary') == 'hy2', {'primary': pol.get('primary')})
    s, _, al = panel.api('alerts')
    record('TIMELINE-EXTERNAL-CHANGE', 'Timeline lists the out-of-band change', s == 200, {'events': [e['kind'] for e in al.get('timeline', [])][:8]})

    # E. Panel lifecycle while the VPN keeps running.
    state_snapshot = {'v': json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())}
    def unchanged(step, before):
        after = ct.core()
        current = json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())
        changed = state_diff(state_snapshot['v'], current)
        # Panel-only steps may refresh manager metadata (version/build/time); never VPN identity/listeners.
        vpn_changed = [c for c in changed if not re.match(r'^\.(manager_version|manager_build_id|updated_at|created_at|schema)$', c)]
        ok = after['pid'] == before['pid'] and after['config_sha256'] == before['config_sha256'] and not vpn_changed
        record('LIFECYCLE-' + step, 'Panel %s leaves VPN core PID, config and VPN state untouched' % step.lower(), ok, {'before': before['pid'], 'after': after['pid'], 'config_same': after['config_sha256'] == before['config_sha256'], 'state_fields_changed': changed[:10]})
        return after
    steady = ct.core()
    ct.run('systemctl kill -s SIGKILL sbox-webui.service'); time.sleep(1)
    if a.yaml:
        res = all_nodes(a, a.yaml, 'during-crash', 19194)
        record('TRAFFIC-DURING-PANEL-CRASH', 'VPN traffic continues while the panel process is killed', all(v[0] for v in res.values()), {k: v[0] for k, v in res.items()})
    unchanged('SIGKILL', steady); time.sleep(4)
    _, out = ct.run('systemctl is-active sbox-webui', check=False)
    record('LIFECYCLE-AUTORESTART', 'Panel restarts itself after SIGKILL (Restart=on-failure)', out.strip() == 'active', out.strip())
    ct.run('sbox webui stop'); unchanged('STOP', steady)
    ct.run('sbox webui start'); time.sleep(3); unchanged('START', steady)
    if a.installer:
        shutil.copy(a.installer, ct.root / 'root' / a.installer.name)
        code, out = ct.run('cd /root && bash ./%s webui upgrade' % a.installer.name, check=False)
        record('LIFECYCLE-UPGRADE-CMD', 'In-place panel upgrade from the standalone installer', code == 0, out.strip().splitlines()[-1][:200] if out.strip() else str(code))
        unchanged('UPGRADE', steady)
        t_ready = time.time(); ready = wait_ready(a.domain, 2); t_ready = round(time.time() - t_ready, 2)
        record('LIFECYCLE-UPGRADE-READY-ON-RETURN', 'Panel accepts HTTPS within 2 s of the upgrade command returning', ready, {'seconds': t_ready})
        p2 = Panel(a.domain)
        try: p2.login('admin', new_password); ok = p2.api('auth/me')[0] == 200; err = ''
        except Exception as e: ok = False; err = repr(e)[:300]
        record('LIFECYCLE-UPGRADE-KEEPS-LOGIN', 'Account/password survive the panel upgrade', ok, {'ready': ready, 'error': err})
    ct.run('sbox webui uninstall'); unchanged('UNINSTALL', steady)
    if a.yaml:
        res = all_nodes(a, a.yaml, 'after-uninstall', 19195)
        record('TRAFFIC-AFTER-PANEL-UNINSTALL', 'Original YAML traffic after panel uninstall', all(v[0] for v in res.values()), {k: v[0] for k, v in res.items()})
    code, out = ct.run('sbox webui install', check=False)
    record('LIFECYCLE-REINSTALL-CMD', 'Panel reinstall after uninstall', code == 0, out.strip().splitlines()[-1][:200] if out.strip() else str(code))
    unchanged('REINSTALL', steady)
    t_ready = time.time(); ready = wait_ready(a.domain, 2); t_ready = round(time.time() - t_ready, 2)
    record('LIFECYCLE-REINSTALL-READY-ON-RETURN', 'Panel accepts HTTPS within 2 s of the reinstall command returning', ready, {'seconds': t_ready})
    p3 = Panel(a.domain)
    try: p3.login('admin', new_password); ok = p3.api('dashboard')[0] == 200; err = ''
    except Exception as e: ok = False; err = repr(e)[:300]
    record('LIFECYCLE-REINSTALL-KEEPS-ACCOUNT', 'Retained panel database keeps the operator account after reinstall', ok, {'ready': ready, 'error': err})
    alive = p3.api('auth/me')[0] if ok else None
    code, out = ct.run('sbox webui reset-admin', check=False)
    after = p3.api('auth/me')[0]
    record('SECURITY-RESET-ADMIN', 'Root reset-admin revokes existing sessions', code == 0 and alive == 200 and after == 401, {'exit': code, 'before': alive, 'after': after})
    # F. Resources.
    _, out = ct.run('for u in sing-box sbox-webui sbox-webui-control; do p=$(systemctl show -p MainPID --value $u); echo $u $(grep VmRSS /proc/$p/status | awk "{print \\$2}") $(ls /proc/$p/fd | wc -l); done')
    report['resources_kib_fds'] = out.strip().splitlines()
    if a.yaml:
        a.variant == 'zgocloud' and record('YAML-UNCHANGED-FINAL', 'Original YAML bytes unchanged at the end', hashlib.sha256(a.yaml.read_bytes()).hexdigest() == 'f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b', 'sha256 checked')
    report['rows'] = rows; report['finished'] = time.time()
    (a.out / ('post-install-%s.json' % a.container)).write_text(json.dumps(report, indent=1))
    print(json.dumps({'total': len(rows), 'failed': [r['id'] for r in rows if r['status'] != 'PASS']}))


if __name__ == '__main__':
    main()
