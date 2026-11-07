#!/usr/bin/env python3
"""In-place upgrade of an installation made by an OLDER release (disposable lab container).

Run INSIDE the lab client namespace, like lab_post_install.py:
  nsenter -t CLIENT_PID -n -m python3 lab_upgrade.py --container zgo2 --variant zgocloud \
      --installer NEW.sh --out DIR --domain ... --yaml ... --mihomo ... --geo ... --ca-bundle ...

Steps: use the OLD panel (change password, create a user, API token), record the
VPN identity/config/PID and real traffic, remove the lab sysctl shim, run the NEW
installer's documented upgrade command, then verify identity, data, login, tokens,
traffic, new features, panel rollback to the old release on the migrated database
and re-upgrade. Nothing outside the disposable container/namespace is changed.
"""
import argparse, base64, hashlib, json, os, re, shutil, sqlite3, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_post_install as L  # noqa: E402
from lab_post_install import Container, Panel, record, rows, sh, all_nodes, prepare_commit, state_diff, wait_ready  # noqa: E402

ORIGINAL_YAML_SHA = 'f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b'
IDENTITY_FIELDS = ('uuid', 'password', 'private_key', 'public_key', 'short_id', 'sni', 'path', 'port', 'udp_range', 'server_name')


def identity(state):
    """Every credential/listener field of every protocol plus domain (compared, never printed)."""
    out = {'domain': state.get('domain')}
    for name, p in sorted(state.get('protocols', {}).items()):
        for k in IDENTITY_FIELDS:
            if k in p: out['%s.%s' % (name, k)] = p[k]
    for k in ('legacy_identity', 'zgo_legacy', 'legacy'):
        if k in state: out[k] = state[k]
    return out


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def users(state):
    return {u['name']: digest({k: v for k, v in u.items() if k not in ('updated_at',)}) for u in state.get('managed_users', [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--container', required=True); ap.add_argument('--variant', required=True); ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--domain', required=True); ap.add_argument('--yaml', type=Path)
    ap.add_argument('--mihomo', required=True); ap.add_argument('--geo', required=True); ap.add_argument('--ca-bundle', required=True)
    ap.add_argument('--installer', required=True, type=Path); ap.add_argument('--upgrade-args', default='webui upgrade')
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    ct = Container(a.container)
    global NODES; NODES = 6 if a.variant == 'zgocloud' else 5
    hosts = Path(tempfile.mkdtemp()) / 'hosts'; hosts.write_text('127.0.0.1 localhost\n%s %s\n' % (L.CT_IP, a.domain))
    sh('mount', '--bind', hosts, '/etc/hosts'); sh('mount', '--bind', a.ca_bundle, '/etc/ssl/certs/ca-certificates.crt')
    os.environ['SSL_CERT_FILE'] = a.ca_bundle
    report = {'container': a.container, 'variant': a.variant, 'lab': ct.meta['note'], 'started': time.time()}
    sj = lambda: json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())

    # 1. The OLD installation as an operator would have used it.
    _, old_version = ct.run('sbox version', check=False); old_version = old_version.strip()
    panel_present = (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').exists()
    new_password = 'Lab-' + base64.urlsafe_b64encode(os.urandom(18)).decode()
    old_user_ok, token, audit_rows_old, p = True, None, '0', None
    if panel_present:
        creds = (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text()
        password = re.search(r'Password: (\S+)', creds)[1]
        t_old = time.time(); old_ready = wait_ready(a.domain, 30); report['old_panel_first_ready_seconds'] = round(time.time() - t_old, 1)
        print('INFO old release panel ready after %.1f s (ready=%s)' % (time.time() - t_old, old_ready), flush=True)
        p = Panel(a.domain); p.login('admin', password)
        s, _, b = p.api('auth/change-password', {'old': password, 'password': new_password}); p.csrf = b.get('csrf', p.csrf)
        s, prev, res = prepare_commit(p, {'kind': 'user-create', 'data': {'name': 'old-release-user', 'tags': ['lab']}})
        old_user_ok = s == 200 and bool(res)
        s_tok, _, tok = p.api('api-tokens', {'name': 'lab-read', 'scope': 'read', 'hours': 24})
        token = tok.get('token') if isinstance(tok, dict) else None
        _, audit_rows_old = ct.run("python3 -c \"import sqlite3;print(sqlite3.connect('/var/lib/sbox-webui/panel.db').execute('select count(*) from audit').fetchone()[0])\"")
    else:
        # Pre-WebUI origin: an operator setting changed through the old CLI must survive.
        ct.run('sbox client-policy primary hy2')
    st0 = sj(); core0 = ct.core(); id0 = identity(st0); users0 = users(st0)
    policy0 = digest(st0.get('client_policy'))
    record('UPG-ORIGIN', 'Origin: installation made by the older release' + (', used through its own panel' if panel_present else ' (no panel; CLI policy changed)'),
           bool(old_version) and old_user_ok and (bool(token) or not panel_present),
           {'old_version': old_version, 'panel_present': panel_present, 'user_created': old_user_ok, 'token_created': bool(token), 'users': sorted(users0), 'audit_rows': audit_rows_old.strip(), 'client_policy_primary': (st0.get('client_policy') or {}).get('primary')})
    if a.yaml:
        r = all_nodes(a, a.yaml, 'old-release', 19290)
        record('UPG-TRAFFIC-BEFORE', 'Client file: every node carries traffic on the old release', all(v[0] for v in r.values()) and len(r) == NODES, {k: v[0] for k, v in r.items()})
    ex_old = None
    uid = next((u['id'] for u in st0.get('managed_users', []) if u['name'] == 'old-release-user'), None)
    if uid and p:
        s, _, ex_old = p.api('client-profiles/export', {'id': uid, 'profile': 'global', 'format': 'yaml'})

    # 2. Remove the lab-only shim (the new release must not need it) and upgrade.
    shim = ct.root / 'usr/local/sbin/sysctl'
    had_shim = shim.exists()
    if had_shim: shim.unlink()
    shutil.copy(a.installer, ct.root / 'root' / a.installer.name)
    t0 = time.time()
    code, out = ct.run('cd /root && bash ./%s %s </dev/null' % (a.installer.name, a.upgrade_args), check=False, timeout=900)
    took = round(time.time() - t0, 1)
    (a.out / ('upgrade-%s.log' % a.container)).write_text(out)
    t_ready = time.time(); ready = wait_ready(a.domain, 2); t_ready = round(time.time() - t_ready, 2)
    _, new_version = ct.run('sbox version', check=False); new_version = new_version.strip()
    record('UPG-COMMAND', 'Documented upgrade command completes without prompts (stdin closed)', code == 0, {'command': 'bash ./%s %s </dev/null' % (a.installer.name, a.upgrade_args), 'exit': code, 'seconds': took, 'tail': out.strip().splitlines()[-1][:160] if out.strip() else '', 'shim_removed': had_shim})
    record('UPG-VERSION', 'Manager reports the new version after the upgrade', new_version != old_version and bool(new_version), {'before': old_version, 'after': new_version})
    record('UPG-READY-ON-RETURN', 'Panel accepts HTTPS within 2 s of the upgrade returning', ready, {'seconds': t_ready})

    # 3. VPN identity, config and process.
    st1 = sj(); core1 = ct.core(); id1 = identity(st1)
    changed = state_diff(st0, st1)
    record('UPG-IDENTITY', 'Every protocol credential, key, port, path, SNI and hop range is unchanged', id0 == id1, {'fields_compared': len(id0), 'digest_before': digest(id0), 'digest_after': digest(id1), 'differing': sorted(k for k in set(id0) | set(id1) if id0.get(k) != id1.get(k))})
    record('UPG-USERS', 'Managed users and their credentials survive the upgrade', users(st1) == users0, {'users': sorted(users(st1))})
    record('UPG-CONFIG', 'Rendered sing-box config unchanged by the upgrade', core1['config_sha256'] == core0['config_sha256'], {'same': core1['config_sha256'] == core0['config_sha256'], 'state_fields_changed': changed[:12]})
    record('UPG-CORE-PID', 'VPN core process not restarted by the upgrade', core1['pid'] == core0['pid'], {'before': core0['pid'], 'after': core1['pid']})
    code, dout = ct.run('sbox doctor --json', check=False)
    try: d = json.loads(dout[dout.index('{'):])
    except ValueError: d = {}
    record('UPG-DOCTOR', 'sbox doctor after upgrade: no failures', code == 0 and d.get('failures') == 0, {'exit': code, 'failures': d.get('failures'), 'warnings': d.get('warnings')})
    if a.variant == 'zgocloud':
        code, zout = ct.run('sbox zgo-verify', check=False)
        record('UPG-ZGO-VERIFY', 'sbox zgo-verify after upgrade', code == 0, zout.strip().splitlines()[-1][:200] if zout.strip() else str(code))
    if a.yaml:
        r = all_nodes(a, a.yaml, 'upgraded', 19291)
        record('UPG-TRAFFIC-AFTER', 'Client file: every node carries traffic after the upgrade', all(v[0] for v in r.values()) and len(r) == NODES, {k: v[0] for k, v in r.items()})
        if a.variant == 'zgocloud': record('UPG-YAML-BYTES', 'Original YAML bytes unchanged', hashlib.sha256(a.yaml.read_bytes()).hexdigest() == ORIGINAL_YAML_SHA, 'sha256 checked')
    if ex_old and isinstance(ex_old, dict) and ex_old.get('content'):
        y = Path(tempfile.mkdtemp()) / 'old-user.yaml'; y.write_text(ex_old['content'])
        r = all_nodes(a, y, 'old-user', 19292)
        record('UPG-TRAFFIC-OLD-USER-PROFILE', 'Profile exported by the OLD panel still connects on every protocol after upgrade', all(v[0] for v in r.values()), {k: v[0] for k, v in r.items()})

    # 4. Panel data and new features on the migrated database.
    record('UPG-CLIENT-POLICY', 'Client policy chosen on the old release is preserved', digest(st1.get('client_policy')) == policy0, {'primary': (st1.get('client_policy') or {}).get('primary')})
    p2 = Panel(a.domain)
    if not panel_present:
        # First panel on this host: root-only generated credential, mandatory change.
        creds = (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text(); first = re.search(r'Password: (\S+)', creds)[1]
        _, out_mode = ct.run('stat -c "%U %a" /etc/sbox-webui/bootstrap-admin.txt')
        p2.login('admin', first); gate = p2.api('users')[0]
        s, _, b = p2.api('auth/change-password', {'old': first, 'password': new_password}); p2.csrf = b.get('csrf')
        record('UPG-FIRST-PANEL', 'Panel attached to a pre-WebUI install: root-only credential, change required before use', out_mode.split() == ['root', '600'] and gate == 428 and s == 200, {'mode': out_mode.strip(), 'gate': gate, 'change': s})
        p2 = Panel(a.domain)
    try: p2.login('admin', new_password); login_ok = p2.api('auth/me')[0] == 200; err = ''
    except Exception as e: login_ok = False; err = repr(e)[:200]
    record('UPG-LOGIN', 'Operator password set on the old release still logs in', login_ok, {'error': err})
    if token:
        s, _, _ = p2.req('/api/v1/users', headers={'Authorization': 'Bearer ' + token})
        record('UPG-API-TOKEN', 'API token issued by the old release still authorizes reads', s == 200, str(s))
    db = ct.root / 'var/lib/sbox-webui/panel.db'
    con = sqlite3.connect('file:%s?mode=ro' % db, uri=True)
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    cols = {r[1] for r in con.execute('pragma table_info(audit)')}
    uv = con.execute('pragma user_version').fetchone()[0]; n_audit = con.execute('select count(*) from audit').fetchone()[0]; con.close()
    if panel_present: record('UPG-DB-MIGRATION', 'Additive migration: new tables/columns added, history kept, schema version unchanged for rollback', {'alerts', 'events', 'session_meta', 'token_meta'} <= tables and {'origin', 'outcome', 'target'} <= cols and n_audit >= int(audit_rows_old.strip() or 0) and uv == 1,
           {'user_version': uv, 'audit_rows_before': audit_rows_old.strip(), 'audit_rows_after': n_audit, 'new_tables': sorted({'alerts', 'events', 'session_meta', 'token_meta'} & tables)})
    s, _, dash = p2.api('dashboard')
    record('UPG-NEW-DASHBOARD', 'New dashboard works on the upgraded installation', s == 200 and {t['key'] for t in dash.get('tiles', [])} >= {'core', 'panel', 'certificate', 'listeners', 'external'}, {'status': s, 'tiles': {t['key']: t['status'] for t in dash.get('tiles', [])} if s == 200 else None})
    s, _, ver = p2.api('system/version')
    record('UPG-INTEGRITY', 'Upgraded panel files match the new build manifest', s == 200 and ver.get('panel_integrity', {}).get('status') == 'ok', {'panel': ver.get('panel_version') if s == 200 else None, 'manager': (ver.get('manager') or {}).get('manager_version') if s == 200 else None})
    s, _, ul = p2.api('users')
    names = [u.get('name') for u in (ul.get('users', ul) if isinstance(ul, dict) else ul)] if s == 200 else []
    if panel_present: record('UPG-USERS-IN-PANEL', 'User created on the old release is listed in the new panel', 'old-release-user' in names, {'status': s, 'count': len(names)})

    # 5. Panel rollback to the previous release on the migrated DB, then forward again.
    if not panel_present:
        code, rout = ct.run('sbox webui rollback', check=False)
        record('UPG-PANEL-ROLLBACK-NONE', 'Rollback with no previous panel release refuses cleanly and leaves the VPN untouched', code != 0 and ct.core()['pid'] == core1['pid'], {'exit': code, 'message': rout.strip().splitlines()[-1][:160] if rout.strip() else ''})
    else:
        pre_rb = ct.core()
        code, rout = ct.run('sbox webui rollback', check=False)
        ok_rb = wait_ready(a.domain, 15)
        p3 = Panel(a.domain)
        try: p3.login('admin', new_password); rb_login = p3.api('auth/me')[0] == 200
        except Exception: rb_login = False
        _, cur = ct.run('readlink /usr/local/lib/sbox-webui/current', check=False)
        record('UPG-PANEL-ROLLBACK', 'Panel rollback restores the previous release; it runs on the migrated database and keeps the login', code == 0 and ok_rb and rb_login and ct.core()['pid'] == pre_rb['pid'],
               {'exit': code, 'current': cur.strip(), 'login': rb_login, 'core_pid_same': ct.core()['pid'] == pre_rb['pid']})
        code, out2 = ct.run('cd /root && bash ./%s webui upgrade </dev/null' % a.installer.name, check=False, timeout=900)
        ready2 = wait_ready(a.domain, 2)
        p4 = Panel(a.domain)
        try: p4.login('admin', new_password); again = p4.api('dashboard')[0] == 200
        except Exception: again = False
        record('UPG-REUPGRADE', 'Upgrading again after rollback restores the new panel with data intact', code == 0 and ready2 and again, {'exit': code, 'ready': ready2, 'dashboard': again})
    record('UPG-IDENTITY-FINAL', 'VPN identity unchanged after rollback and re-upgrade', identity(sj()) == id0, {'digest': digest(identity(sj()))})

    report['rows'] = rows; report['finished'] = time.time()
    (a.out / ('upgrade-%s.json' % a.container)).write_text(json.dumps(report, indent=1))
    print(json.dumps({'total': len(rows), 'failed': [r['id'] for r in rows if r['status'] != 'PASS']}))


if __name__ == '__main__':
    main()
