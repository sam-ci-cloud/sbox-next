#!/usr/bin/env python3
"""Generic install with custom ports, a custom hop range and an existing certificate pair (lab).

  nsenter -t CLIENT_PID -n -m python3 lab_custom.py --container gc --out DIR --mihomo BIN --geo DIR --ca-bundle FILE --ports reality=8443,...
Checks the manager state, live listeners, panel inbounds/firewall views and real traffic
on every node of the installer-generated client file.
"""
import argparse, json, os, re, shutil, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_post_install as L  # noqa: E402
from lab_post_install import Container, Panel, record, rows, sh, all_nodes  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    for k in ('--container', '--mihomo', '--geo', '--ca-bundle', '--ports', '--hop', '--cert-path', '--key-path'): ap.add_argument(k, required=True)
    ap.add_argument('--out', required=True, type=Path); ap.add_argument('--domain', default='vpn.sbox.test')
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    ct = Container(a.container)
    hosts = Path(tempfile.mkdtemp()) / 'hosts'; hosts.write_text('127.0.0.1 localhost\n%s %s\n' % (L.CT_IP, a.domain))
    sh('mount', '--bind', hosts, '/etc/hosts'); sh('mount', '--bind', a.ca_bundle, '/etc/ssl/certs/ca-certificates.crt'); os.environ['SSL_CERT_FILE'] = a.ca_bundle
    want = {k: int(v) for k, v in (x.split('=') for x in a.ports.split(','))}
    st = json.loads((ct.root / 'etc/sbox-manager/state.json').read_text())
    got = {k: st['protocols'][k]['port'] for k in want}
    _, ss = ct.run('ss -H -lntu')
    listening = {k: (':%d ' % v) in ss for k, v in want.items()}
    code, doc = ct.run('sbox doctor --json', check=False)
    try: d = json.loads(doc[doc.index('{'):])
    except ValueError: d = {}
    src = st.get('certificate', st.get('cert', {}))
    _, live = ct.run('readlink -f /etc/sbox-manager/certs/fullchain.pem 2>/dev/null; sha256sum %s /etc/sbox-manager/certs/*.pem 2>/dev/null | cut -c1-16' % a.cert_path, check=False)
    record('CUSTOM-EXISTING-CERT-INSTALL', '--cert existing with an operator certificate path installs; doctor clean; TLS inbounds serve that certificate',
           code == 0 and d.get('failures') == 0, {'doctor_exit': code, 'failures': d.get('failures'), 'cert_state': {k: v for k, v in src.items() if 'key' not in k.lower()} if isinstance(src, dict) else str(src)[:80]})
    # Panel views.
    ct.run('sbox webui reset-admin >/dev/null 2>&1')
    boot = re.search(r'Password: (\S+)', (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text())[1]
    p = Panel(a.domain); p.login('admin', boot); s, _, b = p.api('auth/change-password', {'old': boot, 'password': 'Custom-Lab-password-2026'}); p.csrf = b['csrf']
    s, _, inb = p.api('inbounds'); s2, _, fw = p.api('security/firewall'); s3, _, health = p.api('protocols/health')
    shown = {}
    for row in (inb.get('inbounds') if isinstance(inb, dict) else inb) or []:
        k = row.get('protocol') or row.get('id') or row.get('name'); shown[str(k)] = row.get('port')
    fw_text = json.dumps(fw)
    hp = {x['id']: x.get('port') for x in health.get('protocols', [])}
    record('CUSTOM-PORTS-IN-UI', 'Custom ports and hop range are in state, listening, and shown by the panel inbounds, firewall and protocol health views',
           got == want and all(listening.values()) and all(str(v) in json.dumps(inb) for v in want.values()) and all(str(v) in fw_text for v in want.values()) and a.hop.replace('-', ':') in fw_text.replace('-', ':'),
           {'state': got, 'listening': listening, 'panel_inbounds_status': s, 'firewall_status': s2, 'health_ports': hp, 'hop_in_firewall_view': a.hop.replace('-', ':') in fw_text.replace('-', ':')})
    y = Path(tempfile.mkdtemp()) / 'g.yaml'; shutil.copy(ct.root / 'etc/sbox-manager/exports/clmi-global.yaml', y)
    res = all_nodes(argparse.Namespace(mihomo=a.mihomo, geo=a.geo), y, 'custom', 19490)
    record('CUSTOM-TRAFFIC', 'Installer-generated client file on custom ports: every node carries traffic', all(v[0] for v in res.values()) and len(res) >= 5, {k: v[0] for k, v in res.items()})
    (a.out / ('custom-%s.json' % a.container)).write_text(json.dumps({'container': a.container, 'lab': ct.meta['note'], 'rows': rows}, indent=1))
    print(json.dumps({'total': len(rows), 'failed': [r['id'] for r in rows if r['status'] != 'PASS']}))


if __name__ == '__main__':
    main()
