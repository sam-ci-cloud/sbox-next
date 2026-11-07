#!/usr/bin/env python3
"""Start the REAL panel HTTPS server/store with the UI fixture bridge.

FIXTURE ONLY: for browser layout/a11y/screenshot tests. Not VPN evidence.
Usage: dev_panel.py --variant zgocloud --users 30 --port 19443 --work DIR
Prints one JSON line: {origin, port, password, pid}.
"""
import argparse, json, os, pathlib, ssl, subprocess, sys, threading, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend')); sys.path.insert(0, str(ROOT / 'tests'))
from server import App, Server  # noqa: E402
from ui_fixture import FixtureControl  # noqa: E402
from common import password_hash  # noqa: E402

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--variant', default='universal'); ap.add_argument('--users', type=int, default=0)
    ap.add_argument('--port', type=int, default=19443); ap.add_argument('--work', required=True)
    ap.add_argument('--host', default='panel.sbox.test'); ap.add_argument('--frontend', default=str(ROOT / 'frontend'))
    ap.add_argument('--password', default='Fixture-admin-password-2026')
    ap.add_argument('--reader-password', default='Fixture-reader-password-2026')
    ap.add_argument('--accounting-health',choices=['ready','degraded'],default='ready')
    ap.add_argument('--family',choices=['preserve','ipv4','dual','ipv6','advanced'],default='preserve')
    a = ap.parse_args(); work = pathlib.Path(a.work); work.mkdir(parents=True, exist_ok=True)
    cert, key = work / 'cert.pem', work / 'key.pem'
    if not cert.exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '3', '-subj', '/CN=' + a.host,
                        '-addext', 'subjectAltName=DNS:' + a.host, '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    db = work / 'panel.db'
    for suffix in ('', '-wal', '-shm'):
        pathlib.Path(str(db) + suffix).unlink(missing_ok=True)
    control = FixtureControl(a.variant, a.users)
    summary = control.op_accounting_summary
    def accounting_summary(data):
        value=summary(data);value['health']={**value.get('health',{}),'status':a.accounting_health,'sampled_at':time.time(),'reason':'Synthetic collector stopped' if a.accounting_health=='degraded' else ''};return value
    control.op_accounting_summary=accounting_summary
    overview=control.op_overview
    def network_overview(data):
        value=overview(data);value['deployment_family']={'mode':a.family,'listen':{'preserve':'0.0.0.0','ipv4':'0.0.0.0','dual':'::','ipv6':'2001:db8::1','advanced':'0.0.0.0'}[a.family]}
        if a.family=='advanced':value['deployment_family']['policies']={'inbound':'ipv4','egress':'dual','dns':'dual','client':'ipv4'}
        return value
    control.op_overview=network_overview
    origin = 'https://%s:%d' % (a.host, a.port)
    app = App({'database': str(db), 'origin': origin, 'frontend': a.frontend, 'variant': a.variant, 'qrencode': [sys.executable, str(ROOT / 'tests/qrencode_ctypes.py')]}, control)
    app.store.reset_password()
    with app.store.db() as d:
        d.execute("UPDATE accounts SET hash=?, reset=0 WHERE name='admin'", (password_hash(a.password),))
        d.execute("INSERT INTO accounts(name,hash,role,reset) VALUES('reader',?,'reader',0)", (password_hash(a.reader_password),))
    server = Server(('127.0.0.1', a.port), app)
    # Browser matrices load the whole app 24+ times a minute from one address; the product
    # limit (600/min) stays the default everywhere else.
    server.request_limit = 6000
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    if hasattr(app, 'start_background'):
        app.start_background(interval=float(os.environ.get('SBOX_FIXTURE_SAMPLE_SECONDS', '5')))
    print(json.dumps({'origin': origin, 'port': a.port, 'password': a.password, 'reader_password': a.reader_password, 'pid': os.getpid(), 'fixture': True}), flush=True)
    server.serve_forever(poll_interval=0.5)

if __name__ == '__main__':
    main()
