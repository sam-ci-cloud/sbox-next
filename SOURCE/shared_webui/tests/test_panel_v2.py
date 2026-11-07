"""2026.10.25 panel contracts: real HTTPS server + SQLite store + controller.

The bridge is the labelled UI fixture (tests/ui_fixture.py); results here are
API/security evidence, NOT VPN evidence. Set SBOX_WEBUI_ROOT to another
shared_webui tree to run the same assertions against a baseline (fail-first).
"""
import base64, re, http.client, json, os, pathlib, socket, ssl, subprocess, sys, tempfile, threading, time, unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path(os.environ.get('SBOX_WEBUI_ROOT', HERE.parent)).resolve()
sys.path.insert(0, str(ROOT / 'backend')); sys.path.insert(0, str(ROOT / 'privileged-bridge')); sys.path.append(str(HERE))
from common import Problem, password_hash, totp  # noqa: E402
from server import App, Server  # noqa: E402
from ui_fixture import FixtureControl  # noqa: E402
import controller  # noqa: E402
BASELINE = not hasattr(controller, 'preview')
import ctypes.util  # noqa: E402
# 1.8.0 D10: QR tests need the real libqrencode (installed with qrencode on servers).
# Without it they are BLOCKED_ENV skips, never passes and never false failures.
def _have_libqrencode():
    try:
        ctypes.CDLL('libqrencode.so.4'); return True  # honours LD_LIBRARY_PATH as the encoder does
    except OSError:
        return ctypes.util.find_library('qrencode') is not None
HAVE_LIBQRENCODE = _have_libqrencode()
needs_libqrencode = unittest.skipUnless(HAVE_LIBQRENCODE, 'BLOCKED_ENV: libqrencode.so.4 not installed (apt install libqrencode4)')

FAKE_QR = HERE / 'qrencode_ctypes.py'


class Panel(unittest.TestCase):
    variant = 'zgocloud'

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.root = pathlib.Path(cls.tmp.name)
        cls.control = FixtureControl(cls.variant, users=3, protected_name='<b>legacy</b>')
        cls.app = App({'database': str(cls.root / 'db'), 'origin': 'https://panel.example.test', 'frontend': str(ROOT / 'frontend'), 'variant': cls.variant,
                       'qrencode': [sys.executable, str(FAKE_QR)]}, cls.control)
        cls.server = Server(('127.0.0.1', 0), cls.app)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=panel.example.test',
                        '-keyout', str(cls.root / 'key'), '-out', str(cls.root / 'cert')], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cls.root / 'cert', cls.root / 'key'); cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.tmp.cleanup()

    def setUp(self):
        self.server.rates.clear()
        self.app.invalidate()  # each test starts without cached bridge reads (production: <= cache window)
        with self.app.store.db() as db: db.execute('DELETE FROM attempts')

    def req(self, path, body=None, headers=None, method=None, raw=False):
        conn = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=ssl._create_unverified_context(), timeout=20)
        h = {'Host': 'panel.example.test', **(headers or {})}
        if body is not None: h['Content-Type'] = 'application/json'; body = json.dumps(body)
        conn.request(method or ('POST' if body is not None else 'GET'), path, body, h)
        r = conn.getresponse(); data = r.read(); conn.close()
        if raw: return r.status, dict(r.getheaders()), data
        try: value = json.loads(data)
        except ValueError: value = data
        return r.status, dict(r.getheaders()), value

    def admin(self, name='admin', role='admin', password='Admin-SYNTHETIC-password-1'):
        with self.app.store.db() as db:
            db.execute('INSERT INTO accounts(name,hash,role,reset) VALUES(?,?,?,0) ON CONFLICT(name) DO UPDATE SET hash=excluded.hash,role=excluded.role,reset=0,enabled=1,totp=NULL,recovery=\'[]\'',
                       (name, password_hash(password), role))
        code, h, body = self.req('/api/v1/auth/login', {'username': name, 'password': password})
        self.assertEqual(code, 200, body)
        return {'Cookie': h['Set-Cookie'].split(';')[0], 'X-CSRF-Token': body['csrf']}

    def token(self, h, scope):
        code, _, body = self.req('/api/v1/api-tokens', {'name': 'tok-' + scope, 'scope': scope, 'hours': 1}, h)
        self.assertEqual(code, 200, body); return {'Authorization': 'Bearer ' + body['token']}


class AccountsAndAuth(Panel):
    def test_duplicate_account_is_409_not_503(self):
        h = self.admin()
        self.assertEqual(self.req('/api/v1/accounts', {'name': 'dup', 'password': 'dup-SYNTHETIC-password', 'role': 'reader'}, h)[0], 200)
        code, _, body = self.req('/api/v1/accounts', {'name': 'dup', 'password': 'dup-SYNTHETIC-password', 'role': 'reader'}, h)
        self.assertEqual(code, 409, body)

    def test_disable_unknown_account_is_404(self):
        h = self.admin()
        self.assertEqual(self.req('/api/v1/accounts', {'name': 'nobody-here', 'enabled': False}, h)[0], 404)

    def test_reauth_requires_totp_when_enrolled(self):
        h = self.admin('mfa-admin')
        secret = base64.b32encode(b'synthetic-mfa-key-0001').decode()
        with self.app.store.db() as db: db.execute("UPDATE accounts SET totp=?,last_totp=-1 WHERE name='mfa-admin'", (secret,))
        code, _, _ = self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        self.assertEqual(code, 401, 'password alone must not refresh a session that has MFA')
        code, _, body = self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1', 'code': totp(secret)}, h)
        self.assertEqual(code, 200, body)
        code, _, _ = self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1', 'code': totp(secret)}, h)
        self.assertEqual(code, 401, 'a TOTP code cannot be replayed')

    def test_reauth_failures_are_throttled(self):
        h = self.admin('throttle-admin')
        codes = [self.req('/api/v1/auth/reauthenticate', {'password': 'wrong-password-guess'}, h)[0] for _ in range(10)]
        self.assertIn(429, codes, codes)
        self.assertEqual(self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)[0], 429)

    def test_last_admin_cannot_be_disabled_by_another_admin(self):
        if BASELINE: self.skipTest('new guard')
        with self.app.store.db() as db: db.execute("UPDATE accounts SET enabled=0 WHERE role='admin'")
        h = self.admin('solo-a'); self.admin('solo-b')
        self.assertEqual(self.req('/api/v1/accounts', {'name': 'solo-b', 'enabled': False}, h)[0], 200)
        with self.app.store.db() as db: n = db.execute("SELECT COUNT(*) FROM accounts WHERE role='admin' AND enabled=1").fetchone()[0]
        self.assertEqual(n, 1)

    def test_sessions_list_and_revoke_other_but_not_current(self):
        if BASELINE: self.skipTest('new endpoint')
        h1 = self.admin('sess'); h2 = self.admin('sess')
        code, _, body = self.req('/api/v1/auth/sessions', headers=h1); self.assertEqual(code, 200)
        mine = [s for s in body['sessions'] if s['current']]; others = [s for s in body['sessions'] if not s['current']]
        self.assertEqual(len(mine), 1); self.assertGreaterEqual(len(others), 1)
        self.assertNotIn('hash', json.dumps(body))
        self.assertEqual(self.req('/api/v1/auth/sessions/revoke', {'id': mine[0]['id']}, h1)[0], 409)
        self.assertEqual(self.req('/api/v1/auth/sessions/revoke', {'id': others[0]['id']}, h1)[0], 200)
        self.assertEqual(self.req('/api/v1/auth/me', headers=h2)[0], 401)
        self.assertEqual(self.req('/api/v1/auth/me', headers=h1)[0], 200)

    def test_individual_token_revoke_and_list_has_no_secret(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin('tok-admin'); bearer = self.token(h, 'read')
        code, _, body = self.req('/api/v1/api-tokens', headers=h)
        self.assertEqual(code, 200); ident = body['tokens'][0]['id']; self.assertNotIn(bearer['Authorization'][7:], json.dumps(body))
        self.assertEqual(self.req('/api/v1/users', headers=bearer)[0], 200)
        self.assertEqual(self.req('/api/v1/api-tokens', {'revoke': ident}, h)[0], 200)
        self.assertEqual(self.req('/api/v1/users', headers=bearer)[0], 401)

    def test_totp_disable_needs_fresh_session_and_current_code(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin('mfa-off')
        secret = base64.b32encode(b'synthetic-mfa-key-0002').decode()
        with self.app.store.db() as db: db.execute("UPDATE accounts SET totp=?,last_totp=-1 WHERE name='mfa-off'", (secret,))
        self.assertEqual(self.req('/api/v1/auth/totp/disable', {'code': '000000'}, h)[0], 401)
        self.assertEqual(self.req('/api/v1/auth/totp/disable', {'code': totp(secret)}, h)[0], 200)


class Scope(Panel):
    WRITES = [('/api/v1/changes/prepare', {'kind': 'user-create', 'data': {'name': 'x'}}), ('/api/v1/changes/commit', {'token': 'a' * 64}),
              ('/api/v1/actions', {'action': 'backup', 'arguments': {}}), ('/api/v1/subscriptions/rotate-token', {'id': 'legacy'}),
              ('/api/v1/subscriptions/revoke', {'id': 'legacy'}), ('/api/v1/client-profiles/export', {'id': 'legacy', 'profile': 'global', 'format': 'yaml'}),
              ('/api/v1/accounts', {'name': 'x', 'password': 'reader-escalation-pw', 'role': 'admin'}), ('/api/v1/api-tokens', {'name': 'x', 'scope': 'write', 'hours': 1}),
              ('/api/v1/notifications', {'enabled': False}), ('/api/v1/notifications/test', {}), ('/api/v1/auth/change-password', {'old': 'x', 'password': 'y' * 12}),
              ('/api/v1/auth/totp/enroll', {}), ('/api/v1/alerts/silence', {'minutes': 5}), ('/api/v1/subscriptions/settings', {'landing_page': True}),
              ('/api/v1/auth/sessions/revoke', {'others': True})]

    def test_read_token_and_reader_account_cannot_mutate_anything(self):
        h = self.admin(); bearer = self.token(h, 'read')
        reader = self.admin('reader-x', 'reader', 'Reader-SYNTHETIC-password')
        for path, body in self.WRITES:
            with self.subTest(path=path, who='read-token'):
                self.assertIn(self.req(path, body, bearer)[0], (401, 403, 404), path)
            with self.subTest(path=path, who='reader'):
                code = self.req(path, body, reader)[0]
                if path in ('/api/v1/auth/change-password', '/api/v1/auth/sessions/revoke', '/api/v1/auth/totp/enroll'):
                    self.assertIn(code, (200, 401, 404, 428))  # own account only
                else:
                    self.assertIn(code, (401, 403, 404, 428), path)
        with self.app.store.db() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM accounts WHERE name='x'").fetchone())

    def test_write_token_cannot_change_security_settings(self):
        h = self.admin(); bearer = self.token(h, 'write')
        for path, body in [('/api/v1/api-tokens', {'name': 'x2', 'scope': 'write', 'hours': 1}), ('/api/v1/accounts', {'name': 'x2', 'password': 'x' * 14, 'role': 'admin'}),
                           ('/api/v1/auth/change-password', {'old': 'x', 'password': 'y' * 12}), ('/api/v1/notifications', {'enabled': False})]:
            self.assertIn(self.req(path, body, bearer)[0], (403, 428), path)

    def test_expired_token_denied_on_every_read_endpoint(self):
        h = self.admin(); bearer = self.token(h, 'read')
        with self.app.store.db() as db: db.execute('UPDATE tokens SET expires=0')
        for p in ['users', 'inbounds', 'policy', 'certificates', 'logs', 'traffic', 'dashboard', 'alerts', 'system/version', 'protocols/health', 'audit', 'subscriptions']:
            self.assertEqual(self.req('/api/v1/' + p, headers=bearer)[0], 401, p)

    def test_large_payload_bounded(self):
        conn = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=ssl._create_unverified_context(), timeout=20)
        conn.request('POST', '/api/v1/auth/login', None, {'Host': 'panel.example.test', 'Content-Type': 'application/json', 'Content-Length': '40000'})
        response = conn.getresponse(); data = response.read(); conn.close()
        self.assertEqual(response.status, 413); self.assertLess(int(response.getheader('Content-Length')), 200)


class Subscriptions(Panel):
    def rotate(self, h, ident):
        code, _, body = self.req('/api/v1/subscriptions/rotate-token', {'id': ident}, h); self.assertEqual(code, 200, body); return body

    def test_token_not_in_audit_or_timeline_and_headers(self):
        h = self.admin(); urls = self.rotate(h, 'legacy')['urls']; raw = urls['global'].split('/sub/')[1].split('/')[0]
        code, headers, data = self.req(urls['global'].replace('https://panel.example.test', ''), raw=True)
        self.assertEqual(code, 200); self.assertEqual(headers['Cache-Control'], 'no-store'); self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertTrue(headers['Content-Type'].startswith('application/yaml')); self.assertIn('attachment; filename="sbox-global.yaml"', headers['Content-Disposition'])
        self.assertNotIn('Set-Cookie', headers)
        with self.app.store.db() as db:
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            dump = '\n'.join(str(tuple(r)) for t in tables for r in db.execute('SELECT * FROM "%s"' % t))
        self.assertNotIn(raw, dump)

    def test_revoked_and_unknown_tokens_are_404_without_body_data(self):
        h = self.admin(); urls = self.rotate(h, 'legacy')['urls']; path = urls['cn'].replace('https://panel.example.test', '')
        self.assertEqual(self.req('/api/v1/subscriptions/revoke', {'id': 'legacy'}, h)[0], 200)
        code, headers, body = self.req(path, raw=True)
        self.assertEqual(code, 404); self.assertNotIn(b'proxies', body); self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.req('/sub/' + 'A' * 43 + '/global.yaml')[0], 404)

    def test_token_cannot_reach_admin_api(self):
        h = self.admin(); raw = self.rotate(h, 'legacy')['urls']['global'].split('/sub/')[1].split('/')[0]
        for p in ['/api/v1/system/status', '/api/v1/users', '/api/v1/dashboard']:
            self.assertEqual(self.req(p, headers={'Authorization': 'Bearer ' + raw})[0], 401)
            self.assertEqual(self.req(p, headers={'Cookie': 'sbox_session=' + raw})[0], 401)

    @needs_libqrencode
    def test_landing_page_opt_in_scoped_and_escaped(self):
        """Personal page = shared Export Center fed by an inert JSON catalog of this token's own URLs."""
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin(); body = self.rotate(h, 'legacy'); base = body['urls']['global'].rsplit('/', 1)[0] + '/'
        path = base.replace('https://panel.example.test', '')
        self.assertNotIn('page', body)
        self.assertEqual(self.req(path)[0], 404, 'landing page must be opt-in')
        self.assertEqual(self.req(path + 'qr?kind=sub')[0], 404, 'landing QR is opt-in too')
        self.assertEqual(self.req('/api/v1/subscriptions/settings', {'landing_page': True}, h)[0], 200)
        code, headers, page = self.req(path + '?admin=1&role=admin', raw=True)
        text = page.decode()
        self.assertEqual(code, 200); self.assertNotIn('Set-Cookie', headers); self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
        self.assertIn('&lt;b&gt;legacy&lt;/b&gt;', text); self.assertNotIn('<b>legacy</b>', text)
        self.assertIn('/export-center.js', text); self.assertIn('/subscribe.js', text); self.assertNotIn('<script>', text, 'no inline script')
        data = json.loads(re.search(r'<script type="application/json" id="xc-data">(.*?)</script>', text, re.S).group(1))
        self.assertEqual(data['user'], '<b>legacy</b>')
        for profile in ('global', 'cn', 'internal'):
            for fmt in ('yaml', 'singbox', 'json', 'links'):
                self.assertEqual(data['urls'][profile][fmt], base + profile + '.' + fmt)
        self.assertEqual(data['unavailable'], {}, 'every format offers every routing profile')
        for leak in ('/api/v1', 'csrf', 'app.js', 'uuid', 'private_key', 'private-key', 'short_id'):
            self.assertNotIn(leak, text.lower())
        for p in self.control.state['protocols'].values():
            self.assertNotIn(p['password'], text); self.assertNotIn(p['uuid'], text)
        self.assertIn('noreferrer', text)
        zh = self.req(path + '?lang=zh', raw=True)[2].decode(); self.assertIn('lang="zh-Hant"', zh); self.assertIn('"lang": "zh"', zh)
        self.req('/api/v1/subscriptions/settings', {'landing_page': False}, h)

    def test_landing_qr_only_encodes_this_tokens_own_links(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin(); base = self.rotate(h, 'legacy')['urls']['global'].rsplit('/', 1)[0] + '/'
        path = base.replace('https://panel.example.test', '')
        self.req('/api/v1/subscriptions/settings', {'landing_page': True}, h)
        for query, status in (('?kind=sub&text=https://evil.example', 400), ('?kind=sub&profile=bogus', 400), ('?kind=sub&format=links', 400),
                              ('?kind=sub&endpoint=bogus', 400), ('?kind=node&index=x', 400), ('?kind=node&index=99', 404), ('?kind=sub&profile=cn&format=bogus', 400)):
            self.assertEqual(self.req(path + 'qr' + query)[0], status, query)
        if HAVE_LIBQRENCODE:
            code, _, out = self.req(path + 'qr?kind=sub&profile=internal&format=singbox')
            self.assertEqual(code, 200, out); self.assertTrue(out['svg'].lstrip().startswith(('<?xml', '<svg')))
        self.req('/api/v1/subscriptions/settings', {'landing_page': False}, h)

    def test_singbox_full_profile_format_is_served(self):
        if BASELINE: self.skipTest('new format')
        h = self.admin(); urls = self.rotate(h, 'legacy')
        code, headers, _ = self.req(urls['exports']['internal']['singbox'].replace('https://panel.example.test', ''), raw=True)
        self.assertEqual(code, 200); self.assertIn('application/json', headers['Content-Type'])
        self.assertIn('sbox-internal-sing-box.json', headers['Content-Disposition'])
        self.assertEqual(urls['exports']['cn']['singbox'], urls['exports']['global']['singbox'].replace('global.singbox', 'cn.singbox'))
        self.assertEqual(self.req(urls['exports']['cn']['singbox'].replace('https://panel.example.test', ''))[0], 200)
        self.assertEqual(urls['catalog']['clients'][1]['formats'][0]['id'], 'singbox')

    def test_subscription_refresh_interval_header(self):
        if BASELINE: self.skipTest('new header')
        h = self.admin(); urls = self.rotate(h, 'legacy')['urls']
        self.assertEqual(self.req(urls['internal'].replace('https://panel.example.test', ''), raw=True)[1].get('Profile-Update-Interval'), '24')

    @needs_libqrencode
    def test_qr_output_with_script_refused(self):
        if BASELINE: self.skipTest('new sanitizer')
        h = self.admin()
        with patch.dict(os.environ, {'SBOX_TEST_QR_EVIL': '1'}):
            self.assertEqual(self.req('/api/v1/qr', {'text': 'https://example.test/x'}, h)[0], 503)
        code, _, body = self.req('/api/v1/qr', {'text': 'https://example.test/x'}, h)
        self.assertEqual(code, 200); self.assertTrue(body['svg'].lstrip().startswith(('<?xml', '<svg')))


class Changes(Panel):
    def users(self):
        return [u for u in self.control.op_users({}) if u['id'] != 'legacy']

    def test_bulk_disable_exact_ids_preview_and_legacy_protection(self):
        if BASELINE: self.skipTest('new kind')
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        ids = [u['id'] for u in self.users()[:2]]
        code, _, body = self.req('/api/v1/changes/prepare', {'kind': 'users-bulk', 'data': {'action': 'disable', 'ids': ids + ['legacy']}}, h)
        self.assertEqual(code, 403, body)
        code, _, body = self.req('/api/v1/changes/prepare', {'kind': 'users-bulk', 'data': {'action': 'disable', 'ids': ids}}, h)
        self.assertEqual(code, 200, body)
        names = {u['name'] for u in self.users() if u['id'] in ids}
        self.assertEqual(set(body['summary']['users']['disabled']), {n for n in names if any(u['enabled'] for u in self.users() if u['name'] == n)})
        self.assertEqual(body['summary']['protected_identity'], 'unchanged')
        self.assertTrue(any('sing-box' in s for s in body['summary']['services']))
        self.assertNotIn('password', json.dumps(body['summary']).lower())
        before = {u['id']: u['enabled'] for u in self.users()}
        code, _, result = self.req('/api/v1/changes/commit', {'token': body['token']}, h)
        self.assertEqual(code, 200, result); self.assertTrue(result['committed']); self.assertIn('state_fingerprint', result)
        after = {u['id']: u['enabled'] for u in self.users()}
        for ident in before:
            self.assertEqual(after[ident], False if ident in ids else before[ident])

    def test_stale_preview_denied_after_out_of_band_change(self):
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        code, _, body = self.req('/api/v1/changes/prepare', {'kind': 'user-create', 'data': {'name': 'stale-one'}}, h); self.assertEqual(code, 200, body)
        self.control.state['managed_users'].append(self.control._user('cli-added'))  # simulated CLI mutation
        code, _, result = self.req('/api/v1/changes/commit', {'token': body['token']}, h)
        self.assertEqual(code, 409, result); self.assertFalse(any(u['name'] == 'stale-one' for u in self.users()))

    def test_commit_token_single_use(self):
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        code, _, body = self.req('/api/v1/changes/prepare', {'kind': 'user-create', 'data': {'name': 'once-only'}}, h)
        self.assertEqual(self.req('/api/v1/changes/commit', {'token': body['token']}, h)[0], 200)
        self.assertIn(self.req('/api/v1/changes/commit', {'token': body['token']}, h)[0], (404, 422))
        self.assertEqual(sum(1 for u in self.users() if u['name'] == 'once-only'), 1)

    def test_zgocloud_inbound_edit_refused(self):
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        self.assertEqual(self.req('/api/v1/changes/prepare', {'kind': 'inbounds', 'data': {'tuic': {'port': 40000}}}, h)[0], 403)

    def test_bulk_create_100_independent_credentials(self):
        state = {'protocols': {p: {'enabled': True, 'uuid': 'legacy-' + p, 'password': 'legacy-pw-' + p} for p in ('reality', 'vmess', 'hy2', 'tuic', 'anytls')}}
        result = controller.candidate(state, {'kind': 'users-import', 'data': {'names': ['bulk%03d' % i for i in range(100)]}}, 'zgocloud')
        creds = [(p, r['uuid'], r['password']) for u in result['managed_users'] for p, r in u['protocols'].items()]
        self.assertEqual(len(result['managed_users']), 100); self.assertEqual(len(creds), 500)
        self.assertEqual(len({c[1] for c in creds}), 500); self.assertEqual(len({c[2] for c in creds}), 500)
        self.assertEqual(result['protocols'], state['protocols'])


class Monitoring(Panel):
    def test_dashboard_sources_and_advanced_raw(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin(); code, _, body = self.req('/api/v1/dashboard', headers=h)
        self.assertEqual(code, 200, body)
        keys = {t['key'] for t in body['tiles']}
        self.assertTrue({'core', 'panel', 'certificate', 'listeners', 'external'} <= keys)
        for t in body['tiles']: self.assertTrue(t['source'], t)
        external = next(t for t in body['tiles'] if t['key'] == 'external'); self.assertEqual(external['status'], 'unknown')
        self.assertIn('renewal_timers', json.dumps(body['advanced'])); self.assertNotIn('renewal_timers', json.dumps({k: v for k, v in body.items() if k != 'advanced'}))

    def test_missing_certbot_timer_is_unavailable_not_503(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin(); old = self.control.op_overview
        def no_timer(data):
            v = old(data); v['renewal_timers'] = {'certbot.timer': {'ActiveState': 'unavailable', 'reason': 'Unit is not installed'}}; return v
        self.control.op_overview = no_timer
        try:
            code, _, body = self.req('/api/v1/dashboard', headers=h)
        finally: self.control.op_overview = old
        self.assertEqual(code, 200); cert = next(t for t in body['tiles'] if t['key'] == 'certificate'); self.assertEqual(cert['detail']['renewal'], 'unavailable')

    def test_alert_open_dedup_resolve_and_timeline(self):
        if BASELINE: self.skipTest('new engine')
        self.control.service_state = 'failed'
        try:
            self.app.evaluate(); self.app.evaluate()
            rows = {a['key']: a for a in self.app.store.alerts()}
            self.assertIn('core.down', rows); self.assertEqual(rows['core.down']['severity'], 'critical'); self.assertGreaterEqual(rows['core.down']['count'], 2)
            self.assertIsNone(rows['core.down']['resolved_at'])
        finally: self.control.service_state = 'active'
        transitions = self.app.evaluate()
        self.assertIn(('resolved', 'core.down'), [(t[0], t[1]) for t in transitions])
        h = self.admin(); _, _, body = self.req('/api/v1/alerts', headers=h)
        kinds = [e['kind'] for e in body['timeline']]
        self.assertIn('alert-opened', kinds); self.assertIn('alert-resolved', kinds)
        self.assertIsNotNone(next(a for a in body['alerts'] if a['key'] == 'core.down')['resolved_at'])

    def test_notifications_only_on_transitions(self):
        if BASELINE: self.skipTest('new engine')
        sent = []
        self.app.store.set_setting('notifications', {'enabled': True, 'url': 'https://hooks.example.test/x', 'kind': 'webhook'})
        with patch.object(self.app, 'notify', side_effect=lambda e, d: sent.append(e)):
            self.control.service_state = 'failed'
            try:
                for _ in range(3): self.app.evaluate()
            finally: self.control.service_state = 'active'
            self.app.evaluate(); self.app.evaluate()
        self.app.store.set_setting('notifications', {})
        self.assertEqual([e for e in sent if 'core.down' in e], ['alert:core.down:opened', 'alert:core.down:resolved'])

    def test_listener_missing_alert(self):
        if BASELINE: self.skipTest('new engine')
        self.control.listening['tuic'] = False
        try:
            self.app.evaluate(); self.assertIn('listener.tuic-in', self.app.store.open_alert_keys())
        finally: self.control.listening['tuic'] = True
        self.app.evaluate(); self.assertNotIn('listener.tuic-in', self.app.store.open_alert_keys())

    def test_traffic_window_and_report_redacted(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin()
        for w in ('1h', '24h', '7d'):
            code, _, body = self.req('/api/v1/traffic?window=' + w, headers=h); self.assertEqual(code, 200, body); self.assertIn('host-wide', body['unit'])
        self.assertEqual(self.req('/api/v1/traffic?window=99y', headers=h)[0], 400)
        code, headers, text = self.req('/api/v1/diagnostics/report', headers=h, raw=True)
        self.assertEqual(code, 200); text = text.decode()
        for p in self.control.state['protocols'].values():
            self.assertNotIn(p['password'], text); self.assertNotIn(p['uuid'], text)

    def test_audit_filters(self):
        if BASELINE: self.skipTest('new filters')
        self.req('/api/v1/auth/login', {'username': 'admin', 'password': 'definitely-wrong'})
        h = self.admin()
        code, _, body = self.req('/api/v1/audit?outcome=denied&event=login', headers=h)
        self.assertEqual(code, 200); self.assertTrue(body['events']); self.assertTrue(all(e['outcome'] == 'denied' for e in body['events']))
        code, _, body = self.req('/api/v1/audit?actor=admin&limit=5', headers=h)
        self.assertTrue(all(e['actor'] == 'admin' for e in body['events'])); self.assertLessEqual(len(body['events']), 5)

    def test_protocol_health_local_probe_labels(self):
        if BASELINE: self.skipTest('new endpoint')
        h = self.admin(); code, _, body = self.req('/api/v1/protocols/probe', {}, h)
        self.assertEqual(code, 200, body)
        for row in body['protocols']:
            self.assertEqual(row['external_probe']['status'], 'not-run')
            if row['network'] == 'udp': self.assertEqual(row['local_probe']['status'], 'not-probed')
        self.assertTrue(all('NAT alias' in a['kind'] for a in body['aliases']))


class Universal(Panel):
    variant = 'universal'

    def test_universal_inbound_preview_lists_listener_and_firewall_impact(self):
        if BASELINE: self.skipTest('new preview')
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        code, _, body = self.req('/api/v1/changes/prepare', {'kind': 'inbounds', 'data': {'anytls': {'port': 27999}}}, h)
        self.assertEqual(code, 200, body)
        self.assertEqual(body['summary']['listeners'], [{'protocol': 'anytls', 'field': 'port', 'before': 27443, 'after': 27999}])
        self.assertTrue(any('firewall' in s for s in body['summary']['services']))


class Startup(unittest.TestCase):
    """The panel must accept connections as soon as it is started, even when DNS is slow or broken."""

    def test_server_listens_without_reverse_dns(self):
        def slow(*_a, **_k):
            time.sleep(6); return 'slow.invalid'
        with patch('socket.getfqdn', slow):
            t0 = time.time(); srv = Server(('127.0.0.1', 0), object()); took = time.time() - t0
        try:
            self.assertLess(took, 1.0, 'server construction waited on reverse DNS')
            with socket.create_connection(srv.server_address[:2], timeout=1): pass
        finally: srv.server_close()

    def test_installer_readiness_requires_an_accepting_socket(self):
        import install
        self.assertTrue(hasattr(install, 'wait_listening'), 'installer readiness only checks systemd is-active')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); port = listener.getsockname()[1]
            self.assertTrue(install.wait_listening('0.0.0.0', port, 2))  # wildcard listen is probed on loopback
        with socket.socket() as closed:
            closed.bind(('127.0.0.1', 0)); port = closed.getsockname()[1]   # bound, not listening
            t0 = time.time(); self.assertFalse(install.wait_listening('127.0.0.1', port, 1.0)); self.assertLess(time.time() - t0, 3)


class NotificationTransport(unittest.TestCase):
    """Webhook delivery: redirects are never followed and TLS must match the hostname."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); d = pathlib.Path(cls.tmp.name); cls.d = d
        run = lambda *a: subprocess.run([str(x) for x in a], check=True, capture_output=True)
        run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=Test CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign', '-addext', 'subjectKeyIdentifier=hash', '-keyout', d / 'ca.key', '-out', d / 'ca.crt')
        for host in ('hook.example.test', 'other.example.test'):
            run('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=' + host, '-keyout', d / (host + '.key'), '-out', d / (host + '.csr'))
            (d / (host + '.ext')).write_text('subjectAltName=DNS:%s\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' % host)
            run('openssl', 'x509', '-req', '-in', d / (host + '.csr'), '-CA', d / 'ca.crt', '-CAkey', d / 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', d / (host + '.ext'), '-out', d / (host + '.crt'))
        cls.app = App({'database': str(d / 'db'), 'origin': 'https://panel.example.test', 'frontend': str(ROOT / 'frontend'), 'variant': 'universal'}, FixtureControl('universal', 0))
        cls.app.store.set_setting('notifications', {'enabled': True, 'url': 'https://hook.example.test/x', 'kind': 'webhook'})

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def serve(self, host, status, location=None):
        import http.server as hs
        hits = []
        class H(hs.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path); self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(status)
                if location: self.send_header('Location', location)
                self.send_header('Content-Length', '0'); self.end_headers()
            def log_message(self, *a): pass
        srv = hs.HTTPServer(('127.0.0.1', 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(self.d / (host + '.crt'), self.d / (host + '.key'))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, hits

    def deliver(self, port):
        import server as S
        real = socket.create_connection
        make = ssl.create_default_context
        trust = lambda *a, **k: make(cafile=str(self.d / 'ca.crt'))
        # Validated public address is pinned by public_https_url; here it is redirected to the local test server.
        with patch.object(S, 'public_https_url', lambda url: (__import__('urllib.parse').parse.urlsplit(url), ['192.0.2.10'])), \
             patch.object(S.socket, 'create_connection', lambda addr, timeout=None: real(('127.0.0.1', port), timeout)), \
             patch.object(S.ssl, 'create_default_context', trust):
            self.app.store.set_setting('notification-last', {})
            return self.app.notify('lab-test', {'detail': 'x'})

    def test_redirect_to_private_destination_is_not_followed(self):
        srv, hits = self.serve('hook.example.test', 302, 'http://169.254.169.254/latest/meta-data/')
        try:
            with self.assertRaises(Problem) as cm: self.deliver(srv.server_address[1])
            self.assertEqual(cm.exception.status, 422)
            self.assertEqual(hits, ['/x'])  # one request; the Location was never fetched
        finally: srv.shutdown(); srv.server_close()

    def test_tls_hostname_mismatch_is_rejected(self):
        srv, hits = self.serve('other.example.test', 200)
        try:
            with self.assertRaises((ssl.SSLCertVerificationError, ssl.SSLError, Problem)): self.deliver(srv.server_address[1])
            self.assertEqual(hits, [], 'payload must not be sent over an unverified TLS session')
        finally: srv.shutdown(); srv.server_close()

    def test_matching_certificate_delivers(self):
        srv, hits = self.serve('hook.example.test', 204)
        try:
            self.deliver(srv.server_address[1]); self.assertEqual(hits, ['/x'])
        finally: srv.shutdown(); srv.server_close()


class TrafficCounters(unittest.TestCase):
    """Host traffic rates from /proc/net/dev counters (no synthetic data)."""

    def sample(self, t, eth_rx, eth_tx, uptime, extra=None):
        net = {'eth0': {'rx': eth_rx, 'tx': eth_tx}, 'lo': {'rx': 10 ** 12, 'tx': 10 ** 12}, 'veth9': {'rx': t * 10 ** 6, 'tx': t * 10 ** 6}}
        net.update(extra or {})
        return {'sampled_at': t, 'uptime_seconds': uptime, 'network': net}

    def test_steady_rate_excludes_loopback_and_veth(self):
        import monitor
        s = [self.sample(1000 + 30 * i, 3000 * 30 * i, 1000 * 30 * i, 500 + 30 * i) for i in range(5)]
        r = monitor.rate_series(s, 3600, now=1150)
        self.assertEqual(r['interfaces'], ['eth0'])
        self.assertEqual({round(p['rx_bps']) for p in r['points']}, {3000}); self.assertEqual({round(p['tx_bps']) for p in r['points']}, {1000})
        self.assertEqual((r['resets_dropped'], r['gaps']), (0, 0))

    def test_counter_reset_and_reboot_are_dropped_not_negative(self):
        import monitor
        s = [self.sample(1000, 9_000_000, 9_000_000, 900), self.sample(1030, 9_090_000, 9_030_000, 930),
             self.sample(1060, 1_000, 1_000, 960),            # driver reload: counters restart at ~0
             self.sample(1090, 91_000, 31_000, 990),
             self.sample(1120, 5_000, 5_000, 12),             # reboot: uptime went backwards
             self.sample(1150, 95_000, 35_000, 42)]
        r = monitor.rate_series(s, 3600, now=1150)
        self.assertEqual(r['resets_dropped'], 2)
        self.assertTrue(all(p['rx_bps'] >= 0 and p['tx_bps'] >= 0 for p in r['points']))
        self.assertLessEqual(r['stats']['rx_max'], 3000)

    def test_missing_samples_are_a_gap_not_a_flat_line(self):
        import monitor
        s = [self.sample(1000, 0, 0, 10), self.sample(1030, 30_000, 30_000, 40), self.sample(1600, 600_000, 600_000, 610), self.sample(1630, 630_000, 630_000, 640)]
        r = monitor.rate_series(s, 3600, now=1630)
        self.assertEqual(r['gaps'], 1); self.assertTrue(any(p.get('gap') for p in r['points']))

    def test_large_64bit_counters_and_new_interface(self):
        import monitor
        big = 2 ** 63
        s = [self.sample(1000, big, big, 10), self.sample(1030, big + 30 * 5000, big + 30 * 5000, 40, {'ens5': {'rx': 0, 'tx': 0}}),
             self.sample(1060, big + 60 * 5000, big + 60 * 5000, 70, {'ens5': {'rx': 30 * 100, 'tx': 0}})]
        r = monitor.rate_series(s, 3600, now=1060)
        self.assertEqual([round(p['rx_bps']) for p in r['points']], [5000, 5100])
        self.assertEqual(r['interfaces'], ['ens5', 'eth0'])

    def test_empty_history_is_empty_not_zero(self):
        import monitor
        r = monitor.rate_series([], 3600, now=1000)
        self.assertEqual(r['points'], []); self.assertIsNone(r['latest']); self.assertIsNone(r['stats']['rx_p50'])


class ApiSpec(Panel):
    """api-spec/openapi.json documents every dispatcher route; documented reads are live."""

    def test_spec_matches_dispatcher_routes(self):
        r = subprocess.run([sys.executable, str(ROOT / 'tools/api_inventory.py')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-800:])

    def test_documented_reads_respond(self):
        h = self.admin(); spec = json.loads((ROOT / 'api-spec/openapi.json').read_text())
        bad = {}
        for path, methods in spec['paths'].items():
            if 'get' not in methods or '{' in path or path.endswith('logs/stream'): continue
            code, _, _ = self.req(path, headers=h)
            if code in (404, 405) or code >= 500: bad[path] = code
        self.assertEqual(bad, {})


class DashboardLoad(Panel):
    """Concurrent dashboard polling must not multiply root-bridge calls or SQLite writes."""

    def test_concurrent_dashboards_share_bridge_reads(self):
        h = self.admin(); calls = []; real = self.app.control
        def counting(op, data=None):
            calls.append(op); time.sleep(0.02)  # the real bridge runs a subprocess per op
            return real(op, data) if data is not None else real(op)
        writes = []; real_sample = self.app.store.sample
        self.app.control = counting; self.app.store.sample = lambda v: (writes.append(1), real_sample(v))
        try:
            with self.app.cache_lock: self.app.cache.clear()
            results = []
            def hit():
                code, _, body = self.req('/api/v1/dashboard', headers=h); results.append((code, body.get('tiles') is not None if isinstance(body, dict) else False))
            ts = [threading.Thread(target=hit) for _ in range(20)]
            [t.start() for t in ts]; [t.join() for t in ts]
        finally:
            self.app.control = real; self.app.store.sample = real_sample
        self.assertEqual({r for r in results}, {(200, True)})
        per_op = {op: calls.count(op) for op in set(calls)}
        self.assertLessEqual(len(calls), 6, per_op)     # was 3 bridge calls per request (60)
        self.assertLessEqual(len(writes), 2, len(writes))

    def test_commit_invalidates_cached_dashboard(self):
        h = self.admin(); self.req('/api/v1/auth/reauthenticate', {'password': 'Admin-SYNTHETIC-password-1'}, h)
        _, _, before = self.req('/api/v1/dashboard', headers=h)
        code, _, prev = self.req('/api/v1/changes/prepare', {'kind': 'user-create', 'data': {'name': 'cache-probe'}}, h)
        self.assertEqual(code, 200, prev)
        code, _, res = self.req('/api/v1/changes/commit', {'token': prev['token']}, h); self.assertEqual(code, 200, res)
        with self.app.cache_lock: self.assertEqual(self.app.cache, {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
