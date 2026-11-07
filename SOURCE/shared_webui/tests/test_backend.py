"""Executed stdlib security/HTTP contracts; simulated control is NOT VPN evidence."""
import base64,copy,http.client,importlib.util,json,os,pathlib,socket,sqlite3,ssl,subprocess,sys,tempfile,threading,time,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'));sys.path.insert(0,str(ROOT/'privileged-bridge'))
from common import Problem,atomic_json,digest,password_hash,password_ok,public_https_url,redact,totp,verify_totp
from store import Store
from server import App,Server
from controller import candidate
from bridge import Control

class Security(unittest.TestCase):
    def test_missing_optional_certbot_timer_keeps_host_status_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            control=Control(base=tmp)
            control.state=lambda:{'sing_box':{'version':'1.13.14'}}
            def observed(args,data=None,timeout=60):
                if 'certbot.timer' in args:raise Problem(422,'Unit not installed')
                if args[-1]=='version':return 'sing-box version 1.13.14\n'
                if 'journalctl' in args[0]:return '-- No entries --\n'
                return 'ActiveState=active\nMainPID=0\n'
            control.run=observed
            result=control.overview()
            self.assertEqual(result['renewal_timers']['certbot.timer']['ActiveState'],'unavailable')
            self.assertEqual(result['recent_errors']['count'],0)
    def test_uninstalled_panel_reinstalls_even_with_retained_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp);settings=path/'etc/sbox-webui/settings.json';settings.parent.mkdir(parents=True);settings.write_text('{}')
            source=(ROOT/'privileged-bridge/manager_extension.sh').read_text().replace('/etc/',str(path)+'/etc/')
            script=path/'functions';script.write_text(source)
            result=subprocess.run(['bash','-c','source "$1"; webui_command() { echo INSTALLED; }; webui_install_if_enabled','test',str(script)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'INSTALLED')
    def test_atomic_file_mode_overrides_restrictive_installer_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'settings';old=os.umask(0o077)
            try:atomic_json(path,{'schema':1},0o640)
            finally:os.umask(old)
            self.assertEqual(path.stat().st_mode&0o777,0o640)
    def test_password_scrypt_salted_and_memory_hard(self):
        a=password_hash('SYNTHETIC-12-password');b=password_hash('SYNTHETIC-12-password')
        self.assertNotEqual(a,b);self.assertIn('scrypt$32768$8$3$',a);self.assertTrue(password_ok('SYNTHETIC-12-password',a));self.assertFalse(password_ok('bad',a))
    def test_short_and_huge_password_rejected(self):
        for s in ['short','a'*257,None]:
            with self.assertRaises(Problem):password_hash(s)
    def test_totp_window_replay(self):
        secret=base64.b32encode(b'synthetic-key-0123456').decode();step=int(time.time()//30)
        self.assertEqual(verify_totp(secret,totp(secret,step)),step)
        self.assertIsNone(verify_totp(secret,totp(secret,step),step));self.assertIsNone(verify_totp(secret,'bad'))
    def test_redaction(self):
        v=redact({'password':'hidden','private_key':'hidden','uuid':'hidden','body':'password=hidden https://example.test/token vless://hidden'})
        self.assertNotIn('hidden',json.dumps(v));self.assertNotIn('example.test',json.dumps(v))
    def test_redaction_json_bearer_and_pem(self):
        for text in ['"password": "HIDDEN_VALUE"','Authorization: Bearer HIDDEN_VALUE','-----BEGIN PRIVATE KEY-----\nHIDDEN_VALUE\n-----END PRIVATE KEY-----']:
            self.assertNotIn('HIDDEN_VALUE',redact(text))
    def test_ssrf_rejects_private_metadata_mixed_dns(self):
        for value in ['http://example.test','https://127.0.0.1','https://169.254.169.254','https://[::1]','https://user:pass@example.test','https://example.test:9443','https://example.test/#frag']:
            with self.subTest(value=value),self.assertRaises(Problem):public_https_url(value)
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443)),(2,1,6,'',('10.0.0.1',443))]),self.assertRaises(Problem):public_https_url('https://example.test')
    def test_ssrf_resolves_public_and_pins(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]):self.assertEqual(public_https_url('https://example.test/path')[1],['1.1.1.1'])
    def test_controller_new_user_unique_and_not_reusing_legacy(self):
        state={'protocols':{p:{'enabled':True} for p in ('reality','vmess','hy2','tuic','anytls')}}
        a=candidate(state,{'kind':'user-create','data':{'name':'Alice'}},'zgocloud')
        b=candidate(a,{'kind':'user-create','data':{'name':'Bob'}},'zgocloud')
        self.assertEqual(len(b['managed_users']),2)
        self.assertNotEqual(b['managed_users'][0]['protocols'],b['managed_users'][1]['protocols']);self.assertEqual(b['protocols'],state['protocols'])
    def test_controller_legacy_denial_and_unknown_fields(self):
        state={'protocols':{}}
        for req in [{'kind':'inbounds','data':{'tuic':{'port':9443}}},{'kind':'user-disable','id':'legacy'},{'kind':'user-create','data':{'name':'x','quota':1}},{'kind':'policy','data':{'exec':'id'}}]:
            with self.assertRaises(Problem):candidate(state,req,'zgocloud')

class Database(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.store=Store(self.root/'panel.db');self.creds=self.root/'bootstrap';self.store.bootstrap(self.creds);self.password=self.creds.read_text().split('Password: ')[1].splitlines()[0]
    def tearDown(self):self.tmp.cleanup()
    def test_bootstrap_root_mode_entropy_no_plaintext_db(self):
        self.assertEqual(self.creds.stat().st_mode&0o777,0o600);self.assertGreaterEqual(len(self.password),43);self.assertNotIn(self.password.encode(),(self.root/'panel.db').read_bytes())
    def test_reset_admin_revokes_sessions_and_tokens(self):
        sid,_=self.store.login('admin',self.password,'','127.0.0.1');self.assertTrue(self.store.auth(sid)['reset']);self.store.bootstrap(self.creds)
        with self.assertRaises(Problem):self.store.auth(sid)
    def test_root_reset_recovers_from_login_throttle(self):
        for _ in range(8):
            with self.assertRaises(Problem):self.store.login('admin','wrong','','127.0.0.1')
        self.store.bootstrap(self.creds)
        password=self.creds.read_text().split('Password: ')[1].splitlines()[0]
        sid,_=self.store.login('admin',password,'','127.0.0.1');self.assertTrue(self.store.auth(sid)['reset'])
    def test_first_password_change_rotates_csrf(self):
        sid,csrf=self.store.login('admin',self.password,'','127.0.0.1');actor=self.store.auth(sid);new=self.store.change_password(actor,sid,self.password,'different-strong-password')
        self.assertNotEqual(csrf,new);self.assertFalse(self.store.auth(sid)['reset'])
    def test_session_idle_and_absolute_expiry(self):
        sid,_=self.store.login('admin',self.password,'','127.0.0.1')
        with self.store.db() as db:db.execute('UPDATE sessions SET seen=?',(time.time()-1801,))
        with self.assertRaises(Problem):self.store.auth(sid)
    def test_login_rate_limit(self):
        for _ in range(8):
            with self.assertRaises(Problem):self.store.login('wrong','wrong','','test')
        with self.assertRaises(Problem) as e:self.store.login('admin',self.password,'','test')
        self.assertEqual(e.exception.status,429)
    def test_newer_schema_and_corrupt_db_fail_closed(self):
        with self.store.db() as db:db.execute('PRAGMA user_version=999')
        with self.assertRaises(Problem):Store(self.root/'panel.db')
        (self.root/'broken.db').write_bytes(b'broken')
        with self.assertRaises(sqlite3.DatabaseError):Store(self.root/'broken.db')
    def test_bounded_samples_and_audit(self):
        self.store.sample({'sampled_at':time.time()-100000,'network':{}});self.store.sample({'sampled_at':time.time(),'network':{}})
        self.assertEqual(len(self.store.history()),1)

class HTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=pathlib.Path(cls.tmp.name)
        def control(op,data=None):
            if op=='users':return [{'id':'legacy','name':'Legacy','enabled':True,'protected':True,'tags':[],'protocols':['tuic']}]
            if op=='export':return {'content':'proxies: []\n'}
            if op=='prepare':return {'token':'a'*64,'diff':'example','restart':False}
            return {'schema':1,'variant':'universal'}
        cls.app=App({'database':str(cls.root/'db'),'origin':'https://panel.example.test','frontend':str(ROOT/'frontend')},control)
        cls.app.store.bootstrap(cls.root/'credentials');cls.password=(cls.root/'credentials').read_text().split('Password: ')[1].splitlines()[0]
        cls.server=Server(('127.0.0.1',0),cls.app)
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=panel.example.test','-keyout',str(cls.root/'key'),'-out',str(cls.root/'cert')],check=True,capture_output=True)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cls.root/'cert',cls.root/'key');cls.server.socket=ctx.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
    def req(self,path,body=None,headers=None,method=None):
        conn=http.client.HTTPSConnection('127.0.0.1',self.server.server_port,context=ssl._create_unverified_context(),timeout=10)
        h={'Host':'panel.example.test',**(headers or {})}
        if body is not None:h['Content-Type']='application/json';body=json.dumps(body)
        conn.request(method or ('POST' if body is not None else 'GET'),path,body,h)
        response=conn.getresponse();data=response.read();result=(response.status,dict(response.getheaders()),data);conn.close();return result
    def login(self):
        # Reset between tests, preserving independent rate keys through valid login.
        self.app.store.bootstrap(self.root/'credentials');p=(self.root/'credentials').read_text().split('Password: ')[1].splitlines()[0]
        code,h,b=self.req('/api/v1/auth/login',{'username':'admin','password':p});self.assertEqual(code,200)
        return h['Set-Cookie'].split(';')[0],json.loads(b)['csrf'],p
    def ready(self):
        cookie,csrf,p=self.login();code,_,body=self.req('/api/v1/auth/change-password',{'old':p,'password':'new-SYNTHETIC-password'},{'Cookie':cookie,'X-CSRF-Token':csrf});self.assertEqual(code,200)
        return {'Cookie':cookie,'X-CSRF-Token':json.loads(body)['csrf']}
    def test_public_health_minimal_and_no_admin(self):
        code,_,body=self.req('/api/v1/health');self.assertEqual(code,200);self.assertEqual(set(json.loads(body)),{'ok','schema'})
        for p in ['system/status','users','logs','certificates','api-docs']:self.assertEqual(self.req('/api/v1/'+p)[0],401)
    def test_ipv6_listener_accepts_ipv4_and_ipv6_tls(self):
        if not socket.has_ipv6:self.skipTest('IPv6 unavailable')
        try:socket.socket(socket.AF_INET6).close()
        except OSError:self.skipTest('Kernel IPv6 disabled on this test host (NOT_RUN, not PASS)')
        server=Server(('::',0),self.app)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(self.root/'cert',self.root/'key');server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for host in ['127.0.0.1','::1']:
                client=http.client.HTTPSConnection(host,server.server_port,context=ssl._create_unverified_context(),timeout=5)
                client.request('GET','/api/v1/health',headers={'Host':'panel.example.test'});response=client.getresponse();self.assertEqual(response.status,200);response.read();client.close()
        finally:server.shutdown();server.server_close()
    def test_secure_cookie_first_login_gate(self):
        cookie,csrf,p=self.login();self.assertEqual(self.req('/api/v1/users',headers={'Cookie':cookie})[0],428)
        code,h,_=self.req('/api/v1/auth/login',{'username':'admin','password':p});self.assertEqual(code,200)
        for flag in ('Secure','HttpOnly','SameSite=Strict'):self.assertIn(flag,h['Set-Cookie'])
    def test_csrf_origin_and_host_denial(self):
        h=self.ready();self.assertEqual(self.req('/api/v1/changes/prepare',{}, {'Cookie':h['Cookie']})[0],403)
        self.assertEqual(self.req('/api/v1/users',headers={**h,'Origin':'https://evil.test'})[0],403)
        self.assertEqual(self.req('/api/v1/users',headers={**h,'Host':'evil.test'})[0],400)
        code,headers,_=self.req('/api/v1/users',headers=h);self.assertEqual(code,200);self.assertNotIn('Access-Control-Allow-Origin',headers)
    def test_logout_revokes_session(self):
        h=self.ready();self.assertEqual(self.req('/api/v1/auth/logout',{},h)[0],200);self.assertEqual(self.req('/api/v1/auth/me',headers=h)[0],401)
    def test_reader_cannot_mutate_but_can_change_own_password(self):
        h=self.ready();self.assertEqual(self.req('/api/v1/accounts',{'name':'reader','password':'reader-SYNTHETIC-password','role':'reader'},h)[0],200)
        _,head,b=self.req('/api/v1/auth/login',{'username':'reader','password':'reader-SYNTHETIC-password'});rh={'Cookie':head['Set-Cookie'].split(';')[0],'X-CSRF-Token':json.loads(b)['csrf']}
        code,_,body=self.req('/api/v1/auth/change-password',{'old':'reader-SYNTHETIC-password','password':'reader-new-password'},rh);self.assertEqual(code,200)
        rh['X-CSRF-Token']=json.loads(body)['csrf'];self.assertEqual(self.req('/api/v1/changes/prepare',{},rh)[0],403)
    def test_read_token_denied_write_expired_token_denied_read(self):
        h=self.ready();code,_,body=self.req('/api/v1/api-tokens',{'name':'test','scope':'read','hours':1},h);self.assertEqual(code,200)
        raw=json.loads(body)['token'];bh={'Authorization':'Bearer '+raw}
        self.assertEqual(self.req('/api/v1/users',headers=bh)[0],200);self.assertEqual(self.req('/api/v1/changes/prepare',{},bh)[0],403)
        with self.app.store.db() as db:db.execute('UPDATE tokens SET expires=0')
        self.assertEqual(self.req('/api/v1/users',headers=bh)[0],401)
    def test_read_token_cannot_change_account_password_even_with_old_password(self):
        h=self.ready();code,_,body=self.req('/api/v1/api-tokens',{'name':'password-scope','scope':'read','hours':1},h);self.assertEqual(code,200)
        bh={'Authorization':'Bearer '+json.loads(body)['token']}
        self.assertEqual(self.req('/api/v1/auth/change-password',{'old':'new-SYNTHETIC-password','password':'another-SYNTHETIC-password'},bh)[0],403)
    def test_subscription_rotated_revoked_and_not_admin(self):
        h=self.ready();code,_,body=self.req('/api/v1/subscriptions/rotate-token',{'id':'legacy'},h);self.assertEqual(code,200)
        path=json.loads(body)['urls']['global'].replace('https://panel.example.test','');code,headers,body=self.req(path);self.assertEqual(code,200);self.assertEqual(body,b'proxies: []\n');self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(self.req(path,headers={'If-None-Match':headers['ETag']})[0],304)
        self.req('/api/v1/subscriptions/rotate-token',{'id':'legacy'},h);self.assertEqual(self.req(path)[0],404)
        self.assertEqual(self.req('/api/v1/users',headers={'Authorization':'Bearer '+path.split('/')[2]})[0],401)
    def test_sensitive_reauth_expiry(self):
        h=self.ready()
        with self.app.store.db() as db:db.execute('UPDATE sessions SET fresh=0')
        self.assertEqual(self.req('/api/v1/subscriptions/rotate-token',{'id':'legacy'},h)[0],428)
    def test_path_traversal_invalid_actions_and_frame_csp(self):
        for p in ['/../etc/passwd','/%2e%2e/etc/passwd','/app.js/../../etc/passwd']:self.assertEqual(self.req(p)[0],400)
        h=self.ready();self.assertEqual(self.req('/api/v1/actions',{'action':'exec','arguments':{'command':'id'}},h)[0],400)
        _,headers,_=self.req('/');self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy']);self.assertEqual(headers['X-Frame-Options'],'DENY')
    def test_malformed_json_and_body_limit(self):
        conn=http.client.HTTPSConnection('127.0.0.1',self.server.server_port,context=ssl._create_unverified_context(),timeout=20)
        conn.request('POST','/api/v1/auth/login',None,{'Host':'panel.example.test','Content-Type':'application/json','Content-Length':'33000'})
        response=conn.getresponse();response.read();conn.close();self.assertEqual(response.status,413)
    def test_account_disable_revokes_session(self):
        h=self.ready()
        # Account may have been created by another test; use a distinct name.
        self.req('/api/v1/accounts',{'name':'blocked','password':'blocked-password-123','role':'admin'},h)
        _,head,_=self.req('/api/v1/auth/login',{'username':'blocked','password':'blocked-password-123'});cookie=head['Set-Cookie'].split(';')[0]
        self.req('/api/v1/accounts',{'name':'blocked','enabled':False},h)
        self.assertEqual(self.req('/api/v1/auth/me',headers={'Cookie':cookie})[0],401)

if __name__=='__main__':unittest.main(verbosity=2)
