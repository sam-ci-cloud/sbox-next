import ipaddress
"""Self-hosted HTTPS panel with cookie/CSRF and scoped API authentication."""
import base64
import hashlib
import hmac
import html
from http import cookies
from auth_events import auth_failure
import export_catalog
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import re
from pathlib import Path
import secrets
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import threading
import sys
import traceback
import time
import urllib.parse
from common import Problem, SCHEMA, VERSION, clean_name, digest, password_hash, password_ok, public_https_url, redact, require, token, verify_totp
import monitor
import probes
from store import Store
from subscription_vault import SubscriptionVault

PROFILES = ('global', 'cn', 'internal')
STARTED = time.time()


class UnixControl:
    def __init__(self, path, monitor_key=''):
        self.path=path;self.local=threading.local();self.monitor_key=monitor_key
    def set_context(self,value):self.local.context=value
    def clear_context(self):self.local.__dict__.clear()
    def __call__(self, op, data=None):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(920)
            sock.connect(self.path)
            sock.sendall(json.dumps({'op': op, 'data': data or {},'context':getattr(self.local,'context',{'kind':'monitor','key':self.monitor_key})}).encode() + b'\n')
            with sock.makefile('rb') as stream: raw = stream.readline(1048577)
        require(len(raw) <= 1048576, 'Control response too large', 503)
        result = json.loads(raw)
        if not result['ok']: raise Problem(result['status'], result['error'])
        return result['data']


class App:
    def __init__(self, settings, control=None):
        self.cfg = settings
        self.store = Store(settings['database'])
        self.subscriptions = SubscriptionVault(self.store)
        self.control = control or UnixControl(settings['socket'],settings.get('monitor_key',''))
        self.notify_lock = threading.Lock()
        self.outbox_lock = threading.Lock()
        self.frontend = Path(settings.get('frontend', str(Path(__file__).resolve().parents[1] / 'frontend')))
        self.qrencode = settings.get('qrencode', '/usr/bin/qrencode')
        self.probes, self.probe_lock = {}, threading.Lock()
        self.last_doctor, self.last_doctor_at = None, 0
        self.last_fingerprint = None
        self.cache, self.cache_lock, self.flight = {}, threading.Lock(), {}
        self.last_sample_bucket = None
        self.remote_probes=[];self.remote_probe_at=0

    def cached(self, key, fn, seconds):
        """Short-lived single-flight cache for bridge reads: concurrent callers wait for one
        computation instead of each queueing a root-bridge call. Cleared on every commit/action."""
        with self.cache_lock:
            old = self.cache.get(key)
            if old and old[0] + seconds > time.time(): return old[1]
            gate = self.flight.setdefault(key, threading.Lock())
        with gate:
            with self.cache_lock:
                old = self.cache.get(key)
                if old and old[0] + seconds > time.time(): return old[1]
            value = fn()
            with self.cache_lock: self.cache[key] = (time.time(), value)
            return value

    def invalidate(self):
        with self.cache_lock: self.cache.clear()

    def notify(self, event, detail):
        with self.notify_lock:
            cfg = self.store.setting('notifications', {})
            require(cfg.get('enabled') and cfg.get('url'), 'Configure an HTTPS notification destination first')
            last = self.store.setting('notification-last', {})
            require(last.get(event, 0) + 300 < time.time(), 'Notification suppressed by five-minute rate limit', 429)
            url, addresses = public_https_url(cfg['url'])
            payload = {'event': event, 'detail': redact(detail), 'time': time.time()}
            kind = cfg.get('kind', 'webhook')
            if kind == 'discord': payload = {'content': json.dumps(payload, ensure_ascii=False)}
            if kind == 'telegram': payload = {'chat_id': cfg.get('chat_id'), 'text': json.dumps(payload, ensure_ascii=False)}
            # Pin the validated address for this connection; TLS still verifies hostname.
            conn = http.client.HTTPSConnection(url.hostname, timeout=8, context=ssl.create_default_context())
            raw = socket.create_connection((addresses[0], 443), timeout=8)
            conn.sock = conn._context.wrap_socket(raw, server_hostname=url.hostname)
            try:
                conn.request('POST', urllib.parse.urlunsplit(('', '', url.path or '/', url.query, '')), json.dumps(payload), {'Content-Type': 'application/json'})
                response = conn.getresponse(); response.read(8192)
                require(200 <= response.status < 300, 'Destination rejected notification; redirects are forbidden', 422)
            finally: conn.close()
            last[event] = time.time(); self.store.set_setting('notification-last', last)
            self.store.audit('notification', 'sent', event, origin='panel')
            return {'sent': True}

    def observe(self, max_age=0):
        value = self.cached('overview', lambda: self.control('overview'), max_age) if max_age else self.control('overview')
        value['probes']=self.remote_probes
        bucket = int(value.get('sampled_at') or time.time()) // 10
        if bucket != self.last_sample_bucket:  # samples are stored per 10 s bucket; skip redundant writes
            self.last_sample_bucket = bucket; self.store.sample(value);self.store.host_budget(value)
        return value

    # -- monitoring ------------------------------------------------------
    def evaluate(self, overview=None, run_doctor=False):
        """One alert evaluation pass; returns the list of transitions."""
        overview = overview or self.observe()
        with self.cache_lock:  # alerts use fresh state; let the dashboard show the same state
            self.cache['overview'] = (time.time(), overview); self.cache.pop('dashboard', None)
        cert = self.control('certificate')
        try: inbounds = self.control('inbounds')
        except Problem: inbounds = None
        doctor = None
        if run_doctor:
            try:
                doctor = self.control('doctor')
                self.last_doctor, self.last_doctor_at = doctor, time.time()
            except Problem: doctor = None
        try:
            usage=self.control('accounting-summary')
            if usage.get('enabled'):
                health=usage['health'];families_dummy=None
                if health.get('status')!='ready':
                    change=self.store.raise_alert('vpn.collector','critical','VPN accounting unavailable',health.get('reason','No fresh authenticated counters'),'Authenticated VPN StatsService collector; host counters excluded')
                    if change:self.deliver([(change,'vpn.collector','critical','VPN accounting unavailable',health.get('reason',''))])
                elif self.store.resolve_alert('vpn.collector'):self.deliver([('resolved','vpn.collector','ok','VPN accounting recovered','Fresh authenticated counters resumed')])
                current={u['id']:u for u in usage.get('users',[])}
                for key in self.store.open_alert_keys():
                    if not key.startswith('vpn.') or key=='vpn.collector':continue
                    parts=key[4:].split(':');row=current.get(parts[0]);view=row.get('usage',{}) if row else {};resolve=row is None
                    if row and len(parts)==4 and parts[-1] in ('80','95','100'):
                        resolve=not view.get('quota_bytes') or str(view.get('period_start'))!=parts[1] or str(view.get('reset_seq'))!=parts[2] or view.get('used_bytes') is not None and view['used_bytes']*100<view['quota_bytes']*int(parts[-1])
                    elif row and len(parts)==3 and parts[1]=='expiry':resolve=view.get('status')!='expired'
                    if resolve and self.store.resolve_alert(key):self.deliver([('resolved',key,'ok','VPN quota alert resolved','Current managed-user plan is below this threshold')])
                seen=set(self.store.setting('quota-events-seen',[]))
                for e in reversed(usage.get('events',[])):
                    if e['key'] not in seen:
                        key='vpn.'+e['key'];change=self.store.raise_alert(key,e['severity'],e['title'],'Managed user '+e['user_id'][:8]+'; '+time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(e['time'])),'Authenticated VPN user usage; not host/provider usage')
                        if change:self.deliver([(change,key,e['severity'],e['title'],'Managed VPN quota event')])
                        seen.add(e['key'])
                self.store.set_setting('quota-events-seen',sorted(seen)[-1000:])
        except Exception:pass
        families, active = monitor.evaluate_alerts(overview, cert, inbounds, self.store.login_failures(), doctor)
        transitions = []
        for key, (severity, title, detail, source) in active.items():
            change = self.store.raise_alert(key, severity, title, detail, source)
            if change: transitions.append((change, key, severity, title, detail))
        for key in self.store.open_alert_keys():
            if key.split('.')[0] in families and key not in active:
                row = self.store.resolve_alert(key)
                if row: transitions.append(('resolved', key, 'ok', 'Recovered: ' + row['title'], ''))
        budget=self.store.host_budget()
        for percent in (80,95,100):
            key='host.budget.'+str(percent);hit=bool(budget.get('quota_bytes') and (budget.get('used_bytes') or 0)*100>=budget['quota_bytes']*percent)
            if hit:
                change=self.store.raise_alert(key,'critical' if percent==100 else 'warning','Host transfer budget reached '+str(percent)+'%','Host RX + TX lower bound since monitoring began; provider invoice may differ','Linux host interface counters; not VPN user quota')
                if change:self.deliver([(change,key,'warning','Host transfer budget '+str(percent)+'%','Operator-entered provider budget. VPN user quotas are independent.')])
            elif self.store.resolve_alert(key):self.deliver([('resolved',key,'ok','Host budget alert resolved','New billing cycle or operator budget update')])
        pid=(overview.get('service') or {}).get('MainPID');previous=self.store.setting('monitor-last-core-pid')
        if pid and str(pid)!='0':
            if previous and previous!=pid:self.store.event('core-restart','info','VPN core process changed','Previous PID '+str(previous)+'; current PID '+str(pid),'systemd MainPID observed on this VPS')
            self.store.set_setting('monitor-last-core-pid',pid)
        fingerprint = overview.get('state_fingerprint')
        if fingerprint and self.last_fingerprint and fingerprint != self.last_fingerprint:
            recent = self.store.audit_query(event='change-committed', since=time.time() - 120, limit=1)['total']
            if not recent:
                self.store.event('external-change', 'info', 'Configuration changed outside the panel', 'State fingerprint %s -> %s (CLI or another operator)' % (self.last_fingerprint, fingerprint), 'manager state.json fingerprint')
        if fingerprint: self.last_fingerprint = fingerprint
        self.deliver(transitions)
        return transitions

    def deliver(self, transitions):
        cfg = self.store.setting('notifications', {})
        silence = self.store.setting('alert-silence-until', 0) or 0
        if not cfg.get('enabled') or silence > time.time(): return
        for change, key, severity, title, detail in transitions:
            if severity == 'info': continue
            self.store.queue_notification('alert:'+key+':'+change,{'state':change,'severity':severity,'title':str(title)[:200],'detail':str(detail)[:1000]})
        if not self.outbox_lock.acquire(blocking=False):return
        try:
            for row in self.store.due_notifications():
                try:self.notify(row['event'],json.loads(row['payload']))
                except Exception as exc:self.store.notification_result(row['event'],type(exc).__name__+(' ('+str(exc.status)+')' if isinstance(exc,Problem) else ''),row['attempts'])
                else:self.store.notification_result(row['event'])
        finally:self.outbox_lock.release()

    def start_background(self, interval=30, doctor_every=3600):
        def loop():
            while True:
                try:
                    if time.time()-self.remote_probe_at>=60:
                        origin=urllib.parse.urlsplit(self.cfg['origin']);self.remote_probes=probes.collect(self.store.setting('monitor-targets',[]),{'host':origin.hostname,'port':origin.port or 443});self.remote_probe_at=time.time()
                    self.evaluate(run_doctor=time.time() - self.last_doctor_at >= doctor_every)
                except Exception: pass
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True, name='sbox-monitor').start()

    def rates(self, window, end=None):
        return monitor.rate_series(self.store.history(window, end=end), window, now=end)

    def dashboard(self):
        return self.cached('dashboard', self._dashboard, 2)

    def _dashboard(self):
        overview = self.observe(max_age=3)
        cert = self.cached('certificate', lambda: self.control('certificate'), 60)
        try: inbounds = self.cached('inbounds', lambda: self.control('inbounds'), 10)
        except Problem: inbounds = None
        last = self.store.audit_query(event='change-committed', limit=1)['events']
        panel = {'version': VERSION, 'uptime_seconds': time.time() - STARTED, 'pid': os.getpid()}
        value = monitor.dashboard(overview, cert, inbounds, self.store.alerts(), last[0] if last else None, self.rates(3600), panel)
        try:
            accounting=self.cached('dashboard-accounting',lambda:self.control('accounting-summary'),3)
            rows=accounting.get('users',[]);counts={key:0 for key in ('active','manually_disabled','expired','quota_exceeded','pending_reconciliation')};upcoming=[];now=time.time()
            for row in rows:
                usage=row.get('usage',{});status=usage.get('status')
                if status in counts:counts[status]+=1
                for kind,field in (('reset','next_reset'),('expiry','expires_at')):
                    stamp=usage.get(field)
                    if stamp and now<stamp<=now+7*86400:upcoming.append({'id':row['id'],'name':row['name'],'kind':kind,'time':stamp})
            value['people']={'available':True,'total':len(rows),'counts':counts,'health':accounting.get('health',{}),'upcoming':sorted(upcoming,key=lambda event:event['time'])[:6],'source':'Managed user status and authenticated quota snapshot; not online presence'}
        except Problem:value['people']={'available':False}
        monitor.accounting_health(value, value.get('people', {}).get('health', {}))
        value['advanced'] = {'overview': overview, 'certificate': cert}
        return value

    def probe(self, row, domain):
        """Loopback-only probe of one inbound. Never contacts the Internet."""
        started = time.time()
        if row['network'] == 'udp':
            return {'status': 'not-probed', 'detail': 'QUIC (Hysteria2/TUIC) needs a protocol client; only the UDP socket inventory is checked.', 'sampled_at': started}
        try:address=ipaddress.ip_address(row.get('listen','0.0.0.0'))
        except ValueError:return {'status':'not-probed','detail':'Listener address is not a local IP; use authenticated client verification.','sampled_at':started}
        if address.is_unspecified:target='::1' if address.version==6 else '127.0.0.1'
        elif address.is_loopback:target=str(address)
        else:return {'status':'not-probed','detail':'Explicit non-loopback listener. Owned socket inventory is available; this sandboxed loopback probe does not establish public reachability. Use authenticated client verification.','sampled_at':started}
        try:
            with socket.create_connection((target, row['port']), timeout=3) as sock:
                if row['type'] == 'vless':
                    return {'status': 'ok', 'detail': 'TCP accepted on loopback. REALITY forwards unauthenticated TLS to its external camouflage site, so no handshake is attempted.', 'latency_ms': round((time.time() - started) * 1000, 1), 'sampled_at': started}
                if not row.get('tls'):
                    return {'status': 'ok', 'detail': 'TCP accepted on loopback (no TLS on this inbound).', 'latency_ms': round((time.time() - started) * 1000, 1), 'sampled_at': started}
                context = ssl.create_default_context()
                try:
                    with context.wrap_socket(sock, server_hostname=domain) as tls:
                        version = tls.version()
                    return {'status': 'ok', 'detail': 'TLS %s handshake verified for %s on loopback.' % (version, domain), 'latency_ms': round((time.time() - started) * 1000, 1), 'sampled_at': started}
                except ssl.SSLCertVerificationError as exc:
                    return {'status': 'warning', 'detail': 'TCP accepted but the certificate did not verify for %s: %s' % (domain, exc.verify_message), 'sampled_at': started}
        except ssl.SSLError as exc:
            return {'status': 'error', 'detail': 'TLS handshake failed on loopback: %s' % exc.reason, 'sampled_at': started}
        except OSError as exc:
            return {'status': 'error', 'detail': 'Loopback connection failed: %s' % (exc.strerror or exc.__class__.__name__), 'sampled_at': started}

    def protocol_health(self, run_probe=False):
        inbounds = self.control('inbounds')
        cert = self.control('certificate')
        if run_probe:
            with self.probe_lock:
                fresh = all(p.get('sampled_at', 0) + 30 > time.time() for p in self.probes.values()) and self.probes
                if not fresh:
                    self.probes = {row['id']: self.probe(row, cert.get('domain') or 'localhost') for row in inbounds.get('inbounds', [])}
        value = monitor.protocol_health(inbounds, cert, self.probes)
        value['probe_ttl_seconds'] = 30
        return value


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    KEEPALIVE_MAX_REQUESTS = 16
    KEEPALIVE_IDLE_SECONDS = 2
    KEEPALIVE_LIFETIME_SECONDS = 5
    server_version = 'SBOX-WebUI'
    sys_version = ''

    def log_message(self, *args): pass  # Never log URL paths containing subscription tokens.

    def setup(self):
        self._request_count = 0
        self._reuse_deadline = time.monotonic() + self.KEEPALIVE_LIFETIME_SECONDS
        self.request.settimeout(15)
        super().setup()

    def handle_one_request(self):
        self._request_count += 1
        if self._request_count > 1:
            # End reuse at a response boundary, where Connection: close can
            # notify the client. Truncating this idle read at the lifetime
            # deadline silently dropped the next request on high-RTT paths.
            # Occupancy remains bounded by lifetime + one idle window (and
            # the existing request timeout), with at most 16 reads.
            self.request.settimeout(self.KEEPALIVE_IDLE_SECONDS)
        super().handle_one_request()

    def framing(self):
        # Persistent reads must never leave an ambiguous body for the next
        # request. Mutations always close after their response as before.
        lengths = self.headers.get_all('Content-Length', [])
        require(len(lengths) <= 1 and not self.headers.get_all('Transfer-Encoding'), 'Ambiguous request framing', 400)
        if self.command in ('GET', 'HEAD'):
            try: length = int(lengths[0]) if lengths else 0
            except ValueError: raise Problem(400, 'Invalid body length')
            require(length == 0, 'Read requests cannot contain a body', 400)
        self.request.settimeout(15)

    def send(self, status, value, content_type='application/json; charset=utf-8', headers=None, csp=None):
        if content_type.startswith('application/json') and not isinstance(value, bytes): value = json.dumps(value, ensure_ascii=False).encode()
        elif isinstance(value, str): value = value.encode()
        if status >= 400 or self.command not in ('GET', 'HEAD') or self._request_count >= self.KEEPALIVE_MAX_REQUESTS or time.monotonic() >= self._reuse_deadline:
            self.close_connection = True
        self.send_response(status)
        self.send_header('Connection', 'close' if self.close_connection else 'keep-alive')
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(value)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', csp or "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        for key, header_value in (headers or {}).items(): self.send_header(key, header_value)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(value)

    @property
    def app(self): return self.server.app

    def portal_routes(self,path,query,data):
        require(not self.headers.get('Authorization'),'Portal requires its own browser session',403)
        suffix=path[len('/api/v1/portal/'):];write=self.command=='POST'
        if suffix=='login' and write:
            require(not query and set(data)=={'username','password'},'Unknown portal login field')
            self.server.rate('portal-login:'+self.client_address[0],20)
            try:value=self.app.control('portal-login',{**data,'peer':self.client_address[0]})
            except Problem as exc:
                if exc.status in (401,429):auth_failure(self.client_address[0],'portal')
                raise
            sid=value.pop('session')
            return self.send(200,value,headers={'Set-Cookie':'sbox_portal_session='+sid+'; Path=/api/v1/portal; Max-Age=28800; Secure; HttpOnly; SameSite=Strict'})
        jar=cookies.SimpleCookie()
        try:jar.load(self.headers.get('Cookie',''))
        except cookies.CookieError:raise Problem(401,'Unauthorized')
        sid=jar['sbox_portal_session'].value if 'sbox_portal_session' in jar else ''
        require(0<len(sid)<=256,'Unauthorized',401)
        if hasattr(self.app.control,'set_context'):self.app.control.set_context({'kind':'portal','session':sid})
        if suffix=='session' and self.command in ('GET','HEAD'):
            require(not query,'Unknown portal session field',403)
            return self.send(200,self.app.control('portal-session',{'session':sid}))
        if suffix=='me/history' and self.command in ('GET','HEAD'):
            require(set(query)<= {'window','start','end','timezone'},'Unknown personal history field',403)
            return self.send(200,self.app.control('portal-history',{'session':sid,'selection':query}))
        if suffix in ('me','me/usage') and self.command in ('GET','HEAD'):
            require(set(query)<= {'window'},'Unknown portal query field',403)
            return self.send(200,self.app.control('portal-me',{'session':sid,'window':query.get('window','30d')}))
        require(not query,'Unknown portal query field',403)
        if suffix in ('me/connection','me/qr','me/node-qr','me/export','me/replace-link','me/revoke-link') and write:
            self.server.rate('portal-connection:'+digest(sid),60)
            identity=self.app.control('portal-connection',{'session':sid,'csrf':self.headers.get('X-CSRF-Token','')})
            ident=identity['id']  # Root derives this from the session; never from HTTP input.
            if suffix=='me/connection':
                require(not data,'Unknown connection field',403)
                return self.send(200,self.subscription_connection(ident,identity.get('endpoints')))
            if suffix=='me/export':
                require({'profile','format'}<=set(data)<= {'profile','format','endpoint'},'Invalid export selection')
                return self.send(200,self.app.control('portal-export',{'session':sid,'csrf':self.headers.get('X-CSRF-Token',''),**data}))
            if suffix=='me/node-qr':
                require({'profile','index'}<=set(data)<= {'profile','index','endpoint'} and data['profile'] in PROFILES and type(data['index']) is int and 0<=data['index']<16,'Invalid node selection')
                value=self.app.control('portal-export',{'session':sid,'csrf':self.headers.get('X-CSRF-Token',''),'profile':data['profile'],'format':'links','endpoint':data.get('endpoint','auto')})['content']
                nodes=[line.strip() for line in value.splitlines() if re.match(r'^(?:vless|vmess|hysteria2|tuic|anytls)://',line.strip())]
                require(data['index']<len(nodes),'Node not found',404)
                return self.send(200,{'svg':self.qr(nodes[data['index']])})
            if suffix=='me/qr':
                require({'profile','format'}<=set(data)<= {'profile','format','endpoint'} and data['profile'] in PROFILES and data['format'] in export_catalog.FORMATS,'Invalid QR selection')
                link=self.subscription_connection(ident,identity.get('endpoints'))
                require(link.get('recoverable'),'The active link cannot be revealed; ask your administrator',409)
                choice=data.get('endpoint','auto');require(choice in {e['id'] for e in (identity.get('endpoints') or {'choices':[{'id':'auto'}]})['choices']},'Endpoint unavailable')
                url=link['exports'][data['profile']][data['format']]+('?' + urllib.parse.urlencode({'endpoint':choice}) if choice!='auto' else '')
                return self.send(200,{'svg':self.qr(url)})
            require(set(data)=={'confirm'} and data['confirm'] is True,'Confirm that existing imports will stop updating')
            if suffix=='me/replace-link':
                require(identity['enabled'],'User is disabled',409)
                self.app.subscriptions.issue(ident)
            else:self.app.subscriptions.revoke(ident)
            self.app.store.audit('portal','subscription-replaced' if suffix=='me/replace-link' else 'subscription-revoked',origin='portal',target=ident)
            return self.send(200,self.subscription_connection(ident,identity.get('endpoints')))
        if suffix=='logout' and write:
            require(not data,'Unknown logout field',403)
            value=self.app.control('portal-logout',{'session':sid,'csrf':self.headers.get('X-CSRF-Token','')})
            return self.send(200,value,headers={'Set-Cookie':'sbox_portal_session=; Path=/api/v1/portal; Max-Age=0; Secure; HttpOnly; SameSite=Strict'})
        if suffix=='me/change-password' and write:
            require(set(data)=={'old','password'},'Unknown password field',403)
            return self.send(200,self.app.control('portal-password',{'session':sid,'csrf':self.headers.get('X-CSRF-Token',''),**data}))
        raise Problem(403,'Portal operation is forbidden')

    def body(self):
        require(not self.headers.get('Transfer-Encoding'), 'Transfer encoding is unsupported')
        require(self.headers.get('Content-Type', '').split(';')[0] == 'application/json', 'JSON required', 415)
        try: length = int(self.headers.get('Content-Length', '0'))
        except ValueError: raise Problem(400, 'Invalid body length')
        limit=65536 if urllib.parse.urlsplit(self.path).path=='/api/v1/changes/prepare' else 32768
        require(0 < length <= limit, 'Body exceeds bounded request size', 413)
        value = json.loads(self.rfile.read(length))
        require(isinstance(value, dict), 'JSON object required')
        return value

    def actor(self, mutate=False, account_action=False):
        auth = self.headers.get('Authorization', '')
        self.bearer = auth.startswith('Bearer ')
        if self.bearer: self.raw = auth[7:]
        else:
            jar = cookies.SimpleCookie()
            try: jar.load(self.headers.get('Cookie', ''))
            except cookies.CookieError: raise Problem(401, 'Unauthorized')
            self.raw = jar['sbox_session'].value if 'sbox_session' in jar else ''
        require(len(self.raw) <= 256, 'Unauthorized', 401)
        actor = self.app.store.auth(self.raw, self.bearer)
        self.origin_kind = 'api-token' if self.bearer else 'browser'
        if mutate:
            if account_action:require(not self.bearer,'Account changes require a browser session',403)
            if not self.bearer: require(hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), actor['csrf'] or ''), 'CSRF token required', 403)
            if not account_action: require(actor['role'] == 'admin' and actor['scope'] in ('admin', 'write'), 'Read-only account or token', 403)
        if hasattr(self.app.control,'set_context'):self.app.control.set_context({'kind':'token' if self.bearer else 'browser','raw':self.raw,'csrf':self.headers.get('X-CSRF-Token','')})
        return actor

    def fresh(self, actor):
        require(not self.bearer and actor['fresh'] + 300 > time.time(), 'Reauthenticate before this sensitive action', 428)

    def admin(self, actor):
        require(actor['role'] == 'admin', 'Admin required', 403)

    def audit(self, actor, event, detail='', outcome='ok', target=''):
        self.app.store.audit(actor['name'], event, detail, origin=getattr(self, 'origin_kind', ''), outcome=outcome, target=target)

    def check_origin(self):
        origin = self.headers.get('Origin')
        require(origin is None or origin == self.app.cfg['origin'], 'Cross-origin request denied', 403)
        require(self.headers.get('Sec-Fetch-Site') not in ('cross-site',), 'Cross-site request denied', 403)
        host = self.headers.get('Host', '')
        require(host == urllib.parse.urlsplit(self.app.cfg['origin']).netloc, 'Invalid Host header', 400)

    def handle_request(self):
        self.connection.settimeout(20)
        self.check_origin()
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        require(len(self.path) <= 4096, 'URL too long', 414)
        require('%' not in path and '..' not in path and '\\' not in path, 'Invalid path')
        write = self.command in ('POST', 'PUT', 'PATCH', 'DELETE')
        data = self.body() if write else {}
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        store = self.app.store
        if path == '/api/v1/health' and not write: return self.send(200, {'ok': True, 'schema': SCHEMA})
        if path == '/api/v1/auth/login' and self.command == 'POST':
            require(set(data) <= {'username', 'password', 'code'}, 'Unknown login field')
            require(all(isinstance(v, str) for v in data.values()), 'Invalid login fields')
            sid, csrf = store.login(data.get('username', ''), data.get('password', ''), data.get('code', ''), self.client_address[0], self.headers.get('User-Agent', '')[:160])
            return self.send(200, {'csrf': csrf}, headers={'Set-Cookie': 'sbox_session=' + sid + '; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Strict'})
        if path.startswith('/api/v1/portal/'):
            return self.portal_routes(path,query,data)
        if path.startswith('/sub/') and self.command in ('GET', 'HEAD'): return self.subscription(path, query)
        static = {'/portal':('portal.html','text/html; charset=utf-8'),'/usage.js':('usage.js','text/javascript; charset=utf-8'),'/usage.css':('usage.css','text/css; charset=utf-8'),'/portal.js':('portal.js','text/javascript; charset=utf-8'),'/portal.css':('portal.css','text/css; charset=utf-8'),'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'),
                  '/subscribe.css': ('subscribe.css', 'text/css; charset=utf-8'), '/subscribe.js': ('subscribe.js', 'text/javascript; charset=utf-8'), '/export-center.js': ('export-center.js', 'text/javascript; charset=utf-8'), '/export-center.css': ('export-center.css', 'text/css; charset=utf-8')}
        if path in static and self.command in ('GET', 'HEAD'):
            name, kind = static[path]
            return self.send(200, (self.app.frontend / name).read_bytes(), kind)
        require(path.startswith('/api/v1/'), 'Not found', 404)
        suffix = path[len('/api/v1/'):]
        actor = self.actor(write, suffix.startswith('auth/'))
        if actor['reset']:
            require(suffix in ('auth/me', 'auth/change-password', 'auth/logout'), 'Change initial password first', 428)
        if suffix.startswith('auth/'): return self.auth_routes(suffix, actor, data, write, query)
        if suffix == 'dashboard' and not write: return self.send(200, self.app.dashboard())
        if suffix == 'network' and not write:
            self.admin(actor);return self.send(200,self.app.control('network'))
        if suffix == 'system/status' and not write: return self.send(200, self.app.observe())
        if suffix == 'system/version' and not write: return self.send(200, self.version())
        if suffix=='security/webui-guard' and self.command in ('GET','HEAD'):
            require(not query,'Unexpected WebUI guard query')
            return self.send(200,self.app.control('webui-guard'))
        reads = {'accounting':'accounting-summary','quota-doctor':'quota-doctor','system/capabilities': 'capabilities', 'system/performance': 'performance', 'inbounds': 'inbounds', 'users': 'users', 'policy': 'policy', 'certificates': 'certificate', 'security/firewall': 'firewall', 'security/firewall-status': 'firewall-status', 'security/bans': 'bans', 'security/status': 'security', 'backups': 'backups'}
        if suffix in reads and not write: return self.send(200, self.app.control(reads[suffix]))
        if suffix == 'diagnostics/doctor' and not write:
            raw = self.app.control('doctor'); self.app.last_doctor, self.app.last_doctor_at = raw, time.time()
            value = monitor.guided_doctor(raw); value['raw'] = raw
            return self.send(200, value)
        if suffix == 'diagnostics/report' and not write: return self.send(200, self.report(), 'text/plain; charset=utf-8')
        if suffix == 'protocols/health' and not write: return self.send(200, self.app.protocol_health(False))
        if suffix == 'protocols/probe' and self.command == 'POST':
            self.server.rate('probe:' + str(actor['id']), 6)
            return self.send(200, self.app.protocol_health(True))
        if suffix == 'certificates/readiness' and not write: return self.send(200, self.readiness())
        if suffix=='plans/preview' and self.command=='POST':
            return self.send(200,self.app.control('quota-preview',data))
        if suffix=='accounting/history' and not write:
            require('id' in query and set(query)<= {'id','window','start','end','timezone'},'Unknown history query field')
            return self.send(200,self.app.control('accounting-history',{'id':query['id'],'selection':{k:v for k,v in query.items() if k!='id'}}))
        if suffix=='system/timezones' and not write:
            from zoneinfo import available_timezones
            countries={}
            zone_table=Path('/usr/share/zoneinfo/zone.tab')
            if zone_table.is_file():
                for line in zone_table.read_text().splitlines():
                    if line and not line.startswith('#'):
                        columns=line.split('\t')
                        if len(columns)>=3:countries[columns[2]]=columns[0].split(',')[0]
            return self.send(200,{'timezones':sorted(z for z in available_timezones() if not z.startswith(('posix/','right/'))),'countries':countries,'source':'System IANA timezone database'})
        if suffix=='accounting/user' and not write:

            require(set(query)<= {'id','window'},'Unknown usage query field');return self.send(200,self.app.control('accounting-user',{'id':query.get('id',''),'window':query.get('window','30d')}))
        if suffix=='monitor/settings':
            if write:
                self.admin(actor);self.fresh(actor);require(set(data)<= {'targets','host_budget'},'Unknown monitor settings')
                if 'targets' in data:store.set_setting('monitor-targets',probes.validate(data['targets']))
                if 'host_budget' in data:
                    from quota_models import quota_plan
                    require(isinstance(data['host_budget'],dict) and set(data['host_budget'])<= {'quota_bytes','timezone','reset_day'},'Only provider budget, billing timezone and monthly reset day are configurable');p=quota_plan({**data['host_budget'],'period':'monthly'});store.set_setting('host-budget',p)
                self.audit(actor,'monitor-settings-updated');self.app.remote_probe_at=0
            return self.send(200,{'targets':store.setting('monitor-targets',[]),'host_budget':store.setting('host-budget',{}),'source':'Operator-entered provider budget; measured host interface deltas. Independent of all VPN user quotas.'})
        if suffix=='monitor/history' and not write:
            window,end=monitor.selected_range(query)
            values=store.history(window,end=end);return self.send(200,{'samples':values,'host_budget':store.host_budget(),'probes':self.app.remote_probes,'source':'Linux host procfs + statvfs + systemd; optional probes originate on this VPS. Not per-user VPN traffic.','window_seconds':window,'sampled_at':end})
        if suffix == 'traffic' and not write:
            window,end = monitor.selected_range(query)
            rates = self.app.rates(window,end=end)
            # Backward compatible raw field (latest 360 samples) for API consumers.
            return self.send(200, {**rates, 'samples': store.history(3600)[-360:], 'sample_count': rates['samples'], 'source': 'Host interface totals; not VPN-only or per-user accounting. ' + rates['source']})
        if suffix == 'alerts' and not write:
            return self.send(200, {'alerts': store.alerts(), 'timeline': store.timeline(), 'silenced_until': store.setting('alert-silence-until', 0) or 0,
                                   'notifications': bool(store.setting('notifications', {}).get('enabled')),'notification_outbox':store.notification_status(),
                                   'rules': 'Core down/recovered, listener missing, certificate expiry/renewal timer, disk/memory pressure, error bursts, pending transaction, repeated failed sign-ins, core version drift, doctor firewall/NAT drift (hourly).'})
        if suffix == 'alerts/silence' and write:
            self.admin(actor)
            require(set(data) == {'minutes'} and type(data['minutes']) is int and 0 <= data['minutes'] <= 1440, 'minutes must be 0–1440')
            until = time.time() + data['minutes'] * 60 if data['minutes'] else 0
            store.set_setting('alert-silence-until', until); self.audit(actor, 'alerts-silenced', str(data['minutes']))
            return self.send(200, {'silenced_until': until})
        if suffix == 'alerts/evaluate' and write:
            self.admin(actor)
            transitions = self.app.evaluate(run_doctor=bool(data.get('doctor')))
            return self.send(200, {'transitions': [{'change': c, 'key': k, 'severity': s, 'title': t} for c, k, s, t, _ in transitions], 'alerts': store.alerts()})
        if suffix in ('logs', 'logs/stream') and not write:
            result = self.app.control('logs', {'search': query.get('search', '')})
            if suffix.endswith('/stream'): return self.send(200, 'event: logs\ndata: ' + json.dumps(result) + '\n\n', 'text/event-stream')
            return self.send(200, result)
        if suffix == 'changes/prepare' and self.command == 'POST':
            if data.get('kind')!='policy':self.fresh(actor)
            try: result = self.app.control('prepare', data)
            except Problem as e:
                self.audit(actor, 'change-denied', e.message, 'denied', data.get('kind', 'invalid')); raise
            self.audit(actor, 'change-prepared', (result.get('summary') or {}).get('title', ''), target=data.get('kind'))
            return self.send(200, result)
        if suffix == 'changes/commit' and self.command == 'POST':
            preview=self.app.control('change-preview',data)
            if preview['kind']!='policy':self.fresh(actor)
            onboarding=preview.get('onboarding_id');raw_subscription=None
            if onboarding:
                # Reserve the hashed link before the root commit. If this write
                # fails, the VPN user never exists. Until the manager commits,
                # resolution rejects the not-yet-existing immutable user ID.
                raw_subscription=self.app.subscriptions.issue(onboarding,reserve=True)
            try: result = self.app.control('commit', data)
            except Exception as e:
                if onboarding:
                    try:
                        # An uncertain response may follow a completed commit.
                        # Never orphan that account by removing its valid link.
                        exists=any(u['id']==onboarding for u in self.app.control('users'))
                        if not exists:
                            self.app.subscriptions.revoke(onboarding,expected_hash=digest(raw_subscription))
                    except Exception:pass
                self.audit(actor, 'change-failed', e.message if isinstance(e,Problem) else 'Commit outcome requires reconciliation', 'failed', preview['kind']);raise
            if raw_subscription:
                result['onboarding']={'user_id':onboarding,**self.subscription_connection(onboarding),'shown_once':False,'portal_url':self.app.cfg['origin']+'/portal'}
            self.audit(actor, 'change-committed', json.dumps({k: result.get(k) for k in ('state_fingerprint', 'service_active', 'restarted')}), target=preview['kind'])
            self.app.invalidate()
            return self.send(200, result)
        if suffix.startswith('changes/') and not write:
            return self.send(200,self.app.control('change-preview',{'token':suffix.split('/')[1]}))
        if suffix == 'actions' and self.command == 'POST':
            self.fresh(actor)
            require(set(data) == {'action', 'arguments'}, 'Invalid action request')
            require(isinstance(data['arguments'],dict), 'Action arguments must be an object')
            require(data['action'] in ('firewall-apply', 'security-repair', 'unban', 'webui-guard-repair', 'webui-guard-unban', 'renew-test', 'certificate-renew', 'backup', 'restore', 'recover', 'restart', 'core-update', 'update-preview'), 'Unknown action')
            if data['action'] in ('restart', 'core-update', 'recover', 'restore', 'certificate-renew'): require(data['arguments'].pop('confirm_restart', False) is True, 'Confirm VPN interruption')
            self.audit(actor,'action-started',data['action'],target=data['action'])
            try:result = self.app.control(data['action'], data['arguments'])
            except Exception:
                self.audit(actor,'action-failed',data['action'],'failed',data['action']);raise
            self.audit(actor, 'action', data['action'], target=data['action'])
            self.app.invalidate()
            return self.send(200, {'action': data['action'], 'completed_at': time.time(), 'result': result, **(result if isinstance(result, dict) else {})})
        if suffix == 'subscriptions' and not write:
            with store.db() as db: rows = {r['user']: r['created'] for r in db.execute('SELECT user,created FROM subscriptions')}
            return self.send(200, {'users': [{**u, 'subscription_active': u['id'] in rows, 'subscription_created': rows.get(u['id'])} for u in self.app.control('users')],
                                   'landing_page': bool(store.setting('subscription-landing', False)), 'update_interval_hours': 24})
        if suffix == 'subscriptions/settings' and write:
            self.admin(actor); self.fresh(actor)
            require(set(data) == {'landing_page'} and type(data['landing_page']) is bool, 'landing_page must be boolean')
            store.set_setting('subscription-landing', data['landing_page']); self.audit(actor, 'subscription-settings', 'landing_page=' + str(data['landing_page']))
            return self.send(200, {'landing_page': data['landing_page']})
        if suffix == 'subscriptions/reveal' and self.command=='POST':
            self.admin(actor);self.fresh(actor)
            require(set(data)=={'id'} and isinstance(data['id'],str),'Invalid reveal request')
            require(any(u['id']==data['id'] for u in self.app.control('users')),'Unknown user',404)
            self.audit(actor,'subscription-revealed',target=data['id'])
            return self.send(200,self.subscription_connection(data['id']))
        if suffix == 'subscriptions/rotate-token' and write:
            self.fresh(actor)
            require(set(data) == {'id'}, 'Invalid token request')
            require(any(u['id'] == data['id'] and u['enabled'] for u in self.app.control('users')), 'Unknown/disabled user', 404)
            self.app.subscriptions.issue(data['id'])
            self.audit(actor, 'subscription-rotated', '', target=data['id'])
            return self.send(200,{**self.subscription_connection(data['id']),'shown_once':False})
        if suffix == 'subscriptions/revoke' and write:
            self.fresh(actor)
            require(set(data) == {'id'} and isinstance(data['id'], str), 'Invalid revoke request')
            count=self.app.subscriptions.revoke(data['id'])
            self.audit(actor, 'subscription-revoked', str(count), target=data['id'])
            return self.send(200, {'ok': True, 'revoked': count})
        if suffix == 'client-profiles' and not write: return self.send(200, {'profiles': list(PROFILES), 'formats': list(export_catalog.FORMATS), 'refresh': 'Static files already downloaded do not update automatically.'})
        if suffix == 'client-profiles/export' and write:
            self.fresh(actor)
            result = self.app.control('export', data)
            self.audit(actor, 'client-exported', data.get('profile', '') + '.' + data.get('format', ''), target=data.get('id', ''))
            return self.send(200, result)
        if suffix == 'qr' and write:
            require(set(data) == {'text'} and isinstance(data['text'], str) and 1 <= len(data['text']) <= 2048, 'QR text must contain 1–2048 characters')
            return self.send(200, {'svg': self.qr(data['text'])})
        if suffix == 'audit' and not write:
            self.admin(actor)
            try:
                limit = min(500, max(1, int(query.get('limit', 100)))); offset = max(0, int(query.get('offset', 0)))
                since = float(query['since']) if query.get('since') else None; until = float(query['until']) if query.get('until') else None
            except ValueError: raise Problem(400, 'Invalid audit filter')
            for key in ('actor', 'event', 'outcome', 'text'): require(len(query.get(key, '')) <= 64, 'Filter too long')
            return self.send(200, store.audit_query(query.get('actor', ''), query.get('event', ''), query.get('outcome', ''), since, until, query.get('text', ''), limit, offset))
        if suffix == 'accounts': return self.accounts(actor, data, write)
        if suffix == 'api-tokens':
            self.admin(actor)
            if write:
                require(not self.bearer, 'API tokens are managed from a browser session', 403)
                self.fresh(actor)
                if data.get('revoke_all'):
                    count = store.revoke_token(actor, everything=True); return self.send(200, {'ok': True, 'revoked': count})
                if 'revoke' in data:
                    store.revoke_token(actor, data['revoke']); return self.send(200, {'ok': True, 'revoked': 1})
                require(set(data) <= {'name', 'scope', 'hours'}, 'Unknown token field')
                require(data.get('scope') in ('read', 'write'), 'Choose read or write scope')
                require(type(data.get('hours')) is int and 1 <= data['hours'] <= 720, 'Token lifetime must be 1–720 hours')
                return self.send(200, {'token': store.create_token(actor, data.get('name'), data['scope'], data['hours']), 'shown_once': True})
            return self.send(200, {'tokens': store.tokens(actor)})
        if suffix == 'notifications':
            self.admin(actor)
            if write:
                self.fresh(actor)
                require(set(data) <= {'url', 'kind', 'chat_id', 'enabled'}, 'Unknown notification field')
                require(type(data.get('enabled')) is bool, 'enabled must be boolean')
                if data.get('enabled'):
                    url, _ = public_https_url(data.get('url'))
                    require(data.get('kind') in ('telegram', 'discord', 'webhook'), 'Invalid notification provider')
                    if data['kind'] == 'telegram': require(url.hostname == 'api.telegram.org' and data.get('chat_id'), 'Telegram requires api.telegram.org and chat_id')
                    if data['kind'] == 'discord': require(url.hostname == 'discord.com' and url.path.startswith('/api/webhooks/'), 'Discord webhook URL required')
                elif not data.get('url'):
                    # Disabling keeps the stored destination unless a new one is entered.
                    data = {**store.setting('notifications', {}), 'enabled': False}
                store.set_setting('notifications', data); self.audit(actor, 'notifications-updated', 'enabled=' + str(data.get('enabled')))
            cfg = store.setting('notifications', {})
            return self.send(200, {'enabled': cfg.get('enabled', False), 'kind': cfg.get('kind', 'webhook'), 'configured': bool(cfg.get('url')), 'rate_limit_seconds': 300})
        if suffix == 'notifications/test' and write:
            self.admin(actor); self.fresh(actor); return self.send(200, self.app.notify('test', 'SBOX notification test'))
        if suffix == 'api-docs' and not write:
            spec = Path(__file__).resolve().parents[1] / 'api-spec/openapi.json'
            return self.send(200, json.loads(spec.read_text()))
        raise Problem(404, 'Not found')

    def auth_routes(self, suffix, actor, data, write, query=None):
        store = self.app.store
        if suffix == 'auth/me' and not write:
            return self.send(200, {'name': actor['name'], 'role': actor['role'], 'reset': bool(actor['reset']), 'totp': bool(actor['totp']), 'csrf': actor['csrf'], 'schema': SCHEMA, 'version': VERSION,
                                   'fresh_until': (actor['fresh'] + 300) if not self.bearer else None, 'variant': self.app.cfg.get('variant')})
        if suffix == 'auth/logout' and write:
            with store.db() as db: db.execute('DELETE FROM sessions WHERE hash=?', (digest(self.raw),))
            return self.send(200, {'ok': True}, headers={'Set-Cookie': 'sbox_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict'})
        if suffix == 'auth/change-password' and write:
            return self.send(200, {'csrf': store.change_password(actor, self.raw, data.get('old'), data.get('password'))})
        if suffix == 'auth/reauthenticate' and write:
            require(set(data) <= {'password', 'code'} and isinstance(data.get('password'), str) and isinstance(data.get('code', ''), str), 'Invalid reauthentication request')
            store.reauthenticate(actor, self.raw, data.get('password'), data.get('code', ''))
            return self.send(200, {'ok': True, 'fresh_until': time.time() + 300})
        if suffix == 'auth/totp/enroll' and write:
            self.fresh(actor)
            secret = base64.b32encode(secrets.token_bytes(20)).decode()
            with store.db() as db: db.execute('UPDATE accounts SET pending_totp=? WHERE id=?', (secret, actor['id']))
            return self.send(200, {'secret': secret, 'uri': 'otpauth://totp/SBOX:' + actor['name'] + '?secret=' + secret + '&issuer=SBOX'})
        if suffix == 'auth/totp/verify' and write:
            self.fresh(actor)
            require(actor['pending_totp'], 'Enroll first')
            step = verify_totp(actor['pending_totp'], data.get('code'))
            require(step is not None, 'Invalid or replayed code', 401)
            codes = [token()[:16] for _ in range(8)]
            with store.db() as db: db.execute('UPDATE accounts SET totp=pending_totp,pending_totp=NULL,last_totp=?,recovery=? WHERE id=?', (step, json.dumps([digest(c) for c in codes]), actor['id']))
            self.audit(actor, 'totp-enabled')
            return self.send(200, {'recovery_codes': codes})
        if suffix == 'auth/totp/disable' and write:
            self.fresh(actor)
            require(actor['totp'], 'Two-factor authentication is not enabled')
            step = verify_totp(actor['totp'], data.get('code'), actor['last_totp'])
            require(step is not None, 'Enter a current authenticator code to turn off two-factor authentication', 401)
            with store.db() as db: db.execute("UPDATE accounts SET totp=NULL,pending_totp=NULL,recovery='[]',last_totp=? WHERE id=?", (step, actor['id']))
            self.audit(actor, 'totp-disabled')
            return self.send(200, {'ok': True})
        if suffix == 'auth/sessions' and not write:
            everyone = actor['role'] == 'admin' and (query or {}).get('all') == '1'
            return self.send(200, {'sessions': store.sessions(actor, self.raw, everyone), 'idle_timeout_seconds': 1800, 'absolute_timeout_seconds': 28800})
        if suffix == 'auth/sessions/revoke' and write:
            require(set(data) <= {'id', 'others', 'all_accounts'}, 'Invalid session request')
            everyone = bool(data.get('all_accounts'))
            if everyone: self.admin(actor); self.fresh(actor)
            count = store.revoke_sessions(actor, self.raw, data.get('id'), bool(data.get('others')), everyone)
            return self.send(200, {'revoked': count})
        raise Problem(404, 'Not found')

    def accounts(self, actor, data, write):
        store = self.app.store
        self.admin(actor)
        with store.db() as db:
            if write:
                self.fresh(actor)
                require(set(data) <= {'name', 'password', 'enabled', 'role'}, 'Unknown account field')
                name = clean_name(data.get('name'))
                if 'enabled' in data:
                    require(name != actor['name'] and type(data['enabled']) is bool, 'Cannot disable self')
                    row = db.execute('SELECT id,role,enabled FROM accounts WHERE name=?', (name,)).fetchone()
                    require(row is not None, 'Account not found', 404)
                    if not data['enabled'] and row['role'] == 'admin':
                        admins = db.execute("SELECT COUNT(*) FROM accounts WHERE role='admin' AND enabled=1").fetchone()[0]
                        require(admins > 1, 'At least one enabled administrator must remain', 409)
                    db.execute('UPDATE accounts SET enabled=? WHERE name=?', (int(data['enabled']), name))
                    db.execute('DELETE FROM sessions WHERE account=?', (row['id'],))
                    if not data['enabled']: db.execute('DELETE FROM tokens WHERE account=?', (row['id'],))
                else:
                    require(data.get('role') in ('admin', 'reader'), 'Invalid role')
                    require(db.execute('SELECT 1 FROM accounts WHERE name=?', (name,)).fetchone() is None, 'Account name already exists', 409)
                    db.execute('INSERT INTO accounts(name,hash,role) VALUES(?,?,?)', (name, password_hash(data.get('password')), data['role']))
            rows = [dict(r) for r in db.execute('SELECT name,role,enabled,reset,totp IS NOT NULL AS mfa FROM accounts ORDER BY name')]
        if write: self.audit(actor, 'account-updated', json.dumps({k: data[k] for k in ('enabled', 'role') if k in data}), target=name)
        return self.send(200, {'accounts': rows})

    def qr(self, text):
        configured = self.app.qrencode
        command = [configured] if isinstance(configured, str) else configured
        require(isinstance(command, (list, tuple)) and command and all(isinstance(part, str) and part for part in command), 'Invalid QR encoder command', 503)
        try: result = subprocess.run([*command, '-t', 'SVG', '-o', '-'], input=text, capture_output=True, text=True, timeout=5, check=True)
        except (OSError, subprocess.SubprocessError): raise Problem(503, 'Install the qrencode OS package to enable QR')
        svg = result.stdout
        # qrencode output contains only geometry; refuse anything script-capable.
        require(svg.lstrip().startswith(('<?xml', '<svg')) and '<script' not in svg.lower() and 'on' + 'load' not in svg.lower() and len(svg) < 400000, 'Unexpected QR output', 503)
        # Adjacent SVG module rectangles must share crisp pixel boundaries.
        # Antialiased hairlines can break independent QR decoders at some scales.
        return re.sub(r'<svg\b([^>]*)>', lambda m: m.group(0) if re.search(r'\bshape-rendering\s*=', m.group(1)) else '<svg shape-rendering="crispEdges"' + m.group(1) + '>', svg, count=1)

    def version(self):
        manifest = self.app.frontend.parent / 'MANIFEST.json'
        integrity = {'status': 'unknown', 'detail': 'MANIFEST.json not found (development tree)'}
        if manifest.is_file():
            try:
                expected = json.loads(manifest.read_text()); root = manifest.parent; bad = []
                for name, sha in expected.items():
                    p = root / name
                    if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != sha: bad.append(name)
                integrity = {'status': 'ok' if not bad else 'error', 'files': len(expected), 'mismatched': bad[:20],
                             'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()[:24], 'detail': 'All panel files match the build manifest' if not bad else 'Panel files differ from the build manifest'}
            except (OSError, ValueError): integrity = {'status': 'error', 'detail': 'Manifest unreadable'}
        try: manager = self.app.control('version')
        except Problem as e: manager = {'error': e.message}
        return {'panel_version': VERSION, 'api_schema': SCHEMA, 'panel_integrity': integrity, 'manager': manager, 'variant': self.app.cfg.get('variant'),
                'panel_started_at': STARTED, 'release_path': str(self.app.frontend.parent)}

    def readiness(self):
        cert = self.app.control('certificate')
        domain = cert.get('domain') or ''
        answers = {}
        for family, name in ((socket.AF_INET, 'A'), (socket.AF_INET6, 'AAAA')):
            try: answers[name] = sorted({r[4][0] for r in socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)})
            except (OSError, UnicodeError): answers[name] = []
        local = set()
        try:
            for r in socket.getaddrinfo(socket.gethostname(), None): local.add(r[4][0])
        except OSError: pass
        acme = cert.get('mode') in ('certbot-http01', 'certbot-dns-cloudflare')
        checks = [
            {'item': 'DNS A record', 'status': 'ok' if answers['A'] else 'warning', 'value': answers['A'] or ['none'], 'source': 'this server\'s resolver (may differ from public resolvers)'},
            {'item': 'DNS AAAA record', 'status': 'info', 'value': answers['AAAA'] or ['none'], 'source': 'this server\'s resolver',
             'note': 'An AAAA record that points elsewhere can break HTTP-01 validation and IPv6 clients.'},
            {'item': 'Certificate', 'status': 'ok' if cert.get('expires_at') and cert['expires_at'] > time.time() + 14 * 86400 else 'warning', 'value': [cert.get('issuer') or 'unknown'], 'source': cert.get('source')},
            {'item': 'HTTP-01 port 80', 'status': 'unknown' if cert.get('mode') == 'certbot-http01' else 'info', 'value': ['inbound TCP 80 must reach this server during renewal' if cert.get('mode') == 'certbot-http01' else 'not used by this certificate mode'],
             'source': 'cannot be verified from inside the server', 'note': 'Cloudflare proxy (orange cloud), provider security groups or ISP filtering can block HTTP-01.'},
            {'item': 'Provider security group', 'status': 'unknown', 'value': ['not readable from the server'], 'source': 'external precondition'},
        ]
        return {'domain': domain, 'mode': cert.get('mode'), 'acme': acme, 'checks': checks, 'local_addresses': sorted(local)[:20], 'sampled_at': time.time(),
                'renew_preview': {'command': 'certbot renew --cert-name %s' % domain if acme else None, 'restarts': 'sing-box is reloaded with the new certificate; client YAML is unchanged',
                                  'prerequisites': ['DNS A/AAAA point to this server', 'TCP 80 reachable from the Internet (HTTP-01) or DNS provider token (DNS-01)', 'Let\'s Encrypt rate limits not exceeded']},
                'note': 'A local check cannot prove that a public CA can reach this server. "Renew now" reports the CA\'s answer; nothing here is faked.'}

    def report(self):
        """Copyable, redacted diagnostics text. Contains no credentials."""
        lines = ['SBOX diagnostics report (redacted)', 'generated: ' + time.strftime('%Y-%m-%d %H:%M:%S %Z'), 'panel: ' + VERSION + ' variant: ' + str(self.app.cfg.get('variant'))]
        try:
            o = self.app.observe(); svc = o.get('service', {})
            lines += ['core: %s/%s pid=%s version=%s expected=%s' % (svc.get('ActiveState'), svc.get('SubState'), svc.get('MainPID'), o.get('core_version'), o.get('expected_core_version')),
                      'memory available: %s of %s bytes; disk available: %s of %s bytes' % (o.get('memory_available_bytes'), o.get('memory_total_bytes'), o.get('disk_available_bytes'), o.get('disk_total_bytes')),
                      'recent core errors (1h): %s' % (o.get('recent_errors') or {}).get('count')]
        except Problem as e: lines.append('overview unavailable: ' + e.message)
        try:
            c = self.app.control('certificate'); lines.append('certificate: mode=%s expires_at=%s issuer=%s' % (c.get('mode'), c.get('expires_at'), c.get('issuer')))
        except Problem as e: lines.append('certificate unavailable: ' + e.message)
        try:
            for r in self.app.control('inbounds').get('inbounds', []): lines.append('inbound %s %s/%s listening=%s users=%s' % (r['id'], r['port'], r['network'], r.get('listening'), r.get('user_count')))
        except Problem as e: lines.append('inbounds unavailable: ' + e.message)
        if self.app.last_doctor:
            d = self.app.last_doctor; lines.append('doctor (%s): failures=%s warnings=%s' % (time.strftime('%Y-%m-%d %H:%M', time.localtime(self.app.last_doctor_at)), d.get('failures'), d.get('warnings')))
            lines += ['  [%s] %s' % (c.get('status'), c.get('label')) for c in d.get('checks', []) if c.get('status') != 'ok']
        for a in self.app.store.alerts():
            if a['resolved_at'] is None: lines.append('open alert: [%s] %s - %s' % (a['severity'], a['title'], a['detail']))
        lines.append('external reachability: not tested by this server')
        return redact('\n'.join(lines)) + '\n'

    def subscription_connection(self, ident, endpoints=None):
        result=self.app.subscriptions.reveal(ident)
        result['endpoints']=endpoints if endpoints is not None else self.app.control('endpoints',{'id':ident})
        raw=result.pop('token',None)
        if raw:
            base=self.app.cfg['origin']+'/sub/'+raw+'/'
            result['urls']={p:base+p+'.yaml' for p in PROFILES}
            result['exports']=export_catalog.subscription_urls(base)
            if self.app.store.setting('subscription-landing',False):result['page']=base
        result['catalog']=export_catalog.catalog(result['endpoints'],result.get('exports') if result.get('recoverable') else None,result.get('state','ready'))
        return result

    def subscription(self, path, query):
        parts = path.split('/')
        require(len(parts) == 4 and re.fullmatch(r'(?:v1\.)?[A-Za-z0-9_-]{43}',parts[2]), 'Not found', 404)
        # Per-IP request cap; subscription attempts do not share login lockout.
        self.server.rate('sub:' + self.client_address[0], 120)
        with self.app.store.db() as db:
            row = db.execute('SELECT user FROM subscriptions WHERE hash=?', (digest(parts[2]),)).fetchone()
        require(row is not None, 'Not found', 404)
        if hasattr(self.app.control,'set_context'):self.app.control.set_context({'kind':'subscription','raw':parts[2]})
        users = self.app.control('users')
        user = next((u for u in users if u['id'] == row['user'] and u['enabled']), None)
        require(user is not None, 'Not found', 404)
        if parts[3] == '':
            require(self.app.store.setting('subscription-landing', False), 'Not found', 404)
            return self.landing(parts[2], user, query)
        if parts[3] == 'qr':
            require(self.app.store.setting('subscription-landing', False), 'Not found', 404)
            return self.landing_qr(parts[2], row['user'], query)
        profile, sep, fmt = parts[3].partition('.')
        require(sep and profile in PROFILES and fmt in export_catalog.FORMATS and profile not in export_catalog.UNAVAILABLE.get(fmt, ()), 'Not found', 404)
        value = self.app.control('export', {'id': row['user'], 'profile': profile, 'format': fmt,'endpoint':query.get('endpoint','auto')})['content']
        etag = '"' + hashlib.sha256(value.encode()).hexdigest() + '"'
        if self.headers.get('If-None-Match') == etag: return self.send(304, b'', 'application/octet-stream', {'ETag': etag})
        return self.send(200, value.encode(), {'yaml': 'application/yaml; charset=utf-8', 'json': 'application/json; charset=utf-8', 'singbox': 'application/json; charset=utf-8', 'links': 'text/plain; charset=utf-8'}[fmt],
                         {'ETag': etag, 'Content-Disposition': 'attachment; filename="' + export_catalog.FILE_NAMES[fmt].format(profile=profile) + '"', 'Profile-Update-Interval': '24'})

    def landing(self, raw, user, query):
        """Personal setup page: the same Export Center as the console and portal, fed by
        the same catalog. Everything is derived from this token's own user."""
        zh = query.get('lang') == 'zh' or (query.get('lang') != 'en' and 'zh' in (self.headers.get('Accept-Language') or '').lower()[:5])
        e = html.escape
        base = self.app.cfg['origin'] + '/sub/' + raw + '/'
        endpoints = self.app.control('endpoints', {'id': user['id']})
        data = export_catalog.catalog(endpoints, export_catalog.subscription_urls(base), 'ready', user['name'])
        data['lang'] = 'zh' if zh else 'en'
        # JSON in a non-executable script element. <, > and & are \\u-escaped so no name or
        # label can close the element or enter a script-data escape state.
        blob = json.dumps(data, ensure_ascii=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        T = (lambda en, z: z if zh else en)
        page = ('''<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark">
<title>%s</title><link rel="stylesheet" href="/subscribe.css"><link rel="stylesheet" href="/export-center.css"><script defer src="/export-center.js"></script><script defer src="/subscribe.js"></script></head><body><main>
<p class="lang"><a href="?lang=en" rel="noreferrer">English</a> <a href="?lang=zh" rel="noreferrer">繁體中文</a></p>
<h1>%s</h1><p class="lead">%s <strong>%s</strong></p>
<script type="application/json" id="xc-data">%s</script>
<div id="export-center"><noscript><p>%s</p><p><a href="%s" rel="noreferrer">%s</a></p></noscript></div>
</main></body></html>''' % ('zh-Hant' if zh else 'en', e(T('Connect your device', '連接你的裝置')), e(T('Connect your device', '連接你的裝置')),
            e(T('Personal connection for', '個人連線：')), e(user['name']), blob,
            e(T('Turn on JavaScript to choose an app and profile. Without it, this link imports the general browsing profile for Mihomo apps:', '請開啟 JavaScript 以選擇 app 及設定檔。未開啟時，可用此連結匯入 Mihomo app 的一般上網設定檔：')),
            e(base + 'global.yaml'), e(base + 'global.yaml')))
        csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        return self.send(200, page, 'text/html; charset=utf-8', {'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store'}, csp=csp)

    def landing_qr(self, raw, ident, query):
        """QR for the landing page: only this token's own subscription URLs or node links."""
        require(set(query) <= {'kind', 'profile', 'format', 'endpoint', 'index'}, 'Unknown QR field')
        profile, endpoint = query.get('profile', 'global'), query.get('endpoint', 'auto')
        require(profile in PROFILES, 'Invalid profile')
        require(endpoint in {c['id'] for c in self.app.control('endpoints', {'id': ident})['choices']}, 'Endpoint unavailable')
        if query.get('kind') == 'node':
            try: index = int(query.get('index', ''))
            except ValueError: raise Problem(400, 'Invalid node')
            content = self.app.control('export', {'id': ident, 'profile': profile, 'format': 'links', 'endpoint': endpoint})['content']
            nodes = [line.strip() for line in content.splitlines() if re.match(r'^(?:vless|vmess|hysteria2|tuic|anytls)://', line.strip())]
            require(0 <= index < len(nodes), 'Node not found', 404)
            text = nodes[index]
        else:
            fmt = query.get('format', 'yaml')
            require(fmt in export_catalog.FORMATS and fmt != 'links' and profile not in export_catalog.UNAVAILABLE.get(fmt, ()), 'Invalid format')
            text = export_catalog.with_endpoint(self.app.cfg['origin'] + '/sub/' + raw + '/' + profile + '.' + fmt, endpoint)
        return self.send(200, {'svg': self.qr(text)}, headers={'Cache-Control': 'no-store'})

    def dispatch(self):
        if hasattr(self.app.control,'clear_context'):self.app.control.clear_context()
        try:
            self.framing()
            self.server.rate(self.client_address[0], self.server.request_limit)
            try:self.handle_request()
            finally:
                if hasattr(self.app.control,'clear_context'):self.app.control.clear_context()
        except Problem as e:
            headers = {'Retry-After': '60'} if e.status == 429 else None
            self.send(e.status, {'error': e.message, 'status': e.status}, headers=headers)
        except sqlite3.IntegrityError: self.send(409, {'error': 'Conflicting record already exists', 'status': 409})
        except (ValueError, TypeError, KeyError): self.send(400, {'error': 'Invalid request', 'status': 400})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError):
            # The browser closed the connection while a response was written
            # (navigation, tab close). Nothing to report and no reply possible.
            self.close_connection = True
        except Exception as exc:
            frames=traceback.extract_tb(exc.__traceback__)[-4:]
            print('SBOX request exception',type(exc).__name__,getattr(exc,'sqlite_errorname',''),','.join(Path(f.filename).name+':'+str(f.lineno)+':'+f.name for f in frames),file=sys.stderr,flush=True)
            # Deliberately do not serialize secrets, URLs, paths or DB errors.
            self.send(503, {'error': 'Operation unavailable. Inspect the root/panel service journal and doctor.', 'status': 503})
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = dispatch
    def do_OPTIONS(self): self.send(403, {'error': 'Cross-origin access is disabled'})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    def handle_error(self, request, client_address):
        # Disconnects/TLS failures must not log credential-bearing request lines
        # or turn a network flood into an unbounded journal stream.
        pass
    def __init__(self, address, app):
        self.address_family=socket.AF_INET6 if ':' in address[0] else socket.AF_INET
        self.app = app
        self.slots = threading.BoundedSemaphore(24)
        self.rates, self.rate_lock = {}, threading.Lock()
        self.request_limit = 600  # requests per minute per client address (all paths)
        super().__init__(address, Handler)

    def server_bind(self):
        # http.server.HTTPServer.server_bind() resolves socket.getfqdn(host) between
        # bind() and listen(). With slow or unreachable resolvers that left the port
        # refusing connections for 10+ seconds after every start. The panel never
        # uses server_name, so bind directly and skip the reverse lookup.
        if self.address_family==socket.AF_INET6 and self.server_address[0]=='::':
            self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = str(self.server_address[0]), self.server_address[1]
    def rate(self, key, limit):
        with self.rate_lock:
            now = int(time.time() // 60)
            if len(self.rates) >= 4096:
                self.rates = {k: v for k, v in self.rates.items() if v[0] == now}
                require(key in self.rates or len(self.rates)<4096,'Rate table is full; retry next minute',429)
            old = self.rates.get(key, (now, 0))
            count = old[1] + 1 if old[0] == now else 1
            self.rates[key] = (now, count)
            require(count <= limit, 'Rate limit exceeded', 429)
    def process_request(self, request, address):
        if not self.slots.acquire(timeout=5):
            request.close(); return
        try: super().process_request(request, address)
        except Exception: self.slots.release(); raise
    def process_request_thread(self, request, address):
        try: super().process_request_thread(request, address)
        finally: self.slots.release()


def main():
    cfg = json.loads(Path('/etc/sbox-webui/settings.json').read_text())
    require(os.geteuid() != 0, 'Panel must run as an unprivileged user', 403)
    app = App(cfg)
    server = Server((cfg['listen'], cfg['port']), app)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg['certificate'], cfg['key'])
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    app.start_background(interval=30, doctor_every=3600)
    server.serve_forever(poll_interval=1)

if __name__ == '__main__': main()
