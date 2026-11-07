"""UI-owned metadata only. VPN users/configuration remain manager-owned."""
import contextlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from auth_events import auth_failure
from common import Problem, SCHEMA, clean_name, digest, password_hash, password_ok, redact, require, token

class Store:
    def __init__(self, path):
        self.path = Path(path)
        self._anchor = None
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        if self.path.exists():
            with self.db() as db:
                require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'Database integrity check failed', 503)
                version = db.execute('PRAGMA user_version').fetchone()[0]
                require(version <= SCHEMA, 'Newer database schema; restore matching panel build', 503)
        with self.db() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version < SCHEMA:
                if self.path.stat().st_size:
                    snapshot = sqlite3.connect(str(self.path) + '.before-migration')
                    db.backup(snapshot); snapshot.close()
                    os.chmod(str(self.path) + '.before-migration', 0o600)
                db.executescript('''
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, reset INTEGER NOT NULL DEFAULT 1, totp TEXT, pending_totp TEXT, last_totp INTEGER DEFAULT -1, recovery TEXT DEFAULT '[]');
                    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, account INTEGER NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL, seen REAL NOT NULL, fresh REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, account INTEGER NOT NULL, scope TEXT NOT NULL, name TEXT NOT NULL, expires REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS subscriptions(user TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, created REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS samples(time INTEGER PRIMARY KEY, data TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, time REAL NOT NULL, count INTEGER NOT NULL);
                    PRAGMA user_version=1;
                    COMMIT;
                ''')
        self.additive_migrations()
        self.path.chmod(0o600)
        # Keep the panel-owned WAL and shared-memory files attached. A root
        # read-only bridge connection must never become the last connection
        # racing to create new sidecars with root ownership.
        anchor=sqlite3.connect(self.path,timeout=10,check_same_thread=False,isolation_level=None)
        try:
            anchor.execute('PRAGMA journal_mode=WAL')
            anchor.execute('SELECT key FROM settings LIMIT 1').fetchall()
        except Exception:anchor.close();raise
        self._anchor=anchor

    def close(self):
        anchor=getattr(self,'_anchor',None)
        if anchor is not None:self._anchor=None;anchor.close()

    def __del__(self):
        try:self.close()
        except Exception:pass

    def additive_migrations(self):
        # Additive objects only. PRAGMA user_version stays 1 so the previous
        # panel build (which refuses newer schemas) can still be rolled back to
        # with the same database; it ignores these tables/columns.
        with self.db() as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='subscription_recovery'").fetchone():
                backup = Path(str(self.path) + '.before-subscription-recovery-v1')
                require(not backup.is_symlink(), 'Unsafe migration backup', 503)
                target = sqlite3.connect(backup)
                try: db.backup(target)
                finally: target.close()
                backup.chmod(0o600)
            db.executescript('''
                CREATE TABLE IF NOT EXISTS feature_migrations(name TEXT PRIMARY KEY,applied_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS subscription_recovery(user TEXT PRIMARY KEY,version INTEGER NOT NULL,nonce TEXT NOT NULL,key_id TEXT NOT NULL);
                INSERT OR IGNORE INTO feature_migrations VALUES('subscription-recovery-v1',CAST(strftime('%s','now') AS REAL));
                CREATE TABLE IF NOT EXISTS alerts(key TEXT PRIMARY KEY, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, source TEXT NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, resolved_at REAL, count INTEGER NOT NULL DEFAULT 1, notified REAL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, source TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS session_meta(hash TEXT PRIMARY KEY, created REAL NOT NULL, ip TEXT NOT NULL, agent TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS notification_outbox(event TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,retry_at REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT);
                CREATE TABLE IF NOT EXISTS token_meta(hash TEXT PRIMARY KEY, created REAL NOT NULL, last_used REAL);
            ''')
            columns = {r['name'] for r in db.execute('PRAGMA table_info(audit)')}
            for name, kind in (('origin', "TEXT NOT NULL DEFAULT ''"), ('outcome', "TEXT NOT NULL DEFAULT 'ok'"), ('target', "TEXT NOT NULL DEFAULT ''")):
                if name not in columns:
                    db.execute('ALTER TABLE audit ADD COLUMN ' + name + ' ' + kind)

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA busy_timeout=10000')
            with db: yield db
        finally: db.close()

    def audit(self, actor, event, detail='', origin='', outcome='ok', target=''):
        with self.db() as db:
            db.execute('INSERT INTO audit(time,actor,event,detail,origin,outcome,target) VALUES(?,?,?,?,?,?,?)',
                       (time.time(), str(actor)[:64], event[:64], str(redact(detail))[:2000], str(origin)[:16], str(outcome)[:16], str(redact(str(target)))[:128]))
            db.execute('DELETE FROM audit WHERE id < (SELECT COALESCE(MAX(id),0)-10000 FROM audit)')

    def audit_query(self, actor='', event='', outcome='', since=None, until=None, text='', limit=100, offset=0):
        where, args = [], []
        for column, value in (('actor', actor), ('outcome', outcome)):
            if value:
                where.append(column + '=?'); args.append(value)
        if event:
            where.append('event LIKE ?'); args.append(event.replace('%', '').replace('_', '') + '%')
        if text:
            where.append('(detail LIKE ? OR target LIKE ?)'); clean = '%' + text.replace('%', '').replace('_', '') + '%'; args += [clean, clean]
        if since is not None:
            where.append('time>=?'); args.append(float(since))
        if until is not None:
            where.append('time<=?'); args.append(float(until))
        clause = (' WHERE ' + ' AND '.join(where)) if where else ''
        with self.db() as db:
            total = db.execute('SELECT COUNT(*) FROM audit' + clause, args).fetchone()[0]
            rows = [dict(r) for r in db.execute('SELECT id,time,actor,event,detail,origin,outcome,target FROM audit' + clause + ' ORDER BY id DESC LIMIT ? OFFSET ?', args + [int(limit), int(offset)])]
            actors = [r[0] for r in db.execute('SELECT DISTINCT actor FROM audit ORDER BY actor LIMIT 100')]
        return {'events': rows, 'total': total, 'actors': actors, 'limit': limit, 'offset': offset, 'retention': 'latest 10000 events'}

    def reset_password(self):
        secret = token()
        with self.db() as db:
            old = db.execute('SELECT id FROM accounts WHERE name=?', ('admin',)).fetchone()
            encoded = password_hash(secret)
            if old:
                db.execute('UPDATE accounts SET hash=?,reset=1,enabled=1,totp=NULL,pending_totp=NULL,recovery=\'[]\' WHERE id=?', (encoded, old['id']))
            else:
                db.execute('INSERT INTO accounts(name,hash,role) VALUES(?,?,?)', ('admin', encoded, 'admin'))
            db.execute('DELETE FROM sessions'); db.execute('DELETE FROM tokens')
            db.execute('DELETE FROM attempts')
        self.audit('root-cli', 'admin-reset')
        return secret

    def bootstrap(self, credential_file):
        secret = self.reset_password()
        fd = os.open(credential_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write('Username: admin\nPassword: ' + secret + '\nChange this password at first browser login.\n')
            stream.flush(); os.fsync(stream.fileno())

    def throttle(self, ip):
        now = time.time()
        with self.db() as db:
            db.execute('DELETE FROM attempts WHERE time < ?', (now - 900,))
            row = db.execute('SELECT * FROM attempts WHERE ip=?', (ip,)).fetchone()
            if row and row['count'] >= 8:auth_failure(ip,'rate-limit')
            require(not row or row['count'] < 8, 'Too many login attempts. Retry in 15 minutes.', 429)
            db.execute('INSERT INTO attempts VALUES(?,?,1) ON CONFLICT(ip) DO UPDATE SET count=count+1', (ip, now))

    def login(self, name, password, code, ip, agent=''):
        from common import verify_totp
        self.throttle(ip)
        with self.lock, self.db() as db:
            row = db.execute('SELECT * FROM accounts WHERE name=?', (name,)).fetchone()
            # A fixed dummy hash maintains the same expensive KDF for unknown names.
            encoded = row['hash'] if row else 'scrypt$32768$8$3$MDAwMDAwMDAwMDAwMDAwMA==$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA='
            valid = password_ok(password, encoded)
            if row and row['totp'] and valid:
                step = verify_totp(row['totp'], code, row['last_totp'])
                valid = step is not None
                if valid: db.execute('UPDATE accounts SET last_totp=? WHERE id=?', (step, row['id']))
                else:
                    recovery = json.loads(row['recovery'])
                    if digest(str(code)) in recovery:
                        recovery.remove(digest(str(code))); valid = True
                        db.execute('UPDATE accounts SET recovery=? WHERE id=?', (json.dumps(recovery), row['id']))
            if not row or not valid or not row['enabled']:
                # Audit separately after this transaction so failure cannot roll it back.
                auth_failure(ip,'login')
                self.audit('anonymous', 'login-failed', ip, origin='browser', outcome='denied', target=str(name)[:64])
                raise Problem(401, 'Invalid credentials')
            session, csrf, now = token(), token(), time.time()
            if row['hash'].startswith('scrypt$32768$8$1$'):
                db.execute('UPDATE accounts SET hash=? WHERE id=?',(password_hash(password),row['id']))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)', (digest(session), row['id'], csrf, now + 28800, now, now))
            db.execute('INSERT OR REPLACE INTO session_meta VALUES(?,?,?,?)', (digest(session), now, str(ip)[:64], str(agent or '')[:160]))
            db.execute('DELETE FROM session_meta WHERE hash NOT IN (SELECT hash FROM sessions)')
            db.execute('DELETE FROM attempts WHERE ip=?', (ip,))
        self.audit(row['name'], 'login', ip, origin='browser')
        return session, csrf

    def auth(self, raw, bearer=False):
        now = time.time()
        with self.db() as db:
            if bearer:
                row = db.execute('SELECT a.*,t.scope,t.expires FROM tokens t JOIN accounts a ON a.id=t.account WHERE t.hash=?', (digest(raw),)).fetchone()
                require(row is not None and row['expires'] > now and row['enabled'] and not row['reset'], 'Unauthorized', 401)
                result = dict(row); result.update(csrf=None, fresh=0)
                meta = db.execute('SELECT last_used FROM token_meta WHERE hash=?', (digest(raw),)).fetchone()
                if meta is None or (meta['last_used'] or 0) + 60 < now:
                    db.execute('INSERT INTO token_meta(hash,created,last_used) VALUES(?,?,?) ON CONFLICT(hash) DO UPDATE SET last_used=excluded.last_used', (digest(raw), now, now))
            else:
                row = db.execute('SELECT a.*,s.csrf,s.expires,s.seen,s.fresh FROM sessions s JOIN accounts a ON a.id=s.account WHERE s.hash=?', (digest(raw),)).fetchone()
                require(row is not None and row['enabled'] and row['expires'] > now and row['seen'] + 1800 > now, 'Unauthorized', 401)
                result = dict(row); result['scope'] = row['role']
                # Limit writes caused by a frequently polled dashboard.
                if row['seen'] + 60 < now: db.execute('UPDATE sessions SET seen=? WHERE hash=?', (now, digest(raw)))
            db.execute('DELETE FROM sessions WHERE expires < ? OR seen < ?', (now, now - 1800))
        return result

    def change_password(self, actor, raw, old, new):
        require(password_ok(old, actor['hash']), 'Invalid credentials', 401)
        encoded = password_hash(new)
        require(not password_ok(new, actor['hash']), 'Choose a different password')
        csrf = token()
        with self.db() as db:
            db.execute('UPDATE accounts SET hash=?,reset=0 WHERE id=?', (encoded, actor['id']))
            db.execute('DELETE FROM sessions WHERE account=? AND hash<>?', (actor['id'], digest(raw)))
            db.execute('UPDATE sessions SET csrf=?,fresh=? WHERE hash=?', (csrf, time.time(), digest(raw)))
            db.execute('DELETE FROM tokens WHERE account=?', (actor['id'],))
        self.audit(actor['name'], 'password-changed')
        return csrf

    def history(self, seconds=3600, end=None):
        """Samples newest-last within explicit bounds (bounded to 12000 rows)."""
        end = time.time() if end is None else end
        since = end - seconds
        with self.db() as db:
            return [value for row in db.execute('SELECT data FROM (SELECT time,data FROM samples WHERE time>=? AND time<=? ORDER BY time DESC LIMIT 12000) ORDER BY time', (since-10, end)) if since <= (value := json.loads(row['data'])).get('sampled_at', 0) <= end]

    def sample(self, value):
        """Store a compact host sample. Retention: every sample for 24 h, one
        per 10 minutes for 7 days and hourly through 30 days."""
        stamp = int(value['sampled_at']) // 10 * 10
        compact = {k: value.get(k) for k in ('sampled_at', 'network', 'cpu_percent', 'memory_total_bytes', 'memory_available_bytes', 'disk_total_bytes', 'disk_available_bytes', 'uptime_seconds', 'boot_id', 'load_average','swap_total_bytes','swap_free_bytes','disk_io','probes') if k in value}
        compact['service'] = {k:(value.get('service') or {}).get(k) for k in ('ActiveState','MainPID','NRestarts')}
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO samples VALUES(?,?)', (stamp, json.dumps(compact)))
            day = stamp - 86400
            db.execute('DELETE FROM samples WHERE time < ?', (stamp - 30 * 86400,))
            # Thin older-than-24h samples to the first sample of each 10-minute bucket.
            db.execute('DELETE FROM samples WHERE time < ? AND time NOT IN (SELECT MIN(time) FROM samples WHERE time < ? GROUP BY time/600)', (day, day))
            week=stamp-7*86400
            db.execute('DELETE FROM samples WHERE time < ? AND time NOT IN (SELECT MIN(time) FROM samples WHERE time < ? GROUP BY time/3600)',(week,week))

    def host_budget(self,value=None):
        from quota_models import quota_plan,quota_boundaries
        from monitor import physical_interfaces
        cfg=quota_plan(self.setting('host-budget',{'period':'monthly'}));now=time.time();start,end=quota_boundaries(now,cfg)
        with self.db() as db:
            old=db.execute("SELECT value FROM settings WHERE key='host-meter'").fetchone();meter=json.loads(old[0]) if old else {}
            if value:
                previous=meter.get('network',{});delta=0;gap=meter.get('gap',False)
                for name in physical_interfaces(value.get('network',{})):
                    cur=value['network'][name];prev=previous.get(name)
                    if prev:
                        if value.get('boot_id')==meter.get('boot_id') and cur['rx']>=prev['rx'] and cur['tx']>=prev['tx']:delta+=cur['rx']-prev['rx']+cur['tx']-prev['tx']
                        else:gap=True
                used=meter.get('used_bytes',0)
                if meter.get('period_end') and now>=meter['period_end']:used=0;gap=True;delta=0
                meter.update(used_bytes=used+delta,lifetime_bytes=meter.get('lifetime_bytes',0)+delta,network=value.get('network',{}),boot_id=value.get('boot_id'),period_start=start,period_end=end,sampled_at=value['sampled_at'],gap=gap,started_at=meter.get('started_at',value['sampled_at']))
                db.execute("INSERT INTO settings VALUES('host-meter',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(meter),))
        return {k:meter.get(k) for k in ('used_bytes','lifetime_bytes','period_start','period_end','sampled_at','started_at','gap')}|{'quota_bytes':cfg['quota_bytes'],'timezone':cfg['timezone'],'reset_day':cfg['reset_day'],'source':'Host interface RX + TX since monitoring began; excludes virtual interfaces. Provider invoice may differ. Not individual VPN user traffic.','accuracy':'Measured lower bound since monitoring activation; no imported provider totals'}

    def setting(self, key, default=None):
        with self.db() as db:
            row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
            return json.loads(row['value']) if row else default

    def set_setting(self, key, value):
        with self.db() as db: db.execute('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))

    # -- reauthentication -------------------------------------------------
    def reauthenticate(self, actor, raw, password, code):
        """Fresh-session proof. Requires the TOTP/recovery code when MFA is
        enrolled and shares the bounded failure counter with login."""
        from common import verify_totp
        key = 'reauth:' + str(actor['id'])
        self.throttle(key)
        valid = password_ok(password, actor['hash'])
        with self.lock, self.db() as db:
            row = db.execute('SELECT totp,last_totp,recovery FROM accounts WHERE id=?', (actor['id'],)).fetchone()
            if valid and row['totp']:
                step = verify_totp(row['totp'], code or '', row['last_totp'])
                if step is not None:
                    db.execute('UPDATE accounts SET last_totp=? WHERE id=?', (step, actor['id']))
                else:
                    recovery = json.loads(row['recovery'])
                    if code and digest(str(code)) in recovery:
                        recovery.remove(digest(str(code)))
                        db.execute('UPDATE accounts SET recovery=? WHERE id=?', (json.dumps(recovery), actor['id']))
                    else:
                        valid = False
            if valid:
                db.execute('UPDATE sessions SET fresh=? WHERE hash=?', (time.time(), digest(raw)))
                db.execute('DELETE FROM attempts WHERE ip=?', (key,))
        if not valid:
            self.audit(actor['name'], 'reauth-failed', '', origin='browser', outcome='denied')
            raise Problem(401, 'Invalid credentials' + (' or authenticator code' if row['totp'] else ''))
        self.audit(actor['name'], 'reauthenticated', '', origin='browser')

    # -- sessions and tokens ------------------------------------------------
    def sessions(self, actor, raw, everyone=False):
        now = time.time()
        with self.db() as db:
            query = ('SELECT s.hash,s.expires,s.seen,s.fresh,a.name,m.created,m.ip,m.agent FROM sessions s JOIN accounts a ON a.id=s.account '
                     'LEFT JOIN session_meta m ON m.hash=s.hash WHERE s.expires>? AND s.seen>?')
            args = [now, now - 1800]
            if not everyone:
                query += ' AND s.account=?'; args.append(actor['id'])
            rows = db.execute(query + ' ORDER BY s.seen DESC LIMIT 200', args).fetchall()
        current = digest(raw)
        return [{'id': r['hash'][:16], 'account': r['name'], 'created': r['created'] or r['expires'] - 28800, 'last_seen': r['seen'],
                 'expires': min(r['expires'], r['seen'] + 1800), 'ip': r['ip'] or 'unknown', 'agent': r['agent'] or 'unknown',
                 'current': r['hash'] == current, 'recently_verified': r['fresh'] + 300 > now} for r in rows]

    def revoke_sessions(self, actor, raw, ident=None, others=False, everyone=False):
        current = digest(raw)
        with self.db() as db:
            if others:
                scope = '' if everyone else ' AND account=?'
                args = [current] + ([] if everyone else [actor['id']])
                count = db.execute('DELETE FROM sessions WHERE hash<>?' + scope, args).rowcount
            else:
                require(isinstance(ident, str) and len(ident) == 16 and all(c in '0123456789abcdef' for c in ident), 'Invalid session id')
                row = db.execute('SELECT hash,account FROM sessions WHERE substr(hash,1,16)=?', (ident,)).fetchone()
                require(row is not None, 'Session not found or already ended', 404)
                require(everyone or row['account'] == actor['id'], 'Session belongs to another account', 403)
                require(row['hash'] != current, 'Use Sign out to end the current session', 409)
                count = db.execute('DELETE FROM sessions WHERE hash=?', (row['hash'],)).rowcount
            db.execute('DELETE FROM session_meta WHERE hash NOT IN (SELECT hash FROM sessions)')
        self.audit(actor['name'], 'sessions-revoked', str(count), origin='browser', target='others' if others else ident)
        return count

    def tokens(self, actor):
        with self.db() as db:
            rows = db.execute('SELECT t.hash,t.name,t.scope,t.expires,m.created,m.last_used FROM tokens t LEFT JOIN token_meta m ON m.hash=t.hash WHERE t.account=? ORDER BY t.expires DESC', (actor['id'],)).fetchall()
        return [{'id': r['hash'][:16], 'name': r['name'], 'scope': r['scope'], 'expires': r['expires'], 'created': r['created'], 'last_used': r['last_used'], 'expired': r['expires'] <= time.time()} for r in rows]

    def create_token(self, actor, name, scope, hours):
        raw = token(); now = time.time()
        with self.db() as db:
            db.execute('INSERT INTO tokens VALUES(?,?,?,?,?)', (digest(raw), actor['id'], scope, clean_name(name), now + hours * 3600))
            db.execute('INSERT OR REPLACE INTO token_meta(hash,created,last_used) VALUES(?,?,NULL)', (digest(raw), now))
        self.audit(actor['name'], 'api-token-created', scope, origin='browser', target=name)
        return raw

    def revoke_token(self, actor, ident=None, everything=False):
        with self.db() as db:
            if everything:
                count = db.execute('DELETE FROM tokens WHERE account=?', (actor['id'],)).rowcount
            else:
                require(isinstance(ident, str) and len(ident) == 16 and all(c in '0123456789abcdef' for c in ident), 'Invalid token id')
                count = db.execute('DELETE FROM tokens WHERE account=? AND substr(hash,1,16)=?', (actor['id'], ident)).rowcount
                require(count == 1, 'Token not found', 404)
            db.execute('DELETE FROM token_meta WHERE hash NOT IN (SELECT hash FROM tokens)')
        self.audit(actor['name'], 'api-token-revoked', str(count), origin='browser', target='all' if everything else ident)
        return count

    # -- alerts and incident timeline ----------------------------------------
    def event(self, kind, severity, title, detail='', source=''):
        with self.db() as db:
            db.execute('INSERT INTO events(time,kind,severity,title,detail,source) VALUES(?,?,?,?,?,?)', (time.time(), kind[:64], severity[:16], title[:200], str(redact(detail))[:1000], source[:200]))
            db.execute('DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)')

    def raise_alert(self, key, severity, title, detail, source):
        """Open/refresh one deduplicated alert. Returns 'opened', 'escalated' or None."""
        now = time.time()
        with self.lock, self.db() as db:
            row = db.execute('SELECT * FROM alerts WHERE key=?', (key,)).fetchone()
            if row and row['resolved_at'] is None:
                transition = 'escalated' if severity != row['severity'] and severity == 'critical' else None
                db.execute('UPDATE alerts SET last_seen=?,count=count+1,severity=?,title=?,detail=?,source=? WHERE key=?', (now, severity, title[:200], str(redact(detail))[:1000], source[:200], key))
            else:
                transition = 'opened'
                db.execute('INSERT INTO alerts(key,severity,title,detail,source,first_seen,last_seen,resolved_at,count,notified) VALUES(?,?,?,?,?,?,?,NULL,1,NULL) '
                           'ON CONFLICT(key) DO UPDATE SET severity=excluded.severity,title=excluded.title,detail=excluded.detail,source=excluded.source,first_seen=excluded.first_seen,last_seen=excluded.last_seen,resolved_at=NULL,count=1,notified=NULL',
                           (key, severity, title[:200], str(redact(detail))[:1000], source[:200], now, now))
        if transition:
            self.event('alert-' + transition, severity, title, detail, source)
        return transition

    def resolve_alert(self, key, title=None):
        now = time.time()
        with self.lock, self.db() as db:
            row = db.execute('SELECT * FROM alerts WHERE key=? AND resolved_at IS NULL', (key,)).fetchone()
            if not row:
                return None
            db.execute('UPDATE alerts SET resolved_at=? WHERE key=?', (now, key))
        self.event('alert-resolved', 'ok', title or ('Recovered: ' + row['title']), '', row['source'])
        return dict(row)

    def alerts(self, include_resolved_days=7):
        since = time.time() - include_resolved_days * 86400
        with self.db() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM alerts WHERE resolved_at IS NULL OR resolved_at>=? ORDER BY resolved_at IS NOT NULL, last_seen DESC LIMIT 200', (since,))]
        rank = {'critical': 0, 'warning': 1, 'info': 2}
        rows.sort(key=lambda r: (r['resolved_at'] is not None, rank.get(r['severity'], 3), -r['last_seen']))
        return rows

    def open_alert_keys(self):
        with self.db() as db:
            return {r[0] for r in db.execute('SELECT key FROM alerts WHERE resolved_at IS NULL')}

    def timeline(self, days=7, limit=150):
        since = time.time() - days * 86400
        with self.db() as db:
            events = [dict(r) for r in db.execute('SELECT time,kind,severity,title,detail,source FROM events WHERE time>=? ORDER BY id DESC LIMIT ?', (since, limit))]
            changes = [dict(r) for r in db.execute("SELECT time,actor,event,detail,origin,outcome,target FROM audit WHERE time>=? AND (event LIKE 'change-%' OR event LIKE 'action%' OR event IN ('admin-reset','subscription-rotated','subscription-revoked','sessions-revoked','totp-enabled','totp-disabled','password-changed')) ORDER BY id DESC LIMIT ?", (since, limit))]
        for c in changes:
            events.append({'time': c['time'], 'kind': 'audit:' + c['event'], 'severity': 'warning' if c['outcome'] not in ('ok', '') else 'info',
                           'title': c['event'], 'detail': c['detail'], 'source': 'panel audit (' + (c['origin'] or 'unknown origin') + ', ' + c['actor'] + ')'})
        events.sort(key=lambda e: -e['time'])
        return events[:limit]

    def queue_notification(self,event,payload):
        now=time.time()
        with self.db() as db:
            db.execute('DELETE FROM notification_outbox WHERE created<?',(now-7*86400,))
            db.execute('INSERT OR IGNORE INTO notification_outbox(event,payload,created,retry_at) VALUES(?,?,?,?)',(event,json.dumps(payload),now,now))
            db.execute('DELETE FROM notification_outbox WHERE event IN (SELECT event FROM notification_outbox ORDER BY created DESC LIMIT -1 OFFSET 1000)')

    def due_notifications(self):
        with self.db() as db:return [dict(r) for r in db.execute('SELECT * FROM notification_outbox WHERE retry_at<=? ORDER BY created,event LIMIT 5',(time.time(),))]

    def notification_result(self,event,error=None,attempts=0):
        with self.db() as db:
            if error is None:db.execute('DELETE FROM notification_outbox WHERE event=?',(event,))
            else:db.execute('UPDATE notification_outbox SET attempts=?,retry_at=?,last_error=? WHERE event=?',(attempts+1,time.time()+min(3600,30*2**min(attempts,7)),str(error)[:80],event))

    def notification_status(self):
        with self.db() as db:
            row=db.execute('SELECT COUNT(*) AS pending,MIN(retry_at) AS next_retry_at,MAX(attempts) AS maximum_attempts FROM notification_outbox').fetchone();error=db.execute('SELECT last_error FROM notification_outbox WHERE last_error IS NOT NULL ORDER BY retry_at DESC LIMIT 1').fetchone()
        return {**dict(row),'last_error':error[0] if error else None,'retention':'At most 1000 notifications / 7 days; retry backoff 30 seconds to 1 hour; up to 5 deliveries per evaluation'}

    def login_failures(self, seconds=900):
        with self.db() as db:
            return db.execute("SELECT COUNT(*) FROM audit WHERE event IN ('login-failed','reauth-failed') AND time>=?", (time.time() - seconds,)).fetchone()[0]
