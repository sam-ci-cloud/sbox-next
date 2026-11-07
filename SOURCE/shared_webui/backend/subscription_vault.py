"""Repeatable subscription bearers, derived from a key kept outside SQLite.

The old three-column subscriptions table remains the source of validity. Its
hash-only rows are deliberately never upgraded by reading them. The extra row
contains only a random nonce and key fingerprint, not a recoverable credential
without the separate key. Replacing/revoking is always an explicit operation.
"""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import time

from common import Problem, digest, require

KEY_NAME = 'subscription.key'


def read_key(path, owner=None):
    path = Path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and
                (owner is None or info.st_uid == owner),
                'Subscription key ownership or permissions are unsafe', 503)
        value = os.read(fd, 33)
        require(len(value) == 32, 'Invalid subscription key', 503)
        return value
    finally:
        os.close(fd)


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:32]


class SubscriptionVault:
    def __init__(self, store):
        self.store = store
        self.path = store.path.parent / KEY_NAME

    def key(self, create=False):
        with self.store.db() as db:
            expected = {r[0] for r in db.execute('SELECT DISTINCT key_id FROM subscription_recovery')}
        if create and not self.path.exists() and not self.path.is_symlink():
            require(not expected, 'Restore the subscription key from a matching private backup', 503)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(secrets.token_bytes(32)); stream.flush(); os.fsync(stream.fileno())
                    directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try: os.fsync(directory)
                    finally: os.close(directory)
                except Exception:
                    self.path.unlink(missing_ok=True)
                    raise
        try:
            value = read_key(self.path, self.store.path.stat().st_uid)
        except (OSError, Problem):
            raise Problem(503, 'Restore the subscription key from a matching private backup') from None
        require(not expected or expected == {key_id(value)},
                'Restore the subscription key from a matching private backup', 503)
        return value

    @staticmethod
    def derive(key, user, nonce, version=2):
        message = ('SBOX/subscription/v' + str(version) + '\0' + user + '\0' + nonce).encode()
        value = base64.urlsafe_b64encode(hmac.digest(key, message, 'sha256')).decode().rstrip('=')
        # Version lives in recovery metadata. Keeping the original 43-character
        # bearer shape lets the preceding release serve new links on rollback.
        # Retain reveal support for links issued by the earlier private candidate.
        return ('v1.' if version == 1 else '') + value

    def issue(self, user, reserve=False):
        with self.store.lock:
            return self._issue(user,reserve)

    def _issue(self, user, reserve=False):
        require(isinstance(user, str) and 0 < len(user) <= 64, 'Invalid subscription user')
        key = self.key(create=True); nonce = secrets.token_hex(24)
        raw = self.derive(key, user, nonce)
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if reserve:
                require(db.execute('SELECT 1 FROM subscriptions WHERE user=?', (user,)).fetchone() is None,
                        'Onboarding link already reserved; inspect current user state', 409)
            db.execute('INSERT INTO subscriptions VALUES(?,?,?) ON CONFLICT(user) DO UPDATE SET hash=excluded.hash,created=excluded.created',
                       (user, digest(raw), time.time()))
            db.execute('INSERT INTO subscription_recovery VALUES(?,?,?,?) ON CONFLICT(user) DO UPDATE SET version=excluded.version,nonce=excluded.nonce,key_id=excluded.key_id',
                       (user, 2, nonce, key_id(key)))
        return raw

    def reveal(self, user):
        with self.store.db() as db:
            row = db.execute('SELECT s.hash,s.created,r.version,r.nonce,r.key_id FROM subscriptions s LEFT JOIN subscription_recovery r ON r.user=s.user WHERE s.user=?', (user,)).fetchone()
        if row is None: return {'state': 'absent', 'active': False, 'recoverable': False}
        result = {'state': 'legacy', 'active': True, 'recoverable': False, 'created': row['created']}
        if row['version'] not in (1, 2): return result
        try: key = self.key()
        except Problem: return {**result, 'state': 'key_unavailable'}
        raw = self.derive(key, user, row['nonce'], row['version'])
        # Older builds may rotate the original hash while ignoring our table.
        if not hmac.compare_digest(digest(raw), row['hash']): return result
        return {**result, 'state': 'ready', 'recoverable': True, 'token': raw}

    def revoke(self, user, expected_hash=None):
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if expected_hash is None:
                count = db.execute('DELETE FROM subscriptions WHERE user=?', (user,)).rowcount
            else:
                count = db.execute('DELETE FROM subscriptions WHERE user=? AND hash=?', (user, expected_hash)).rowcount
            if expected_hash is None or count: db.execute('DELETE FROM subscription_recovery WHERE user=?', (user,))
        return count
