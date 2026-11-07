"""SBOX WebUI v1: common validation and security primitives (stdlib only)."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
import threading
import urllib.parse

VERSION = '1.11.0'
SCHEMA = 1
PROTOCOLS = ('reality', 'vmess', 'hy2', 'tuic', 'anytls')
KDF_SLOTS=threading.BoundedSemaphore(2)

class Problem(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)

def require(ok, message, status=400):
    if not ok:
        raise Problem(status, message)

def token():
    return secrets.token_urlsafe(32)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(value):
    require(isinstance(value, str) and 12 <= len(value) <= 256, 'Password must contain 12–256 characters')
    salt = secrets.token_bytes(16)
    with KDF_SLOTS:raw = hashlib.scrypt(value.encode(), salt=salt, n=32768, r=8, p=3, maxmem=67108864)
    return 'scrypt$32768$8$3$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(raw).decode()

def password_ok(value, encoded):
    try:
        _, n, r, p, salt, expected = encoded.split('$')
        require(n=='32768' and r=='8' and p in ('1','3'), 'Invalid password hash')
        with KDF_SLOTS:actual = hashlib.scrypt(str(value).encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), maxmem=67108864)
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError, Problem):
        return False

def atomic_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)

SECRET_KEYS = re.compile(r'password|private.?key|secret|token|authorization|cookie|uuid|short.?id|recovery|credential|generation', re.I)

def redact(value):
    if isinstance(value, dict):
        return {k: '[redacted]' if SECRET_KEYS.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----','[redacted private key]',value,flags=re.S)
        value = re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]+','[redacted authorization]',value)
        value = re.sub(r'(?i)(?:vless|vmess|tuic|hysteria2|anytls)://\S+', '[redacted link]', value)
        value = re.sub(r'(?i)(password|private[_ -]?key|secret|token|uuid|short[_ -]?id|authorization|cookie)["\x27]?\s*[=:]\s*(?:"[^"]*"|\S+)', r'\1=[redacted]', value)
        value = re.sub(r'(?i)(?:https?://)[^\s]+', '[redacted URL]', value)
        return value[:16384]
    return value

def clean_name(value):
    require(isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9._-]{1,64}', value)), 'Use 1–64 letters, digits, dots, underscores or hyphens')
    return value

def totp(secret, step=None):
    key = base64.b32decode(secret, casefold=True)
    raw = hmac.new(key, struct.pack('>Q', int(time.time() // 30) if step is None else step), hashlib.sha1).digest()
    pos = raw[-1] & 15
    return str((struct.unpack('>I', raw[pos:pos+4])[0] & 0x7fffffff) % 1000000).zfill(6)

def verify_totp(secret, code, last=-1):
    now = int(time.time() // 30)
    for step in (now - 1, now, now + 1):
        if step > last and hmac.compare_digest(totp(secret, step), str(code)):
            return step
    return None

def _embedded_ipv4(address):
    """IPv4 carried inside IPv6 transition forms (mapped, compatible, NAT64,
    6to4, Teredo). Each must itself be a public address."""
    found = []
    if address.version != 6:
        return found
    if address.ipv4_mapped: found.append(address.ipv4_mapped)
    if address.sixtofour: found.append(address.sixtofour)
    if address.teredo: found.extend(address.teredo)
    raw = int(address)
    if address in ipaddress.ip_network('64:ff9b::/96') or address in ipaddress.ip_network('64:ff9b:1::/48'):
        found.append(ipaddress.IPv4Address(raw & 0xffffffff))
    if raw >> 32 == 0 and raw > 1:  # deprecated IPv4-compatible ::a.b.c.d
        found.append(ipaddress.IPv4Address(raw & 0xffffffff))
    return found

def destination_allowed(value):
    """Outbound notification destinations must be public unicast on every
    Python version shipped by Ubuntu 24.04 (3.12) and Debian 12 (3.11)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_loopback or address.is_link_local or address.is_unspecified:
        return False
    if address.version == 4 and address in ipaddress.ip_network('100.64.0.0/10'):
        return False
    return all(destination_allowed(str(inner)) for inner in _embedded_ipv4(address))

def public_https_url(value):
    require(isinstance(value, str) and len(value) <= 2048 and not re.search(r'[\x00-\x20\\\x7f]', value), 'Invalid HTTPS URL')
    try:
        u = urllib.parse.urlsplit(value)
        require(u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.fragment and u.port in (None, 443), 'Public HTTPS on port 443 is required')
        records = socket.getaddrinfo(u.hostname, 443, type=socket.SOCK_STREAM)
        addresses = sorted({r[4][0].split('%')[0] for r in records})
        require(addresses and all(destination_allowed(a) for a in addresses), 'Private, reserved and metadata destinations are forbidden')
        return u, addresses
    except (ValueError, OSError):
        raise Problem(400, 'HTTPS destination could not be validated')

def capabilities(version, variant, accounting=None, health=None):
    cfg=accounting or {};coverage=cfg.get('coverage',{});supported=bool(cfg.get('enabled') and re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?',str(version)) and re.fullmatch('[a-f0-9]{64}',str(cfg.get('core_sha256',''))) and all(coverage.get(p) is True for p in PROTOCOLS))
    return dict(variant=variant, core_version=version, independent_users=True,
                per_user_traffic=supported, quotas=supported, online_sessions=False,
                expiry=supported, user_portal=True,multi_vps=False,
                reason='Verified authenticated payload accounting and per-managed-user data-plane enforcement. Availability and collection gaps are reported separately.' if supported else 'No verified accounting adapter is enabled for this core. User traffic is unavailable; quota inputs are disabled.',
                accounting_source='sing-box V2Ray StatsService' if supported else None,protocol_coverage={p:bool(supported and coverage.get(p)) for p in PROTOCOLS},accounting_health=health,admin_schema=SCHEMA,panel_version=VERSION)
