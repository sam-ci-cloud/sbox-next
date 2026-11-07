"""Synthetic Universal state and helpers for REALITY fallback tests. TEST ONLY.

Every hostname is under the reserved .test TLD, every key is generated per run
and nothing here is a real credential. Used by tests/test_reality_fallback.py
and shared_webui/tests/lab_reality_fallback.py.
"""
import copy
import atexit
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = 'cloud.sbox.test'
REMOTE_SNI = 'www.microsoft.com'
SCHEMA = '2'
MINIMUM = '1.12.0'


def core_binary(cache=Path(tempfile.gettempdir()) / 'sbox-test-core'):
    """The pinned accounting core from assets/, decompressed once per host."""
    data = gzip.decompress((ROOT / 'assets/sing-box-accounting.gz').read_bytes())
    expected = hashlib.sha256(data).hexdigest()
    cache = cache / expected[:16]
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / 'sing-box'
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        tmp = target.with_suffix('.tmp')
        tmp.write_bytes(data)
        tmp.chmod(0o755)
        tmp.replace(target)
    return target


def reality_keypair():
    out = subprocess.run([str(core_binary()), 'generate', 'reality-keypair'], capture_output=True, text=True, check=True).stdout
    pairs = dict(line.split(': ', 1) for line in out.strip().splitlines())
    return pairs['PrivateKey'].strip(), pairs['PublicKey'].strip()


def base_state(private_key='A' * 43, public_key='B' * 43, reality_port=443, listen='0.0.0.0'):
    """A complete schema-2 Universal state with only VLESS REALITY enabled."""
    return {
        'schema': 2, 'manager_version': '1.1.0', 'created_at': '2026-10-30T00:00:00Z', 'updated_at': '2026-10-30T00:00:00Z',
        'region': 'global', 'node_name': 'LAB', 'domain': DOMAIN,
        'server': {'ipv4': '', 'ipv6': '', 'listen': listen},
        'sing_box': {'version': '1.13.14', 'channel': 'fixed'},
        'certificate': {'mode': 'none', 'source_mode': 'none', 'source_fullchain': '', 'source_key': '', 'insecure': False},
        'client_policy': {'primary': 'reality'},
        'firewall': {'enabled': False}, 'tuning': {'enabled': False}, 'security': {'block_private': False},
        'protocols': {
            'reality': {'enabled': True, 'port': reality_port, 'uuid': str(uuid.uuid4()), 'sni': REMOTE_SNI, 'dest_port': 443,
                        'fingerprint': 'chrome', 'private_key': private_key, 'public_key': public_key, 'short_id': '0123456789abcdef'},
            'vmess': {'enabled': False, 'port': 28443, 'uuid': str(uuid.uuid4()), 'path': 'lab-vm', 'tls': True, 'sni': DOMAIN},
            'hy2': {'enabled': False, 'port': 25443, 'password': 'h' * 24, 'udp_range': ''},
            'tuic': {'enabled': False, 'port': 26443, 'uuid': str(uuid.uuid4()), 'password': 't' * 24},
            'anytls': {'enabled': False, 'port': 27443, 'password': 'a' * 24},
        },
    }


def trusted_certificate(state, cert='/etc/letsencrypt/live/%s/fullchain.pem' % DOMAIN, key='/etc/letsencrypt/live/%s/privkey.pem' % DOMAIN):
    s = copy.deepcopy(state)
    s['certificate'] = {'mode': 'certbot-dns-cloudflare', 'source_mode': 'letsencrypt', 'source_fullchain': cert, 'source_key': key, 'insecure': False}
    return s


def self_hosted(state, port=8443, listen='127.0.0.1'):
    s = trusted_certificate(state)
    remote = s['protocols']['reality']['sni']
    s['protocols']['reality']['sni'] = s['domain']
    s['protocols']['reality']['fallback'] = {'mode': 'self_hosted', 'hostname': s['domain'], 'listen': listen, 'port': port, 'remote_sni': remote}
    return s


def state_tool(action, state, extra='', helper=None, cert_dir='/etc/sbox-manager/certs', env=None):
    """Run the state program exactly as the manager's state_tool does."""
    helper = helper or ROOT / 'src/state.py'
    with tempfile.TemporaryDirectory(prefix='sbox-state-') as td:
        path = Path(td) / 'state.json'
        path.write_text(json.dumps(state))
        result = subprocess.run(['python3', str(helper), action, str(path), str(extra), cert_dir, '1.1.0', SCHEMA, MINIMUM, ''],
                                capture_output=True, text=True, env={**os.environ, **(env or {})})
        return result


def render(state, helper=None, cert_dir='/etc/sbox-manager/certs'):
    managed = tempfile.TemporaryDirectory(prefix='sbox-render-')
    atexit.register(managed.cleanup)
    out = Path(managed.name)
    result = state_tool('render', state, out, helper, cert_dir, env={'SBOX_CERT_LAYOUT': 'live'})
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return out


def lab_certificates(directory, hostnames=(DOMAIN,), days=30):
    """A throw-away lab CA and one leaf per hostname. TEST ONLY - never trusted."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)
    run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', str(days + 1),
        '-subj', '/CN=SBOX offline lab CA (test only)', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash', '-keyout', str(d / 'ca.key'), '-out', str(d / 'ca.crt'))
    leaves = {}
    for host in hostnames:
        stem = d / host
        run('openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=' + host,
            '-keyout', str(stem) + '.key', '-out', str(stem) + '.csr')
        ext = Path(str(stem) + '.ext')
        # Explicit key identifiers: Python 3.13+ verifies with X509_STRICT, and
        # OpenSSL 4 no longer adds them implicitly to -extfile certificates.
        ext.write_text('subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' % host)
        run('openssl', 'x509', '-req', '-in', str(stem) + '.csr', '-CA', str(d / 'ca.crt'), '-CAkey', str(d / 'ca.key'),
            '-CAcreateserial', '-days', str(days), '-extfile', str(ext), '-out', str(stem) + '.crt')
        leaves[host] = (Path(str(stem) + '.crt'), Path(str(stem) + '.key'))
    return d / 'ca.crt', leaves
