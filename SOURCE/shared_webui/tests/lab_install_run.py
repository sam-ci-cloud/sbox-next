#!/usr/bin/env python3
"""Run a standalone installer inside a disposable systemd container (lab_container.py).

LAB ONLY. Prepares the lab network (container <-> client namespace), lab CA
certificate lineage, REALITY camouflage target and HTTP probe target, then runs
the exact standalone installer with stdin closed and records the outcome.

  lab_install_run.py --name zgo1 --variant zgocloud --installer PATH --out DIR
  lab_install_run.py --name gen1 --variant universal --installer PATH --out DIR -- install global --yes ...

Environment passed to the installer: SBOX_SECURITY_DEFERRED=true (the lab has
no SSH daemon; the owned SSH jail is deferred and therefore NOT tested here).
"""
import argparse, json, os, re, shutil, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CT = HERE / 'lab_container.py'
NL = HERE / 'lab_netlink.py'
CT_IP, CLI_IP, HTTP_IP, CAMO_IP = '10.99.0.1', '10.99.0.2', '198.51.100.10', '203.0.113.80'


def sh(*a, check=True, timeout=None, input=None):
    p = subprocess.run([str(x) for x in a], capture_output=True, text=True, timeout=timeout, input=input)
    if check and p.returncode: raise SystemExit('failed: %s\n%s' % (' '.join(map(str, a))[:300], (p.stderr or p.stdout)[-1500:]))
    return p


def cexec(name, cmd, check=True, timeout=600):
    return sh('python3', CT, 'exec', name, '--', 'bash', '-c', cmd, check=check, timeout=timeout)


def lineage(root, domain, ca):
    d = root / 'etc/letsencrypt'
    for sub in ('archive/' + domain, 'live/' + domain, 'renewal'): (d / sub).mkdir(parents=True, exist_ok=True)
    a = d / 'archive' / domain
    shutil.copy(ca / 'leaf.crt', a / 'cert1.pem'); shutil.copy(ca / 'ca.crt', a / 'chain1.pem')
    (a / 'fullchain1.pem').write_text((ca / 'leaf.crt').read_text() + (ca / 'ca.crt').read_text())
    shutil.copy(ca / 'leaf.key', a / 'privkey1.pem'); (a / 'privkey1.pem').chmod(0o600)
    for f in ('cert', 'chain', 'fullchain', 'privkey'):
        link = d / 'live' / domain / (f + '.pem')
        if link.is_symlink() or link.exists(): link.unlink()
        link.symlink_to('../../archive/%s/%s1.pem' % (domain, f))
    (d / 'renewal' / (domain + '.conf')).write_text(
        '# LAB LINEAGE: issued by a disposable lab CA, not a public CA\nversion = 2.9.0\narchive_dir = /etc/letsencrypt/archive/{0}\ncert = /etc/letsencrypt/live/{0}/cert.pem\n'
        'privkey = /etc/letsencrypt/live/{0}/privkey.pem\nchain = /etc/letsencrypt/live/{0}/chain.pem\nfullchain = /etc/letsencrypt/live/{0}/fullchain.pem\n[renewalparams]\nauthenticator = standalone\n'.format(domain))


def pki(work, domain, camo):
    ca = work / 'ca'; ca.mkdir(parents=True, exist_ok=True)
    sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '30', '-subj', '/CN=SBOX DISPOSABLE LAB CA (not public)', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', ca / 'ca.key', '-out', ca / 'ca.crt')
    for name, stem in ((domain, 'leaf'), (camo, 'camo')):
        sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=' + name, '-keyout', ca / (stem + '.key'), '-out', ca / (stem + '.csr'))
        (ca / (stem + '.ext')).write_text('subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' % name)
        sh('openssl', 'x509', '-req', '-in', ca / (stem + '.csr'), '-CA', ca / 'ca.crt', '-CAkey', ca / 'ca.key', '-CAcreateserial', '-days', '20', '-extfile', ca / (stem + '.ext'), '-out', ca / (stem + '.crt'))
    return ca


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', required=True); ap.add_argument('--variant', choices=['zgocloud', 'universal'], required=True)
    ap.add_argument('--installer', required=True, type=Path); ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--domain', default=None); ap.add_argument('--camo', default='www.apple.com')
    ap.add_argument('--subst', default='/home/claude/lab/subst'); ap.add_argument('--fail2ban-deb', default='/home/claude/lab/fail2ban_1.1.0-1.upstream1_all.deb')
    ap.add_argument('--cache', default='/home/claude/lab/cache'); ap.add_argument('--keep', action='store_true')
    ap.add_argument('--no-defer', action='store_true', help='run the real owned-SSH-jail setup (no SBOX_SECURITY_DEFERRED)')
    ap.add_argument('--env', action='append', default=[], help='extra KEY=VALUE for the installer')
    ap.add_argument('--pre', default='', help='command run inside the container before the installer (lab staging only)')
    ap.add_argument('--sysctl-shim', action='store_true', help='LAB SHIM for installing an OLD release as an upgrade origin')
    ap.add_argument('args', nargs=argparse.REMAINDER)
    a = ap.parse_args()
    # The ZgoCloud hostname is fixed by its installer; pass it explicitly (kept out of shared code).
    if a.variant == 'zgocloud' and not a.domain: raise SystemExit('--domain is required for the zgocloud variant')
    domain = a.domain or 'vpn.sbox.test'
    a.out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    created = json.loads(sh('python3', CT, 'create', a.name, '--subst', a.subst, '--fail2ban-deb', a.fail2ban_deb, '--cache', a.cache, timeout=300).stdout.strip().splitlines()[-1])
    pid1 = created['pid1']; base = Path('/home/claude/lab/containers') / a.name; root = base / 'root'
    client = subprocess.Popen(['unshare', '--net', '--mount', '--propagation', 'private', 'sleep', 'infinity'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True); time.sleep(0.4)
    (base / 'client.pid').write_text(str(client.pid))
    nl = lambda pid, *x: sh('nsenter', '-t', pid, '-n', 'python3', NL, *x)
    nl(client.pid, 'veth', 'zc0', 'eth0', pid1)
    nl(client.pid, 'addr', 'zc0', CLI_IP + '/24'); nl(client.pid, 'up', 'zc0'); nl(client.pid, 'up', 'lo'); nl(client.pid, 'addr', 'lo', CAMO_IP + '/32')
    nl(pid1, 'addr', 'eth0', CT_IP + '/24'); nl(pid1, 'up', 'eth0'); nl(pid1, 'up', 'lo'); nl(pid1, 'addr', 'lo', HTTP_IP + '/32')
    nl(pid1, 'route', CAMO_IP + '/32', CLI_IP); nl(pid1, 'route-default', CLI_IP)
    ca = pki(base, domain, a.camo)
    lineage(root, domain, ca)
    bundle = root / 'etc/ssl/certs/ca-certificates.crt'
    bundle.write_text(Path('/etc/ssl/certs/ca-certificates.crt').read_text() + (ca / 'ca.crt').read_text())
    (root / 'etc/hosts').write_text('127.0.0.1 localhost\n%s %s\n%s %s\n' % (CT_IP, domain, CAMO_IP, a.camo))
    http = root / 'opt/sbox-lab/http'; http.mkdir(parents=True, exist_ok=True)
    (http / 'probe').write_text('SBOX-LAB-PROTOCOL-OK\n'); (http / 'payload').write_bytes(os.urandom(4 * 1048576))
    camo = subprocess.Popen(['nsenter', '-t', str(client.pid), '-n', 'openssl', 's_server', '-accept', CAMO_IP + ':443', '-cert', ca / 'camo.crt', '-key', ca / 'camo.key', '-tls1_3', '-www', '-quiet'],
                            stdin=subprocess.DEVNULL, stdout=open(base / 'camo.log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    (base / 'camo.pid').write_text(str(camo.pid))
    cexec(a.name, 'systemd-run --unit=lab-http --property=Restart=always python3 -m http.server 18080 --bind %s --directory /opt/sbox-lab/http' % HTTP_IP)
    if a.sysctl_shim:
        shim = root / 'usr/local/sbin/sysctl'; shim.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(a.subst) / 'sysctl-tolerant', shim); shim.chmod(0o755)
    if a.pre: cexec(a.name, a.pre)
    shutil.copy(a.installer, root / 'root' / a.installer.name)
    args = [x for x in a.args if x != '--']
    import shlex
    envs = ([] if a.no_defer else ['SBOX_SECURITY_DEFERRED=true']) + a.env
    for e in envs: assert re.match(r'^[A-Z_][A-Z0-9_]*=', e), e
    envtxt = ' '.join(shlex.quote(e) for e in envs)
    cmd = 'cd /root && %s bash ./%s %s </dev/null > /root/install.log 2>&1; echo $? > /root/install.exit' % (envtxt, a.installer.name, ' '.join(args))
    t0 = time.time()
    # Daemons started by the installer may inherit descriptors; never wait for pipe EOF.
    subprocess.run(['python3', str(CT), 'exec', a.name, '--', 'bash', '-c', cmd], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    elapsed = time.time() - t0
    exit_code = int((root / 'root/install.exit').read_text().strip() or 999)
    log = (root / 'root/install.log').read_text(errors='replace')
    (a.out / ('install-%s.log' % a.name)).write_text(log)
    meta = json.loads((base / 'meta.json').read_text())
    result = {'name': a.name, 'variant': a.variant, 'installer': str(a.installer), 'installer_sha256': sh('sha256sum', a.installer).stdout.split()[0],
              'command': ('%s bash ./%s %s </dev/null' % (envtxt, a.installer.name, ' '.join(args))).strip(), 'exit': exit_code,
              'seconds': round(elapsed, 1), 'lab': meta['note'], 'lab_substitutes': meta['lab_substitutes'], 'fail2ban': meta.get('fail2ban_install', {}).get('source'), 'sysctl_shim': a.sysctl_shim, 'pre': a.pre,
              'network': {'container': CT_IP, 'client_ns_pid': client.pid, 'http_target': HTTP_IP, 'camo_target': CAMO_IP}, 'domain': domain}
    (a.out / ('install-%s.json' % a.name)).write_text(json.dumps(result, indent=1))
    print(json.dumps({k: result[k] for k in ('name', 'exit', 'seconds')}))


if __name__ == '__main__':
    main()
