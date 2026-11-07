import secrets
"""Root lifecycle helper. Panel-only actions never operate on sing-box/SSH."""
import grp
import hashlib
import json
import os
import ipaddress
from pathlib import Path
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import ssl
import tempfile
from common import Problem, VERSION, atomic_json, require

ROOT = Path(__file__).resolve().parents[1]
LIB = Path('/usr/local/lib/sbox-webui')
ETC = Path('/etc/sbox-webui')
DATA = Path('/var/lib/sbox-webui')
UNITS = Path('/etc/systemd/system')

def wait_listening(listen, port, seconds=30):
    """True once the panel accepts TCP connections (a wildcard listen is probed on loopback)."""
    host = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(listen, listen)
    deadline = time.monotonic() + seconds
    while True:
        try:
            with socket.create_connection((host, port), timeout=1): return True
        except OSError:
            if time.monotonic() >= deadline: return False
            time.sleep(0.2)


def run(argv):
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL)

def secure_dir(path, mode=0o755, owners=(0,)):
    require(not path.is_symlink() and (not path.exists() or path.is_dir()), 'Unsafe panel path')
    for parent in path.parents:require(not parent.is_symlink(),'Symlink ancestor in panel path')
    require(not path.exists() or path.stat().st_uid in owners,'Panel path belongs to another account')
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    path.chmod(mode)

def verify(root):
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name != 'MANIFEST.json'}
    require(actual == set(manifest), 'Panel manifest inventory mismatch')
    for name, sha in manifest.items():
        p = root / name
        require(not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest() == sha, 'Panel component checksum mismatch')
    return hashlib.sha256((root / 'MANIFEST.json').read_bytes()).hexdigest()[:24]

def unit(name, value):
    p = UNITS / name
    require(not p.is_symlink(), 'Unsafe unit path')
    p.write_text(value); p.chmod(0o644)

def bootstrap_admin(build, action):
    # UI-owned files are parsed/written under the panel UID, never under root.
    output = subprocess.check_output(['/usr/sbin/runuser','-u','sbox-webui','--','/usr/bin/python3','-B',str(build/'backend/admin.py'),action], text=True)
    secret = json.loads(output)['password']
    if secret:
        path=ETC/'bootstrap-admin.txt'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write('Username: admin\nPassword: '+secret+'\nChange this password at first browser login.\n');stream.flush();os.fsync(stream.fileno())

def certificate(cfg, state):
    local_only=not state['certificate'].get('source_fullchain') and state['certificate']['mode']=='none'
    if local_only:
        require(cfg['listen'] in ('127.0.0.1','::1'), 'Public HTTPS requires a trusted domain certificate; configure sbox certificate first. The VPN remains installed. Loopback is available only by explicit operator setting.')
        require(cfg['variant']=='universal','ZgoCloud requires its managed trusted certificate')
        # Preserve certificate-free REALITY-only universal installs. The new
        # admin certificate is local to an SSH tunnel and never used by VPN.
        local=ETC/'local-tunnel';secure_dir(local,0o700)
        local_cert,local_key=local/'cert.pem',local/'key.pem'
        valid=local_cert.is_file() and local_key.is_file() and subprocess.run(['/usr/bin/openssl','x509','-in',str(local_cert),'-noout','-checkend','604800'],capture_output=True).returncode==0
        if not valid:
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','365','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(local_key),'-out',str(local_cert)],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            local_key.chmod(0o600)
        cfg.update(origin='https://localhost:'+str(cfg['port']),panel_certificate_mode='local TLS over SSH tunnel')
        state={**state,'domain':'localhost','certificate':{**state['certificate'],'source_fullchain':str(local_cert),'source_key':str(local_key)}}
    cert, key = Path(state['certificate']['source_fullchain']), Path(state['certificate']['source_key'])
    require(cert.is_file() and key.is_file(), 'Panel needs the existing VPN certificate/key. Configure a certificate first.')
    matched = subprocess.run(['/usr/bin/openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', state['domain']], capture_output=True, text=True, env={**os.environ, 'LC_ALL': 'C'})
    require(matched.returncode == 0 and matched.stdout.rstrip().endswith(' does match certificate'), 'Panel certificate hostname mismatch')
    require(subprocess.run(['/usr/bin/openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'], capture_output=True).returncode == 0, 'Panel certificate expired')
    require(subprocess.run(['/usr/bin/openssl','pkey','-in',str(key),'-passin','pass:','-noout'],stdin=subprocess.DEVNULL,capture_output=True).returncode==0,'Panel private key is invalid or encrypted')
    if not ipaddress.ip_address(cfg['listen']).is_loopback:
        trusted=subprocess.run(['/usr/bin/openssl','verify','-purpose','sslserver','-verify_hostname',state['domain'],'-untrusted',str(cert),str(cert)],capture_output=True,stdin=subprocess.DEVNULL)
        require(trusted.returncode == 0, 'Public WebUI requires a trusted domain certificate chain; configure a valid certificate before enabling public HTTPS.')
    check=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);check.load_cert_chain(cert,key)
    tls = ETC / 'tls';secure_dir(tls, 0o750)
    gid = pwd.getpwnam('sbox-webui').pw_gid
    os.chown(tls, 0, gid)
    # A single generation symlink publishes a complete pair.
    gen = tls / ('pair-' + hashlib.sha256(cert.read_bytes() + key.read_bytes()).hexdigest()[:24])
    if not gen.exists():
        staged=Path(tempfile.mkdtemp(prefix='.pair-',dir=tls));staged.chmod(0o750);os.chown(staged,0,gid)
        for src, name, mode in ((cert, 'cert.pem', 0o644), (key, 'key.pem', 0o640)):
            dest = staged / name; shutil.copyfile(src, dest); dest.chmod(mode); os.chown(dest, 0, gid)
            with dest.open('rb') as stream:os.fsync(stream.fileno())
        os.replace(staged,gen)
    require((gen/'cert.pem').read_bytes()==cert.read_bytes() and (gen/'key.pem').read_bytes()==key.read_bytes(),'Panel certificate generation is inconsistent')
    gen.chmod(0o750)
    temp = tls / '.next'; temp.unlink(missing_ok=True); temp.symlink_to(gen.name)
    os.replace(temp, tls / 'live')
    cfg.update(certificate=str(tls / 'live/cert.pem'), key=str(tls / 'live/key.pem'),origin='https://'+state['domain']+':'+str(cfg['port']))
    if not local_only:cfg.pop('panel_certificate_mode',None)

def write_units():
    unit('sbox-webui-firewall.service', '''[Unit]
Description=SBOX public HTTPS panel owned firewall rule
After=network-pre.target ufw.service sbox-manager-firewall.service
Before=sbox-webui.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-webui/firewall.py apply
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
    # Drift self-healing: a foreign UFW reload/firewall tool can drop the panel rule while the
    # panel keeps listening. Check every two minutes; re-apply only the owned rule on drift.
    unit('sbox-webui-firewall-repair.service', '''[Unit]
Description=Restore the SBOX panel firewall rule after drift
After=sbox-webui-firewall.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-webui/firewall.py repair
''')
    unit('sbox-webui-firewall-repair.timer', '''[Unit]
Description=Check the SBOX panel firewall rule every two minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
''')
    unit('sbox-webui-control.service', '''[Unit]
Description=SBOX WebUI restricted manager bridge
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-webui/current/privileged-bridge/bridge.py
Restart=on-failure
RestartSec=3
RuntimeDirectory=sbox-webui-control
RuntimeDirectoryMode=0750
Group=sbox-webui
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
MemoryMax=256M
TasksMax=64
CPUQuota=50%
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
[Install]
WantedBy=multi-user.target
''')
    unit('sbox-webui.service', '''[Unit]
Description=SBOX HTTPS administration
After=network.target sbox-webui-control.service sbox-webui-firewall.service
Wants=sbox-webui-control.service
Requires=sbox-webui-firewall.service
[Service]
Type=simple
User=sbox-webui
Group=sbox-webui
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-webui/current/backend/server.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/sbox-webui
CapabilityBoundingSet=
MemoryMax=160M
TasksMax=40
CPUQuota=40%
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
''')
    # Certificate-only refresh publishes a panel copy then reloads only the panel.
    unit('sbox-webui-certificate.service', '''[Unit]
Description=Refresh SBOX panel certificate copy
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-webui/current/backend/install.py refresh-certificate
''')
    unit('sbox-webui-certificate.timer', '''[Unit]
Description=Check SBOX panel certificate every five minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
''')

def main():
    require(os.geteuid() == 0, 'Root required', 403)
    action = sys.argv[1]
    variant = sys.argv[2] if len(sys.argv) > 2 else None
    if action in ('install', 'upgrade'):
        require(variant in ('universal', 'zgocloud'), 'Unknown variant')
        build = verify(ROOT)
        for p in (LIB, ETC): secure_dir(p)
        try:allowed_uid=pwd.getpwnam('sbox-webui').pw_uid
        except KeyError:allowed_uid=0
        secure_dir(DATA, 0o700, (0,allowed_uid))
        try: user = pwd.getpwnam('sbox-webui')
        except KeyError:
            run(['/usr/sbin/useradd', '--system', '--home-dir', str(DATA), '--shell', '/usr/sbin/nologin', 'sbox-webui'])
            user = pwd.getpwnam('sbox-webui')
        os.chown(DATA, user.pw_uid, user.pw_gid)
        target = LIB / ('release-' + build)
        require(not target.is_symlink(),'Unsafe panel release link')
        if target.exists(): verify(target)
        else:
            stage = LIB / ('.stage-' + build)
            if stage.exists(): shutil.rmtree(stage)
            shutil.copytree(ROOT, stage, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            verify(stage)
            stage.chmod(0o755);os.chown(stage,0,0)
            for p in stage.rglob('*'):
                p.chmod(0o755 if p.is_dir() else 0o644);os.chown(p, 0, 0)
            os.replace(stage, target)
        state = json.loads(Path('/etc/sbox-manager/state.json').read_text())
        settings = ETC / 'settings.json'
        if settings.exists():
            cfg = json.loads(settings.read_text());require(cfg['variant'] == variant, 'Wrong variant for this installation')
        else:
            port = int(os.environ.get('SBOX_WEBUI_PORT', '9443'))
            require(1024 <= port <= 65535 and port not in {p['port'] for n,p in state['protocols'].items() if n not in ('hy2','tuic') and p['enabled']}, 'Panel HTTPS port is invalid or overlaps VPN')
            from network_policy import listen_for
            mode=state.get('server',{}).get('panel_family','preserve')
            listen = os.environ.get('SBOX_WEBUI_LISTEN', listen_for(state['server'],mode) or '0.0.0.0')
            import ipaddress
            address=ipaddress.ip_address(listen)
            require(not address.is_multicast and not getattr(address,'ipv4_mapped',None), 'Panel listen must be a native IPv4/IPv6 address')
            with socket.socket(socket.AF_INET6 if ':' in listen else socket.AF_INET) as probe: probe.bind((listen, port))
            cfg = dict(schema=1, variant=variant, port=port, listen=listen, origin='https://' + state['domain'] + ':' + str(port), database=str(DATA/'panel.db'), socket='/run/sbox-webui-control/control.sock')
        cfg.setdefault('monitor_key',secrets.token_urlsafe(48))
        certificate(cfg, state)
        atomic_json(settings, cfg, 0o640);os.chown(settings,0,user.pw_gid)
        bootstrap_admin(target,'init')
        current = LIB / 'current'
        old = os.readlink(current) if current.is_symlink() else None
        if old and old != target.name:
            nxt=LIB/'.previous';nxt.unlink(missing_ok=True);nxt.symlink_to(old);os.replace(nxt,LIB/'previous')
        nxt=LIB/'.current';nxt.unlink(missing_ok=True);nxt.symlink_to(target.name);os.replace(nxt,current)
        shutil.copyfile(ROOT/'backend/firewall.py',LIB/'firewall.py');(LIB/'firewall.py').chmod(0o644);os.chown(LIB/'firewall.py',0,0)
        write_units()
        run(['/usr/sbin/runuser','-u','sbox-webui','--','test','-r',str(current/'backend/server.py')])
        run(['/usr/sbin/runuser','-u','sbox-webui','--','test','-r',str(settings)])
        run(['/usr/sbin/runuser','-u','sbox-webui','--','test','-r',cfg['key']])
        run(['/usr/bin/systemctl','daemon-reload'])
        run(['/usr/bin/systemctl','enable','sbox-webui-firewall.service','sbox-webui-control.service','sbox-webui.service','sbox-webui-certificate.timer','sbox-webui-firewall-repair.timer'])
        try:
            run(['/usr/bin/systemctl','reset-failed','sbox-webui.service','sbox-webui-control.service','sbox-webui-firewall.service'])
            run(['/usr/bin/systemctl','stop','sbox-webui.service'])
            run(['/usr/bin/systemctl','restart','sbox-webui-firewall.service'])
            run(['/usr/bin/systemctl','restart','sbox-webui-control.service','sbox-webui.service'])
            run(['/usr/bin/systemctl','start','sbox-webui-certificate.timer','sbox-webui-firewall-repair.timer'])
            require(wait_listening(cfg['listen'], cfg['port'], 30), 'Panel did not accept connections within 30 seconds; see journalctl -u sbox-webui', 503)
            run(['/usr/bin/systemctl','is-active','--quiet','sbox-webui-control.service','sbox-webui.service'])
            run(['/usr/bin/python3','-B',str(current/'backend/webui_security.py'),'setup'])
        except Exception:
            if old:
                nxt=LIB/'.current';nxt.unlink(missing_ok=True);nxt.symlink_to(old);os.replace(nxt,current)
                run(['/usr/bin/systemctl','restart','sbox-webui-control.service','sbox-webui.service'])
            raise
        print('Panel ready: ' + cfg['origin'])
        from firewall import guidance
        print(guidance(cfg))
    elif action == 'reset-admin':
        bootstrap_admin(LIB/'current','reset')
    elif action == 'recover-db':
        run(['/usr/bin/systemctl','stop','sbox-webui.service'])
        bootstrap_admin(LIB/'current','recover')
        run(['/usr/bin/systemctl','start','sbox-webui.service'])
        print('UI migration snapshot restored. All sessions/API/subscription tokens revoked; retrieve the root-only initial credential. VPN state was not changed.')
    elif action == 'doctor':
        cfg=json.loads((ETC/'settings.json').read_text());verify(LIB/'current')
        run(['/usr/bin/python3','-B',str(LIB/'current/backend/webui_security.py'),'status'])
        require(cfg['schema']==1,'Unsupported settings schema')
        run(['/usr/sbin/runuser','-u','sbox-webui','--','/usr/bin/python3','-B','-c','import sqlite3; d=sqlite3.connect("file:/var/lib/sbox-webui/panel.db?mode=ro",uri=True); assert d.execute("PRAGMA quick_check").fetchone()[0]=="ok"'])
        require((ETC/'bootstrap-admin.txt').stat().st_mode & 0o777 == 0o600, 'Unsafe bootstrap credential permissions')
        print('Panel assets/database/settings/credential permissions validated. Public access and provider firewall need an external check.')
    elif action == 'refresh-certificate':
        settings=ETC/'settings.json';cfg=json.loads(settings.read_text());state=json.loads(Path('/etc/sbox-manager/state.json').read_text())
        previous=dict(cfg);old=(ETC/'tls/live/cert.pem').read_bytes()
        certificate(cfg,state)
        if cfg!=previous:
            atomic_json(settings,cfg,0o640);os.chown(settings,0,pwd.getpwnam('sbox-webui').pw_gid)
        if cfg!=previous or old!=(ETC/'tls/live/cert.pem').read_bytes():run(['/usr/bin/systemctl','try-restart','sbox-webui.service'])
    elif action == 'rollback':
        prev=LIB/'previous';require(prev.is_symlink(), 'No previous panel release')
        verify(prev)
        cur=os.readlink(LIB/'current');old=os.readlink(prev)
        tmp=LIB/'.rollback';tmp.unlink(missing_ok=True);tmp.symlink_to(old);os.replace(tmp,LIB/'current')
        tmp.symlink_to(cur);os.replace(tmp,prev)
        run(['/usr/bin/systemctl','reset-failed','sbox-webui-control.service','sbox-webui.service'])
        run(['/usr/bin/systemctl','restart','sbox-webui-control.service','sbox-webui.service'])
        cfg=json.loads((ETC/'settings.json').read_text())
        require(wait_listening(cfg['listen'],cfg['port'],30), 'Rolled-back panel did not accept HTTPS connections within 30 seconds; inspect the panel journal.',503)
    elif action == 'uninstall':
        protection=LIB/'current/backend/webui_security.py'
        if protection.is_file():run(['/usr/bin/python3','-B',str(protection),'remove'])
        run(['/usr/bin/python3','-B',str(LIB/'firewall.py'),'remove'])
        run(['/usr/bin/systemctl','disable','--now','sbox-webui-firewall.service'])
        run(['/usr/bin/systemctl','disable','--now','sbox-webui.service','sbox-webui-control.service','sbox-webui-certificate.timer','sbox-webui-firewall-repair.timer'])
        for name in ('sbox-webui.service','sbox-webui-firewall.service','sbox-webui-control.service','sbox-webui-certificate.service','sbox-webui-certificate.timer','sbox-webui-firewall-repair.service','sbox-webui-firewall-repair.timer'):(UNITS/name).unlink(missing_ok=True)
        run(['/usr/bin/systemctl','daemon-reload'])
        # Keep root recovery credentials and UI database, including revocation state.
        print('Panel stopped/removed from systemd. VPN remains installed. Panel data retained for recovery/reinstall.')
    else:raise Problem(400,'Unknown panel lifecycle action')

if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print('Panel lifecycle failed: '+str(exc),file=sys.stderr);sys.exit(1)
