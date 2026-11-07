#!/usr/bin/env python3
# Managed by sbox-manager
"""Owned SSH Fail2Ban jail and early inet nftables sets; no proxy log guessing."""
import ast,configparser,ipaddress,json,os,re,shutil,stat,subprocess,sys,tempfile
from pathlib import Path
JAIL=Path('/etc/fail2ban/jail.d/sbox-manager.local')
ACTION=Path('/etc/fail2ban/action.d/sbox-manager.conf')
SETTINGS=Path('/etc/sbox-manager/security.json')
OWNER='Managed by sbox-manager'
PROGRAM=Path('/usr/local/lib/sbox-manager-security/action')
TABLE='sbox_guard'
# Exact previously shipped action programs remain compatible on nft versions
# that expose the ownership marker in JSON. This avoids rewriting live guard
# files merely to add/upgrade the panel. nft 1.0.6 needs the new program.
COMPATIBLE_PRIOR_PROGRAMS={'a97850c09e20f3d401a20c6783cc509a429550b1ce708d65b081abdc691dfee0','5df33c3eee61a4d073bea4a28711e69e3638f52b4abddda7f18b9641946a8f44'}
# Package files that may define the distribution's stock [sshd] jail.
STOCK_SSHD_SOURCES={'/etc/fail2ban/jail.conf','/etc/fail2ban/jail.d/defaults-debian.conf'}

class CommandFailure(subprocess.CalledProcessError):
    def __str__(self):
        message=super().__str__()
        if self.stderr:message+='\nstderr:\n'+self.stderr.rstrip()
        elif self.stdout:message+='\nstdout:\n'+self.stdout.rstrip()
        return message

def run(args,check=True,data=None):
    result=subprocess.run(args,input=data,capture_output=True,text=True,check=False,timeout=30,env={**os.environ,'LC_ALL':'C'})
    if check and result.returncode:
        # Keep the subprocess attributes as well as displaying its real error.
        raise CommandFailure(result.returncode,args,output=result.stdout,stderr=result.stderr)
    return result

def owned(path):
    if path.is_symlink() or (path.exists() and (not path.is_file() or OWNER not in path.read_text()[:300])):
        raise RuntimeError('foreign or unsafe path: '+str(path))

def atomic(path,text,mode=0o600):
    owned(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.sbox-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f: f.write(text); f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
        os.replace(name,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)

def nft_state():
    p=run(['nft','-j','list','table','inet',TABLE],False)
    if p.returncode:
        if 'No such file or directory' in p.stderr: return None
        raise RuntimeError('cannot inspect nftables: '+p.stderr.strip())
    data=json.loads(p.stdout)['nftables']; sets={};chains={};rules=[];tables=[]
    for item in data:
        if 'table' in item:tables.append(item['table'])
        if 'set' in item:sets[item['set']['name']]=item['set']
        if 'chain' in item:chains[item['chain']['name']]=item['chain']
        if 'rule' in item:rules.append(item['rule'])
    comment=tables[0].get('comment') if len(tables)==1 else None
    if len(tables)==1 and comment is None:
        # nftables 1.0.6 omits table comments from JSON even when the kernel
        # retains them. Require the exact table-level marker in native output;
        # all set/chain/rule structural checks below still apply unchanged.
        native=run(['nft','list','table','inet',TABLE]).stdout
        if re.match(r'^table inet '+re.escape(TABLE)+r'\s*\{\s*comment "'+re.escape(OWNER)+r'"\s*\n',native):comment=OWNER
    if len(tables)!=1 or comment!=OWNER or set(sets)!={'banned4','banned6'} or set(chains)!={'input'}:
        raise RuntimeError('foreign/drifted nft table; refusing mutation')
    ch=chains['input']
    if ch.get('hook')!='input' or ch.get('prio')!=-20 or ch.get('policy')!='accept' or ch.get('type')!='filter':
        raise RuntimeError('unsafe guard hook priority/policy')
    expected=[]
    for proto,setname in [('ip','banned4'),('ip6','banned6')]:
        expected.append([{'match':{'op':'==','left':{'payload':{'protocol':proto,'field':'saddr'}},'right':'@'+setname}},{'drop':None}])
    if len(rules)!=2 or [r.get('expr') for r in rules]!=expected or any(r.get('chain')!='input' for r in rules):
        raise RuntimeError('foreign/drifted guard rules; refusing mutation')
    if sets['banned4'].get('type')!='ipv4_addr' or sets['banned6'].get('type')!='ipv6_addr':
        raise RuntimeError('invalid guard set type')
    return data

def start(bans=()):
    if nft_state() is None:
        script='''table inet sbox_guard {
 comment "Managed by sbox-manager"
 set banned4 { type ipv4_addr; }
 set banned6 { type ipv6_addr; }
 chain input {
  type filter hook input priority -20; policy accept;
  ip saddr @banned4 drop
  ip6 saddr @banned6 drop
 }
}
'''
        for version,setname in [(4,'banned4'),(6,'banned6')]:
            ips=[str(address(ip)) for ip in bans if address(ip).version==version]
            if ips:script=script.replace('set '+setname+' { type ipv'+str(version)+'_addr; }','set '+setname+' { type ipv'+str(version)+'_addr; elements = { '+', '.join(ips)+' }; }')
        run(['nft','-f','-'],data=script)
    nft_state()

def address(raw): return ipaddress.ip_address(raw)

def reconcile():
    p=run(['fail2ban-client','get','sbox-sshd','banip'])
    bans=[str(address(ip)) for ip in p.stdout.split()]
    start(bans)
    # One transaction restores current bans after a foreign ruleset reload and
    # removes stale entries left by a crashed daemon. Only our jail's sets move.
    script='flush set inet sbox_guard banned4\nflush set inet sbox_guard banned6\n'
    for ip in bans:
        setname='banned4' if address(ip).version==4 else 'banned6'
        script+='add element inet sbox_guard '+setname+' { '+ip+' }\n'
    run(['nft','-f','-'],data=script)


def stop():
    if nft_state() is not None:
        run(['nft','-f','-'],data='flush set inet sbox_guard banned4\nflush set inet sbox_guard banned6\n')

def element(action,raw):
    ip=address(raw);start();family='banned4' if ip.version==4 else 'banned6'
    present=run(['nft','get','element','inet',TABLE,family,'{',str(ip),'}'],False).returncode==0
    if action=='ban' and not present: run(['nft','add','element','inet',TABLE,family,'{',str(ip),'}'])
    if action=='unban' and present: run(['nft','delete','element','inet',TABLE,family,'{',str(ip),'}'])

def normalize_ignore(value):
    try:return str(ipaddress.ip_network(value,strict=False))
    except ValueError:
        # Fail2Ban also supports DNS names in ignoreip; preserve their semantics.
        if re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*',value):return value.lower()
        raise RuntimeError('invalid inherited management exclusion: '+value)

def inherited_ignoreip():
    # Use Fail2Ban's own layered reader (INCLUDES, jail.conf, jail.d/*.conf,
    # jail.local, jail.d/*.local and interpolation), not ConfigParser guesses.
    from fail2ban.client.configreader import ConfigReader
    from fail2ban.helpers import splitwords
    reader=ConfigReader(basedir=str(JAIL.parent.parent))
    if not reader.read('jail'):raise RuntimeError('cannot resolve Fail2Ban jail defaults')
    try:return [normalize_ignore(x) for x in splitwords(reader.get('DEFAULT','ignoreip'))]
    except configparser.NoOptionError:return []

def settings():
    owned(SETTINGS)
    saved=json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}
    cidrs=['127.0.0.0/8','::1/128']+inherited_ignoreip()+list(saved.get('ignoreip',[]))
    current=os.environ.get('SSH_CONNECTION',os.environ.get('SSH_CLIENT','')).split()
    if current:cidrs.append(str(ipaddress.ip_network(current[0],strict=False)))
    for item in os.environ.get('SBOX_MANAGEMENT_CIDRS','').replace(',',' ').split():
        cidrs.append(str(ipaddress.ip_network(item,strict=False)))
    return {'_owner':OWNER,'ignoreip':list(dict.fromkeys(normalize_ignore(x) for x in cidrs))}

def sshd_binary():
    found=shutil.which('sshd')
    if found:return found
    for path in ('/usr/sbin/sshd','/usr/local/sbin/sshd'):
        if os.access(path,os.X_OK):return path
    raise RuntimeError('sshd executable unavailable; SSH configuration was not changed')

def prepare_sshd_runtime():
    # Called ONLY after sshd reports the known missing runtime prerequisite.
    # /run is volatile and owned by the distribution; do not install a unit,
    # tmpfiles rule or cleanup hook, nor alter any existing directory metadata.
    parent_fd=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parent=os.fstat(parent_fd)
        if parent.st_uid!=0 or parent.st_mode&0o022:
            raise RuntimeError('/run must be root-owned and not group/world-writable')
        created=False
        try:os.mkdir('sshd',0o755,dir_fd=parent_fd);created=True
        except FileExistsError:pass # ssh.service may have created it meanwhile
        child_fd=os.open('sshd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
        try:
            if created:
                os.fchown(child_fd,0,0)
                os.fchmod(child_fd,0o755) # manager umask is 077; explicit distro mode
            current=os.fstat(child_fd)
            if not stat.S_ISDIR(current.st_mode) or current.st_uid!=0 or current.st_mode&0o022:
                raise RuntimeError('/run/sshd must be a root-owned directory, not group/world-writable')
        finally:os.close(child_fd)
    finally:os.close(parent_fd)
    return created

def sshd_configuration():
    args=[sshd_binary(),'-T']
    result=run(args,False)
    if result.returncode==0:return result.stdout
    failure=CommandFailure(result.returncode,args,output=result.stdout,stderr=result.stderr)
    # Status 255 alone is ambiguous. Match the actual C-locale OpenSSH error,
    # never create a directory on an invalid configuration/host-key diagnostic.
    missing=re.search(r'^Missing privilege separation directory: (/run/sshd|/var/run/sshd)\r?$',result.stderr,re.M)
    if not missing:raise failure
    if missing[1]=='/var/run/sshd' and Path('/var/run').resolve()!=Path('/run'):
        raise RuntimeError(str(failure)+'\nRefusing to repair a nonstandard /var/run alias')
    try:
        # A file, dangling symlink or inaccessible existing path is not absence.
        try:Path('/run/sshd').lstat()
        except FileNotFoundError:pass
        else:raise RuntimeError('/run/sshd already exists; refusing to replace it or change its permissions')
        created=prepare_sshd_runtime()
    except (OSError,RuntimeError) as error:
        raise RuntimeError(str(failure)+'\nSSH runtime prerequisite could not be prepared safely: '+str(error)) from None
    print('SECURITY NOTICE: '+str(failure),file=sys.stderr)
    print('SECURITY NOTICE: '+('Created /run/sshd as root:root mode 0755' if created else 'Verified /run/sshd created concurrently')+'; retrying sshd -T.',file=sys.stderr)
    # A repaired prerequisite is not a successful SSH validation. Keep all
    # normal checks, report any new error, and never restart SSH or create keys.
    return run(args).stdout

def connection():
    from fail2ban.client.csocket import CSocket
    from fail2ban.client.configreader import ConfigReader
    reader=ConfigReader(basedir=str(JAIL.parent.parent))
    if not reader.read('fail2ban'):raise RuntimeError('cannot resolve Fail2Ban socket configuration')
    try:path=reader.get('Definition','socket')
    except configparser.NoOptionError:path='/var/run/fail2ban/fail2ban.sock'
    return CSocket(path)

def validate_ignoreip(cfg,commands):
    effective=[]
    for command in commands:
        if command[:3]==['set','sbox-sshd','addignoreip']:effective.extend(command[3:])
    if not set(cfg['ignoreip'])<=set(normalize_ignore(x) for x in effective):
        raise RuntimeError('effective sbox-sshd configuration removes management exclusions; inspect later jail overrides')

def verify_live_ignoreip(cfg):
    client=connection()
    try:reply=client.send(['get','sbox-sshd','ignoreip'])
    finally:client.close()
    if reply[0]!=0:raise RuntimeError('cannot verify active management whitelist')
    if not set(cfg['ignoreip'])<=set(normalize_ignore(str(x)) for x in reply[1]):
        raise RuntimeError('active sbox-sshd management whitelist differs from validated configuration')


def program_directory_safe():
    parent=PROGRAM.parent
    if parent.exists() or parent.is_symlink():
        st=parent.lstat()
        if parent.is_symlink() or not parent.is_dir() or st.st_uid!=0 or st.st_mode&0o022:
            raise RuntimeError('unsafe security executable directory: '+str(parent))

def fail2ban_server_starts():
    """Fail before any commit when the packaged Fail2Ban server cannot start.

    Example: Ubuntu 24.04's release-pocket fail2ban 1.0.2-3 imports the removed
    asynchat module on Python 3.12; only the noble-updates package works. Its
    client still parses configuration, so a config test alone misses it."""
    server=shutil.which('fail2ban-server')
    if not server:raise RuntimeError('fail2ban-server missing')
    first=(Path(server).read_text(errors='replace').splitlines() or [''])[0]
    interpreter=first[2:].split() if first.startswith('#!') else ['python3']
    probe=run([*interpreter,'-c','import fail2ban.server.asyncserver, fail2ban.server.server'],False)
    if probe.returncode:
        detail=(probe.stderr.strip().splitlines() or ['unknown error'])[-1][:200]
        raise RuntimeError('the installed Fail2Ban server cannot start ('+detail+'); install the distribution update first: apt-get update && apt-get install --only-upgrade fail2ban. No runtime change was made')

def preflight():
    program_directory_safe()
    owned(JAIL);owned(ACTION);owned(PROGRAM);owned(SETTINGS)
    for executable in ('nft','fail2ban-client'):
        if not shutil.which(executable):raise RuntimeError(executable+' missing; run explicit sbox security setup/repair before protected full operations')
    from fail2ban.client.configreader import ConfigReader
    import systemd.journal
    fail2ban_server_starts()
    run(['nft','-j','list','tables'])
    nft_state()
    # A read can succeed even when the required inet hook is unsupported.
    run(['nft','-c','-f','-'],data='add table inet sbox_capability_check\nadd chain inet sbox_capability_check input { type filter hook input priority -20; policy accept; }\ndelete table inet sbox_capability_check\n')
    return sshd_configuration()

def sshd_jail_sources():
    """Fail2Ban configuration files (other than ours) that define [sshd]."""
    import glob
    files=['/etc/fail2ban/jail.conf',*sorted(glob.glob('/etc/fail2ban/jail.d/*.conf')),'/etc/fail2ban/jail.local',*sorted(glob.glob('/etc/fail2ban/jail.d/*.local'))]
    found=[]
    for name in files:
        if name==str(JAIL):continue
        try:text=Path(name).read_text(errors='replace')
        except OSError:continue
        if re.search(r'^\s*\[sshd\]\s*$',text,re.M):found.append(name)
    return found

def stock_sshd_jail():
    """True when only distribution package files define the [sshd] jail.

    That stock jail watches the same sshd events with a lower retry count and
    bans port 22 only. Racing it means SBOX's all-port guard may never fire and
    an SBOX unban leaves SSH blocked, so SBOX supersedes it. An [sshd] jail the
    operator customized (jail.local or another jail.d file) is left alone."""
    sources=sshd_jail_sources()
    return bool(sources) and set(sources)<=STOCK_SSHD_SOURCES

def setup():
    ssh=preflight()
    owned(JAIL);owned(ACTION);owned(PROGRAM)
    # Derive actual listening sshd ports; -T alone misses systemd socket overrides.
    ports=set(re.findall(r'^port (\d+)$',ssh,re.M))
    listeners=run(['ss','-H','-lntp']).stdout
    live=set()
    for line in listeners.splitlines():
        if re.search(r'\("sshd"|\("systemd"',line):
            endpoint=line.split()[3]; port=endpoint.rsplit(':',1)[-1]
            if port.isdigit(): live.add(port)
    # systemd may own non-SSH sockets too: constrain its ports to ssh.socket.
    socket_text=run(['systemctl','show','ssh.socket','-p','Listen','--value'],False).stdout
    socket_ports=set(re.findall(r':(\d+)\s+\(Stream\)',socket_text))
    ssh_ports={line.split()[3].rsplit(':',1)[-1] for line in listeners.splitlines() if '("sshd"' in line}
    ports=(ssh_ports|socket_ports) or ports
    if not ports:raise RuntimeError('cannot establish SSH port; SSH settings were not changed')
    atomic(PROGRAM,Path(__file__).read_text(),0o700)
    cfg=settings()
    supersede=stock_sshd_jail()
    cfg['supersedes_stock_sshd_jail']=supersede
    atomic(SETTINGS,json.dumps(cfg,indent=2)+'\n')
    atomic(ACTION,f'''# {OWNER}
[Definition]
actionstart = {PROGRAM} start
actioncheck = {PROGRAM} check
# Jail stop removes only this jail's bans; table removal belongs to uninstall.
actionstop = {PROGRAM} stop
actionban = {PROGRAM} ban <ip>
actionunban = {PROGRAM} unban <ip>
''')
    atomic(JAIL,f'''# {OWNER}
[sbox-sshd]
enabled = true
filter = sshd[mode=normal, _daemon="sshd(?:-session)?", journalmatch="_SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session"]
backend = systemd
port = {','.join(sorted(ports,key=int))}
maxretry = 6
findtime = 600
bantime = 600
usedns = no
ignoreip = {' '.join(cfg['ignoreip'])}
action = sbox-manager
'''+('''
# The distribution's stock [sshd] jail watches the same events (lower retry
# count, port 22 only). sbox-sshd supersedes it with all-port early drops.
# Removing this file (sbox security remove/uninstall) restores the stock jail.
[sshd]
enabled = false
''' if supersede else ''))
    run(['fail2ban-client','-t'])
    commands=[ast.literal_eval(line) for line in run(['fail2ban-client','-d']).stdout.splitlines() if line.startswith('[')]
    validate_ignoreip(cfg,commands)
    start()
    run(['systemctl','enable','--now','fail2ban.service'])
    # Wait for the package service socket; no reload of foreign jails.
    import time
    for _ in range(30):
        if run(['fail2ban-client','ping'],False).returncode==0:break
        time.sleep(.2)
    if run(['fail2ban-client','status','sbox-sshd'],False).returncode==0:
        run(['fail2ban-client','reload','sbox-sshd'])
    else:
        # Upstream reload of a named jail cannot create a missing jail. Apply
        # only this jail's parsed upstream configuration over its local socket;
        # a whole-server reload would also mutate third-party jails.
        client=connection()
        try:
            for command in commands:
                if len(command)>1 and command[1]=='sbox-sshd':
                    response=client.send(command)
                    if response[0]!=0:raise RuntimeError('jail configuration failed: '+str(response))
        finally:client.close()
    run(['fail2ban-client','status','sbox-sshd'])
    if supersede and run(['fail2ban-client','status','sshd'],False).returncode==0:
        # Stopping the superseded stock jail lifts only its own duplicate bans.
        run(['fail2ban-client','stop','sshd'])
    verify_live_ignoreip(cfg)
    reconcile()
    print('SSH jail active; early IPv4/IPv6 all-port drops protect SSH and VPN, including NAT redirects. Proxy auth jails are disabled: no proven per-protocol event corpus.')

def healthy():
    program_directory_safe()
    owned(JAIL);owned(ACTION);owned(PROGRAM)
    if not JAIL.is_file() or not ACTION.is_file() or not PROGRAM.is_file() or not os.access(PROGRAM,os.X_OK) or nft_state() is None:raise RuntimeError('security setup pending: run sbox security setup')
    for path,mode in [(JAIL,0o600),(ACTION,0o600),(PROGRAM,0o700)]:
        st=path.stat()
        if st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o777!=mode:raise RuntimeError('insecure security file metadata: '+str(path))
    if PROGRAM.read_bytes()!=Path(__file__).read_bytes():
        import hashlib
        previous=hashlib.sha256(PROGRAM.read_bytes()).hexdigest()
        native_json=json.loads(run(['nft','-j','list','table','inet',TABLE]).stdout)['nftables']
        marker=any(x.get('table',{}).get('comment')==OWNER for x in native_json)
        if previous not in COMPATIBLE_PRIOR_PROGRAMS or not marker:raise RuntimeError('security helper update pending: run sbox security setup')
    run(['fail2ban-client','status','sbox-sshd'])

def remove():
    paths=(JAIL,ACTION,PROGRAM)
    for path in paths:owned(path)
    configured=any(path.exists() for path in paths)
    # An untouched legacy installation has no owned security objects. Missing
    # optional tools are a no-op there; never guess that a configured guard is gone.
    if not shutil.which('nft'):
        if configured:raise RuntimeError('nft missing; owned guard/files retained for explicit security repair')
        return
    table=nft_state()
    if JAIL.exists():
        if not shutil.which('fail2ban-client'):
            raise RuntimeError('fail2ban-client missing; owned guard/files retained for repair')
        status=run(['fail2ban-client','status','sbox-sshd'],False)
        if status.returncode==0:run(['fail2ban-client','stop','sbox-sshd'])
        elif run(['fail2ban-client','ping'],False).returncode!=0:
            raise RuntimeError('Fail2Ban unavailable; guard/files retained rather than bypassing protection')
    superseded=JAIL.exists() and re.search(r'^\[sshd\]$',JAIL.read_text(),re.M) is not None
    if table is not None:run(['nft','delete','table','inet',TABLE])
    for path in paths:
        if path.exists():path.unlink()
    if superseded and run(['fail2ban-client','ping'],False).returncode==0:
        # Restore the distribution's stock SSH protection that we superseded.
        run(['fail2ban-client','reload'],False)
    try:PROGRAM.parent.rmdir()
    except OSError:pass
    # Package, database, foreign jails and bans are deliberately retained.

def main():
    if os.geteuid()!=0:raise RuntimeError('root is required')
    args=sys.argv[1:];action=args[0] if args else 'status'
    if action=='preflight':preflight()
    elif action=='setup':setup()
    elif action=='start':start()
    elif action=='stop':stop()
    elif action=='reconcile':reconcile()
    elif action=='check':
        if nft_state() is None:raise RuntimeError('guard table missing')
    elif action=='status':healthy();print(run(['fail2ban-client','status','sbox-sshd']).stdout)
    elif action=='bans':healthy();print(run(['fail2ban-client','get','sbox-sshd','banip']).stdout)
    elif action in ('ban','unban') and len(args)==2: element(action,args[1])
    elif action=='remove':remove()
    else:raise RuntimeError('invalid security action')
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:
        print('SECURITY ERROR: '+str(e),file=sys.stderr);sys.exit(1)
