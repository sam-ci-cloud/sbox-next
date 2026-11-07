"""Narrow root bridge. Unix peer UID + restrictive socket; fixed argv only."""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from common import Problem, capabilities, redact, require
from accounting import Engine
from portal_auth import Portal
from usage_history import history
from plan_input import preview as plan_preview
from quota_models import quota_plan
from authorization import authorize
import webui_security
from network_policy import endpoint_options

MAX_OUTPUT = 786432  # bytes of manager stdout returned to the panel


class Control:
    def __init__(self, base='/etc/sbox-manager', manager='/usr/local/bin/sbox', variant='universal'):
        self.base, self.manager, self.variant = Path(base), manager, variant
        self.cache, self.mutex = {}, threading.Lock()
        self.previous_cpu = None
        self.last_check = None
        self.guard_lock = threading.Lock()

    def capability_report(self):
        state=self.state();cfg=state.get('accounting',{});verified=False
        if cfg.get('enabled'):
            try:
                binary=Path('/usr/local/lib/sbox-manager/sing-box');key=(binary.stat().st_ino,binary.stat().st_mtime_ns,binary.stat().st_size)
                if not hasattr(self,'cap_binary') or self.cap_binary[0]!=key:self.cap_binary=(key,hashlib.sha256(binary.read_bytes()).hexdigest())
                verified=self.cap_binary[1]==cfg.get('core_sha256')
            except OSError:pass
        return capabilities(state['sing_box']['version'],self.variant,cfg if verified else None,self.accounting().health() if cfg.get('enabled') else None)

    def accounting(self):
        if not hasattr(self,'meter'):self.meter=Engine(str(self.base))
        return self.meter

    def portal_change(self,request):
        prepared=json.loads(self.run([self.manager,'_webui-control','prepare'],request,180))
        return json.loads(self.run([self.manager,'_webui-control','commit'],{'token':prepared['token']},180))

    def accounting_summary(self):
        engine=self.accounting();health=engine.health();state=self.state();rows=[]
        users=state.get('managed_users',[]);views=engine.store().views(users,health)
        fields={'used_bytes','upload_bytes','download_bytes','quota_bytes','remaining_bytes','unlimited','status','freshness','sampled_at','next_reset','expires_at','collection_gap','period_start','reset_seq'}
        for user,view in zip(users,views):
            rows.append({'id':user['id'],'name':user['name'],'usage':{k:v for k,v in view.items() if k in fields},'plan':user.get('quota'),
                         'portal':{k:v for k,v in user.get('portal',{}).items() if k in ('username','enabled','reset')}})
        legacy={'id':'legacy'}
        return {'enabled':bool(state.get('accounting',{}).get('enabled')),'health':health,'users':rows,'legacy':engine.store().view(legacy,health),
                'legacy_note':'One protected shared identity aggregate. Cannot attribute its shared credential to individual people.',
                'policy':{k:state.get('accounting',{}).get(k) for k in ('poll_seconds','failure_policy')},'events':engine.store().events()}

    def state(self):
        return json.loads((self.base / 'state.json').read_text())

    def run(self, args, data=None, timeout=60, allow_failure=False):
        # Subscription refresh is a read: let a short backup/configuration
        # operation finish rather than making the client lose its new provider.
        # Writes still fail fast and are never automatically replayed.
        lock_wait = '15' if args == [self.manager, '_webui-control', 'export'] else '1'
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin', 'LANG': 'C.UTF-8', 'SBOX_LOCK_WAIT_SECONDS': lock_wait, 'SBOX_ASSUME_DEFAULTS': 'true'}
        p = subprocess.run(args, input=json.dumps(data) if data is not None else '', text=True, capture_output=True, timeout=timeout, env=env)
        # Never return raw exceptions/command output to the public server.
        if p.returncode and not allow_failure:
            message = self.scrub((p.stderr or p.stdout)[-6000:])
            raise Problem(409 if 'lock' in message or 'changed' in message else 422, message or 'Manager action failed')
        # Fail closed: a cut-off export (e.g. a complete profile with offline rule sets) would be served
        # as a corrupt file. The bound stays below the server's 1 MiB control-response limit.
        require(len(p.stdout.encode()) <= MAX_OUTPUT, 'Manager output exceeded the bounded size', 507)
        return {'stdout':p.stdout,'exit_code':p.returncode} if allow_failure else p.stdout

    def scrub(self, value):
        try:
            state = self.state()
            for p in state['protocols'].values():
                for k, v in p.items():
                    if k in ('password', 'uuid', 'private_key', 'short_id') and isinstance(v, str): value = value.replace(v, '[redacted]')
            for u in state.get('managed_users', []):
                for p in u['protocols'].values():
                    for v in p.values(): value = value.replace(v, '[redacted]')
        except (OSError, ValueError, KeyError): pass
        return redact(value)

    def cached(self, key, fn, seconds=5):
        with self.mutex:
            old = self.cache.get(key)
            if old and old[0] + seconds > time.time(): return old[1]
            result = fn()
            self.cache[key] = (time.time(), result)
            return result

    def overview(self):
        def collect():
            s = self.state()
            service = self.run(['/usr/bin/systemctl', 'show', 'sing-box.service', '--property=ActiveState,SubState,MainPID,ExecMainStartTimestamp,ActiveEnterTimestampMonotonic,MemoryCurrent,CPUUsageNSec,NRestarts'])
            service = dict(l.split('=', 1) for l in service.splitlines() if '=' in l)
            core_rss=None
            try:
                for line in Path('/proc/'+str(int(service.get('MainPID','0')))+'/status').read_text().splitlines():
                    if line.startswith('VmRSS:'):core_rss=int(line.split()[1])*1024
            except (OSError,ValueError):pass
            stat = os.statvfs(self.base)
            mem = dict((l.split(':')[0], int(l.split()[1]) * 1024) for l in Path('/proc/meminfo').read_text().splitlines())
            net = {}
            for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
                iface, fields = line.split(':'); fields = fields.split()
                if iface.strip() != 'lo': net[iface.strip()] = {'rx': int(fields[0]), 'tx': int(fields[8])}
            cpu = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
            actual_version=None
            try:
                version_output=self.run(['/usr/local/lib/sbox-manager/sing-box','version'])
                match=re.search(r'^sing-box version (\S+)',version_output,re.M)
                actual_version=match[1] if match else None
            except Problem:pass
            cpu_percent = None
            if self.previous_cpu:
                total=sum(cpu[:8])-sum(self.previous_cpu[:8]);idle=cpu[3]+cpu[4]-self.previous_cpu[3]-self.previous_cpu[4]
                if total>0:cpu_percent=round(100*(total-idle)/total,2)
            self.previous_cpu=cpu
            errors=self.run(['/usr/bin/journalctl','--no-pager','-u','sing-box.service','--since','1 hour ago','-p','err','-n','200','-o','json'])
            timers={}
            for unit in ('certbot.timer','sbox-webui-certificate.timer'):
                try:
                    info=self.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,NextElapseUSecRealtime'])
                    timers[unit]=dict(l.split('=',1) for l in info.splitlines() if '=' in l)
                except Problem:timers[unit]={'ActiveState':'unavailable','reason':'Unit is not installed or could not be queried'}
            io={}
            for line in Path('/proc/diskstats').read_text().splitlines():
                f=line.split()
                if len(f)>=14 and not f[2].startswith(('loop','ram','dm-')):
                    if not (Path('/sys/class/block')/f[2]/'partition').exists():io[f[2]]={'read_bytes':int(f[5])*512,'write_bytes':int(f[9])*512,'busy_ms':int(f[12])}
            try:load=[float(x) for x in Path('/proc/loadavg').read_text().split()[:3]]
            except (OSError,ValueError):load=None
            pending=any(p.exists() or p.is_symlink() for p in (Path('/var/lib/sbox-manager/transaction.json'),Path('/var/backups/sbox-manager/.policy-journal.json')))
            try:boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            except OSError:boot_id=None
            try:fingerprint=hashlib.sha256((self.base/'state.json').read_bytes()).hexdigest()[:16]
            except OSError:fingerprint=None
            return dict(deployment_family={'mode':s.get('server',{}).get('mode','preserve'),'listen':s.get('server',{}).get('listen'),'ipv4_saved':bool(s.get('server',{}).get('ipv4')),'ipv6_saved':bool(s.get('server',{}).get('ipv6')),'policies':s.get('server',{}).get('policies'),'scope':s.get('server',{}).get('scope'),'fallback_delay_ms':s.get('server',{}).get('fallback_delay_ms')},sampled_at=time.time(), source='Linux procfs/statvfs + systemd; host network counters include all services', service=service,
                        load_average=load,cpu_count=os.cpu_count(),pending_transaction=pending,boot_id=boot_id,state_fingerprint=fingerprint,
                        core_version=actual_version,expected_core_version=s['sing_box']['version'], uptime_seconds=float(Path('/proc/uptime').read_text().split()[0]), cpu_ticks=cpu,cpu_percent=cpu_percent,
                        recent_errors={'count':sum(1 for l in errors.splitlines() if l.lstrip().startswith('{')),'window':'last hour, capped at 200 journal entries','source':'journalctl priority err'},renewal_timers=timers,last_validated_check=self.last_check,
                        memory_total_bytes=mem['MemTotal'], memory_available_bytes=mem['MemAvailable'],swap_total_bytes=mem.get('SwapTotal'),swap_free_bytes=mem.get('SwapFree'),disk_io=io,
                        core_rss_bytes=core_rss,disk_used_bytes=(stat.f_blocks-stat.f_bfree)*stat.f_frsize,
                        disk_total_bytes=stat.f_blocks * stat.f_frsize, disk_available_bytes=stat.f_bavail * stat.f_frsize, network=net,
                        external_reachability='unavailable: requires a client/ISP packet check', capabilities=self.capability_report())
        return self.cached('overview', collect)

    def inbounds(self):
        state = self.state()
        config = json.loads((self.base / 'config.json').read_text())
        result = []
        names={'user-'+u['id']+suffix:u['name'] for u in state.get('managed_users',[]) for suffix in ['',*('@'+p for p in u['protocols'])]}
        sockets=set()
        for row in self.run(['/usr/bin/ss','-H','-lntu']).splitlines():
            fields=row.split()
            if len(fields)>4:
                try:sockets.add((fields[0],int(fields[4].rsplit(':',1)[1])))
                except (ValueError,IndexError):pass
        for item in config['inbounds']:
            result.append(dict(id=item['tag'], type=item['type'], listen=item['listen'], port=item['listen_port'],
                               network='udp' if item['type'] in ('hysteria2', 'tuic') else 'tcp',
                               tls=bool(item.get('tls', {}).get('enabled')), transport=item.get('transport', {}).get('type', 'native'),
                               user_count=len(item.get('users', [])), user_names=[names.get(u.get('name'),'Original shared identity') for u in item.get('users',[])],protected=self.variant == 'zgocloud',
                               listening=(('udp' if item['type'] in ('hysteria2','tuic') else 'tcp'),item['listen_port']) in sockets))
        aliases = []
        for name in ('hy2', 'tuic'):
            p = state['protocols'][name]
            if p.get('udp_range') and p['enabled']:
                aliases.append(dict(kind='NAT alias', protocol=name, range=p['udp_range'], target_port=p['port'], network='udp'))
        return dict(inbounds=result, aliases=aliases, source='Live manager configuration + ss local socket inventory',sampled_at=time.time(), protocols={p: {'enabled': v['enabled'], 'port': v['port'], **({'multiplex': v.get('multiplex') is True} if p == 'vmess' else {})} for p, v in state['protocols'].items()})

    def users(self):
        s = self.state()
        rows = [dict(id='legacy', name='Legacy shared identity' if self.variant == 'zgocloud' else 'Original installer identity', protected=True, enabled=True, tags=[], protocols=[p for p in s['protocols'] if s['protocols'][p]['enabled']])]
        rows.extend({k: (list(u['protocols']) if k == 'protocols' else u[k]) for k in ('id', 'name', 'enabled', 'tags', 'protocols')} for u in s.get('managed_users', []))
        return rows

    PINNED_CORE = Path('/usr/local/lib/sbox-accounting/core-candidate')
    PINNED_MANIFEST = Path('/usr/local/lib/sbox-accounting/current/core_manifest.json')

    def pinned_core_preview(self, version):
        # Describe the verified pinned core retained from the installed SBOX
        # package. No network request is made and no external metadata is read.
        help_text = ('Choose latest/stable, beta or an exact version. Accounting source builds are verified and tested; incompatible changes keep the current core.')
        try:
            manifest = json.loads(self.PINNED_MANIFEST.read_text())
            expected = str(manifest['sha256'])
            pinned = str(manifest['version'])
        except (OSError, ValueError, KeyError, TypeError):
            raise Problem(409, 'No verified pinned core is recorded on this server. ' + help_text)
        require(re.fullmatch(r'[0-9a-f]{64}', expected) and re.fullmatch(r'\d+\.\d+\.\d+', pinned), 'Invalid pinned core manifest', 409)
        if version != pinned:
            from core_resolver import preview
            try: return preview(version)
            except (ValueError, OSError) as exc: raise Problem(409, str(exc)) from None
        path = self.PINNED_CORE
        require(path.is_file() and not path.is_symlink(), 'The verified pinned core file is missing. ' + help_text, 409)
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1048576), b''):
                digest.update(block)
        require(digest.hexdigest() == expected, 'The retained pinned core does not match its manifest. ' + help_text, 409)
        return {'version': pinned, 'sha256': expected, 'published_at': None, 'changelog': '',
                'source': 'Verified pinned core from the installed SBOX package (local file; no download)',
                'warning': 'Reinstalls the verified pinned core and restarts the VPN after the manager checks the configuration. ' + help_text}

    def certificate(self):
        s = self.state()
        cp = s['certificate'].get('source_fullchain')
        result = {'domain': s['domain'], 'mode': s['certificate']['mode'], 'expires_at': None, 'source': 'openssl x509; not a public-chain reachability proof', 'sampled_at': time.time()}
        if cp and Path(cp).is_file():
            out = self.run(['/usr/bin/openssl', 'x509', '-in', cp, '-noout', '-enddate', '-startdate', '-issuer'])
            for line in out.splitlines():
                k, _, v = line.partition('=')
                if k == 'notAfter': result['expires_at'] = ssl.cert_time_to_seconds(v)
                elif k == 'notBefore': result['starts_at'] = ssl.cert_time_to_seconds(v)
                elif k == 'issuer': result['issuer'] = v
        return result

    def dispatch(self, op, data):
        require(isinstance(data, dict), 'Arguments must be an object')
        if op=='webui-guard':
            require(not data,'Unexpected WebUI guard arguments')
            return webui_security.snapshot()
        if op in ('webui-guard-repair','webui-guard-unban'):
            if op=='webui-guard-repair':require(not data,'Unexpected WebUI repair arguments')
            else:
                require(set(data)=={'ip'} and isinstance(data['ip'],str),'Select one WebUI ban address')
                try:address=str(ipaddress.ip_address(data['ip']))
                except ValueError:raise Problem(400,'Choose a valid IP address')
            with self.guard_lock:
                try:
                    if op=='webui-guard-repair':webui_security.setup()
                    else:webui_security.unban(address)
                except (OSError,RuntimeError,subprocess.SubprocessError):raise Problem(503,'WebUI login protection could not be changed. Check installed Fail2Ban and owned configuration; foreign files are retained.')
                return {'guard':webui_security.snapshot()}
        if op=='network':
            require(not data,'Unexpected network report arguments')
            if self.variant=='zgocloud':return {'protected':True,'change_allowed':False}
            return json.loads(self.run([self.manager,'network','report'],timeout=30))
        if op=='endpoints':
            require(set(data)=={'id'},'Select a user');return endpoint_options(self.state())
        if op=='portal-export':
            require({'session','csrf','profile','format'}<=set(data)<= {'session','csrf','profile','format','endpoint'},'Invalid personal export',403)
            identity=Portal(self.accounting(),self.portal_change).dispatch('portal-connection',{'session':data['session'],'csrf':data['csrf']})
            require(identity['enabled'],'User is disabled',409)
            return self.dispatch('export',{'id':identity['id'],'profile':data['profile'],'format':data['format'],'endpoint':data.get('endpoint','auto')})
        if op.startswith('portal-'):
            result=Portal(self.accounting(),self.portal_change).dispatch(op,data)
            if op=='portal-connection':result['endpoints']=endpoint_options(self.state())
            return result
        if op=='accounting-summary':require(not data,'Unexpected accounting arguments');return self.cached('accounting',self.accounting_summary,2)
        if op=='quota-preview':return plan_preview(data)
        if op=='accounting-history':
            require(set(data)=={'id','selection'} and isinstance(data['id'],str) and re.fullmatch('[a-f0-9]{32}',data['id']),'Invalid history user')
            user=next((u for u in self.state().get('managed_users',[]) if u['id']==data['id']),None)
            require(user is not None,'Unknown user',404)
            return history(self.accounting().store(),user,data['selection'])
        if op=='accounting-user':
            require(set(data)=={'id','window'} and isinstance(data['id'],str) and re.fullmatch('[a-f0-9]{32}',data['id']) and data['window'] in ('7d','30d'),'Invalid usage selection')
            user=next((u for u in self.state().get('managed_users',[]) if u['id']==data['id']),None);require(user is not None,'Unknown user',404);engine=self.accounting()
            return {'id':user['id'],'name':user['name'],'usage':engine.store().view(user,engine.health(),window=7 if data['window']=='7d' else 30),'plan':quota_plan(user.get('quota')),'protocol_totals':engine.store().protocols(user['id']),'portal':{k:v for k,v in user.get('portal',{}).items() if k in ('username','enabled','reset')}}
        if op=='quota-doctor':require(not data,'Unexpected diagnostic arguments');return self.accounting().doctor()
        if op == 'overview': return self.overview()
        if op == 'inbounds': return self.inbounds()
        if op == 'users': return self.users()
        if op == 'capabilities': return self.capability_report()
        if op == 'version':
            require(not data, 'Unexpected arguments')
            def collect():
                result={'variant':self.variant,'expected_core_version':self.state()['sing_box']['version'],'sampled_at':time.time()}
                for key,args in (('manager_version',[self.manager,'version']),('manager_build_id',[self.manager,'_build-id'])):
                    try:result[key]=self.run(args,timeout=20).strip()[:80] or None
                    except Problem:result[key]=None
                try:
                    match=re.search(r'^sing-box version (\S+)',self.run(['/usr/local/lib/sbox-manager/sing-box','version']),re.M)
                    result['core_version']=match[1] if match else None
                except Problem:result['core_version']=None
                return result
            return self.cached('version', collect, 60)
        if op == 'policy': return self.state().get('client_policy', {'primary': 'tuic'})
        if op == 'certificate': return self.cached('cert', self.certificate, 30)
        if op == 'doctor':
            require(not data,'Unexpected diagnostic arguments')
            observed=self.run([self.manager,'doctor','--json'],timeout=120,allow_failure=True)
            try:value=redact(json.loads(observed['stdout']))
            except ValueError:raise Problem(503,'Manager doctor did not return structured diagnostics')
            value['exit_code']=observed['exit_code'];value['sampled_at']=time.time()
            self.last_check={'sampled_at':value['sampled_at'],'failures':value.get('failures'),'source':'manager doctor --json','exit_code':observed['exit_code']}
            self.cache.pop('overview',None)
            return value
        if op == 'change-preview':
            require(set(data)=={'token'} and re.fullmatch('[a-f0-9]{64}',str(data['token'])),'Invalid change token')
            path=Path('/var/lib/sbox-webui-control/changes')/data['token']
            require(path.is_dir() and not path.is_symlink(),'Unknown or consumed preview',404)
            created=int((path/'created').read_text());require(created+600>time.time(),'Preview expired',409)
            request=json.loads((path/'request.json').read_text());result={'kind':request['kind'],'expires_at':created+600}
            if request.get('onboarding'):
                candidate=json.loads((path/'state.json').read_text());known={u['id'] for u in self.state().get('managed_users',[])};new=[u['id'] for u in candidate.get('managed_users',[]) if u['id'] not in known];require(len(new)==1,'Onboarding preview changed',409);result['onboarding_id']=new[0]
            return result
        if op == 'backups':
            require(not data, 'Unexpected arguments')
            return {'backups': [{'name': p.name, 'bytes': p.stat().st_size, 'created': p.stat().st_mtime, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(Path('/var/backups/sbox-manager').glob('*.tar.gz'))[-100:] if p.is_file() and not p.is_symlink()]}
        if op == 'restore':
            require(set(data) == {'name', 'sha256'} and re.fullmatch(r'[A-Za-z0-9._-]{1,150}\.tar\.gz', str(data['name'])), 'Invalid backup selection')
            path = Path('/var/backups/sbox-manager') / data['name']
            require(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == data['sha256'], 'Backup changed or unavailable', 409)
            return {'text': self.scrub(self.run([self.manager, 'restore', str(path), '--force'], timeout=180))}
        if op in ('update-preview', 'core-update'):
            require(set(data) == {'version'} and re.fullmatch(r'(?:latest|stable|beta|prerelease|\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)', str(data['version'])), 'Choose latest, beta or an exact version')
            if op == 'update-preview':
                # Local only: SBOX never downloads cores (no GitHub or mirror).
                # The only core the panel can install is the verified pinned
                # core retained from the installed SBOX package.
                return self.pinned_core_preview(data['version'])
        if op == 'certificate-renew':
            require(not data, 'Unexpected arguments')
            s = self.state()
            require(s['certificate']['mode'] in ('certbot-http01', 'certbot-dns-cloudflare'), 'Not a managed ACME certificate')
            self.run(['/usr/bin/certbot', 'renew', '--cert-name', s['domain'], '--non-interactive', '--force-renewal', '--no-directory-hooks'], timeout=900)
            return {'text': self.scrub(self.run([self.manager, '_cert-deploy', '/etc/letsencrypt/live/' + s['domain']], timeout=180))}
        if op == 'logs':
            require(set(data) <= {'search'}, 'Invalid log arguments')
            search = data.get('search', '')
            require(isinstance(search, str) and len(search) <= 128, 'Invalid log search')
            sampled = self.cached('logs', lambda: {'text':self.scrub(self.run(['/usr/bin/journalctl', '--no-pager', '-u', 'sing-box.service', '-n', '200', '-o', 'cat'])),'sampled_at':time.time()}, 5)
            return {'text': '\n'.join(l for l in sampled['text'].splitlines() if search.casefold() in l.casefold()), 'sampled_at': sampled['sampled_at'], 'limit': 200}
        if op in ('prepare', 'commit', 'export'):
            if op == 'commit': require(set(data) == {'token'} and re.fullmatch('[a-f0-9]{64}', str(data['token'])), 'Invalid change token')
            if op == 'export':
                require({'id','profile','format'} <= set(data) <= {'id','profile','format','endpoint'} and re.fullmatch(r'legacy|[a-f0-9]{32}', str(data['id'])), 'Invalid export')
                require(data.get('endpoint','auto') in ('auto','domain','ipv4','ipv6'),'Unknown endpoint choice')
                require(data['profile'] in ('global', 'cn', 'internal') and data['format'] in ('yaml', 'links', 'json', 'singbox'), 'Unknown format/profile')
            out = self.run([self.manager, '_webui-control', op], data, 180)
            if op == 'export': return {'content': out}
            self.cache.clear()
            return json.loads(out)
        reads = {'doctor': ['doctor', '--json'], 'firewall': ['firewall', 'ports', 'json'], 'firewall-status': ['firewall', 'status'], 'security': ['security', 'status'], 'bans': ['security', 'bans'], 'performance': ['performance', 'report', '--json']}
        writes = {'firewall-apply': ['firewall', 'apply'], 'security-repair': ['security', 'repair'], 'renew-test': ['renew-test'], 'backup': ['backup'], 'recover': ['recover'], 'restart': ['restart']}
        if op == 'unban':
            require(set(data) == {'ip'}, 'Invalid unban'); address = str(ipaddress.ip_address(data['ip']))
            args = ['security', 'unban', address]
        elif op == 'core-update':
            require(set(data) == {'version'} and re.fullmatch(r'(?:latest|stable|beta|prerelease|\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)', str(data['version'])), 'Choose latest, beta or an exact version')
            args = ['update', data['version']]
        elif op in reads or op in writes:
            require(not data, 'Unexpected arguments')
            args = {**reads,**writes}[op]
        else: raise Problem(400, 'Operation is not allowlisted')
        out = self.run([self.manager] + args + (['--force'] if op == 'core-update' else []), timeout=900 if op in ('core-update', 'renew-test') else 120)
        try: value = json.loads(out)
        except ValueError: value = {'text': self.scrub(out)}
        if op=='doctor':self.last_check={'sampled_at':time.time(),'failures':value.get('failures'),'source':'manager doctor --json'}
        return value

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(15)
        _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        if uid not in (0, self.server.panel_uid): return
        try:
            raw = self.rfile.readline(65537)
            require(len(raw) <= 65536 and raw.endswith(b'\n'), 'Request too large', 413)
            req = json.loads(raw)
            require(isinstance(req, dict) and {'op','data'}<=set(req)<= {'op','data','context'}, 'Invalid bridge request')
            require(isinstance(req['op'],str) and isinstance(req['data'],dict),'Invalid bridge request')
            principal={'kind':'root'} if uid==0 else authorize(req['op'],req['data'],req.get('context',{}),self.server.cfg)
            value = self.server.control.dispatch(req['op'], req['data'])
            if principal['kind']=='subscription' and req['op']=='users':value=[u for u in value if u['id']==principal['id']]
            result = {'ok': True, 'data': value}
        except Problem as e: result = {'ok': False, 'status': e.status, 'error': e.message}
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError): result = {'ok': False, 'status': 503, 'error': 'Bridge operation unavailable; inspect root service journal'}
        self.wfile.write(json.dumps(result).encode() + b'\n')

class Bridge(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 32
    def __init__(self,*a,**kw):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*a,**kw)
    def process_request(self,request,address):
        # Backpressure preserves the eight-worker limit without dropping a normal
        # dashboard burst. The Unix backlog remains bounded while one slot frees.
        if not self.slots.acquire(timeout=5):request.close();return
        try:super().process_request(request,address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

def main():
    require(os.geteuid() == 0, 'Root required', 403)
    cfg = json.loads(Path('/etc/sbox-webui/settings.json').read_text())
    path = Path('/run/sbox-webui-control/control.sock')
    path.unlink(missing_ok=True)
    with Bridge(str(path), Handler) as server:
        server.cfg=cfg
        server.panel_uid = pwd.getpwnam('sbox-webui').pw_uid
        server.control = Control(variant=cfg['variant'])
        os.chown(path, 0, pwd.getpwnam('sbox-webui').pw_gid)
        path.chmod(0o660)
        server.serve_forever(poll_interval=1)

if __name__ == '__main__': main()
