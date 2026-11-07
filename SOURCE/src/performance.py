#!/usr/bin/env python3
"""Bounded, read-only host/VPN inventory. No probes or load unless requested."""
import argparse, datetime, hashlib, hmac, ipaddress, json, os, platform, re, selectors, shutil, signal, subprocess, time
from pathlib import Path

KEYS = ['net.core.default_qdisc','net.ipv4.tcp_congestion_control','net.ipv4.tcp_available_congestion_control','net.core.rmem_max','net.core.wmem_max','net.core.somaxconn','net.core.netdev_max_backlog','net.ipv4.tcp_fastopen','net.ipv4.tcp_mtu_probing','net.ipv4.udp_rmem_min','net.ipv4.udp_wmem_min','net.netfilter.nf_conntrack_count','net.netfilter.nf_conntrack_max']

def run(args, timeout=8):
    if not shutil.which(args[0]): return {'status':'unavailable','command':args[0]}
    # Bound memory BEFORE capture, not by slicing an already unlimited output.
    limits = {'stdout':131072, 'stderr':1024}
    output = {name:bytearray() for name in limits}
    truncated = {name:False for name in limits}
    proc = None
    timed_out = False
    def terminate():
        if proc is not None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env={**os.environ,'LC_ALL':'C'})
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for name in limits: selector.register(getattr(proc,name), selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True; terminate(); break
                for event,_ in selector.select(remaining):
                    name = event.data
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    if not chunk: selector.unregister(event.fileobj); continue
                    available = limits[name] - len(output[name])
                    output[name].extend(chunk[:available])
                    if len(chunk) > available:
                        truncated[name] = True
                if any(truncated.values()): terminate(); break
        remaining = max(0.01, deadline - time.monotonic())
        try: rc = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True; terminate(); rc = proc.wait(timeout=2)
        status = 'timeout' if timed_out else ('truncated' if any(truncated.values()) else ('ok' if rc == 0 else 'error'))
        return {'status':status,'rc':rc,'stdout_truncated':truncated['stdout'],
                'stderr_truncated':truncated['stderr'],
                **{name:bytes(value).decode('utf-8',errors='replace') for name,value in output.items()}}
    except OSError as exc:
        return {'status':'error','command':args[0],'error_type':type(exc).__name__,'stderr':str(exc)[:1024]}
    finally:
        if proc is not None:
            if proc.poll() is None: terminate(); proc.wait(timeout=2)
            for name in limits:
                stream = getattr(proc,name)
                if stream is not None: stream.close()

def read(path):
    try:
        with Path(path).open('r',encoding='utf-8',errors='replace') as stream: return stream.read(131072)
    except OSError: return None


def redact(text, key=None):
    # A random per-report secret makes IPv4 enumeration and cross-report linking
    # impractical. No key file, state mutation or secret in serialized output.
    key=os.urandom(32) if key is None else key
    def replace(m):
        value=m[0]
        try:addr=ipaddress.ip_address(value.split('%',1)[0])
        except ValueError:return value
        tag=hmac.new(key,bytes([addr.version])+addr.packed,hashlib.sha256).hexdigest()[:32]
        return 'IP'+str(addr.version)+'-'+tag
    # IPv6 first, including embedded dotted IPv4 and zone identifiers. JSON
    # escaping of a quote is outside these tokens; all fields pass this filter.
    text=re.sub(r'(?<![\w:])(?:[0-9a-fA-F]*:)[0-9a-fA-F:.]*(?:%[A-Za-z0-9_.-]+)?(?![\w:])',replace,text)
    return re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',replace,text)

SERVICES = ('sing-box.service', 'sbox-accounting.service', 'sbox-webui.service',
            'sbox-webui-control.service', 'sbox-fallback-web.service')


def cpu_delta(before, after):
    """First eight Linux counters only: guest ticks are already in user/nice."""
    try:
        a = list(map(int, before.splitlines()[0].split()[1:9]))
        b = list(map(int, after.splitlines()[0].split()[1:9]))
        delta = [y - x for x, y in zip(a, b)]
        if len(delta) != 8 or min(delta) < 0 or sum(delta) <= 0:
            return None
        total = sum(delta)
        return {'busy_percent': round(100 * (total - delta[3] - delta[4]) / total, 2),
                'steal_percent': round(100 * delta[7] / total, 2)}
    except (AttributeError, ValueError, IndexError):
        return None


def counter_file(path):
    text = read(path)
    if text is None:
        return None
    try:
        return {key: int(value) for key, value in (line.split() for line in text.splitlines())}
    except (ValueError, TypeError):
        return None


def cgroup_directory(name, mount=Path('/sys/fs/cgroup')):
    # systemd provides this path; still refuse escapes and symlink components.
    if not name.startswith('/') or '..' in Path(name).parts:
        return None
    path = mount
    try:
        for component in Path(name).parts[1:]:
            path = path / component
            if path.is_symlink():
                return None
        return path if path.is_dir() and path.resolve().is_relative_to(mount.resolve()) else None
    except OSError:
        return None


def service_resources(unit):
    if unit not in SERVICES:
        raise ValueError('Unit outside SBOX resource inventory')
    result = run(['systemctl', 'show', unit, '--property=ControlGroup,ActiveState,InvocationID,CPUQuotaPerSecUSec,MemoryMax,NRestarts'])
    fields = dict(line.split('=', 1) for line in result.get('stdout', '').splitlines() if '=' in line)
    directory = cgroup_directory(fields.get('ControlGroup', ''))
    if result['status'] != 'ok' or directory is None:
        return {'status': 'unavailable', 'service': fields}
    return {'status': 'ok', 'service': fields,
            'sample_monotonic': time.monotonic(),
            'cpu_stat': counter_file(directory / 'cpu.stat'),
            'cpu_max': read(directory / 'cpu.max'),
            'memory_events': counter_file(directory / 'memory.events'),
            'memory_current': read(directory / 'memory.current'),
            'pressure': {resource: read(directory / (resource + '.pressure'))
                         for resource in ('cpu', 'memory', 'io')},
            'io_stat': read(directory / 'io.stat')}


def throttle_delta(before, after, elapsed):
    try:
        keys = ('nr_periods', 'nr_throttled', 'throttled_usec')
        values = [after[key] - before[key] for key in keys]
        if elapsed <= 0 or min(values) < 0:
            return None
        return dict(periods=values[0], throttled_periods=values[1],
                    throttled_usec=values[2],
                    throttled_wall_percent=round(values[2] / (elapsed * 10000), 2))
    except (KeyError, TypeError):
        return None


def service_delta(before, after):
    # Manual restarts need not increment NRestarts. InvocationID identifies
    # every activation, and each unit uses its actual counter sample interval.
    try:
        identity=before['service'].get('InvocationID')
        if not identity or identity!=after['service'].get('InvocationID'):
            return None
        return throttle_delta(before.get('cpu_stat'),after.get('cpu_stat'),
                              after['sample_monotonic']-before['sample_monotonic'])
    except (KeyError,TypeError):
        return None


def os_updates(root=Path('/')):
    root=Path(root)
    # Simulation reads existing package metadata only; no update/install/reboot.
    result=run(['apt-get','-s','-o','Debug::NoLocking=1','upgrade'],timeout=4)
    lines=[line for line in result.get('stdout','').splitlines() if line.startswith('Inst ')]
    usable=result['status']=='ok'
    security=sum(bool(re.search(r'(?:-security|esm[^ ]*)',line,re.I)) for line in lines)
    try:metadata_updated_at=(root/'var/lib/apt/periodic/update-success-stamp').stat().st_mtime
    except OSError:metadata_updated_at=None
    return {'status':result['status'],'security_updates':security if usable else None,
            'other_updates':len(lines)-security if usable else None,
            'reboot_required':(root/'var/run/reboot-required').exists(),
            'metadata_updated_at':metadata_updated_at,
            'source':'APT cached-metadata upgrade simulation; security origin markers only; no repository refresh or package changes',
            'limits':'Held/phased packages may be excluded; stale cached metadata cannot establish the latest available updates.'}


def collect(root='/etc/sbox-manager', sample=1):
    report={'format':2,'address_anonymization':{'scheme':'HMAC-SHA256-128','scope':'one report; secret key discarded'},'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'local-host-read-only','reachability':{'ipv4':'not actively probed','ipv6':'not actively probed'},'provider_bandwidth_mbps':None,'limits':['No WAN/protocol throughput, mobile, DNS leak or reachability measurement inferred from inventory.','Permission errors and unavailable commands are recorded, not treated as passes.','No raw service log messages or credential-bearing configs collected.'], 'host':{'kernel':platform.release(),'arch':platform.machine(),'vcpus':os.cpu_count(),'os':read('/etc/os-release'),'meminfo':read('/proc/meminfo'),'loadavg':read('/proc/loadavg')},'commands':{}}
    cpuinfo=read('/proc/cpuinfo') or ''
    report['host']['cpu_model']=next((line.split(':',1)[1].strip() for line in cpuinfo.splitlines() if line.startswith('model name')),None)
    report['host']['memory_pressure']=read('/proc/pressure/memory')
    report['host']['cpu_pressure']=read('/proc/pressure/cpu')
    report['host']['io_pressure']=read('/proc/pressure/io')
    commands={'route_to_ipv4':['ip','-4','route','get','1.1.1.1'],'route_to_ipv6':['ip','-6','route','get','2606:4700:4700::1111'],'udp_sockets':['ss','-uanm'],'interfaces':['ip','-s','-d','link'],'routes4':['ip','-4','route'],'routes6':['ip','-6','route'],'sockets':['ss','-s'],'listeners':['ss','-H','-lntup'],'tcp':['ss','-tinm'],'qdisc':['tc','-s','qdisc','show'],'iptables':['iptables-save'],'ip6tables':['ip6tables-save'],'nft':['nft','list','ruleset'],'ufw':['ufw','status','verbose'],'netfilter_backend':['iptables','--version'],'sysctl':['sysctl',*KEYS],'service':['systemctl','show','sing-box.service','-p','MainPID','-p','NRestarts','-p','CPUUsageNSec','-p','MemoryCurrent','-p','MemoryPeak','-p','TasksCurrent','-p','ActiveState','-p','ExecMainStatus','-p','ActiveEnterTimestamp'],'fail2ban':['fail2ban-client','status'],'ssh':['sshd','-T'],'core':['/usr/local/lib/sbox-manager/sing-box','version'],'mihomo':['mihomo','-v']}
    for name,args in commands.items():
        value=run(args)
        if name=='ssh' and 'stdout' in value:
            value['stdout']='\n'.join(x for x in value['stdout'].splitlines() if x.startswith(('port ','listenaddress ','syslogfacility ','loglevel ')))
        if name in ('iptables','ip6tables','nft') and 'stdout' in value:
            # Foreign firewall comments are arbitrary operator text.
            value['stdout']=re.sub(r'(?:--comment|comment)\s+"[^"]*"','comment "REDACTED"',value['stdout'])
        report['commands'][name]=value
    services_before={unit:service_resources(unit) for unit in SERVICES}
    sample_started=time.monotonic()
    for phase in ('before','after'):
        report[phase]={p:read(p) for p in ['/proc/stat','/proc/softirqs','/proc/net/snmp','/proc/net/netstat','/proc/net/snmp6','/proc/net/dev','/proc/net/softnet_stat']}
        if phase=='before': time.sleep(sample)
    elapsed=time.monotonic()-sample_started
    report['counter_sample_seconds']=elapsed
    report['requested_sample_seconds']=sample
    counters=cpu_delta(report['before']['/proc/stat'], report['after']['/proc/stat'])
    if counters is not None:
        report['host']['cpu_steal_percent']=counters['steal_percent']
        report['host']['cpu_busy_percent']=counters['busy_percent']
    report['services']={}
    for unit in SERVICES:
        after=service_resources(unit)
        before=services_before[unit]
        # Restart/cgroup replacement invalidates any derived interval.
        after['cpu_interval']=service_delta(before,after)
        report['services'][unit]=after
    state_path=Path(root)/'state.json'
    if state_path.is_file():
        try:
            st=json.loads(state_path.read_text()); cfg=json.loads((Path(root)/'config.json').read_text())
            report['vpn']={'schema':st.get('schema'),'tuning':st.get('tuning'),'firewall':st.get('firewall'),'protocols':{k:{'enabled':v.get('enabled'),'port':v.get('port'),**({'multiplex':v['multiplex']} if 'multiplex' in v else {})} for k,v in st['protocols'].items()},'config_sha256':hashlib.sha256((Path(root)/'config.json').read_bytes()).hexdigest(),'listen_options':[{k:v for k,v in i.items() if k in ('type','listen','listen_port','tcp_fast_open','tcp_multi_path','udp_fragment','congestion_control','ignore_client_bandwidth','bbr_profile','heartbeat')} for i in cfg.get('inbounds',[])]}
            paths={i.get('tls',{}).get('certificate_path') for i in cfg.get('inbounds',[])}-{None}
            report['certificates']=[run(['openssl','x509','-in',p,'-noout','-dates','-checkend','604800']) for p in sorted(paths)]
        except (OSError,ValueError,KeyError,TypeError,AttributeError) as e: report['vpn']={'status':'invalid-or-unreadable','error':type(e).__name__}
    report['os_updates']=os_updates()
    report['resolver_config']=read('/etc/resolv.conf')
    report['configured_sysctl']=read('/etc/sysctl.d/99-sbox-manager.conf')
    service=report['commands']['service'].get('stdout','')
    m=re.search(r'^MainPID=([1-9]\d*)$',service,re.M)
    if m:
        pid=m[1]; report['process']={'status':read(f'/proc/{pid}/status'),'limits':read(f'/proc/{pid}/limits')}
        try: report['process']['fd_count']=len(list(Path(f'/proc/{pid}/fd').iterdir()))
        except OSError: pass
    journal=run(['journalctl','-u','sing-box.service','--since','-15min','-n','1000','--no-pager','-o','cat'])
    report['journal_summary']={'status':journal['status'],'bounded_lines':len(journal.get('stdout','').splitlines()),'error_class_counts':{k:len(re.findall(v,journal.get('stdout',''),re.I)) for k,v in {'fatal':'fatal|panic','fd':'too many open files','memory':'out of memory|cannot allocate','timeout':'timeout|deadline','auth':'authentication failed|invalid password'}.items()}}
    return json.loads(redact(json.dumps(report,ensure_ascii=False)))

def network_report(target, samples=3, socks_port=None, peer=None, allow_private=False, expected_status="204", family="dual"):
    """Operator-requested bounded probes; never reads browsing/history/user traffic."""
    import socket,urllib.parse,statistics
    if not isinstance(target,str) or re.search(r'[\x00-\x20\x7f\\]',target):raise ValueError('Target must be credential-free HTTPS')
    url=urllib.parse.urlsplit(target)
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.port is not None and not 1<=url.port<=65535:raise ValueError('Target must be public HTTPS without credentials, query or fragment')
    if type(samples) is not int or not 1<=samples<=5:raise ValueError('Samples must be1..5')
    if family not in ("dual","ipv4","ipv6") or socks_port is not None and family!="dual":raise ValueError("--family selects direct curl transport only; set proxied address families in the client policy")
    if socks_port is not None and (type(socks_port) is not int or not 1024<=socks_port<=65535):raise ValueError('SOCKS port must be a local high port')
    if not allow_private and socks_port is not None:
        try:literal=ipaddress.ip_address(url.hostname)
        except ValueError:literal=None
        if url.hostname.lower() in ("localhost",) or literal is not None and (not literal.is_global or literal.is_multicast):raise ValueError("Nonpublic proxy target requires --allow-private-target")
    if not allow_private and socks_port is None:
        # Bound name lookup in a child so resolver failure cannot hang diagnostics.
        resolve=run(['python3','-I','-c','import socket,json,sys;print(json.dumps(sorted(set(x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)))))',url.hostname],timeout=4)
        try:addresses=json.loads(resolve.get('stdout',''))
        except ValueError:addresses=[]
        if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):raise ValueError('Target resolution unavailable/nonpublic or intercepted fake-IP. Use an explicit local SOCKS endpoint for remote DNS, or --allow-private-target only for an understood internal test')
    if expected_status not in ('200','204','200/204'):raise ValueError('Expected status must be200,204 or200/204')
    rows=[]
    for sample in range(samples):
        args=['curl','-q','--silent','--show-error','--head','--max-time','5','--max-redirs','0','--proto','=https','--output',os.devnull,'--write-out','%{json}\n']
        args+=['--noproxy','','--socks5-hostname','127.0.0.1:'+str(socks_port)] if socks_port else ['--noproxy','*']
        if family!='dual':args.append('--ipv4' if family=='ipv4' else '--ipv6')
        args += [target,'--output',os.devnull,target]
        result=run(args,timeout=12)
        for index,line in enumerate(result.get('stdout','').splitlines()):
            try:item=json.loads(line)
            except ValueError:continue
            def ms(key):return round(float(item.get(key,0))*1000,3)
            rows.append({'sample':sample,'request':'first request in new curl process' if index==0 else 'reuse attempt','path':'proxied via explicitly supplied local SOCKS' if socks_port else 'direct from this machine','curl_exit':item.get('exitcode',result.get('rc')),'http_status':item.get('http_code'),'probe_status':('transport-failure' if item.get('exitcode',result.get('rc')) else 'success' if str(item.get('http_code')) in expected_status.split('/') else 'http-status-mismatch'),'direct_address_family':(6 if ':' in item.get('remote_ip','') else 4) if not socks_port and item.get('remote_ip') else None,'new_connections':item.get('num_connects'),'connection_reused':index>0 and item.get('num_connects')==0,'dns_ms':ms('time_namelookup'),'tcp_connect_cumulative_ms':ms('time_connect'),'tls_complete_cumulative_ms':ms('time_appconnect'),'first_byte_cumulative_ms':ms('time_starttransfer'),'total_ms':ms('time_total'),'tcp_phase_derived_ms':round(max(0,ms('time_connect')-ms('time_namelookup')),3),'tls_and_tunnel_phase_derived_ms':round(max(0,ms('time_appconnect')-ms('time_connect')),3)})
        if not result.get('stdout'):rows.append({'sample':sample,'status':result['status'],'curl_exit':result.get('rc'),'error':'Probe did not return timing data'})
    peer_rows=[]
    if peer:
        host,port=peer.rsplit(':',1);host=host.strip('[]');port=int(port)
        if not 1<=port<=65535 or not re.fullmatch(r'[A-Za-z0-9.:%_-]{1,253}',host):raise ValueError('Invalid explicit peer host:port')
        for _ in range(samples):
            # Socket/DNS work is bounded in the same output-limited subprocess.
            script='import socket,time,json,sys;t=time.monotonic();a=socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM);d=time.monotonic();s=socket.socket(a[0][0],a[0][1]);s.settimeout(3);s.connect(a[0][4]);print(json.dumps({"dns_ms":(d-t)*1000,"tcp_connect_ms":(time.monotonic()-d)*1000,"address_family":6 if a[0][0]==socket.AF_INET6 else 4}));s.close()'
            r=run(['python3','-I','-c',script,host,str(port)],timeout=4)
            try:peer_rows.append(json.loads(r.get('stdout','')))
            except ValueError:peer_rows.append({'status':r['status'],'error':'Explicit peer DNS/TCP connection failed'})
    return {'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Optional operator-requested direct/proxied HTTP HEAD timing, not network RTT or passive traffic collection','target_origin':url.scheme+'://'+url.netloc,'rows':rows,'peer_tcp_samples':peer_rows,'limitations':['No cache flush: first request is not proof of cold OS DNS','Curl connect is to the local SOCKS listener when proxied; VPN authentication/QUIC handshake is not isolated','TLS/tunnel phase differences are derived timings; total/first-byte times are not one RTT','Reuse is claimed only when curl reports zero new connections; redirects are not followed','A single target/path/sample cannot attribute hosting or protocol delay causally'],'capabilities':{'congestion_control':run(['sysctl','-n','net.ipv4.tcp_congestion_control']) .get('stdout','').strip(),'available_congestion_control':run(['sysctl','-n','net.ipv4.tcp_available_congestion_control']).get('stdout','').strip(),'tcp_fastopen':run(['sysctl','-n','net.ipv4.tcp_fastopen']).get('stdout','').strip()},'changes_applied':False,'dns_location':'SOCKS remote hostname resolution; no local target lookup' if socks_port else 'system resolver; VPN/TUN interception may affect direct measurements'}

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--json',action='store_true'); ap.add_argument('--os-updates',action='store_true'); ap.add_argument('--root',default='/etc/sbox-manager'); ap.add_argument('--sample-seconds',type=float,default=1);ap.add_argument('--network',action='store_true');ap.add_argument('--target',default='https://www.gstatic.com/generate_204');ap.add_argument('--samples',type=int,default=3);ap.add_argument('--socks-port',type=int);ap.add_argument('--peer');ap.add_argument('--allow-private-target',action='store_true');ap.add_argument('--expected-status',choices=['200','204','200/204'],default='204');ap.add_argument('--family',choices=['dual','ipv4','ipv6'],default='dual')
    a=ap.parse_args()
    if not 0 <= a.sample_seconds <= 10: ap.error('sample must be 0..10 seconds')
    if a.network:
        try:r=network_report(a.target,a.samples,a.socks_port,a.peer,a.allow_private_target,a.expected_status,a.family)
        except (ValueError,OSError) as exc:ap.error(str(exc))
        print(json.dumps(r,indent=2));return
    if a.os_updates: print(json.dumps(os_updates())); return
    r=collect(a.root,a.sample_seconds)
    if a.json: print(json.dumps(r,indent=2,ensure_ascii=False)); return
    print('sbox performance inventory — '+r['timestamp_utc']); print('Source: '+r['source']); print('Kernel: '+r['host']['kernel']+'; vCPUs: '+str(r['host']['vcpus']))
    for name,value in r['commands'].items():
        print('\n['+name+'] '+value['status']); print(value.get('stdout',value.get('stderr','')).rstrip())
    print('\nLimits: '+' '.join(r['limits'])); print('\nUse --json for counters, sample details and machine-readable evidence.')
if __name__=='__main__': main()
