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

def collect(root='/etc/sbox-manager', sample=1):
    report={'format':2,'address_anonymization':{'scheme':'HMAC-SHA256-128','scope':'one report; secret key discarded'},'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'local-host-read-only','reachability':{'ipv4':'not actively probed','ipv6':'not actively probed'},'provider_bandwidth_mbps':None,'limits':['No WAN/protocol throughput, mobile, DNS leak or reachability measurement inferred from inventory.','Permission errors and unavailable commands are recorded, not treated as passes.','No raw service log messages or credential-bearing configs collected.'], 'host':{'kernel':platform.release(),'arch':platform.machine(),'vcpus':os.cpu_count(),'os':read('/etc/os-release'),'meminfo':read('/proc/meminfo'),'loadavg':read('/proc/loadavg')},'commands':{}}
    cpuinfo=read('/proc/cpuinfo') or ''
    report['host']['cpu_model']=next((line.split(':',1)[1].strip() for line in cpuinfo.splitlines() if line.startswith('model name')),None)
    report['host']['memory_pressure']=read('/proc/pressure/memory')
    report['host']['cpu_pressure']=read('/proc/pressure/cpu')
    commands={'route_to_ipv4':['ip','-4','route','get','1.1.1.1'],'route_to_ipv6':['ip','-6','route','get','2606:4700:4700::1111'],'udp_sockets':['ss','-uanm'],'interfaces':['ip','-s','-d','link'],'routes4':['ip','-4','route'],'routes6':['ip','-6','route'],'sockets':['ss','-s'],'listeners':['ss','-H','-lntup'],'tcp':['ss','-tinm'],'qdisc':['tc','-s','qdisc','show'],'iptables':['iptables-save'],'ip6tables':['ip6tables-save'],'nft':['nft','list','ruleset'],'ufw':['ufw','status','verbose'],'netfilter_backend':['iptables','--version'],'sysctl':['sysctl',*KEYS],'service':['systemctl','show','sing-box.service','-p','MainPID','-p','NRestarts','-p','CPUUsageNSec','-p','MemoryCurrent','-p','MemoryPeak','-p','TasksCurrent','-p','ActiveState','-p','ExecMainStatus','-p','ActiveEnterTimestamp'],'fail2ban':['fail2ban-client','status'],'ssh':['sshd','-T'],'core':['/usr/local/lib/sbox-manager/sing-box','version'],'mihomo':['mihomo','-v']}
    for name,args in commands.items():
        value=run(args)
        if name=='ssh' and 'stdout' in value:
            value['stdout']='\n'.join(x for x in value['stdout'].splitlines() if x.startswith(('port ','listenaddress ','syslogfacility ','loglevel ')))
        if name in ('iptables','ip6tables','nft') and 'stdout' in value:
            # Foreign firewall comments are arbitrary operator text.
            value['stdout']=re.sub(r'(?:--comment|comment)\s+"[^"]*"','comment "REDACTED"',value['stdout'])
        report['commands'][name]=value
    for phase in ('before','after'):
        report[phase]={p:read(p) for p in ['/proc/stat','/proc/softirqs','/proc/net/snmp','/proc/net/netstat','/proc/net/snmp6','/proc/net/dev','/proc/net/softnet_stat']}
        if phase=='before': time.sleep(sample)
    report['counter_sample_seconds']=sample
    stat=read('/proc/stat')
    try:
        a=list(map(int,report['before']['/proc/stat'].splitlines()[0].split()[1:])); b=list(map(int,stat.splitlines()[0].split()[1:])); delta=[y-x for x,y in zip(a,b)]
        report['host']['cpu_steal_percent']=100*delta[7]/max(1,sum(delta[:8]))
    except (AttributeError,ValueError,IndexError): pass
    state_path=Path(root)/'state.json'
    if state_path.is_file():
        try:
            st=json.loads(state_path.read_text()); cfg=json.loads((Path(root)/'config.json').read_text())
            report['vpn']={'schema':st.get('schema'),'tuning':st.get('tuning'),'firewall':st.get('firewall'),'protocols':{k:{'enabled':v.get('enabled'),'port':v.get('port')} for k,v in st['protocols'].items()},'config_sha256':hashlib.sha256((Path(root)/'config.json').read_bytes()).hexdigest(),'listen_options':[{k:v for k,v in i.items() if k in ('type','listen','listen_port','tcp_fast_open','tcp_multi_path','udp_fragment','congestion_control','ignore_client_bandwidth','bbr_profile','heartbeat')} for i in cfg.get('inbounds',[])]}
            paths={i.get('tls',{}).get('certificate_path') for i in cfg.get('inbounds',[])}-{None}
            report['certificates']=[run(['openssl','x509','-in',p,'-noout','-dates','-checkend','604800']) for p in sorted(paths)]
        except (OSError,ValueError,KeyError,TypeError,AttributeError) as e: report['vpn']={'status':'invalid-or-unreadable','error':type(e).__name__}
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

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--json',action='store_true'); ap.add_argument('--root',default='/etc/sbox-manager'); ap.add_argument('--sample-seconds',type=float,default=1)
    a=ap.parse_args()
    if not 0 <= a.sample_seconds <= 10: ap.error('sample must be 0..10 seconds')
    r=collect(a.root,a.sample_seconds)
    if a.json: print(json.dumps(r,indent=2,ensure_ascii=False)); return
    print('sbox performance inventory — '+r['timestamp_utc']); print('Source: '+r['source']); print('Kernel: '+r['host']['kernel']+'; vCPUs: '+str(r['host']['vcpus']))
    for name,value in r['commands'].items():
        print('\n['+name+'] '+value['status']); print(value.get('stdout',value.get('stderr','')).rstrip())
    print('\nLimits: '+' '.join(r['limits'])); print('\nUse --json for counters, sample details and machine-readable evidence.')
if __name__=='__main__': main()
