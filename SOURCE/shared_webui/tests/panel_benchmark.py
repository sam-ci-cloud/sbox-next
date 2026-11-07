"""30-minute panel resource measurement and real protocol A/B, disposable VM only."""
import argparse,concurrent.futures,http.client,json,os,pathlib,ssl,statistics,subprocess,sys,threading,time
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file(),'Marked disposable VM only'
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--idle-seconds',type=int,default=1800);p.add_argument('--load-seconds',type=int,default=120);p.add_argument('--protocol-lab',type=pathlib.Path);a=p.parse_args()
out=a.output;out.mkdir(parents=True,exist_ok=True);cfg=json.loads(pathlib.Path('/etc/sbox-webui/settings.json').read_text());samples=[];rows=[];stop=threading.Event()
def run(argv,**kw):return subprocess.run(argv,check=True,capture_output=True,text=True,timeout=kw.pop('timeout',180),**kw).stdout
def core_pid():return run(['systemctl','show','sing-box','-p','MainPID','--value']).strip()
def stats(unit):
    data=dict(l.split('=',1) for l in run(['systemctl','show',unit,'-p','MainPID','-p','MemoryCurrent','-p','CPUUsageNSec','-p','NRestarts','-p','ActiveState']).splitlines() if '=' in l)
    rss=None
    try:
        for line in pathlib.Path('/proc/'+data['MainPID']+'/status').read_text().splitlines():
            if line.startswith('VmRSS:'):rss=int(line.split()[1])*1024
    except OSError:pass
    return {**data,'rss_bytes':rss}
def disk():return sum(f.stat().st_size for f in pathlib.Path('/var/lib/sbox-webui').iterdir() if f.is_file() and not f.is_symlink())
def collect(phase):
    data={'time':time.time(),'phase':phase,'panel':stats('sbox-webui'),'bridge':stats('sbox-webui-control'),'ui_disk_bytes':disk(),'core_pid':core_pid()}
    samples.append(data);(out/'resource-samples.json').write_text(json.dumps(samples,indent=2)+'\n');return data
def phase(name,seconds):
    begin=time.monotonic();collect(name)
    while time.monotonic()-begin<seconds:
        time.sleep(min(5,max(.01,seconds-(time.monotonic()-begin))));collect(name)
def request(path,body=None,cookie=None):
    client=http.client.HTTPSConnection('::1' if cfg['listen']=='::1' else '127.0.0.1',cfg['port'],context=ssl._create_unverified_context(),timeout=20)
    headers={'Host':cfg['origin'].split('://')[1]}
    if cookie:headers['Cookie']=cookie
    if body is not None:headers['Content-Type']='application/json'
    start=time.monotonic();client.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,headers);r=client.getresponse();data=r.read();latency=time.monotonic()-start;result=(r.status,dict(r.getheaders()),data,latency);client.close();return result
before=core_pid()
run(['systemctl','stop','sbox-webui','sbox-webui-control']);assert core_pid()==before
phase('panel-and-bridge-stopped',60)
run(['systemctl','start','sbox-webui-control','sbox-webui']);time.sleep(3);assert core_pid()==before
assert request('/api/v1/health')[0]==200
phase('idle-panel',a.idle_seconds)
code,head,body,_=request('/api/v1/auth/login',{'username':'admin','password':'Lab-verified-password-2026'})
assert code==200,'Benchmark requires the disposable test admin account'
cookie=head['Set-Cookie'].split(';')[0]
def poll_client(index):
    result=[];end=time.monotonic()+a.load_seconds
    while time.monotonic()<end:
        start=time.monotonic()
        try:code,_,_,seconds=request('/api/v1/system/status',cookie=cookie);result.append({'client':index,'status':code,'seconds':seconds})
        except Exception as e:result.append({'client':index,'status':0,'error':type(e).__name__})
        time.sleep(max(0,2-(time.monotonic()-start)))
    return result
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    jobs=[pool.submit(poll_client,i) for i in range(10)]
    phase('ten-dashboard-clients',a.load_seconds)
    latencies=[r for job in jobs for r in job.result()]
(out/'api-latencies.json').write_text(json.dumps(latencies,indent=2)+'\n')
assert core_pid()==before,'Panel-only stop/start/load changed core PID'
def percentile(data,fraction):
    data=sorted(data);return data[min(len(data)-1,int((len(data)-1)*fraction))]
summary={'variant':cfg['variant'],'scope':'local KVM guest, 2 vCPU/2 GiB; not an ISP or public-cloud throughput claim','idle_seconds_requested':a.idle_seconds,'load_seconds':a.load_seconds,'core_pid_unchanged':True,'thresholds':{'idle_combined_rss_mib':96,'load_combined_rss_mib':160,'idle_one_cpu_percent':2,'api_p95_seconds':1,'disk_growth_mib':16},'phases':{}}
for name in ('idle-panel','ten-dashboard-clients'):
    data=[x for x in samples if x['phase']==name];seconds=data[-1]['time']-data[0]['time'];cpu={}
    for unit in ('panel','bridge'):
        cpu[unit]=100*(int(data[-1][unit]['CPUUsageNSec'])-int(data[0][unit]['CPUUsageNSec']))/1e9/seconds
    memory=max(sum(x[u]['rss_bytes'] or 0 for u in ('panel','bridge')) for x in data)
    summary['phases'][name]={'measured_seconds':seconds,'average_one_cpu_percent':cpu,'peak_combined_rss_bytes':memory,'ui_disk_growth_bytes':data[-1]['ui_disk_bytes']-data[0]['ui_disk_bytes'],'service_pids':{u:sorted({x[u]['MainPID'] for x in data}) for u in ('panel','bridge')}}
times=[x['seconds'] for x in latencies if x['status']==200]
summary['http']={'requests':len(latencies),'failures':sum(x['status']!=200 for x in latencies),'p50_seconds':percentile(times,.5),'p95_seconds':percentile(times,.95)}
summary['passed']=summary['http']['failures']==0 and summary['http']['p95_seconds']<1 and summary['phases']['idle-panel']['peak_combined_rss_bytes']<96*1048576 and sum(summary['phases']['idle-panel']['average_one_cpu_percent'].values())<2 and summary['phases']['ten-dashboard-clients']['peak_combined_rss_bytes']<160*1048576 and all(v['ui_disk_growth_bytes']<16*1048576 for v in summary['phases'].values())
(out/'benchmark-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print('RESOURCE BENCHMARK',summary['passed'],flush=True)
if a.protocol_lab:
    for enabled in (False,True):
        run(['systemctl','start' if enabled else 'stop','sbox-webui','sbox-webui-control'])
        assert core_pid()==before
        label='panel-on' if enabled else 'panel-off'
        with (out/(label+'-protocol.log')).open('w') as log:
            result=subprocess.run(['env','SBOX_LAB=1','python3',str(a.protocol_lab),'--helper','/usr/local/lib/sbox-manager/sbox-state','--out',str(out/label),'--transfer-bytes','1048576','--udp-seconds','3'],stdout=log,stderr=subprocess.STDOUT,timeout=600)
        summary[label]={'exit_code':result.returncode,'results':str(out/label/'results.json')}
        (out/'benchmark-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    run(['systemctl','start','sbox-webui-control','sbox-webui'])
assert core_pid()==before
sys.exit(0 if summary['passed'] else 1)

