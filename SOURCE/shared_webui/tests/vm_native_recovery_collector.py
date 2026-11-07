"""Opt-in installed-system regression: native recovery must refresh collector mounts.

Run only in a disposable systemd guest containing /root/lab-ready:
SBOX_DISPOSABLE_RECOVERY=1 python3 vm_native_recovery_collector.py PRIVATE_OUTPUT
The real manager snapshots/restores its owned runtime and restarts the VPN.
"""
from pathlib import Path
import hashlib,json,os,sqlite3,subprocess,sys,tempfile,time
assert os.geteuid()==0 and Path('/root/lab-ready').is_file() and os.environ.get('SBOX_DISPOSABLE_RECOVERY')=='1','Explicit disposable guest only'
os.umask(0o077);out=Path(sys.argv[1]);out.mkdir(mode=0o700,parents=True,exist_ok=True)
def run(args,**kw):return subprocess.run(args,capture_output=True,text=True,timeout=180,**kw)
def pid():return int(subprocess.check_output(['systemctl','show','sbox-accounting.service','-p','MainPID','--value']))
def identities():
 s=json.loads(Path('/etc/sbox-manager/state.json').read_text());return hashlib.sha256(json.dumps({'original':s['protocols'],'users':{u['id']:u['protocols'] for u in s.get('managed_users',[])}},sort_keys=True).encode()).hexdigest()
def totals():
 with sqlite3.connect('file:/var/lib/sbox-accounting/usage.db?mode=ro',uri=True) as db:return dict(db.execute('SELECT user_id,lifetime_up+lifetime_down FROM totals'))
def health():return json.loads(Path('/var/lib/sbox-accounting/health.json').read_text())
before_pid=pid();before_identity=identities();before_totals=totals();assert before_pid>0 and health()['status']=='ready','Start with healthy accounting'
source=Path('/usr/local/lib/sbox-manager/manager').read_text();assert source.rstrip().endswith('main "$@"');source=source.rstrip()[:-len('main "$@"')]
with tempfile.TemporaryDirectory(prefix='native-recovery-',dir=out) as tmp:
 library=Path(tmp)/'manager-library.sh';library.write_text(source);library.chmod(0o600)
 script='''source "$1"
ASSUME_DEFAULTS=true
need_root; need_systemd; ensure_runtime_dir; acquire_lock
install -d -m 0700 "$TXN_SNAPSHOT_DIR"
snap="$(mktemp -d "$TXN_SNAPSHOT_DIR/collector-recovery.XXXXXXXX")"
snapshot_runtime "$snap"
write_txn_journal "$snap" 'disposable native recovery regression'
recover_command
'''
 result=run(['bash','-c',script,'fixture',str(library)],env={**os.environ,'SBOX_ASSUME_DEFAULTS':'true'})
 (out/'native-recovery.log').write_text(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError('Native recovery failed; private journal/log retained')
 time.sleep(4);after=health();refreshed=pid()!=before_pid;healthy=after['status']=='ready' and time.time()-after['sampled_at']<4
 same_identity=identities()==before_identity;after_totals=totals();retained=all(after_totals.get(k,0)>=v for k,v in before_totals.items())
 report={'collector_refreshed':refreshed,'collector_ready':healthy,'vpn_identities_unchanged':same_identity,'counters_retained':retained,'auto_repaired':False}
 if not healthy or not refreshed:
  # Keep a failed regression recoverable without hiding its result.
  repair=run(['systemctl','restart','sbox-accounting.service']);report['auto_repaired']=repair.returncode==0;time.sleep(3)
 report['status']='PASS' if refreshed and healthy and same_identity and retained else 'FAIL'
 (out/'native-recovery.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
 sys.exit(report['status']!='PASS')
