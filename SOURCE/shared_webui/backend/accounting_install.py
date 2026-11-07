"""Root-only independent accounting runtime installer. Never changes panel lifecycle."""
import hashlib,json,os,pwd,grp,secrets,shutil,subprocess,sys,time,tempfile,struct
from pathlib import Path
from common import require,atomic_json
from quota_models import quota_plan
from accounting import root_json
LIB=Path('/usr/local/lib/sbox-accounting');BASE=Path('/etc/sbox-manager');DATA=Path('/var/lib/sbox-accounting')
INSTALLED=Path('/usr/local/lib/sbox-manager/sing-box')
FILES=('accounting.py','usage_history.py','quota_models.py','stats_rpc.py','common.py','portal_auth.py','core_manifest.json','accounting_install.py','accounting_restore.py')
def verify_runtime(root):
 # Import only from the exact deployed layout, without the source checkout,
 # panel directory or PYTHONPATH hiding a missing collector dependency.
 result=subprocess.run([sys.executable,'-I','-B','-c',
  'import sys;sys.path.insert(0,sys.argv[1]);import accounting,portal_auth,accounting_restore,accounting_install',str(root)],
  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 require(result.returncode==0,'Accounting runtime dependencies are incomplete',503)
def verify_core(path,manifest):
 require(path.is_file() and not path.is_symlink(),'Missing verified accounting core')
 raw=path.read_bytes()
 require(hashlib.sha256(raw).hexdigest()==manifest['sha256'],'Accounting core digest mismatch')
 require(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==62,'Accounting core must be Linux AMD64 ELF')
 return path
def verify_installed_core(state,manifest,path=Path('/usr/local/lib/sbox-manager/sing-box')):
 accounting=state.get('accounting',{})
 if accounting.get('enabled'):
  require(all(accounting.get('coverage',{}).get(p) is True for p in ('reality','vmess','hy2','tuic','anytls')),'Installed accounting coverage is incomplete')
  digest=accounting.get('core_sha256','')
  require(isinstance(digest,str) and len(digest)==64 and all(c in '0123456789abcdef' for c in digest),'Missing installed accounting core digest')
  verify_core(path,{'sha256':digest})
 else:
  require(state['sing_box']['version']==manifest['version'],'Initial accounting activation requires the staged core version')
def preflight():
 root=Path(__file__).resolve().parent;manifest=json.loads((root/'core_manifest.json').read_text())
 state=json.loads((BASE/'state.json').read_text())
 require(os.uname().machine in ('x86_64','amd64'),'Accounting activation is supported only on validated Linux AMD64')
 verify_installed_core(state,manifest)
 for name in FILES:require((root/name).is_file() and not (root/name).is_symlink(),'Incomplete accounting release')
 with tempfile.TemporaryDirectory(prefix='sbox-accounting-preflight-') as scratch:
  for name in FILES:shutil.copyfile(root/name,Path(scratch)/name)
  verify_runtime(Path(scratch))
 source=os.environ.get('SBOX_ACCOUNTING_CORE_SOURCE')
 verify_core(Path(source) if source else LIB/'core-candidate',manifest)
 print('Accounting asset and core preflight passed; no deployed files changed.')
def ensure_h2():
 # Avoid a second apt transaction on every upgrade. The normal base install
 # includes this dependency; old installations still get a bounded repair.
 import importlib
 modules=('h2.connection','h2.config','h2.events')
 try:
  for name in modules:importlib.import_module(name)
  return
 except ImportError:pass
 subprocess.run(['apt-get','-o','DPkg::Lock::Timeout=300','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=30','-o','Acquire::https::Timeout=30','install','-y','python3-h2'],check=True,stdout=sys.stderr,stdin=subprocess.DEVNULL,timeout=600,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'})
 importlib.invalidate_caches()
 for name in modules:importlib.import_module(name)

def stage():
 root=Path(__file__).resolve().parent;manifest=json.loads((root/'core_manifest.json').read_text());build=hashlib.sha256(b''.join((root/n).read_bytes() for n in FILES)).hexdigest()[:24]
 source=os.environ.get('SBOX_ACCOUNTING_CORE_SOURCE','')
 if source:verify_core(Path(source),manifest)
 for path in (LIB,DATA):
  require(not path.is_symlink(),'Unsafe accounting namespace');path.mkdir(mode=0o700,parents=True,exist_ok=True);require(path.stat().st_uid==0 and not path.stat().st_mode&0o022,'Unsafe accounting owner')
 target=LIB/('release-'+build)
 if target.exists():require(all((target/n).is_file() and not (target/n).is_symlink() and (target/n).read_bytes()==(root/n).read_bytes() for n in FILES),'Accounting runtime integrity mismatch')
 if not target.exists():
  with tempfile.TemporaryDirectory(prefix='.runtime-',dir=LIB) as scratch:
   stage=Path(scratch)/'release';stage.mkdir(mode=0o700)
   for name in FILES:shutil.copyfile(root/name,stage/name);(stage/name).chmod(0o600)
   os.replace(stage,target)
 verify_runtime(target)
 candidate=LIB/'core-candidate'
 if source:
  source=Path(source);require(source.is_file() and not source.is_symlink(),'Missing embedded accounting core')
  temp=LIB/('.core-'+secrets.token_hex(10))
  try:
   shutil.copyfile(source,temp);temp.chmod(0o700);verify_core(temp,manifest)
   with temp.open('rb') as stream:os.fsync(stream.fileno())
   os.replace(temp,candidate)
  finally:temp.unlink(missing_ok=True)
 if candidate.exists():verify_core(candidate,manifest)
 ensure_h2()
 gid=grp.getgrnam('sboxmgr').gr_gid
 key=BASE/'stats-auth.key'
 if not key.exists():
  fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
  with os.fdopen(fd,'w') as out:out.write(secrets.token_hex(32));out.flush();os.fsync(out.fileno())
 require(not key.is_symlink() and key.stat().st_uid==0,'Unsafe stats key');os.chown(key,0,gid);key.chmod(0o640)
 if not (BASE/'quota-runtime.json').exists():root_json(BASE/'quota-runtime.json',{'blocked':[],'source':'initial accounting policy'},gid)
 unit='''[Unit]
Description=SBOX authenticated user accounting and quota collector
After=sing-box.service network.target
[Service]
Type=simple
User=root
UMask=0077
ExecStart=/usr/bin/python3 -B /usr/local/lib/sbox-accounting/current/accounting.py daemon
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/sbox-manager /var/lib/sbox-accounting /run/sbox-manager
MemoryMax=256M
CPUQuota=30%
TasksMax=32
[Install]
WantedBy=multi-user.target
'''
 Path('/etc/systemd/system/sbox-accounting.service').write_text(unit)
 subprocess.run(['systemctl','daemon-reload'],check=True)
 temp=LIB/'.current';temp.unlink(missing_ok=True);temp.symlink_to(target.name);os.replace(temp,LIB/'current')
 print(json.dumps({'staged':True,'build':build,'core_sha256':manifest['sha256']}))
def candidate(out):
 state=json.loads((BASE/'state.json').read_text());manifest=json.loads((LIB/'current/core_manifest.json').read_text())
 require(os.uname().machine in ('x86_64','amd64'),'This release validates accounting on Linux AMD64; other architectures retain the original CLI/core until separately validated')
 binary=LIB/'core-candidate';require(binary.is_file() and hashlib.sha256(binary.read_bytes()).hexdigest()==manifest['sha256'],'Run the complete standalone installer to stage its verified accounting core')
 if state.get('accounting',{}).get('enabled') and state['sing_box']['version']!=manifest['version']:
  # Product upgrade carrying a newer verified engine: the installed core was
  # verified against its recorded digest in preflight; move the pin forward.
  verify_installed_core(state,manifest,INSTALLED)
  state['sing_box']={**state['sing_box'],'version':manifest['version']}
 require(state['sing_box']['version']==manifest['version'],'Accounting activation requires the exact verified staged core version.')
 previous=state.get('accounting',{});state['accounting']={'enabled':True,'port':previous.get('port',25001),'poll_seconds':previous.get('poll_seconds',2),'failure_policy':previous.get('failure_policy','open'),'core_sha256':manifest['sha256'],'coverage':{p:True for p in ('reality','vmess','hy2','tuic','anytls')},'activated_at':previous.get('activated_at',time.time())}
 for user in state.get('managed_users',[]):user.setdefault('quota',quota_plan())
 atomic_json(Path(out),state,0o600)
if __name__=='__main__':
 require(os.geteuid()==0,'Root required',403)
 if sys.argv[1]=='stage':stage()
 elif sys.argv[1]=='preflight':preflight()
 elif sys.argv[1]=='candidate':candidate(sys.argv[2])
 else:raise SystemExit('Unknown accounting installer action')
