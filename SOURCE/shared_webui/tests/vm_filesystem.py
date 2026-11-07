# DISPOSABLE-LAB-GUARD
import os as _lab_os
from pathlib import Path as _LabPath
_lab_marker = _LabPath('/opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS')
if _lab_os.geteuid() != 0 or _lab_marker.is_symlink() or not _lab_marker.is_file() or _lab_marker.stat().st_uid != 0:
    raise SystemExit('Root in an explicitly marked disposable VM is required; never run on production')
from pathlib import Path
import subprocess,hashlib,json,time,os,signal,datetime,sys,traceback
P=Path;installer=sys.argv[1];source_path=sys.argv[2];domain=json.loads(P('/etc/sbox-manager/state.json').read_text())['domain'];root=P('/opt/sbox-lab');assert (root/'ALLOW_DESTRUCTIVE_TESTS').exists();rows=[]
def run(a,timeout=120,env=None):return subprocess.run(a,capture_output=True,text=True,timeout=timeout,env=env)
def cmd(a,timeout=120):
 p=run(a,timeout);assert p.returncode==0,p.stderr[-400:];return p.stdout

def test(name,fn):
 if os.environ.get('SBOX_FS_CASE') and os.environ['SBOX_FS_CASE']!=name:return
 try:r=fn();d={'test':name,'status':'PASS','detail':r}
 except Exception as e:d={'test':name,'status':'FAIL','error':str(e)[:500],'trace':traceback.format_exc()[-2000:]}
 rows.append(d);print(json.dumps(d),flush=True);(root/'fs-negative.json').write_text(json.dumps(rows,indent=2)+'\n');assert d['status']=='PASS'
def pid():return cmd(['systemctl','show','sing-box','-p','MainPID','--value']).strip()
def concurrent():
 cmd(['sbox','firewall','apply']);assert json.loads(cmd(['sbox','doctor','--json']))['failures']==0
 old=pid();zgo=bool(json.loads(P('/etc/sbox-manager/state.json').read_text()).get('zgo_legacy_compat'));args=[] if zgo else ['client-policy','apply'];a=subprocess.Popen(['bash',installer,*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);time.sleep(.2);b=run(['bash',installer,*args]);_,err=a.communicate(timeout=40)
 codes=sorted([a.returncode,b.returncode]);assert codes in ([0,1],[0,0]) and old==pid(),(codes,err[-200:],b.stderr[-200:]);assert not zgo or codes==[0,1],codes
 if 1 in codes:assert 'Another sbox session' in err+b.stderr

 return {'exit_codes':sorted([a.returncode,b.returncode]),'pid_unchanged':True}
backup=cmd(['sbox','backup']).strip()
protocols_before=json.loads(P('/etc/sbox-manager/state.json').read_text())['protocols']
test('concurrent_outer_installers',concurrent)
source=P(source_path).read_text().removesuffix('main "$@"\n')
def funcs(body):
 p=root/'isolated-functional-check.sh';p.write_text(source+'\n'+body);p.chmod(0o700);return run(['bash',str(p)])
def apt_lock():
 ready=root/'apt-ready';ready.unlink(missing_ok=True)
 code='import fcntl,time;from pathlib import Path;f=open("/var/lib/dpkg/lock-frontend","a");fcntl.lockf(f,fcntl.LOCK_EX);Path("/opt/sbox-lab/apt-ready").touch();time.sleep(2)'
 holder=subprocess.Popen(['python3','-c',code]);end=time.monotonic()+5
 while not ready.exists() and time.monotonic()<end:time.sleep(.05)
 t=time.monotonic();p=funcs('apt_run install -y jq\n');holder.wait();assert p.returncode==0,p.stderr[-400:]
 return {'active_posix_lock_released_after_s':2,'apt_elapsed_s':round(time.monotonic()-t,3),'exit':p.returncode}
test('apt_waits_real_package_lock',apt_lock)
def noexec():
 d=root/'noexec';d.mkdir(exist_ok=True);cmd(['mount','-t','tmpfs','-o','size=1m,mode=700,noexec','tmpfs',str(d)])
 try:
  p=funcs('EXEC_WORK_DIR=/opt/sbox-lab/noexec\nensure_exec_work_dir\n[ "$EXEC_WORK_DIR" != /opt/sbox-lab/noexec ]\n');assert p.returncode==0,p.stderr[-400:]
 finally:cmd(['umount',str(d)])
 return 'actual noexec mount rejected; trusted executable fallback selected'
test('actual_noexec_staging_fallback',noexec)
def full():
 d=root/'full';d.mkdir(exist_ok=True);cmd(['mount','-t','tmpfs','-o','size=1m,mode=700','tmpfs',str(d)])
 try:
  with (d/'fill').open('wb',buffering=0) as f:
   try:
    while True:f.write(b'x'*4096);f.flush()
   except OSError:pass
  p=run(['bash',installer,'version'],env={**os.environ,'TMPDIR':str(d)});assert p.returncode!=0 and 'No space left' in p.stderr
 finally:cmd(['umount',str(d)])
 return 'real ENOSPC bootstrap failed nonzero before payload execution'
test('actual_full_temporary_filesystem',full)
def certs():
 from cryptography import x509
 from cryptography.hazmat.primitives import serialization,hashes
 from cryptography.hazmat.primitives.asymmetric import ec
 from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
 ca=x509.load_pem_x509_certificate((root/'ca/ca.crt').read_bytes());cakey=serialization.load_pem_private_key((root/'ca/ca.key').read_bytes(),None)
 d=root/('certificate-negatives-'+str(time.time_ns()));d.mkdir(exist_ok=True);key=ec.generate_private_key(ec.SECP256R1());kp=d/'key';kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));kp.chmod(0o600)
 now=datetime.datetime.now(datetime.timezone.utc)
 specs=[('expired',domain,now-datetime.timedelta(days=3),now-datetime.timedelta(days=1),ExtendedKeyUsageOID.SERVER_AUTH),('wrong-domain','different.example.test',now-datetime.timedelta(hours=1),now+datetime.timedelta(days=5),ExtendedKeyUsageOID.SERVER_AUTH),('wrong-eku',domain,now-datetime.timedelta(hours=1),now+datetime.timedelta(days=5),ExtendedKeyUsageOID.CLIENT_AUTH),('valid-new-pair',domain,now-datetime.timedelta(hours=1),now+datetime.timedelta(days=10),ExtendedKeyUsageOID.SERVER_AUTH)]
 old=pid();original=json.loads(P('/etc/sbox-manager/state.json').read_text())['protocols']
 outcomes=[]
 for name,leaf_domain,start,end,eku in specs:
  cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,leaf_domain)])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end).add_extension(x509.SubjectAlternativeName([x509.DNSName(leaf_domain)]),False).add_extension(x509.ExtendedKeyUsage([eku]),False).sign(cakey,hashes.SHA256()))
  cp=d/(name+'.pem');cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
  p=run(['sbox','certificate','--cert','existing','--cert-path',str(cp),'--key-path',str(kp),'--yes']);expected=0 if name=='valid-new-pair' else 1;assert (p.returncode==0)==(expected==0),(name,p.stderr[-300:])
  assert json.loads(P('/etc/sbox-manager/state.json').read_text())['protocols']==original
  if expected:assert pid()==old and not P('/var/lib/sbox-manager/transaction.json').exists(),(name,pid(),old,P('/var/lib/sbox-manager/transaction.json').exists())
  outcomes.append({'case':name,'exit':p.returncode})
 # A mismatched private key is refused in certificate planning too.
 wrong=d/'wrong-key';wrong.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));wrong.chmod(0o600)
 p=run(['sbox','certificate','--cert','existing','--cert-path',str(cp),'--key-path',str(wrong),'--yes']);assert p.returncode!=0
 outcomes.append({'case':'mismatched-key','exit':p.returncode})
 assert json.loads(cmd(['sbox','doctor','--json']))['failures']==0
 return outcomes
test('real_certificate_negatives_and_new_pair',certs)

cmd(['sbox','restore',backup,'--force']);assert json.loads(P('/etc/sbox-manager/state.json').read_text())['protocols']==protocols_before
print('PASS original state and certificate restored after filesystem negatives',flush=True)
