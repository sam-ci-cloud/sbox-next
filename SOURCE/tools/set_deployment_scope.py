#!/usr/bin/env python3
"""Preview/annotate deployment context before upgrading an older private preset.
Only server.scope changes. Apply creates an installed-manager native backup,
locks against manager mutations, checks the original state fingerprint and writes
atomically. It never regenerates configuration or restarts a service.
"""
import argparse,fcntl,hashlib,json,os,subprocess,tempfile
from pathlib import Path

def prepare(state,scope):
 if state.get('zgo_legacy_compat'):raise ValueError('Protected fixed-endpoint state retains its original deployment contract')
 result=json.loads(json.dumps(state));result['server']['scope']=scope;return result

def main():
 from product_version import identity
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--state',type=Path,default=Path('/etc/sbox-manager/state.json'));ap.add_argument('--scope',choices=['public','internal'],required=True);ap.add_argument('--apply',action='store_true');a=ap.parse_args();raw=a.state.read_bytes();original=json.loads(raw);candidate=prepare(original,a.scope)
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/'candidate.json';p.write_text(json.dumps(candidate));p.chmod(0o600);helper=Path(__file__).resolve().parents[1]/'src/state.py';r=subprocess.run(['python3',str(helper),'validate',str(p),'','/etc/sbox-manager/certs',identity()['version'],'2','1.12.0'],capture_output=True,text=True)
  if r.returncode:raise SystemExit(r.stderr or r.stdout)
 report={'scope_before':original['server'].get('scope','unspecified'),'scope_after':a.scope,'network_preset_unchanged':original['server'].get('mode','preserve'),'credentials_users_quotas_subscriptions_unchanged':True,'runtime_configuration_or_services_changed':False,'apply':a.apply}
 if not a.apply:print(json.dumps(report));return
 if os.geteuid()!=0 or a.state!=Path('/etc/sbox-manager/state.json') or a.state.is_symlink() or a.state.stat().st_uid!=0:raise SystemExit('Apply requires root and the original regular installed state path')
 pending=[Path('/var/lib/sbox-manager/transaction.json'),Path('/var/lib/sbox-manager/policy-transaction.json'),Path('/var/backups/sbox-manager/features.pending')]
 if any(p.exists() for p in pending):raise SystemExit('Recover pending transactions before annotating context')
 # The session lock excludes interactive manager mutation while the installed
 # backup command obtains its own manager lock; do not hold both across backup.
 session=os.open('/run/sbox-manager/session.lock',os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600);fcntl.flock(session,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  backup=subprocess.run(['/usr/local/bin/sbox','backup'],capture_output=True,text=True,timeout=120)
  if backup.returncode:raise SystemExit('Native backup failed; context not changed')
  report['native_backup']=backup.stdout.strip().splitlines()[-1]
  lock=os.open('/run/sbox-manager/manager.lock',os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   if any(p.exists() for p in pending):raise SystemExit('Recover pending transactions before annotating context')
   if a.state.read_bytes()!=raw:raise SystemExit('State changed since preview; nothing changed')
   fd,name=tempfile.mkstemp(prefix='.context-',dir=a.state.parent)
   try:
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as out:json.dump(candidate,out,ensure_ascii=False,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
    os.replace(name,a.state);d=os.open(a.state.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(d)
    finally:os.close(d)
   finally:Path(name).unlink(missing_ok=True)
  finally:os.close(lock)
 finally:os.close(session)
 print(json.dumps(report))
if __name__=='__main__':main()
