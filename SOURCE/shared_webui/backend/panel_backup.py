"""Root backup/restore of panel accounts, MFA, subscriptions and preferences.
The manager's authenticated manifest covers this optional component. Browser
sessions and API tokens are revoked on an explicit historical data restore.
"""
from pathlib import Path
import json,os,pwd,shutil,sqlite3,subprocess,sys,tempfile
from common import require,SCHEMA
import ipaddress
from network_policy import panel_apply
from subscription_vault import KEY_NAME,read_key,key_id
DATABASE=Path('/var/lib/sbox-webui/panel.db')

def validate(path,require_pair=True):
 path=Path(path)
 require(path.is_file() and not path.is_symlink() and path.stat().st_size<=128*1024**2,'Unsafe/missing panel database backup',503)
 db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
 try:
  require(db.execute('PRAGMA quick_check').fetchone()[0]=='ok' and db.execute('PRAGMA user_version').fetchone()[0]==SCHEMA,'Invalid/incompatible panel database backup',503)
  tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
  require({'accounts','sessions','subscriptions','tokens','settings'}<=tables,'Incomplete panel database backup',503)
  if require_pair and 'subscription_recovery' in tables:
   expected={r[0] for r in db.execute('SELECT DISTINCT key_id FROM subscription_recovery')}
   if expected:
    try:key=read_key(path.parent/KEY_NAME,path.stat().st_uid)
    except OSError:require(False,'Matching subscription key is required',503)
    require(expected=={key_id(key)},'Subscription backup key does not match database',503)
 finally:db.close()

def snapshot(destination,source=DATABASE,require_pair=True):
 source=Path(source)
 if not source.exists():return False
 validate(source,require_pair);target=Path(destination)/'panel';target.mkdir(mode=0o700);out=target/'panel.db'
 db=sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)
 try:
  copy=sqlite3.connect(out)
  try:db.backup(copy)
  finally:copy.close()
 finally:db.close()
 out.chmod(0o600)
 keypath=source.parent/KEY_NAME
 if keypath.exists() or keypath.is_symlink():
  value=read_key(keypath,source.stat().st_uid)
  fd=os.open(target/KEY_NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
 settings=Path('/etc/sbox-webui/settings.json')
 if settings.is_file() and not settings.is_symlink():
  cfg=json.loads(settings.read_text());network=target/'network.json';network.write_text(json.dumps({'listen':cfg['listen'],'port':cfg['port']}));network.chmod(0o600)
 validate(out,require_pair)
 with out.open('rb') as f:os.fsync(f.fileno())
 return True

def network_record(path):
 p=Path(path).parent/'network.json'
 if not p.exists():return None
 require(not p.is_symlink() and p.stat().st_size<1024,'Unsafe network backup',503)
 record=json.loads(p.read_text());require(set(record)=={'listen','port'} and type(record['port']) is int,'Invalid network backup',503)
 address=ipaddress.ip_address(record['listen']);require(not address.is_multicast and not getattr(address,'ipv4_mapped',None),'Invalid backup listener',503)
 return record

def restore(source):
 archived=Path(source)/'panel/panel.db'
 if not archived.exists():return False  # Earlier backups retain the live panel.
 validate(archived);network=network_record(archived);settings=Path('/etc/sbox-webui/settings.json');old_network=json.loads(settings.read_text()) if settings.exists() else None
 if network and old_network:require(network['port']==old_network['port'],'Restore panel port separately before restoring this network snapshot',503)
 require(DATABASE.is_file() and not DATABASE.is_symlink(),'Install the panel before restoring its data',503)
 user=pwd.getpwnam('sbox-webui');root=Path('/var/lib/sbox-webui-control');require(not root.is_symlink(),'Unsafe panel restore namespace',503);root.mkdir(mode=0o700,exist_ok=True)
 require(root.stat().st_uid==0 and not root.stat().st_mode&0o077,'Unsafe panel restore owner/mode',503)
 with tempfile.TemporaryDirectory(prefix='panel-restore-',dir=root) as td:
  # A missing/mismatched live key is precisely why a paired restore may be
  # needed. Keep its pre-restore DB and any safe existing key for rollback;
  # only the incoming archive must form a recoverable pair. Public snapshots
  # always retain the strict default validation above.
  saved=Path(td);snapshot(saved,require_pair=False);subprocess.run(['systemctl','stop','sbox-webui','sbox-webui-control'],check=True)
  def replace_file(path,destination):
   fd,name=tempfile.mkstemp(prefix='.restore-panel-',dir=DATABASE.parent);stage=Path(name)
   try:
    with os.fdopen(fd,'wb') as target,path.open('rb') as source:
     shutil.copyfileobj(source,target);target.flush();os.fchmod(target.fileno(),0o600);os.fchown(target.fileno(),user.pw_uid,user.pw_gid);os.fsync(target.fileno())
    os.replace(stage,destination)
   finally:stage.unlink(missing_ok=True)
  def replace(path):
   for suffix in ('-wal','-shm'):Path(str(DATABASE)+suffix).unlink(missing_ok=True)
   replace_file(path,DATABASE)
   archived_key=path.parent/KEY_NAME;live_key=DATABASE.parent/KEY_NAME
   if archived_key.exists():replace_file(archived_key,live_key)
   else:live_key.unlink(missing_ok=True)
  try:
   replace(archived)
   # Run SQL as the panel user, never execute archived code or SQL as root.
   code="import sqlite3;d=sqlite3.connect('/var/lib/sbox-webui/panel.db');d.execute('DELETE FROM sessions');d.execute('DELETE FROM tokens');d.commit();d.close()"
   subprocess.run(['runuser','-u','sbox-webui','--','python3','-I','-c',code],check=True)
   subprocess.run(['systemctl','restart','sbox-webui-control','sbox-webui'],check=True)
   if network:panel_apply(json.loads(Path('/etc/sbox-manager/state.json').read_text()),forced=network['listen'])
  except Exception:
   subprocess.run(['systemctl','stop','sbox-webui','sbox-webui-control'],check=False);replace(saved/'panel/panel.db');
   if old_network:panel_apply(json.loads(Path('/etc/sbox-manager/state.json').read_text()),forced=old_network['listen'])
   subprocess.run(['systemctl','restart','sbox-webui-control','sbox-webui'],check=True);raise
 return True
if __name__=='__main__':
 require(os.geteuid()==0,'Root required',403)
 action,path=sys.argv[1:]
 if action=='snapshot':print('Panel database included in private backup.' if snapshot(path) else 'No installed panel database to include.')
 elif action=='validate':validate(Path(path)/'panel/panel.db')
 elif action=='restore':print('Panel restored; accounts/MFA/subscriptions/preferences retained, sessions/API tokens revoked.' if restore(path) else 'Historical backup has no panel database; live panel retained.')
 else:raise SystemExit('Unknown panel backup action')
