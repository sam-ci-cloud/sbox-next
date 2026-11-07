"""Run as panel UID so UI-controlled SQLite files are never opened as root."""
import json,os,sys,sqlite3,shutil
from pathlib import Path
from common import require
from store import Store
require(os.geteuid()!=0,'Run as the panel account')
if sys.argv[1]=='recover':
    root=Path('/var/lib/sbox-webui');source=root/'panel.db.before-migration';target=root/'panel.db'
    require(source.is_file() and not source.is_symlink(),'No safe database migration snapshot')
    with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as db:
        require(db.execute('PRAGMA quick_check').fetchone()[0]=='ok','Migration snapshot is corrupt')
    for suffix in ('-wal','-shm'):(root/('panel.db'+suffix)).unlink(missing_ok=True)
    shutil.copyfile(source,root/'.db-recover');os.chmod(root/'.db-recover',0o600);os.replace(root/'.db-recover',target)
store=Store('/var/lib/sbox-webui/panel.db')
if sys.argv[1]=='recover':
    with store.db() as db:db.execute('DELETE FROM subscriptions')
with store.db() as db:empty=db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]==0
secret=store.reset_password() if empty or sys.argv[1] in ('reset','recover') else None
print(json.dumps({'password':secret}))
