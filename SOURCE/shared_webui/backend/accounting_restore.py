"""Root-only lower-bound merge for an explicitly selected manager backup.
Never executes archived code, replaces live counters with smaller values, or
imports old portal sessions. All writes remain under the manager transaction lock.
"""
import argparse,json,math,os,re,sqlite3,time
from pathlib import Path
from accounting import MeterStore
from common import require
TABLES={'totals':('user_id','lifetime_up','lifetime_down','period_up','period_down','period_start','period_end','reset_seq','sampled_at','gap','status'),'protocol_totals':('user_id','protocol','up','down'),'hourly':('user_id','protocol','bucket','up','down'),'daily':('user_id','protocol','bucket','up','down')}
HISTORY_TABLES={'history_bins':('user_id','bucket','up','down'),'history_users':('user_id','started_at'),'history_coverage':('bucket','observed_seconds','first','last'),'history_gaps':('user_id','bucket'),'history_legacy':('user_id','resolution','bucket','up','down')}
HISTORY_LIMIT=200000

def history_schema(db):
 tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 present=tables&HISTORY_TABLES.keys()
 require(not present or present==HISTORY_TABLES.keys(),'Incomplete accounting history backup',503)
 for table in present:require(tuple(r[1] for r in db.execute('PRAGMA table_info('+table+')'))==HISTORY_TABLES[table],'Accounting history table mismatch',503)
 return bool(present)

def timestamp(value):
 return type(value) in (int,float) and math.isfinite(value) and 0<=value<2**53

def history_rows(db,table,ident=None):
 sql='SELECT * FROM '+table+(' WHERE user_id=?' if ident is not None else '')+' LIMIT ?'
 rows=db.execute(sql,(ident,HISTORY_LIMIT+1) if ident is not None else (HISTORY_LIMIT+1,)).fetchall()
 require(len(rows)<=HISTORY_LIMIT,'Accounting history exceeds import bound',503)
 return rows

def restore_history(db,archived,allowed):
 if not history_schema(archived):
  # Old UTC aggregates remain explicitly legacy, including when the live DB
  # already has newer local-date tracking and begin_history will not run again.
  for ident in sorted(allowed):
   for table,resolution in (('hourly','hour'),('daily','day')):
    rows=archived.execute('SELECT bucket,SUM(up) AS up,SUM(down) AS down FROM '+table+' WHERE user_id=? GROUP BY bucket LIMIT ?',(ident,HISTORY_LIMIT+1)).fetchall()
    require(len(rows)<=HISTORY_LIMIT,'Accounting history exceeds import bound',503)
    for row in rows:
     require(type(row['bucket']) is int and row['bucket']>=0 and all(type(row[k]) is int and 0<=row[k]<2**63 for k in ('up','down')),'Invalid archived UTC history',503)
     db.execute('INSERT INTO history_legacy VALUES(?,?,?,?,?) ON CONFLICT(user_id,resolution,bucket) DO UPDATE SET up=MAX(up,excluded.up),down=MAX(down,excluded.down)',(ident,resolution,row['bucket'],row['up'],row['down']))
  return
 starts=[]
 for ident in sorted(allowed):
  for row in history_rows(archived,'history_users',ident):
   require(timestamp(row['started_at']),'Invalid archived history start',503);starts.append(row['started_at'])
   db.execute('INSERT INTO history_users VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET started_at=MIN(started_at,excluded.started_at)',(ident,row['started_at']))
  for table in ('history_bins','history_gaps','history_legacy'):
   columns=HISTORY_TABLES[table]
   for row in history_rows(archived,table,ident):
    resolution=row['resolution'] if table=='history_legacy' else None
    require(resolution is None or resolution in ('hour','day'),'Invalid archived history resolution',503)
    interval=3600 if resolution=='hour' else 86400 if resolution=='day' else 900
    require(type(row['bucket']) is int and row['bucket']>=0 and row['bucket']%interval==0,'Invalid archived history bucket',503)
    if table!='history_gaps':require(all(type(row[k]) is int and 0<=row[k]<2**63 for k in ('up','down')),'Invalid archived history counter',503)
    conflict='user_id,resolution,bucket' if table=='history_legacy' else 'user_id,bucket'
    update='DO NOTHING' if table=='history_gaps' else 'DO UPDATE SET up=MAX(up,excluded.up),down=MAX(down,excluded.down)'
    db.execute('INSERT INTO '+table+'('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+') ON CONFLICT('+conflict+') '+update,tuple(row[k] for k in columns))
 for row in history_rows(archived,'history_coverage'):
  bucket=row['bucket'];observed=row['observed_seconds'];first=row['first'];last=row['last']
  require(type(bucket) is int and bucket>=0 and bucket%900==0 and all(timestamp(x) for x in (observed,first,last)) and bucket<=first<=last<=bucket+900 and observed<=last-first,'Invalid archived history coverage',503)
  # Aggregate rows do not identify the exact observed subintervals. MAX is a
  # conservative union lower bound; adding seconds could invent full coverage
  # when live and archived observations overlap. Keep the enclosing interval.
  db.execute('INSERT INTO history_coverage VALUES(?,?,?,?) ON CONFLICT(bucket) DO UPDATE SET observed_seconds=MAX(observed_seconds,excluded.observed_seconds),first=MIN(first,excluded.first),last=MAX(last,excluded.last)',(bucket,observed,first,last))
 tracked=archived.execute("SELECT value FROM meta WHERE key='history_tracking_started_at'").fetchone()
 if tracked:
  started=float(tracked[0]);require(timestamp(started),'Invalid archived tracking start',503);starts.append(started)
 if starts:
  current=db.execute("SELECT value FROM meta WHERE key='history_tracking_started_at'").fetchone()
  if current:
   started=float(current[0]);require(timestamp(started),'Invalid current tracking start',503);starts.append(started)
  db.execute("INSERT INTO meta VALUES('history_tracking_started_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(min(starts)),))

def validate(path):
 path=Path(path);require(path.is_file() and not path.is_symlink() and path.stat().st_size<=600*1024**2,'Missing/unsafe accounting backup',503)
 db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
 try:
  require(db.execute('PRAGMA quick_check').fetchone()[0]=='ok' and db.execute('PRAGMA user_version').fetchone()[0]==1,'Incompatible accounting backup',503)
  for table,columns in TABLES.items():require(tuple(r['name'] for r in db.execute('PRAGMA table_info('+table+')'))==columns,'Accounting backup table mismatch',503)
  history_schema(db)
 finally:db.close()
def merge(path,state,destination='/var/lib/sbox-accounting/usage.db'):
 # The protected original shares one StatsService name across Hysteria2 and
 # AnyTLS; the collector records it once as 'legacy_shared' (see accounting.py).
 # Only the protected legacy identity may carry that combined counter.
 shared=('legacy_shared',) if state.get('zgo_legacy_compat') else ()
 def protocols_for(ident):return ('reality','vmess','hy2','tuic','anytls')+(shared if ident=='legacy' else ())
 validate(path);allowed={'legacy'}|{u['id'] for u in state.get('managed_users',[])};store=MeterStore(destination);archived=sqlite3.connect('file:'+str(Path(path))+'?mode=ro',uri=True);archived.row_factory=sqlite3.Row;count=0
 try:
  with store.db() as db:
   db.execute('BEGIN IMMEDIATE')
   for ident in sorted(allowed):
    row=archived.execute('SELECT * FROM totals WHERE user_id=?',(ident,)).fetchone()
    if row is None:continue
    v=dict(row)
    for key in ('lifetime_up','lifetime_down','period_up','period_down','reset_seq'):require(type(v[key]) is int and 0<=v[key]<2**63,'Invalid archived counter',503)
    current=db.execute('SELECT * FROM totals WHERE user_id=?',(ident,)).fetchone()
    if current:
     same_cycle=current['period_start']==v['period_start'] and current['reset_seq']==v['reset_seq']
     db.execute('UPDATE totals SET lifetime_up=MAX(lifetime_up,?),lifetime_down=MAX(lifetime_down,?),period_up=MAX(period_up,?),period_down=MAX(period_down,?),gap=1 WHERE user_id=?',(v['lifetime_up'],v['lifetime_down'],v['period_up'] if same_cycle else 0,v['period_down'] if same_cycle else 0,ident))
    else:
     v['gap']=1;db.execute('INSERT INTO totals('+','.join(TABLES['totals'])+') VALUES('+','.join('?' for _ in v)+')',tuple(v[k] for k in TABLES['totals']))
    count+=1
    for table in ('protocol_totals','hourly','daily'):
     cols=TABLES[table];limit=10000 if table=='protocol_totals' else 200000
     rows=archived.execute('SELECT '+','.join(cols)+' FROM '+table+' WHERE user_id=? LIMIT ?',(ident,limit+1)).fetchall();require(len(rows)<=limit,'Accounting history exceeds import bound',503)
     for history in rows:
      require(history['protocol'] in protocols_for(ident) and all(type(history[k]) is int and 0<=history[k]<2**63 for k in ('up','down')),'Invalid archived protocol counter',503)
      conflict='user_id,protocol' if table=='protocol_totals' else 'user_id,protocol,bucket';db.execute('INSERT INTO '+table+'('+','.join(cols)+') VALUES('+','.join('?' for _ in cols)+') ON CONFLICT('+conflict+') DO UPDATE SET up=MAX(up,excluded.up),down=MAX(down,excluded.down)',tuple(history[k] for k in cols))
   restore_history(db,archived,allowed)
   # Restoring never establishes collector continuity with an archived sample.
   # The next live ingest must observe a fresh interval before claiming coverage.
   db.execute("DELETE FROM meta WHERE key='history_last_sample'")
   # Restored state may contain older credential generations. Requiring a fresh
   # portal login prevents resurrection of sessions from a historical backup.
   db.execute('DELETE FROM portal_sessions')
   db.execute("INSERT INTO meta VALUES('last_restore',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps({'at':time.time(),'source':'Explicit manager backup; merged lower bounds, collection gap recorded','users':count}),))
 finally:archived.close()
 return {'restored_usage_identities':count,'existing_usage':'never reduced','collection_gap':True,'portal_sessions':'revoked; fresh login required'}
if __name__=='__main__':
 require(os.geteuid()==0,'Root required',403);ap=argparse.ArgumentParser();ap.add_argument('action',choices=['validate','merge']);ap.add_argument('database');ap.add_argument('state',nargs='?');a=ap.parse_args()
 if a.action=='validate':validate(a.database);print('Accounting backup validated')
 else:print(json.dumps(merge(a.database,json.loads(Path(a.state).read_text()))))
