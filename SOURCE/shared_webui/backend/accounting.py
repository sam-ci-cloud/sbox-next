"""Root-owned authenticated VPN accounting, calendar quotas and usage-only sessions.
No NIC totals enter this database. Counters are sampled without resetting them;
watermarks, deltas and aggregates commit in the same SQLite transaction.
"""
import argparse,contextlib,fcntl,grp,hashlib,hmac,json,os
from pathlib import Path
import re,secrets,sqlite3,subprocess,sys,time
from common import Problem,require,password_hash,password_ok,digest,token,atomic_json
from quota_models import quota_plan,quota_boundaries,quota_status
from stats_rpc import query
from usage_history import record_coverage,begin_history
SOURCE='sing-box V2Ray StatsService: authenticated routed payload; excludes host/provider overhead'
PROTOS=('reality','vmess','hy2','tuic','anytls')
DEFAULT_DATA=Path('/var/lib/sbox-accounting')

def effective_poll_seconds(state):
 # Limited or expiring users need a tighter sampling bound. Unlimited installs
 # retain their configured cadence. The core guard independently checks at 100ms.
 interval=max(1,min(int(state.get('accounting',{}).get('poll_seconds',2)),60))
 for user in state.get('managed_users',[]):
  plan=user.get('quota',{})
  if user.get('enabled',True) and (plan.get('quota_bytes',0) or plan.get('expires_at',0)):
   return 1
 return interval

def root_json(path,value,gid=None):
 path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);temp=path.parent/('.meter-'+secrets.token_hex(12));fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640 if gid is not None else 0o600)
 try:
  os.fchmod(fd,0o640 if gid is not None else 0o600)
  if gid is not None:os.fchown(fd,0,gid)
  with os.fdopen(fd,'w') as stream:json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
  os.replace(temp,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:temp.unlink(missing_ok=True)

def identities(state):
 result={};tags={'reality':'reality','vmess':'vmess','hy2':'hy2','tuic':'tuic','anytls':'anytls'}
 for p,name in tags.items():
  if state['protocols'].get(p,{}).get('enabled'):result[name]=('legacy',p)
 # The original protected Hysteria2 and AnyTLS entries both use the internal
 # name 'sbox'. Keep their wire/config identities and count the actual combined
 # StatsService measurement once; it cannot honestly be split by protocol.
 if state.get('zgo_legacy_compat') and any(state['protocols'].get(p,{}).get('enabled') for p in ('hy2','anytls')):
  result['sbox']=('legacy','legacy_shared')
 for user in state.get('managed_users',[]):
  for p in user['protocols']:result['user-'+user['id']+'@'+p]=(user['id'],p)
 return result

class MeterStore:
 def __init__(self,path):
  self.path=Path(path);self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  require(not self.path.is_symlink(),'Unsafe accounting database',503)
  with self.db() as db:
   check=db.execute('PRAGMA quick_check').fetchone()[0];require(check=='ok','Accounting database integrity failure',503)
   require(db.execute('PRAGMA user_version').fetchone()[0]<=1,'Accounting database schema is newer than this engine',503)
   db.executescript('''
   CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS watermarks(instance TEXT,tag TEXT,up INTEGER NOT NULL,down INTEGER NOT NULL,stamp REAL NOT NULL,PRIMARY KEY(instance,tag));
   CREATE TABLE IF NOT EXISTS totals(user_id TEXT PRIMARY KEY,lifetime_up INTEGER NOT NULL DEFAULT 0,lifetime_down INTEGER NOT NULL DEFAULT 0,period_up INTEGER NOT NULL DEFAULT 0,period_down INTEGER NOT NULL DEFAULT 0,period_start REAL,period_end REAL,reset_seq INTEGER NOT NULL DEFAULT 0,sampled_at REAL,gap INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'active');
   CREATE TABLE IF NOT EXISTS meter_deltas(id INTEGER PRIMARY KEY,user_id TEXT,protocol TEXT,up INTEGER,down INTEGER,collected_at REAL,instance TEXT,counter_sequence TEXT UNIQUE,source TEXT);
   CREATE TABLE IF NOT EXISTS protocol_totals(user_id TEXT,protocol TEXT,up INTEGER,down INTEGER,PRIMARY KEY(user_id,protocol));
   CREATE TABLE IF NOT EXISTS hourly(user_id TEXT,protocol TEXT,bucket INTEGER,up INTEGER,down INTEGER,PRIMARY KEY(user_id,protocol,bucket));
   CREATE TABLE IF NOT EXISTS daily(user_id TEXT,protocol TEXT,bucket INTEGER,up INTEGER,down INTEGER,PRIMARY KEY(user_id,protocol,bucket));
   CREATE TABLE IF NOT EXISTS events(key TEXT PRIMARY KEY,time REAL NOT NULL,user_id TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS portal_sessions(hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,generation TEXT NOT NULL,csrf TEXT NOT NULL,created REAL NOT NULL,seen REAL NOT NULL,expires REAL NOT NULL);
   CREATE TABLE IF NOT EXISTS portal_attempts(key TEXT PRIMARY KEY,started REAL,count INTEGER);
   PRAGMA user_version=1;
   ''')
  with self.db() as db:
   if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='history_bins'").fetchone():
    backup=Path(str(self.path)+'.before-history-v1');require(not backup.is_symlink(),'Unsafe history migration backup',503)
    target=sqlite3.connect(backup)
    try:db.backup(target)
    finally:target.close()
    backup.chmod(0o600)
   db.executescript('''
   CREATE TABLE IF NOT EXISTS history_bins(user_id TEXT,bucket INTEGER,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(user_id,bucket));
   CREATE TABLE IF NOT EXISTS history_legacy(user_id TEXT,resolution TEXT,bucket INTEGER,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(user_id,resolution,bucket));
   CREATE TABLE IF NOT EXISTS history_users(user_id TEXT PRIMARY KEY,started_at REAL NOT NULL);
   CREATE TABLE IF NOT EXISTS history_coverage(bucket INTEGER PRIMARY KEY,observed_seconds REAL NOT NULL,first REAL NOT NULL,last REAL NOT NULL);
   CREATE TABLE IF NOT EXISTS history_gaps(user_id TEXT,bucket INTEGER,PRIMARY KEY(user_id,bucket));
   CREATE TABLE IF NOT EXISTS feature_migrations(name TEXT PRIMARY KEY,applied_at REAL NOT NULL);
   INSERT OR IGNORE INTO feature_migrations VALUES('history-v1',CAST(strftime('%s','now') AS REAL));
   ''')
  self.path.chmod(0o600)
 @contextlib.contextmanager
 def db(self):
  db=sqlite3.connect(self.path,timeout=3)
  try:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA busy_timeout=3000');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
   with db:yield db
  finally:db.close()
 def metadata(self,key,default=None):
  with self.db() as db:
   r=db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone();return json.loads(r[0]) if r else default
 def ingest(self,state,instance,counters,now=None):
  now=time.time() if now is None else now;mapping=identities(state);users={u['id']:u for u in state.get('managed_users',[])};users['legacy']={'id':'legacy','enabled':True,'quota':{'period':'none'}}
  blocked=[];limits={}
  with self.db() as db:
   db.execute("INSERT OR IGNORE INTO meta VALUES('metering_started_at',?)",(json.dumps(now),))
   old=db.execute("SELECT value FROM meta WHERE key='sample'").fetchone();old=json.loads(old[0]) if old else {};logical=max(now,old.get('logical_time',now));new_instance=bool(old.get('instance') and old['instance']!=instance);clock_back=logical>now+1
   begin_history(db,users,logical)
   changes={i:[0,0] for i in users};gaps=set(users) if new_instance else set();period_replaced=set()
   if 'sbox' in mapping:
    migrated=db.execute('INSERT OR IGNORE INTO feature_migrations VALUES(?,?)',('legacy-shared-stats-v1',logical)).rowcount
    if migrated:
     # Earlier coverage did not observe this combined identity. Preserve known
     # bytes while disclosing incomplete legacy intervals; never invent a split.
     db.execute("INSERT OR IGNORE INTO history_gaps SELECT 'legacy',bucket FROM history_coverage WHERE bucket>=? AND bucket<=?",(logical-91*86400,logical))
     gaps.add('legacy')
   marks={r['tag']:r for r in db.execute('SELECT tag,up,down FROM watermarks WHERE instance=?',(instance,))}
   for ident,user in users.items():
    p=quota_plan(user.get('quota'));r=db.execute('SELECT * FROM totals WHERE user_id=?',(ident,)).fetchone();start,end=quota_boundaries(logical,p)
    if r is None:
     db.execute('INSERT INTO totals(user_id,period_start,period_end,reset_seq) VALUES(?,?,?,?)',(ident,start if start is not None else logical,end,p['reset_seq']))
    elif p['reset_seq']>r['reset_seq'] or (r['period_end'] is not None and logical>=r['period_end']):
     # A missed boundary has no trustworthy split of its spanning delta. Lifetime
     # retains it; the new cycle starts from a conservative measured lower bound.
     if old.get('logical_time',logical)<(r['period_end'] or logical) and old.get('logical_time',logical)<logical:period_replaced.add(ident)
     db.execute('UPDATE totals SET period_up=0,period_down=0,period_start=?,period_end=?,reset_seq=? WHERE user_id=?',(start if start is not None else logical,end,max(p['reset_seq'],r['reset_seq']),ident))
    elif end!=r['period_end']:
     # Changing plan/timezone/reset-day does not erase already charged bytes.
     db.execute('UPDATE totals SET period_end=? WHERE user_id=?',(end,ident))
   for tag,(ident,proto) in mapping.items():
    up=counters.get('user>>>'+tag+'>>>traffic>>>uplink',0);down=counters.get('user>>>'+tag+'>>>traffic>>>downlink',0)
    require(type(up) is int and type(down) is int and 0<=up<2**63 and 0<=down<2**63,'Invalid authenticated counter sample',503)
    previous=marks.get(tag)
    if not previous and not up and not down:continue
    if previous and (up<previous['up'] or down<previous['down']):du=dd=0;gaps.add(ident)
    else:du=up-(previous['up'] if previous else 0);dd=down-(previous['down'] if previous else 0)
    if new_instance:gaps.add(ident)
    if not previous or up!=previous['up'] or down!=previous['down']:db.execute('INSERT INTO watermarks VALUES(?,?,?,?,?) ON CONFLICT(instance,tag) DO UPDATE SET up=excluded.up,down=excluded.down,stamp=excluded.stamp',(instance,tag,up,down,logical))
    if not (du or dd):continue
    sequence=hashlib.sha256((instance+'|'+tag+'|'+str(up)+'|'+str(down)).encode()).hexdigest()
    inserted=db.execute('INSERT OR IGNORE INTO meter_deltas(user_id,protocol,up,down,collected_at,instance,counter_sequence,source) VALUES(?,?,?,?,?,?,?,?)',(ident,proto,du,dd,logical,instance,sequence,SOURCE)).rowcount
    require(inserted==1,'Duplicate meter delta/watermark inconsistency',503)
    changes[ident][0]+=du;changes[ident][1]+=dd
    db.execute('INSERT INTO protocol_totals VALUES(?,?,?,?) ON CONFLICT(user_id,protocol) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(ident,proto,du,dd))
    db.execute('INSERT INTO history_bins VALUES(?,?,?,?) ON CONFLICT(user_id,bucket) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(ident,int(logical)//900*900,du,dd))
    for table,size in [('hourly',3600),('daily',86400)]:db.execute('INSERT INTO '+table+' VALUES(?,?,?,?,?) ON CONFLICT(user_id,protocol,bucket) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(ident,proto,int(logical)//size*size,du,dd))
   for ident,user in users.items():
    du,dd=changes[ident];pu,pd=(0,0) if ident in period_replaced else (du,dd)
    if du or dd or ident in gaps or ident in period_replaced or clock_back:db.execute('UPDATE totals SET lifetime_up=lifetime_up+?,lifetime_down=lifetime_down+?,period_up=period_up+?,period_down=period_down+?,sampled_at=?,gap=MAX(gap,?) WHERE user_id=?',(du,dd,pu,pd,logical,int(ident in gaps or ident in period_replaced or clock_back),ident))
    else:db.execute('UPDATE totals SET sampled_at=? WHERE user_id=? AND sampled_at IS NULL',(logical,ident))
    row=db.execute('SELECT * FROM totals WHERE user_id=?',(ident,)).fetchone();p=quota_plan(user.get('quota'));used=row['period_up']+row['period_down'];status='protected_legacy' if ident=='legacy' else quota_status(user,used,logical)
    if row['status']!=status:db.execute('UPDATE totals SET status=? WHERE user_id=?',(status,ident))
    if status not in ['active','protected_legacy']:
     blocked.extend(tag for tag,(owner,_) in mapping.items() if owner==ident)
    elif ident!='legacy' and p['quota_bytes']:
     # Byte budget for the core guard: the absolute value of this user's own
     # up+down core counters (this sample) at which the quota is exhausted.
     # The core checks it every 100 ms, independent of this polling cycle.
     sampled=sum(counters.get('user>>>'+tag+'>>>traffic>>>'+d,0) for tag,(owner,_) in mapping.items() if owner==ident for d in ('uplink','downlink'))
     limits['user-'+ident]=sampled+max(0,p['quota_bytes']-used)
    if ident!='legacy':
     for percent in [80,95,100]:
      if p['quota_bytes'] and used*100>=p['quota_bytes']*percent:
       key=ident+':'+str(row['period_start'])+':'+str(p['reset_seq'])+':'+str(percent);db.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)',(key,logical,ident,'critical' if percent==100 else 'warning','Quota reached '+str(percent)+'%'))
     if status=='expired':db.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)',(ident+':expiry:'+str(p['expires_at']),logical,ident,'critical','Account expired'))
   record_coverage(db,users,old,logical,now,effective_poll_seconds(state),new_instance,gaps|set(users) if clock_back else gaps)
   for table in ('history_bins','history_coverage','history_gaps','history_legacy'):db.execute('DELETE FROM '+table+' WHERE bucket<?',(int(logical)-91*86400,))
   sample={'instance':instance,'sampled_at':now,'logical_time':logical,'source':SOURCE,'clock_moved_backwards':clock_back,'core_discontinuity':new_instance,'health':'ok','counter_count':len(counters)}
   db.execute("INSERT INTO meta VALUES('sample',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(sample),))
   db.execute('DELETE FROM hourly WHERE bucket<?',(int(logical)-7*86400,));db.execute('DELETE FROM daily WHERE bucket<?',(int(logical)-90*86400,));db.execute('DELETE FROM meter_deltas WHERE id<(SELECT MAX(id)-100000 FROM meter_deltas)');db.execute('DELETE FROM events WHERE key IN (SELECT key FROM events ORDER BY time DESC LIMIT -1 OFFSET 10000)')
   db.execute('DELETE FROM watermarks WHERE instance NOT IN (SELECT instance FROM watermarks GROUP BY instance ORDER BY MAX(stamp) DESC LIMIT 2)')
  return {'blocked':sorted(set(blocked)),'proven_blocked':sorted(set(blocked)),'limits':limits,'sampled_at':now,'source':SOURCE}
 def view(self,user,health=None,now=None,window=30,snapshot=None):
  now=time.time() if now is None else now;ident=user['id'];p=quota_plan(user.get('quota')) if ident!='legacy' else quota_plan({'period':'none'})
  if snapshot is not None:row=snapshot.get(ident);history=[]
  else:
   with self.db() as db:
    row=db.execute('SELECT * FROM totals WHERE user_id=?',(ident,)).fetchone();history=[dict(r) for r in db.execute('SELECT bucket AS time,SUM(up) AS up,SUM(down) AS down FROM daily WHERE user_id=? AND bucket>=? GROUP BY bucket ORDER BY bucket',(ident,int(now)-window*86400))]
  row=dict(row) if row else {}
  if row and (health or {}).get('status')=='ready' and (health or {}).get('sampled_at') is not None:row['sampled_at']=health['sampled_at']
  fresh=bool(row.get('sampled_at') is not None and -1<=now-row['sampled_at']<=max(15,(health or {}).get('poll_seconds',2)*3) and (health or {}).get('status','ready')=='ready')
  pending=p['reset_seq']>row.get('reset_seq',0) if row else bool(p['reset_seq']);known=row.get('period_up',0)+row.get('period_down',0) if row else None;logical=max(now,row.get('sampled_at') or now,(health or {}).get('logical_time') or now);start,end=quota_boundaries(logical,p)
  status='protected_legacy' if ident=='legacy' else quota_status(user,None if pending else known,logical)
  if status=='active' and (health or {}).get('status')=='degraded' and ident in (health or {}).get('blocked_users',[]):status='pending_reconciliation'
  return {'used_bytes':known if row and not pending else None,'upload_bytes':row.get('period_up') if not pending else None,'download_bytes':row.get('period_down') if not pending else None,'lifetime_up_bytes':row.get('lifetime_up'),'lifetime_down_bytes':row.get('lifetime_down'),'quota_bytes':p['quota_bytes'],'remaining_bytes':max(0,p['quota_bytes']-known) if p['quota_bytes'] and known is not None and not pending else None,'unlimited':p['quota_bytes']==0,'period':p['period'],'timezone':p['timezone'],'reset_seq':row.get('reset_seq',p['reset_seq']),'period_start':row.get('period_start',start),'period_end':row.get('period_end',end),'next_reset':row.get('period_end',end),'expires_at':p['expires_at'] or None,'status':status,'freshness':'fresh' if fresh else 'unavailable' if not row else 'stale','sampled_at':row.get('sampled_at'),'source':SOURCE,'accuracy':'Authenticated payload measured since accounting activation; historical pre-activation traffic is unavailable'+('; collection discontinuity recorded' if row.get('gap') else ''),'collection_gap':bool(row.get('gap')),'reset_pending':pending,'history':history,'history_source':'UTC daily authenticated payload aggregates; not host traffic'}
 def views(self,users,health=None,now=None):
  with self.db() as db:snapshot={r['user_id']:dict(r) for r in db.execute('SELECT * FROM totals')}
  return [self.view(u,health,now,snapshot=snapshot) for u in users]
 def protocols(self,ident):
  with self.db() as db:return [dict(r) for r in db.execute('SELECT protocol,up AS upload_bytes,down AS download_bytes FROM protocol_totals WHERE user_id=? ORDER BY protocol',(ident,))]
 def backup(self,path):
  path=Path(path);require(not path.is_symlink(),'Unsafe accounting backup',503);temp=path.with_name('.backup-'+secrets.token_hex(12))
  try:
   with self.db() as source:
    target=sqlite3.connect(temp)
    try:source.backup(target);require(target.execute('PRAGMA quick_check').fetchone()[0]=='ok','Backup failed integrity check',503)
    finally:target.close()
   temp.chmod(0o600);fd=os.open(temp,os.O_RDONLY)
   try:os.fsync(fd)
   finally:os.close(fd)
   os.replace(temp,path)
  finally:temp.unlink(missing_ok=True)
 def events(self):
  with self.db() as db:return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY time DESC LIMIT 100')]


def fail_safe_policy(state,previous,now=None):
 # Byte budgets are absolute core-counter values and stay valid for the same
 # core instance; keep enforcing them while counters cannot be sampled.
 managed={u['id'] for u in state.get('managed_users',[])};previous_limits=previous.get('limits',{}) if isinstance(previous,dict) else {}
 kept={k:v for k,v in (previous_limits if isinstance(previous_limits,dict) else {}).items() if isinstance(k,str) and k[5:] in managed and type(v) is int and v>=0}
 now=time.time() if now is None else now;known=identities(state);previous=previous.get('proven_blocked',previous.get('blocked',[])) if isinstance(previous,dict) else previous;blocked={x for x in previous if x in known and known[x][0]!='legacy'}
 for user in state.get('managed_users',[]):
  p=quota_plan(user.get('quota'))
  if not user.get('enabled',True) or p['manual_disabled'] or (p['expires_at'] and now>=p['expires_at']):blocked.update(tag for tag,(owner,_) in known.items() if owner==user['id'])
 proven=sorted(blocked)
 if state.get('accounting',{}).get('failure_policy','open')=='closed':blocked.update(tag for tag,(owner,_) in known.items() if owner!='legacy')
 return {'blocked':sorted(blocked),'proven_blocked':proven,'limits':kept,'sampled_at':now,'source':SOURCE,'degraded':True,'reason':'No fresh counters; '+('fail closed for all managed identities' if state.get('accounting',{}).get('failure_policy','open')=='closed' else 'preserved prior blocks plus explicit manual/expiry rules')}

class Engine:
 def __init__(self,base='/etc/sbox-manager',data=DEFAULT_DATA):
  self.base=Path(base);self.data=Path(data);self.data.mkdir(mode=0o700,parents=True,exist_ok=True);self._store=None;self._binary=None
 def state(self):return json.loads((self.base/'state.json').read_text())
 def store(self):
  if self._store is None:
   require((self.data/'usage.db').exists() or not (self.data/'last-good.db').exists(),'Accounting database is missing; restore its last-good backup before collecting',503)
   self._store=MeterStore(self.data/'usage.db')
  return self._store
 def verify_core(self,pid,cfg):
  binary=Path('/usr/local/lib/sbox-manager/sing-box');info=binary.stat();running=Path('/proc/'+str(pid)+'/exe').stat();require(info.st_ino==running.st_ino and info.st_dev==running.st_dev,'Running core differs from installed candidate',503)
  key=(info.st_ino,info.st_mtime_ns,info.st_size)
  if self._binary is None or self._binary[0]!=key:self._binary=(key,hashlib.sha256(binary.read_bytes()).hexdigest())
  require(self._binary[1]==cfg.get('core_sha256') and all(cfg.get('coverage',{}).get(p) is True for p in PROTOS),'Core accounting provenance/coverage does not match',503)
  target='0100007F:'+format(int(cfg.get('port',25001)),'04X');inodes={line.split()[9] for line in Path('/proc/net/tcp').read_text().splitlines()[1:] if line.split()[1]==target and line.split()[3]=='0A'}
  owned=set()
  for fd in Path('/proc/'+str(pid)+'/fd').iterdir():
   try:owned.add(os.readlink(fd))
   except OSError:pass
  require(any('socket:['+inode+']' in owned for inode in inodes),'Local stats socket does not belong to the verified core',503)
 def health(self):
  try:
   r=json.loads((self.data/'health.json').read_text());stamp=r.get('sampled_at')
   if type(stamp) not in (int,float) or not isinstance(r,dict):raise ValueError('Invalid collector heartbeat')
  except (OSError,ValueError,AttributeError):return {'status':'unavailable','reason':'Accounting collector has not produced a validated heartbeat','source':SOURCE}
  reasons=[]
  if not -1<=time.time()-stamp<=max(15,r.get('poll_seconds',2)*3):reasons.append('Collector heartbeat is stale or clock moved backwards')
  try:
   fs=os.statvfs(self.data)
   if fs.f_bavail*fs.f_frsize<8192 or fs.f_flag&getattr(os,'ST_RDONLY',1) or not self.data.stat().st_mode&0o200 or not os.access(self.data,os.W_OK):reasons.append('Accounting storage is full, read-only or unwritable')
  except OSError:reasons.append('Accounting storage is unavailable')
  try:
   proc=subprocess.run(['systemctl','show','sbox-accounting.service','--property=ActiveState,SubState,MainPID'],capture_output=True,text=True,timeout=1)
   service=dict(line.split('=',1) for line in proc.stdout.splitlines() if '=' in line)
   r['collector_service']=service if proc.returncode==0 else {'status':'unavailable'}
   if proc.returncode!=0:reasons.append('Accounting collector service status is unavailable')
   if proc.returncode==0 and (service.get('ActiveState')!='active' or service.get('SubState')!='running' or not service.get('MainPID','0').isdigit() or int(service['MainPID'])<=0):reasons.append('Accounting collector service is not running')
  except (OSError,subprocess.TimeoutExpired):
   r['collector_service']={'status':'unavailable'};reasons.append('Accounting collector service status is unavailable')
  if reasons:r.update(status='degraded',reason='; '.join(reasons))
  try:r['blocked_users']=sorted({tag[5:37] for tag in json.loads((self.base/'quota-runtime.json').read_text()).get('blocked',[]) if re.fullmatch(r'user-[a-f0-9]{32}@(reality|vmess|hy2|tuic|anytls)',tag)})
  except (OSError,ValueError):pass
  return r
 def reconcile(self,lock_held=False):
  lock=None
  if not lock_held:
   path=Path('/run/sbox-manager/manager.lock');path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);lock=path.open('a')
   try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:lock.close();return {'status':'deferred','reason':'Manager transaction is in progress'}
  state=None
  try:
   state=self.state();cfg=state.get('accounting',{});require(cfg.get('enabled'),'Accounting is not enabled',503)
   pid=int(subprocess.check_output(['systemctl','show','sing-box','-p','MainPID','--value'],text=True));require(pid>0,'Core is not running',503)
   self.verify_core(pid,cfg)
   boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();start=Path('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1].split()[19];instance=boot+':'+str(pid)+':'+start
   counters=query(int(cfg.get('port',25001)),str(self.base/'stats-auth.key'));store=self.store();policy=store.ingest(state,instance,counters)
   gid=grp.getgrnam('sboxmgr').gr_gid;root_json(self.base/'quota-runtime.json',policy,gid)
   result={'status':'ready','source':SOURCE,'sampled_at':time.time(),'logical_time':store.metadata('sample',{}).get('logical_time'),'poll_seconds':effective_poll_seconds(state),'configured_poll_seconds':cfg.get('poll_seconds',2),'core_instance':instance,'per_protocol':{p:True for p in PROTOS},'quota_enforcement':'per-managed-identity active connection closure; no core restart','guard_poll_seconds':0.1,'policy_published_at':policy['sampled_at']}
  except Exception as exc:
   # Explicit manual/expiry rules remain enforceable even when counters fail.
   # Proven quota blocks are retained; no new charge is invented during outage.
   if state and state.get('accounting',{}).get('enabled'):
    try:
     try:previous=json.loads((self.base/'quota-runtime.json').read_text())
     except (OSError,ValueError):previous=[]
     policy=fail_safe_policy(state,previous)
     root_json(self.base/'quota-runtime.json',policy,grp.getgrnam('sboxmgr').gr_gid)
    except Exception:pass
   result={'status':'degraded','source':SOURCE,'sampled_at':time.time(),'reason':'Stats/database/core reconciliation unavailable; last known values and policy retained','failure_type':type(exc).__name__,'poll_seconds':2}
  finally:
   if lock:lock.close()
  root_json(self.data/'health.json',result)
  if result['status']=='ready':
   backup=self.data/'last-good.db'
   try:
    if not backup.exists() or backup.stat().st_mtime+3600<time.time():self.store().backup(backup)
   except Exception:pass
  return result
 def daemon(self):
  with (self.data/'collector.lock').open('a') as pidlock:
   try:fcntl.flock(pidlock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise SystemExit('Accounting collector is already running')
   while True:
    started=time.monotonic()
    try:self.reconcile()
    except OSError as exc:
     # Disk/health publication failure must not become an unbounded restart loop.
     # Readers independently check heartbeat, storage and service state.
     print('Accounting storage/publication unavailable: '+type(exc).__name__,file=sys.stderr,flush=True)
    try:interval=effective_poll_seconds(self.state())
    except (OSError,ValueError):interval=2
    # Reconciliation time belongs inside the cadence, rather than being added
    # to every interval. Yield even when a slow collector misses its deadline.
    time.sleep(max(.05,interval-(time.monotonic()-started)))
 def recover(self):
  # Operator stops the collector before recovery. Keep the damaged DB/WAL/SHM.
  lock=(self.data/'collector.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  backup=self.data/'last-good.db';require(backup.is_file() and not backup.is_symlink(),'No validated accounting backup',503)
  check=sqlite3.connect('file:'+str(backup)+'?mode=ro',uri=True)
  try:require(check.execute('PRAGMA quick_check').fetchone()[0]=='ok','Backup is corrupt',503)
  finally:check.close()
  archive=self.data/('damaged-'+str(int(time.time()))+'-'+secrets.token_hex(4));archive.mkdir(mode=0o700)
  for suffix in ('','-wal','-shm'):
   p=self.data/('usage.db'+suffix)
   if p.exists():os.replace(p,archive/p.name)
  import shutil
  shutil.copyfile(backup,self.data/'usage.db');(self.data/'usage.db').chmod(0o600);self._store=None
  with self.store().db() as db:
   db.execute('UPDATE totals SET gap=1');db.execute("INSERT OR REPLACE INTO meta VALUES('recovery',?)",(json.dumps({'time':time.time(),'backup_time':backup.stat().st_mtime,'uncertainty':'Restored historical lower bound. Current-instance watermarks replay unrecorded bytes where available; prior-instance gaps cannot be recovered.'}),))
  lock.close();return {'recovered':True,'archive':str(archive),'uncertainty':'Historical lower bound; collection gap retained'}
 def doctor(self):
  state=self.state();cfg=state.get('accounting',{});health=self.health();return {'enabled':bool(cfg.get('enabled')),'source':SOURCE,'core_version':state['sing_box']['version'],'validated_core_sha256':cfg.get('core_sha256'),'health':health,'protocols':{p:bool(cfg.get('enabled') and cfg.get('coverage',{}).get(p)) for p in PROTOS},'legacy':'One protected shared aggregate; never individual people','units':'GB=1000000000 B; GiB=1073741824 B; used=upload+download','failure_policy':cfg.get('failure_policy','open'),'retention':'latest 100000 raw deltas; 7d hourly and 90d daily; latest 10000 events'}

if __name__=='__main__':
 require(os.geteuid()==0,'Root required',403)
 ap=argparse.ArgumentParser();ap.add_argument('action',choices=['daemon','reconcile','doctor','backup','recover']);ap.add_argument('--inherited-lock',action='store_true');args=ap.parse_args();engine=Engine()
 if args.action=='daemon':engine.daemon()
 elif args.action=='reconcile':
  if args.inherited_lock:
   st=os.fstat(9);require(st.st_ino==os.stat('/run/sbox-manager/manager.lock').st_ino,'Inherited manager lock is unavailable',503)
  print(json.dumps(engine.reconcile(args.inherited_lock)))
 elif args.action=='backup':engine.store().backup(engine.data/'last-good.db');print('Validated accounting backup saved')
 elif args.action=='recover':print(json.dumps(engine.recover()))
 else:print(json.dumps(engine.doctor(),indent=2))
