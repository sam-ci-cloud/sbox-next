"""Root-validated personal principal; immutable managed ID comes from its session."""
import hmac,json,secrets,time
from common import Problem,require,password_ok,digest,token
from accounting import SOURCE
from usage_history import history
DUMMY='scrypt$32768$8$3$MDAwMDAwMDAwMDAwMDAwMA==$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA='
class Portal:
 def __init__(self,engine,change=None):self.engine=engine;self.change=change
 def user(self,ident):
  require(isinstance(ident,str) and ident!='legacy','Invalid portal account',401)
  user=next((u for u in self.engine.state().get('managed_users',[]) if u['id']==ident),None)
  require(user is not None and user.get('portal',{}).get('enabled'),'Invalid portal account',401);return user
 def login(self,data):
  require(set(data)=={'username','password','peer'},'Unknown portal login field')
  require(all(isinstance(data[k],str) and len(data[k])<=256 for k in data),'Invalid credentials',401)
  now=time.time();store=self.engine.store();keys=['ip:'+data['peer'],'name:'+data['username'].casefold()]
  with store.db() as db:
   db.execute('DELETE FROM portal_attempts WHERE started<?',(now-900,))
   db.execute('DELETE FROM portal_attempts WHERE key IN (SELECT key FROM portal_attempts ORDER BY started DESC LIMIT -1 OFFSET 20000)')
   for key in keys:
    row=db.execute('SELECT count FROM portal_attempts WHERE key=?',(key,)).fetchone();require(not row or row[0]<8,'Too many login attempts. Retry in 15 minutes.',429)
   for key in keys:db.execute('INSERT INTO portal_attempts VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',(key,now))
  user=next((u for u in self.engine.state().get('managed_users',[]) if u.get('portal',{}).get('username','').casefold()==data['username'].casefold()),None);portal=user.get('portal',{}) if user else {};valid=password_ok(data['password'],portal.get('password_hash',DUMMY))
  require(user is not None and portal.get('enabled') and valid,'Invalid credentials',401)
  sid=token();csrf=self.csrf_token(sid)
  with store.db() as db:
   db.execute('DELETE FROM portal_sessions WHERE expires<? OR seen<?',(now,now-1800))
   db.execute('DELETE FROM portal_sessions WHERE hash IN (SELECT hash FROM portal_sessions WHERE user_id=? ORDER BY created DESC LIMIT -1 OFFSET 31)',(user['id'],))
   db.execute('INSERT INTO portal_sessions VALUES(?,?,?,?,?,?,?)',(digest(sid),user['id'],portal['generation'],digest(csrf),now,now,now+28800))
   for key in keys:db.execute('DELETE FROM portal_attempts WHERE key=?',(key,))
  return {'session':sid,'csrf':csrf,'reset_password':bool(portal.get('reset',True)),'expires_at':now+28800}
 def csrf_token(self,sid):return hmac.new(sid.encode(),b'SBOX portal CSRF v1','sha256').hexdigest()
 def actor(self,sid,csrf=None):
  require(isinstance(sid,str) and len(sid)<=256,'Unauthorized',401);now=time.time()
  with self.engine.store().db() as db:
   r=db.execute('SELECT * FROM portal_sessions WHERE hash=?',(digest(sid),)).fetchone();require(r is not None and r['expires']>now and r['seen']+1800>now,'Unauthorized',401);user=self.user(r['user_id'])
   require(hmac.compare_digest(r['generation'],user['portal']['generation']),'Unauthorized',401)
   if csrf is not None:require(isinstance(csrf,str) and hmac.compare_digest(r['csrf'],digest(csrf)),'CSRF token required',403)
   if r['seen']+60<now:db.execute('UPDATE portal_sessions SET seen=? WHERE hash=?',(now,digest(sid)))
  return user
 def dispatch(self,op,data):
  if op=='portal-login':return self.login(data)
  allowed={'portal-session':{'session'},'portal-me':{'session','window'},'portal-history':{'session','selection'},'portal-connection':{'session','csrf'},'portal-logout':{'session','csrf'},'portal-password':{'session','csrf','old','password'}}
  require(op in allowed and set(data)==allowed[op],'Portal operation/fields are forbidden',403)
  user=self.actor(data['session'],None if op in ('portal-me','portal-history','portal-session') else data['csrf'])
  if op=='portal-session':
   csrf=self.csrf_token(data['session'])
   with self.engine.store().db() as db:row=db.execute('SELECT csrf FROM portal_sessions WHERE hash=?',(digest(data['session']),)).fetchone()
   return {'csrf':csrf} if row and hmac.compare_digest(row['csrf'],digest(csrf)) else {'requires_signin':True}
  if op=='portal-history':
   require(not user['portal'].get('reset',True),'Change initial password first',428)
   return history(self.engine.store(),user,data['selection'])
  if op=='portal-connection':
   require(not user['portal'].get('reset',True),'Change initial password first',428)
   return {'id':user['id'],'enabled':bool(user.get('enabled',True))}
  if op=='portal-logout':
   with self.engine.store().db() as db:db.execute('DELETE FROM portal_sessions WHERE hash=?',(digest(data['session']),))
   return {'logged_out':True}
  if op=='portal-password':
   require(isinstance(data['old'],str) and password_ok(data['old'],user['portal']['password_hash']),'Invalid credentials',401)
   require(self.change is not None,'Portal password changes are unavailable',503)
   require(not password_ok(data['password'],user['portal']['password_hash']),'Choose a different password')
   self.change({'kind':'portal-account','id':user['id'],'data':{'password':data['password'],'reset':False}})
   return {'changed':True,'login_again':True}
  require(data['window'] in ('7d','30d'),'Window must be 7d or 30d')
  if user['portal'].get('reset',True):return {'display_name':user['name'],'reset_password':True,'status':'password_change_required'}
  view=self.engine.store().view(user,self.engine.health(),window=7 if data['window']=='7d' else 30)
  # A literal allowlist ensures future admin telemetry additions cannot leak here.
  fields={'used_bytes','upload_bytes','download_bytes','quota_bytes','remaining_bytes','unlimited','period','timezone','period_start','period_end','next_reset','expires_at','status','freshness','sampled_at','source','accuracy','collection_gap','reset_pending','history','history_source'}
  return {'display_name':user['name'],'reset_password':False,**{k:v for k,v in view.items() if k in fields}}
