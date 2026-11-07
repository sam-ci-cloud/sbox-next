"""Root bridge principal check, independent of HTTP routing/frontend visibility."""
import hmac,json,sqlite3,time
from pathlib import Path
from common import require,digest
READS={'network','endpoints','overview','inbounds','users','capabilities','version','policy','certificate','doctor','backups','logs','firewall','firewall-status','security','bans','webui-guard','performance','accounting-summary','accounting-user','accounting-history','quota-preview','quota-doctor','monitor-probes'}
MONITOR={'overview','inbounds','certificate','doctor','accounting-summary','monitor-probes'}
def authorize(op,data,context,cfg,dbpath='/var/lib/sbox-webui/panel.db'):
 require(isinstance(context,dict) and len(json.dumps(context))<2048,'Unauthorized bridge principal',401)
 kind=context.get('kind')
 if op=='portal-login':
  require(kind in ('monitor','anonymous'),'Forbidden portal principal',403)
  if kind=='monitor':require(hmac.compare_digest(str(context.get('key','')),str(cfg.get('monitor_key','!'))),'Unauthorized bridge principal',401)
  return {'kind':'portal'}
 if kind=='portal':
  require(op in ('portal-me','portal-password','portal-logout','portal-connection','portal-export','portal-history','portal-session'),'Portal principal cannot access admin operations',403)
  require(set(context)=={'kind','session'} and data.get('session')==context['session'],'Portal session mismatch',403)
  return {'kind':'portal'}
 if kind=='monitor':
  require(set(context)=={'kind','key'} and cfg.get('monitor_key') and hmac.compare_digest(str(context['key']),cfg['monitor_key']),'Unauthorized bridge principal',401)
  require(op in MONITOR,'Background principal is read-only',403);return {'kind':'monitor'}
 require(kind in ('browser','token','subscription'),'Unauthorized bridge principal',401)
 require(isinstance(context.get('raw'),str) and 0<len(context['raw'])<=256,'Unauthorized',401)
 db=sqlite3.connect('file:'+str(dbpath)+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
 try:
  if kind=='subscription':
   r=db.execute('SELECT user FROM subscriptions WHERE hash=?',(digest(context['raw']),)).fetchone();require(r is not None,'Not found',404)
   require(op in ('users','export','endpoints') and (op=='users' or data.get('id')==r['user']),'Subscription principal is bound to its user',403);return {'kind':'subscription','id':r['user']}
  if kind=='token':r=db.execute('SELECT a.*,t.scope,t.expires FROM tokens t JOIN accounts a ON a.id=t.account WHERE t.hash=?',(digest(context['raw']),)).fetchone()
  else:r=db.execute('SELECT a.*,s.csrf,s.expires,s.seen,s.fresh FROM sessions s JOIN accounts a ON a.id=s.account WHERE s.hash=?',(digest(context['raw']),)).fetchone()
  require(r is not None and r['enabled'] and not r['reset'] and r['expires']>time.time(),'Unauthorized',401)
  if kind=='browser':require(r['seen']+1800>time.time(),'Unauthorized',401)
  if op not in READS:
   require(r['role']=='admin' and (kind!='token' or r['scope'] in ('admin','write')),'Admin write scope required',403)
   if kind=='browser':require(hmac.compare_digest(str(context.get('csrf','')),r['csrf']),'CSRF token required',403)
  if op in ('webui-guard-repair','webui-guard-unban'):
   require(kind=='browser' and r['fresh']+300>time.time(),'Reauthenticate before changing WebUI login protection',428)
  if op in ('export','network','endpoints'):require(r['role']=='admin','Admin required',403)
  return {'kind':kind,'id':r['id']}
 finally:db.close()
