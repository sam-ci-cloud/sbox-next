"""Root authorization checks real database sessions, roles, scope, CSRF and expiry."""
import sys,tempfile,unittest,time,json
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('backend','privileged-bridge')]
from authorization import authorize,READS
from common import digest,Problem
from store import Store
class Authz(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'panel.db';self.store=Store(str(self.path));self.cfg={'monitor_key':'private-monitor-key'}
  with self.store.db() as db:
   db.execute("INSERT INTO accounts(name,hash,role,reset) VALUES('a','hash','admin',0)");self.admin=db.execute("SELECT id FROM accounts WHERE name='a'").fetchone()[0]
   db.execute("INSERT INTO accounts(name,hash,role,reset) VALUES('r','hash','reader',0)");self.reader=db.execute("SELECT id FROM accounts WHERE name='r'").fetchone()[0]
   for raw,ident in [('admin',self.admin),('reader',self.reader)]:db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)',(digest(raw),ident,'csrf',time.time()+3600,time.time(),time.time()))
   db.execute('INSERT INTO subscriptions VALUES(?,?,?)',('a'*32,digest('subscription'),time.time()))
 def tearDown(self):self.tmp.cleanup()
 def call(self,op,ctx,data=None):return authorize(op,data or {},ctx,self.cfg,str(self.path))
 def test_portal_all_nonportal_ops_forbidden_at_root(self):
  for op in sorted(READS|{'export','prepare','commit','core-update','unban','restore','restart','portal-login'}):
   with self.subTest(op=op),self.assertRaises(Problem):self.call(op,{'kind':'portal','session':'opaque'},{'session':'opaque'})
 def test_portal_requires_matching_session(self):
  with self.assertRaises(Problem):self.call('portal-me',{'kind':'portal','session':'a'},{'session':'b'})
 def test_monitor_key_and_allowlist(self):
  self.call('overview',{'kind':'monitor','key':self.cfg['monitor_key']})
  for op,ctx in [('export',{'kind':'monitor','key':self.cfg['monitor_key']}),('overview',{'kind':'monitor','key':'wrong'}),('overview',{})]:
   with self.assertRaises(Problem):self.call(op,ctx)
 def test_admin_write_needs_root_csrf_and_current_session(self):
  self.call('prepare',{'kind':'browser','raw':'admin','csrf':'csrf'})
  for ctx in [{'kind':'browser','raw':'admin'},{'kind':'browser','raw':'reader','csrf':'csrf'},{'kind':'browser','raw':'no-such','csrf':'csrf'}]:
   with self.assertRaises(Problem):self.call('prepare',ctx)
 def test_reader_cannot_export_secrets(self):
  self.call('users',{'kind':'browser','raw':'reader'})
  with self.assertRaises(Problem):self.call('export',{'kind':'browser','raw':'reader','csrf':'csrf'})
 def test_subscription_scope_pinned(self):
  ctx={'kind':'subscription','raw':'subscription'};self.call('export',ctx,{'id':'a'*32});self.call('endpoints',ctx,{'id':'a'*32})
  for op,data in [('export',{'id':'b'*32}),('endpoints',{'id':'b'*32}),('network',{}),('overview',{}),('prepare',{})]:
   with self.assertRaises(Problem):self.call(op,ctx,data)
 def test_revocation_checked_on_every_bridge_request(self):
  ctx={'kind':'browser','raw':'admin','csrf':'csrf'};self.call('overview',ctx)
  with self.store.db() as db:db.execute('DELETE FROM sessions')
  with self.assertRaises(Problem):self.call('overview',ctx)
if __name__=='__main__':unittest.main()
