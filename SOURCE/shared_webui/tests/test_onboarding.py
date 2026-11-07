"""Transactional onboarding faults against the real HTTPS handler and SQLite.
The labelled control fixture models only the root commit boundary, not VPN traffic.
"""
import sqlite3,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_panel_v2 import Panel
from common import Problem,capabilities,PROTOCOLS
class Onboarding(Panel):
 def setUp(self):
  super().setUp();self.original=self.app.control;self.exists=False;self.commits=0;self.mode='ok';self.ident='e'*32
  def control(op,data=None):
   if op=='change-preview':return {'kind':'user-create','onboarding_id':self.ident}
   if op=='users':return [{'id':self.ident,'enabled':True}] if self.exists else []
   if op=='commit':
    self.commits+=1
    if self.mode=='reject':raise Problem(409,'State changed')
    self.exists=True
    if self.mode=='lost':raise Problem(503,'Lost response')
    return {'committed':True}
   return self.original(op,data)
  self.app.control=control
  with self.app.store.db() as db:db.execute('DELETE FROM subscriptions WHERE user=?',(self.ident,))
 def tearDown(self):self.app.control=self.original
 def count(self):
  with self.app.store.db() as db:return db.execute('SELECT COUNT(*) FROM subscriptions WHERE user=?',(self.ident,)).fetchone()[0]
 def test_success_returns_three_once_only_urls_and_hash_storage(self):
  code,_,v=self.req('/api/v1/changes/commit',{'token':'a'*64},self.admin());self.assertEqual(code,200,v);self.assertTrue(self.exists);self.assertEqual(self.commits,1);self.assertEqual(set(v['onboarding']['urls']),{'global','cn','internal'});self.assertEqual(self.count(),1)
  with self.app.store.db() as db:value=db.execute('SELECT hash FROM subscriptions WHERE user=?',(self.ident,)).fetchone()[0]
  self.assertTrue(all(value not in u for u in v['onboarding']['urls'].values()))
 def test_sqlite_rejected_insert_never_commits_vpn_account(self):
  h=self.admin()
  with self.app.store.db() as db:db.execute("CREATE TRIGGER fail_onboarding BEFORE INSERT ON subscriptions BEGIN SELECT RAISE(ABORT,'subscription write rejected'); END")
  try:
   code,_,_=self.req('/api/v1/changes/commit',{'token':'a'*64},h);self.assertEqual(code,409);self.assertEqual(self.commits,0);self.assertFalse(self.exists);self.assertEqual(self.count(),0)
  finally:
   with self.app.store.db() as db:db.execute('DROP TRIGGER fail_onboarding')
 def test_rejected_root_commit_removes_reserved_link(self):
  self.mode='reject';code,_,_=self.req('/api/v1/changes/commit',{'token':'a'*64},self.admin());self.assertEqual(code,409);self.assertEqual(self.count(),0);self.assertFalse(self.exists)
 def test_uncertain_completed_root_commit_keeps_link(self):
  self.mode='lost';code,_,_=self.req('/api/v1/changes/commit',{'token':'a'*64},self.admin());self.assertEqual(code,503);self.assertTrue(self.exists);self.assertEqual(self.count(),1)
class Capability(unittest.TestCase):
 def test_only_verified_supported_core_exposes_quota(self):
  cfg={'enabled':True,'core_sha256':'a'*64,'coverage':dict.fromkeys(PROTOCOLS,True)}
  self.assertTrue(capabilities('1.13.14','universal',cfg)['quotas'])
  self.assertTrue(capabilities('1.14.2','universal',cfg)['quotas'])
  for version,config in [('invalid',cfg),('1.13.14',{}),('1.13.14',{**cfg,'coverage':{'tuic':True}}),('1.13.14',{**cfg,'core_sha256':''})]:self.assertFalse(capabilities(version,'zgocloud',config)['quotas'])
if __name__=='__main__':unittest.main()
