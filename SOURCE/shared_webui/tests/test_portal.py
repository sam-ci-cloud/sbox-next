import sys,tempfile,json,unittest,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'));sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privileged-bridge'))
from accounting import Engine
from portal_auth import Portal
from controller import candidate
from common import Problem
class Isolation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.path=self.base/'state.json';self.state={'protocols':{p:{'enabled':True} for p in ['reality','vmess','hy2','tuic','anytls']},'accounting':{'enabled':True}}
  for n in ['Alice','Bob']:self.state=candidate(self.state,{'kind':'user-create','data':{'name':n,'portal':{'username':'login-'+n,'password':'Portal-'+n+'-only-password-2026','reset':False}}},'zgocloud')
  self.path.write_text(json.dumps(self.state));self.engine=Engine(self.base,self.base/'meter');self.portal=Portal(self.engine,self.change);self.alice=self.state['managed_users'][0];self.bob=self.state['managed_users'][1]
 def tearDown(self):self.tmp.cleanup()
 def change(self,request):self.state=candidate(self.state,request,'zgocloud');self.path.write_text(json.dumps(self.state))
 def login(self,name='Alice',peer='127.0.0.1'):
  return self.portal.dispatch('portal-login',{'username':'login-'+name,'password':'Portal-'+name+'-only-password-2026','peer':peer})
 def test_usage_bound_to_session_and_no_admin_fields(self):
  self.engine.store().ingest(self.state,'core',{'user>>>user-'+self.alice['id']+'@tuic>>>traffic>>>uplink':1234,'user>>>user-'+self.bob['id']+'@tuic>>>traffic>>>uplink':9876})
  sid=self.login();r=self.portal.dispatch('portal-me',{'session':sid['session'],'window':'30d'});self.assertEqual(r['used_bytes'],1234)
  text=json.dumps(r);self.assertNotIn(self.bob['id'],text)
  for key in ['cpu','memory','uuid','password','subscription','portal','generation','user_id','id','core_instance']:self.assertNotIn(key,r)
 def test_reject_arbitrary_user_and_history_arguments(self):
  sid=self.login()
  for field in ['id','user_id','user','other']:
   with self.subTest(field=field),self.assertRaises(Problem):self.portal.dispatch('portal-me',{'session':sid['session'],'window':'7d',field:self.bob['id']})
  with self.assertRaises(Problem):self.portal.dispatch('portal-me',{'session':sid['session'],'window':'../../Bob'})
 def test_every_non_portal_operation_refused(self):
  sid=self.login()
  for op in ['overview','users','export','quota','prepare','commit','logs','certificate','accounts','tokens','subscriptions','firewall','portal-register']:
   with self.subTest(op=op),self.assertRaises(Problem):self.portal.dispatch(op,{'session':sid['session']})
 def test_portal_session_persistent_and_generation_revoked(self):
  sid=self.login();self.portal=Portal(Engine(self.base,self.base/'meter'),self.change);self.assertEqual(self.portal.actor(sid['session'])['id'],self.alice['id'])
  self.change({'kind':'portal-account','id':self.alice['id'],'data':{'password':'New-independent-portal-password-2026'}})
  with self.assertRaises(Problem):self.portal.actor(sid['session'])
 def test_vpn_disabled_can_still_see_quota_status(self):
  self.state['managed_users'][0]['enabled']=False;self.path.write_text(json.dumps(self.state));sid=self.login();r=self.portal.dispatch('portal-me',{'session':sid['session'],'window':'7d'});self.assertEqual(r['status'],'manually_disabled');self.assertIsNone(r['used_bytes'])
 def test_password_change_csrf_and_current_password(self):
  sid=self.login()
  for csrf,old in [('wrong','Portal-Alice-only-password-2026'),(sid['csrf'],'wrong')]:
   with self.assertRaises(Problem):self.portal.dispatch('portal-password',{'session':sid['session'],'csrf':csrf,'old':old,'password':'A-new-independent-password-2026'})
  r=self.portal.dispatch('portal-password',{'session':sid['session'],'csrf':sid['csrf'],'old':'Portal-Alice-only-password-2026','password':'A-new-independent-password-2026'});self.assertTrue(r['login_again'])
  with self.assertRaises(Problem):self.portal.actor(sid['session'])
 def test_logout_csrf(self):
  sid=self.login()
  with self.assertRaises(Problem):self.portal.dispatch('portal-logout',{'session':sid['session'],'csrf':'bad'})
  self.portal.dispatch('portal-logout',{'session':sid['session'],'csrf':sid['csrf']})
  with self.assertRaises(Problem):self.portal.actor(sid['session'])
 def test_login_generic_errors_and_throttle(self):
  errors=[]
  for name in ['unknown','login-Alice']:
   with self.assertRaises(Problem) as error:self.portal.login({'username':name,'password':'wrong','peer':'peer-'+name})
   errors.append((error.exception.status,error.exception.message))
  self.assertEqual(errors[0],errors[1])
  for n in range(8):
   try:self.portal.login({'username':'missing','password':'wrong','peer':'flood'})
   except Problem:pass
  with self.assertRaises(Problem) as error:self.portal.login({'username':'missing','password':'wrong','peer':'flood'})
  self.assertEqual(error.exception.status,429)
 def test_no_vpn_password_reuse_no_legacy_portal(self):
  pw=self.alice['protocols']['tuic']['password']
  with self.assertRaises(Problem):self.change({'kind':'portal-account','id':self.alice['id'],'data':{'password':pw}})
  with self.assertRaises(Problem):self.change({'kind':'portal-account','id':'legacy','data':{'username':'legacy','password':'Not-allowed-password'}})
 def test_quota_only_change_preserves_credentials_and_protected_legacy(self):
  before=self.alice['protocols'];self.change({'kind':'quota','id':self.alice['id'],'data':{'quota_bytes':'5GiB'}});u=self.state['managed_users'][0];self.assertEqual(u['protocols'],before);self.assertEqual(u['quota']['quota_bytes'],5368709120)
 def test_connection_requires_same_session_csrf_and_password_change(self):
  sid=self.login()
  identity=self.portal.dispatch('portal-connection',{'session':sid['session'],'csrf':sid['csrf']})
  self.assertEqual(identity['id'],self.alice['id'])
  for extra in ({'id':self.bob['id']},{'csrf':'wrong'}):
   with self.assertRaises(Problem):self.portal.dispatch('portal-connection',{'session':sid['session'],'csrf':sid['csrf'],**extra})
  self.change({'kind':'portal-account','id':self.alice['id'],'data':{'reset':True}})
  with self.assertRaises(Problem) as error:self.portal.dispatch('portal-connection',{'session':sid['session'],'csrf':sid['csrf']})
  self.assertEqual(error.exception.status,428)
 def test_personal_export_root_derives_id_and_refuses_id_override(self):
  from bridge import Control
  control=Control(self.base);control.meter=self.engine
  control.run=lambda args,data=None,timeout=0:json.dumps({'id':data['id'],'format':data['format']})
  sid=self.login();data={'session':sid['session'],'csrf':sid['csrf'],'profile':'global','format':'yaml'}
  result=control.dispatch('portal-export',data)
  self.assertEqual(json.loads(result['content'])['id'],self.alice['id'])
  with self.assertRaises(Problem):control.dispatch('portal-export',{**data,'id':self.bob['id']})
  with self.assertRaises(Problem):control.dispatch('portal-export',{**data,'profile':'../../other'})
 def test_csrf_can_be_recovered_after_new_tab_without_rotating_session(self):
  sid=self.login();before=self.portal.actor(sid['session'])['id']
  for _ in range(2):self.assertEqual(self.portal.dispatch('portal-session',{'session':sid['session']})['csrf'],sid['csrf'])
  self.assertEqual(self.portal.actor(sid['session'],sid['csrf'])['id'],before)
 def test_history_same_user_and_snapshot_matches_admin_builder(self):
  from bridge import Control
  from unittest.mock import patch
  import usage_history
  sid=self.login();now=time.time();self.engine.store().ingest(self.state,'test-core',{'user>>>user-'+self.alice['id']+'@tuic>>>traffic>>>uplink':765},now)
  control=Control(self.base);control.meter=self.engine
  with patch.object(usage_history.time,'time',return_value=now):
   personal=self.portal.dispatch('portal-history',{'session':sid['session'],'selection':{'window':'24h'}})
   admin=control.dispatch('accounting-history',{'id':self.alice['id'],'selection':{'window':'24h'}})
  self.assertEqual(personal,admin);self.assertEqual(personal['totals']['upload_bytes'],765)
  with self.assertRaises(Problem):self.portal.dispatch('portal-history',{'session':sid['session'],'selection':{'window':'24h','id':self.bob['id']}})
if __name__=='__main__':unittest.main()
