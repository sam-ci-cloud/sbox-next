"""Meaningful scale, bounded IPC, atomic bulk validation and recovery regressions."""
import sys,tempfile,unittest,time,json,copy
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('backend','privileged-bridge')]
from accounting import MeterStore,fail_safe_policy
from quota_models import quota_plan
from controller import candidate,preview
from common import Problem
PROTOS=['reality','vmess','hy2','tuic','anytls']
class Scale(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=MeterStore(Path(self.tmp.name)/'usage.db');self.users=[{'id':format(i+1,'032x'),'name':'user'+str(i),'enabled':True,'tags':[],'protocols':{'tuic':{}},'quota':quota_plan({'quota_bytes':1000})} for i in range(1000)];self.state={'accounting':{'enabled':True},'protocols':{p:{'enabled':True} for p in PROTOS},'managed_users':self.users}
 def tearDown(self):self.tmp.cleanup()
 def test_thousand_users_persistent_views_and_bulk_atomicity(self):
  now=time.time();counters={'user>>>user-'+u['id']+'@tuic>>>traffic>>>uplink':i for i,u in enumerate(self.users)};self.store.ingest(self.state,'core',counters,now);rows=self.store.views(self.users,{'status':'ready'},now);self.assertEqual(len(rows),1000);self.assertEqual(rows[999]['used_bytes'],999)
  req={'kind':'quota-bulk','data':{'ids':[u['id'] for u in self.users],'plan':{'quota_bytes':'5 GiB'}}};new=candidate(self.state,req,'zgocloud');self.assertTrue(all(u['quota']['quota_bytes']==5*1024**3 for u in new['managed_users']));self.assertTrue(all(u['quota']['quota_bytes']==1000 for u in self.users));review=preview(self.state,new,req,'zgocloud');self.assertFalse(review['restart']);self.assertEqual(len(review['summary']['changed_ids']),1000);self.assertLess(len(json.dumps(review)),262144);self.assertEqual(new['protocols'],self.state['protocols'])
  req['data']['ids'].append('legacy')
  with self.assertRaises(Problem):candidate(self.state,req,'zgocloud')
 def test_old_restored_reset_sequence_does_not_reset_meter(self):
  state=copy.deepcopy(self.state);state['managed_users']=state['managed_users'][:1];user=state['managed_users'][0];user['quota']['reset_seq']=5;tag='user>>>user-'+user['id']+'@tuic>>>traffic>>>uplink';self.store.ingest(state,'core',{tag:300});user['quota']['reset_seq']=1;self.store.ingest(state,'core',{tag:400});self.assertEqual(self.store.view(user)['used_bytes'],400)
 def test_switch_to_open_removes_outage_blocks_but_preserves_proven_ones(self):
  state=copy.deepcopy(self.state);state['managed_users']=state['managed_users'][:2];state['accounting']['failure_policy']='closed';closed=fail_safe_policy(state,[]);self.assertEqual(len(closed['blocked']),2);state['accounting']['failure_policy']='open';opened=fail_safe_policy(state,closed);self.assertEqual(opened['blocked'],[])
  proven='user-'+state['managed_users'][0]['id']+'@tuic';closed=fail_safe_policy(state,[proven]);self.assertIn(proven,fail_safe_policy(state,closed)['blocked'])
 def test_backup_restores_verified_values(self):
  self.state['managed_users']=self.users[:1];u=self.users[0];self.store.ingest(self.state,'core',{'user>>>user-'+u['id']+'@tuic>>>traffic>>>uplink':300});path=Path(self.tmp.name)/'backup.db';self.store.backup(path);backup=MeterStore(path);self.assertEqual(backup.view(u)['used_bytes'],300)
 def test_failure_policy_open_and_closed_preserve_legacy(self):
  state=copy.deepcopy(self.state);state['managed_users']=state['managed_users'][:2];state['accounting']['failure_policy']='open';self.assertEqual(fail_safe_policy(state,[])['blocked'],[]);state['accounting']['failure_policy']='closed';blocked=fail_safe_policy(state,['legacy','tuic'])['blocked'];self.assertEqual(len(blocked),2);self.assertTrue(all(x.startswith('user-') for x in blocked))
if __name__=='__main__':unittest.main()
