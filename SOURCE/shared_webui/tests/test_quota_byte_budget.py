"""1.2.1: the collector publishes per-user byte budgets for the core guard."""
from pathlib import Path
import sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore,fail_safe_policy
U='a'*32;V='b'*32
def state(quota_u,quota_v):
 return {'protocols':{p:{'enabled':True} for p in ('reality','vmess','hy2','tuic','anytls')},
  'managed_users':[{'id':U,'name':'u','enabled':True,'protocols':{'hy2':{},'reality':{}},'quota':quota_u},
                   {'id':V,'name':'v','enabled':True,'protocols':{'tuic':{}},'quota':quota_v}]}
def c(ident,proto,up,down):return {'user>>>user-%s@%s>>>traffic>>>uplink'%(ident,proto):up,'user>>>user-%s@%s>>>traffic>>>downlink'%(ident,proto):down}
class ByteBudget(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory();self.store=MeterStore(Path(self.t.name)/'usage.db')
 def tearDown(self):self.t.cleanup()
 def test_budget_is_sampled_counters_plus_remaining(self):
  st=state({'quota_bytes':10000,'period':'none'},{'period':'none'})
  self.store.ingest(st,'core-1',{**c(U,'hy2',100,200),**c(U,'reality',50,50)},now=1792886400)
  policy=self.store.ingest(st,'core-1',{**c(U,'hy2',1100,2200),**c(U,'reality',50,50)},now=1792886402)
  # used = 3400 since collection began; counters sampled = 3400; budget = 3400 + 6600
  self.assertEqual(policy['limits'],{'user-'+U:10000})
  self.assertNotIn('user-'+V,policy['limits'],'unlimited users carry no budget')
 def test_exhausted_user_is_blocked_not_budgeted(self):
  st=state({'quota_bytes':1000,'period':'none'},{'period':'none'})
  policy=self.store.ingest(st,'core-1',c(U,'hy2',600,600),now=1792886400)
  self.assertIn('user-%s@hy2'%U,policy['blocked']);self.assertNotIn('user-'+U,policy['limits'])
 def test_fail_safe_keeps_budgets_for_known_users_only(self):
  st=state({'quota_bytes':1000,'period':'none'},{'period':'none'})
  kept=fail_safe_policy(st,{'blocked':[],'limits':{'user-'+U:777,'user-'+'c'*32:5}},now=1792886400)
  self.assertEqual(kept['limits'],{'user-'+U:777})
if __name__=='__main__':unittest.main()
