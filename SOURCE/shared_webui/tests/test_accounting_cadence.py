"""Finite quotas get a bounded cadence without a work-duration sleep penalty."""
from pathlib import Path
import sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import Engine,effective_poll_seconds
class Cadence(unittest.TestCase):
 def test_unlimited_users_keep_configured_interval(self):
  self.assertEqual(effective_poll_seconds({'accounting':{'poll_seconds':9},'managed_users':[{'quota':{'quota_bytes':0}}]}),9)
 def test_limited_and_expiring_users_sample_every_second(self):
  for plan in [{'quota_bytes':1048576},{'expires_at':2000000000}]:
   with self.subTest(plan=plan):self.assertEqual(effective_poll_seconds({'accounting':{'poll_seconds':60},'managed_users':[{'quota':plan}]}),1)
 def test_disabled_user_does_not_accelerate_unlimited_installation(self):
  self.assertEqual(effective_poll_seconds({'managed_users':[{'enabled':False,'quota':{'quota_bytes':1048576}}]}),2)
 def test_collection_time_is_included_and_overruns_still_yield(self):
  class Stop(Exception):pass
  for work,expected in [(.4,.6),(1.5,.05)]:
   with self.subTest(work=work),tempfile.TemporaryDirectory() as td:
    engine=Engine(data=td)
    state={'managed_users':[{'quota':{'quota_bytes':1}}]}
    with patch.object(engine,'reconcile'),patch.object(engine,'state',return_value=state),patch('accounting.time.monotonic',side_effect=[10,10+work]),patch('accounting.time.sleep',side_effect=Stop) as sleep:
     with self.assertRaises(Stop):engine.daemon()
     self.assertAlmostEqual(sleep.call_args.args[0],expected)
if __name__=='__main__':unittest.main(verbosity=2)
