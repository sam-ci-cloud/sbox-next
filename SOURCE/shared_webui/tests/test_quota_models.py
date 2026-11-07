import sys,unittest,datetime as d
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from quota_models import quota_size,quota_plan,quota_boundaries,quota_status
class QuotaModels(unittest.TestCase):
 def at(self,text):return d.datetime.fromisoformat(text).timestamp()
 def test_bytes_units(self):
  self.assertEqual(quota_size('5 GiB'),5368709120);self.assertEqual(quota_size('5GB'),5000000000);self.assertEqual(quota_size(0),0)
  for v in [True,-1,float('nan'),'5','-5GB','1e9 GB','1.1234567GB',{},'1.1B']:
   with self.subTest(v=repr(v)),self.assertRaises(ValueError):quota_size(v)
 def test_validation(self):
  for v in [{'period':'rolling'},{'timezone':'../../UTC'},{'timezone':'no/such'},{'reset_day':0},{'period':'weekly','reset_day':8},{'expires_at':float('nan')},{'manual_disabled':1},{'reset_seq':-1},{'bogus':1}]:
   with self.subTest(v=v),self.assertRaises(ValueError):quota_plan(v)
 def test_month_end_leap_and_recover_original_anchor(self):
  p=quota_plan({'reset_day':31});a,b=quota_boundaries(self.at('2024-02-29T12:00:00+00:00'),p);self.assertEqual(a,self.at('2024-02-29T00:00:00+00:00'));self.assertEqual(b,self.at('2024-03-31T00:00:00+00:00'))
  a,b=quota_boundaries(self.at('2025-02-28T12:00:00+00:00'),p);self.assertEqual(b,self.at('2025-03-31T00:00:00+00:00'))
 def test_april_30_to_may_31(self):
  a,b=quota_boundaries(self.at('2026-04-30T00:00:00+00:00'),quota_plan({'reset_day':31}));self.assertEqual(b,self.at('2026-05-31T00:00:00+00:00'))
 def test_daily_dst_no_double_reset(self):
  p=quota_plan({'period':'daily','timezone':'Europe/Berlin'});a,b=quota_boundaries(self.at('2026-03-29T12:00:00+02:00'),p);self.assertEqual(b-a,23*3600)
  a,b=quota_boundaries(self.at('2026-10-25T12:00:00+01:00'),p);self.assertEqual(b-a,25*3600)
 def test_weekly(self):
  a,b=quota_boundaries(self.at('2026-10-25T12:00:00+00:00'),quota_plan({'period':'weekly','reset_day':1}));self.assertEqual(a,self.at('2026-10-19T00:00:00+00:00'));self.assertEqual(b,self.at('2026-10-26T00:00:00+00:00'))
 def test_manual_precedence_and_expiry(self):
  u={'enabled':False,'quota':{'quota_bytes':100,'expires_at':10}};self.assertEqual(quota_status(u,1000,20),'manually_disabled');u['enabled']=True;self.assertEqual(quota_status(u,1,20),'expired');u['quota']['expires_at']=0;self.assertEqual(quota_status(u,100,20),'quota_exceeded');self.assertEqual(quota_status(u,None,20),'active')
if __name__=='__main__':unittest.main()
