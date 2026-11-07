"""Exact bytes, stored-instant preservation and DST ambiguity must be explicit."""
from pathlib import Path
import sys,unittest,datetime as dt,json,tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from plan_input import preview
from common import Problem
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privileged-bridge'))
from bridge import Control
from accounting import Engine
NOW=dt.datetime(2026,10,28,tzinfo=dt.timezone.utc).timestamp()
class Input(unittest.TestCase):
 def data(self,**kw):return {'amount':'100','unit':'GB','unlimited':False,'period':'monthly','timezone':'Asia/Hong_Kong','reset_day':31,'no_expiry':True,**kw}
 def test_exact_decimal_binary_fraction_and_unlimited(self):
  for amount,unit,n in [('100','GB',100000000000),('100','GiB',107374182400),('1.25','GB',1250000000),('0.5','GiB',536870912)]:
   self.assertEqual(preview(self.data(amount=amount,unit=unit),NOW)['plan']['quota_bytes'],n)
  self.assertEqual(preview(self.data(unlimited=True),NOW)['plan']['quota_bytes'],0)
  for a,u in [('0.1','B'),('1e5','GB'),('-1','GB'),('1001','TB')]:
   with self.subTest(a=a,u=u),self.assertRaises(Problem):preview(self.data(amount=a,unit=u),NOW)
 def test_local_hong_kong_is_not_utc_and_month_end_preview(self):
  r=preview(self.data(no_expiry=False,expiry_local='2026-11-01T00:00'),NOW)
  self.assertEqual(r['expires_utc'],'2026-10-31T16:00:00+00:00');self.assertEqual(r['plan']['reset_day'],31)
  self.assertEqual(dt.datetime.fromtimestamp(r['next_reset'],dt.timezone.utc).isoformat(),'2026-10-30T16:00:00+00:00')
 def test_nonexistent_and_repeated_dst_times(self):
  with self.assertRaises(Problem):preview(self.data(timezone='America/New_York',no_expiry=False,expiry_local='2026-03-08T02:30'),NOW)
  d=self.data(timezone='America/New_York',no_expiry=False,expiry_local='2026-11-01T01:30');r=preview(d,NOW);self.assertTrue(r['requires_occurrence']);self.assertEqual(len(r['occurrences']),2)
  a=preview({**d,'expiry_fold':'earlier'},NOW);b=preview({**d,'expiry_fold':'later'},NOW);self.assertEqual(b['plan']['expires_at']-a['plan']['expires_at'],3600)
 def test_preserve_untouched_existing_seconds_and_fold(self):
  original=dt.datetime.fromisoformat('2026-11-01T06:30:37+00:00').timestamp()
  r=preview(self.data(timezone='America/New_York',no_expiry=False,expiry_local='2026-11-01T01:30',original_expires_at=original),NOW)
  self.assertEqual(r['plan']['expires_at'],original)
 def test_old_user_without_plan_gets_stored_default_not_browser_timezone(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);ident='a'*32;state={'protocols':{},'managed_users':[{'id':ident,'name':'older-user','enabled':True,'protocols':{}}],'accounting':{}}
   (base/'state.json').write_text(json.dumps(state));control=Control(base);control.meter=Engine(base,base/'meter')
   row=control.dispatch('accounting-user',{'id':ident,'window':'30d'})
   self.assertEqual(row['plan']['timezone'],'UTC');self.assertEqual(row['plan']['quota_bytes'],0)
   self.assertNotIn('quota',json.loads((base/'state.json').read_text())['managed_users'][0])
 def test_weekdays_and_irrelevant_fields(self):
  self.assertEqual(preview(self.data(period='daily',reset_day=31),NOW)['plan']['reset_day'],1)
  for d in [self.data(period='weekly',reset_day=8),self.data(timezone='invalid'),{**self.data(),'user_id':'b'*32}]:
   with self.assertRaises(Problem):preview(d,NOW)
if __name__=='__main__':unittest.main()
