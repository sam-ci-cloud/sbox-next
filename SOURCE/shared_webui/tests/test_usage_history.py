"""Real SQLite history: zero/missing, bounded selections, local dates and isolation."""
import datetime as dt,json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore
from usage_history import history,selection
from common import Problem
ID='a'*32;OTHER='b'*32

def epoch(s):return dt.datetime.fromisoformat(s).timestamp()
class History(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=MeterStore(Path(self.tmp.name)/'usage.db');self.user={'id':ID,'enabled':True,'protocols':{'tuic':{}},'quota':{'timezone':'Asia/Hong_Kong'}};self.state={'protocols':{},'managed_users':[self.user,{**self.user,'id':OTHER}],'accounting':{'poll_seconds':2}}
 def tearDown(self):self.tmp.cleanup()
 def ingest(self,stamp,up=0,other=0,core='core'):
  self.store.ingest(self.state,core,{'user>>>user-'+ID+'@tuic>>>traffic>>>uplink':up,'user>>>user-'+OTHER+'@tuic>>>traffic>>>uplink':other},stamp)
 def test_axis_complete_one_point_no_fake_zeros_and_isolation(self):
  now=epoch('2026-10-27T12:05:00+00:00');self.ingest(now,100,900)
  d=history(self.store,self.user,{'window':'24h'},now=now)
  self.assertGreaterEqual(len(d['buckets']),24);self.assertLessEqual(len(d['buckets']),25)
  self.assertEqual(d['totals']['upload_bytes'],100);self.assertEqual(d['totals']['download_bytes'],0)
  self.assertTrue(any(b['state']=='before_collection' and b['up'] is None for b in d['buckets']))
  self.assertNotIn(OTHER,json.dumps(d));self.assertEqual(sum(b['up'] or 0 for b in d['buckets']),100)
 def test_observed_zero_is_distinct_from_missing(self):
  start=epoch('2026-10-27T12:00:00+00:00')
  for i in range(0,901,10):self.ingest(start+i)
  d=history(self.store,self.user,{'window':'custom','start':'2026-10-27','end':'2026-10-27'},now=start+900)
  self.assertEqual(d['totals']['upload_bytes'],0);self.assertTrue(any(b['observed_seconds']>=900 for b in d['buckets']))
  self.assertEqual(d['buckets'][-1]['state'],'recorded');self.assertEqual(d['buckets'][-1]['up'],0)
  empty=history(self.store,{**self.user,'id':'c'*32},{'window':'24h'},now=start+900)
  self.assertIsNone(empty['totals']['upload_bytes'])
 def test_outage_and_counter_reset_are_partial(self):
  now=epoch('2026-10-27T12:00:00+00:00');self.ingest(now,100);self.ingest(now+10,100);self.ingest(now+1800,130);self.ingest(now+1810,1)
  d=history(self.store,self.user,{'window':'24h'},now=now+1810)
  self.assertTrue(any(b['state']=='partial' for b in d['buckets']));self.assertTrue(d['incomplete']);self.assertEqual(d['totals']['upload_bytes'],130)
 def test_hong_kong_daily_boundary_and_legacy_utc_disclosure(self):
  a=epoch('2026-10-26T15:59:00+00:00');self.ingest(a,100);self.ingest(a+120,150)
  d=history(self.store,self.user,{'window':'30d'},now=a+120)
  rows=[b for b in d['buckets'] if b['up'] is not None];self.assertEqual([r['label'] for r in rows],['2026-10-26','2026-10-27']);self.assertEqual([r['up'] for r in rows],[100,50]);self.assertEqual(d['timezone'],'Asia/Hong_Kong')
 def test_daily_dst_lengths_and_half_hour_zone(self):
  for zone,date,hours,now in [('America/New_York','2026-03-08',23,'2026-03-10T00:00:00+00:00'),('America/New_York','2026-11-01',25,'2026-11-03T00:00:00+00:00'),('Asia/Kathmandu','2026-10-27',24,'2026-10-29T00:00:00+00:00')]:
   with self.subTest(zone=zone,date=date):
    s=selection({'window':'custom','start':date,'end':date,'timezone':zone},'UTC',epoch(now));self.assertEqual(s['end']-s['start'],hours*3600)
 def test_custom_and_window_bounds(self):
  now=epoch('2026-10-27T12:00:00+00:00')
  for p in [{'window':'all'},{'window':'custom','start':'2026-10-28','end':'2026-10-28'},{'window':'custom','start':'2026-01-01','end':'2026-10-27'},{'window':'custom','start':'2026-10-27','end':'2026-10-26'},{'window':'custom','start':'oops','end':'2026-10-27'},{'window':'30d','timezone':'invalid'},{'window':'30d','id':OTHER}]:
   with self.subTest(p=p),self.assertRaises(Problem):selection(p,'UTC',now)
  for w in ('24h','7d','30d','90d'):
   d=history(self.store,self.user,{'window':w},now=now);self.assertLessEqual(len(d['buckets']),170);self.assertEqual(d['window'],w)
 def test_old_daily_remains_explicit_utc_without_manufactured_local_history(self):
  now=epoch('2026-10-27T12:00:00+00:00')
  with self.store.db() as db:db.execute('INSERT INTO daily VALUES(?,?,?,?,?)',(ID,'tuic',int(now)//86400*86400,50,75))
  d=history(self.store,self.user,{'window':'90d'},now=now);self.assertEqual(d['legacy_utc_daily'][0]['up'],50);self.assertIsNone(d['totals']['upload_bytes'])
 def test_migration_freezes_prior_daily_before_new_delta_without_double_count(self):
  now=epoch('2026-10-27T12:00:00+00:00')
  with self.store.db() as db:db.execute('INSERT INTO daily VALUES(?,?,?,?,?)',(ID,'tuic',int(now)//86400*86400,50,75))
  self.ingest(now,100)
  d=history(self.store,self.user,{'window':'30d'},now=now+1)
  self.assertEqual(d['legacy_utc_daily'][0]['up'],50);self.assertEqual(d['totals']['upload_bytes'],100)
 def test_old_collector_rollback_does_not_create_false_observed_zeros(self):
  now=epoch('2026-10-27T12:00:00+00:00');self.ingest(now)
  with self.store.db() as db:
   old=json.loads(db.execute("SELECT value FROM meta WHERE key='sample'").fetchone()[0]);old['logical_time']=now+600;db.execute("UPDATE meta SET value=? WHERE key='sample'",(json.dumps(old),))
  self.ingest(now+610)
  d=history(self.store,self.user,{'window':'24h'},now=now+610)
  self.assertTrue(d['incomplete']);self.assertEqual(sum(b['observed_seconds'] for b in d['buckets']),0)
 def test_timezone_change_regroups_same_source_without_changing_bytes(self):
  now=epoch('2026-10-26T15:59:00+00:00');self.ingest(now,100);self.ingest(now+120,150)
  hk=history(self.store,self.user,{'window':'30d'},now=now+121)
  ny=history(self.store,self.user,{'window':'30d','timezone':'America/New_York'},now=now+121)
  self.assertEqual(hk['totals'],ny['totals']);self.assertEqual(len([b for b in hk['buckets'] if b['up'] is not None]),2);self.assertEqual(len([b for b in ny['buckets'] if b['up'] is not None]),1)
 def test_quarter_hour_zone_and_leap_day(self):
  self.user['quota']['timezone']='Asia/Kathmandu';now=epoch('2026-10-26T18:14:00+00:00');self.ingest(now,100);self.ingest(now+120,150)
  d=history(self.store,self.user,{'window':'30d'},now=now+121);self.assertEqual([b['up'] for b in d['buckets'] if b['up'] is not None],[100,50])
  s=selection({'window':'custom','start':'2028-02-28','end':'2028-03-01'},'Asia/Hong_Kong',epoch('2028-03-02T00:00:00+00:00'));self.assertEqual(s['end']-s['start'],72*3600)
if __name__=='__main__':unittest.main()
