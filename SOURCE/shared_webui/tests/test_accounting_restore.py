import copy,datetime as dt,json,sqlite3,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore
from accounting_restore import merge,validate
from quota_models import quota_plan
from usage_history import history
class Restore(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.id='a'*32;self.tag='user-'+self.id+'@reality';self.state={'protocols':{'reality':{'enabled':True}},'managed_users':[{'id':self.id,'enabled':True,'protocols':{'reality':{}},'quota':quota_plan({'period':'none'})}]}
 def tearDown(self):self.tmp.cleanup()
 def make(self,name,up,down,now=1780000000):
  s=MeterStore(self.root/name);s.ingest(self.state,name,{'user>>>'+self.tag+'>>>traffic>>>uplink':up,'user>>>'+self.tag+'>>>traffic>>>downlink':down},now);return s
 def test_restored_usage_idempotent_monotonic_with_gap_and_no_old_sessions(self):
  source=self.make('saved.db',200,300);live=self.make('live.db',500,100);state=copy.deepcopy(self.state)
  with live.db() as db:db.execute('INSERT INTO portal_sessions VALUES(?,?,?,?,?,?,?)',('old',self.id,'generation','csrf',1,1,9999999999))
  for _ in range(2):merge(source.path,state,live.path)
  view=live.view(state['managed_users'][0],now=1780000000);self.assertEqual(view['lifetime_up_bytes'],500);self.assertEqual(view['lifetime_down_bytes'],300);self.assertEqual(view['used_bytes'],800);self.assertTrue(view['collection_gap']);self.assertEqual(self.state,state)
  with live.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM portal_sessions').fetchone()[0],0)
 def test_empty_destination_imports_actual_archived_user(self):
  source=self.make('saved.db',200,300);target=self.root/'new.db';merge(source.path,self.state,target);view=MeterStore(target).view(self.state['managed_users'][0],now=1780000000);self.assertEqual(view['used_bytes'],500);self.assertEqual(view['lifetime_up_bytes'],200)
 def test_old_cycle_is_not_charged_to_current_cycle(self):
  self.state['managed_users'][0]['quota']=quota_plan({'period':'daily'});source=self.make('saved.db',200,300);live=self.make('live.db',20,30,1780000000+86400);merge(source.path,self.state,live.path);view=live.view(self.state['managed_users'][0],now=1780000000+86400);self.assertEqual(view['used_bytes'],50);self.assertEqual(view['lifetime_up_bytes'],200)
 def test_corrupt_source_never_changes_destination(self):
  live=self.make('live.db',20,30);bad=self.root/'bad';bad.write_bytes(b'bad sqlite');before=live.path.read_bytes()
  with self.assertRaises(Exception):merge(bad,self.state,live.path)
  self.assertEqual(before,live.path.read_bytes())
 def history_source(self):
  self.state['managed_users'][0]['quota']=quota_plan({'period':'none','timezone':'Asia/Hong_Kong'})
  source=MeterStore(self.root/'history.db');start=dt.datetime.fromisoformat('2026-10-26T15:59:50+00:00').timestamp()
  for seconds,up,down in [(0,100,0),(10,150,20),(20,170,30),(900,190,40),(910,210,50),(920,1,1),(930,21,6)]:
   source.ingest(self.state,'history-core',{'user>>>'+self.tag+'>>>traffic>>>uplink':up,'user>>>'+self.tag+'>>>traffic>>>downlink':down},start+seconds)
  return source,start+931
 def test_restores_calendar_history_coverage_and_gaps_to_empty_destination(self):
  source,now=self.history_source();user=self.state['managed_users'][0];target=self.root/'restored.db'
  selections=[{'window':w} for w in ('24h','7d','30d','90d')]+[{'window':'custom','start':'2026-10-26','end':'2026-10-27'}]
  before=[history(source,user,selection,now=now) for selection in selections]
  with source.db() as db:self.assertGreater(db.execute('SELECT COUNT(*) FROM history_gaps').fetchone()[0],0)
  merge(source.path,self.state,target);restored=MeterStore(target)
  for selection,expected in zip(selections,before):
   with self.subTest(selection=selection):
    actual=history(restored,user,selection,now=now)
    for key in ('buckets','totals','incomplete','collection_started_at','legacy_utc_daily'):self.assertEqual(actual[key],expected[key],key)
  with source.db() as original,restored.db() as actual:
   for table in ('history_bins','history_users','history_coverage','history_gaps','history_legacy'):
    self.assertEqual([tuple(r) for r in actual.execute('SELECT * FROM '+table+' ORDER BY 1,2')],[tuple(r) for r in original.execute('SELECT * FROM '+table+' ORDER BY 1,2')],table)
 def test_history_merge_preserves_live_bytes_and_is_idempotent(self):
  source,now=self.history_source();live=self.make('live-history.db',500,100,now);user=self.state['managed_users'][0]
  def bins(store):
   with store.db() as db:return {r['bucket']:(r['up'],r['down']) for r in db.execute('SELECT * FROM history_bins WHERE user_id=?',(self.id,))}
  expected=bins(live)
  for bucket,values in bins(source).items():expected[bucket]=tuple(max(a,b) for a,b in zip(expected.get(bucket,(0,0)),values))
  merge(source.path,self.state,live.path);once=history(live,user,{'window':'30d'},now=now)
  self.assertEqual(bins(live),expected)
  merge(source.path,self.state,live.path);self.assertEqual(history(live,user,{'window':'30d'},now=now),once)
  with live.db() as db:self.assertIsNone(db.execute("SELECT value FROM meta WHERE key='history_last_sample'").fetchone())
 def test_overlapping_partial_coverage_cannot_become_invented_full_coverage(self):
  source,now=self.history_source();live=self.make('partial.db',500,100,now);bucket=int(now)//900*900
  for store in (source,live):
   with store.db() as db:db.execute('INSERT OR REPLACE INTO history_coverage VALUES(?,?,?,?)',(bucket,600,bucket,bucket+900))
  merge(source.path,self.state,live.path)
  with live.db() as db:
   row=db.execute('SELECT * FROM history_coverage WHERE bucket=?',(bucket,)).fetchone()
   self.assertEqual(row['observed_seconds'],600);self.assertEqual(row['first'],bucket);self.assertEqual(row['last'],bucket+900)
 def test_invalid_archived_history_rolls_back_all_usage_changes(self):
  source,now=self.history_source();live=self.make('live-invalid.db',20,30,now)
  with live.db() as db:before=[tuple(r) for r in db.execute('SELECT * FROM totals ORDER BY user_id')]
  with source.db() as db:db.execute('UPDATE history_bins SET up=-1 WHERE user_id=?',(self.id,))
  with self.assertRaises(Exception):merge(source.path,self.state,live.path)
  with live.db() as db:self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM totals ORDER BY user_id')],before)
 def test_old_backup_keeps_utc_legacy_history_when_live_tracking_exists(self):
  source=self.make('old.db',200,300);live=self.make('new.db',20,30,1780000000+86400);user=self.state['managed_users'][0]
  with source.db() as db:
   for table in ('history_bins','history_users','history_coverage','history_gaps','history_legacy'):db.execute('DROP TABLE '+table)
   db.execute("DELETE FROM meta WHERE key LIKE 'history_%'")
  merge(source.path,self.state,live.path)
  result=history(live,user,{'window':'30d'},now=1780000000+86401)
  self.assertTrue(any(r['up']==200 and r['down']==300 for r in result['legacy_utc_daily']))
  self.assertEqual(result['totals'],{'upload_bytes':20,'download_bytes':30})
if __name__=='__main__':unittest.main()
