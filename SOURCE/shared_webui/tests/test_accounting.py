"""Deterministic database/clock/fault regression; real wire proof is separate."""
import sys,tempfile,unittest,json,sqlite3
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore,identities
ID='a'*32;BID='b'*32;NOW=1792886400
class Meter(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.store=MeterStore(Path(self.temp.name)/'usage.db');self.state={'protocols':{p:{'enabled':True} for p in ['reality','vmess','hy2','tuic','anytls']},'managed_users':[{'id':i,'enabled':True,'protocols':{'tuic':{}},'quota':{'quota_bytes':1000,'period':'monthly','timezone':'UTC','reset_day':1}} for i in [ID,BID]]}
 def tearDown(self):self.temp.cleanup()
 def sample(self,up=100,down=200,other=0,instance='core1',now=NOW):
  return self.store.ingest(self.state,instance,{'user>>>user-'+ID+'@tuic>>>traffic>>>uplink':up,'user>>>user-'+ID+'@tuic>>>traffic>>>downlink':down,'user>>>user-'+BID+'@tuic>>>traffic>>>uplink':other},now)
 def view(self,i=0,now=NOW):return self.store.view(self.state['managed_users'][i],now=now)
 def test_first_measurement_two_users_and_direction(self):
  self.sample();r=self.view();self.assertEqual((r['used_bytes'],r['upload_bytes'],r['download_bytes']),(300,100,200));self.assertEqual(self.view(1)['used_bytes'],0)
 def test_duplicate_sample_and_reopen_no_double_count(self):
  self.sample();self.sample();self.store=MeterStore(self.store.path);self.sample();self.assertEqual(self.view()['used_bytes'],300)
  with self.store.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM meter_deltas').fetchone()[0],1)
 def test_monotonic_delta(self):
  self.sample();self.sample(130,240,now=NOW+2);self.assertEqual(self.view(now=NOW+2)['used_bytes'],370)
 def test_reset_does_not_subtract(self):
  self.sample();self.sample(10,20,now=NOW+2);self.assertEqual(self.view(now=NOW+2)['used_bytes'],300);self.assertTrue(self.view(now=NOW+2)['collection_gap']);self.sample(20,30,now=NOW+4);self.assertEqual(self.view(now=NOW+4)['used_bytes'],320)
 def test_new_core_counts_new_bytes_and_marks_discontinuity(self):
  self.sample();self.sample(10,20,instance='core2',now=NOW+3);r=self.view(now=NOW+3);self.assertEqual(r['used_bytes'],330);self.assertTrue(r['collection_gap'])
 def test_quota_hit_blocks_only_one_user_and_not_legacy(self):
  p=self.sample(500,600,other=10);self.assertEqual(p['blocked'],['user-'+ID+'@tuic']);self.assertEqual(self.view()['status'],'quota_exceeded');self.assertEqual(self.view(1)['status'],'active')
 def test_topup_and_pause_precedence(self):
  self.sample(500,600);u=self.state['managed_users'][0];u['quota']['quota_bytes']=2000;u['quota']['manual_disabled']=True;self.sample(500,600,now=NOW+2);self.assertEqual(self.view(now=NOW+2)['status'],'manually_disabled');u['quota']['manual_disabled']=False;self.sample(500,600,now=NOW+3);self.assertEqual(self.view(now=NOW+3)['status'],'active')
 def test_manual_disable_survives_reset(self):
  self.sample(500,600);u=self.state['managed_users'][0];u['enabled']=False;u['quota']['reset_seq']=1;self.sample(500,600,now=NOW+2);r=self.view(now=NOW+2);self.assertEqual(r['used_bytes'],0);self.assertEqual(r['status'],'manually_disabled');self.assertEqual(r['lifetime_up_bytes']+r['lifetime_down_bytes'],1100)
 def test_expiry_without_exhaustion(self):
  self.state['managed_users'][0]['quota']['expires_at']=NOW-1;p=self.sample();self.assertIn('user-'+ID+'@tuic',p['blocked']);self.assertEqual(self.view()['status'],'expired')
 def test_clock_back_never_reduces_usage_or_resets(self):
  self.sample();self.sample(150,250,now=NOW-3600);r=self.view();self.assertEqual(r['used_bytes'],400);self.assertTrue(self.store.metadata('sample')['clock_moved_backwards'])
 def test_invalid_sample_rolls_back_all_watermarks(self):
  self.sample()
  with self.assertRaises(Exception):self.sample(-1,20,now=NOW+1)
  self.sample(150,250,now=NOW+2);self.assertEqual(self.view(now=NOW+2)['used_bytes'],400)
 def test_outage_last_known_explicitly_stale_not_fake_zero(self):
  self.sample();r=self.store.view(self.state['managed_users'][0],{'status':'degraded'},now=NOW+60);self.assertEqual(r['used_bytes'],300);self.assertEqual(r['freshness'],'stale')
 def test_reset_during_outage_is_pending_not_zero(self):
  self.sample();self.state['managed_users'][0]['quota']['reset_seq']=1;r=self.store.view(self.state['managed_users'][0],{'status':'degraded'},now=NOW+60);self.assertIsNone(r['used_bytes']);self.assertTrue(r['reset_pending'])
 def test_unknown_user_has_no_fake_usage(self):
  self.assertIsNone(self.view()['used_bytes']);self.assertEqual(self.view()['freshness'],'unavailable')
 def test_threshold_dedup(self):
  self.sample(800,0);self.sample(950,0,now=NOW+1);self.sample(1100,0,now=NOW+2);self.sample(1100,0,now=NOW+3);self.assertEqual(len(self.store.events()),3)
if __name__=='__main__':unittest.main()
