"""Legacy protected shared StatsService identity is one measured aggregate."""
from pathlib import Path
import sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore
class LegacyShared(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.store=MeterStore(Path(self.temp.name)/'usage.db');self.state={'zgo_legacy_compat':True,'protocols':{p:{'enabled':True} for p in ('reality','vmess','hy2','tuic','anytls')},'managed_users':[]}
 def tearDown(self):self.temp.cleanup()
 def ingest(self,up,down,at):return self.store.ingest(self.state,'same-core',{'user>>>sbox>>>traffic>>>uplink':up,'user>>>sbox>>>traffic>>>downlink':down},now=at)
 def amount(self):
  with self.store.db() as d:return tuple(d.execute('SELECT lifetime_up,lifetime_down FROM totals WHERE user_id="legacy"').fetchone())
 def test_measured_shared_counter_counted_once_and_kept_combined(self):
  self.ingest(100,200,1792886400);self.assertEqual(self.amount(),(100,200));self.ingest(100,200,1792886401);self.assertEqual(self.amount(),(100,200));self.ingest(130,240,1792886402);self.assertEqual(self.amount(),(130,240))
  with self.store.db() as d:self.assertEqual([tuple(r) for r in d.execute('SELECT protocol,up,down FROM protocol_totals')],[('legacy_shared',130,240)])
 def test_generic_does_not_adopt_unknown_counter(self):
  self.state.pop('zgo_legacy_compat');self.ingest(100,200,1792886400);self.assertEqual(self.amount(),(0,0))
 def test_preceding_coverage_is_partial_without_fabricated_historical_split(self):
  self.state.pop('zgo_legacy_compat');self.ingest(100,200,1792886400);self.ingest(100,200,1792886402)
  with self.store.db() as d:d.execute('INSERT INTO history_coverage VALUES(?,?,?,?)',(1792885500,900,1792885500,1792886400))
  self.state['zgo_legacy_compat']=True;self.ingest(100,200,1792886404)
  with self.store.db() as d:
   self.assertIsNotNone(d.execute('SELECT 1 FROM history_gaps WHERE user_id="legacy" AND bucket=?',(1792885500,)).fetchone())
   self.assertEqual(d.execute('SELECT COUNT(*) FROM history_bins WHERE bucket<?',(1792886400,)).fetchone()[0],0)
 def test_protected_backup_with_shared_counter_restores(self):
  # 1.2.0 regression: restore rejected the archived 'legacy_shared' counter,
  # so protected backups with Hysteria2/AnyTLS usage could not be restored.
  import shutil,sqlite3,accounting_restore
  from common import Problem
  self.ingest(100,200,1792886400);self.ingest(130,240,1792886402)
  archive=Path(self.temp.name)/'archive.db';shutil.copyfile(Path(self.temp.name)/'usage.db',archive)
  target=Path(self.temp.name)/'restored.db'
  result=accounting_restore.merge(archive,self.state,target)
  self.assertEqual(result['restored_usage_identities'],1)
  with sqlite3.connect(target) as d:self.assertEqual(d.execute("SELECT protocol,up,down FROM protocol_totals WHERE user_id='legacy'").fetchall(),[('legacy_shared',130,240)])
  # A Universal state must not import the protected-only combined counter.
  with self.assertRaises(Problem):accounting_restore.merge(archive,{k:v for k,v in self.state.items() if k!='zgo_legacy_compat'},Path(self.temp.name)/'universal.db')
if __name__=='__main__':unittest.main()
