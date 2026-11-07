"""A collector policy can advance while a killed staging upgrade releases its lock."""
from pathlib import Path
import os,json,tempfile,subprocess,unittest,shutil
ROOT=Path(os.environ.get('SBOX_MANAGER_ROOT',Path(__file__).resolve().parents[2]/'.build'))
SOURCE=ROOT/'src/manager.sh'
SOURCE_NAME='sing-box V2Ray StatsService: authenticated routed payload; excludes host/provider overhead'
class LiveQuotaRecovery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.old=self.root/'snapshot';self.live=self.root/'live';self.old.mkdir();self.live.mkdir();self.ident='1'*32
  state={'managed_users':[{'id':self.ident,'protocols':{'tuic':{},'hy2':{}}}]}
  for folder in (self.old,self.live):
   (folder/'state.json').write_text(json.dumps(state));(folder/'state.json').chmod(0o640)
   (folder/'quota-runtime.json').write_text(json.dumps({'blocked':[],'sampled_at':1000.0,'source':SOURCE_NAME}));(folder/'quota-runtime.json').chmod(0o640)
  source=SOURCE.read_text();body=source[source.index('runtime_snapshot_tool() {'):source.index('seal_runtime_snapshot() {')];self.functions=self.root/'functions.sh';self.functions.write_text(body)
 def tearDown(self):self.tmp.cleanup()
 def run_tool(self,action,*args):
  return subprocess.run(['bash','-c','source "$1"; shift; runtime_snapshot_tool "$@"','test',str(self.functions),action,*map(str,args)],capture_output=True,text=True)
 def advance(self,**values):
  p=self.live/'quota-runtime.json';d=json.loads(p.read_text());d.update(sampled_at=1001.0,**values);p.write_text(json.dumps(d))
 def test_fresh_policy_advance_accepted_only_in_staging_mode(self):
  self.advance(blocked=['user-'+self.ident+'@tuic'])
  self.assertNotEqual(self.run_tool('compare',self.old,self.live).returncode,0)
  r=self.run_tool('compare',self.old,self.live,'live-quota');self.assertEqual(r.returncode,0,r.stderr)
 def test_changed_authoritative_state_is_still_rejected(self):
  self.advance();(self.live/'state.json').write_text('{"managed_users":[]}')
  self.assertNotEqual(self.run_tool('compare',self.old,self.live,'live-quota').returncode,0)
 def test_invalid_policy_cannot_hide_behind_volatile_exception(self):
  for values in ({'blocked':['user-'+'2'*32+'@tuic']},{'blocked':['legacy']},{'sampled_at':float('nan')},{'source':'untrusted'},{'blocked':[],'unexpected':'field'}):
   with self.subTest(values=list(values)):
    p=self.live/'quota-runtime.json';p.write_bytes((self.old/'quota-runtime.json').read_bytes());d=json.loads(p.read_text());d.update(values);p.write_text(json.dumps(d));self.assertNotEqual(self.run_tool('compare',self.old,self.live,'live-quota').returncode,0)
 def test_file_type_and_permissions_remain_exact(self):
  self.advance();p=self.live/'quota-runtime.json';p.chmod(0o666);self.assertNotEqual(self.run_tool('compare',self.old,self.live,'live-quota').returncode,0)
  p.unlink();p.symlink_to(self.old/'quota-runtime.json');self.assertNotEqual(self.run_tool('compare',self.old,self.live,'live-quota').returncode,0)
 def test_snapshot_integrity_stays_byte_exact(self):
  self.assertEqual(self.run_tool('seal',self.old).returncode,0);p=self.old/'quota-runtime.json';p.write_text('{}');self.assertNotEqual(self.run_tool('validate',self.old).returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
