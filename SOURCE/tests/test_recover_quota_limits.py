"""Interrupted-upgrade recovery must accept the accounting collector's own quota policy (incl. per-user limits)."""
import json,os,pathlib,re,shutil,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE='sing-box V2Ray StatsService: authenticated routed payload; excludes host/provider overhead'
def tool():
    m=re.search(r"\nimport hashlib,json,os,stat,sys\n.*?\nelse:raise SystemExit\('invalid snapshot action'\)\n",(ROOT/'src/manager.sh').read_text(),re.S)
    if not m:raise AssertionError('snapshot tool not found')
    return m.group().replace('@@SNAPSHOT_COMPARE@@',(ROOT/'src/snapshot_compare.inc').read_text().rstrip('\n'))
class RecoverQuota(unittest.TestCase):
    def compare(self,live_policy,extra_change=False):
        with tempfile.TemporaryDirectory() as td:
            t=pathlib.Path(td);script=t/'snap.py';script.write_text(tool())
            state={'managed_users':[{'id':'a1','protocols':{'vmess':{}}},{'id':'b2','protocols':{'vmess':{}}}]}
            for d,policy in (('snap',{'blocked':[],'sampled_at':1.0,'source':SOURCE}),('live',live_policy)):
                (t/d).mkdir();(t/d/'state.json').write_text(json.dumps(state));q=t/d/'quota-runtime.json';q.write_text(json.dumps(policy));q.chmod(0o640)
                (t/d/'config.json').write_text('{}' if not (extra_change and d=='live') else '{"changed":1}')
            return subprocess.run([sys.executable,'-B',str(script),'compare',str(t/'snap'),str(t/'live'),'live-quota'],capture_output=True,text=True)
    def base(self,**kw):return {'blocked':[],'proven_blocked':[],'sampled_at':2.0,'source':SOURCE,**kw}
    def test_collector_policy_with_limits_is_accepted(self):
        r=self.compare(self.base(limits={'user-a1':5000000000}));self.assertEqual(r.returncode,0,r.stderr)
        r=self.compare(self.base(limits={}));self.assertEqual(r.returncode,0,r.stderr)
    def test_invalid_limits_are_rejected(self):
        for bad in ({'user-zz':1},{'user-a1':-1},{'user-a1':True},{'user-a1':1.5},[1]):
            with self.subTest(bad=bad):
                r=self.compare(self.base(limits=bad));self.assertNotEqual(r.returncode,0);self.assertIn('invalid live quota',r.stderr+r.stdout)
        r=self.compare(self.base(unexpected=1));self.assertNotEqual(r.returncode,0)
    def test_other_files_stay_byte_exact(self):
        r=self.compare(self.base(limits={'user-a1':1}),extra_change=True);self.assertNotEqual(r.returncode,0);self.assertIn('differs',r.stderr+r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
