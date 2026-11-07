"""Same-host restore/rollback must keep a valid renewable Let's Encrypt lineage."""
import json,pathlib,re,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];MANAGER=(ROOT/'src/manager.sh').read_text()
def function(name):
    m=re.search(r'^'+name+r'\(\) \{\n.*?^\}',MANAGER,re.M|re.S)
    if not m:raise AssertionError('Required shell function missing: '+name)
    return m.group()
class RestoreLineage(unittest.TestCase):
    def decide(self,cert,lineage_ok=True,covers=True):
        with tempfile.TemporaryDirectory() as tmp:
            c=pathlib.Path(tmp)/'state.json';c.write_text(json.dumps({'domain':'vpn.example.test','certificate':cert}))
            script=('set -u\ncertbot_lineage_reusable() { return %d; }\ncert_matches_domain() { return %d; }\n'%(0 if lineage_ok else 1,0 if covers else 1)
                    +function('restore_keeps_certbot_lineage')+'\nrestore_keeps_certbot_lineage "$1"\n')
            return subprocess.run(['bash','-c',script,'t',str(c)],capture_output=True,text=True).returncode==0
    LE={'mode':'certbot-http01','source_mode':'letsencrypt','source_fullchain':'/etc/letsencrypt/live/vpn.example.test/fullchain.pem','source_key':'/etc/letsencrypt/live/vpn.example.test/privkey.pem','insecure':False}
    def test_valid_same_host_lineage_is_kept(self):
        self.assertTrue(self.decide(self.LE));self.assertTrue(self.decide({**self.LE,'mode':'certbot-dns-cloudflare'}))
    def test_static_copy_when_lineage_unusable_or_not_certbot(self):
        self.assertFalse(self.decide(self.LE,lineage_ok=False))
        self.assertFalse(self.decide(self.LE,covers=False))
        self.assertFalse(self.decide({**self.LE,'mode':'existing'}))
        self.assertFalse(self.decide({**self.LE,'source_mode':'restored-backup'}))
        self.assertFalse(self.decide({k:v for k,v in self.LE.items() if k!='source_key'}))
    def test_restore_consults_lineage_before_static_copy(self):
        body=MANAGER[MANAGER.index('restore_command() {'):]
        keep=body.index('restore_keeps_certbot_lineage "$candidate"');static=body.index('source_mode:"restored-backup"')
        self.assertLess(keep,static)
if __name__=='__main__':unittest.main(verbosity=2)
