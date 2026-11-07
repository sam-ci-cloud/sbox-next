"""A preflight /tmp shortfall names stale installer work dirs without deleting anything."""
import os,pathlib,re,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];TEXT=(ROOT/'package/install.sh').read_text()
FN=re.search(r'^stale_installer_workdirs_hint\(\) \{\n.*?^\}',TEXT,re.M|re.S).group()
class StaleHint(unittest.TestCase):
    def run_hint(self,stale=True,locked=False):
        with tempfile.TemporaryDirectory() as td:
            t=pathlib.Path(td);(t/'tmp').mkdir();lock=t/'lock'
            if stale:(t/'tmp/sbox-all-in-one.AbCdEfGhIj').mkdir();(t/'tmp/sbox-all-in-one.AbCdEfGhIj/core').write_bytes(b'x'*2**20)
            holder=subprocess.Popen(['flock',str(lock),'sleep','5']) if locked else None
            if holder:
                import time;time.sleep(.3)
            uid=os.getuid()
            script='say(){ printf "%s\\n" "$*"; }\nstat(){ if [ "$2" = %u ]; then echo 0; else command stat "$@"; fi; }\n'+FN+'\nstale_installer_workdirs_hint\n'
            r=subprocess.run(['bash','-c',script],capture_output=True,text=True,env={**os.environ,'SBOX_HINT_TMP':str(t/'tmp'),'SBOX_HINT_LOCK':str(lock)})
            if holder:holder.kill();holder.wait()
            remaining=list((t/'tmp').iterdir())
            return r,remaining
    def test_stale_dirs_reported_when_no_installer_runs(self):
        r,rem=self.run_hint();self.assertEqual(r.returncode,0);self.assertIn('safe to remove',r.stdout);self.assertIn('MiB in /tmp',r.stdout);self.assertEqual(len(rem),1,'preflight must not delete')
    def test_running_installer_is_not_disturbed(self):
        r,rem=self.run_hint(locked=True);self.assertIn('appears to be running',r.stdout);self.assertNotIn('safe to remove',r.stdout);self.assertEqual(len(rem),1)
    def test_quiet_without_stale_dirs(self):
        r,_=self.run_hint(stale=False);self.assertEqual(r.stdout,'')
    def run_remove(self,locked=False,symlink=False):
        fn=re.search(r'^remove_stale_installer_workdirs\(\) \{\n.*?^\}',TEXT,re.M|re.S).group()
        with tempfile.TemporaryDirectory() as td:
            t=pathlib.Path(td);(t/'tmp').mkdir();lock=t/'lock';(t/'other').mkdir()
            (t/'tmp/sbox-all-in-one.AbCdEfGhIj').mkdir();(t/'tmp/sbox-all-in-one.AbCdEfGhIj/core').write_bytes(b'x'*2**20)
            (t/'tmp/sbox-all-in-one.short').mkdir();(t/'tmp/unrelated').mkdir()
            if symlink:(t/'tmp/sbox-all-in-one.LiNkLiNkLi').symlink_to(t/'other')
            holder=subprocess.Popen(['flock',str(lock),'sleep','5']) if locked else None
            if holder:
                import time;time.sleep(.3)
            script='say(){ printf "%s\\n" "$*"; }\nstat(){ if [ "$2" = %u ]; then echo 0; else command stat "$@"; fi; }\n'+fn+'\nremove_stale_installer_workdirs\n'
            r=subprocess.run(['bash','-c',script],capture_output=True,text=True,env={**os.environ,'SBOX_HINT_TMP':str(t/'tmp'),'SBOX_HINT_LOCK':str(lock)})
            if holder:holder.kill();holder.wait()
            return r,sorted(p.name for p in (t/'tmp').iterdir()),(t/'other').exists()
    def test_recover_removes_only_stale_installer_dirs(self):
        r,rem,other=self.run_remove(symlink=True)
        self.assertEqual(r.returncode,0);self.assertIn('Removed 1 stale work directory',r.stdout)
        self.assertEqual(rem,['sbox-all-in-one.LiNkLiNkLi','sbox-all-in-one.short','unrelated'],'symlinks, other names and unrelated dirs kept');self.assertTrue(other)
    def test_recover_leaves_dirs_while_an_installer_runs(self):
        r,rem,_=self.run_remove(locked=True);self.assertIn('appears to be running',r.stdout);self.assertIn('sbox-all-in-one.AbCdEfGhIj',rem)
    def test_recover_wiring(self):
        block=TEXT[TEXT.index('cmd_recover() {'):][:300];self.assertLess(block.index('remove_stale_installer_workdirs'),block.index('preflight recover'))
    def test_wired_into_tmp_shortfall_only(self):
        block=TEXT[TEXT.index('mb="$(free_mb /tmp)"'):][:400];self.assertIn('stale_installer_workdirs_hint',block.split('else',1)[1])
if __name__=='__main__':unittest.main(verbosity=2)
