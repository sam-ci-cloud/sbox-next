"""Minimal-image bootstrap gates without mutating the workstation's packages."""
from pathlib import Path
import os,shutil,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class Bootstrap(unittest.TestCase):
 def test_generic_readonly_verification_needs_no_python(self):
  with tempfile.TemporaryDirectory() as td:
   for name in ['bash','base64','gzip','sha256sum','mktemp','rm','chmod','stat','id','uname']:
    Path(td,name).symlink_to(shutil.which(name))
   r=subprocess.run([shutil.which('bash'),str(ROOT/'install.sh'),'verify','generic'],env={**os.environ,'PATH':td},capture_output=True,text=True,timeout=40)
   self.assertEqual(r.returncode,0,r.stderr)
 def run_fragment(self,missing,env=None):
  source=(ROOT/'src/install.template.sh').read_text();body=source[source.index(' missing_bootstrap=false'):source.index(' command -v setsid')]
  prefix='''VARIANT=generic
log() { :; }; die() { echo "$*" >&2;exit 9; }; sleep() { :; }
command() { if [ "$1" = -v ] && [ "$2" = python3 ] && [ "$MISSING" = yes ];then return 1;fi;return 0; }
apt-get() { [ "$DEBIAN_FRONTEND" = noninteractive ] && [ "$NEEDRESTART_MODE" = l ] && [ ! -t 0 ] || exit 7;printf '%s\\n' "$*"
 # FAIL_FIRST=N: the first N calls fail (lock held, mirror error) before success.
 CALLS=$((${CALLS:-0}+1)); [ "$CALLS" -gt "${FAIL_FIRST:-0}" ]; }
'''
  return subprocess.run(['bash','-c',prefix+body],env={**os.environ,'MISSING':missing,**(env or {})},capture_output=True,text=True)
 def test_missing_python_bootstraps_os_packages(self):
  r=self.run_fragment('yes');self.assertEqual(r.returncode,0,r.stderr);self.assertIn('update',r.stdout);self.assertIn('install -y --no-install-recommends python3 openssl util-linux ca-certificates',r.stdout)
 def test_bootstrap_waits_for_dpkg_lock(self):
  r=self.run_fragment('yes');self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(r.stdout.count('-o DPkg::Lock::Timeout=600'),2,r.stdout)
 def test_bootstrap_retries_transient_apt_failure(self):
  r=self.run_fragment('yes',{'FAIL_FIRST':'2'});self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(r.stdout.count('update'),3,r.stdout);self.assertEqual(r.stdout.count('install -y'),1,r.stdout)
 def test_bootstrap_gives_up_with_actionable_error(self):
  r=self.run_fragment('yes',{'FAIL_FIRST':'99'});self.assertEqual(r.returncode,9)
  self.assertEqual(r.stdout.count('update'),3,r.stdout);self.assertIn('no SBOX state was changed',r.stderr);self.assertIn('sources.list',r.stderr)
 def test_present_dependencies_do_not_run_apt(self):
  r=self.run_fragment('no');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'')
if __name__=='__main__':unittest.main(verbosity=2)
