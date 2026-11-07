"""Small fixture tests for piped bootstrap trust/error/terminal behavior, no VPS changes."""
import hashlib,io,os,pty,re,select,shutil,subprocess,tarfile,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Bootstrap(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.bin=self.base/'bin';self.bin.mkdir();self.marker=self.base/'ran';self.requests=self.base/'requests'
  self.archive=self.base/'fixture.tar.gz'
  script=b'''#!/bin/bash
if [ "$#" -eq 0 ]; then read -r -p 'FIXTURE ANSWER: ' answer; printf '%s' "$answer" > "$TEST_MARKER"; else printf '%s' "$*" > "$TEST_MARKER"; fi
'''
  with tarfile.open(self.archive,'w:gz') as z:
   i=tarfile.TarInfo('SING-BOX/install.sh');i.size=len(script);i.mode=0o755;z.addfile(i,io.BytesIO(script))
  self.stub('id','echo "${TEST_UID:-0}"');self.stub('uname','if [ "$1" = -s ]; then echo Linux; else echo "${TEST_ARCH:-x86_64}"; fi')
  self.stub('curl','echo fetched >> "$TEST_REQUESTS"; while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then cp "$TEST_ARCHIVE" "$2"; exit; fi; shift; done; exit 92')
  self.bootstrap=self.base/'bootstrap.sh';text=(ROOT/'install.sh').read_text();digest=hashlib.sha256(self.archive.read_bytes()).hexdigest();text=re.sub(r"SBOX_SHA256='[^']+'", "SBOX_SHA256='"+digest+"'",text);self.bootstrap.write_text(text)
  self.env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],'TEST_MARKER':str(self.marker),'TEST_REQUESTS':str(self.requests),'TEST_ARCHIVE':str(self.archive),'BOOTSTRAP_TEST':str(self.bootstrap),'SBOX_BOOTSTRAP_TMPDIR':str(self.base)}
 def stub(self,name,body):
  p=self.bin/name;p.write_text('#!/bin/bash\nset -eu\n'+body+'\n');p.chmod(0o755)
 def piped(self,args='help',**changes):
  return subprocess.run(['bash','-c','cat "$BOOTSTRAP_TEST" | bash -s -- '+args],capture_output=True,text=True,env={**self.env,**changes},start_new_session=True,timeout=15)
 def test_piped_unattended_args_and_fixed_digest(self):
  r=self.piped('help');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(self.marker.read_text(),'help');self.assertIn(': OK',r.stdout)
 def test_checksum_failure_never_executes(self):
  text=self.bootstrap.read_text();self.bootstrap.write_text(re.sub(r"SBOX_SHA256='[^']+'","SBOX_SHA256='"+'0'*64+"'",text));r=self.piped();self.assertNotEqual(r.returncode,0);self.assertFalse(self.marker.exists())
 def test_staged_archive_keeps_fixed_digest_without_online_fetch(self):
  r=self.piped('verify generic',SBOX_INSTALL_ARCHIVE=str(self.archive));self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(self.marker.read_text(),'verify generic');self.assertFalse(self.requests.exists());self.assertIn(': OK',r.stdout)
 def test_staged_corruption_fails_before_execution(self):
  self.archive.write_bytes(self.archive.read_bytes()+b'corruption');r=self.piped(SBOX_INSTALL_ARCHIVE=str(self.archive));self.assertNotEqual(r.returncode,0);self.assertFalse(self.marker.exists());self.assertFalse(self.requests.exists())
 def test_no_tty_guided_fails_before_download(self):
  r=self.piped('');self.assertNotEqual(r.returncode,0);self.assertIn('No controlling terminal',r.stderr);self.assertFalse(self.requests.exists())
 def test_permission_platform_and_download_failure(self):
  for kw in [{'TEST_UID':'1000'},{'TEST_ARCH':'aarch64'}]:
   r=self.piped(**kw);self.assertNotEqual(r.returncode,0);self.assertFalse(self.requests.exists());self.assertFalse(self.marker.exists())
  self.stub('curl','exit 22');r=self.piped();self.assertNotEqual(r.returncode,0);self.assertFalse(self.marker.exists())
 def test_real_controlling_tty_is_used_instead_of_script_pipe(self):
  pid,fd=pty.fork()
  if pid==0:os.execvpe('bash',['bash','-c','cat "$BOOTSTRAP_TEST" | bash'],self.env)
  data=b'';sent=False;deadline=time.monotonic()+15;status=None
  try:
   while time.monotonic()<deadline:
    if select.select([fd],[],[],.1)[0]:
     try:data+=os.read(fd,65536)
     except OSError:break
     if b'FIXTURE ANSWER:' in data and not sent:os.write(fd,b'terminal-input\n');sent=True
    done,s=os.waitpid(pid,os.WNOHANG)
    if done:status=s;break
   if status is None:_,status=os.waitpid(pid,0)
   self.assertEqual(os.waitstatus_to_exitcode(status),0,data.decode(errors='replace'));self.assertTrue(sent);self.assertEqual(self.marker.read_text(),'terminal-input')
  finally:os.close(fd)
if __name__=='__main__':unittest.main(verbosity=2)
