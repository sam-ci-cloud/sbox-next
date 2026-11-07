#!/usr/bin/env python3
"""Local package regressions. No deployment commands run on the workstation."""
import argparse,hashlib,json,os,pathlib,pty,select,signal,subprocess,tempfile,time,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];INSTALL=ROOT/'install.sh'
def run(args=(),data=None,env=None,path=INSTALL):
 return subprocess.run(['bash',str(path),*args],input=data,capture_output=True,text=True,timeout=40,env={**os.environ,**(env or {})},start_new_session=True)
class Package(unittest.TestCase):
 def test_bash_syntax(self):self.assertEqual(subprocess.run(['bash','-n',str(INSTALL)]).returncode,0)
 def test_generic_verify_without_unlock_or_root(self):
  r=run(['verify','generic'],env={'SBOX_ZGO_UNLOCK_FILE':'/definitely/not/read'});self.assertEqual(r.returncode,0,r.stderr);self.assertIn('integrity passed',r.stderr)
 def test_cli_errors(self):
  for args in [('verify',),('verify','bogus'),('verify','generic','oops'),('upgrade','generic','--force'),('help','oops'),('bogus',)]:
   with self.subTest(args=args):self.assertNotEqual(run(args).returncode,0)
 def test_no_terminal_menu_fails_fast(self):
  r=run();self.assertNotEqual(r.returncode,0);self.assertIn('No interactive terminal',r.stderr)
 def test_nonroot_install_refused(self):
  if os.geteuid()==0:
   # Drop to the unprivileged 'nobody' account so the refusal is exercised
   # for real in root CI containers instead of being skipped.
   import shutil
   setpriv=shutil.which('setpriv')
   if not setpriv:self.skipTest('setpriv (util-linux) is required to drop privileges as root')
   with tempfile.TemporaryDirectory() as td:
    copy=pathlib.Path(td)/'install.sh';shutil.copyfile(INSTALL,copy);os.chmod(td,0o755);copy.chmod(0o755)
    r=subprocess.run([setpriv,'--reuid=65534','--regid=65534','--clear-groups','bash',str(copy),'install','generic'],capture_output=True,text=True,timeout=60,cwd=td,env={**os.environ,'HOME':td})
  else:r=run(['install','generic'])
  self.assertNotEqual(r.returncode,0);self.assertIn('root SSH shell',r.stderr)
 def test_wrong_unlock_with_xtrace_no_leak(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'unlock';p.write_text('SYNTHETIC-WRONG-UNLOCK-DO-NOT-LOG');p.chmod(0o600)
   r=subprocess.run(['bash','-xv',str(INSTALL),'verify','zgocloud'],capture_output=True,text=True,env={**os.environ,'SBOX_ZGO_UNLOCK_FILE':str(p)},timeout=40)
   self.assertNotEqual(r.returncode,0);self.assertNotIn(p.read_text(),r.stdout+r.stderr);self.assertIn('Incorrect ZgoCloud unlock',r.stderr)
 def test_unlock_file_private_policy(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'unlock';p.write_text('synthetic');p.chmod(0o644)
   r=run(['verify','zgocloud'],env={'SBOX_ZGO_UNLOCK_FILE':str(p)});self.assertNotEqual(r.returncode,0);self.assertIn('chmod 600',r.stderr)
   p.chmod(0o600);link=pathlib.Path(td)/'symlink';link.symlink_to(p)
   self.assertNotEqual(run(['verify','zgocloud'],env={'SBOX_ZGO_UNLOCK_FILE':str(link)}).returncode,0)
 def test_corruption_and_truncation_fail(self):
  text=INSTALL.read_text()
  variants=[text[:text.index('if [ "$VARIANT" = generic ]; then')],text[:text.index('\nSBOX_CORE_PAYLOAD\n')],text.replace('SBOX_GENERIC_PAYLOAD\n','SBOX_GENERIC_PAYLOAD\n!',1)]
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'broken.sh'
   for s in variants:
    p.write_text(s)
    with self.subTest(bytes=len(s)):self.assertNotEqual(run(['verify','generic'],path=p).returncode,0)
 def test_process_substitution(self):
  r=subprocess.run(['bash','-c','bash <(cat "$1") verify generic','test',str(INSTALL)],capture_output=True,text=True,timeout=40,start_new_session=True)
  self.assertEqual(r.returncode,0,r.stderr)
 def test_menu_on_controlling_terminal(self):
  pid,fd=pty.fork()
  if pid==0:os.execvp('bash',['bash','-c','bash <(cat "$1")','test',str(INSTALL)])
  data=b'';end=time.monotonic()+30;sent=False
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],1)[0]:
     try:chunk=os.read(fd,65536)
     except OSError:break
     if not chunk:break
     data+=chunk
     if b'Select [0-5]' in data and not sent:os.write(fd,b'0\n');sent=True
   else:os.kill(pid,signal.SIGTERM)
   _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
   for label in (b'Universal SBOX',b'ZgoCloud',b'Upgrade',b'Verify package'):self.assertIn(label,data)
  finally:os.close(fd)
 def test_private_tty_prompt_and_no_echo(self):
  secret=b'SYNTHETIC-WRONG-PRIVATE-UNLOCK-1234567890'
  pid,fd=pty.fork()
  if pid==0:
   os.environ.pop('SBOX_ZGO_UNLOCK_FILE',None);os.execvp('bash',['bash',str(INSTALL),'verify','zgocloud'])
  data=b'';sent=False;end=time.monotonic()+30
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],1)[0]:
     try:b=os.read(fd,65536)
     except OSError:break
     if not b:break
     data+=b
     if b'private unlock passphrase:' in data and not sent:os.write(fd,secret+b'\n');sent=True
   else:os.kill(pid,signal.SIGTERM)
   _,status=os.waitpid(pid,0);self.assertNotEqual(os.waitstatus_to_exitcode(status),0)
   self.assertTrue(sent,data.decode(errors='replace'));self.assertNotIn(secret,data);self.assertIn(b'Incorrect ZgoCloud unlock',data)
  finally:os.close(fd)
 def test_repeat_build_does_not_mutate_source(self):
  source=[p for folder in ('src','shared_webui','tools') for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
  before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in source};artifact=INSTALL.read_bytes()
  subprocess.run(['python3',str(ROOT/'tools/build.py')],check=True,capture_output=True)
  self.assertEqual(artifact,INSTALL.read_bytes());self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in source})
if __name__=='__main__':unittest.main(verbosity=2)
