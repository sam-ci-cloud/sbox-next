"""Real sudo use_pty regression: a piped Bash must exec the terminal reader.

Uses a tiny local package fixture, never installs SBOX or downloads anything.
Run as a user with passwordless sudo (GitHub runner), or root on the test VPS.
"""
import os,pty,select,signal,subprocess,time,unittest,tarfile,io,hashlib,re
from pathlib import Path
from test_public_bootstrap import Bootstrap

class SudoTerminal(Bootstrap):
 def test_sudo_pipe_nested_manager_receives_terminal_answers(self):
  root=Path(__file__).resolve().parents[1]
  template=(root/'SOURCE/src/install.template.sh').read_text()
  prefix=template.split('# Parse the entire embedded package')[0]
  tail=template.split('# A separate group cancels')[1].partition('\n')[2].split('COMPLETE=true\n}')[0]
  work=self.base/'manager-stage';work.mkdir()
  (work/'manager').write_text('read -r -p "FIXTURE ANSWER: " answer; printf "%s" "$answer" > "$TEST_MARKER"\n')
  script=(prefix+f'WORK={str(work)!r}\nargs=()\n'+tail+'COMPLETE=true\n').encode()
  with tarfile.open(self.archive,'w:gz') as z:
   i=tarfile.TarInfo('SING-BOX/install.sh');i.size=len(script);i.mode=0o755;z.addfile(i,io.BytesIO(script))
  digest=hashlib.sha256(self.archive.read_bytes()).hexdigest();self.bootstrap.write_text(re.sub(r"SBOX_SHA256='[^']+'","SBOX_SHA256='"+digest+"'",self.bootstrap.read_text()))
  self.test_sudo_pipe_guided_terminal_and_cleanup()
 def test_sudo_pipe_guided_terminal_and_cleanup(self):
  if subprocess.run(['sudo','-n','true'],capture_output=True).returncode:
   self.skipTest('Real sudo fixture needs root/passwordless sudo')
  pid,fd=pty.fork()
  if pid==0:
   for sig in (signal.SIGINT,signal.SIGHUP,signal.SIGTERM):signal.signal(sig,signal.SIG_DFL)
   os.execvpe('bash',['bash','-c','cat "$BOOTSTRAP_TEST" | sudo -n env PATH="$PATH" TEST_MARKER="$TEST_MARKER" TEST_REQUESTS="$TEST_REQUESTS" TEST_ARCHIVE="$TEST_ARCHIVE" SBOX_BOOTSTRAP_TMPDIR="$SBOX_BOOTSTRAP_TMPDIR" bash'],self.env)
  data=b'';sent=False;status=None;deadline=time.monotonic()+6
  try:
   while time.monotonic()<deadline:
    if select.select([fd],[],[],.05)[0]:
     try:data+=os.read(fd,65536)
     except OSError:break
     if b'FIXTURE ANSWER:' in data and not sent:os.write(fd,b'guided-answer\n');sent=True
    done,s=os.waitpid(pid,os.WNOHANG)
    if done:status=s;break
   self.assertTrue(sent,'Prompt was not visible: '+data.decode(errors='replace')[-500:])
   if not self.marker.exists():
    # This contains no secrets: fixture paths, process groups and states only.
    snap=subprocess.run(['ps','-eo','pid,ppid,sid,pgid,tpgid,stat,wchan:22,args'],capture_output=True,text=True).stdout
    lines=[line for line in snap.splitlines() if str(self.base) in line or 'sudo -n env PATH=' in line]
    self.fail('Guided input stopped after prompt under piped sudo. '+repr(lines)+' terminal='+data.decode(errors='replace')[-500:])
   self.assertEqual(self.marker.read_text(),'guided-answer')
   if status is None:
    _,status=os.waitpid(pid,0)
   self.assertEqual(os.waitstatus_to_exitcode(status),0,data.decode(errors='replace')[-500:])
  finally:
   os.close(fd)
   if status is None:
    try:os.kill(pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:os.waitpid(pid,0)
    except ChildProcessError:pass

if __name__=='__main__':unittest.main(verbosity=2)
