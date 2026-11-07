"""Real parent-only cancellation, TTY restoration and native decode cleanup."""
from pathlib import Path
import os,pty,select,signal,subprocess,tempfile,termios,time,unittest
ROOT=Path(__file__).resolve().parents[1]
class Signals(unittest.TestCase):
 def prompt_signal(self,sig,expected):
  before=set(Path('/tmp').glob('sbox-all-in-one.*'));pid,fd=pty.fork()
  if pid==0:
   # A harness started with nohup or as a background job ignores HUP/INT on
   # entry, and Bash cannot trap signals ignored on entry; test the installer,
   # not the launcher's inherited dispositions.
   for sig in (signal.SIGINT,signal.SIGHUP,signal.SIGTERM):signal.signal(sig,signal.SIG_DFL)
   os.environ.pop('SBOX_ZGO_UNLOCK_FILE',None);os.execvp('bash',['bash',str(ROOT/'install.sh'),'verify','zgocloud'])
  # Reaching the prompt includes verifying the whole package (slow on a busy
  # 1-vCPU host); the signal-handling budget starts only once it is sent.
  data=b'';sent=False;end=time.monotonic()+60;status=None
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],.1)[0]:
     try:b=os.read(fd,65536)
     except OSError:break
     if not b:break
     data+=b
     if b'private unlock passphrase:' in data and not sent:os.kill(pid,sig);sent=True;end=time.monotonic()+15
    r,s=os.waitpid(pid,os.WNOHANG)
    if r:status=s;break
   if status is None:
    r,s=os.waitpid(pid,os.WNOHANG)
    if r:status=s
   if status is None:os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
   self.assertTrue(sent);self.assertEqual(os.waitstatus_to_exitcode(status),expected,data.decode(errors='replace')[-500:]);self.assertTrue(termios.tcgetattr(fd)[3]&termios.ECHO);self.assertEqual(set(Path('/tmp').glob('sbox-all-in-one.*'))-before,set())
  finally:os.close(fd)
 def test_term_at_private_prompt(self):self.prompt_signal(signal.SIGTERM,143)
 def test_int_at_private_prompt(self):self.prompt_signal(signal.SIGINT,130)
 def test_hup_at_private_prompt(self):self.prompt_signal(signal.SIGHUP,129)
 def test_native_core_decode_cancellation(self):
  before=set(Path('/tmp').glob('sbox-all-in-one.*'));p=subprocess.Popen(['bash',str(ROOT/'install.sh'),'verify','generic'],stdout=subprocess.PIPE,stderr=subprocess.PIPE);found=False;child=None;end=time.monotonic()+10
  while p.poll() is None and time.monotonic()<end:
   try:
    children=Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().split()
    for c in children:
     cmd=Path('/proc')/c/'cmdline'
     if b'gzip\x00-dc\x00' in cmd.read_bytes() and b'core.gz' in cmd.read_bytes():child=int(c);found=True;os.kill(p.pid,signal.SIGTERM);break
   except (FileNotFoundError,ProcessLookupError):pass
   if found:break
   time.sleep(.001)
  stdout,stderr=p.communicate(timeout=10)
  self.assertTrue(found,'Could not observe actual native core decompression');self.assertEqual(p.returncode,143,stderr.decode(errors='replace')[-300:]);self.assertFalse(Path(f'/proc/{child}').exists());self.assertEqual(set(Path('/tmp').glob('sbox-all-in-one.*'))-before,set())
if __name__=='__main__':unittest.main(verbosity=2)
