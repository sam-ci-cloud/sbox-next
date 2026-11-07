"""Exercise actual installer control functions with tiny child fixtures, no deploy."""
from pathlib import Path
import os,pty,select,signal,subprocess,tempfile,time,unittest
ROOT=Path(__file__).resolve().parents[1]
TEMPLATE=(ROOT/'SOURCE/src/install.template.sh').read_text()
PREFIX=TEMPLATE.split('# Parse the entire embedded package')[0]

class JobControl(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.base=Path(self.tmp.name);self.script=self.base/'fixture.sh'
 def test_inherited_monitor_does_not_background_terminal_reader(self):
  self.script.write_text(PREFIX+'''run_stage bash -c 'read -r -p "STAGE_INPUT: " answer; printf "ANSWER=%s\\n" "$answer"'
COMPLETE=true
''')
  pid,fd=pty.fork()
  if pid==0:os.execvp('bash',['bash','-m',str(self.script)])
  data=b'';sent=False;status=None;end=time.monotonic()+4
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],.05)[0]:
     try:data+=os.read(fd,65536)
     except OSError:break
     if b'STAGE_INPUT:' in data and not sent:os.write(fd,b'foreground-ok\n');sent=True
    r,s=os.waitpid(pid,os.WNOHANG)
    if r:status=s;break
   self.assertIn(b'ANSWER=foreground-ok',data,data.decode(errors='replace'))
   if status is None:_,status=os.waitpid(pid,0)
   self.assertEqual(os.waitstatus_to_exitcode(status),0,data.decode(errors='replace'))
  finally:
   os.close(fd)
   if status is None:
    try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
    except ProcessLookupError:pass
 def cancel_fixture(self,sig,expected,manager=False,stop_first=False):
  marker=self.base/'child.pid'
  if manager:
   work=self.base/'work';work.mkdir()
   (work/'manager').write_text('trap "exit 130" INT; trap "exit 143" TERM; trap "exit 129" HUP\necho $$ > "$MARKER"\nsleep 90\n')
   tail=TEMPLATE.split('# A separate group cancels')[1].partition('\n')[2].split('COMPLETE=true\n}')[0]
   body=f'WORK={str(work)!r}\nargs=()\n'+tail+'COMPLETE=true\n'
  else:body='run_stage bash -c \'echo $$ > "$MARKER"; exec sleep 90\'\nCOMPLETE=true\n'
  self.script.write_text(PREFIX+body)
  p=subprocess.Popen(['bash',str(self.script)],env={**os.environ,'MARKER':str(marker)},stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:
   end=time.monotonic()+4
   while not marker.exists() and p.poll() is None and time.monotonic()<end:time.sleep(.01)
   self.assertTrue(marker.exists())
   child=int(marker.read_text())
   if stop_first:os.kill(child,signal.SIGSTOP)
   os.kill(p.pid,sig)
   out,err=p.communicate(timeout=5)
   self.assertEqual(p.returncode,expected,err.decode(errors='replace'))
   self.assertFalse(Path(f'/proc/{child}').exists(),'Child survived cancellation')
  finally:
   if p.poll() is None:p.kill();p.communicate()
 def test_parent_int_cancels_decode(self):self.cancel_fixture(signal.SIGINT,130)
 def test_parent_int_cancels_manager(self):self.cancel_fixture(signal.SIGINT,130,manager=True)
 def test_parent_hup_cancels_manager(self):self.cancel_fixture(signal.SIGHUP,129,manager=True)
 def test_parent_term_cancels_stopped_manager(self):self.cancel_fixture(signal.SIGTERM,143,manager=True,stop_first=True)
 def test_control_c_cancels_foreground_manager(self):
  import pexpect
  work=self.base/'work';work.mkdir();marker=self.base/'child.pid'
  (work/'manager').write_text('set -e\necho $$ > "$MARKER"\nread -r -p "MANAGER_INPUT: " answer\necho UNEXPECTED_COMPLETION\n')
  tail=TEMPLATE.split('# A separate group cancels')[1].partition('\n')[2].split('COMPLETE=true\n}')[0]
  self.script.write_text(PREFIX+f'WORK={str(work)!r}\nargs=()\n'+tail+'COMPLETE=true\n')
  p=pexpect.spawn('bash',['--noprofile','--norc','-i'],env={**os.environ,'PS1':'JOBTEST# ','MARKER':str(marker)},encoding='utf-8',timeout=5)
  try:
   p.expect_exact('JOBTEST# ');p.sendline('bash '+str(self.script));p.expect_exact('MANAGER_INPUT:')
   child=int(marker.read_text());p.sendcontrol('c');p.expect_exact('JOBTEST# ')
   self.assertNotIn('UNEXPECTED_COMPLETION',p.before);self.assertFalse(Path(f'/proc/{child}').exists(),'Foreground manager survived Ctrl+C')
   p.sendline('exit');p.expect(pexpect.EOF)
  finally:p.close(force=True)
 def test_control_z_and_fg_resume_manager(self):
  import pexpect
  work=self.base/'work';work.mkdir();marker=self.base/'child.pid'
  (work/'manager').write_text('echo $$ > "$MARKER"\nread -r -p "MANAGER_INPUT: " answer\necho "RESUMED_ANSWER=$answer"\n')
  tail=TEMPLATE.split('# A separate group cancels')[1].partition('\n')[2].split('COMPLETE=true\n}')[0]
  self.script.write_text(PREFIX+f'WORK={str(work)!r}\nargs=()\n'+tail+'COMPLETE=true\n')
  p=pexpect.spawn('bash',['--noprofile','--norc','-i'],env={**os.environ,'PS1':'JOBTEST# ','MARKER':str(marker)},encoding='utf-8',timeout=5)
  try:
   p.expect_exact('JOBTEST# ');p.sendline('bash '+str(self.script));p.expect_exact('MANAGER_INPUT:')
   p.sendcontrol('z');p.expect_exact('JOBTEST# ')
   child=int(marker.read_text());self.assertEqual(Path(f'/proc/{child}/stat').read_text().split()[2],'T')
   p.sendline('fg');p.sendline('resume-ok');p.expect_exact('RESUMED_ANSWER=resume-ok');p.expect_exact('JOBTEST# ')
   p.sendline('exit');p.expect(pexpect.EOF)
  finally:p.close(force=True)

if __name__=='__main__':unittest.main(verbosity=2)
