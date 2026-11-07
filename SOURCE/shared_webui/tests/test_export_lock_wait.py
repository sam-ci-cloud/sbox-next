"""Subscription reads tolerate a short real file lock; writes still fail fast."""
import fcntl,json,sys,tempfile,threading,time,unittest
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('backend','privileged-bridge')]
from bridge import Control
from common import Problem

class ExportLock(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.lock=self.root/'manager.lock';self.held=self.lock.open('w');fcntl.flock(self.held,fcntl.LOCK_EX)
  self.manager=self.root/'manager'
  self.manager.write_text('#!/usr/bin/python3\nimport os,subprocess,sys\nr=subprocess.run(["/usr/bin/flock","-w",os.environ["SBOX_LOCK_WAIT_SECONDS"],'+repr(str(self.lock))+',"/usr/bin/printf","export-ok"],capture_output=True,text=True)\nif r.returncode:print("Timed out waiting for the manager lock",file=sys.stderr)\nelse:print(r.stdout,end="")\nsys.exit(r.returncode)\n')
  self.manager.chmod(0o700);self.control=Control(base=self.root,manager=str(self.manager))
 def tearDown(self):self.held.close();self.temp.cleanup()
 def test_export_waits_for_short_operation_then_returns_real_subprocess_output(self):
  timer=threading.Timer(1.6,lambda:fcntl.flock(self.held,fcntl.LOCK_UN));timer.start()
  try:self.assertEqual(self.control.run([str(self.manager),'_webui-control','export'],{'id':'a'*32}), 'export-ok')
  finally:timer.join()
 def test_commit_keeps_fast_conflict_and_does_not_replay_a_write(self):
  started=time.monotonic()
  with self.assertRaises(Problem) as caught:self.control.run([str(self.manager),'_webui-control','commit'],{'token':'b'*64})
  self.assertEqual(caught.exception.status,409);self.assertLess(time.monotonic()-started,3)

if __name__=='__main__':unittest.main()
