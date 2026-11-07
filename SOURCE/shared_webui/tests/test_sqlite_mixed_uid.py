"""Actual root read-only bridge / unprivileged panel SQLite WAL ownership."""
import os,pwd,sqlite3,subprocess,sys,tempfile,unittest,json,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(os.geteuid()==0,'Real mixed-UID reproduction requires the disposable root guest')
class MixedUID(unittest.TestCase):
 def test_root_read_only_query_cannot_make_panel_wal_unwritable(self):
  # The installed panel account when present; otherwise the standard
  # unprivileged 'nobody' account gives the same real root/non-root UID split
  # in a disposable root container that has no SBOX installation.
  try:user=pwd.getpwnam('sbox-webui')
  except KeyError:user=pwd.getpwnam('nobody')
  self.assertNotEqual(user.pw_uid,0)
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);base.chmod(0o711);data=base/'data';data.mkdir();os.chown(data,user.pw_uid,user.pw_gid)
   # Import before dropping privileges; production backend remains inaccessible
   # to arbitrary local users as installed by the root manager.
   code="import sys,os;sys.path.insert(0,sys.argv[1]);from store import Store;os.setgid(int(sys.argv[3]));os.setuid(int(sys.argv[2]));s=Store(sys.argv[4]);print('ready',flush=True);input();exec(\"for i in range(1500):\\n s.set_setting('mixed-uid-proof',i)\");print('written',flush=True)"
   child=subprocess.Popen([sys.executable,'-c',code,str(ROOT/'backend'),str(user.pw_uid),str(user.pw_gid),str(data/'panel.db')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   try:
    self.assertEqual(child.stdout.readline().strip(),'ready')
    stop=threading.Event()
    def read():
     while not stop.is_set():
      db=sqlite3.connect('file:'+str(data/'panel.db')+'?mode=ro',uri=True)
      try:db.execute('SELECT * FROM settings').fetchall()
      except sqlite3.Error:pass
      finally:db.close()
    threads=[threading.Thread(target=read) for _ in range(4)]
    for t in threads:t.start()
    try:stdout,stderr=child.communicate('\n',timeout=60)
    finally:
     stop.set()
     for t in threads:t.join()
    self.assertEqual(child.returncode,0,stderr);self.assertIn('written',stdout)
   finally:
    if child.poll() is None:child.kill();child.communicate()
if __name__=='__main__':unittest.main()
