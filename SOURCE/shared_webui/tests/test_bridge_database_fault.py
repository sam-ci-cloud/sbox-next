"""A failed root SQLite query must return a bounded 503, not an empty socket."""
import os,sqlite3,sys,tempfile,threading,unittest
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('backend','privileged-bridge')]
from bridge import Bridge,Handler
from server import UnixControl
from common import Problem
class Fault(unittest.TestCase):
 def test_real_corrupt_database_error_becomes_structured_503(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'corrupt.db';path.write_bytes(b'not a SQLite database')
   class Work:
    def dispatch(self,op,data):
     db=sqlite3.connect(path)
     try:return db.execute('SELECT * FROM totals').fetchall()
     finally:db.close()
   with Bridge(str(Path(d)/'bridge.sock'),Handler) as server:
    server.panel_uid=os.geteuid();server.cfg={'monitor_key':'test-monitor'};server.control=Work();thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
     with self.assertRaises(Problem) as error:UnixControl(str(Path(d)/'bridge.sock'),'test-monitor')('overview')
     self.assertEqual(error.exception.status,503);self.assertNotIn(str(path),error.exception.message)
    finally:server.shutdown();thread.join()
if __name__=='__main__':unittest.main()
