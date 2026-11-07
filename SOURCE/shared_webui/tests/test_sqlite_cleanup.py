"""Real SQLite setup errors must release descriptors before fault recovery."""
import sys,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from accounting import MeterStore
class Cleanup(unittest.TestCase):
 def test_failed_pragma_closes_real_connection(self):
  with tempfile.TemporaryDirectory() as d:
   real=sqlite3.connect;connections=[]
   def connect(*args,**kw):
    c=real(*args,**kw);c.set_authorizer(lambda action,*args:sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_PRAGMA else sqlite3.SQLITE_OK);connections.append(c);return c
   try:
    with patch('accounting.sqlite3.connect',connect):
     with self.assertRaises(sqlite3.DatabaseError):MeterStore(Path(d)/'usage.db')
    with self.assertRaises(sqlite3.ProgrammingError):connections[0].execute('SELECT 1')
   finally:
    for c in connections:c.close()
if __name__=='__main__':unittest.main()
