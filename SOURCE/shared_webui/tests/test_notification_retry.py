"""Failed notifications remain durable/deduplicated and retry after backoff."""
import sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from server import App
from common import Problem
class Retry(unittest.TestCase):
 def test_failed_delivery_retries_without_new_alert_transition(self):
  with tempfile.TemporaryDirectory() as d:
   app=App({'database':str(Path(d)/'panel.db')},lambda *args:None);app.store.set_setting('notifications',{'enabled':True});stamp=time.time()
   try:
    with patch.object(app,'notify',side_effect=[Problem(422,'unavailable synthetic webhook'),{'sent':True}]) as notify:
     with patch('server.time.time',return_value=stamp):app.deliver([('opened','vpn.synthetic:100','critical','Quota reached','Synthetic delivery fault; no external request')])
     with patch('server.time.time',return_value=stamp+3600):app.deliver([])
     self.assertEqual(notify.call_count,2,'The quota alert must be queued and retried without a new transition')
   finally:app.store.close()
if __name__=='__main__':unittest.main()
