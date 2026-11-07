"""Real Unix socket burst must queue without losing a normal dashboard read."""
import concurrent.futures,sys,tempfile,threading,time,unittest,os
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('backend','privileged-bridge')]
from bridge import Bridge,Handler
from server import UnixControl
class Burst(unittest.TestCase):
 def test_normal_twenty_four_client_burst_keeps_eight_workers(self):
  lock=threading.Lock();active=peak=0
  class Work:
   def dispatch(self,op,data):
    nonlocal active,peak
    with lock:active+=1;peak=max(peak,active)
    try:time.sleep(1.4);return {'ok':True}
    finally:
     with lock:active-=1
  with tempfile.TemporaryDirectory() as d,Bridge(str(Path(d)/'bridge.sock'),Handler) as server:
   server.panel_uid=os.geteuid();server.cfg={'monitor_key':'test-monitor'};server.control=Work();thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();gate=threading.Barrier(24)
   def request(_):
    gate.wait()
    try:return UnixControl(str(Path(d)/'bridge.sock'),'test-monitor')('overview')=={'ok':True}
    except Exception:return False
   try:
    with concurrent.futures.ThreadPoolExecutor(24) as pool:rows=list(pool.map(request,range(24)))
    self.assertEqual(sum(rows),24,rows);self.assertLessEqual(peak,8)
   finally:server.shutdown();thread.join()
if __name__=='__main__':unittest.main()
