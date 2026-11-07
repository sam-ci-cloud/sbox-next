"""Real Unix socket burst/backpressure regression, no mocked responses/network."""
import concurrent.futures,os,pathlib,sys,tempfile,threading,time,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'));sys.path.insert(0,str(ROOT/'privileged-bridge'))
from bridge import Bridge,Handler
from server import UnixControl
class Backpressure(unittest.TestCase):
 def test_24_simultaneous_requests_queue_with_eight_workers(self):
  class Work:
   def __init__(self):self.current=0;self.peak=0;self.lock=threading.Lock()
   def dispatch(self,op,data):
    with self.lock:self.current+=1;self.peak=max(self.peak,self.current)
    try:time.sleep(.04);return {'complete':True}
    finally:
     with self.lock:self.current-=1
  with tempfile.TemporaryDirectory() as tmp:
   path=str(pathlib.Path(tmp)/'control.sock');work=Work()
   with Bridge(path,Handler) as bridge:
    bridge.panel_uid=os.geteuid();bridge.cfg={'monitor_key':'test-only-worker-key'};bridge.control=work;thread=threading.Thread(target=bridge.serve_forever,kwargs={'poll_interval':.01});thread.start()
    try:
     gate=threading.Barrier(24)
     def request(_):gate.wait(timeout=3);return UnixControl(path,'test-only-worker-key')('overview')
     with concurrent.futures.ThreadPoolExecutor(24) as pool:values=list(pool.map(request,range(24)))
     self.assertEqual(values,[{'complete':True}]*24);self.assertLessEqual(work.peak,8)
    finally:bridge.shutdown();thread.join(timeout=3)
if __name__=='__main__':unittest.main(verbosity=2)
