"""Real TCP front-door burst preserves the bounded 24 workers without resets."""
import concurrent.futures,http.client,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import server
from http.client import HTTPConnection
class Burst(unittest.TestCase):
 def test_sixty_concurrent_requests_complete_with_twenty_four_workers(self):
  active=peak=0;lock=threading.Lock()
  class Work(server.Handler):
   def handle_request(self):
    nonlocal active,peak
    with lock:active+=1;peak=max(peak,active)
    try:time.sleep(.12);self.send(200,{'ok':True})
    finally:
     with lock:active-=1
  with patch.object(server,'Handler',Work),server.Server(('127.0.0.1',0),type('App',(),{'control':lambda *a:None})()) as http:
   thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start();gate=threading.Barrier(60)
   def request(_):
    gate.wait(timeout=5)
    try:
     c=HTTPConnection('127.0.0.1',http.server_port,timeout=10);c.request('GET','/api/v1/health');r=c.getresponse();r.read();c.close();return r.status
    except Exception:return 0
   try:
    with concurrent.futures.ThreadPoolExecutor(60) as pool:statuses=list(pool.map(request,range(60)))
    self.assertEqual(statuses.count(200),60,statuses);self.assertLessEqual(peak,24)
   finally:http.shutdown();thread.join()
if __name__=='__main__':unittest.main()
