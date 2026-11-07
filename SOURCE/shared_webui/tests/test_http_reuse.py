"""Bounded real TCP reuse and unambiguous HTTP framing at the public front door."""
from pathlib import Path
import contextlib,http.client,socket,sys,threading,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import server
from http.client import HTTPConnection
@contextlib.contextmanager
def fixture():
 class Work(server.Handler):
  def handle_request(self):self.send(200,{'ok':True})
 with patch.object(server,'Handler',Work):
  http=server.Server(('127.0.0.1',0),type('App',(),{'control':lambda *a:None})());thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
 try:yield http
 finally:http.shutdown();http.server_close();thread.join()
class Reuse(unittest.TestCase):
 def test_sequential_reads_reuse_one_actual_connection(self):
  with fixture() as http:
   c=HTTPConnection('127.0.0.1',http.server_port,timeout=2);sockets=[]
   for _ in range(3):
    c.request('GET','/api/v1/health');r=c.getresponse();r.read();self.assertEqual(r.status,200);self.assertEqual(r.version,11);self.assertIsNotNone(c.sock);sockets.append(c.sock.getsockname())
   self.assertEqual(len(set(sockets)),1);c.close()
 def test_request_budget_forces_connection_close(self):
  with fixture() as http:
   with patch.object(http.RequestHandlerClass,'KEEPALIVE_MAX_REQUESTS',2,create=True):
    c=HTTPConnection('127.0.0.1',http.server_port,timeout=2)
    c.request('GET','/');r=c.getresponse();r.read();self.assertEqual(r.getheader('Connection'),'keep-alive')
    c.request('GET','/');r=c.getresponse();r.read();self.assertEqual(r.getheader('Connection'),'close');self.assertIsNone(c.sock)
 def test_idle_connection_releases_worker(self):
  with fixture() as http:
   with patch.object(http.RequestHandlerClass,'KEEPALIVE_IDLE_SECONDS',.15,create=True):
    c=HTTPConnection('127.0.0.1',http.server_port,timeout=2);c.request('GET','/');r=c.getresponse();r.read();self.assertIsNotNone(c.sock);sock=c.sock;time.sleep(.35);self.assertEqual(sock.recv(1),b'');c.close()
 def test_lifetime_boundary_closes_in_response_without_dropping_next_read(self):
  with fixture() as http:
   with patch.object(http.RequestHandlerClass,'KEEPALIVE_LIFETIME_SECONDS',.15),patch.object(http.RequestHandlerClass,'KEEPALIVE_IDLE_SECONDS',.6):
    c=HTTPConnection('127.0.0.1',http.server_port,timeout=2)
    c.request('GET','/');r=c.getresponse();r.read();self.assertEqual(r.getheader('Connection'),'keep-alive')
    # Cross the reuse lifetime while staying within the advertised idle window.
    # A continuously reused high-RTT connection must get a complete response.
    time.sleep(.25)
    c.request('GET','/');r=c.getresponse();r.read();self.assertEqual(r.status,200);self.assertEqual(r.getheader('Connection'),'close');self.assertIsNone(c.sock)
 def test_ambiguous_or_unconsumed_body_cannot_be_pipelined(self):
  for headers in ['Content-Length: 4\r\n','Content-Length: 0\r\nContent-Length: 0\r\n','Transfer-Encoding: chunked\r\n']:
   with self.subTest(headers=headers),fixture() as http:
    s=socket.create_connection(('127.0.0.1',http.server_port),timeout=2);s.sendall(('GET /api/v1/health HTTP/1.1\r\nHost: fixture\r\n'+headers+'\r\nJUNKGET /api/v1/health HTTP/1.1\r\nHost: fixture\r\n\r\n').encode());response=b''
    while True:
     b=s.recv(65536)
     if not b:break
     response+=b
    s.close();self.assertIn(b' 400 ',response);self.assertEqual(response.count(b'HTTP/'),1);self.assertIn(b'Connection: close',response)
if __name__=='__main__':unittest.main(verbosity=2)
