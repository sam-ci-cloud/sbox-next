import importlib.util,socket,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bench',ROOT/'tools/bench/dual_stack_acceptance.py');bench=importlib.util.module_from_spec(spec);spec.loader.exec_module(bench)
class BenchIsolation(unittest.TestCase):
 def test_occupied_port_never_counts_as_client_ready(self):
  with socket.socket() as sock,tempfile.TemporaryDirectory() as d:
   sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
   p={'type':'anytls','name':'test','server':'example.test','port':443,'password':'synthetic-test-only'}
   with mock.patch.object(bench.subprocess,'Popen') as start:
    start.return_value.poll.return_value=None
    with self.assertRaisesRegex(RuntimeError,'occupied'):bench.start('mihomo',p,'192.0.2.1',port,Path(d))
    start.assert_not_called()
 def test_free_port_returns_unused_port(self):
  port=bench.free_port()
  with socket.socket() as sock:sock.bind(('127.0.0.1',port))
if __name__=='__main__':unittest.main(verbosity=2)
