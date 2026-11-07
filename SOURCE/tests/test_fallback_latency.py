"""Small HTTPS responses must not wait for Nagle/delayed ACK coalescing."""
import importlib.util
from pathlib import Path
import socket
import unittest

spec = importlib.util.spec_from_file_location('fallback', Path(__file__).resolve().parents[1] / 'src/fallback-web/server.py')
fallback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fallback)


class LowLatencyResponse(unittest.TestCase):
    def test_actual_accepted_socket_disables_nagle(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            with socket.create_connection(listener.getsockname()) as client:
                accepted, _ = listener.accept()
                with accepted:
                    self.assertEqual(accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 0)
                    handler = object.__new__(fallback.Handler)
                    handler.request = accepted
                    handler.setup()
                    try:
                        self.assertEqual(accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 1)
                    finally:
                        handler.finish()


if __name__ == '__main__':
    unittest.main(verbosity=2)
