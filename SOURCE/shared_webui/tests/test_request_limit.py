"""The per-address request limit stays 600/min in the product; only the browser fixture raises it."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import server
from common import Problem


class RequestLimit(unittest.TestCase):
    def test_default_limit_is_600_per_minute(self):
        s = server.Server(('127.0.0.1', 0), object())
        try:
            self.assertEqual(s.request_limit, 600)
            for _ in range(600):
                s.rate('198.51.100.7', s.request_limit)
            with self.assertRaises(Problem) as e:
                s.rate('198.51.100.7', s.request_limit)
            self.assertEqual(e.exception.status, 429)
            s.rate('198.51.100.8', s.request_limit)  # other addresses unaffected
        finally:
            s.server_close()

    def test_only_the_fixture_raises_it(self):
        text = (Path(__file__).resolve().parents[1] / 'backend' / 'server.py').read_text()
        self.assertIn('self.server.rate(self.client_address[0], self.server.request_limit)', text)
        self.assertNotIn('request_limit =', text.replace('self.request_limit = 600', ''))


if __name__ == '__main__':
    unittest.main()
