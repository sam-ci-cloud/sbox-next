"""Mihomo groups with no sing-box equivalent (fallback, load-balance) are omitted, never imitated, so
profiles that contain them (e.g. the protected original profile) still export; nothing else is dropped."""
import json, subprocess, sys, tempfile, unittest
from pathlib import Path
import reality_fixture as fx
sys.path.insert(0, str(fx.ROOT / 'shared_webui/backend'))
from export_json import convert, convert_full

NODE = {'name': 'n1', 'type': 'vless', 'server': 'vpn.example.test', 'port': 443, 'uuid': '00000000-0000-4000-8000-000000000001', 'tls': True, 'servername': 'vpn.example.test'}
NODE2 = dict(NODE, name='n2', port=8443)


def doc(extra_groups):
    return {'proxies': [NODE, NODE2], 'dns': {'nameserver': ['https://1.1.1.1/dns-query']},
            'proxy-groups': extra_groups + [{'name': 'auto', 'type': 'url-test', 'proxies': ['n1', 'n2'], 'url': 'https://www.gstatic.com/generate_204'},
                                            {'name': 'VPN', 'type': 'select', 'proxies': (['lb'] if extra_groups else []) + ['auto', 'n1']}],
            'rules': ['MATCH,VPN']}


class UnmappableGroups(unittest.TestCase):
    def test_load_balance_is_omitted_like_fallback(self):
        for kind in ('load-balance', 'fallback'):
            with self.subTest(kind=kind):
                d = doc([{'name': 'lb', 'type': kind, 'proxies': ['n1', 'n2'], 'url': 'https://www.gstatic.com/generate_204', 'strategy': 'consistent-hashing'}])
                for cfg in (convert(d), convert_full(d, 'global')):
                    tags = {o['tag'] for o in cfg['outbounds']}
                    self.assertNotIn('lb', tags)
                    vpn = next(o for o in cfg['outbounds'] if o['tag'] == 'VPN')
                    self.assertEqual(vpn['outbounds'], ['auto', 'n1'], 'reference removed, order kept')
                    with tempfile.TemporaryDirectory() as td:
                        p = Path(td) / 'c.json'; p.write_text(json.dumps(cfg))
                        r = subprocess.run([str(fx.core_binary()), 'check', '-c', str(p)], capture_output=True, text=True, cwd=td)
                        self.assertEqual(r.returncode, 0, r.stderr)

    def test_builtin_direct_member_maps_exactly(self):
        d = doc([]); d['proxy-groups'][-1]['proxies'] = ['auto', 'DIRECT', 'n1']
        for cfg in (convert(d), convert_full(d, 'global')):
            self.assertIn({'type': 'direct', 'tag': 'DIRECT'}, cfg['outbounds'])
            self.assertEqual(next(o for o in cfg['outbounds'] if o['tag'] == 'VPN')['outbounds'], ['auto', 'DIRECT', 'n1'])
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / 'c.json'; p.write_text(json.dumps(cfg))
                self.assertEqual(subprocess.run([str(fx.core_binary()), 'check', '-c', str(p)], capture_output=True, cwd=td).returncode, 0)
        d['proxy-groups'][-1]['proxies'] = ['auto', 'REJECT']
        with self.assertRaises(ValueError):
            convert(d)

    def test_unknown_group_type_still_refused(self):
        with self.assertRaises(ValueError):
            convert(doc([{'name': 'lb', 'type': 'relay', 'proxies': ['n1', 'n2']}]))

    def test_group_left_empty_is_refused(self):
        d = doc([{'name': 'lb', 'type': 'load-balance', 'proxies': ['n1', 'n2']}])
        d['proxy-groups'][-1]['proxies'] = ['lb']
        with self.assertRaises(ValueError):
            convert(d)


if __name__ == '__main__':
    unittest.main()
