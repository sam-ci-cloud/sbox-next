"""Offline mainland-China rule snapshot: parsing semantics, determinism and the committed data file."""
import io, json, sys, tarfile, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cn_rules


def tarball(path, files, licence='MIT License\n'):
    with tarfile.open(path, 'w:gz') as tar:
        for name, text in {**{'dlc/data/' + k: v for k, v in files.items()}, 'dlc/LICENSE': licence}.items():
            data = text.encode(); info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))


class CnRules(unittest.TestCase):
    def test_domain_list_includes_attributes_and_kinds(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td) / 'd.tar.gz'
            tarball(t, {'cn': 'include:a\ninclude:b @ads\ninclude:c @-ads\nexample.cn # comment\n',
                        'a': 'full:Exact.Example.Com\nkeyword:shop\nregexp:^x\\.example$\n',
                        'b': 'ad.example @ads\nplain.example\n', 'c': 'keep.example\ndrop.example @ads\n'})
            out = cn_rules.dlc_cn(t, minimum=1)
        self.assertEqual(out['domain'], ['exact.example.com'])
        self.assertEqual(out['domain_keyword'], ['shop']); self.assertEqual(out['domain_regex'], ['^x\\.example$'])
        self.assertEqual(out['domain_suffix'], ['ad.example', 'example.cn', 'keep.example'], 'attribute filters on include lines')

    def test_wrong_licence_and_include_loop_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td) / 'd.tar.gz'; tarball(t, {'cn': 'x.cn\n'}, licence='Proprietary\n')
            with self.assertRaises(SystemExit): cn_rules.dlc_cn(t, minimum=1)
            tarball(t, {'cn': 'include:a\n', 'a': 'include:cn\n'})
            with self.assertRaises(SystemExit): cn_rules.dlc_cn(t, minimum=1)

    def test_apnic_cn_only_and_collapsed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'a.txt'
            p.write_text('2|apnic|20261107|4|19830613|20261106|+1000\napnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n'
                         'apnic|CN|ipv4|1.0.2.0|512|20110414|allocated\napnic|JP|ipv4|1.0.16.0|4096|20110412|allocated\n'
                         'apnic|CN|ipv6|2001:250::|35|20000426|allocated\napnic|CN|ipv4|1.0.8.0|2048|20110412|reserved\n')
            nets, stamp = cn_rules.apnic_cn(p, minimum=(1, 1))
        self.assertEqual(stamp, '20261107'); self.assertEqual(nets, ['1.0.1.0/24', '1.0.2.0/23', '2001:250::/35'])

    def test_committed_snapshot(self):
        data = cn_rules.verify()
        text = (ROOT / 'shared_webui/backend/cn_rules.json').read_text()
        self.assertNotIn('://', text, 'no download location in a shipped file')
        self.assertEqual(data['sources']['domain_list_community']['licence'], 'MIT')
        self.assertRegex(data['sources']['domain_list_community']['commit'], r'^[0-9a-f]{40}$')


if __name__ == '__main__':
    unittest.main()
