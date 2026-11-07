#!/usr/bin/env python3
"""Adversarial fixtures for the runtime GitHub/mirror dependency scanner."""
import base64, gzip, io, tarfile, tempfile, unittest
from pathlib import Path
from scan_runtime_github import scan


def gh(*parts):
    # Built at runtime so this fixture file itself stays free of literal hosts.
    return ''.join(parts)


from identity import canonical
CANONICAL = canonical()

class RuntimeScanner(unittest.TestCase):
    def tree(self, files):
        root = Path(tempfile.mkdtemp(prefix='sbox-scan-'))
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return root

    def findings(self, files, installers=()):
        root = self.tree(files)
        return scan(root, [root / i for i in installers])[1]

    def test_clean_tree_passes_and_plain_word_is_allowed(self):
        self.assertEqual(self.findings({'src/manager.sh': 'echo "SBOX has no GitHub dependency"\n'}), [])

    def test_runtime_hosts_and_mirrors_are_denied(self):
        for url in (gh('https://api.', 'github', '.com/repos/x/y/releases/latest'),
                    gh('https://raw.', 'githubusercontent', '.com/x/y/main/a.sh'),
                    gh('https://', 'github', '.com/x/y/releases/download/v1/a.tar.gz'),
                    gh('https://gh', 'proxy.net/https://x'), gh('https://gh', '-proxy.com/x'), gh('https://gh', 'fast.top/x'),
                    gh('https://cdn.jsdelivr.net/', 'gh/x/y@main/a.dat'), gh('https://x.', 'github', '.io/y'),
                    gh('ghcr', '.io/x/y:1')):
            with self.subTest(url=url):
                self.assertTrue(self.findings({'shared_webui/backend/server.py': f"URL='{url}'\n"}))

    def test_git_remote_operations_in_runtime_are_denied(self):
        self.assertTrue(self.findings({'src/manager.sh': 'git clone https://example.invalid/x.git\n'}))
        self.assertTrue(self.findings({'package/install.sh': 'git fetch origin\n'}))

    def test_retired_project_identity_is_denied(self):
        self.assertTrue(self.findings({'assets/release.json': '{"repository":"sam-ci-' + 'cloud/retired-product"}'}))

    def test_canonical_repository_metadata_is_not_a_runtime_download(self):
        self.assertEqual(self.findings({'assets/release.json':'{"repository":"%s"}' % CANONICAL}),[])
    def test_docs_allow_only_listed_upstream_provenance(self):
        ok = gh('https://', 'github', '.com/SagerNet/sing-box/tree/v1.13.14')
        self.assertEqual(self.findings({'docs/a.md': f'Source: {ok} .\n'}), [])
        self.assertTrue(self.findings({'docs/a.md': gh('See https://', 'github', '.com/someone/app/releases\n')}))

    def test_new_repository_is_documentation_only(self):
        url = gh('https://', 'github', '.com/' + CANONICAL)
        self.assertEqual(self.findings({'docs/a.md': f'Public source: {url} .\n'}), [])
        self.assertTrue(self.findings({'src/manager.sh': f'curl {url}\n'}))

    def test_go_proxy_module_and_patch_import_are_not_network_hosts(self):
        module = gh('github', '.com/sagernet/sing-box')
        self.assertEqual(self.findings({'shared_webui/backend/core_resolver.py':"MODULE = '"+module+"'\nPROXY = 'https://proxy.golang.org'\n",
                                       'shared_webui/backend/core-patches/accounting.patch':'+\t"'+module+'/adapter"\n'}), [])
        self.assertTrue(self.findings({'shared_webui/backend/evil.py':gh("URL='https://",'github',".com/sagernet/sing-box'\n")}))

    def test_security_floor_keys_are_module_coordinates_only(self):
        module=gh('github','.com/go-chi/chi/v5')
        source="SECURITY_FLOORS = {'"+module+"':'v5.4.0'}\n"
        self.assertEqual(self.findings({'shared_webui/backend/core_resolver.py':source}),[])
        self.assertTrue(self.findings({'shared_webui/backend/core_resolver.py':source+"URL='https://"+module+"'\n"}))

    def test_embedded_installer_payloads_are_decoded(self):
        manager = gh('#!/bin/bash\ncurl https://api.', 'github', '.com/repos/a/b\n').encode()
        payload = base64.b64encode(gzip.compress(manager)).decode()
        installer = f"x\nbase64 -d <<'SBOX_GENERIC_PAYLOAD'\n{payload}\nSBOX_GENERIC_PAYLOAD\n"
        found = self.findings({'install.sh': installer}, ['install.sh'])
        self.assertTrue(any('::manager' in f for f in found), found)

    def test_embedded_webui_archive_is_decoded(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            body = gh("u='https://api.", 'github', ".com/x'\n").encode()
            info = tarfile.TarInfo('backend/x.py'); info.size = len(body); tf.addfile(info, io.BytesIO(body))
        blob = base64.b64encode(gzip.compress(buf.getvalue())).decode()
        manager = f"blob=base64.b64decode('{blob}',validate=True)\n".encode()
        payload = base64.b64encode(gzip.compress(manager)).decode()
        installer = f"base64 -d <<'SBOX_GENERIC_PAYLOAD'\n{payload}\nSBOX_GENERIC_PAYLOAD\n"
        found = self.findings({'install.sh': installer}, ['install.sh'])
        self.assertTrue(any('webui/backend/x.py' in f for f in found), found)

    def test_developer_tests_and_upstream_go_source_are_out_of_scope(self):
        self.assertEqual(self.findings({'core-source/sing-box/go.mod': gh('module ', 'github', '.com/sagernet/sing-box\n'),
                                        'tests/test_x.py': gh("'https://api.", 'github', ".com'\n")}), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
