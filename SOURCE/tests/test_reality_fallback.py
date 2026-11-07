#!/usr/bin/env python3
"""Universal REALITY handshake target: remote (default) vs self-hosted website.

Offline only. Exercises the real state renderer, the real built manager
functions (with stubbed systemctl/ss), the real Personal Cloud server and the
generated site. Root/systemd/VPN behaviour of a live VPS is NOT covered here;
see shared_webui/tests/lab_reality_fallback.py for the namespace lab.
"""
import copy
import hashlib
import http.client
import json
import os
from protected_build_fixture import protected_template
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import reality_fixture as fx  # noqa: E402

BUILD = Path(os.environ.get('SBOX_MANAGER_ROOT', ROOT / '.build'))
MANAGER = BUILD / 'src/manager.sh'
SERVER = ROOT / 'src/fallback-web/server.py'
SITE = ROOT / 'src/fallback-web/site'
BASELINE_HELPER_SHA256 = '8bb804a760529ad49bf1a25b48ae3da36ea2ec445d015a332ca5ec53c9864e51'
MARKER = b'<meta name="generator" content="sbox-personal-cloud">'


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close(); return port


def base_helper():
    """Pinned existing helper baseline; never depend on another Git history."""
    target = ROOT / 'src/helper-baselines/state.py'
    if not target.is_file():
        raise AssertionError('Self-contained baseline helper missing')
    if hashlib.sha256(target.read_bytes()).hexdigest() != BASELINE_HELPER_SHA256:
        raise AssertionError('Pinned baseline helper changed; review against known-good bytes')
    return target


# 1.8.0 D10: these manager functions chown staged files to service users, which
# needs root. As non-root they are BLOCKED_ENV skips (CI runs them as root).
needs_root = unittest.skipUnless(os.geteuid() == 0, 'BLOCKED_ENV: requires root (chown to service users)')


class PKI:
    _dir = None

    @classmethod
    def get(cls):
        if cls._dir is None:
            cls._managed = tempfile.TemporaryDirectory(prefix='sbox-test-pki-')
            __import__('atexit').register(cls._managed.cleanup)
            cls._dir = Path(cls._managed.name)
            cls.ca, cls.leaves = fx.lab_certificates(cls._dir, (fx.DOMAIN, 'other.sbox.test'))
            # A second, distinct leaf for the same host simulates a renewal.
            cls.renewed = fx.lab_certificates(cls._dir / 'renewed', (fx.DOMAIN,))[1][fx.DOMAIN]
            # Renewal trust: the renewed leaf has its own lab CA; keep one bundle.
            (cls._dir / 'bundle.pem').write_bytes(cls.ca.read_bytes() + (cls._dir / 'renewed/ca.crt').read_bytes())
        return cls


# ---------------------------------------------------------------- state model
class StateModel(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = 'P' * 43, 'Q' * 43
        self.remote = fx.base_state(self.priv, self.pub)

    def valid(self, state):
        return fx.state_tool('validate', state)

    def test_old_state_keeps_server_and_nodes_with_dual_stack_client_dns(self):
        helper = base_helper()
        for state in (self.remote, fx.trusted_certificate(self.remote)):
            new, old = fx.render(state), fx.render(state, helper=helper)
            self.assertEqual(sorted(os.listdir(new)), sorted(os.listdir(old)))
            for name in os.listdir(old):
                if name.endswith('.yaml'):
                    # NEXT adds IPv6-capable client DNS; REALITY identities,
                    # remaining transport fields and routing groups retain their contract.
                    import yaml
                    left=yaml.safe_load((new/name).read_text());right=yaml.safe_load((old/name).read_text())
                    for item in (left,right):
                        item.pop('dns',None);item.pop('ipv6',None)
                        for proxy in item.get('proxies',[]):proxy.pop('tfo',None)
                    self.assertEqual(left,right,name)
                else:self.assertEqual((new/name).read_bytes(),(old/name).read_bytes(),name)
            config = json.loads((new / 'server.json').read_text())
            self.assertEqual(config['inbounds'][0]['tls']['reality']['handshake'], {'server': fx.REMOTE_SNI, 'server_port': 443})
            self.assertEqual(config['inbounds'][0]['tls']['server_name'], fx.REMOTE_SNI)

    def test_migration_never_adds_or_changes_reality_fields(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'migrated.json'
            self.assertEqual(fx.state_tool('migrate', self.remote, out).returncode, 0)
            migrated = json.loads(out.read_text())
            self.assertEqual(migrated['protocols']['reality'], self.remote['protocols']['reality'])
            self.assertNotIn('fallback', migrated['protocols']['reality'])

    def test_backup_restore_and_upgrade_normalisation_keep_self_hosted_mode(self):
        state = fx.self_hosted(self.remote, port=9555)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'migrated.json'
            self.assertEqual(fx.state_tool('migrate', state, out).returncode, 0)
            self.assertEqual(json.loads(out.read_text())['protocols']['reality'], state['protocols']['reality'])

    def test_explicit_remote_object_is_identical_to_absent(self):
        explicit = copy.deepcopy(self.remote); explicit['protocols']['reality']['fallback'] = {'mode': 'remote'}
        a, b = fx.render(self.remote), fx.render(explicit)
        for name in os.listdir(a):
            self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)

    def test_self_hosted_uses_loopback_target_and_owner_sni_everywhere(self):
        state = fx.self_hosted(self.remote, port=8443)
        self.assertEqual(self.valid(state).returncode, 0, self.valid(state).stdout)
        out = fx.render(state)
        tls = json.loads((out / 'server.json').read_text())['inbounds'][0]['tls']
        self.assertEqual(tls['reality']['handshake'], {'server': '127.0.0.1', 'server_port': 8443})
        self.assertEqual(tls['server_name'], fx.DOMAIN)
        self.assertEqual(tls['reality']['private_key'], self.priv)
        self.assertNotIn('certificate_path', tls)  # REALITY never carries an ordinary certificate
        import yaml
        for name in ('mihomo.yaml', 'clmi.yaml', 'mihomo-cn.yaml', 'internal.yaml'):
            proxies = [p for p in yaml.safe_load((out / name).read_text())['proxies'] if p.get('type') == 'vless']
            self.assertTrue(proxies, name)
            for p in proxies:
                self.assertEqual(p['servername'], fx.DOMAIN)
                self.assertEqual(p['reality-opts'], {'public-key': self.pub, 'short-id': '0123456789abcdef'})
        links = (out / 'links.txt').read_text()
        self.assertIn('sni=' + fx.DOMAIN, links); self.assertIn('pbk=' + self.pub, links); self.assertNotIn(fx.REMOTE_SNI, links)

    def test_certificate_needed_rule(self):
        cases = [(self.remote, 'false'), (fx.self_hosted(self.remote), 'true')]
        disabled = fx.self_hosted(self.remote); disabled['protocols']['reality']['enabled'] = False; disabled['protocols']['vmess']['enabled'] = True; disabled['protocols']['vmess']['tls'] = False
        cases.append((disabled, 'false'))
        for state, expected in cases:
            r = fx.state_tool('cert-needed', state)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, expected), r.stdout + r.stderr)

    def test_invalid_self_hosted_states_are_refused(self):
        good = fx.self_hosted(self.remote)
        mutations = {
            'hostname not the SBOX domain': lambda s: s['protocols']['reality']['fallback'].update(hostname='www.example.test'),
            'SNI differs from website hostname': lambda s: s['protocols']['reality'].update(sni=fx.REMOTE_SNI),
            'public bind': lambda s: s['protocols']['reality']['fallback'].update(listen='0.0.0.0'),
            'IPv6 any': lambda s: s['protocols']['reality']['fallback'].update(listen='::'),
            'privileged port': lambda s: s['protocols']['reality']['fallback'].update(port=443),
            'WebUI port': lambda s: s['protocols']['reality']['fallback'].update(port=9443),
            'port out of range': lambda s: s['protocols']['reality']['fallback'].update(port=70000),
            'port as string': lambda s: s['protocols']['reality']['fallback'].update(port='8443'),
            'port shared with VMess': lambda s: (s['protocols']['vmess'].update(enabled=True, port=8443)),
            'missing remote_sni': lambda s: s['protocols']['reality']['fallback'].pop('remote_sni'),
            'unknown field': lambda s: s['protocols']['reality']['fallback'].update(upload=True),
            'unknown mode': lambda s: s['protocols']['reality']['fallback'].update(mode='mirror'),
            'self-signed certificate': lambda s: s['certificate'].update(mode='self-signed', insecure=True),
            'insecure flag': lambda s: s['certificate'].update(insecure=True),
            'no certificate': lambda s: s.update(certificate={'mode': 'none', 'source_mode': 'none', 'source_fullchain': '', 'source_key': '', 'insecure': False}),
            'ZgoCloud protected state': lambda s: s.update(zgo_legacy_compat=True),
            'remote object with extra field': lambda s: s['protocols']['reality'].update(fallback={'mode': 'remote', 'port': 1}),
            'accounting port collision': lambda s: s.update(accounting={'enabled': False, 'port': 8443, 'poll_seconds': 2, 'core_sha256': '0' * 64, 'coverage': {p: True for p in ('reality', 'vmess', 'hy2', 'tuic', 'anytls')}, 'failure_policy': 'open'}),
        }
        self.assertEqual(self.valid(good).returncode, 0)
        for name, mutate in mutations.items():
            state = copy.deepcopy(good); mutate(state)
            r = self.valid(state)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn('invalid state', r.stdout + r.stderr, name)


# ----------------------------------------------------------- manager functions
@unittest.skipUnless(MANAGER.is_file(), 'built manager missing; run tools/build.py (NOT_RUN, not PASS)')
class ManagerFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='sbox-mgr-'))
        text = MANAGER.read_text()
        assert text.rstrip().endswith('main "$@"')
        (cls.tmp / 'lib.sh').write_text(text.rstrip()[:-len('main "$@"')] + '\n')
        stubs = cls.tmp / 'bin'; stubs.mkdir()
        (stubs / 'ss').write_text('#!/bin/sh\n[ -f "$STUB_SS" ] && cat "$STUB_SS"\nexit 0\n')
        (stubs / 'dig').write_text('#!/bin/sh\nexit 0\n')  # no DNS lookups offline
        (stubs / 'systemctl').write_text('#!/usr/bin/env python3\n' + SYSTEMCTL_STUB)
        for f in stubs.iterdir():
            f.chmod(0o755)

    def bash(self, script, env=None, stdin=None, timeout=60):
        work = Path(tempfile.mkdtemp(prefix='case-', dir=self.tmp))
        prelude = f'''set -Eeuo pipefail
source "{self.tmp}/lib.sh"
RUNTIME_DIR="{work}/run"; mkdir -p "$RUNTIME_DIR"
LIB_DIR="{work}/lib"; FALLBACK_WEB_DIR="$LIB_DIR/fallback-web"
FALLBACK_WEB_SERVICE_FILE="{work}/units/sbox-fallback-web.service"; mkdir -p "{work}/units"
FALLBACK_WEB_FAILURE="{work}/state/fallback-web-last-failure.json"
'''
        env = {**{k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}, 'PATH': f'{self.tmp}/bin:' + os.environ['PATH'],
               'STUB_LOG': str(work / 'systemctl.log'), 'STUB_DIR': str(work), **(env or {})}
        r = subprocess.run(['bash', '-c', prelude + script], capture_output=True, text=True, env=env, input=stdin, timeout=timeout)
        r.work = work
        return r

    def write_state(self, state, name='state.json'):
        p = self.tmp / name; p.write_text(json.dumps(state)); return p

    @needs_root
    def test_guided_install_builds_both_modes_and_switches_back(self):
        core = fx.core_binary()
        # This fixture exercises certificate/REALITY choices with offline TEST-NET
        # addresses. Actual endpoint/DNS preflight is covered by test_audit_network.
        common = (f'check_domain_dns() {{ :; }}; OPT_scope=internal; ASSUME_DEFAULTS=true; STATE_HELPER="$RUNTIME_DIR/sbox-state"; POLICY_HELPER="$RUNTIME_DIR/sbox-policy"; OPT_domain={fx.DOMAIN}; OPT_node=LAB; '
                  'OPT_ipv4=192.0.2.10; OPT_ipv6=none; OPT_listen=0.0.0.0; OPT_ports="reality=443,vmess=28443"; OPT_firewall=no; OPT_tuning=no; OPT_block_private=yes; OPT_email=none; ')
        build = lambda existing='': (f'build_guided_state "$RUNTIME_DIR/out.json" "{existing}" global "{core}" 1.13.14 fixed "$RUNTIME_DIR/plan.json"; '
                                     'jq -c "{sni:.protocols.reality.sni,dest:.protocols.reality.dest_port,fallback:.protocols.reality.fallback,cert:.certificate.mode}" "$RUNTIME_DIR/out.json"; jq -r .method "$RUNTIME_DIR/plan.json"; '
                                     f'cp "$RUNTIME_DIR/out.json" "{self.tmp}/guided.json"')
        r = self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=; ' + build())
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        out = r.stdout.strip().splitlines()
        self.assertEqual(json.loads(out[0]), {'sni': 'www.cloudflare.com', 'dest': 443, 'fallback': None, 'cert': 'none'})
        self.assertNotIn('fallback', json.loads((self.tmp / 'guided.json').read_text())['protocols']['reality'])
        r = self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=self-hosted; OPT_cert=certbot-http01; ' + build())
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        state = json.loads(r.stdout.strip().splitlines()[0])
        self.assertEqual(state['sni'], fx.DOMAIN); self.assertEqual(state['cert'], 'certbot-http01')
        self.assertEqual(state['fallback'], {'mode': 'self_hosted', 'hostname': fx.DOMAIN, 'listen': '127.0.0.1', 'port': 8443, 'remote_sni': 'www.cloudflare.com'})
        existing = self.tmp / 'guided-self.json'; shutil.copy(self.tmp / 'guided.json', existing)
        # Upgrade/reinstall without the flag keeps the existing self-hosted choice (and its port).
        r = self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=; OPT_cert=certbot-http01; ' + build(existing))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[0])['fallback']['mode'], 'self_hosted', 'an upgrade never silently switches mode')
        shutil.copy(existing, self.tmp / 'guided-self-copy.json')
        r = self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=remote; ' + build(existing))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[0])['sni'], 'www.cloudflare.com', 'switching back restores the previous remote target')
        r = self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=self-hosted; OPT_cert=self-signed; ' + build())
        self.assertNotEqual(r.returncode, 0); self.assertIn('publicly trusted certificate', r.stderr)
        self.assertIn('Remote website used as the REALITY handshake target', self.bash(common + 'OPT_protocols=reality; OPT_reality_fallback=remote; ' + build()).stderr)

    def test_bash_certificate_rule_agrees_with_renderer(self):
        base = fx.base_state()
        variants = [base, fx.self_hosted(base)]
        off = fx.self_hosted(base); off['protocols']['reality']['enabled'] = False; off['protocols']['tuic']['enabled'] = True
        variants.append(off)
        for i, state in enumerate(variants):
            path = self.write_state(state, f'agree{i}.json')
            bash = self.bash(f'state_needs_certificate "{path}" && echo true || echo false').stdout.strip()
            self.assertEqual(bash, fx.state_tool('cert-needed', state).stdout.strip(), i)

    def test_noninteractive_default_keeps_remote(self):
        r = self.bash('ASSUME_DEFAULTS=true; choose_reality_fallback "{}" cloud.sbox.test www.microsoft.com 28443')
        self.assertEqual(r.returncode, 0, r.stderr); self.assertEqual(json.loads(r.stdout), {'mode': 'remote'})
        self.assertIn('does not obtain, copy or store', r.stderr)
        self.assertNotIn('steal', r.stderr.lower())
        current = '{"mode":"self_hosted","hostname":"cloud.sbox.test","listen":"127.0.0.1","port":9000,"remote_sni":"www.apple.com"}'
        r = self.bash(f"ASSUME_DEFAULTS=true; choose_reality_fallback '{current}' cloud.sbox.test www.apple.com")
        self.assertEqual(json.loads(r.stdout)['port'], 9000, r.stderr)

    def test_self_hosted_selection_flag_and_interactive(self):
        r = self.bash('ASSUME_DEFAULTS=true; OPT_reality_fallback=self-hosted; choose_reality_fallback "{}" cloud.sbox.test www.microsoft.com 28443 443')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {'mode': 'self_hosted', 'hostname': 'cloud.sbox.test', 'listen': '127.0.0.1', 'port': 8443, 'remote_sni': 'www.microsoft.com'})
        r = self.bash('choose_reality_fallback "{}" cloud.sbox.test www.cloudflare.com', stdin='2\n9100\n')
        self.assertEqual(json.loads(r.stdout)['port'], 9100, r.stderr)
        r = self.bash('choose_reality_fallback "{}" cloud.sbox.test www.cloudflare.com', stdin='1\n')
        self.assertEqual(json.loads(r.stdout), {'mode': 'remote'})

    def test_invalid_ports_and_conflicts_are_refused(self):
        ss = self.tmp / 'ss-busy.txt'
        ss.write_text('LISTEN 0 128 127.0.0.1:9200 0.0.0.0:* users:(("nginx",pid=4242,fd=6))\n')
        for port, needle in (('80', '1024 to 65535'), ('9443', 'reserved'), ('70000', '1024 to 65535'), ('abc', '1024 to 65535'),
                             ('28443', 'enabled VPN protocol'), ('9200', 'already in use')):
            r = self.bash(f'ASSUME_DEFAULTS=true; OPT_reality_fallback=self-hosted; OPT_reality_fallback_port={port}; choose_reality_fallback "{{}}" cloud.sbox.test www.microsoft.com 28443', env={'STUB_SS': str(ss)})
            self.assertNotEqual(r.returncode, 0, port); self.assertIn(needle, r.stderr, port)
        r = self.bash('ASSUME_DEFAULTS=true; OPT_reality_fallback=mirror; choose_reality_fallback "{}" cloud.sbox.test www.microsoft.com')
        self.assertNotEqual(r.returncode, 0); self.assertIn('remote or self-hosted', r.stderr)
        # Interactive: an invalid answer is explained and asked again.
        r = self.bash('choose_reality_fallback "{}" cloud.sbox.test www.microsoft.com 28443', stdin='2\n28443\n9300\n', env={'STUB_SS': str(ss)})
        self.assertEqual(json.loads(r.stdout)['port'], 9300); self.assertIn('enabled VPN protocol', r.stderr)

    def test_trusted_certificate_required(self):
        r = self.bash('ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=true; OPT_cert=self-signed; collect_certificate_plan cloud.sbox.test true "" "$RUNTIME_DIR/plan.json"')
        self.assertNotEqual(r.returncode, 0); self.assertIn('publicly trusted certificate', r.stderr)
        pki = PKI.get()
        cert, key = pki.leaves[fx.DOMAIN]
        # A lab-CA certificate covers the name but is NOT publicly trusted: refused.
        r = self.bash(f'ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=true; OPT_cert=existing; OPT_cert_path="{cert}"; OPT_key_path="{key}"; collect_certificate_plan cloud.sbox.test true "" "$RUNTIME_DIR/plan.json"')
        self.assertNotEqual(r.returncode, 0); self.assertIn('publicly trusted', r.stderr)
        # Mismatched hostname and missing files are refused too.
        other_cert, other_key = pki.leaves['other.sbox.test']
        r = self.bash(f'ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=true; OPT_cert=existing; OPT_cert_path="{other_cert}"; OPT_key_path="{other_key}"; collect_certificate_plan cloud.sbox.test true "" "$RUNTIME_DIR/plan.json"')
        self.assertNotEqual(r.returncode, 0); self.assertIn('does not cover', r.stderr)
        r = self.bash(f'ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=true; OPT_cert=existing; OPT_cert_path=/nonexistent/c.pem; OPT_key_path="{key}"; collect_certificate_plan cloud.sbox.test true "" "$RUNTIME_DIR/plan.json"')
        self.assertNotEqual(r.returncode, 0)
        # Reuse of this installation's certificate is refused when it was self-signed.
        insecure = fx.self_hosted(fx.base_state()); insecure['certificate'].update(mode='self-signed', insecure=True, source_fullchain=str(cert), source_key=str(key))
        path = self.write_state(insecure, 'insecure.json')
        r = self.bash(f'ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=true; OPT_cert=reuse; collect_certificate_plan cloud.sbox.test true "{path}" "$RUNTIME_DIR/plan.json"')
        self.assertNotEqual(r.returncode, 0); self.assertIn('not publicly trusted', r.stderr)
        # Remote mode keeps every existing certificate option (no behaviour change).
        r = self.bash('ASSUME_DEFAULTS=true; CERT_TRUSTED_ONLY=false; OPT_cert=self-signed; collect_certificate_plan cloud.sbox.test true "" "$RUNTIME_DIR/plan.json"; jq -r .method "$RUNTIME_DIR/plan.json"')
        self.assertEqual(r.stdout.strip(), 'self-signed', r.stderr)

    def test_interactive_menu_hides_self_signed_and_cancel_returns_to_remote(self):
        state = fx.self_hosted(fx.base_state())
        path = self.write_state(state, 'cancel.json')
        r = self.bash(f'cp "{path}" "$RUNTIME_DIR/c.json"; collect_state_certificate_plan "$RUNTIME_DIR/c.json" cloud.sbox.test "" "$RUNTIME_DIR/plan.json"; jq -c "{{sni:.protocols.reality.sni,fallback:.protocols.reality.fallback}}" "$RUNTIME_DIR/c.json"; jq -r .method "$RUNTIME_DIR/plan.json"', stdin='0\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('Self-signed test certificate', r.stderr.split('Go back')[0])
        self.assertIn('Self-signed certificates are not offered', r.stderr)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(json.loads(lines[0]), {'sni': fx.REMOTE_SNI, 'fallback': None})
        self.assertEqual(lines[1], 'none')  # REALITY-only remote mode needs no certificate
        self.assertIn('remote website handshake target', r.stderr)

    def test_unit_is_loopback_unprivileged_and_isolated(self):
        state = fx.self_hosted(fx.base_state(), port=8555)
        r = self.bash(f'fallback_web_unit_content "{self.write_state(state, "unit.json")}"')
        unit = r.stdout
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(unit.startswith('# Managed by sbox-manager'))
        exec_line = next(l for l in unit.splitlines() if l.startswith('ExecStart='))
        self.assertIn('--listen 127.0.0.1 --port 8555 --hostname cloud.sbox.test', exec_line)
        self.assertNotRegex(unit, r'0\.0\.0\.0|\[::\]|--listen ::\b')
        for line in ('DynamicUser=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'ProtectSystem=strict', 'IPAddressDeny=any',
                     'IPAddressAllow=localhost', 'SocketBindDeny=any', 'SocketBindAllow=tcp:8555', 'PrivateDevices=yes',
                     'LoadCredential=tls.crt:/etc/sbox-manager/certs/live/fullchain.pem', 'LoadCredential=tls.key:/etc/sbox-manager/certs/live/privkey.pem',
                     'ExecStartPre=/usr/bin/python3 -I -B /srv/sbox-fallback-web/server.py --preflight --root /srv/sbox-fallback-web/site',
                     'TemporaryFileSystem=/srv:ro',
                     'MemoryMax=', 'TasksMax=', 'Before=sing-box.service', 'WantedBy=multi-user.target sing-box.service'):
            self.assertIn(line, unit)
        self.assertIn('/srv/sbox-fallback-web/server.py', exec_line)
        self.assertIn('--root /srv/sbox-fallback-web/site', exec_line)
        self.assertEqual(sum(line.startswith('BindReadOnlyPaths=') for line in unit.splitlines()), 1)
        self.assertRegex(unit, r'BindReadOnlyPaths=.*/fallback-web:/srv/sbox-fallback-web')
        self.assertRegex(unit, r'InaccessiblePaths=.*-/etc/sbox-manager')
        for forbidden in ('nginx', 'apache', 'caddy', 'User=root', 'sites-enabled', '/etc/sbox-manager/state.json', 'webui'):
            self.assertNotIn(forbidden, re.sub(r'^InaccessiblePaths=.*$', '', unit, flags=re.M))
        masked = re.search(r'^InaccessiblePaths=(.*)$', unit, re.M).group(1).split()
        for private in ('-/etc/sbox-manager', '-/var/lib/sbox-manager', '-/etc/letsencrypt', '-/var/lib/sbox-accounting',
                        '-/usr/local/lib/sbox-webui', '-/etc/sbox-webui', '-/var/lib/sbox-webui', '-/var/backups/sbox-manager'):
            self.assertIn(private, masked)
        if shutil.which('systemd-analyze'):
            u = self.tmp / 'sbox-fallback-web.service'; u.write_text(unit)
            v = subprocess.run(['systemd-analyze', 'verify', str(u)], capture_output=True, text=True)
            relevant = [l for l in v.stderr.splitlines() if 'sbox-fallback-web' in l and ('Unknown' in l or 'Invalid' in l or 'Failed to parse' in l)]
            self.assertEqual(relevant, [], v.stderr)

    def test_systemd_single_bind_exposes_the_complete_read_only_site(self):
        if not Path('/run/systemd/system').exists() or not shutil.which('systemd-run') or not shutil.which('sudo'):
            self.skipTest('systemd system manager is unavailable')
        sudo = subprocess.run(['sudo', '-n', 'true'], capture_output=True, text=True)
        if sudo.returncode:
            self.skipTest('passwordless sudo is unavailable')
        installed = self.bash('install_fallback_web_files')
        self.assertEqual(installed.returncode, 0, installed.stderr)
        app = installed.work / 'lib/fallback-web'
        unit = 'sbox-fallback-single-bind-test-%d-%d' % (os.getpid(), int(time.time() * 1000))
        checks = ' && '.join('test -s /srv/sbox-fallback-web/%s' % name for name in (
            'server.py', 'site/index.html', 'site/files/index.html', 'site/media/index.html', 'site/about/index.html'))
        # The real preflight, as the dynamic service user inside the sandbox.
        checks += ' && /usr/bin/python3 -I -B /srv/sbox-fallback-web/server.py --preflight --root /srv/sbox-fallback-web/site'
        command = [
            'sudo', '-n', 'systemd-run', '--wait', '--pipe', '--collect', '--unit', unit,
            '--property=DynamicUser=yes',
            '--property=NoNewPrivileges=yes',
            '--property=ProtectSystem=strict',
            '--property=ProtectHome=yes',
            '--property=PrivateTmp=yes',
            '--property=TemporaryFileSystem=/srv:ro',
            '--property=BindReadOnlyPaths=%s:/srv/sbox-fallback-web' % app,
            '/bin/sh', '-c', checks
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @needs_root
    def test_bundle_installs_exact_site_and_rejects_tampering(self):
        r = self.bash('install_fallback_web_files && find "$FALLBACK_WEB_DIR" -type f -printf "%P %m\\n" | sort')
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = dict(line.split() for line in r.stdout.splitlines())
        expected = {'server.py'} | {'site/' + str(p.relative_to(SITE)) for p in SITE.rglob('*') if p.is_file()}
        self.assertEqual(set(rows), expected)
        self.assertTrue(all(mode == '644' for mode in rows.values()))
        for name in expected:
            source = SERVER if name == 'server.py' else SITE / name[len('site/'):]
            self.assertEqual((r.work / 'lib/fallback-web' / name).read_bytes(), source.read_bytes(), name)
        r = self.bash('install_fallback_web_files; echo first; FALLBACK_WEB_BUNDLE_SHA256=0000; if install_fallback_web_files; then echo second-ok; else echo second-refused; fi; test -s "$FALLBACK_WEB_DIR/server.py" && echo kept')
        self.assertIn('second-refused', r.stdout); self.assertIn('kept', r.stdout); self.assertIn('digest mismatch', r.stderr)

    @needs_root
    def test_cross_filesystem_mv_that_drops_directory_modes_is_harmless(self):
        # Ubuntu 26.10 ships uutils coreutils; its cross-filesystem mv recreated
        # directories with the manager umask (077), so site/ became 0700 and the
        # DynamicUser service refused to start ("site root has no index.html").
        # Emulate that mv: every directory it creates is 0700.
        fake = self.tmp / 'fakebin'; fake.mkdir(exist_ok=True)
        (fake / 'mv').write_text('#!/bin/bash\n'
            'src="${@: -2:1}"; dst="${@: -1}"\n'
            'if [ -d "$src" ]; then cp -r --no-preserve=mode "$src" "$dst" && find "$dst" -type d -exec chmod 0700 {} + && rm -rf -- "$src"; else /bin/mv "$@"; fi\n')
        (fake / 'mv').chmod(0o755)
        r = self.bash('export PATH="%s:$PATH"; hash -r; install_fallback_web_files && find "$FALLBACK_WEB_DIR" -printf "%%y %%m %%P\\n" | sort' % fake)
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [line.split(' ', 2) for line in r.stdout.splitlines()]
        self.assertTrue(rows)
        for kind, mode, rel in rows:
            self.assertEqual(mode, '755' if kind == 'd' else '644', (kind, mode, rel))
        # No stage directory is left behind in the snapshot-covered tree.
        self.assertEqual(list((r.work / 'lib').glob('.fallback-web.stage.*')), [])

    @needs_root
    def test_reserved_runtime_directory_accepts_only_the_managed_site(self):
        # Every command after the first self-hosted install validates $LIB_DIR.
        # The website tree must be recognized, while foreign entries still fail.
        r = self.bash('install_fallback_web_files && assert_safe_namespaces && echo accepted')
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('accepted', r.stdout)
        r = self.bash('install_fallback_web_files && mkdir "$LIB_DIR/unknown" && assert_safe_namespaces && echo accepted')
        self.assertNotEqual(r.returncode, 0); self.assertIn('Unknown file in reserved runtime directory', r.stderr)
        r = self.bash('install_fallback_web_files && printf "print(1)\\n" > "$FALLBACK_WEB_DIR/server.py" && assert_safe_namespaces && echo accepted')
        self.assertNotEqual(r.returncode, 0); self.assertIn('not an sbox-managed Personal Cloud directory', r.stderr)

    @needs_root
    def test_tree_check_names_unreadable_or_unsafe_paths(self):
        r = self.bash('install_fallback_web_files && fallback_web_tree_check "$FALLBACK_WEB_DIR" && echo clean')
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('clean', r.stdout)
        cases = (
            ('chmod 0700 "$FALLBACK_WEB_DIR/site"', 'site: mode 0700, expected 0755'),
            ('chmod 0600 "$FALLBACK_WEB_DIR/site/media/index.html"', 'site/media/index.html: mode 0600'),
            (': > "$FALLBACK_WEB_DIR/site/about/index.html"', 'site/about/index.html: required file is missing or empty'),
            ('rm -f "$FALLBACK_WEB_DIR/site/files/index.html"', 'site/files/index.html: required file is missing'),
            ('ln -s /etc/passwd "$FALLBACK_WEB_DIR/site/leak.txt"', 'site/leak.txt: symlink is not allowed'),
            ('chmod 0777 "$FALLBACK_WEB_DIR/site/assets"', 'site/assets: mode 0777'),
        )
        for mutate, needle in cases:
            with self.subTest(mutate=mutate):
                r = self.bash('install_fallback_web_files && %s && if fallback_web_tree_check "$FALLBACK_WEB_DIR"; then echo passed; else echo refused; fi' % mutate)
                self.assertIn('refused', r.stdout, r.stderr)
                self.assertIn(needle, r.stdout)

    def test_server_preflight_reports_exact_unreadable_page(self):
        site = self.tmp / 'preflight-site'
        shutil.copytree(SITE, site)
        ok = subprocess.run([sys.executable, '-I', '-B', str(SERVER), '--preflight', '--root', str(site)], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        (site / 'media/index.html').unlink()
        bad = subprocess.run([sys.executable, '-I', '-B', str(SERVER), '--preflight', '--root', str(site)], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn('media/index.html: No such file or directory', bad.stderr)
        self.assertNotIn('Warning', bad.stderr)

    @needs_root
    def test_missing_host_site_page_is_refused_before_systemd_start(self):
        state = fx.self_hosted(fx.base_state(), port=free_port())
        path = self.write_state(state, 'missing-host-site.json')
        script = f'''install_fallback_web_files
fallback_web_sync "{path}"
rm -f "$FALLBACK_WEB_DIR/site/index.html"
if fallback_web_activate "{path}"; then echo unexpectedly-started; else echo correctly-refused; fi
if grep -q "restart sbox-fallback-web.service" "$STUB_LOG"; then echo systemd-was-started; else echo systemd-not-started; fi
'''
        r = self.bash(script)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn('correctly-refused', r.stdout)
        self.assertIn('systemd-not-started', r.stdout)
        self.assertNotIn('unexpectedly-started', r.stdout)

    @needs_root
    def test_sync_writes_and_removes_only_the_sbox_unit(self):
        sh = self.write_state(fx.self_hosted(fx.base_state()), 'sync-sh.json')
        rm = self.write_state(fx.base_state(), 'sync-remote.json')
        r = self.bash(f'fallback_web_sync "{sh}"; test -f "$FALLBACK_WEB_SERVICE_FILE" && echo written; fallback_web_sync "{rm}"; test ! -e "$FALLBACK_WEB_SERVICE_FILE" && echo removed; cat "$STUB_LOG"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('written', r.stdout); self.assertIn('removed', r.stdout)
        self.assertIn('disable --now sbox-fallback-web.service', r.stdout)
        r = self.bash(f'printf "[Service]\\nExecStart=/bin/true\\n" > "$FALLBACK_WEB_SERVICE_FILE"; if fallback_web_sync "{rm}"; then echo changed; else echo refused; fi; grep -c ExecStart=/bin/true "$FALLBACK_WEB_SERVICE_FILE"')
        self.assertIn('refused', r.stdout); self.assertIn('1', r.stdout.splitlines()[-1]); self.assertIn('not managed by SBOX', r.stderr)

    @needs_root
    def test_activation_health_renewal_and_failure_are_visible(self):
        pki = PKI.get()
        port = free_port()
        state = fx.self_hosted(fx.base_state(), port=port)
        path = self.write_state(state, 'activate.json')
        live = self.tmp / 'live'; live.mkdir(exist_ok=True)
        cert, key = pki.leaves[fx.DOMAIN]
        shutil.copy(cert, live / 'fullchain.pem'); shutil.copy(key, live / 'privkey.pem')
        env = {'SSL_CERT_FILE': str(pki._dir / 'bundle.pem')}
        script = f'''SERVICE_CERT="{live}/fullchain.pem"; SERVICE_KEY="{live}/privkey.pem"
install_fallback_web_files; fallback_web_sync "{path}"
export STUB_UNIT="$FALLBACK_WEB_SERVICE_FILE" STUB_APP="$FALLBACK_WEB_DIR"
step() {{ if "$@"; then echo "$1=ok"; else echo "$1=failed"; fi; }}
step fallback_web_activate "{path}"
python3 -c "import ssl,socket;c=ssl.create_default_context();s=c.wrap_socket(socket.create_connection(('127.0.0.1',{port})),server_hostname='{fx.DOMAIN}');print('serial',s.getpeercert()['serialNumber'])"
cp "{pki.renewed[0]}" "{live}/fullchain.pem"; cp "{pki.renewed[1]}" "{live}/privkey.pem"
step fallback_web_activate "{path}"
python3 -c "import ssl,socket;c=ssl.create_default_context();s=c.wrap_socket(socket.create_connection(('127.0.0.1',{port})),server_hostname='{fx.DOMAIN}');print('serial',s.getpeercert()['serialNumber'])"
test ! -s "$FALLBACK_WEB_FAILURE" && echo no-failure-marker || true
cp "{pki.leaves['other.sbox.test'][0]}" "{live}/fullchain.pem"; cp "{pki.leaves['other.sbox.test'][1]}" "{live}/privkey.pem"
step fallback_web_activate "{path}"
jq -r .reason "$FALLBACK_WEB_FAILURE"
systemctl stop sbox-fallback-web.service
'''
        r = self.bash(script, env=env, timeout=120)
        out = r.stdout
        self.assertIn('fallback_web_activate=ok', out.splitlines()[0], r.stderr + out)
        serials = re.findall(r'^serial (\S+)', out, re.M)
        self.assertEqual(len(serials), 2, out + r.stderr)
        self.assertNotEqual(serials[0], serials[1], 'renewal must restart the website with the new certificate')
        self.assertEqual(serials[1].lower(), subprocess.run(['openssl', 'x509', '-in', str(pki.renewed[0]), '-noout', '-serial'], capture_output=True, text=True).stdout.strip().split('=')[1].lower())
        self.assertIn('no-failure-marker', out)
        self.assertIn('fallback_web_activate=failed', out)
        self.assertRegex(out, r'service did not start|health check failed')
        self.assertIn('restart sbox-fallback-web.service', (r.work / 'systemctl.log').read_text())

    def test_doctor_reports_mode_service_and_failures(self):
        remote = self.write_state(fx.base_state(), 'doc-remote.json')
        sh = self.write_state(fx.self_hosted(fx.base_state(), port=free_port()), 'doc-sh.json')
        prelude = 'firewall_owned_dump() { echo "-A SBOX_INPUT -p tcp --dport 443 -j ACCEPT"; }; failures=0; warnings=0; '
        r = self.bash(prelude + f'reality_fallback_doctor "{remote}"; echo "failures=$failures"')
        self.assertIn('[INFO] REALITY handshake target: remote website www.microsoft.com:443', r.stdout)
        self.assertIn('does not copy', r.stdout); self.assertIn('failures=0', r.stdout)
        r = self.bash(prelude + f'mkdir -p "$(dirname "$FALLBACK_WEB_FAILURE")"; echo \'{{"time":"t","reason":"local HTTPS health check failed"}}\' > "$FALLBACK_WEB_FAILURE"; reality_fallback_doctor "{sh}"; echo "failures=$failures warnings=$warnings"')
        self.assertIn('self-hosted SBOX Personal Cloud', r.stdout)
        self.assertIn('[FAIL] Personal Cloud website service active', r.stdout)
        self.assertIn('[OK]   no public firewall rule for the local website port', r.stdout)
        self.assertIn('[WARN] last Personal Cloud website activation failed', r.stdout)
        self.assertRegex(r.stdout, r'failures=[1-9]')

    def test_transaction_snapshot_rollback_and_uninstall_cover_the_website(self):
        text = MANAGER.read_text()
        def body(name):
            m = re.search(r'^' + re.escape(name) + r'\(\) [({]\n(.*?)^[)}]\n', text, re.M | re.S)
            self.assertIsNotNone(m, name); return m.group(1)
        snap = body('snapshot_runtime_base' if 'snapshot_runtime_base() {' in text else 'snapshot_runtime'); self.assertIn('$FALLBACK_WEB_SERVICE_FILE:fallback-web-service', snap); self.assertIn('fallback-web-active', snap); self.assertIn('$FALLBACK_WEB_UNIT:fallback-web', snap)
        restore = body('restore_runtime_base' if 'restore_runtime_base() (' in text else 'restore_runtime')
        self.assertIn('$FALLBACK_WEB_SERVICE_FILE:fallback-web-service', restore); self.assertIn('$FALLBACK_WEB_UNIT enablement', restore)
        self.assertLess(restore.index('Personal Cloud website restart'), restore.index('VPN service restart'))
        verify = body('verify_restored_runtime'); self.assertIn('$FALLBACK_WEB_SERVICE_FILE:fallback-web-service', verify)
        apply = body('apply_candidate')
        for call in ('install_fallback_web_files', 'fallback_web_sync "$candidate_state"', 'fallback_web_activate "$candidate_state"', 'fallback_web_verify_relay "$candidate_state"'):
            self.assertIn(call, apply)
        self.assertLess(apply.index('fallback_web_activate'), apply.index('systemctl restart sing-box.service'))
        self.assertIn('$FALLBACK_WEB_SERVICE_FILE', body('verify_uninstalled_runtime'))
        self.assertIn('systemctl disable --now "$FALLBACK_WEB_UNIT"', body('uninstall_command'))
        # Backups include the certificate whenever the website needs one.
        self.assertIn('state_needs_certificate "$payload/state.json"', body('create_backup_archive'))
        # No firewall code path ever references the website port.
        self.assertNotRegex(body('firewall_apply_family'), r'fallback|8443')

    def test_build_hook_is_universal_only_and_embeds_digest(self):
        m = re.search(r'FALLBACK_WEB_BUNDLE_SHA256="([0-9a-f]{64})"', MANAGER.read_text())
        self.assertIsNotNone(m)
        payload = re.search(r"<<'SBOX_FALLBACK_WEB_BUNDLE'\n(.*?)\nSBOX_FALLBACK_WEB_BUNDLE", MANAGER.read_text(), re.S).group(1)
        import base64
        self.assertEqual(hashlib.sha256(base64.b64decode(payload)).hexdigest(), m.group(1))
        sys.path.insert(0, str(ROOT / 'tools'))
        import build
        # Same public stand-in for the private OS guard as test_platform_and_shared_build.
        text = protected_template((ROOT / 'src/manager.sh').read_text())
        zgo = build.integrate(text, 'zgocloud').decode()
        self.assertIn('FALLBACK_WEB_BUNDLE_SHA256="disabled"', zgo)
        self.assertIsNone(re.search(r"<<'SBOX_FALLBACK_WEB_BUNDLE'\n\S", zgo), 'no website payload in a ZgoCloud build')
        self.assertIn('Self-hosted Personal Cloud is unavailable in this manager build', zgo)


SYSTEMCTL_STUB = r'''
"""Offline systemctl stand-in: records calls and runs the /srv read-only bind path
with credentials copied into a private CREDENTIALS_DIRECTORY."""
import os,re,shlex,signal,subprocess,sys,tempfile,time
args=sys.argv[1:];d=os.environ['STUB_DIR'];open(os.environ['STUB_LOG'],'a').write(' '.join(args)+'\n')
pidfile=os.path.join(d,'fallback.pid')
def alive():
    try:pid=int(open(pidfile).read());os.kill(pid,0);return pid
    except Exception:return 0
def stop():
    pid=alive()
    if pid:
        os.kill(pid,signal.SIGTERM)
        for _ in range(50):
            if not alive():break
            time.sleep(0.05)
    try:os.unlink(pidfile)
    except FileNotFoundError:pass
cmd=[a for a in args if not a.startswith('--')]
verb=cmd[0] if cmd else ''
if verb=='show':print(alive() or 0);sys.exit(0)
if verb=='is-active':sys.exit(0 if alive() else 3)
if verb=='is-failed':sys.exit(1 if alive() else 0)
if verb in('stop',) or (verb=='disable' and '--now' in args):stop();sys.exit(0)
if verb=='restart':
    stop();unit=open(os.environ['STUB_UNIT']).read()
    def rewrite(line):
        return line.replace('/srv/sbox-fallback-web',os.environ['STUB_APP'])
    for pre in re.findall(r'^ExecStartPre=(.*)$',unit,re.M):
        check=subprocess.run(shlex.split(rewrite(pre)),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode:sys.exit(check.returncode)
    execline=rewrite(re.search(r'^ExecStart=(.*)$',unit,re.M).group(1))
    creds=tempfile.mkdtemp(prefix='creds-',dir=d)
    for name,src in re.findall(r'^LoadCredential=([^:]+):(.*)$',unit,re.M):
        open(os.path.join(creds,name),'wb').write(open(src,'rb').read());os.chmod(os.path.join(creds,name),0o400)
    p=subprocess.Popen(shlex.split(execline),env={**os.environ,'CREDENTIALS_DIRECTORY':creds},stdout=subprocess.DEVNULL,stderr=open(os.path.join(d,'fallback.log'),'a'),start_new_session=True)
    time.sleep(0.4)
    if p.poll() is not None:sys.exit(1)
    open(pidfile,'w').write(str(p.pid));sys.exit(0)
sys.exit(0)
'''


# --------------------------------------------------------------- the website
class Website(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pki = PKI.get()
        cls.ca = pki.ca
        cls.cert, cls.key = pki.leaves[fx.DOMAIN]
        cls.root = Path(tempfile.mkdtemp(prefix='sbox-site-'))
        shutil.copytree(SITE, cls.root / 'site')
        site = cls.root / 'site'
        # Hostile additions that must never be served.
        (site / '.env').write_text('SECRET=1\n')
        (site / 'assets/.hidden.css').write_text('x{}')
        (site / 'escape.txt').symlink_to('/etc/passwd')
        (site / 'linked-dir').symlink_to('/etc')
        (site / 'library/run.sh').write_text('#!/bin/sh\necho no\n')
        (site / 'library/empty').mkdir()
        cls.port = free_port()
        cls.proc = subprocess.Popen([sys.executable, '-I', '-B', str(SERVER), '--listen', '127.0.0.1', '--port', str(cls.port), '--hostname', fx.DOMAIN,
                                     '--root', str(site), '--cert', str(cls.cert), '--key', str(cls.key), '--quiet', '--connections', '4', '--handshakes', '8', '--handshake-timeout', '3'],
                                    stderr=subprocess.PIPE, text=True, start_new_session=True)
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', cls.port), timeout=0.2).close(); break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        os.killpg(cls.proc.pid, signal.SIGTERM); cls.proc.wait(5)

    def request(self, method, path, headers=None, body=None, host=fx.DOMAIN):
        ctx = ssl.create_default_context(cafile=str(self.ca))
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10)
        conn._tunnel_host = None
        # SNI and certificate verification use the website hostname.
        conn.sock = ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=10), server_hostname=fx.DOMAIN)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', host)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader('Content-Length', str(len(body)))
        conn.endheaders(body)
        r = conn.getresponse(); data = r.read(); conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def test_every_page_is_a_real_page(self):
        titles = {}
        for path in ('/', '/files/', '/media/', '/about/'):
            status, headers, body = self.request('GET', path)
            self.assertEqual(status, 200, path); self.assertIn(MARKER, body)
            self.assertEqual(headers['content-type'], 'text/html; charset=utf-8')
            titles[path] = re.search(rb'<title>(.*?)</title>', body).group(1)
            for nav in (b'href="/files/"', b'href="/media/"', b'href="/about/"'):
                self.assertIn(nav, body)
            self.assertGreater(len(body), 2500, 'not a placeholder page')
        self.assertEqual(len(set(titles.values())), 4)

    def test_mime_types_head_and_downloads(self):
        expected = {'/assets/site.css': 'text/css; charset=utf-8', '/assets/site.js': 'text/javascript; charset=utf-8', '/assets/logo.svg': 'image/svg+xml',
                    '/library/documents/personal-cloud-guide.pdf': 'application/pdf', '/library/spreadsheets/travel-checklist.csv': 'text/csv; charset=utf-8',
                    '/library/documents/getting-started.md': 'text/markdown; charset=utf-8', '/library/documents/welcome.txt': 'text/plain; charset=utf-8'}
        for path, kind in expected.items():
            status, headers, body = self.request('GET', path)
            self.assertEqual((status, headers['content-type']), (200, kind), path)
            self.assertEqual(int(headers['content-length']), len(body))
            if path.startswith('/library/'):
                self.assertTrue(headers['content-disposition'].startswith('attachment;'), path)
            status, h2, empty = self.request('HEAD', path)
            self.assertEqual((status, empty, h2['content-length']), (200, b'', headers['content-length']))
        self.assertTrue(self.request('GET', '/library/documents/personal-cloud-guide.pdf')[2].startswith(b'%PDF-1.4'))

    def test_security_headers(self):
        _, headers, _ = self.request('GET', '/')
        self.assertIn("default-src 'none'", headers['content-security-policy'])
        self.assertIn("frame-ancestors 'none'", headers['content-security-policy'])
        self.assertEqual(headers['x-content-type-options'], 'nosniff')
        self.assertEqual(headers['referrer-policy'], 'no-referrer')
        self.assertEqual(headers['x-frame-options'], 'DENY')
        self.assertEqual(headers['server'], 'PersonalCloud')
        self.assertNotIn('set-cookie', headers)

    def test_refusals(self):
        cases = {
            '/missing.html': 404, '/library/': 404, '/assets/': 404, '/library/empty/': 404,
            '/.env': 404, '/assets/.hidden.css': 404, '/%2eenv': 404, '/escape.txt': 404, '/linked-dir/hostname': 404,
            '/../etc/passwd': 404, '/%2e%2e/%2e%2e/etc/passwd': 404, '/library/..%2f..%2fserver.py': 404, '/..\\server.py': 404,
            '/library/run.sh': 404, '/server.py': 404, '//etc/passwd': 404, '/%00': 404,
        }
        for path, code in cases.items():
            status, _, body = self.request('GET', path)
            self.assertEqual(status, code, path); self.assertNotIn(b'root:', body); self.assertNotIn(b'SECRET', body)
        status, _, body = self.request('GET', '/nope')
        self.assertIn(b'Page not found', body)
        status, headers, _ = self.request('GET', '/files')
        self.assertEqual((status, headers['location']), (301, '/files/'))

    def test_only_get_and_head(self):
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'PROPFIND', 'MKCOL', 'CONNECT'):
            status, headers, _ = self.request(method, '/library/documents/welcome.txt', body=b'' if method in ('POST', 'PUT') else None)
            self.assertEqual((status, headers.get('allow')), (405, 'GET, HEAD'), method)
        status, _, _ = self.request('GET', '/', body=b'upload')
        self.assertEqual(status, 413)
        status, _, _ = self.request('GET', '/', host='admin.sbox.test')
        self.assertEqual(status, 421)
        status, _, _ = self.request('GET', '/' + 'a' * 3000)
        self.assertEqual(status, 414)

    def test_listener_is_loopback_only_and_public_bind_refused(self):
        spec = __import__('importlib.util').util.spec_from_file_location('srv', SERVER)
        mod = __import__('importlib.util').util.module_from_spec(spec); spec.loader.exec_module(mod)
        self.assertEqual(mod.listeners_on_port(self.port), ['127.0.0.1'])
        for listen in ('0.0.0.0', '::', '192.0.2.10', 'localhost'):
            r = subprocess.run([sys.executable, '-I', str(SERVER), '--listen', listen, '--port', str(free_port()), '--hostname', fx.DOMAIN, '--cert', str(self.cert), '--key', str(self.key)], capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 2, listen); self.assertIn('refused', r.stderr)
        other = PKI.get().leaves['other.sbox.test']
        r = subprocess.run([sys.executable, '-I', str(SERVER), '--port', str(free_port()), '--hostname', fx.DOMAIN, '--cert', str(other[0]), '--key', str(other[1])], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2); self.assertIn('does not cover', r.stderr)
        r = subprocess.run([sys.executable, '-I', str(SERVER), '--port', '1023', '--hostname', fx.DOMAIN, '--cert', str(self.cert), '--key', str(self.key)], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2)

    def test_busy_site_still_completes_tls_handshake(self):
        # REALITY relays every ClientHello (including authenticated users') to
        # this site and needs its TLS handshake. With every serving slot busy a
        # new visitor must still complete TLS and receive a clean 503, never a
        # pre-handshake close that would fail authenticated REALITY users.
        ctx = ssl.create_default_context(cafile=str(self.ca))
        idle = [ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.port)), server_hostname=fx.DOMAIN) for _ in range(4)]
        try:
            time.sleep(0.2)
            extra = ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=5), server_hostname=fx.DOMAIN)
            extra.settimeout(5)
            data = b''
            while True:
                chunk = extra.recv(4096)
                if not chunk:
                    break
                data += chunk
            extra.close()
            self.assertTrue(data.startswith(b'HTTP/1.1 503 '), data[:80])
            self.assertIn(b'Connection: close', data)
        finally:
            for s in idle:
                s.close()
        time.sleep(0.3)
        self.assertEqual(self.request('GET', '/')[0], 200)

    def test_handshake_bound_sheds_abusive_concurrency(self):
        # Separately bounded handshake pool: connections beyond it are closed
        # rather than queued indefinitely (fixture: --handshakes 8).
        held = [socket.create_connection(('127.0.0.1', self.port)) for _ in range(8)]
        try:
            time.sleep(0.2)
            extra = socket.create_connection(('127.0.0.1', self.port), timeout=5)
            extra.settimeout(5)
            closed = extra.recv(1) == b''
            extra.close()
            self.assertTrue(closed, 'a connection beyond the handshake bound must be closed, not queued indefinitely')
        finally:
            for s in held:
                s.close()
        time.sleep(0.3)
        self.assertEqual(self.request('GET', '/')[0], 200)

    def test_health_check_verifies_trust_and_hostname(self):
        env = {**os.environ, 'SSL_CERT_FILE': str(PKI.get()._dir / 'bundle.pem')}
        r = subprocess.run([sys.executable, '-I', str(SERVER), '--check', '--compact', '--port', str(self.port), '--hostname', fx.DOMAIN], capture_output=True, text=True, env=env, timeout=30)
        report = json.loads(r.stdout)
        self.assertEqual(r.returncode, 0, r.stdout); self.assertTrue(report['ok'])
        self.assertTrue(all(c['ok'] for c in report['checks'] if c['severity'] == 'fail'))
        # Without the lab CA the system trust store rejects the lab certificate.
        r = subprocess.run([sys.executable, '-I', str(SERVER), '--check', '--compact', '--port', str(self.port), '--hostname', fx.DOMAIN], capture_output=True, text=True,
                           env={k: v for k, v in os.environ.items() if k != 'SSL_CERT_FILE'}, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        # Negative control: wrong hostname fails verification.
        r = subprocess.run([sys.executable, '-I', str(SERVER), '--check', '--compact', '--port', str(self.port), '--hostname', 'other.sbox.test'], capture_output=True, text=True, env=env, timeout=30)
        self.assertNotEqual(r.returncode, 0)


class SiteContent(unittest.TestCase):
    def test_generated_site_is_current_and_self_contained(self):
        r = subprocess.run([sys.executable, str(ROOT / 'src/fallback-web/build_site.py'), '--check'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for page in SITE.rglob('*.html'):
            text = page.read_text()
            self.assertNotRegex(text, r'(?:src|href)="(?:https?:)?//', page)
            self.assertNotIn('style=', text, page); self.assertNotRegex(text, r'<script>(?!</script>)', page)
            for banned in ('Synology', 'DSM', 'File Station', 'Video Station', 'Google', 'Microsoft', 'Cloudflare', 'sbox-manager', '9443', '/api/', 'password'):
                self.assertNotIn(banned, text, (page, banned))
        for css in SITE.rglob('*.css'):
            self.assertNotIn('@import', css.read_text()); self.assertNotIn('url(http', css.read_text())

    def test_files_page_lists_exactly_the_curated_library(self):
        page = (SITE / 'files/index.html').read_text()
        listed = set(re.findall(r'href="/library/([^"]+)" download', page))
        actual = {str(p.relative_to(SITE / 'library')) for p in (SITE / 'library').rglob('*') if p.is_file()}
        self.assertEqual(listed, actual)
        self.assertGreaterEqual(len(actual), 8)


class ZgoCloudBoundary(unittest.TestCase):
    def test_protected_payloads_match_canonical_release(self):
        # Mutable release payloads are authenticated by the synchronized release
        # manifest, not a stale 1.1.2 ciphertext (resealing uses fresh randomness).
        release = json.loads((ROOT / 'assets/release.json').read_text())
        meta = json.loads((ROOT / 'assets/zgocloud.json').read_text())
        self.assertEqual(meta['manager_sha256'], release['components']['zgo_manager_sha256'])
        for name, key in [('assets/zgocloud.enc','zgo_envelope_sha256'),('assets/sing-box-accounting.gz','core_gzip_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),release['components'][key],name)
        # The owner identity and reviewed patch remain independently pinned.
        for name, digest in {
            'src/helper-baselines/state.py':'8bb804a760529ad49bf1a25b48ae3da36ea2ec445d015a332ca5ec53c9864e51',
            'core-source/sbox-accounting.patch':'44a206e5b00b303811f09a4a6085d6ddeb1187fe41638640c768cf3933f995c5'
        }.items():self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest,name)
        self.assertEqual(release['original_zgocloud_yaml_sha256'], 'f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b')
        self.assertEqual(hashlib.sha256((ROOT / 'assets/zgocloud.enc').read_bytes()).hexdigest(), release['components']['zgo_envelope_sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
