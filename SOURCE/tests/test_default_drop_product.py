"""Managed firewall can enforce default-drop, not just accept-list (D4, 1.8.0).

Fail-first: 1.7.1 (and live 1.4.1) only add ACCEPT rules in front of an INPUT policy
ACCEPT, so any listener is reachable (proved on VPS-A/B 2026-11-05). 1.8.0 embeds the
generator applied and verified on VPS-B as `inet sbox_hardening`, driven by
state.firewall.default_drop, re-applied at boot by sbox-manager-firewall.service, and
enabled interactively only through a dead-man trial plus `sbox firewall confirm`.
"""
import copy, json, os, re, shutil, subprocess, tempfile, textwrap, unittest
from pathlib import Path
import reality_fixture as fx

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'src/manager.sh').read_text()
GENERATOR = ROOT / 'src/hardening.py'

SAVE4 = textwrap.dedent('''\
    *filter
    :INPUT ACCEPT [0:0]
    :SBOX_INPUT - [0:0]
    -A INPUT -j SBOX_INPUT
    -A INPUT -p tcp -m tcp --dport 9443 -m comment --comment sbox-webui -j ACCEPT
    -A SBOX_INPUT -p tcp -m tcp --dport 443 -m comment --comment "sbox:reality" -j ACCEPT
    -A SBOX_INPUT -p tcp -m tcp --dport 60189 -m comment --comment "sbox:vmess" -j ACCEPT
    -A SBOX_INPUT -p udp -m udp --dport 33878 -m comment --comment "sbox:tuic" -j ACCEPT
    -A SBOX_INPUT -j RETURN
    COMMIT
    ''')


def func(name, text=SRC):
    m = re.search(r'^' + name + r'\(\) [\{\(]\n.*?^[\}\)]\n', text, re.M | re.S)
    if not m:
        raise AssertionError('manager.sh has no %s()' % name)
    return m.group(0)


class DefaultDropProduct(unittest.TestCase):
    def test_firewall_apply_reconciles_the_gate(self):
        apply_ = func('firewall_apply_file')
        self.assertIn('hardening_reconcile_file "$state"', apply_)

    def test_assembled_manager_embeds_generator_byte_exact(self):
        r = subprocess.run(['python3', 'tools/build.py'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        built = (ROOT / '.build/src/manager.sh').read_text()
        m = re.search(r"^write_hardening_helper\(\) \{\n  cat <<'SBOX_HARDENING_PY'\n(.*?)^SBOX_HARDENING_PY\n\}", built, re.M | re.S)
        self.assertIsNotNone(m, 'assembled manager lacks write_hardening_helper')
        self.assertEqual(m.group(1), GENERATOR.read_text())
        self.assertNotIn('@@HELPER_', built)

    def reconcile(self, state_json, table_present, timers_active=()):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); log = d / 'calls'; st = d / 'state.json'; st.write_text(json.dumps(state_json))
            stubs = textwrap.dedent(f'''\
                warn() {{ echo "WARN $*" >> {log}; }}
                hardening_tool() {{ echo "hardening $*" >> {log}; }}
                nft() {{ [ "{'yes' if table_present else 'no'}" = yes ]; }}
                systemctl() {{ case " {' '.join(timers_active)} " in *" $3 "*) return 0;; esac; return 1; }}
                ''')
            r = subprocess.run(['bash', '-c', stubs + func('hardening_reconcile_file') + f'hardening_reconcile_file {st}\n'],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            return log.read_text() if log.exists() else ''

    def test_reconcile_decisions(self):
        on = {'firewall': {'enabled': True, 'default_drop': True}}
        off = {'firewall': {'enabled': True}}
        disabled = {'firewall': {'enabled': False, 'default_drop': True}}
        self.assertIn('hardening apply', self.reconcile(on, False))
        self.assertIn('hardening remove', self.reconcile(off, True))
        self.assertEqual(self.reconcile(off, False), '')                                   # nothing to do
        self.assertEqual(self.reconcile(off, True, ['sbox-hardening-rollback.timer']), '')  # trial pending: keep
        self.assertEqual(self.reconcile(off, True, ['sbox-hardening-sync.timer']), '')      # interim 1.4.x tooling: keep
        self.assertNotIn('apply', self.reconcile(disabled, False))

    def test_state_validation(self):
        private, public = fx.reality_keypair()
        base = fx.trusted_certificate(fx.base_state(private, public))
        ok = copy.deepcopy(base); ok['firewall'].update(enabled=True, default_drop=True)
        fx.render(ok)
        for bad in ({'enabled': True, 'default_drop': 'yes'}, {'enabled': False, 'default_drop': True}):
            s = copy.deepcopy(base); s['firewall'].update(bad)
            with self.subTest(bad=bad), self.assertRaises(Exception):
                fx.render(s)

    def test_cli_trial_arms_rollback_before_apply_and_persists_only_on_confirm(self):
        body = func('firewall_default_drop_command')
        on = body[body.index('    on)'):body.index('    confirm)')]
        self.assertLess(on.index('systemd-run'), on.index('hardening_tool apply'), 'dead-man must be armed first')
        self.assertNotIn('default_drop=true', on, 'trial must not persist state')
        confirm = body[body.index('    confirm)'):body.index('    off)')]
        self.assertIn('.firewall.default_drop=true', confirm)
        self.assertIn('state_tool validate', confirm)

    @unittest.skipUnless(all(shutil.which(x) for x in ('unshare', 'nsenter', 'nft', 'ip')), 'needs unshare/nsenter/nft/ip')
    def test_real_kernel_enforcement_two_namespaces(self):
        if subprocess.run(['unshare', '-rn', 'true'], capture_output=True).returncode:
            self.skipTest('unprivileged network namespaces unavailable')
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 's4').write_text(SAVE4); (d / 's6').write_text(SAVE4.replace(
                '-A INPUT -p tcp -m tcp --dport 9443 -m comment --comment sbox-webui -j ACCEPT\n', ''))
            (d / 'sshd').write_text('port 22\n')
            rendered = subprocess.run(['python3', '-I', str(GENERATOR), 'render', '--iptables-save', str(d / 's4'),
                                       '--ip6tables-save', str(d / 's6'), '--sshd-t', str(d / 'sshd')],
                                      capture_output=True, text=True, check=True).stdout
            (d / 'gate.nft').write_text(rendered)
            probe = 'import socket,sys\ntry:\n socket.create_connection(("10.9.0.1",int(sys.argv[1])),2);print("open")\nexcept OSError as e:print("closed",type(e).__name__)\n'
            (d / 'probe.py').write_text(probe)
            script = textwrap.dedent(f'''\
                set -e
                ip link set lo up
                unshare -n sleep 40 & child=$!; sleep 0.3
                ip link add v0 type veth peer name v1 netns $child
                ip addr add 10.9.0.1/24 dev v0; ip link set v0 up
                nsenter -t $child -n --preserve-credentials sh -c "ip addr add 10.9.0.2/24 dev v1; ip link set v1 up; ip link set lo up"
                for p in 60189 40199; do python3 -c "import socket,time;s=socket.socket();s.setsockopt(1,2,1);s.bind(('0.0.0.0',$p));s.listen();time.sleep(30)" & done
                sleep 0.5
                C="nsenter -t $child -n --preserve-credentials"
                echo "before 60189 $($C python3 {d}/probe.py 60189)"; echo "before 40199 $($C python3 {d}/probe.py 40199)"
                nft -f {d}/gate.nft
                echo "after 60189 $($C python3 {d}/probe.py 60189)"; echo "after 40199 $($C python3 {d}/probe.py 40199)"
                echo "after ping $($C ping -c1 -W2 10.9.0.1 >/dev/null 2>&1 && echo ok || echo fail)"
                # host-initiated (established/related) traffic must still work
                $C python3 -c "import socket,time;s=socket.socket();s.bind(('10.9.0.2',5555));s.listen();time.sleep(8)" & sleep 0.4
                echo "outbound $(python3 -c "import socket;socket.create_connection(('10.9.0.2',5555),2);print('ok')" 2>&1 | tail -1)"
                kill $(jobs -p) 2>/dev/null; true
                ''')
            r = subprocess.run(['unshare', '-rn', 'bash', '-c', script], capture_output=True, text=True, timeout=90)
            out = r.stdout
            self.assertIn('before 60189 open', out, out + r.stderr)
            self.assertIn('before 40199 open', out)          # 1.7.1 behaviour: everything reachable
            self.assertIn('after 60189 open', out)           # SBOX port still served
            self.assertIn('after 40199 closed', out)         # unknown listener now blocked
            self.assertIn('after ping ok', out)
            self.assertIn('outbound ok', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
