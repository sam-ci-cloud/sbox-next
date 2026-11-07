"""Requested fq qdisc is actually attached to NICs (D5, 1.8.0).

Fail-first: 1.7.1 only writes net.core.default_qdisc=fq. That applies to qdiscs created
later, but NICs exist before sysctl runs, so live hosts kept pfifo_fast (VPS-B, 1 queue)
and mq+pfifo_fast (VPS-A, 2 queues) — observed 2026-11-05 with `tc qdisc show`.
"""
import os, re, shutil, subprocess, tempfile, textwrap, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANAGER = (ROOT / 'src/manager.sh').read_text()


def function(name):
    m = re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', MANAGER, re.M | re.S)
    if not m:
        raise AssertionError('manager.sh has no %s()' % name)
    return m.group(0)


def body_of(name):
    return function(name)


PRELUDE = 'warn() { echo "WARN: $*" >&2; }\n'


def fake_sys(root, devices):
    """devices: {name: (tx_queues, physical)}"""
    for name, (n, physical) in devices.items():
        q = root / name / 'queues'; q.mkdir(parents=True)
        for i in range(n):
            (q / f'tx-{i}').mkdir()
        if physical:
            (root / name / 'device').mkdir()


class EgressQdisc(unittest.TestCase):
    def test_hooks_cover_fresh_tuning_existing_tuning_and_boot(self):
        tuning = body_of('apply_tuning')
        early = re.search(r'if \[ -f "\$SYSCTL_FILE" \] && \[ "\$explicit" != true \]; then (.*?)fi', tuning).group(1)
        self.assertIn('apply_egress_qdisc', early, 'hosts with tuning already applied must still get the qdisc')
        self.assertGreaterEqual(tuning.count('apply_egress_qdisc'), 2)
        boot = MANAGER[MANAGER.index('    _firewall-apply)'):]
        boot = boot[:boot.index(';;')]
        self.assertIn('apply_egress_qdisc', boot, 'boot path (sbox-manager-firewall.service) must re-attach')
        self.assertIn('.tuning.enabled == true', boot)

    def test_stubbed_discovery_commands_and_idempotence(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); sysnet = d / 'net'; bin_ = d / 'bin'; bin_.mkdir(); log = d / 'tc.log'
            fake_sys(sysnet, {'eth0': (1, True), 'ens5': (2, True), 'lo': (1, False), 'veth9': (1, False), 'wg0': (1, False)})
            (bin_ / 'tc').write_text(textwrap.dedent(f'''\
                #!/bin/bash
                echo "$*" >> {log}
                if [ "$1 $2" = "qdisc show" ]; then
                  case "$4" in eth0) echo "qdisc ${{CUR_ETH0:-pfifo_fast}} 0: root";; ens5) echo "qdisc mq 0: root";; esac
                fi
                exit 0
                '''))
            (bin_ / 'tc').chmod(0o755)
            script = PRELUDE + function('apply_egress_qdisc') + 'apply_egress_qdisc\n'
            env = dict(os.environ, PATH=f'{bin_}:{os.environ["PATH"]}', SBOX_SYS_NET=str(sysnet), SBOX_QDISC_WANT='fq')
            r = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = [l for l in log.read_text().splitlines() if 'replace' in l]
            self.assertIn('qdisc replace dev eth0 root fq', calls)
            self.assertIn('qdisc replace dev ens5 root handle 1: mq', calls)
            self.assertIn('qdisc replace dev ens5 parent 1:1 fq', calls)
            self.assertIn('qdisc replace dev ens5 parent 1:2 fq', calls)
            self.assertFalse([c for c in calls if any(v in c for v in (' lo ', 'veth9', 'wg0'))], calls)
            # already fq on a single-queue NIC -> no replace for it
            log.write_text('')
            env['CUR_ETH0'] = 'fq'
            subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, check=True)
            self.assertFalse([l for l in log.read_text().splitlines() if 'replace dev eth0' in l])
            # not requested -> nothing at all
            log.write_text('')
            env['SBOX_QDISC_WANT'] = 'pfifo_fast'
            subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, check=True)
            self.assertEqual(log.read_text(), '')

    def test_missing_tc_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            sysnet = Path(d) / 'net'; fake_sys(sysnet, {'eth0': (1, True)})
            script = PRELUDE + function('apply_egress_qdisc') + 'apply_egress_qdisc; echo rc=$?\n'
            env = dict(os.environ, PATH='/nonexistent', SBOX_SYS_NET=str(sysnet), SBOX_QDISC_WANT='fq')
            r = subprocess.run(['/bin/bash', '-c', 'command(){ return 1; }; ' + script], env=env, capture_output=True, text=True)
            self.assertIn('rc=0', r.stdout)

    @unittest.skipUnless(shutil.which('unshare') and shutil.which('tc') and shutil.which('ip'), 'needs unshare, tc and ip')
    def test_real_kernel_veth_single_and_multi_queue(self):
        probe = subprocess.run(['unshare', '-rn', 'true'], capture_output=True)
        if probe.returncode != 0:
            self.skipTest('unprivileged network namespaces unavailable')
        with tempfile.TemporaryDirectory() as d:
            sysnet = Path(d) / 'net'
            fake_sys(sysnet, {'v0': (2, True), 'v1': (1, True)})   # mirrors the real veth queue counts below
            script = (PRELUDE + function('apply_egress_qdisc') + textwrap.dedent('''\
                set -e
                ip link add v0 numtxqueues 2 numrxqueues 2 type veth peer name v1 numtxqueues 1 numrxqueues 1
                ip link set v0 up; ip link set v1 up
                apply_egress_qdisc
                apply_egress_qdisc   # idempotent
                tc qdisc show dev v0; echo ---; tc qdisc show dev v1
                '''))
            env = dict(os.environ, SBOX_SYS_NET=str(sysnet), SBOX_QDISC_WANT='fq')
            r = subprocess.run(['unshare', '-rn', 'bash', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            v0, v1 = r.stdout.split('---')
            self.assertRegex(v0, r'qdisc mq 1: root')
            self.assertEqual(len(re.findall(r'qdisc fq \w+: parent 1:[12] ', v0)), 2, v0)
            self.assertRegex(v1, r'qdisc fq \w+: root')


if __name__ == '__main__':
    unittest.main(verbosity=2)
