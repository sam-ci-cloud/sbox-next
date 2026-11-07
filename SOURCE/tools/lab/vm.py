#!/usr/bin/env python3
"""Disposable systemd "VM" lab: overlay of a debootstrapped rootfs booted with
real systemd as PID 1 in private PID/mount/UTS/IPC/network namespaces and a
private cgroup2 mount. LAB TOOL (not a clean VPS):

  vm.py create NAME [--base stonking] [--peer]   # --peer adds veth 10.77.0.1(host side ns 'NAME-peer') <-> 10.77.0.2(vm)
  vm.py exec NAME -- CMD...
  vm.py pid NAME
  vm.py destroy NAME
"""
import argparse, json, os, shutil, signal, subprocess, sys, time
from pathlib import Path

LAB = Path(os.environ.get('SBOX_LAB_ROOT', '/var/tmp/sbox-lab'))
BASE = LAB / 'vms'


def run(*a, check=True, **kw):
    p = subprocess.run([str(x) for x in a], capture_output=True, text=True, **kw)
    if check and p.returncode:
        raise SystemExit('failed: %s\n%s' % (' '.join(map(str, a))[:300], (p.stderr or p.stdout)[-1500:]))
    return p


def nsargs(pid):
    return ['nsenter', '-t', str(pid), '-m', '-u', '-i', '-n', '-p', '-r', '-w', '/usr/bin/env', '-i',
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8', 'TERM=dumb']


def create(a):
    d = BASE / a.name
    if d.exists():
        raise SystemExit('exists: ' + str(d))
    for sub in ('up', 'wk', 'root'):
        (d / sub).mkdir(parents=True)
    lower = LAB / 'rootfs' / a.base
    run('mount', '-t', 'overlay', 'overlay', '-o', 'lowerdir=%s,upperdir=%s,workdir=%s' % (lower, d / 'up', d / 'wk'), d / 'root')
    r = d / 'root'
    (r / 'etc/hostname').write_text(a.name + '\n')
    (r / 'etc/hosts').write_text('127.0.0.1 localhost\n127.0.1.1 %s\n' % a.name)
    (r / 'opt/sbox-lab').mkdir(parents=True, exist_ok=True)
    (r / 'opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS').write_text('disposable systemd lab VM\n')
    boot = d / 'boot.sh'
    boot.write_text('''#!/bin/bash
set -e
R=%s
mount --rbind /dev $R/dev
mount -t sysfs sysfs $R/sys -o ro 2>/dev/null || mount --rbind /sys $R/sys
# A private cgroup2 subtree per machine: unit cgroups of concurrently running
# machines must never be shared (a stop would kill the other machine's unit).
CG=$(mktemp -d); mount -t cgroup2 cgroup2 $CG; mkdir -p $CG/sbox-lab-%s; echo $$ > $CG/sbox-lab-%s/cgroup.procs
mount --bind $CG/sbox-lab-%s $R/sys/fs/cgroup; umount $CG; rmdir $CG
mount -t bpf bpf $R/sys/fs/bpf 2>/dev/null || true
mount -t tmpfs tmpfs $R/run; mount -t tmpfs tmpfs $R/tmp
hostname %s
true
cd $R && exec unshare --cgroup chroot $R /lib/systemd/systemd --system --unit=multi-user.target
''' % (r, a.name, a.name, a.name, a.name))
    boot.chmod(0o755)
    log = open(d / 'boot.log', 'w')
    p = subprocess.Popen(['unshare', '--pid', '--mount', '--uts', '--ipc', '--net', '--fork', '--mount-proc=%s/proc' % r,
                          '--propagation', 'private', str(boot)], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    pid1 = None
    for _ in range(150):
        time.sleep(0.2)
        out = run('pgrep', '-P', str(p.pid), check=False).stdout.split()
        if out:
            cand = int(out[0])
            try:
                if Path('/proc/%d/comm' % cand).read_text().strip() == 'systemd':
                    pid1 = cand
                    break
            except OSError:
                pass
    if not pid1:
        raise SystemExit('VM did not boot; see ' + str(d / 'boot.log'))
    st = ''
    for _ in range(120):
        st = run(*nsargs(pid1), 'systemctl', 'is-system-running', check=False).stdout.strip()
        if st in ('running', 'degraded'):
            break
        time.sleep(0.5)
    meta = {'name': a.name, 'pid1': pid1, 'unshare_pid': p.pid, 'root': str(r), 'base': a.base, 'created': time.time()}
    if a.peer:
        # A separate "internet client" namespace connected by a veth pair.
        peer = a.name + '-peer'
        run('ip', 'netns', 'add', peer)
        run('ip', 'link', 'add', 'vh-' + a.name[:10], 'type', 'veth', 'peer', 'name', 'vv-' + a.name[:10])
        run('ip', 'link', 'set', 'vh-' + a.name[:10], 'netns', peer)
        run('ip', 'link', 'set', 'vv-' + a.name[:10], 'netns', str(pid1))
        run('ip', 'netns', 'exec', peer, 'ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'vh-' + a.name[:10])
        run('ip', 'netns', 'exec', peer, 'ip', 'link', 'set', 'vh-' + a.name[:10], 'up')
        run('ip', 'netns', 'exec', peer, 'ip', 'link', 'set', 'lo', 'up')
        run(*nsargs(pid1), 'ip', 'link', 'set', 'vv-' + a.name[:10], 'name', 'eth0')
        run(*nsargs(pid1), 'ip', 'addr', 'add', '10.77.0.2/24', 'dev', 'eth0')
        run(*nsargs(pid1), 'ip', 'link', 'set', 'eth0', 'up')
        run(*nsargs(pid1), 'ip', 'route', 'add', 'default', 'via', '10.77.0.1')
        meta['peer_netns'] = peer
    (d / 'meta.json').write_text(json.dumps(meta, indent=1))
    print(json.dumps({'name': a.name, 'pid1': pid1, 'state': st}))


def meta(name):
    return json.loads((BASE / name / 'meta.json').read_text())


def destroy(a):
    d = BASE / a.name
    try:
        m = meta(a.name)
        try:
            os.kill(m['pid1'], signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.killpg(m['unshare_pid'], signal.SIGKILL)
        except ProcessLookupError:
            pass
        for _ in range(50):
            if not Path('/proc/%d' % m['pid1']).exists():
                break
            time.sleep(0.1)
        if m.get('peer_netns'):
            run('ip', 'netns', 'del', m['peer_netns'], check=False)
    except FileNotFoundError:
        pass
    for _ in range(5):
        if run('umount', '-R', '-l', d / 'root', check=False).returncode:
            break
    # Remove the machine's private cgroup subtree (children first).
    import tempfile
    cg = tempfile.mkdtemp()
    if run('mount', '-t', 'cgroup2', 'cgroup2', cg, check=False).returncode == 0:
        sub = Path(cg) / ('sbox-lab-' + a.name)
        if sub.is_dir():
            for path in sorted((x for x in sub.rglob('*') if x.is_dir()), key=lambda x: len(x.parts), reverse=True) + [sub]:
                try:
                    os.rmdir(path)
                except OSError:
                    pass
        run('umount', cg, check=False)
    os.rmdir(cg)
    shutil.rmtree(d, ignore_errors=True)
    print('destroyed', a.name)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('create'); c.add_argument('name'); c.add_argument('--base', default='stonking'); c.add_argument('--peer', action='store_true')
    e = sub.add_parser('exec'); e.add_argument('name'); e.add_argument('argv', nargs=argparse.REMAINDER)
    p = sub.add_parser('pid'); p.add_argument('name')
    x = sub.add_parser('destroy'); x.add_argument('name')
    a = ap.parse_args()
    if a.cmd == 'create':
        create(a)
    elif a.cmd == 'pid':
        print(meta(a.name)['pid1'])
    elif a.cmd == 'destroy':
        destroy(a)
    else:
        argv = a.argv[1:] if a.argv[:1] == ['--'] else a.argv
        sys.exit(subprocess.run(nsargs(meta(a.name)['pid1']) + argv).returncode)


if __name__ == '__main__':
    main()
