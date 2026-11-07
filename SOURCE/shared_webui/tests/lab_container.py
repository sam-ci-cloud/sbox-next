#!/usr/bin/env python3
"""Disposable systemd container for installer/panel lifecycle tests.

LAB TOOL. Used where KVM and Ubuntu/Debian package mirrors are unavailable.
The container is an overlay of this host's Ubuntu 24.04 root filesystem with
real systemd as PID 1 in private PID/mount/UTS/IPC/network namespaces. The
host's network namespace, firewall and services are never modified; every
write lands in the overlay's upper directory, which is deleted on destroy.

Packages that could not be downloaded are replaced by clearly named LAB
SUBSTITUTES (see lab_substitutes in meta.json). Results from this lab are
labelled "systemd-container lab (substituted packages)" and are never reported
as a clean-OS installation.

LIMITATION: the containers mount the host cgroup-v1 hierarchy, so units with the
same name in concurrently running containers share one cgroup (MemoryMax,
TasksMax, `systemctl kill`). Resource measurements and kill tests must run with a
single container alive.

  lab_container.py create NAME --subst DIR [--fail2ban-deb FILE] [--cache DIR]
  lab_container.py exec NAME -- CMD...
  lab_container.py pid NAME
  lab_container.py destroy NAME
"""
import argparse, json, os, shutil, signal, subprocess, sys, time
from pathlib import Path

BASE = Path(os.environ.get('SBOX_LAB_ROOT', '/home/claude/lab/containers'))


def run(*a, check=True, **kw):
    p = subprocess.run([str(x) for x in a], capture_output=True, text=True, **kw)
    if check and p.returncode: raise SystemExit('failed: %s\n%s' % (' '.join(map(str, a))[:300], (p.stderr or p.stdout)[-1500:]))
    return p


def nsexec(pid, *cmd, check=True, timeout=None, env=None):
    base = ['nsenter', '-t', str(pid), '-m', '-u', '-i', '-n', '-p', '-r', '-w', '/usr/bin/env', '-i',
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8', 'TERM=dumb']
    base += ['%s=%s' % kv for kv in (env or {}).items()]
    return run(*(base + list(cmd)), check=check, timeout=timeout)


def create(a):
    d = BASE / a.name
    if d.exists(): raise SystemExit('exists: ' + str(d))
    for sub in ('up', 'wk', 'root'): (d / sub).mkdir(parents=True)
    run('mount', '-t', 'overlay', 'overlay', '-o', 'lowerdir=/,upperdir=%s,workdir=%s' % (d / 'up', d / 'wk'), d / 'root')
    r = d / 'root'
    subst = Path(a.subst)
    placed = []
    def put(src, dest, mode=0o755):
        dest = r / dest.lstrip('/'); dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink(): dest.unlink()
        shutil.copyfile(src, dest); dest.chmod(mode); placed.append(str(dest.relative_to(r)))
    put(subst / 'ss', '/usr/bin/ss'); put(subst / 'ip', '/usr/bin/ip'); put(subst / 'modprobe', '/usr/sbin/modprobe')
    put(subst / 'certbot', '/usr/bin/certbot'); put(subst / 'sshd', '/usr/sbin/sshd'); put(subst / 'qrencode', '/usr/bin/qrencode')
    put(subst / 'dig-wrapper', '/usr/bin/dig'); put(subst / 'curl-wrapper', '/usr/local/bin/curl'); put(subst / 'rsyslogd', '/usr/sbin/rsyslogd')
    for f in (subst / 'pylib/systemd').glob('*.py'): put(f, '/usr/lib/python3/dist-packages/systemd/' + f.name, 0o644)
    # Ubuntu 24.04's stock interpreter is 3.12; the build host relinked python3 to 3.13.
    alt = r / 'etc/alternatives/python3'
    if alt.is_symlink() or alt.exists(): alt.unlink()
    alt.symlink_to('/usr/bin/python3.12'); placed.append('etc/alternatives/python3 -> /usr/bin/python3.12')
    for extra in ('usr/local/bin/python3', 'usr/local/bin/python'):
        q = r / extra
        if q.exists() or q.is_symlink():
            q.unlink(); q.symlink_to('/usr/bin/python3.12'); placed.append(extra + ' -> /usr/bin/python3.12')
    (r / 'opt/sbox-lab/cache').mkdir(parents=True, exist_ok=True)
    if a.cache:
        for f in Path(a.cache).glob('sing-box-*-linux-amd64.tar.gz'): shutil.copyfile(f, r / 'opt/sbox-lab/cache' / f.name)
    (r / 'opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS').write_text('disposable systemd container\n')
    (r / 'root/lab-ready').write_text('disposable systemd container\n')
    (r / 'etc/hostname').write_text(a.name + '\n')
    # Keep unrelated host services from starting inside the container.
    for unit in ('redis-server.service', 'docker.service', 'containerd.service', 'docker.socket', 'postgresql.service', 'postgresql@16-main.service'):
        p = r / 'etc/systemd/system' / unit
        if p.exists() or p.is_symlink(): p.unlink()
        p.symlink_to('/dev/null')
    boot = d / 'boot.sh'
    boot.write_text('''#!/bin/bash
R=%s
mount --rbind /dev $R/dev
mount -t sysfs sysfs $R/sys -o ro 2>/dev/null || mount --rbind /sys $R/sys
mount -t tmpfs tmpfs $R/sys/fs/cgroup
for c in cpu cpuacct cpuset memory devices freezer blkio pids; do mkdir -p $R/sys/fs/cgroup/$c; mount -t cgroup -o $c cgroup $R/sys/fs/cgroup/$c 2>/dev/null; done
mkdir -p $R/sys/fs/cgroup/systemd; mount -t cgroup -o none,name=systemd cgroup $R/sys/fs/cgroup/systemd
mount -t tmpfs tmpfs $R/run; mount -t tmpfs tmpfs $R/tmp
hostname %s
cd $R && exec chroot $R /lib/systemd/systemd --system --unit=multi-user.target
''' % (r, a.name))
    boot.chmod(0o755)
    log = open(d / 'boot.log', 'w')
    p = subprocess.Popen(['unshare', '--pid', '--mount', '--uts', '--ipc', '--net', '--fork', '--mount-proc=%s/proc' % r, '--propagation', 'private', str(boot)],
                         stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    pid1 = None
    for _ in range(100):
        time.sleep(0.2)
        out = run('pgrep', '-P', str(p.pid), check=False).stdout.split()
        if out:
            pid1 = int(out[0])
            try:
                if Path('/proc/%d/comm' % pid1).read_text().strip() == 'systemd': break
            except OSError: pass
    if not pid1: raise SystemExit('container did not boot; see ' + str(d / 'boot.log'))
    for _ in range(120):
        st = nsexec(pid1, 'systemctl', 'is-system-running', check=False).stdout.strip()
        if st in ('running', 'degraded'): break
        time.sleep(0.5)
    meta = {'name': a.name, 'pid1': pid1, 'unshare_pid': p.pid, 'root': str(r), 'created': time.time(), 'lab_substitutes': placed,
            'note': 'systemd-container lab (substituted packages): overlay of host Ubuntu 24.04 rootfs; not a clean OS install'}
    if a.fail2ban_deb:
        shutil.copyfile(a.fail2ban_deb, r / 'opt/sbox-lab' / Path(a.fail2ban_deb).name)
        # python3-systemd is provided by the lab substitute module, not a package.
        res = nsexec(pid1, 'dpkg', '-i', '--force-depends', '/opt/sbox-lab/' + Path(a.fail2ban_deb).name, check=False)
        # The upstream .deb ships its native unit at /fail2ban.service; Ubuntu's package installs it
        # under /lib/systemd/system. Place it there (a sysv-redirected unit ignores `enable --now`).
        unit = r / 'fail2ban.service'
        if unit.exists():
            shutil.copyfile(unit, r / 'lib/systemd/system/fail2ban.service'); placed.append('lib/systemd/system/fail2ban.service (from the upstream .deb)')
            nsexec(pid1, 'systemctl', 'daemon-reload', check=False)
        meta['fail2ban_install'] = {'exit': res.returncode, 'tail': (res.stdout + res.stderr)[-600:], 'source': 'official upstream release asset ' + Path(a.fail2ban_deb).name}
    (d / 'meta.json').write_text(json.dumps(meta, indent=1))
    print(json.dumps({'name': a.name, 'pid1': pid1, 'state': st}))


def meta(name):
    return json.loads((BASE / name / 'meta.json').read_text())


def destroy(a):
    d = BASE / a.name
    try:
        m = meta(a.name)
        # SIGKILL the namespace init first: that terminates every process in the
        # container's PID namespace. Killing only the unshare process group left
        # the container's systemd (and its services) running as orphans.
        for pid in (m['pid1'],):
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        try: os.killpg(m['unshare_pid'], signal.SIGKILL)
        except ProcessLookupError: pass
        for _ in range(50):
            if not Path('/proc/%d' % m['pid1']).exists(): break
            time.sleep(0.1)
    except FileNotFoundError: pass
    for helper in ('camo.pid', 'client.pid'):  # started by lab_install_run.py
        try: os.kill(int((d / helper).read_text()), signal.SIGKILL)
        except (OSError, ValueError): pass
    for _ in range(5):
        if run('umount', '-R', '-l', d / 'root', check=False).returncode: break
    shutil.rmtree(d, ignore_errors=True)
    print('destroyed', a.name)


def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('create'); c.add_argument('name'); c.add_argument('--subst', required=True); c.add_argument('--fail2ban-deb'); c.add_argument('--cache')
    e = sub.add_parser('exec'); e.add_argument('name'); e.add_argument('argv', nargs=argparse.REMAINDER)
    p = sub.add_parser('pid'); p.add_argument('name')
    x = sub.add_parser('destroy'); x.add_argument('name')
    a = ap.parse_args()
    if os.geteuid() != 0: raise SystemExit('root required')
    if a.cmd == 'create': create(a)
    elif a.cmd == 'pid': print(meta(a.name)['pid1'])
    elif a.cmd == 'destroy': destroy(a)
    else:
        argv = a.argv[1:] if a.argv[:1] == ['--'] else a.argv
        base = ['nsenter', '-t', str(meta(a.name)['pid1']), '-m', '-u', '-i', '-n', '-p', '-r', '-w', '/usr/bin/env', '-i',
                'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8', 'TERM=dumb']
        # Inherit our stdio directly: a daemon started by the command cannot block us on pipe EOF.
        sys.exit(subprocess.run(base + argv).returncode)


if __name__ == '__main__':
    main()
