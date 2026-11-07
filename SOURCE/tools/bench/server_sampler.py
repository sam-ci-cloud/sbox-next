#!/usr/bin/env python3
"""Sample server resource counters once per second during a benchmark (read-only).

Columns: utc, sing-box CPU %, sing-box RSS MiB, host CPU busy/steal %, PSI cpu/io avg10,
cgroup throttling deltas for sing-box, accounting and WebUI units, TCP retransmits,
UDP receive-buffer errors, conntrack entries. Stops after --seconds or on SIGTERM.
"""
import argparse
import csv
import os
import signal
import time

UNITS = ('sing-box', 'sbox-accounting', 'sbox-webui', 'sbox-fallback-web')


def cpu_times():
    f = open('/proc/stat').readline().split()[1:]
    v = list(map(int, f))
    idle = v[3] + v[4]
    steal = v[7] if len(v) > 7 else 0
    return sum(v), idle, steal


def pid_of(unit):
    try:
        for line in open('/sys/fs/cgroup/system.slice/%s.service/cgroup.procs' % unit):
            return int(line)
    except OSError:
        return None


def proc_cpu(pid):
    try:
        f = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()
        return int(f[11]) + int(f[12]), int(f[21]) * os.sysconf('SC_PAGE_SIZE') / 2**20
    except (OSError, TypeError, IndexError):
        return None, None


def cg(unit):
    out = {}
    try:
        for line in open('/sys/fs/cgroup/system.slice/%s.service/cpu.stat' % unit):
            k, v = line.split()
            out[k] = int(v)
    except OSError:
        pass
    return out


def psi(kind):
    try:
        return float(open('/proc/pressure/%s' % kind).readline().split()[1].split('=')[1])
    except OSError:
        return ''


def snmp():
    lines = open('/proc/net/snmp').read().splitlines()
    out = {}
    for i in range(0, len(lines) - 1, 2):
        keys, vals = lines[i].split(), lines[i + 1].split()
        for k, v in zip(keys[1:], vals[1:]):
            out[keys[0] + k] = int(v)
    return out


def conntrack():
    try:
        return int(open('/proc/sys/net/netfilter/nf_conntrack_count').read())
    except OSError:
        return ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--seconds', type=int, default=7200)
    a = ap.parse_args()
    hz = os.sysconf('SC_CLK_TCK')
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    cols = ['utc', 'sb_cpu_pct', 'sb_rss_mib', 'host_busy_pct', 'steal_pct', 'psi_cpu', 'psi_io', 'psi_mem',
            'tcp_retrans', 'udp_rcvbuf_err', 'udp_in_err', 'conntrack'] + \
           ['%s_throttled_ms' % u for u in UNITS]
    fh = open(a.out, 'w', newline='')
    w = csv.writer(fh)
    w.writerow(cols)
    prev_t, prev_i, prev_s = cpu_times()
    pid = pid_of('sing-box')
    prev_p, _ = proc_cpu(pid) if pid else (None, None)
    prev_cg = {u: cg(u) for u in UNITS}
    prev_n = snmp()
    end = time.time() + a.seconds
    while not stop[0] and time.time() < end:
        time.sleep(1)
        t, i, s = cpu_times()
        dt = max(1, t - prev_t)
        pid = pid_of('sing-box') or pid
        p, rss = proc_cpu(pid) if pid else (None, None)
        sb = '' if p is None or prev_p is None else round(100.0 * (p - prev_p) / hz, 1)
        n = snmp()
        row = [time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), sb, '' if rss is None else round(rss, 1),
               round(100.0 * (dt - (i - prev_i)) / dt, 1), round(100.0 * (s - prev_s) / dt, 1),
               psi('cpu'), psi('io'), psi('memory'),
               n.get('Tcp:RetransSegs', 0) - prev_n.get('Tcp:RetransSegs', 0),
               n.get('Udp:RcvbufErrors', 0) - prev_n.get('Udp:RcvbufErrors', 0),
               n.get('Udp:InErrors', 0) - prev_n.get('Udp:InErrors', 0), conntrack()]
        for u in UNITS:
            c = cg(u)
            row.append(round((c.get('throttled_usec', 0) - prev_cg[u].get('throttled_usec', 0)) / 1000, 1) if c else '')
            prev_cg[u] = c
        w.writerow(row)
        fh.flush()
        prev_t, prev_i, prev_s, prev_p, prev_n = t, i, s, p, n


if __name__ == '__main__':
    main()
