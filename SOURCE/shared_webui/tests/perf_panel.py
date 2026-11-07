#!/usr/bin/env python3
"""Panel resource/latency measurement on a real lab installation (A/B across releases).

Run INSIDE the lab client namespace:
  nsenter -t CLIENT_PID -n -m python3 perf_panel.py --container NAME --domain D --label L --out FILE [--idle 600]

Same harness, request mix and host for every release measured. Measures:
cold start to an accepting socket (5 restarts), idle panel+bridge RSS/CPU/fds,
a 600-request burst from 10 concurrent clients (landing data + common reads),
peak RSS under load, panel SQLite growth, and whether the VPN core PID changed.
These are controlled local measurements, not VPS/ISP capacity claims.
"""
import argparse, base64, json, os, re, socket, statistics, sys, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab_post_install import Container, Panel, CT_IP, sh  # noqa: E402

TICK = os.sysconf('SC_CLK_TCK')


def pids(ct):
    out = {}
    for unit in ('sbox-webui', 'sbox-webui-control', 'sing-box'):
        _, p = ct.run('systemctl show -p MainPID --value %s.service' % unit)
        out[unit] = int(p.strip() or 0)
    return out


def proc(ct, pid):
    root = ct.root  # same kernel: /proc of the host shows container PIDs under their host numbers
    _, out = ct.run('cat /proc/%d/status | grep -E "^(VmRSS|Threads):"; ls /proc/%d/fd | wc -l; cut -d" " -f14,15 /proc/%d/stat' % (pid, pid, pid))
    rss = int(re.search(r'VmRSS:\s+(\d+)', out)[1]); thr = int(re.search(r'Threads:\s+(\d+)', out)[1])
    lines = out.strip().splitlines(); fds = int(lines[-2]); ut, st = map(int, lines[-1].split())
    return {'rss_kib': rss, 'threads': thr, 'fds': fds, 'cpu_ticks': ut + st}


def pct(values, q):
    v = sorted(values); return round(v[min(len(v) - 1, int(round(q / 100 * (len(v) - 1))))], 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--container', required=True); ap.add_argument('--domain', required=True); ap.add_argument('--label', required=True)
    ap.add_argument('--out', required=True, type=Path); ap.add_argument('--idle', type=int, default=600); ap.add_argument('--ca-bundle', required=True)
    a = ap.parse_args()
    ct = Container(a.container)
    hosts = Path('/tmp/perf-hosts-%s' % a.container); hosts.write_text('127.0.0.1 localhost\n%s %s\n' % (CT_IP, a.domain))
    sh('mount', '--bind', hosts, '/etc/hosts'); sh('mount', '--bind', a.ca_bundle, '/etc/ssl/certs/ca-certificates.crt'); os.environ['SSL_CERT_FILE'] = a.ca_bundle
    _, version = ct.run('sbox version'); res = {'label': a.label, 'container': a.container, 'manager_version': version.strip(), 'note': ct.meta['note']}
    ct.run('sbox webui reset-admin >/dev/null 2>&1 || true')
    boot = re.search(r'Password: (\S+)', (ct.root / 'etc/sbox-webui/bootstrap-admin.txt').read_text())[1]
    core0 = pids(ct)['sing-box']

    # 1. Cold start to an accepting socket.
    starts = []
    for _ in range(5):
        # Space restarts >= 2.5 s apart: systemd's default start limit is 5 starts per 10 s.
        ct.run('systemctl reset-failed sbox-webui.service sbox-webui-control.service 2>/dev/null; systemctl restart sbox-webui-control.service sbox-webui.service')
        t0 = time.monotonic()
        while time.monotonic() - t0 < 60:
            try:
                with socket.create_connection((a.domain, 9443), timeout=1): break
            except OSError: time.sleep(0.05)
        acc = round(time.monotonic() - t0, 2)
        while time.monotonic() - t0 < 60:
            try:
                if Panel(a.domain).req('/api/v1/health')[0] == 200: break
            except Exception: pass
            time.sleep(0.05)
        starts.append((acc, round(time.monotonic() - t0, 2)))
        time.sleep(max(0, 2.5 - (time.monotonic() - t0)))
    res['cold_start_s'] = {'samples_accept_then_first_https_200': starts, 'median_accept': statistics.median(x[0] for x in starts), 'median_first_https_200': statistics.median(x[1] for x in starts)}

    p = Panel(a.domain); p.login('admin', boot)
    pw = 'Perf-' + base64.urlsafe_b64encode(os.urandom(15)).decode()
    s, _, b = p.api('auth/change-password', {'old': boot, 'password': pw}); p.csrf = b.get('csrf')
    s, _, _ = p.api('dashboard'); landing = 'dashboard' if s == 200 else 'system/status'
    res['landing_route'] = landing
    db0 = (ct.root / 'var/lib/sbox-webui/panel.db').stat().st_size

    # 2. Idle.
    pp = pids(ct); samples = []
    first = {k: proc(ct, pp[k]) for k in ('sbox-webui', 'sbox-webui-control')}; t0 = time.monotonic()
    while time.monotonic() - t0 < a.idle:
        time.sleep(5); samples.append(sum(proc(ct, pp[k])['rss_kib'] for k in ('sbox-webui', 'sbox-webui-control')))
    last = {k: proc(ct, pp[k]) for k in ('sbox-webui', 'sbox-webui-control')}; span = time.monotonic() - t0
    cpu = sum(last[k]['cpu_ticks'] - first[k]['cpu_ticks'] for k in last) / TICK / span * 100
    res['idle'] = {'seconds': round(span), 'panel_plus_bridge_rss_mib_peak': round(max(samples) / 1024, 2), 'panel_rss_mib': round(last['sbox-webui']['rss_kib'] / 1024, 2),
                   'bridge_rss_mib': round(last['sbox-webui-control']['rss_kib'] / 1024, 2), 'avg_cpu_percent_of_one_cpu': round(cpu, 3),
                   'panel_threads': last['sbox-webui']['threads'], 'panel_fds': last['sbox-webui']['fds'], 'bridge_fds': last['sbox-webui-control']['fds'],
                   'pids_stable': pids(ct) == pp}

    # 3. Burst: 10 clients x 60 requests (landing, status, traffic, audit rotating).
    # Sign in again: the panel ends sessions after 30 minutes idle by design.
    p = Panel(a.domain); p.login('admin', pw)
    # The panel allows 600 requests per minute per client; start the 600-request burst in a fresh minute window.
    time.sleep(60 - time.time() % 60 + 0.5)
    routes = [landing, 'system/status', 'traffic', 'audit']
    lat = {r: [] for r in routes}; errors = []; lock = threading.Lock(); peak = [0]
    def worker(n):
        c = Panel(a.domain); c.cookie, c.csrf = p.cookie, p.csrf
        for i in range(60):
            r = routes[(n + i) % len(routes)]; t = time.monotonic()
            try: st = c.api(r)[0]
            except Exception as e: st = repr(e)[:80]
            ms = (time.monotonic() - t) * 1000
            with lock:
                lat[r].append(ms)
                if st != 200: errors.append(str(st))
    stop = threading.Event()
    def sampler():
        while not stop.is_set():
            try: peak[0] = max(peak[0], sum(proc(ct, pp[k])['rss_kib'] for k in ('sbox-webui', 'sbox-webui-control')))
            except Exception: pass
            time.sleep(0.5)
    th = threading.Thread(target=sampler); th.start()
    t0 = time.monotonic(); ws = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
    [w.start() for w in ws]; [w.join() for w in ws]; wall = time.monotonic() - t0; stop.set(); th.join()
    allv = [v for vs in lat.values() for v in vs]
    res['burst'] = {'requests': len(allv), 'errors': len(errors), 'error_samples': sorted(set(errors))[:5], 'wall_s': round(wall, 2), 'rps': round(len(allv) / wall, 1),
                    'p50_ms': pct(allv, 50), 'p95_ms': pct(allv, 95), 'max_ms': round(max(allv), 1),
                    'per_route_p50_p95_ms': {r: [pct(v, 50), pct(v, 95)] for r, v in lat.items()}, 'peak_rss_mib': round(peak[0] / 1024, 2)}
    res['panel_db_growth_bytes'] = (ct.root / 'var/lib/sbox-webui/panel.db').stat().st_size - db0
    res['vpn_core_pid_unchanged'] = pids(ct)['sing-box'] == core0
    a.out.parent.mkdir(parents=True, exist_ok=True); a.out.write_text(json.dumps(res, indent=1))
    print(json.dumps(res))


if __name__ == '__main__':
    main()
