#!/usr/bin/env python3
"""Panel server resources with 1000 users (real panel server and store; FIXTURE bridge data).

  perf_users.py OUT.json
Starts tests/dev_panel.py with --users 1000, signs in, requests the users list 40 times
(plus filtered/paged variants used by the UI) and samples the panel process RSS.
"""
import http.client, json, os, re, signal, ssl, statistics, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def rss(pid):
    return int(re.search(r'VmRSS:\s+(\d+)', Path('/proc/%d/status' % pid).read_text())[1])


def main():
    out = Path(sys.argv[1]); work = Path(tempfile.mkdtemp())
    p = subprocess.Popen([sys.executable, str(HERE / 'dev_panel.py'), '--variant', 'universal', '--users', '1000', '--port', '19555', '--work', str(work)],
                         stdout=open(work / 'panel.json', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    try:
        for _ in range(100):
            time.sleep(0.2)
            try: info = json.loads((work / 'panel.json').read_text().splitlines()[0]); break
            except (ValueError, IndexError): pass
        ctx = ssl._create_unverified_context()
        def req(path, body=None, h=None):
            c = http.client.HTTPSConnection('127.0.0.1', 19555, context=ctx, timeout=60)
            hh = {'Host': 'panel.sbox.test:19555', **(h or {})}
            if body is not None: hh['Content-Type'] = 'application/json'
            c.request('POST' if body is not None else 'GET', path, json.dumps(body) if body is not None else None, hh)
            r = c.getresponse(); d = r.read(); hd = dict(r.getheaders()); c.close(); return r.status, hd, d
        s, h, d = req('/api/v1/auth/login', {'username': 'admin', 'password': info['password']})
        auth = {'Cookie': h['Set-Cookie'].split(';')[0]}
        rss0 = rss(info['pid']); lat, sizes = [], []
        for i in range(40):
            t = time.monotonic(); s, _, d = req('/api/v1/users', h=auth); lat.append((time.monotonic() - t) * 1000); sizes.append(len(d))
            assert s == 200, s
        body = json.loads(d); users = body.get('users', body) if isinstance(body, dict) else body
        rss1 = rss(info['pid'])
        res = {'label': 'FIXTURE data, real panel server/store', 'users_returned': len(users), 'requests': 40, 'p50_ms': round(statistics.median(lat), 1),
               'p95_ms': round(sorted(lat)[int(0.95 * len(lat)) - 1], 1), 'max_ms': round(max(lat), 1), 'payload_bytes': sizes[-1],
               'panel_rss_mib_before': round(rss0 / 1024, 1), 'panel_rss_mib_after': round(rss1 / 1024, 1), 'rss_growth_mib': round((rss1 - rss0) / 1024, 1),
               'note': 'The browser pages the list client-side (25/100 per page); see E2E USERS-PAGING-1000 for render/paging checks.'}
        out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(res, indent=1)); print(json.dumps(res))
    finally:
        os.killpg(p.pid, signal.SIGTERM)


if __name__ == '__main__':
    main()
