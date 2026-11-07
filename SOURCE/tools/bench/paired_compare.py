#!/usr/bin/env python3
"""Paired same-host comparison of two client_bench.py sample sets.

usage: paired_compare.py BASELINE/samples.csv CANDIDATE/samples.csv --out paired_compare.csv

For every (protocol, test) present in both sets: sample counts, pass counts,
median/p95/p99 of TTFB (latency tests) or median throughput (transfer tests),
the relative change and a 95% bootstrap confidence interval for the change of
the median (2000 resamples, fixed seed). Lower latency and higher throughput
are improvements; the verdict column applies the methodology thresholds
(investigate >5% regressions, reject >10%) only where the CI excludes zero.
"""
import argparse
import csv
import random
import statistics

LATENCY = 'ttfb_ms'
THROUGHPUT = 'throughput_mbps'


def load(path):
    rows = {}
    for r in csv.DictReader(open(path)):
        rows.setdefault((r['protocol'], r['test']), []).append(r)
    return rows


def pct(v, p):
    s = sorted(v)
    if not s:
        return None
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def boot(a, b, rng, n=2000):
    diffs = []
    for _ in range(n):
        ra = [rng.choice(a) for _ in a]
        rb = [rng.choice(b) for _ in b]
        diffs.append(statistics.median(rb) - statistics.median(ra))
    return pct(diffs, 2.5), pct(diffs, 97.5)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('baseline')
    ap.add_argument('candidate')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    base, cand = load(a.baseline), load(a.candidate)
    rng = random.Random(20261102)
    cols = ['protocol', 'test', 'metric', 'n_base', 'n_cand', 'pass_base', 'pass_cand', 'base_median', 'cand_median',
            'base_p95', 'cand_p95', 'base_p99', 'cand_p99', 'delta_median_pct', 'ci95_low', 'ci95_high', 'verdict']
    out = []
    for key in sorted(set(base) & set(cand)):
        b, c = base[key], cand[key]
        metric = THROUGHPUT if any(r[THROUGHPUT] for r in b) else LATENCY
        bv = [float(r[metric]) for r in b if r[metric] and r['status'] == 'PASS']
        cv = [float(r[metric]) for r in c if r[metric] and r['status'] == 'PASS']
        row = {'protocol': key[0], 'test': key[1], 'metric': metric, 'n_base': len(b), 'n_cand': len(c),
               'pass_base': sum(r['status'] == 'PASS' for r in b), 'pass_cand': sum(r['status'] == 'PASS' for r in c)}
        if len(bv) >= 2 and len(cv) >= 2:
            mb, mc = statistics.median(bv), statistics.median(cv)
            lo, hi = boot(bv, cv, rng)
            delta = 100.0 * (mc - mb) / mb if mb else 0.0
            better = (mc < mb) if metric == LATENCY else (mc > mb)
            significant = not (lo <= 0 <= hi)
            worse_pct = -delta if metric == THROUGHPUT else delta
            if not significant:
                verdict = 'no significant change'
            elif better:
                verdict = 'improved'
            elif worse_pct > 10:
                verdict = 'REGRESSION >10% (reject unless justified)'
            elif worse_pct > 5:
                verdict = 'regression >5% (investigate)'
            else:
                verdict = 'minor regression <=5%'
            row.update(base_median=round(mb, 2), cand_median=round(mc, 2), base_p95=round(pct(bv, 95), 2),
                       cand_p95=round(pct(cv, 95), 2), base_p99=round(pct(bv, 99), 2), cand_p99=round(pct(cv, 99), 2),
                       delta_median_pct=round(delta, 2), ci95_low=round(lo, 2), ci95_high=round(hi, 2), verdict=verdict)
        elif row['pass_cand'] < row['pass_base']:
            row['verdict'] = 'FEWER PASSES'
        else:
            row['verdict'] = 'pass-count only'
        out.append(row)
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows(out)
    for r in out:
        print('%-8s %-24s %-15s n=%s/%s pass=%s/%s med %s -> %s (%s%%) CI[%s,%s] %s' % (
            r['protocol'], r['test'], r['metric'], r['n_base'], r['n_cand'], r['pass_base'], r['pass_cand'],
            r.get('base_median', ''), r.get('cand_median', ''), r.get('delta_median_pct', ''),
            r.get('ci95_low', ''), r.get('ci95_high', ''), r['verdict']))


if __name__ == '__main__':
    main()
