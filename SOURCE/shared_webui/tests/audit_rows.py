#!/usr/bin/env python3
"""Turn ui_audit.cjs output into pass/fail rows (and compare with a baseline audit).

  audit_rows.py AUDIT.json OUT.json [--baseline BASELINE.json]
"""
import json, sys


def summarize(d):
    runs = d['runs']
    by = lambda pred: [r for r in runs if pred(r)]
    out = {}
    for theme in ('dark', 'light'):
        rs = by(lambda r: r['theme'] == theme)
        fails = [f for r in rs for f in r['contrastFails']]
        out['contrast_' + theme] = {'runs': len(rs), 'text_elements_checked': sum(r['contrastChecked'] for r in rs), 'failures': len(fails),
                                    'lowest_ratio': min((f.get('ratio') for f in fails if f.get('ratio')), default=None), 'examples': fails[:3]}
    t24 = [i for r in runs for i in r['targetIssues'] if i['kind'] == 'below-24px']
    t44 = [i for r in runs for i in r['targetIssues'] if i['kind'] == 'mobile-below-44px']
    out['targets'] = {'checked': sum(r['targetsChecked'] for r in runs), 'below_24': len(t24), 'mobile_below_44': len(t44), 'examples_24': t24[:3], 'examples_44': t44[:3]}
    out['overflow_runs'] = len(by(lambda r: r['overflow'].get('over')))
    out['ax_missing'] = sum(len(r['ax']['missing']) for r in runs if r.get('ax'))
    out['runs'] = len(runs); out['widths'] = sorted({r['width'] for r in runs}); out['pages'] = sorted({r['page'] for r in runs}); out['langs'] = sorted({r['lang'] for r in runs})
    return out


def main():
    a = json.load(open(sys.argv[1])); s = summarize(a)
    base = None
    if '--baseline' in sys.argv: base = summarize(json.load(open(sys.argv[sys.argv.index('--baseline') + 1])))
    row = lambda i, n, ok, ev: {'id': i, 'name': n, 'status': 'PASS' if ok else 'FAIL', 'evidence': ev}
    rows = [
        row('CONTRAST-DARK', 'Dark theme: every visible text element meets WCAG AA (4.5:1, 3:1 large)', s['contrast_dark']['failures'] == 0, s['contrast_dark']),
        row('CONTRAST-LIGHT', 'Light theme: every visible text element meets WCAG AA', s['contrast_light']['failures'] == 0, s['contrast_light']),
        row('TARGETS-24', 'Every non-inline interactive target is at least 24x24 px (WCAG 2.2 2.5.8)', s['targets']['below_24'] == 0, s['targets']),
        row('TARGETS-44-MOBILE', 'Phone widths: main controls at least 44 px tall', s['targets']['mobile_below_44'] == 0, s['targets']),
        row('NO-OVERFLOW', 'No horizontal overflow at any audited width', s['overflow_runs'] == 0, {'overflow_runs': s['overflow_runs'], 'widths': s['widths']}),
        row('AX-NAMES', 'Every interactive control has an accessible name', s['ax_missing'] == 0, {'missing': s['ax_missing']}),
    ]
    json.dump({'summary': s, 'baseline_summary': base, 'rows': rows}, open(sys.argv[2], 'w'), indent=1)
    for r in rows: print(r['status'], r['id'])


if __name__ == '__main__':
    main()
