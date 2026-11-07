#!/usr/bin/env python3
"""Run isolated suites and reject empty or unverified success reports."""
from pathlib import Path
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def assess_output(suite, code, output):
    """A zero process exit alone is not proof that assertions executed."""
    row = {'status': 'failed', 'unittest_methods': 0, 'skipped': 0,
           'script_checks': 0, 'executed_checks': 0, 'reason': ''}
    ran = re.findall(r'^Ran (\d+) tests? in [\d.]+s\s*$', output, re.M)
    ok = re.findall(r'^OK(?: \(skipped=(\d+)\))?\s*$', output, re.M)
    if ran:
        row['unittest_methods'] = int(ran[-1])
        row['skipped'] = int(ok[-1] or 0) if ok else 0
        row['executed_checks'] = max(0, row['unittest_methods'] - row['skipped'])
    if code != 0:
        row['reason'] = 'Process failed or timed out'
        return row
    if suite == 'tests/test_assets.py':
        # This reviewed adversarial archive script emits structured assertions,
        # not unittest output. No other zero-test script is implicitly accepted.
        try:
            report = json.loads(output)
            checks = report['results']
            valid = (re.fullmatch(r'[0-9a-f]{64}', report['runtime_sha256']) and
                     isinstance(checks, list) and len(checks) == 8 and
                     all(isinstance(c, dict) and c.get('test') and c.get('status') == 'PASS' for c in checks) and
                     len({c['test'] for c in checks}) == len(checks))
            if valid:
                row.update(status='passed', script_checks=len(checks), executed_checks=len(checks))
                return row
        except (ValueError, TypeError, KeyError):
            pass
        row['reason'] = 'Missing or invalid archive assertion report'
        return row
    if len(ran) != 1 or len(ok) != 1 or int(ran[0]) == 0 or re.search(r'^FAILED\b', output, re.M):
        row['reason'] = 'Missing, empty or unsuccessful unittest report'
        return row
    if row['skipped'] > row['unittest_methods']:
        row['reason'] = 'Invalid skipped-test count'
        return row
    row['status'] = 'passed' if row['executed_checks'] else 'skipped'
    if row['status'] == 'skipped':
        row['reason'] = 'All discovered methods were skipped; not a pass'
    return row


def run_process(args, env, timeout=180):
    process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True,
                               errors='replace', start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        return process.returncode, output
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        # Stop descendants as well as the parent, including test HTTP servers.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = process.communicate()
        if isinstance(error, KeyboardInterrupt):
            raise
        return 124, output + f'\nTIMEOUT after {timeout} seconds\n'


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def summarize(results, complete=False):
    failed = sum(r['status'] == 'failed' for r in results)
    checks = sum(r['executed_checks'] for r in results)
    return {'status': ('failed' if failed or not checks else 'passed') if complete else 'running',
            'complete': complete, 'suites': len(results), 'failed_suites': failed,
            'skipped_suites': sum(r['status'] == 'skipped' for r in results),
            'unittest_methods': sum(r['unittest_methods'] for r in results),
            'skipped': sum(r['skipped'] for r in results),
            'script_checks': sum(r['script_checks'] for r in results),
            'executed_checks': checks}


def select_suites(requested=None):
    paths = sorted((ROOT / 'shared_webui/tests').glob('test_*.py')) + sorted((ROOT / 'tests').glob('test_*.py'))
    if not requested:
        return paths
    selected = set()
    for selector in requested:
        matches = [p for p in paths if selector in (p.stem, p.name, p.relative_to(ROOT).as_posix())]
        if not matches:
            raise ValueError('Unknown suite: ' + selector)
        selected.update(matches)
    return [p for p in paths if p in selected]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', action='append', help='Exact suite stem, filename or relative path; repeatable')
    parser.add_argument('--list', action='store_true', help='List selected suites without building or executing')
    parser.add_argument('--skip-build', action='store_true', help='Reuse an explicitly prepared .build directory')
    parser.add_argument('--timeout', type=float, default=180, help='Bound each suite, in seconds')
    parser.add_argument('--fail-fast', action='store_true')
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 3600:
        parser.error('--timeout must be greater than zero and at most 3600 seconds')
    return args


def require_build(path):
    if not (path / 'src/manager.sh').is_file():
        raise RuntimeError('--skip-build requires a prepared .build/src/manager.sh; run tools/build.py first')


def main(argv=None):
    options = parse_args(argv)
    paths = select_suites(options.suite)
    if options.list:
        for path in paths:
            print(path.relative_to(ROOT).as_posix())
        return 0
    logs = Path(os.environ.get('SBOX_TEST_RESULTS_DIR', ROOT / '.build/test-results')).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    write_json(logs / 'results.json', results)
    write_json(logs / 'summary.json', summarize(results))
    try:
        if options.skip_build:
            require_build(ROOT / '.build')
        else:
            subprocess.run([sys.executable, str(ROOT / 'tools/build.py')], check=True)
        env = {**os.environ, 'SBOX_MANAGER_ROOT': str(ROOT / '.build'),
               'SBOX_TEST_SOURCE': str(ROOT / '.build'), 'PYTHONDONTWRITEBYTECODE': '1'}
        if not paths:
            raise RuntimeError('No regression suites discovered')
        for path in paths:
            suite = path.relative_to(ROOT).as_posix()
            args = [sys.executable, str(path)]
            # This suite tests real owner/mode transitions on disposable paths.
            # Normal suites keep their non-root coverage; CI opts in explicitly
            # to running only this privilege-requiring suite with sudo.
            if (path.name == 'test_reality_fallback.py' and
                    env.get('SBOX_CI_PRIVILEGED_TESTS') == '1' and os.geteuid() != 0):
                args = ['sudo', '-n', '-E', '--', *args]
            if path.name in ('test_policy_quota.py', 'test_cli_security.py', 'test_udp_ownership.py'):
                args.append(str(ROOT / '.build'))
            start = time.monotonic()
            code, output = run_process(args, env, options.timeout)
            (logs / (path.stem + '.log')).write_text(output)
            row = {'suite': suite, 'returncode': code, 'seconds': round(time.monotonic() - start, 3),
                   **assess_output(suite, code, output)}
            results.append(row)
            write_json(logs / 'results.json', results)
            write_json(logs / 'summary.json', summarize(results))
            if row['status'] == 'failed':
                print('Failure output for ' + suite + ' (last 16000 characters):', flush=True)
                print(output[-16000:], flush=True)
            print(json.dumps(row), flush=True)
            if options.fail_fast and row['status'] == 'failed':
                break
    except (Exception, KeyboardInterrupt) as error:
        summary = summarize(results)
        summary.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', error=type(error).__name__)
        write_json(logs / 'summary.json', summary)
        print(json.dumps(summary), flush=True)
        return 1
    summary = summarize(results, complete=True)
    write_json(logs / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    sys.exit(main())
