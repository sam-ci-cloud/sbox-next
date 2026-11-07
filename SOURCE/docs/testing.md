# Testing

Different checks answer different questions. None is a substitute for every other layer.

## Source and regression checks

```bash
python3 tools/check_project.py --verify-build
python3 tools/test_check_docs.py
python3 tools/test.py
```

The runner builds the embedded manager and exercises isolated authentication, authorization, accounting, history, quota, recovery, concurrent-request and installer suites. It requires actual unittest output or the explicitly reviewed archive assertion report; exit code zero alone is not enough. Empty suites, malformed reports and timeouts fail. Skipped methods are not counted as executed checks. Interrupted runs retain an incomplete report rather than a previous successful result.

Results are written under `.build/test-results/` as per-suite logs plus `results.json` and `summary.json`. The summary distinguishes discovered methods, skipped methods, script assertions and executed checks. It is not a count of end-user features. Review every skipped or environment-dependent case before release. Never change a test to conceal a missing system capability.

## Browser fixtures

Install the pinned development dependencies as described in [development](development.md), then run:

```bash
npm run test:browser
```

These tests exercise actual production CSS and JavaScript in Chromium using labelled synthetic data. They cover menu positioning, chart tooltips/focus, dialog layering and text reflow across 320, 360, 375, 390, 414, 600, 640, 768, 1024, 1280, 1440 and 1920 CSS-pixel widths. The auditor also has deliberately broken overflow, contrast, accessible-name and runtime-error fixtures; those cases must fail the auditor itself. A healthy fixture must pass.

Fixtures do not verify real authentication, every page state, mobile hardware, VPN traffic or firewall enforcement. CI retains short-lived synthetic regression outputs; private live-campaign reports do not belong in the public repository.

### Layout matrix and chart truth

```bash
node shared_webui/tests/test_layout_matrix_browser.cjs OUTDIR        # full matrix
node shared_webui/tests/test_layout_matrix_browser.cjs OUTDIR --quick
node shared_webui/tests/test_chart_truth.cjs
```

The layout matrix starts the real panel with the labelled fixture bridge and audits admin and portal pages at 320–2560 CSS pixels (16 widths), in English and Traditional Chinese, light/dark/system themes and 125–200% text. States include dialogs, the plan form with every section, the time-zone list with all/many/some/one/no matches, action menus, the password form and chart tooltips. The geometry audit (`layout_audit.cjs`) checks document overflow, controls outside the viewport, pairwise overlap of interactive controls, hit testing at each control's visible centre, clipping by overflow-hidden ancestors, accessible names and overlays inside the viewport. It also asserts full-width use, the preset set, exact byte previews, the complete time-zone list and its search, the labelled fallback and password confirmation. Negative controls inject an overlapping control, horizontal overflow, an unnamed and a clipped control, a full-page cover, the old 1360px cap and a 15-result time-zone cap; each must be detected.

### Universal REALITY handshake target

```bash
python3 tests/test_reality_fallback.py
sudo python3 shared_webui/tests/lab_reality_fallback.py OUTDIR --browser
```

The unit suite covers the state model (old state = remote and byte-identical rendering, self-hosted loopback target and owner SNI, invalid states), real manager functions with stubbed `systemctl`/`ss` (non-interactive and interactive choice, port conflicts, trusted-certificate requirement and clean cancellation, unit hardening with `systemd-analyze verify`, bundle integrity, owned-unit sync, activation, renewal restart and visible failure, doctor output, rollback/uninstall hooks), the website (pages, MIME types, HEAD, 404/405/413/414/421, traversal, dotfiles, symlink escapes, no listings, headers, loopback-only bind, bounded concurrency, health check) and the ZgoCloud boundary. The lab runs inside a new network and mount namespace with only loopback, a throw-away lab CA and the pinned core; it proves ordinary TLS reaches the Personal Cloud site (or the lab remote target) through the REALITY port, an authenticated client built from the exported profile still proxies traffic, and a wrong key does not. None of this is live VPS or public-network acceptance.

### Disposable systemd lab machines (Docker)

```bash
bash tools/lab/docker_lab.sh image ubuntu-24.04      # also ubuntu-26.04, ubuntu-26.10, debian-12
ip=$(bash tools/lab/docker_lab.sh new lab1 ubuntu-24.04 /path/to/lab-ca-dir)
docker cp SING-BOX.tar.gz lab1:/root/ && docker exec lab1 bash -c 'cd /root && tar -xzf SING-BOX.tar.gz && cd SING-BOX && bash install.sh install generic --yes ...'
docker cp tools/lab/protocol_traffic.py lab1:/root/ && docker exec lab1 python3 /root/protocol_traffic.py /root/out --ca /root/lab/ca.crt --accounting
docker cp tools/lab/f2b_netns.sh lab1:/root/ && docker exec lab1 bash /root/f2b_netns.sh
```

ACME is exercised against a local Pebble CA (`apt-get install pebble`) with `server = https://127.0.0.1:14000/dir` in the lab machine's `/etc/letsencrypt/cli.ini`: real Certbot HTTP-01 issuance, `sbox renew-test`, forced renewal and the deploy hook. Public Let's Encrypt and public DNS remain owner-side checks.

### Disposable systemd lab machines (namespace harness)

```bash
bash tools/lab/make_lab.sh stonking noble
bash tools/lab/campaign.sh "$PWD/install.sh" /path/to/previous/install.sh s_fresh s_feature_rollback s_crash_recover s_uninstall s_install_rollback s_upgrade_from_published
bash tools/lab/f2b_live.sh c1
bash tools/lab/traffic_acct.sh c1
```

[`tools/lab`](../tools/lab/README.md) boots Ubuntu 26.10 / 24.04 root filesystems with real systemd as PID 1 and runs the standalone installer: fresh install with the self-hosted Personal Cloud, injected-failure rollback of an install and of a matching upgrade, SIGKILL in the middle of a transaction followed by `sbox recover`, upgrade from an archived prior installer, switching the REALITY target both ways, uninstall and reinstall. A separate network namespace sends real sshd login failures (Fail2Ban ban, all-port drop, unban, expiry) and real VLESS REALITY traffic (byte-exact delivery, per-user accounting, quota block and reset, wrong-key refusal). It is root-only lab evidence, not a public-network or VPS result.

## Real authenticated UI audit

Use a test account and an authorized disposable deployment. Supply its password through `SBOX_AUDIT_PASSWORD`, not a committed file or secret-valued command argument:

```bash
node shared_webui/tests/ui_audit.cjs https://your-test-domain:9443 /private/ui-audit review --full
```

This auditor checks real page readiness, overflow, contrast, control sizes, accessible names and browser errors. Detected defects produce a nonzero exit. TLS verification and the supplied hostname are respected by default. `--map-loopback`, `--fixture-insecure-tls` and `--fixture-html` are explicit local-fixture options, not live acceptance evidence.

Audit dialogs, menus, validation errors, long translated content and data states separately. Inspect screenshots and compare chart/API/CSV/database totals; aggregate geometry checks alone can miss overlapping controls or semantic mistakes.

## Deployment and network acceptance

Use disposable supported Linux systems for root/systemd, permission, firewall, process inspection and lifecycle tests. Real protocol acceptance requires an independent client and authenticated traffic. Check every enabled transport, user isolation, quota blocking, trusted HTTPS, portal import/export, restart, full backup/restore and matching upgrades.

For Fail2Ban, establish a clean control connection, generate bounded failed logins from a second authorized host, observe the event/filter/jail/kernel rule, verify that the intended new connection is actually blocked, then verify timed and manual unban. Keep an independent management path available. Test that a spoofed forwarded-IP header cannot select the ban target. A filter parser test or green service status is not end-to-end proof.

Maintain a private feature-by-feature acceptance matrix with the exact revision, environment, steps, expected/observed behavior and evidence. Mark each case passed, failed, blocked, skipped or not run. Do not infer coverage from suite totals. Keep credentials, real configurations, screenshots, captures and recovery material private; public bug reports need only redacted reproduction steps.
