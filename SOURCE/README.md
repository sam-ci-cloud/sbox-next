# SBOX — editable corresponding source

1.8.0 is based on the 1.7.1 baseline. Each change below has a test that failed on 1.7.1 and passes now:

- sing-box JSON exports carry Smart Auto, LOCK and VPN groups.
- Owners choose the starting group (Anti-Block Auto by default, or Smart Auto).
- Health-check interval, probe timeout and failure trigger are configurable, and the WebUI shows the worst-case detection time.
- The requested fq qdisc is actually attached to network interfaces.
- Fresh installs recommend dual stack when a working public IPv6 is detected.
- An optional default-drop inbound firewall gate, enabled through a dead-man trial.
- Opt-in UDP egress controls for providers that filter UDP replies.

The 565bbe security core is unchanged and was not rebuilt. See [protocols](docs/protocols.md), [network policies](docs/network-modes.md) and [security](docs/security.md).


**An all-in-one sing-box server deployment and management platform.**

[![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-blue)](LICENSE)

[繁體中文（香港）](docs/zh-HK.md) · [Get started](docs/getting-started.md) · [Documentation](docs/README.md) · [Contributing](CONTRIBUTING.md)

Deploy a complete VPN service from one self-contained Bash installer. SBOX brings the server, authenticated HTTPS console, management CLI, user portal, subscriptions, monitoring and real per-user accounting into one maintained project.

## What SBOX provides

| Area | Included |
| --- | --- |
| VPN transports | VLESS REALITY + Vision, VMess WebSocket + TLS, Hysteria2, TUIC v5 and AnyTLS |
| Administration | HTTPS console on **9443**, guided user creation, user details, CLI, MFA, light/dark/system and English/繁體中文 |
| Usage and plans | Guided quota and local expiry forms, 24h/7d/30d/90d/custom usage history, daily/weekly/monthly plans and top-ups |
| Operations | Certificate renewal, monitoring and alerts, scoped Fail2Ban, backups, in-place upgrades and transaction recovery |
| Clients | sing-box and Mihomo exports; Anti-Block Auto, Smart Auto and LOCK policies |

Hysteria2 supports configurable UDP hopping. Client policies select transports for new connections; they do not migrate established sessions. See [protocols and client behavior](docs/protocols.md).

## Public Bash install

```bash
curl -fsSL https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh | sudo bash
```

The public bootstrap downloads the pinned content-addressed release from singbox, checks its SHA-256 and uses /dev/tty for guided input. See [publication status](docs/PUBLICATION_STATUS.md) for runtime provenance and current publication scope.

## Quick start

Copy `SING-BOX.tar.gz` to the VPS and run, as root:

```bash
cd /root
tar -xzf SING-BOX.tar.gz
cd /root/SING-BOX
bash install.sh
```

`install.sh` verifies every file against `SHA256SUMS`, runs a read-only preflight of the host and then starts the menu: fresh Universal or ZgoCloud install, upgrade with automatic backup, recovery, rollback and read-only verification. `bash install.sh preflight generic` is a dry run that changes nothing.

Before installation, point your domain at the VPS, prepare a trusted certificate or ACME validation, and allow the selected VPN ports plus HTTPS **9443** in the provider firewall. HTTP-01 validation also needs TCP 80. The WebUI accepts any source IP, subject to authentication, rate limits and temporary security bans.

[Installation and local checksum instructions →](docs/installation.md)

The transferred TAR installs without GitHub. Its application and patched accounting core are embedded. A separate public URL installer downloads that same complete TAR from the [SBOX repository](https://github.com/sam-ci-cloud/sbox-next), checks a digest embedded in the bootstrap, validates the archive and runs the local installer. It needs no login, git or access token.

The core is not frozen: `sbox update latest` discovers upstream stable Go modules, rejects incompatible patches, builds with authenticated module checksums and runs the accounting tests before a transactional update. Exact versions and the preview channel are selectable; incompatible updates keep the running core. See [compatible core updates](docs/core-compatibility.md). Distribution packages, ACME, DNS and time synchronization use normal Internet access.

Historical Claude **1.2.0/1.2.1** evidence used patched sing-box **1.14.4**. That campaign was validated on its then-authorized Ubuntu 26.10 VPS: same-host before/after benchmarks of all five transports, an in-place upgrade from 1.1.4 and an isolated protected ZgoCloud simulation (private test CA, hostname override and an egress guard; the production hostname and server were never contacted). The release evidence lists passed, failed, blocked and unrun cases, including public IPv6, which these hosts could not provide.

Unified **1.3.0** retains that exact patched core and selectively adds TCP_NODELAY, pressure diagnostics, truthful accounting health, explicit safe retention, OS maintenance visibility and protected performance controls. Current scoped evidence and historical limits are distinguished in [integration decisions](docs/unified-integration.md) and the public release compatibility report.

## Personal dashboard

Users sign in at `/portal` to view their own usage and plan, retrieve the same active subscription on future visits, copy a link, show a local QR or download YAML/JSON/protocol links. Repeated viewing does not rotate credentials. Administrators can revisit the same connection details. Older hash-only links stay valid and require explicit replacement before they can be shown again.

## Choose a deployment

| | Universal SBOX | ZgoCloud |
| --- | --- | --- |
| Intended use | A configurable deployment for your own server | An owner-authorized deployment compatible with the original six-node client identity |
| Setup | Guided network, protocol and certificate choices | Preserves protected credentials, fixed ports, SNI and UDP ranges |
| Unlock | None | Separately held private passphrase, entered without echo |
| Administration | Full CLI, WebUI, quotas, portal and monitoring | The same common application, with protected identity constraints |
| REALITY handshake target | Remote website (default) or [self-hosted SBOX Personal Cloud](docs/reality-fallback.md) with your own trusted certificate | Original protected configuration |

An upgrade retains the installed product. Switching products on an existing installation is refused. [ZgoCloud handling](docs/installation.md#zgocloud) explains the private boundary.

## Supported systems

All supported deployments require **Linux amd64 / x86-64, systemd and root access**.

| System | Universal | ZgoCloud |
| --- | --- | --- |
| Ubuntu 24.04 | Supported | Supported |
| Ubuntu 26.04 | Supported | Supported |
| Ubuntu 26.10 | Supported | Supported (1.2.0+) |
| Debian 12 | Supported | — |

ARM64 and other distributions are refused by this installer. A domain and trusted TLS are required for the public WebUI. [Requirements and platform coverage](docs/installation.md#requirements) distinguish pristine-image and public-VPS tests.

## Everyday operations

```bash
sbox status
sbox doctor
sbox webui doctor
sbox quota show
sbox client-policy show
sbox backup
```

Open the console at `https://your-domain:9443`. Retrieve the initial administrator credentials locally from `/etc/sbox-webui/bootstrap-admin.txt`, change the initial password and enroll MFA. Portal accounts are separate from administrator and VPN credentials.

[CLI reference](docs/cli-reference.md) · [WebUI and portal](docs/webui.md) · [Upgrade and recovery](docs/upgrades-and-recovery.md)

## Documentation

| Start and configure | Operate and maintain |
| --- | --- |
| [Getting started](docs/getting-started.md) | [Users, accounting and quotas](docs/users-and-quotas.md) |
| [Installation](docs/installation.md) | [Certificates](docs/certificates.md) |
| [Configuration](docs/configuration.md) | [Security](docs/security.md) |
| [Protocols and client policies](docs/protocols.md) | [Upgrades and recovery](docs/upgrades-and-recovery.md) |
| [WebUI, portal and subscriptions](docs/webui.md) | [Troubleshooting](docs/troubleshooting.md) |

Developers: [architecture](docs/architecture.md), [building](docs/development.md), [testing](docs/testing.md) and [release process](docs/releasing.md).

## Development

```bash
python3 tools/build.py
python3 tools/check_project.py
python3 tools/test.py
```

The ordinary build is offline and deterministic from committed source and the existing sealed asset. Frontend assembly needs no npm packages. Updating protected ZgoCloud content requires a separate private owner reseal; bundling the existing envelope does not. [Development setup](docs/development.md) lists test dependencies and source boundaries.

## Limits and compatibility

Quotas use authenticated payload counters and polling, so enforcement can overshoot. Plan-cycle totals and selected historical dates are separate. New installations cannot display history from before collection began; gaps remain visible. The original shared identity is metered as one aggregate.

Configuration changes can restart the core and interrupt established streams. Client compatibility varies by protocol. Public IPv6 and physical mobile/ISP paths need testing on your own deployment; no censorship-resistance or throughput guarantee is made. See [troubleshooting](docs/troubleshooting.md) and [upgrade guidance](docs/upgrades-and-recovery.md).

## Security, support and licensing

Treat the installer as privileged software: review or pin a trusted revision, keep root-only backups private, and use trusted TLS. Never publish profiles, subscription URLs, unlocks, private keys or database snapshots. Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

For reproducible bugs and improvements, use the contribution guide and the local test/evidence workflow in the delivery. No hosted issue tracker or response-time commitment is provided.

SBOX Next is distributed under the [GNU GPL v3 license](LICENSE). The patched sing-box core, its patch and build inputs are included in this repository under [core-source/](core-source/README.md), with upstream licensing and attribution in [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_LICENSES/README.md). The source archive includes these materials alongside the installer. SBOX is an independent project and is not endorsed by upstream sing-box.

NEXT 1.4.0 adds clear device connection actions and IPv6-capable client DNS. Managers and WebUI use 1.4.0; the patched core remains unchanged. The installer/TTY fix from 1.3.1 is preserved. See [terminal fix](docs/TERMINAL_FIX.md).
