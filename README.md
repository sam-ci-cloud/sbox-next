# SBOX

[![Product verification](https://github.com/sam-ci-cloud/sbox-next/actions/workflows/publication.yml/badge.svg)](https://github.com/sam-ci-cloud/sbox-next/actions/workflows/publication.yml) [![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

SBOX manages a self-hosted VPN server on Linux: five protocols, client configuration exports, a bilingual HTTPS Web UI, traffic accounting, quotas and transactional recovery. It brings server configuration and day-to-day subscriber management together while keeping routing and DNS choices explicit.

This is a **pre-release candidate**. Read [validation and open limitations](VALIDATION.md) before deploying it. A successful CI run does not prove physical-device TUN behavior or every provider's network path.

## Requirements

- **Linux amd64 (x86_64)** with systemd, root access and working apt repositories.
- Universal installer: **Debian 12; Ubuntu 24.04, 26.04 or 26.10**. The protected variant supports the listed Ubuntu releases. ARM64 and unlisted operating systems are refused.
- At least **1 GiB free on `/`**, **300 MiB on `/tmp`**; **512 MiB RAM recommended**. Preflight checks the actual environment.
- A domain and trusted TLS certificate for a public Web UI. Point its A/AAAA records at the intended server and allow the selected ports in the provider firewall.

See the full [installation requirements](SOURCE/docs/installation.md#requirements) and [compatibility notes](COMPATIBILITY.md).

## Install and configure

From an interactive root/sudo SSH session on a supported server:

```bash
curl -fsSL https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh | sudo bash
```

Choose the Universal/Generic installation and follow the guided domain, certificate, protocol and network choices. The bootstrap downloads this repository's content-addressed release, verifies the **complete package SHA-256**, validates archive paths, then runs the local installer. There is no checksum bypass or fallback mirror.

For a reviewable download first:

```bash
curl -fsSL https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh -o sbox-install.sh
less sbox-install.sh
sudo bash sbox-install.sh install generic
```

Then inspect the installed state:

```bash
sudo sbox status
sudo sbox doctor
sudo sbox firewall ports
```

The installer reports the Web UI access details. The usual public endpoint is `https://your-domain:9443/`; it needs a trusted certificate and an inbound provider TCP rule for that port. Keep admin credentials and generated subscriber links private. See [Web UI setup and management](SOURCE/docs/webui.md), [configuration](SOURCE/docs/configuration.md), [unattended installation](SOURCE/examples/noninteractive.md) and [troubleshooting](SOURCE/docs/troubleshooting.md).

### Offline and IPv6-only bootstrap

The same fixed package hash is mandatory for a staged package:

```bash
sudo env SBOX_INSTALL_ARCHIVE=/absolute/path/SING-BOX.tar.gz bash sbox-install.sh install generic
```

Download the archive from [Releases](https://github.com/sam-ci-cloud/sbox-next/releases) and verify it against `PUBLIC_PAYLOAD.json` or the release `SHA256SUMS`. Native IPv6-only servers may need staged installation or an explicitly configured trusted transport to reach GitHub's release endpoints. SBOX does not create NAT64/DNS64. See [standalone installation](SOURCE/docs/installation.md).

## Protocols and network modes

| Protocol | Server transport |
| --- | --- |
| VLESS REALITY | REALITY / Vision |
| VMess | WebSocket + TLS |
| Hysteria2 | QUIC / UDP |
| TUIC | TUIC v5 / QUIC / UDP |
| AnyTLS | TLS |

IPv4-only, dual-stack and IPv6-only modes have separate listener, outbound, DNS and client-endpoint choices. Dual stack requires working connectivity on both families; a label or IPv4-only test does not establish IPv6 health. Domain endpoints also depend on usable DNS and client dialing policy. See [protocols](SOURCE/docs/protocols.md) and [network modes](SOURCE/docs/network-modes.md).

## Web UI and client exports

The authenticated Chinese/English Web UI manages users, plans, subscriptions, protocol settings and diagnostics. It displays traffic/accounting history with 1h, 6h, 24h, 7d, 30d and custom ranges. Keep native backups before administrative changes; quotas are periodic access limits with possible overshoot, not exact byte-billing caps.

Client exports include persistent links/QR, Mihomo YAML and sing-box JSON. Choose an engine by its actual features:

| Capability | Mihomo YAML | sing-box JSON export |
| --- | --- | --- |
| Protocol nodes and selectors | Yes | Yes |
| Ordered Anti-Block fallback | Yes | No; documented Smart Auto/LOCK choices |
| GLOBAL / CN / INTERNAL profile routing and DNS | Included | Not a full equivalent |
| Complete physical-device TUN setup | Requires device-specific validation | Not provided by this local SOCKS export |

Do not silently treat `urltest` as ordered fallback. Device app versions and access-network DNS behavior need their own acceptance checks. See [compatibility](COMPATIBILITY.md) and [client/profile documentation](SOURCE/docs/protocols.md).

## Routing, DNS and security

SBOX exposes LAN/direct protection, custom rule ordering, geographic rules, profile modes and proxy selectors. Strict family policies make resolver transport, bootstrap and destination choices explicit. When private-destination blocking is enabled, domain resolution is part of the address check; sniffing alone is not an IP security boundary.

The product includes certificate management, Fail2Ban integration, scoped firewall rules, validated configuration changes and rollback. Host rules do not configure a provider security group. Read [network policies](SOURCE/docs/network-modes.md), [security controls](SOURCE/docs/security.md) and [the security policy](SECURITY.md). The known panel-rule drift and provider UDP limitations remain documented in [VALIDATION.md](VALIDATION.md).

## Maintain and recover

Use `sbox backup` and copy authenticated backups off the server privately. Follow [upgrade, restore and rollback instructions](SOURCE/docs/upgrades-and-recovery.md); a same-candidate upgrade test does not establish compatibility with every historical deployment. Never post databases, exported links, TLS keys or backups in public issues.

- [Installation and certificates](SOURCE/docs/installation.md)
- [Web UI](SOURCE/docs/webui.md) · [Configuration](SOURCE/docs/configuration.md)
- [Troubleshooting](SOURCE/docs/troubleshooting.md) · [Recovery](SOURCE/docs/upgrades-and-recovery.md)
- [Release notes](RELEASE_NOTES.md) · [Validation scope](VALIDATION.md)
- [Developer and dependency maintenance](DEPENDENCY_MAINTENANCE.md)

The pinned patched sing-box 1.14.4 core is unchanged. Corresponding source, licenses, SBOM and build instructions are included under `SOURCE/core-source/`. Publication does not rebuild that core or claim a new performance improvement. [LICENSE](LICENSE) and [NOTICE](NOTICE) preserve project and upstream obligations.

## 繁體中文快速開始

SBOX 適用於上述受支援嘅 Linux amd64 系統。準備好域名、TLS 憑證同供應商防火牆規則後，喺互動 SSH 終端執行上面嘅安裝指令，選擇 Universal/Generic，再跟精靈設定。完成後用 `sudo sbox status`、`sudo sbox doctor` 檢查，並按安裝輸出開啟 HTTPS 管理介面。

Mihomo YAML 同 sing-box JSON 功能並不完全相同；請先睇比較表。實體裝置 TUN／DNS leak、長時間穩定性同部分供應商 UDP 路徑仍有未完成驗收，唔應視為全面 Production Ready。私人交付 ZIP、owner key、伺服器密碼同備份唔屬於公開 repo 或 release。
