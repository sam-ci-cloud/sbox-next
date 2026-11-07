# Validation scope and open acceptance

The shipped package is pinned in `PUBLIC_PAYLOAD.json`. Release 1.8.1 changes the bundled core's dependency graph and the firewall reconciliation code; earlier server/network acceptance evidence applies only to the exact earlier code. The 1.8.1 lab acceptance below was run on this exact package. Public Actions runs validate the newly published source and packaging environment; they are separate from retained owner-only real-host evidence.

Previously executed acceptance covered two freshly installed VPS, native sing-box and Mihomo nodes across five protocols and IPv4/IPv6, strict-family cases, public HTTPS management, native backup/restore, certificate renewal checks, service/reboot recovery and scoped measurements. Each result applies only to its exact code/config/environment. Local isolated CI packets are not a physical-client WAN test. Detailed host fingerprints and operational records remain private.

| Open item | Status / limit |
| --- | --- |
| Provider UDP path | **NEEDS_PROVIDER**: one tested path drops incoming IPv4 UDP from client source ports below 10000. High-source-port and IPv6 success do not remove this limitation. |
| Physical client TUN and access-network DNS leakage | **BLOCKED_ENV**: no suitable connected physical-device/access-network acceptance environment. |
| Mainland-China ISP/split-horizon access-network behavior | **BLOCKED_ENV**: not validated from an authorized mainland access network. |
| Long soak, arbitrary-loss QUIC impairment and precise native handshake tails | **NOT_RUN**. Sparse application TTFB samples are not protocol handshake p99 or a stability guarantee. |
| Device IPv6 fake-IP behavior and live DHCP renewal | **NOT_RUN** in the relevant real-device/static-host environments. |
| Cross-version upgrade and rollback | **PASS (lab, 1.11.0)**: genuine 1.8.0, 1.8.1, 1.9.0, 1.9.1, 1.9.2 and 1.10.0 packages each upgraded to 1.11.0 with users, credentials, quota, tokens, served subscriptions and node identities unchanged; interrupted upgrade + recover and restore drills below. Destructive final uninstall remains **NOT_RUN**. |
| Management firewall drift | **PASS (lab, 1.11.0)**: `sbox firewall status` now checks the panel's own rule and fails when it is missing; a two-minute repair timer restored a foreign-removed panel rule in 58 s (IPv4+IPv6) with the panel reachable throughout; `ufw reload` no longer removes the rule. Reboot persistence of the timer itself was not separately exercised. |
| Automated Go version updates | Previously **FAIL** on the patched fork graph. This repository uses explicit controlled/manual Go updates, not a claim that the generic updater was repaired. See [maintenance policy](DEPENDENCY_MAINTENANCE.md). |
| Quotas | Periodic access limits can overshoot. They are not universal hard byte caps or exact billing counters. |
| sing-box JSON export | Complete profile (TUN, DNS, routing incl. offline CN rules, per-family and published-address node candidates) since 1.10.0/1.11.0; Mihomo's ordered first-healthy fallback and load-balance groups have no sing-box equivalent and are omitted. A rare TUN start-up stall (whole client egress for ~30 s, then self-recovery) was seen twice in ~160 lab cold starts; root cause not established. |
| Patched core rebuild | **PASS (build/scan scope)**: rebuilt three times byte-identically (including empty build and module caches); govulncheck binary and source call-graph scans and the declared-module advisory audit report zero findings. Protocol/accounting acceptance of the rebuilt core on real hosts is a separate gate. |

For the panel issue, inspect the actual configured port and both family rules plus every relevant nftables base chain. A listener or `sbox firewall status` alone is insufficient. The scoped recovery exercised was `systemctl restart sbox-webui-firewall.service` followed by `sbox firewall apply`; preserve SSH and unrelated policy and verify trusted HTTPS afterwards. This operational recovery is not a permanent source fix.

The release remains a **pre-release**. Neither successful publication nor green CI establishes full production readiness. Do not share owner archives, customer configurations, credentials or private evidence in public support requests.

## 1.11.0 lab acceptance

Three Vultr servers (Los Angeles, Tokyo, Singapore), all six directions, IPv4 and IPv6, Mihomo and sing-box
clients, exact 1.11.0 candidate package. Physical devices, home routers, multi-day soak, billing and mainland
ISP paths are out of scope by the owner.

| Check | Result |
| --- | --- |
| Hysteria2/TUIC with the preferred address family dead (both families, 2 reps) | 1.10.0-style single outbound 0/48; 1.11.0 per-family group 48/48 (p50 1.4-1.5 s, max 2.5 s); Mihomo 48/48 |
| Complete sing-box profile cold start in TUN, normal | 60/60 (p50 1.2-2.0 s) |
| Same, bootstrap resolver unreachable for 30 s | 18/18 connected via published-address candidates (max 5.7 s); 1.10.0 profile 0/4 |
| TUN global / internal / CN profiles | 18/18 profiles PASS; CN sites routed direct with CN resolver, other traffic via VPN, attached LAN reachable |
| VMess mux / AnyTLS A/B (silent NAT drop, parallel 8, idle) | settings kept; measured limits in `SOURCE/docs/performance-five-protocols.md` |
| Live panel (Tokyo, synthetic MFA administrator) | Export Center, QR decode, CN download, MFA login PASS (390 and 1440 px) |
| MFA through upgrade and through backup/restore | enforced before, after upgrade and after restore |
| Genuine upgrades 1.8.0 ... 1.10.0 -> 1.11.0 | 6/6 PASS on one server; 1.10.0 -> 1.11.0 PASS on the other two |
| `sbox restore --yes` | refuses with exit 1 and guidance; `--force` restores |

## 1.9.0 lab acceptance

Three fresh dual-stack Ubuntu 26.10 VPS (1 vCPU, 1 GiB) in three regions, each acting
as SBOX server and as client (official Mihomo v1.19.33 and sing-box 1.14.4). Every
directed path was tested (6 directions x 5 protocols x 2 client engines x IPv4/IPv6
server endpoints = 120 cells), each cell with verified-TLS HTTPS and UDP DNS to IPv4
and IPv6 destinations, egress identity checked at the target, interleaved order.
Times are normalized by the measured round-trip time of the same path and family.

| Matrix | 1.8.1 | 1.9.0 (VMess reuse on) |
| --- | --- | --- |
| Cells PASS | 120/120 | 120/120 |
| HTTPS (TLS verified, egress identity) | 1200/1200 | 1200/1200 |
| UDP DNS | 240/240 | 240/240 |
| VMess repeated request, median / p95 | 937 / 1660 ms | 610 / 1114 ms |
| VMess UDP relay (round trips) | 5.1 | 2.0 |
| VLESS, TUIC, Hysteria2, AnyTLS repeated request, median | 821, 614, 617, 616 ms | 826, 608, 609, 608 ms |

Parallel 4 x 4 MiB downloads through VMess: 68 -> 77-81 Mbit/s (short path) and
49 -> 53-57 Mbit/s (long path); no throughput regression from multiplexing.

| Upgrade / lifecycle check | Result |
| --- | --- |
| Genuine 1.8.1 -> 1.9.0 with users, quota and subscriptions (3 servers) | PASS: users, credentials, quota, subscription tokens and node definitions identical |
| Genuine 1.8.0 -> 1.9.0 (fresh 1.8.0 install, includes core replacement) | PASS: same checks; certificate source preserved |
| `sbox performance vmess-mux on` | PASS on 3 servers; server, CLI exports and all per-user subscriptions updated; links/QR unchanged |
| Forced rollback and re-upgrade | PASS; certificate renewal stays connected (renewal dry-run PASS) |
| Upgrade killed mid-flight, then `install.sh recover` | PASS after the 1.9.0 recovery fix; subscriptions return |
| Clients against servers with and without VMess reuse | PASS (mixed fleet) |

### Rejected after measurement

- Client TCP Fast Open: 12% faster on healthy paths, but Mihomo failed 10/10 requests when
  the server's IPv6 path was unreachable and sing-box failed 10/10 when IPv4 was
  unreachable (a lazy TFO connection defeats address-family fallback). Exports keep it off.
- Early data via the `?ed=` path in `vmess://` links: sing-box based clients send the path
  literally and fail (HTTP 404). Links stay unchanged; early data is in YAML/JSON only.

### Still open

Long soak, physical home/mobile clients and TUN on end-user devices, per-user quota
enforcement under live traffic, and IPv4/IPv6 endpoint-preference tuning for QUIC
protocols remain NOT_RUN for 1.9.0.

## 1.8.1 lab acceptance

Three disposable Ubuntu 26.10 VPS: two servers upgraded in place from 1.8.0 to this
package with the package's own `upgrade.sh`, and one Linux client. The same client
matrix ran before and after the upgrade with byte-identical client configurations:

| Check | Before (1.8.0) | After (1.8.1) |
| --- | --- | --- |
| Rows: 2 servers x 5 protocols x 2 client engines (Mihomo, sing-box) x IPv4/IPv6 endpoints | 40/40 PASS | 40/40 PASS |
| TCP + verified TLS to IPv4 and IPv6 destinations | 80/80 | 80/80 |
| UDP DNS to IPv4 and IPv6 destinations | 80/80 | 80/80 |
| Cold request total time, median / p95 (server 1; server 2) | 595/719 ms; 1418/1725 ms | 607/739 ms; 1427/1660 ms |

After upgrade: the running core is the new binary, static firewall rules and listeners
are identical to before, client node definitions are unchanged (only the version
comment in exported profiles changes), the panel answers HTTPS 200 with a valid
certificate over IPv4 and IPv6, and the accounting collector is attached to the new
core for all five protocols. A rollback drill restored the previous configuration and
core, then the host was upgraded again; a certbot renewal dry-run succeeds afterwards.
Timings are single cold requests through a fresh client and are not a latency claim.
Per-user quota enforcement, long soak and physical clients were not part of this run.

### Known issues found during the drill (unchanged since 1.8.0)

- `bash rollback.sh --yes` accepts each prompt's default, and "Restore this backup?"
  defaults to No: the restore is cancelled but the script exits 0. Use
  `bash rollback.sh --force` for an unattended rollback and check `sbox version`
  and the running core afterwards.
- A same-host restore of a server whose certificate was managed by certbot HTTP-01
  switches it to a static copy of the certificate and drops the port-80 renewal rule.
  Run `sbox certificate`, choose Let's Encrypt HTTP-01 (the valid lineage is reused,
  nothing is issued), then `sbox renew-test`.
- Rollback restores configuration, users, quotas, certificates and their core; the
  manager program stays at the newer version.

## 1.8.1 changes and their evidence scope

**Panel firewall reconciliation (Generic manager).** `sbox firewall apply` now
restores the installed panel's declared narrow firewall rule before the
default-drop hardening collector reads live INPUT ports. The panel helper runs
only if it is a regular, root-owned file without group/other write access in a
root-owned directory without group/other write access; any failure aborts
reconciliation before hardening is rebuilt. Hosts without panel settings keep
the existing path. Arbitrary foreign UFW ports are never mirrored. The protected
ZgoCloud manager has no default-drop collector and keeps its own firewall code.

**OpenSSH parser.** The SSH safety parser accepts the canonical capitalized
`Port` output of newer OpenSSH (observed on Ubuntu 26.10), keeping numeric
validation and refusal behavior. Case-sensitive parsing previously found no SSH
port on such hosts.

**Core dependencies.** `github.com/andybalholm/brotli` v1.1.0 -> v1.2.7
(GO-2026-6888) and `github.com/klauspost/compress` v1.19.1 -> v1.20.2
(GO-2026-6865). Both were present as compiled symbols in the previous core,
reachable through uTLS certificate decompression, OpenConnect and tailscale
zstdframe. No other module changed; the accounting patch and protocol contract
are unchanged. Both versions are also minimum floors for locally built cores.

Fail-first unit tests cover each change. The firewall change reproduces a
failure condition in isolation; it does not identify who removed a production
rule historically. CLI status coverage, arbitrary foreign reload sequences and
reboot persistence remain open. No latency improvement is claimed.
