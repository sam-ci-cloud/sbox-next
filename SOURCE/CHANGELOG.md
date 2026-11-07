# SBOX changes

## 1.11.0 (unreleased)

- Export Center: replacing or revoking a subscription link moved out of the dialog footer into a collapsed
  "Manage subscription link" section that states the consequences; every replace/revoke is confirmed, and
  the confirmation offers Back (nothing changes) instead of closing the dialog.
- Routing wording corrected everywhere: the internal profile is "All destinations, including private
  addresses" (no direct rules); a routing note states that the VPN server connection is always direct,
  that TUN mode usually keeps the device's own attached network reachable, and that system-proxy mode
  covers only apps using the system proxy.
- The selection summary always names the configuration type (YAML, complete JSON, basic JSON, node URI);
  method labels distinguish subscription URL, static file and single-server (node URI) links.
- Complete sing-box JSON: routing is now derived from the generated Mihomo rules in the same order, so the
  administrator's custom routing rules and the local-network precedence apply (previously dropped).
- Traditional Chinese interface text uses one written register (47 colloquial Cantonese strings rewritten).
- sing-box profiles: Hysteria2/TUIC on a dual-stack name get one candidate per address family, so a dead
  preferred family no longer breaks the node (sing-box binds QUIC to the first resolved address only).
- sing-box profiles: the server's published addresses are bootstrap candidates, so a failing, slow or poisoned
  local resolver no longer blocks the VPN (lab: 30 s resolver outage at start-up, 0/4 -> all connected in ~5 s).
- sing-box exports of profiles with Mihomo load-balance groups or a DIRECT selector member (the protected
  original profile) no longer fail: load-balance is omitted like fallback, DIRECT maps to a direct outbound.
- Exports larger than 256 KiB were silently truncated by the privileged bridge (a complete profile with the CN
  rule sets is ~300 KB); output is now returned intact up to 768 KiB and refused, never cut, beyond.
- `sbox firewall status` reports the panel's own rule; a two-minute repair timer restores only that rule after a
  foreign UFW reload or firewall tool removed it.
- A restore declined through `--yes` (prompt default No) now exits non-zero with guidance instead of success.
- `recover.sh` removes the /tmp work directories left by killed installers (only when no installer holds the lock),
  so an interrupted upgrade on a small /tmp no longer blocks both recovery and the next upgrade.
- Complete sing-box profile now offers Mainland China direct, from an offline, pinned, licensed rule snapshot
  embedded as inline rule sets (no runtime downloads).

## 1.10.0

- Connect & Export Center: one shared component (`shared_webui/frontend-src/shared/export-center.*`) and one backend catalog (`backend/export_catalog.py`) replace four separate export flows (user Share, user Download client file, personal portal, subscription page). Single column, grouped choices (app, routing profile, server address, connection method), one summary with copy / QR / download / single-server links. QR captions state whether they contain a subscription URL or one server link.
- New export format `singbox`: complete sing-box profile (sing-box 1.12+) with DNS, routing (general browsing or everything through the VPN; mainland China direct stays Mihomo-only because it would need third-party rule downloads), Smart Auto/LOCK groups, a TUN inbound and a local mixed proxy. The basic SOCKS `json` bundle is unchanged.
- The server address choice applies to subscriptions, file downloads, single-server links and QR codes alike; file names keep the chosen address.
- Subscription page: same component; QR codes come from a token-scoped endpoint that encodes only that user's own links; catalog JSON is fully escaped.
- Existing subscription URLs, tokens, links and QR payloads are unchanged.

## 1.9.2

- Performance (VMess connection reuse on): exported Mihomo `smux` and sing-box `multiplex` add `max-connections: 1` / `max_connections: 1`. sing-mux defaults opened a new connection for every concurrent request and dialled them one at a time (8 parallel requests: 19.9-25.5 network round trips; now 7.8-10.3 from healthy to 3% loss). Server configuration, `vmess://` links and QR codes are unchanged; users get it when their profile/subscription refreshes.
- sing-box JSON exporter maps sing-mux pool fields (`max-connections`, `min-streams`, `max-streams`) and AnyTLS session fields (`idle-session-check-interval`, `idle-session-timeout`, `min-idle-session`) as integers and still refuses anything it cannot represent.
- Five-protocol performance study (VLESS REALITY Vision, VMess WS TLS, Hysteria2, TUIC v5, AnyTLS; 6 directed paths, IPv4/IPv6, Mihomo and sing-box): other protocol defaults were measured and kept; see `docs/performance-five-protocols.md`.

## 1.9.1

- Repository identity release; no functional change from 1.9.0.

## 1.9.0

- Performance: VMess connection reuse (`protocols.vmess.multiplex`): server sing-mux + WebSocket early data; Mihomo `smux` + early data; sing-box JSON `multiplex` + transport early data. CLI `sbox performance vmess-mux on|off|status`; panel inbound control. Fresh installs on; upgrades keep it off until enabled. Links/QR unchanged.
- Fix: same-host `sbox restore` / `rollback.sh` keeps a valid certbot lineage (`restore_keeps_certbot_lineage`) instead of switching to a static restored copy that silently disabled renewal.
- Fix: interrupted-upgrade recovery accepts the accounting collector's validated per-user `limits` in quota-runtime.json (previously every recovery on a server with quota users failed).
- Installer: read-only preflight hint for stale `/tmp/sbox-all-in-one.*` work directories when no installer holds the lock.
- sing-box JSON exporter maps `smux` and WebSocket early-data options and still rejects any field it cannot represent.

## 1.8.1

- Security: core dependencies raised for GO-2026-6888 (brotli v1.2.7) and GO-2026-6865 (klauspost/compress v1.20.2); matching security floors for locally built cores.
- Firewall: panel rule reconciled before default-drop regeneration; helper and helper directory ownership/permission checks.
- Firewall: case-insensitive OpenSSH `Port` parsing.

## 1.8.0

- Security: block-private resolves names before checking addresses; non-public ranges incl. 100.64.0.0/10 rejected.
- Network form clears saved override/interface; IPv4 interface preflight; DHCP replies under default-drop; strict-family DNS literals; local-network rule order setting.
- Release: single canonical repository identity, content-addressed packages, complete manifests.

- D2: sing-box JSON exports Smart Auto (urltest), LOCK and VPN (selector) groups. Anti-Block Auto (first-alive fallback) has no sing-box equivalent and is documented as unavailable.
- D1: `client_policy.default_group` (anti_block by default, or smart); CLI `sbox client-policy default`; WebUI selector.
- D6: `health_interval_s` / `health_timeout_ms` / `health_max_failed` (defaults 60/5000/2); CLI `sbox client-policy health`; WebUI shows the worst-case detection time.
- D5: the requested fq qdisc is attached to physical NICs on tuning, on existing-tuning hosts and at boot.
- D3: fresh installs default to dual stack when the detected public IPv6 was probed successfully.
- D4: optional default-drop inbound gate (`inet sbox_hardening`); `sbox firewall default-drop on|off`, `sbox firewall confirm`.
- D7: opt-in `server.udp_egress` {prefer_ipv6, reject_quic}.
- D10: environment-only test gaps report explicit BLOCKED_ENV skips.
- Fix: unchanged older states keep a byte-identical summary.json.

See ../RELEASE_NOTES.md in the public repository.
