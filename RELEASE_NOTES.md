# SBOX release notes

This repository (`sam-ci-cloud/sbox-next`) is a new, independent repository with its own history. It is not a fork. Packages are published under content-addressed tags (`pkg-<first 16 hex digits of the package SHA-256>`); the bootstrap script pins the full SHA-256.

## 1.11.0

- **Clearer Connect & export:** replacing or revoking a subscription link now lives in a separate "Manage
  subscription link" section that explains what happens, and always asks first (with Back). The routing choices
  say exactly what they do; "All destinations, including private addresses" replaces the misleading "Everything
  through the VPN", with a note on what always connects directly.
- **sing-box: Hysteria2 and TUIC survive a dead IPv4 or IPv6 path.** Before, a sing-box app kept trying the dead
  address family and never connected; now it falls back to the other family in about 1.5 seconds (lab: 0/48 ->
  48/48 across six directions).
- **sing-box: no dependence on a working local DNS server to reach the VPN.** The server's own published
  addresses are used as a fallback (lab: 30-second DNS outage, never connected -> connected in about 5 s).
- **sing-box: Mainland China direct** is now available in the complete sing-box profile, from rule data shipped
  with SBOX (no downloads from third-party sites).
- **Fixes:** large complete profiles (with China rules) were cut off; sing-box exports of the original protected
  profile failed; the administrator's custom routing rules were missing from complete sing-box profiles;
  `sbox firewall status` now notices a missing panel rule and a timer restores it within two minutes;
  `restore --yes` no longer reports success when nothing was restored; `recover.sh` cleans up after a killed
  upgrade so the next attempt is not blocked.
- Upgrades from 1.8.0 and later keep users, credentials, quotas, subscription links and settings. Re-import or
  refresh sing-box profiles to get the new behaviour; links, QR codes and Mihomo profiles keep working.

## 1.10.0

- **One clear Connect & export screen** everywhere (administrator console, personal portal, subscription page): choose the app, which traffic uses the VPN, the server address and how to connect, then copy, scan or download. Each QR code says whether it contains a subscription or a single server link.
- **Complete sing-box profile:** sing-box apps now get routing, DNS and a whole-device VPN (TUN) from the subscription or file, not only a local proxy. The previous basic proxy file is still available.
- Existing subscription links, QR codes and client files keep working; nothing needs to be re-issued.

## 1.9.2

- **Faster VMess with many parallel requests (when VMess connection reuse is on):** client profiles now keep all requests on one reused connection. Before, a burst of 8 requests (a typical page load) opened up to 8 extra connections one after another and took 19.9-25.5 network round trips; now 7.8-10.3, from a healthy network to 3% packet loss, with about 17% more parallel download throughput at 1% loss and one third less server CPU for request-heavy traffic. Refresh or re-import the profile to get it. Links and QR codes are unchanged.
- Measured trade-off: if the network path changes within about 45 seconds of the last activity (for example Wi-Fi to mobile), a Mihomo client now needs about 26 seconds instead of about 11 to abandon the dead connection (sing-box clients already needed about 26 seconds).
- **Five-protocol study:** VLESS REALITY Vision, Hysteria2, TUIC v5 and AnyTLS were tested against their alternative settings on six directed paths with loss, jitter, idle, outage and dead-address-family scenarios. Their current settings were the best supported options; rejected alternatives and the reasons are in `SOURCE/docs/performance-five-protocols.md`.
- In-place upgrades keep users, credentials, ports, subscription links, quotas, usage history, certificates and settings; the server configuration does not change.

## 1.9.1

- Repository identity release with the verified 1.9.0 functionality; no functional change.

## 1.9.0

- **Faster VMess (opt-in for upgrades, on for new installs):** connection reuse with sing-mux and WebSocket early data. In a six-direction lab (Los Angeles, Tokyo, Singapore; IPv4 and IPv6; Mihomo and sing-box clients) repeated VMess requests went from 9.2 to 6.1 network round trips (median 935 ms to 610 ms) and UDP relays from 5.1 to 2.0 round trips, with no loss of parallel download throughput. Enable it with `sbox performance vmess-mux on` or in the panel under **VPN configuration > Inbounds**; users get it when their subscription refreshes.
- Existing client files, links and QR codes keep working unchanged. The `vmess://` link format is deliberately unchanged because some sing-box based apps read the usual early-data path suffix literally and fail.
- **Fix:** a same-host rollback or restore no longer turns a renewable Let's Encrypt certificate into a static copy; automatic renewal stays connected. Restores on a different host still use the certificate from the backup.
- **Fix:** `sbox recover` after an interrupted upgrade no longer fails with "invalid live quota policy fields" on servers that have quota users; the panel and subscriptions become available again once recovery completes.
- If an installer was killed (for example by the out-of-memory killer) and `/tmp` is too full to retry, the preflight now names the leftover work directories and the safe removal command instead of only reporting low space.
- Client TCP Fast Open remains off in exported profiles: measured faster on healthy networks, but it broke address-family fallback when one IP family was unreachable.

## 1.8.1

- **Security:** the bundled core no longer contains GO-2026-6888 (brotli decoder memory exhaustion) or GO-2026-6865 (compression panic). Dependency floors keep locally built cores at or above the fixed versions.
- **Firewall:** `sbox firewall apply` restores the panel's narrow rule before regenerating the default-drop policy, and only runs a safely owned panel helper.
- **Firewall:** the default-drop gate recognizes the SSH port on newer OpenSSH releases that print `Port` in capitals.
- Pre-release: see [VALIDATION.md](VALIDATION.md) for evidence scope and open items.

## 1.8.0

## Security

- **Block private destinations now covers domain names.** Previously a domain that resolved to a private, loopback, link-local or metadata address bypassed the rule and the server connected to it. The server now resolves first (never from stale cache), then rejects private addresses and the remaining non-public ranges (including 100.64.0.0/10). Verified with the bundled core against real DNS names.
- **Strict-family DNS** no longer depends on resolver host names. On IPv6-only devices, China-direct domains use the providers' plain IPv6 resolvers because their certificates do not cover IPv6 addresses; all other DNS stays encrypted.

## Fixes

- Clearing the DNS override explanation or bind interface in the WebUI removes the saved value.
- The endpoint check validates the selected interface for IPv4 as well as IPv6.
- The default-drop firewall allows DHCPv4/DHCPv6 replies needed for address renewal.
- New "Local network devices" choice in client policy (direct by default for new installs).

## Known provider limitation

Some providers drop inbound IPv4 UDP whose source port is below 10000. Hysteria2 and TUIC over IPv4 can then fail for some clients. Use IPv6 or a TCP-based protocol on such hosts; see the opt-in `udp_egress` settings.
