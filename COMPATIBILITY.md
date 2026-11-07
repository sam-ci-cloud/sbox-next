# Compatibility — SBOX

Linux amd64; supported OS identifiers are in SOURCE/assets/release.json. The patched sing-box1.14.4 binary, compiler, dependencies and accounting API are unchanged. Source and core digests are independently checked. Five protocols: VLESS REALITY Vision, VMess WebSocket/TLS, Hysteria2, TUIC v5 and AnyTLS.

Mihomo acceptance uses the installed Clash Verge Rev2.5.10 core, Mihomo1.19.33. Core CLI packet tests and generated configuration imports do not prove a physical Android/iOS/Windows/macOS GUI workflow. Device-specific errors still need device logs when not reproduced.

IPv4-only means IPv4 VPN listeners/egress/DNS/dialing. Dual supports both. IPv6-only requires routed IPv6 clients and destinations; it does not create NAT64/DNS64. Advanced mixed-family policies are explicit. Mihomo global IPv6 enables node sockets independently of destination DNS AAAA policy. JSON is a local SOCKS bundle with Smart Auto, LOCK and VPN groups (1.8.0). sing-box has no first-healthy fallback group, so Anti-Block Auto is YAML-only, and JSON urltest has no probe timeout or failure-count field. It is not a complete mobile TUN profile or a copy of every YAML routing rule.

HTTPS subscriptions retain their certificate domain. A VPN IPv6 literal does not change the subscription URL to an uncertified literal. IPv6-only clients need an IPv6-reachable subscription origin, or a staged configuration. Domain endpoint dialing depends on usable DNS and selected client policy. Internal link-local deployments require explicit interface scope and manual client setup; portable links/QR cannot infer a device interface.

Upgrades preserve old implicit/preserve network policy and current panel settings. Network migration is explicit, backs up first and restarts affected services. Native restore includes the authenticated optional HTTPS network record; older backups without it retain current settings. Same-port network restore is supported; port migration is a separate operation.

Native IPv6-only online bootstrap depends on the external release endpoints or a verified translation/proxy route. A staged SHA-pinned archive is supported; no untrusted mirror is introduced. Geography/provider routing, untested physical devices, new soak campaigns and quota overshoot remain honest limitations. Existing historical tests retain their executed versions/scopes; only changed paths receive new evidence.

1.8.0 additions are opt-in or preserve existing behaviour on upgrade. Exceptions: the qdisc fix attaches fq where tuning already requested it, and fresh installs with a probed public IPv6 default to dual stack. The default-drop gate (D4) is a Generic-manager feature; the protected ZgoCloud variant keeps its own firewall code. The ZgoCloud manager was resealed for 1.8.0 with 772 protected literals and the original YAML verified unchanged.
