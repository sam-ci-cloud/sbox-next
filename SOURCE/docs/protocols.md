# Protocols and client policies

## Server transports

| Family | Implemented transport | Notes |
| --- | --- | --- |
| VLESS | REALITY with Vision | Retains configured REALITY keys and handshake target; ordinary TLS reachability alone does not prove REALITY works |
| VMess | WebSocket over TLS | Domain, certificate and WebSocket path must match the export |
| Hysteria2 | QUIC over UDP | Supported configurable UDP hopping; provider/local firewall must permit its selected range |
| TUIC | TUIC v5 over UDP | Protected ZgoCloud also retains its original extra range/port alias |
| AnyTLS | TLS transport | Uses the generated compatible client configuration and trusted TLS |

Universal ports are selected through setup and `sbox ports`; use `sbox firewall ports` for the exact current allowances. Do not infer requirements from a generic port table. ZgoCloud preserves its original six nodes across these five families, including fixed ports and both UDP behaviors.

Use a client version that supports the selected transport and its TLS/UDP requirements. Sharing a protocol name does not establish full application compatibility.

XHTTP, ShadowTLS, Naive and post-quantum VLESS Encryption are not advertised as SBOX features. Additional upstream source capabilities do not imply a supported SBOX configuration. TLS negotiation is not a censorship-resistance guarantee.

## REALITY handshake target

Universal REALITY relays ordinary (non-REALITY) TLS either to a **remote website handshake target** (default; SBOX never copies that site's certificate) or to the **self-hosted SBOX Personal Cloud** website on `127.0.0.1`, which presents your own trusted certificate for your SBOX domain. The self-hosted website is an original, read-only multi-page site run by an isolated SBOX service; it is not a copy of any third-party site. See [REALITY handshake target](reality-fallback.md). ZgoCloud keeps its protected configuration.

## Client-side policies

- **Anti-Block Auto:** ordered fallback across enabled exported transports: the first *healthy* transport in priority order, without comparing speed. The preferred transport is followed by the configured fallback order.
- **Smart Auto:** optional URL-test selection with measured tolerance and configurable active-only or continuous probes.
- **LOCK:** manual client pinning to an enabled node.

**Starting group (1.8.0):** the 🚀 VPN selector starts on Anti-Block Auto by default (unchanged from 1.7.1). Set it to Smart Auto with `sbox client-policy default smart` or in the WebUI (Client policy → *Group devices start on*). This helps where some transports take a slower route for your users. Measured on 2026-11-05 from one Hong Kong ISP to one VPS: TLS RTT 166 ms on tcp/443 versus 242–250 ms for every UDP transport and other TCP ports. Clients may keep a locally stored choice until the profile is re-imported.

**Health checks (1.8.0):** both automatic groups share `health_interval_s` (30–600, default 60), `health_timeout_ms` (1000–10000, default 5000; must be shorter than the interval) and `health_max_failed` (1–5, default 2). In Mihomo, `max-failed-times` counts failed *real connections* through the group that trigger an immediate extra check; it does not mean "probes before a node is marked dead". A transport that dies right after a check is noticed within about interval + timeout (65 s by default), or sooner when connections through it fail. The WebUI shows this bound as you edit.

These policies choose a path for **new connections**. They do not migrate established TCP/QUIC flows, preserve a call through a network outage or learn filtering rules with a persistent AI agent. Five transports on one VPS still share one IP/provider failure domain. A generic health URL does not detect every filtering condition.

### Engine parity (Mihomo YAML vs sing-box JSON)

| Policy element | Mihomo / Clash Meta YAML | sing-box JSON (1.8.0+) |
| --- | --- | --- |
| 🚀 VPN selector | `select`, default **Anti-Block Auto**, or **Smart Auto** when `client_policy.default_group = smart` | `selector`, default always **Smart Auto** (see Anti-Block row) |
| 🧠 Smart Auto | `url-test`: url, interval (default 60 s), tolerance (10–300 ms), timeout (default 5000 ms), max-failed-times (default 2), lazy. All from state | `urltest`: same url, interval and tolerance. Probe timeout, failure count and lazy have no sing-box field, so the core's built-in behaviour applies. |
| 🛡 Anti-Block Auto | `fallback`: first healthy transport in priority order | **Not available.** sing-box has no first-alive group type, so it is omitted rather than imitated. |
| 🔒 LOCK | `select` over all enabled transports | `selector`, same members and default |
| DNS, routing rules, GLOBAL/CN/INTERNAL bypass | full profile | not included: JSON stays a local SOCKS client (127.0.0.1:1080) |

Before 1.8.0 the JSON export contained no groups and sent all traffic through the first transport only.

Inspect policy with `sbox client-policy show`. Change the preferred enabled transport with `sbox client-policy primary tuic`, then reload/import the export in the client. A client may preserve a previously selected group. Subscription import does not force all clients to discard their saved choices.

See [CLI reference](cli-reference.md) and [test limitations](testing.md).
