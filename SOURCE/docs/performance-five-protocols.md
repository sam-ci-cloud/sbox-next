# Five-protocol performance study (1.9.2)

Lab: three 1 vCPU / 1 GiB servers (Los Angeles, Tokyo, Singapore), every server also a client.
Six directed paths, IPv4 and IPv6, Mihomo 1.19.33 and sing-box 1.14.4 clients, SBOX server core
(sing-box 1.14.4 + accounting). Latency is reported in multiples of the path's network round-trip
time (RTT: 67-182 ms), median unless stated. A request that reuses a warm tunnel cannot go below
about 6 RTT in this harness (the target is reached through the tunnel and back with its own TLS).
Impairment (loss, jitter, outages, dead address family, silent NAT drop) was applied only to the
experiment ports with reversible traffic control; SSH and production traffic were never touched.
Baseline and candidate settings ran interleaved in randomized order on the same paths.

| Protocol | Baseline (1.9.1) | Tested alternatives | Change | After | Stability | Conclusion |
|---|---|---|---|---|---|---|
| VLESS REALITY Vision | cold 8.25, warm 8.19, 8 parallel 9.59, UDP setup 4.06 | uTLS chrome/firefox/safari; client TCP Fast Open; sing-mux with and without Vision; xudp vs packetaddr; REALITY target latency | none | unchanged | recovers in 0.9 s after silent NAT drop (new connection per request) | Already the best option within its security model. TFO saves 1 RTT but makes traffic distinguishable from browsers and broke dual-stack fallback; mux changes the Vision property and inherits the sing-mux stall; packetaddr breaks UDP; target adds 3.5-5 ms. |
| VMess WS TLS | warm 7.29 (bimodal, p95 9.94), 8 parallel 19.90, server CPU 90 ms per test case | sing-mux pool (max connections 1/2/4/8, max streams 4), h2mux/smux/yamux, padding, no mux | Mihomo `smux` / sing-box `multiplex`: `max-connections: 1` | 8 parallel 7.8 (healthy) to 10.3 (3% loss); warm p95 6.7; server CPU 60 ms | parallel download +17% at 1% loss; small request during a download +1 RTT p90 at 1% loss; path change within ~45 s: Mihomo 11 -> 26 s | Implemented. smux rejected (never abandons a dead session: keep-alive disabled); yamux rejected (10 Mbps single-stream cap in sing-box). |
| Hysteria2 | cold 8.46, warm 6.13, 8 parallel 7.77 | server BBR profile standard/aggressive/conservative; client BBR profile; Brutal (client up/down) | none | unchanged | 1% loss 61 Mbps, 3% loss 61 Mbps (16 MiB, Mihomo) | BBR standard is best or equal; aggressive is not better (worse at 3% loss); Brutal is slower on healthy paths, costs more CPU and needs per-user bandwidth. |
| TUIC v5 | cold 7.35 (best), warm 6.12, 8 parallel 7.64 | congestion bbr/cubic/new_reno; UDP relay native/quic; 0-RTT | none | unchanged | cubic/new_reno collapse to 1.3-2.0 Mbps at 1% loss vs 35-44 with BBR | BBR + native relay + 0-RTT off is best: 0-RTT showed no gain on reconnection and adds replay risk; quic relay makes UDP reliable but not faster. |
| AnyTLS | cold 8.36, warm 6.11, 8 parallel 10.05 | min-idle-session 1, idle timeout 120 s | none | unchanged | default recovers in 3.9 s after silent NAT drop | Keeping a warm session saves ~2 RTT after idle, but AnyTLS has no heartbeat: a session kept across a mobile NAT timeout costs ~4 s. Default kept. |

Shared findings:

- Address families: with one family unreachable, every TCP protocol falls back on both clients and Mihomo Hysteria2/TUIC also connect. sing-box Hysteria2/TUIC do not (no QUIC fast fallback in that client); Smart Auto routes around them, a LOCK on a QUIC node does not.
- All five protocols resume within about 1 s after a 45 s outage (VMess mux needs a second attempt).
- VMess mux (h2mux) sessions are closed by the server after 30 s idle (sing-mux), so the first request after idle pays a reconnect; QUIC protocols stay warm through keep-alive.
- Paths that reorder packets heavily hurt QUIC protocols far more than TCP protocols (quic-go loss detection).
- Server CPU for 24 MiB of downloads on 1 vCPU: TCP without mux 0.43-0.54 s, mux and QUIC 0.75-0.80 s, Brutal 0.97 s.

## 1.11.0 re-measurement: VMess mux and AnyTLS idle sessions

New lab runs on the 1.11.0 servers (six directions, Mihomo and sing-box, IPv4). Times are medians; request times
are in network round trips (RTT) to normalise path length.

| Variant | Silent NAT drop after 20 s idle: first request | Recovery | Parallel 8 wall time | Request after 40 s idle |
| --- | --- | --- | --- | --- |
| VMess mux, `max_connections 1` (shipped) | fails | ~26 s | 0.74-0.82 s | 9.2-9.5 RTT |
| VMess mux, default pool | fails | ~26 s | 1.95-2.88 s | - |
| VMess without mux | succeeds | <1 s | 0.97-1.04 s | - |
| AnyTLS (shipped) | fails | 25 s | 1.0 s | 5.9-6.1 RTT |
| AnyTLS idle timeout 15 s / check 5 s | fails | 6.7 s (max 9.7 s) | 1.0-1.6 s | 8.2-8.3 RTT |

- VMess: the ~26 s comes from sing-mux's fixed 30 s h2mux idle/read timeout, which no client profile field can
  change (Mihomo and sing-box apps embed it). Disabling mux removes the stale-session wait but loses the parallel
  request improvement, so the shipped setting is kept.
- AnyTLS: a 15 s idle timeout recovers faster after a silent path loss, with no persistent dead session, but
  every request after an idle gap longer than ~15 s pays about 2.2 extra RTT for a new session. That common-path
  cost outweighs the rare-path gain, so the shipped setting is kept.
- Smart Auto switching to another protocol is not address-family fallback; per-family Hysteria2/TUIC candidates
  (1.11.0) handle a dead family inside the same protocol.
