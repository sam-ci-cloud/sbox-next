# Network policies, endpoint validation and migration

The Universal installer keeps three presets: IPv4-only, IPv4 + IPv6 and IPv6-only. New installs default to public scope. `--scope internal` explicitly permits an advanced private/local deployment. Admin WebUI and SSH policies are separate.

| Preset | Listener | Egress | Server DNS | Client node dialing |
| --- | --- | --- | --- | --- |
| IPv4-only | 0.0.0.0 | IPv4 | A only | IPv4 |
| IPv4 + IPv6 | :: | both | both, IPv4 preference | both/fallback |
| IPv6-only | assigned IPv6 | IPv6 | AAAA only | IPv6 |
| Legacy preserve | unchanged | unchanged | unchanged | unchanged |

Preserve is never inferred as strict IPv4 just because its listener is0.0.0.0. Upgrades preserve saved behavior and user preferences. Changing policy restarts the VPN; use a maintenance window.

**Default on a new install (1.8.0):** when `detect_public_ipv6` reaches a public service over IPv6 and you keep the detected address, the guided prompt defaults to **IPv4 + IPv6**, so IPv6-only clients can connect. A typed address that was not probed, or no IPv6 at all, keeps the IPv4-only default. A non-interactive `--yes` install without `--family` follows the same rule; pass `--family ipv4` to keep IPv4-only. Upgrades keep the current policy and only print that IPv6 clients cannot connect when listeners are IPv4-only.

## Public and internal endpoints

Public explicit modes require native global unicast addresses. Unspecified, multicast and IPv4-mapped IPv6 endpoints are refused. Internal scope allows loopback/ULA for a deliberately private deployment. Link-local requires the server interface and assigned address, plus manual client scope; portable URIs cannot infer a client's interface. The preflight flags this and requires an explicit advanced override before proceeding.

Public required A/AAAA records must match saved addresses without additional unverified endpoints. Dual inbound requires both families. Missing/stale DNS blocks a new public configuration; legacy preserve reports its unchanged scope. IPv6 assignment and interface are checked on the host. A saved public IPv4 may be NAT-mapped rather than locally assigned; mapping and provider firewall reachability still require an external test. DNS agreement or a local listener is not Internet reachability evidence.

For transitional DNS, an intentional fronting/NAT arrangement or private resolution, use `--endpoint-override-file /root/endpoint-reason.txt` (root-owned0600,12–512character explanation). Advanced state uses `server.endpoint_override`. Errors become explicit warnings; authentication, TLS and transaction rollback are retained. Overrides do not make unassigned addresses or routes work. Keep the reason free of credentials; it is not printed.

A previously private explicit1.5.0 preset may need context annotation before upgrade. Run the supplied `source/tools/set_deployment_scope.py --scope internal` for a preview; `--apply` creates an installed-manager native backup, verifies unchanged state and atomically annotates only context. It neither regenerates server configuration nor restarts services. Review the result and retain the backup before upgrading. Protected fixed-node state is excluded from this Universal migration tool.

## Advanced independent policy

Create a root-owned0600 JSON file. For IPv4 inbound with dual egress:

```json
{"scope":"public","policies":{"inbound":"ipv4","egress":"dual","dns":"dual","client":"ipv4"}}
```

```bash
sbox network preview /root/network.json
sbox network apply /root/network.json
```

Preview validates real core/Mihomo exports and DNS/assignment without changing state. Apply asks explicitly, creates a native backup and uses the manager transaction. `--force` is an explicit unattended confirmation. Roll back with the recorded backup and matching pinned core; see [recovery](upgrades-and-recovery.md). Users, subscriptions, credentials and quotas are retained.

Inbound/client allow ipv4,dual,ipv6. Egress/DNS also allow prefer_ipv4 and prefer_ipv6. Single-family egress requires matching DNS. An egress preference requires dual-answer DNS; conflicting preference dimensions are rejected. Single-family listeners require matching client dialing. These restrictions make each supported combination well-defined. Strict-family node URIs pin saved addresses with correct IPv6 brackets while preserving SNI; full client files carry explicit node dialing policy.

Optional `fallback_delay_ms` is100–1000ms and applies only to explicit dual-family egress. For example, add `"fallback_delay_ms":150` to an advanced policy with egress prefer_ipv6 and DNS dual. It advances the alternate-family connection attempt when IPv6 is slow/unreachable; absent/null keeps the existing core default. It does not change client-to-VPS dialing or supply translation. See [measured results](optimization-1.6.md).

## Optional diagnostics

```bash
sbox doctor --network --target https://cp.cloudflare.com/generate_204 --samples 3
sbox doctor --network --family ipv6 --target https://cp.cloudflare.com/generate_204
sbox doctor --network --socks-port 1080 --target https://example.com/ --expected-status 200
```

Diagnostics are opt-in and bounded to1–5samples. They label first requests versus actual reuse, direct versus SOCKS, cumulative versus derived phases, transport errors versus HTTP-status mismatches, and capabilities without applying tuning. Curl total time is not an RTT, and QUIC/proxy authentication is not isolated by its TCP timing. OS DNS caches are not flushed. Explicit peer host:port probes measure TCP establishment, not a guaranteed physical RTT. Local TUN/fake-IP interception can invalidate a direct baseline; SOCKS hostname resolution stays remote. `--allow-private-target` is only for an understood operator-controlled internal test.

## IPv6-only bootstrap

The release hostname may lack native IPv6 reachability. No untrusted mirror or checksum bypass is used. Transfer the verified release TAR through an operator-controlled path, then use the local archive with the public bootstrap:

```bash
sudo env SBOX_INSTALL_ARCHIVE=/root/SING-BOX.tar.gz bash /root/install.sh
```

The embedded exact SHA-256 is still mandatory before extraction/execution. The standalone archive also works directly: `cd /root/SING-BOX && bash install.sh`. Preinstall OS prerequisites or provide usable IPv6 package repositories. An explicitly configured HTTPS_PROXY or provider NAT64/DNS64 may support online download; the installer does not change system DNS/routes. Staged verification in an IPv6-only namespace is a different claim from full native IPv6-only online installation.


## Network setup and endpoint selection

WebUI → VPN configuration → Network setup observes addresses, default routes and A/AAAA records. Observations do not prove provider firewall reachability. Three presets keep setup simple; Advanced Settings separates listener, egress, server DNS and device dialing. Client preferences use Mihomo ipv4-prefer/ipv6-prefer and native resolver strategies. A pure IPv6 egress cannot reach IPv4-only destinations without operator-provided translation.

Existing HTTPS binding is preserved unless explicitly selected. The wizard can match subscription HTTPS to the preset or choose its family separately. A fresh explicit-family install chooses the same family for HTTPS. IPv6 uses the assigned host address, dual uses a dual-family wildcard socket, and IPv4 uses its wildcard. The hostname/certificate and HTTPS port stay unchanged. Network apply creates a native backup, journals the old listener and rolls back on failed health checks; current sessions may need reconnection. SSH and provider firewall are unchanged. Legacy upgrades do not implicitly disable outbound IPv6.

Connect Your Device can export a domain or an available IPv4/IPv6 VPN endpoint. Subscription URLs carry endpoint=ipv4/ipv6/domain and retain the same bearer and HTTPS origin. Refreshing the link, downloading and scanning the corresponding QR yield the same endpoint policy. Single-node QR remains separate. Literal endpoints preserve TLS/REALITY SNI; URI IPv6 hosts are bracketed, YAML/JSON strings are unbracketed. A client without IPv4 requires IPv6 HTTPS too, or a verified staged configuration.

Network snapshot restore retains users, credentials, quota/accounting data and subscriptions. Authenticated new backups include the HTTPS listener/port record; old backups without that record keep existing panel binding. Restore refuses a port mismatch: plan port migration separately. For public deployments DNS exceptions are explicit explanations, never a substitute for local address assignment. Advanced internal addresses require explicit internal context; link-local client scope is manual and nonportable.

## UDP egress controls (1.8.0, opt-in)

Some providers drop UDP *replies* whose source port is low. Measured on one VPS on 2026-11-05: IPv4 UDP from source ports below 10000 never reached the VM, while IPv6 was unaffected. Through such a node, QUIC/HTTP3 (udp/443), STUN and low-port game or voice traffic fail over IPv4. Clients behind a carrier NAT that assigns low source ports may also be unable to use Hysteria2/TUIC on that node.

Two server-side switches live under **Network → Advanced Settings → UDP egress**, stored as `server.udp_egress`:

| Switch | Effect in server.json | Trade-off |
| --- | --- | --- |
| `prefer_ipv6` | adds outbound `direct-udp6` (domain resolver `prefer_ipv6`) and routes `network: udp` to it | Helps only destinations that have AAAA records; IPv4-literal destinations are unchanged. Refused when server egress is IPv4-only |
| `reject_quic` | rejects `udp` port 443 | Browsers and apps fall back to TCP at once instead of timing out; HTTP/3 through this node is disabled |

Both are appended after the security and family reject rules, so those keep precedence. With neither set, `server.json` is byte-identical to 1.7.1. Neither switch can fix the inbound side (clients with low source ports); that needs the provider to relax its filter.
