# Troubleshooting

## Start with bounded diagnostics

```bash
sbox status
sbox doctor
sbox webui doctor
sbox quota show
sbox logs 100
```

Inspect output locally before sharing it. Remove credentials, tokens, domains/IPs, user data and private paths. Never attach a complete profile, database, backup or original ZgoCloud YAML.

| Symptom | Inspect |
| --- | --- |
| Public console unavailable | Domain DNS, trusted certificate, TCP 9443 provider/local firewall, sbox-webui and local control services |
| VPN works but panel is pending | Public panel requires trusted TLS; repair the certificate, then `sbox webui install` |
| Self-hosted REALITY website warning | `sbox reality-fallback check`, `journalctl -u sbox-fallback-web -n 50`; see [REALITY handshake target](reality-fallback.md#troubleshooting) |
| ACME failure | Correct domain records, inbound TCP 80 for HTTP-01 or authorized DNS-01 token/propagation, occupied ports and certificate plan |
| Correct user rejected | Pause/expiry/quota state, actual UTC/timezone policy, core/adapter health and unique managed credentials |
| Unexpected quota bytes | Payload units, upload+download attribution and polling overshoot; compare provider/NIC bytes separately |
| Only one protocol fails | Matching exported credentials, transport/path/SNI, selected port/range and actual compatible client behavior |
| Source address banned | `sbox security bans` lists every jail holding the address; `sbox security unban IP` clears all of them. WebUI: `sbox webui guard` and `sbox webui unban IP`. Keep provider console access |
| `SECURITY ERROR: the installed Fail2Ban server cannot start (... asynchat ...)` | Ubuntu 24.04 without `noble-updates`: `apt-get update && apt-get install --only-upgrade fail2ban`, then rerun the installer. Nothing was changed |
| Personal Cloud: `site root has no index.html`, listener absent, install rolled back (Ubuntu 26.10) | Installer 1.1.0 on uutils coreutils; fixed in 1.1.1 ([details](reality-fallback.md#troubleshooting)) |
| Mutation blocked by pending state | Inspect the journal and `sbox recover`; do not delete snapshots to bypass a guard |
| Upgrade refuses core version | Adapter/core capability mismatch; do not silently force an incompatible stock core |
| Client keeps an old transport | Reimport/reload profile and inspect the client's saved selection; automatic policies affect new connections |

The complete installer needs a controlling TTY for its guided menu. Use explicit supported arguments for automation. Verify the local delivery checksum and shell syntax before running it as root.

Boot delays can come from the provider network stack or systemd-networkd-wait-online. Inspect the actual unit and network state before changing boot dependencies or SSH protections.

When recording a defect locally, include the exact manager/core version, OS/architecture, operation, redacted error and a minimal reproduction. Distinguish a local unit test, a disposable integration fixture and a live deployment. Do not include credentials, private profiles, subscription URLs or unredacted configuration in evidence.
