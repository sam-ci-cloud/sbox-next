# CLI reference

Run installed mutating commands as root. `sbox help` is the shipped help source; product constraints and validation still apply. The all-in-one wrapper has a separate `help` entrypoint and embeds the compatible core.

## Installer entrypoint

| Action | Arguments after the public one-liner |
| --- | --- |
| Guided menu | None; controlling TTY required |
| Fresh Universal | `install generic` plus guided/explicit options |
| Fresh protected product | `install zgocloud` plus supported existing certificate/network options |
| Matching upgrade | `upgrade generic` or `upgrade zgocloud` |
| Transaction recovery | `recover generic` or `recover zgocloud` |
| Read-only verification | `verify generic` or `verify zgocloud` |
| Wrapper help | `help` |

Generic noninteractive installation accepts `--yes` with explicit setup options. The complete wrapper refuses `--core`/`--binary` overrides for fresh installation because it supplies the embedded accounting core.

## Installed manager

| Command | Purpose |
| --- | --- |
| `sbox menu` / `sbox help` / `sbox version` | Menu, shipped help and manager version |
| `sbox status` / `sbox doctor` | Runtime summary and validation; `--json` is supported |
| `sbox configure` / `sbox ports` / `sbox protocols` | Validated node/network, port/hopping and transport changes |
| `sbox certificate` / `sbox renew-test` | Certificate workflow and applicable Certbot dry run |
| `sbox reality-fallback status` / `check` | Show or verify the REALITY handshake target (remote website or self-hosted Personal Cloud) |
| `sbox reality-fallback self-hosted [--port N]` / `remote [--sni HOST]` | Switch the Universal REALITY handshake target transactionally; see [REALITY handshake target](reality-fallback.md) |
| `sbox client-files` / `sbox links` / `sbox qr` | Private export locations, links and QR output |
| `sbox client-policy show` / `sbox client-policy apply` | Inspect/rebuild exported client policy |
| `sbox client-policy primary tuic` | Prefer an enabled transport for new client connections |
| `sbox client-policy probes active-only` | Reduce unused Smart Auto probing; `continuous` restores continuous mode |
| `sbox client-policy default smart` | Start the 🚀 VPN selector on Smart Auto (measured speed); `anti-block` restores the priority-order default. All three policies stay available |
| `sbox client-policy health 60 5000 2` | Health checks for Anti-Block Auto and Smart Auto: interval 30–600 s, probe timeout 1000–10000 ms (shorter than the interval), failed real connections before an immediate re-check 1–5. Defaults 60/5000/2 = 1.7.1 |
| `sbox client-policy rollback DIR` | Restore an eligible policy snapshot; refuses core/server drift |
| `sbox upgrade-policy` | Upgrade policy/helpers/exports without a core restart |
| `sbox quota show` | Persisted managed-user usage/plan view |
| `sbox quota set`, `topup`, `reset`, `pause`, `resume` | Existing managed-user plan changes; see [users/quotas](users-and-quotas.md) |
| `sbox quota bulk --ids-file PATH` | Apply supported plan options to an explicit ID list |
| `sbox quota policy` | Explicit accounting poll/failure-policy changes using supported options |
| `sbox portal account` / `sbox portal disable` | Separate portal account operations for an existing managed user |
| `sbox accounting doctor` / `sbox accounting backup` / `sbox accounting reconcile` | Accounting diagnostics and maintenance |
| `sbox accounting recover --confirm` | Explicit accounting recovery |
| `sbox webui status` / `sbox webui doctor` | Panel/control service and integrity checks |
| `sbox webui install` / `sbox webui upgrade` | Install/update the common panel with its trust prerequisites |
| `sbox webui start` / `sbox webui stop` | Panel service control |
| `sbox webui guard` / `sbox webui unban IP` | Inspect/recover scoped WebUI bans |
| `sbox webui reset-admin` | Deliberately replace bootstrap admin credentials; retrieve the root-only file afterward |
| `sbox webui rollback` / `sbox webui uninstall` | Panel release rollback/removal |
| `sbox security status` / `sbox security bans` / `sbox security unban IP` | Owned SSH protection diagnostics and unban |
| `sbox security setup` / `sbox security repair` | Validated owned security setup/repair |
| `sbox firewall ports` / `sbox firewall status` / `sbox firewall apply` | Required provider allowances and owned local rules |
| `sbox firewall default-drop on` | Load a default-drop inbound gate on **trial** with a 5-minute automatic rollback. Open a new SSH session, then run `sbox firewall confirm` to persist it. `default-drop off` disables it |
| `sbox performance report` | Read-only host/network/counter report; `--json` supported |
| `sbox performance apply baseline` / `sbox performance apply legacy` | Explicit captured/reversible tuning profiles; affects host settings |
| `sbox performance tfo on` / `off` / `status` | REALITY TCP Fast Open (Universal; default on for new 1.2.0 installs). One transactional core restart; re-import client profiles afterwards |
| `sbox performance vmess-mux on` / `off` / `status` | VMess connection reuse: the server accepts sing-mux sessions and WebSocket early data; refreshed YAML/JSON profiles use them over one pooled connection (`max-connections: 1`, 1.9.2). On for new 1.9.0 installs; upgraded servers keep it off until enabled. One transactional core restart with verified rollback. Plain clients, links and QR codes keep working unchanged. |
| `sbox performance dns-cache on` / `off` / `status` | Resilient server DNS: 24 h optimistic cache in front of the system resolver so REALITY (remote target) and cached names keep working through resolver outages. Default on for new installs; enabled once by the 1.2.1 upgrade |
| `sbox backup` / `sbox restore ARCHIVE` / `sbox recover` | Complete private backup, intentional restore and transaction recovery |
| `sbox regenerate` / `sbox repair` / `sbox restart` | Validated regeneration or core restart |
| `sbox update [latest\|stable\|beta\|pinned\|VERSION\|PATH] [--sha256 HEX]` | Resolve verified official Go sources, apply and test the accounting patch, then transact the compatible core. Also accepts the bundled core or SHA-256 verified local imports. Incompatible candidates retain the current core; stock cores cannot enforce quotas and are refused |
| `sbox logs` | Core journal view; optional line count or `follow` |
| `sbox rotate` | Explicit credential rotation; never a routine upgrade step |
| `sbox uninstall` | Deliberate runtime removal; retains defined backup/lineage material |

`DIR`, `PATH`, `IP` and `ARCHIVE` denote operator-selected values, not literal arguments. This table is a command reference, not a script to execute every mutation. Some older manager help text retains historical standalone filename examples; the supported public entrypoint for this project is always root install.sh and the wrapper actions above.
