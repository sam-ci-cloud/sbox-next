# Configuration

Use the installed CLI and authenticated WebUI instead of editing rendered JSON, exports or live databases by hand. Changes are validated through the manager's state and transaction boundaries.

| Task | Supported interface |
| --- | --- |
| Node/domain/listening and network choices | `sbox configure` |
| Protocol ports and Hysteria2 UDP hopping | `sbox ports` |
| Enable/disable transports | `sbox protocols` |
| Certificate source | `sbox certificate` |
| Required provider firewall ports | `sbox firewall ports` |
| Current state and service diagnostics | `sbox status`, `sbox doctor` |
| Client policy and export refresh | `sbox client-policy show`, `sbox client-policy apply` |
| Managed users, plans and subscriptions | HTTPS WebUI on port 9443 |

Universal settings are configurable within validation rules. ZgoCloud rejects changes that violate its protected original identity, fixed ports or UDP ranges. Credential rotation is an explicit operation, not part of a routine upgrade. Do not run `sbox rotate` on a protected deployment unless you understand and satisfy its compatibility constraints.

Client exports support GLOBAL/CN/INTERNAL profiles. Those are routing/profile choices, not an additional server protocol. Anti-Block Auto, Smart Auto and LOCK selection is performed by the client; see [protocols](protocols.md).

The authoritative state is `/etc/sbox-manager/state.json`; exports are under `/etc/sbox-manager/exports/`. Treat both as private. Ordinary application configuration and panel/accounting databases contain subscriber information and credentials; do not upload them for support.

`performance report` is read-only. Explicit `performance apply baseline|legacy` controls captured, manager-owned tuning and can affect the host. Inspect the report and measured workload before choosing a profile. The repository rebuild applies no tuning, changes no DNS and touches no live server.

For certificate and firewall prerequisites, follow [installation](installation.md) and [certificates](certificates.md). Back up before changing a live node.
