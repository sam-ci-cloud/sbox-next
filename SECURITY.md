# Security policy

Use the latest tested release. Report vulnerabilities privately through this repository's GitHub Security Advisories; never attach passwords, unlock files, TLS keys, databases or owner backups to public issues.

Public bootstrap downloads are protected by HTTPS and a fixed archive SHA-256 checked before extraction. Release checksums, corresponding source, CI and branch/tag controls provide separate integrity evidence. A checksum is not an independent publisher signature.

The pinned core retains sing-box 1.14.4 and the accounting patch, with a security-driven compiler/dependency rebuild. Exact pins and scope are in SOURCE/core-source and the SBOM. CI audits declared module versions, npm lock dependencies and compiled Go vulnerability findings. These scans do not establish the absence of unknown vulnerabilities.

Explicit source updates enforce the same compiler/dependency security policy and reject stale unqualified caches or failed scans before replacing anything. A custom future build still needs operator protocol/client acceptance. The shipped release has separate network acceptance evidence.

Stats RPC remains loopback-only with a root-controlled secret. Quotas are periodic; collector degradation is visible and does not silently change the configured failure policy. Preserve SSH/out-of-band recovery before maintenance. The admin management listener is independent of VPN address-family policy.

Owner-specific protected source, identities, unlocks, access credentials and backups are delivered privately. They do not belong in public repository history or release assets. See SOURCE/docs/security.md for operational controls and recovery guidance.

Go version updates follow the explicit [controlled maintenance process](DEPENDENCY_MAINTENANCE.md); the incompatible generic updater is not presented as repaired. Advisory and compiled-core CI checks remain enabled. See [validation scope](VALIDATION.md) for open operational acceptance.
