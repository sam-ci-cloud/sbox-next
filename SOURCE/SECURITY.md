# Security policy

SBOX runs privileged installation and management code. Use a trusted root terminal and verify `SING-BOX.tar.gz` against the delivery `SHA256SUMS` before copying it; `install.sh` re-verifies every file against `SING-BOX/SHA256SUMS` before execution. The checksum detects accidental corruption but is not an independent publisher signature; compare the archive digest with a separately trusted copy supplied by the owner.

## Reporting a vulnerability

There is currently no hosted vulnerability reporting service or public issue tracker for this product. Do not send exploit details or confidential data through public channels. Keep security reports private and provide only a minimal reproduction after the owner has established a trusted contact method. Do not include live profiles, credentials, subscription tokens, database backups, private keys, VPS addresses or unlock material in a public artifact. No response or disclosure timeline is provided.

The supplied product versions are Universal `1.1.3` and protected ZgoCloud `1.1.3-zgocloud`. Record the exact installed version and upgrade constraints; do not assume an unknown installation was validated.

## Boundaries

- Public administration remains HTTPS 9443 with authentication, MFA support, CSRF/origin checks, bounded requests, roles and rate limits. Trusted TLS is required. WebUI bans use the validated socket peer and scope to the management port; SSH protections remain independent.
- The user portal has separate credentials and limited fields. Privileged mutations cross a local validated bridge; core statistics and root-control sockets are not public management listeners.
- The protected ZgoCloud manager is authenticated ciphertext. Encrypt-then-MAC verification precedes decryption; separate PBKDF2-derived encryption/authentication keys protect the envelope. Unlocks are read from a controlling terminal or a protected file, never a secret-valued command argument.
- The owner unlock remains private. Public ciphertext permits offline guesses; keep the existing high-entropy unlock protected. Anyone who obtains it can recover the embedded compatibility credentials.
- Backups include credentials, TLS keys and panel/accounting data. Explicit panel restore revokes sessions/API tokens; it retains durable accounts, MFA and subscriptions. Keep backups and their authentication keys off web roots and outside Git.
- Quotas meter authenticated payload, not provider billing bytes. Polling can overshoot. Configuration CRUD can interrupt established sessions through a core restart. These are documented operational limits, not cryptographic guarantees.

The local checks perform focused secret-pattern/path validation with explicit upstream/test-fixture boundaries. Earlier owner-aware scanning also compared source and decoded Generic payloads against privately held references. These checks are not a comprehensive security audit or proof that every secret format is recognized.

See [operational security](docs/security.md), [recovery](docs/upgrades-and-recovery.md) and [test scope](docs/testing.md).
