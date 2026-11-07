# Upgrades, backups and recovery

## Existing installations

The public script detects installed state and requires the matching product. It preserves protocol identity, users, credentials, plans, subscription data and databases through the supported transaction paths. Do not select fresh installation on a populated server or switch Generic/ZgoCloud products.

```bash
sbox version
sbox status
sbox doctor
sbox backup
```

Before any matching upgrade, retain the exact previously working complete installer, its SHA-256, a verified full backup, certificate sources, backup authentication material, the matching subscription recovery key and the original ZgoCloud unlock/identity when applicable. Copy these privately off the VPS and rehearse restoration on an authorized isolated system.

Test the matching upgrade on a disposable copy of the installation first. From the extracted new package:

```bash
cd /root/SING-BOX
bash upgrade.sh            # = bash install.sh upgrade; variant auto-detected
```

`upgrade.sh` verifies the package, runs the preflight, creates an automatic `sbox backup` (its path is recorded in `/var/backups/sbox-manager/PRE-UPGRADE-BACKUP`) and then runs the transactional feature upgrade. A failed upgrade rolls itself back; `bash rollback.sh` restores the recorded pre-upgrade backup (configuration, users, quotas, certificates and the backed-up core) with `sbox restore`. Explicit `upgrade generic` and `upgrade zgocloud` arguments are equivalent. The protected variant asks for the existing private unlock. An unsupported core/adapter version is refused before component staging; do not bypass that gate or blindly downgrade a newer core.

Afterward check `sbox doctor`, `sbox webui doctor`, `sbox quota show`, user IDs/credentials, subscriptions, lifetime counters and a real client. A required core/configuration restart can interrupt established streams. Per-user quota revocation is a separate path.

## Subscription and history migration

The recovery format includes recovery metadata without replacing the original hash-only subscription table. Existing links remain valid. New links are reproducible with a separate panel-owned 0600 key; preserve that key with its matching database. Losing it prevents reveal but does not authorize automatic rotation. Only an explicit replacement invalidates old subscription URLs. New release links keep the original opaque 43-character wire format so the preceding server can still serve them during a matching rollback. Keep a complete backup with its recovery key before rollback: older backup tools do not include the separate recovery key.

History collection begins with observed coverage. Pre-upgrade aggregates remain available with honest completeness limits; they are not split into invented local-day measurements. Existing counters and plans remain authoritative.

## Interrupted transaction

A failed feature upgrade attempts verified rollback. If interrupted, use:

```bash
sbox recover
```

An unresolved features.pending journal intentionally blocks mutations. Inspect its phase and diagnostics; do not delete it to unlock a change. If the installed older CLI predates feature recovery, the same complete public script supports `recover generic` or `recover zgocloud` arguments, reconstructing checked recovery code without a second application download.

During feature staging, accounting can advance its live quota policy after the installer lock is released. Recovery retains only a validated current collector policy in that explicit comparison mode; every other file and ordinary snapshot integrity remain exact. It does not replay an obsolete policy or overwrite live databases with an old upgrade snapshot.

## Intentional full restore

` sbox restore ` is different from automatic transaction rollback. Use a private archive created by `sbox backup`:

```text
sbox restore /private/backup.tar.gz
sbox restore /private/backup.tar.gz --core /private/trusted-sing-box
```

A host-authenticated archive may restore its verified archived core. An unauthenticated archive uses an independently trusted installed/operator-supplied core and does not execute the untrusted archived binary. Preserve the backup authentication key privately when planning replacement-host recovery; consult the CLI's exact trust checks before installing an archived core.

New complete archives include panel and accounting state plus the separate subscription recovery key. Explicit historical panel restore retains accounts, MFA, subscriptions and preferences while revoking sessions/API tokens. Old archives without a panel component leave the live panel database in place. Verify certificate sources and automatic renewal through the normal certificate workflow afterward.

Keep a provider-level recovery option for failures outside owned application paths, including damaged OS or disk loss. Test your recovery path before relying on it.

## Rollback source

Retain the complete previously working installer and its checksum privately before upgrading; rollback must use that verified local copy and its matching backup. Recovery should use verified local materials and must not depend on a later download remaining available. A source checkout alone is not a substitute for a retained complete installer and recoverable private state.

Automatic transaction recovery and intentional historical restore have different semantics; a historical restore replaces data and revokes browser sessions. Never overwrite a live database with an older copy merely to revert a UI change. Validate the exact old installer against the backed-up format before attempting a downgrade; do not assume a version number establishes reverse compatibility.

## Restoring a backup taken under another engine

An authenticated backup restores its own recorded core. To restore it onto a fresh installation of a newer package (for example a 1.1.x backup onto 1.2.0, whose engine is 1.14.4), pass the package's verified core:

```bash
sbox restore /var/backups/sbox-manager/YOUR-BACKUP.tar.gz --core pinned
```

Users, quotas, usage, certificates, ports and credentials are restored; accounting moves to the pinned core because it carries bundled provenance for all five protocols. The protected ZgoCloud manager keeps same-engine restore only.

## Explicit backup retention

`sbox backup retention` is a dry run. Override counts per invocation with `--keep-backups N --keep-policies N`, or set a root-only `/etc/sbox-manager/retention.json` containing `{"keep_backups":10,"keep_policies":20}`. Counts are1–1000. Add `--prune` explicitly to remove eligible old validated native backups and client-policy snapshots. The command holds the manager lock, validates contents, protects PRE-UPGRADE-BACKUP and active recovery journals, keeps at least the newest validated item, and preserves invalid/corrupt evidence for assisted inspection. It does not prune accounting last-good data, features.pending or transaction directories. No automatic deletion is scheduled. Copy private backups off-host and rehearse restore before relying on retention.
