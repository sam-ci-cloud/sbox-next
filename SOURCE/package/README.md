# SING-BOX (SBOX) standalone package

Copy `SING-BOX.tar.gz` to the VPS, then as root:

```bash
cd /root
tar -xzf SING-BOX.tar.gz
cd /root/SING-BOX
bash install.sh
```

`install.sh` verifies every file in this package against `SHA256SUMS`, runs a
read-only preflight of the host (root, amd64, supported OS, systemd, disk,
memory, apt, existing installation, certificate inputs, ZgoCloud unlock file)
and only then starts the verified all-in-one installer in `bin/`.

| Command | Purpose |
| --- | --- |
| `bash install.sh` | Interactive menu |
| `bash install.sh install generic` | Universal SBOX, guided |
| `bash install.sh install zgocloud` | Protected ZgoCloud (owner unlock required) |
| `bash install.sh preflight generic [options]` | Dry run: checks only, changes nothing |
| `bash verify.sh [generic\|zgocloud]` | Read-only package and payload verification |
| `bash upgrade.sh` | Automatic backup, then in-place upgrade (transactional) |
| `bash recover.sh` | Finish or roll back an interrupted change |
| `bash rollback.sh [BACKUP]` | Restore the automatic pre-upgrade backup |
| `bash uninstall.sh` | Remove the runtime; backups and certificates are kept |

No GitHub access is used or needed. The host uses its normal Internet access for
apt packages, ACME certificates (when selected), DNS and time synchronisation.

Full guide: `docs/INSTALLATION-GUIDE.md`. Test evidence: `docs/TEST-REPORT.md`.
Security notes: `docs/SECURITY-REVIEW.md`. Source and build tools: `source/`.
