# Deployment runbook

A short operator checklist for a real server. Read [installation](installation.md), [REALITY handshake target](reality-fallback.md), [operational security](security.md) and [upgrades and recovery](upgrades-and-recovery.md) for details.

## 1. Prerequisites

- A disposable or backed-up VPS running a supported system (Universal: Ubuntu 24.04, 26.04, 26.10 or Debian 12, amd64; ZgoCloud: Ubuntu 24.04/26.04/26.10), with systemd and a root SSH session.
- A provider console or recovery path that does not depend on SSH.
- A domain whose A (and, if used, AAAA) record points at the server. The self-hosted Personal Cloud and the public panel need a publicly trusted certificate: Let's Encrypt HTTP-01 (inbound TCP 80 open during issuance), Cloudflare DNS-01 (API token) or your own certificate/key.
- Provider security group: the VPN ports printed at the end of installation (`sbox firewall ports`), TCP 9443 for the panel and TCP 22 for SSH.
- ZgoCloud only: the separately held unlock and original identity.

## 2. Install

Extract `SING-BOX.tar.gz` in `/root`, run `cd /root/SING-BOX && bash install.sh` (it verifies `SHA256SUMS` and runs the preflight) and choose **Install Universal SBOX**. Keep the defaults unless you have a reason. For the self-hosted Personal Cloud choose option 2 at *REALITY handshake target* and a trusted certificate method. Save the bootstrap administrator password (`sudo cat /etc/sbox-webui/bootstrap-admin.txt`), sign in at `https://YOUR-DOMAIN:9443`, change it and enrol MFA.

## 3. Verify

```bash
sbox doctor                      # expect: Result: 0 failure(s)
sbox reality-fallback check      # self-hosted mode: loopback HTTPS and REALITY relay
sbox security status
bash tools/vps_acceptance.sh --fail2ban-from root@SECOND_TEST_HOST   # disposable servers only
```

`vps_acceptance.sh` (from the source tree) writes a PASS/FAIL/NOT RUN summary and a redacted evidence archive. From a phone on mobile data, import a user's profile and browse; open `https://YOUR-DOMAIN/` in an ordinary browser to see the Personal Cloud website.

## 4. Upgrade

Take `sbox backup`, keep the previous installer and its SHA-256, then run the new installer and choose **Upgrade Universal SBOX** (`bash ./install.sh upgrade generic`). Users, credentials, subscriptions, plans and databases are preserved. The self-hosted website and its unit are refreshed inside the same recoverable transaction. Run `sbox doctor` afterwards; existing installations should also run `sbox security repair` once after upgrading to 1.1.1.

## 5. Rollback and recovery

- A failed install, change or upgrade restores the previous runtime automatically and says so (`the previous runtime was restored and verified` / `Feature upgrade rolled back`).
- After a crash, power loss or killed session: `sbox recover`. Do not delete journals or snapshots.
- To return to an older release, restore a matching backup with the retained older installer; see [upgrades and recovery](upgrades-and-recovery.md).
- To stop using the self-hosted website: `sbox reality-fallback remote`.

## 6. Uninstall

`sbox uninstall` keeps a final backup and Let's Encrypt lineages, removes SBOX services, the website, firewall rules and the SSH jail, and restores the distribution's own Fail2Ban SSH jail.
