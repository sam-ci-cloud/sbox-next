# Disposable systemd lab (LAB ONLY)

## Docker machines (current harness)

`docker_lab.sh` boots stock distribution images with systemd as PID 1 in
privileged Docker containers (Ubuntu 24.04, 26.04, 26.10 and Debian 12), installs
a throw-away lab CA and maps `lab.sbox.test` / the privately supplied `SBOX_ZGO_TEST_DOMAIN` (default fixture: `zgo.example.test`) to the
machine. The SBOX installer itself installs every runtime package through apt.

It replaces the namespace harness below, whose 12 pass / 22 fail campaign was a
harness defect, not a product failure: Docker/namespace roots use *private* mount
propagation, so systemd's per-unit `LoadCredential=` and bind mounts were
invisible to the unit (`status=200/CHDIR`, the Personal Cloud refused its TLS
credential). `docker_lab.sh` restores shared propagation (`mount --make-rshared /`)
like a real boot and gives systemd >= 258 a private cgroup2 subtree.

| Tool | Purpose |
| --- | --- |
| `docker_lab.sh image OS` / `new NAME OS CA_DIR` / `exec` / `rm` | Build, boot, enter and destroy one machine |
| `protocol_traffic.py OUTDIR --ca CA [--accounting]` | Inside a machine: real sing-box client in a separate netns; 1 MiB TCP + UDP echo over all five transports, wrong credentials refused, restart/reconnect, UDP hop-range ports, per-user accounting, exact quota block/reset, no cross-user leakage |
| `f2b_netns.sh` | Inside a machine: real sshd failures from a netns attacker; ban, SSH + VPN drop, innocent source unaffected, persistence across Fail2Ban/firewall restarts, unban, expiry |

## Namespace machines (previous harness)


These tools boot real distribution root filesystems with **systemd as PID 1** in
private PID/mount/UTS/IPC/network namespaces with a private cgroup2 mount, so the
complete standalone installer can be exercised end to end without a VPS. A
second network namespace (`NAME-peer`, 10.77.0.1) acts as an independent client
or attacker connected by a veth pair to the machine (10.77.0.2). Nothing is
installed on or trusted by the host; certificates come from a throw-away lab CA.

They are not a substitute for a real VPS: there is no public DNS, public ACME,
provider firewall or real Internet path. Use `tools/vps_acceptance.sh` on a
disposable server for that.

| Tool | Purpose |
| --- | --- |
| `make_lab.sh [suite...]` | Debootstrap Ubuntu 26.10 (`stonking`), 26.04 (`resolute`) or 24.04 (`noble`) roots and create the lab CA |
| `vm.py create/exec/destroy NAME [--base SUITE] [--peer]` | Boot, enter and destroy one machine (overlay; every write is discarded) |
| `campaign.sh NEW_INSTALLER OLD_INSTALLER SCENARIO...` | Scenarios `s_fresh`, `s_feature_rollback`, `s_crash_recover`, `s_uninstall`, `s_install_rollback`, `s_upgrade_from_published` |
| `f2b_live.sh NAME` | Real sshd login failures from the peer namespace: ban, all-port drop, collateral, restart persistence, unban, expiry |
| `traffic_acct.sh NAME [USER]` | Real VLESS REALITY traffic with a panel-created user: byte-exact delivery, per-user accounting, quota block, reset, wrong-key refusal |
| `real_shots.cjs ORIGIN BOOTSTRAP_FILE PWFILE OUTDIR USER` | Screenshots of the real installed panel with real accounting data (run inside the peer namespace) |

Typical run (root, Linux with namespaces, overlayfs and cgroup2):

```bash
export SBOX_LAB_ROOT=/var/tmp/sbox-lab
bash tools/lab/make_lab.sh stonking noble
bash tools/lab/campaign.sh "$PWD/install.sh" /path/to/previous/install.sh \
  s_fresh s_feature_rollback s_crash_recover s_uninstall s_install_rollback s_upgrade_from_published
bash tools/lab/f2b_live.sh c1
bash tools/lab/traffic_acct.sh c1
```

Lab-only fault injection: the manager honours `SBOX_LAB_FAULT=apply-website`,
`website-upgrade` or `website-upgrade-hang` **only** when
`/opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS` exists (created by `vm.py` inside the
machine). Never create that marker on a real server.
