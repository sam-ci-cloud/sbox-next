# Operational security

Read the project [security policy](../SECURITY.md) for reporting and trust boundaries.

## Public administration

Keep trusted HTTPS on TCP 9443, change the bootstrap administrator password and enroll MFA. Keep independent provider-console access and a working root SSH session when changing security policy. The WebUI remains available from any source IP; it is protected by authentication and scoped controls rather than a mandatory source allowlist.

Login failures are fixed-format journal events using the validated socket peer. Forwarded headers and submitted usernames cannot choose a ban address. The owned WebUI Fail2Ban jail uses native IPv4/IPv6 actions limited to the management port. An unrelated active jail with the same name is refused before owned configuration is written.

```bash
sbox webui guard
sbox webui unban 203.0.113.10
sbox security status
sbox security bans
sbox security unban 203.0.113.10
```

The address is reserved documentation space; substitute the actual legitimate address when unbanning. WebUI and SSH bans are independent.

### SSH protection (`sbox-sshd`)

`sbox security setup` installs the owned `sbox-sshd` jail: six failed SSH logins within ten minutes ban the source for ten minutes, and the ban is enforced by an early nftables set that drops **all ports** from that address, so a brute-forcing host also loses access to the VPN ports. Loopback, the administrator's current SSH client address and any `SBOX_MANAGEMENT_CIDRS` are allowlisted at setup, so the session running setup is not locked out.

Ubuntu and Debian enable a stock `[sshd]` jail that watches the same log events with a lower retry count but bans port 22 only. When that stock jail is defined only by the distribution's package files, SBOX disables it in its own `jail.d/sbox-manager.local` so the two jails do not race (before 1.1.1 the stock jail could fire first: the all-port guard never triggered and `sbox security unban` left SSH blocked). An `[sshd]` jail you customised in `jail.local` or another file is left untouched. Removing SBOX security or uninstalling deletes the override and reloads Fail2Ban, restoring the stock jail. Existing installations get the change with `sbox security repair`.

`sbox security bans` lists the SBOX jail and any other jail that holds an address; `sbox security unban IP` removes the address from **every** jail that holds it and prints which ones.

Release 1.1.1 was verified with real sshd login failures from a separate network namespace in Ubuntu 26.10 and 24.04 lab machines: ban, all-port packet drop (SSH and VPN 443), no collateral block of another source, persistence across Fail2Ban and firewall restarts, manual unban, automatic expiry and loopback allowlist. Repeat it on your server with `tools/vps_acceptance.sh --fail2ban-from HOST` before relying on it. Existing provider/foreign firewall policies and SSH authentication are not blanket-replaced. IPv6 namespace tests are distinct from unavailable routed public IPv6 acceptance.

## Default-drop inbound gate (1.8.0)

The managed firewall historically added only ACCEPT rules in front of an INPUT policy of ACCEPT, so any process that listened was reachable. `sbox firewall default-drop on` adds one nftables table, `inet sbox_hardening`, with policy **drop**. It allows:

- every SBOX protocol port, read from the manager's own `SBOX_INPUT` rules so it cannot drift;
- every sshd port (`sshd -T`, always);
- the WebUI port and ACME HTTP-01 when they are configured;
- replies to the host's own traffic (`ct state established,related`);
- loopback;
- essential ICMP/ICMPv6, including packet-too-big, neighbour discovery and router advertisements;
- rate-limited ping.

Hysteria2/TUIC ports are `notrack`, so QUIC adds no conntrack load. SBOX's existing tables and the fail2ban ban sets are never edited.

Safety:

- The generator refuses to render without an SSH port or without SBOX rules.
- Loads are atomic.
- `on` arms a 300 s rollback timer *before* loading and persists nothing.
- Only `sbox firewall confirm`, run after a fresh SSH login succeeds, writes `firewall.default_drop=true`.
- The gate is re-applied at every boot by `sbox-manager-firewall.service`.
- Emergency removal from a provider console: `nft delete table inet sbox_hardening`.

Hosts that used the interim 1.4.x tooling (`sbox-hardening-stage`, the same table name) keep working. After upgrading, run `sbox firewall confirm` and then `sbox-hardening-stage uninstall` to hand ownership to the manager.

## Private material

Keep profiles, subscription URLs, original ZgoCloud YAML, REALITY keys, unlocks, MFA recovery codes, databases and complete backups outside Git and web roots. Protect unattended unlock/password files with owner-only permissions. Do not capture credentials or QR pixels in screenshots for support.

Only authorized administrators should access the root-control socket or statistics RPC. These are local authenticated interfaces, not remote management endpoints. Maintain the service's least-privilege users/groups and sandbox settings rather than disabling them to silence a permission error.

## Change safety

Back up before upgrades or identity/security changes. Inspect pending transaction journals; never delete one merely to bypass a guard. Scoped failures and recovery are tested, but no software snapshot replaces an independent provider backup for disk loss or a damaged OS.

The release is not a guarantee of anonymity, censorship resistance, universal performance or freedom from unknown vulnerabilities. Quota overshoot, single-server failure domains and source/secret-scan scope are documented limits.
