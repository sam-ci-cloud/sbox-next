# Noninteractive Universal setup

This example documents supported flags. `vpn.example.com` and `203.0.113.10` are reserved example values: replace them with a domain you control and the VPS's actual IPv4 before running. Prepare DNS, provider firewall and ACME HTTP-01 reachability first. Run from a root shell on a supported amd64 systemd OS.

The command uses the extracted standalone package. Copy `SING-BOX.tar.gz` to a disposable server, extract it in `/root` and run the command from `/root/SING-BOX`; `install.sh` verifies `SHA256SUMS` and runs the preflight first.

```bash
bash install.sh install generic \
  --yes --region global --node sbox --domain vpn.example.com \
  --ipv4 203.0.113.10 --ipv6 none --listen 0.0.0.0 \
  --protocols reality,vmess,hy2,tuic,anytls \
  --hy2-range none --cert certbot-http01 --email none \
  --firewall yes --tuning no --block-private yes
```

Omitting `--ports` uses the manager's validated displayed defaults. Choose explicit port assignments if other services occupy them, then permit the exact resulting set reported by `sbox firewall ports`. Hysteria2 hopping can be selected with `--hy2-range START:END` using an unoccupied supported range.

The wrapper supplies its embedded patched core; do not add a stock `--core` override. `--yes` accepts defaults and is not a bypass for invalid domains, unavailable ACME, conflicting ports or unsupported OSes. A real deployment still needs private credential storage and actual client verification. ZgoCloud uses its separate protected setup constraints and owner unlock.
