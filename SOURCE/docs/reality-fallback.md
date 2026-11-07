# REALITY handshake target: remote website or self-hosted Personal Cloud

[繁體中文（香港）](reality-fallback.zh-HK.md)

VLESS REALITY accepts authenticated clients with its own REALITY key pair and short ID. Every other TLS connection that reaches the REALITY port — an ordinary browser, a scanner, a probe — is relayed to a **handshake target**. Universal SBOX offers two kinds of target. ZgoCloud keeps its protected original configuration and does not offer this choice.

| | Remote website handshake target (default) | Self-hosted SBOX Personal Cloud |
| --- | --- | --- |
| What an ordinary visitor reaches | A well-known remote website you choose (`www.cloudflare.com`, `www.microsoft.com`, `www.apple.com` or a custom hostname) | A small, read-only Personal Cloud website running on this VPS |
| Certificate the visitor sees | That website's own certificate, served by that website | **Your** trusted certificate for **your** SBOX domain |
| Client SNI | The remote hostname | Your SBOX domain |
| Extra requirements | None | DNS for your domain points to this VPS and a publicly trusted certificate (Let's Encrypt DNS-01/HTTP-01 or your own certificate and key) |
| Extra public port | None | None — the website listens on `127.0.0.1` only |

**Neither mode copies, downloads or "steals" a certificate.** In remote mode SBOX only names the remote host as the relay destination; SBOX never obtains, copies or stores that website's certificate or private key. The certificate `reuse` option elsewhere in SBOX means reusing *this installation's own* still-valid certificate. The REALITY key pair is a separate REALITY credential, not a website certificate.

## Choosing during installation

The question appears only when VLESS REALITY is enabled in the Universal wizard:

```text
REALITY handshake target (what an ordinary browser or probe sees on the REALITY port):
  1) Remote website handshake target (default, current behaviour)
  2) Self-hosted SBOX Personal Cloud website on this VPS
```

Option 2 asks for the local website port (default `8443`, loopback only, 1024–65535, not `9443` and not a port already used by an enabled VPN protocol or another program). The website hostname is always the configured SBOX domain, and REALITY uses that domain as its SNI.

The certificate step then requires a publicly trusted certificate for the domain: Cloudflare DNS-01, HTTP-01, your own certificate/key paths, or reuse of this installation's own trusted certificate. Self-signed certificates are not offered for this mode. If you cannot provide a trusted certificate, choose **0 — go back** and the installer returns to the remote website target without changing anything else. A failed issuance stops the transaction and rolls it back; nothing is silently downgraded.

Unattended installs use explicit flags:

```bash
sbox install global --yes --domain cloud.example.com --protocols reality \
  --reality-fallback self-hosted --reality-fallback-port 8443 \
  --cert certbot-dns-cloudflare --cf-token-file /root/cf.token --email none
```

Without `--reality-fallback`, unattended runs keep the current mode (remote for every existing installation).

## Switching later

```bash
sbox reality-fallback status
sbox reality-fallback check                 # verified local HTTPS and REALITY relay test
sbox reality-fallback self-hosted [--port 8443] [--cert ...]
sbox reality-fallback remote [--sni www.cloudflare.com]
```

`sbox configure` offers the same choice interactively. Switching back to remote restores the remote hostname that was in use before the self-hosted mode (or the `--sni` you give). Each switch is one transaction: state, server configuration, client exports, the website unit and the certificate are applied together and rolled back together. **The client SNI changes when you switch, so re-import client profiles afterwards.** REALITY keys, short ID, UUIDs and ports do not change.

## What runs on the VPS

- `sbox-fallback-web.service` — an SBOX-owned systemd unit (marked `Managed by sbox-manager`). It starts before `sing-box.service` and is enabled only in self-hosted mode.
- The server is `server.py`, a Python standard-library HTTPS static server installed with the manager under `/usr/local/lib/sbox-manager/fallback-web/` together with the site. No Nginx, Caddy or Apache package is installed and no existing web server configuration is touched.
- Installation verifies the embedded bundle digest and manifest, stages the tree **on the destination filesystem** (a rename, never a cross-filesystem copy), sets every directory to `0755` and file to `0644` explicitly and refuses activation, naming the exact path, if any page is missing, unreadable, a symlink or not root-owned. The unit's `ExecStartPre` repeats that check as the sandboxed service user (`server.py --preflight`).
- The service runs as a transient unprivileged user (`DynamicUser=yes`) with no capabilities, a read-only bind of only the website directory, `ProtectSystem=strict`, private `/tmp` and devices, a syscall filter, `IPAddressDeny=any` except localhost, `SocketBindAllow=tcp:PORT`, `MemoryMax=96M`, `TasksMax=256` and `CPUQuota=50%`. SBOX state, backups, accounting, WebUI code and state (`/etc/sbox-webui`, `/var/lib/sbox-webui`), Fail2Ban configuration, `/var/log` and Let's Encrypt directories are inaccessible to it. A fresh install rebuilds the sandbox once after the panel is installed so that paths created later are masked too.
- **Admission is handshake-first.** REALITY relays every ClientHello on its port to this site — authenticated users' included — and needs the site's TLS handshake to complete theirs. Up to 192 concurrent TLS handshakes are accepted (5-second handshake timeout); the 32-connection bound applies only to serving pages after TLS, and a visitor beyond it receives a small `503 Service Unavailable` over the completed TLS session. Only connections beyond the handshake bound are closed before TLS. Before 1.2.0 a 32-connection pre-TLS bound let ~32 concurrent unauthenticated visitors make authenticated REALITY connections fail (measured: 26 of 120 failed under 64 parallel visitors).
- The certificate and key reach the service through systemd `LoadCredential=` from SBOX's managed live certificate; the key is never made world-readable or copied into the website directory.
- The listener accepts only `127.0.0.1` or `::1`; any other address is refused at start-up. No firewall rule is added.

### The website

The original **SBOX Personal Cloud** site has four pages — **Home**, **Files**, **Media** and **About** — plus a 404 page. Files lists a small curated read-only library (documents, spreadsheets and pictures) with sizes, dates and download buttons; Media is a gallery of original illustrations. All assets are local and original; there are no external fonts, scripts, images, analytics or third-party brands.

Security properties: `GET`/`HEAD` only (everything else returns 405), request bodies rejected, no directory listings, dotfiles, symlinks, traversal or executable content, a strict Content-Security-Policy, `nosniff`, `no-referrer`, `frame-ancestors 'none'`, bounded request lines, headers, time and concurrent connections. Requests for a different `Host` receive 421. The website is not the SBOX admin panel and exposes no SBOX status, credentials, ports or diagnostics.

The site is product content: upgrades replace it. Customising it is not part of this feature.

## Certificate renewal and health

Renewal uses the existing transactional deploy hook. When a renewed certificate is deployed, SBOX restarts the website (so systemd re-reads the credential), verifies it, restarts sing-box, and then verifies that REALITY relays an ordinary HTTPS request to the website. A failure rolls the transaction back and is recorded; `sbox doctor` then shows a warning with the time and reason.

`sbox doctor` reports, in self-hosted mode:

- the handshake target, website hostname and loopback listener;
- website files installed and the unit matching the state;
- service active and enabled;
- loopback-only listener, a certificate trusted by the system store and covering the hostname, and every page served;
- REALITY relaying ordinary HTTPS on the REALITY port to the website;
- no public firewall rule for the website port;
- the last activation failure, if any.

In remote mode it reports the remote target and that no leftover website service exists.

## Backups, upgrades and uninstall

The mode is part of the state, so backups, restores and upgrades keep it. A matching upgrade (`upgrade generic`) reinstalls the website tree and unit from the new release inside the recoverable feature transaction, restarts the service and verifies loopback HTTPS and the REALITY relay; a failure restores the previous runtime. Old states have no `fallback` object and are treated as remote mode, with the same SNI, destination and client profiles byte-for-byte. Uninstall stops and removes the SBOX-owned unit. Let's Encrypt lineages are kept as before.

## Resource use

In an offline measurement (Python 3.13, after 50 HTTPS page requests) the server used about 26 MB resident memory; the site and sample library are about 45 KB. CPU and memory are capped by the unit limits above. Your figures will vary with the Python version.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Installer refuses the certificate | It must be publicly trusted, unexpired and cover the SBOX domain. Self-signed and lab certificates are refused. |
| `sbox doctor`: website service not active | `journalctl -u sbox-fallback-web -n 50`; a `refused:` or `preflight:` line names the exact bind, certificate or file problem. |
| `site root has no index.html` / listener absent after install (1.1.0 on Ubuntu 26.10) | Fixed in 1.1.1. Ubuntu 26.10 ships the uutils (Rust) `mv`; when the old installer moved the website from `/run` to disk it recreated directories with the manager's `077` umask, so `site/` became `0700` and the unprivileged service could not read it. The transaction then rolled back, which is why the directory and unit were absent afterwards. Use the 1.1.1 installer. |
| `REALITY relays ordinary HTTPS` fails | Confirm `sing-box.service` is active and REALITY uses the SBOX domain as SNI (`sbox reality-fallback status`). |
| Port conflict | Choose another loopback port with `sbox reality-fallback self-hosted --port N`. |
| Want the previous behaviour | `sbox reality-fallback remote`, then re-import client profiles. |

## Verification status

Offline tests and an isolated network-namespace lab verify the renderer, installer functions, website, unit hardening, renewal restart, rollback hooks and both REALITY modes with the pinned core (see [testing](testing.md)). Release 1.1.1 was additionally installed end to end in disposable systemd lab machines built from the Ubuntu 26.10 (systemd 261, Python 3.14, uutils coreutils) and Ubuntu 24.04 archives: fresh install, matching upgrade, injected-failure rollback, crash recovery, uninstall and reinstall, with real VPN traffic and external HTTPS through the REALITY port. Public DNS, public certificate issuance and a real VPS remain deployment checks; run `tools/vps_acceptance.sh` on a disposable server.
