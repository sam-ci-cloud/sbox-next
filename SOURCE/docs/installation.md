# Installation

## Public Bash installer

```bash
curl -fsSL https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh | sudo bash
```

Direct Bash URL: https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh . The repository-root bootstrap downloads this repository's content-addressed release, checks its fixed SHA-256, validates paths and then runs the local installer. With a pipe, guided input is read from /dev/tty. Without a terminal use `sudo bash -s -- install generic --yes` plus every required setup option; see [the unattended example](../examples/noninteractive.md). Permission, architecture, prerequisite, download and checksum failures stop safely.

## Package and status

SBOX ships as one standalone archive, `SING-BOX.tar.gz`. It unpacks to a single
`SING-BOX/` directory with `install.sh` at its root:

```bash
cd /root
tar -xzf SING-BOX.tar.gz
cd /root/SING-BOX
bash install.sh
```

| Path | Content |
| --- | --- |
| `install.sh` | Entrypoint: verifies the package, runs a read-only preflight, then starts the installer |
| `verify.sh`, `upgrade.sh`, `rollback.sh`, `recover.sh`, `uninstall.sh` | Shortcuts for the same commands |
| `bin/sbox-installer.sh` | Generated all-in-one installer: manager, WebUI, pinned accounting core, sealed ZgoCloud envelope |
| `manifest.json`, `SHA256SUMS` | Version, components, network policy and a SHA-256 for every file |
| `docs/` | Installation guide, test report, security review |
| `licenses/` | GPL-3.0, notices and third-party licenses |
| `source/` | Complete corresponding source, tests and build tools |

The delivery channel is recorded in `manifest.json` and
[`assets/distribution.json`](../assets/distribution.json). A `candidate` channel
means the owner's own VPS acceptance of these exact bytes is still outstanding;
see the delivery `TEST-REPORT.md` for what ran and where.

Before copying the archive to a server, compare its SHA-256 with the value in the
delivery `SHA256SUMS`. A matching checksum establishes byte integrity, not
publisher identity.

## Network use

The package needs **no GitHub** account, repository, API, Release, raw URL,
Actions artifact or mirror, and contains no code that contacts them. The VPS uses
its normal Internet access for:

- the configured distribution repositories (`apt-get update`/`install`) for
  Python, nftables, Fail2Ban, Certbot and the other listed packages;
- the ACME CA (Let's Encrypt by default) when `certbot-http01` or
  `certbot-dns-cloudflare` is selected, and the Cloudflare API for DNS-01;
- public IP discovery (`api.ipify.org`, `checkip.amazonaws.com`, `4.ipw.cn`;
  IPv6 `api64.ipify.org`, `ipv6.icanhazip.com`, `6.ipw.cn`) only when `--ipv4` /
  `--ipv6` are not given;
- DNS and time synchronisation.

The VPN core is never downloaded. The pinned, source-built accounting core is
embedded; newer cores arrive with newer SBOX packages, or are imported from a
local file verified by SHA-256 (`sbox update /path/to/file --sha256 HEX`).

## Requirements

| Requirement | Universal | ZgoCloud |
| --- | --- | --- |
| Ubuntu 24.04 / 26.04, amd64 | Supported | Supported |
| Ubuntu 26.10, amd64 | Supported | Supported (from 1.2.0) |
| Debian 12, amd64 | Supported | Refused |
| Running systemd and a root shell | Required | Required |
| 1 GiB free on `/`, 300 MiB on `/tmp`, 512 MiB RAM recommended | Checked by preflight | Checked by preflight |
| Working apt repositories | Required | Required |
| Trusted domain certificate for the public WebUI | Required | Required with original identity/SNI |

ARM64 and unlisted systems are refused. Missing bootstrap packages (Python,
OpenSSL, util-linux, CA certificates) are installed through apt before any SBOX
state is written; apt waits for a held dpkg lock (for example first-boot
unattended-upgrades) and retries transient repository errors.

Point the domain at the server, check occupied ports and open the provider
firewall: the selected VPN ports, TCP 9443 for the WebUI and TCP 80 during ACME
HTTP-01. The installer cannot configure a provider security group for you.

## Preflight (dry run)

```bash
bash install.sh preflight generic --cert existing --cert-path /root/fullchain.pem \
  --key-path /root/privkey.pem --domain vpn.example.com
```

Preflight changes nothing. It checks root, amd64, the OS matrix, systemd, free
disk space and memory, apt and the dpkg lock, an existing installation (fresh
install vs upgrade, product switch), certificate inputs (PEM, expiry, key match,
SAN coverage, key permissions), TCP 80 for HTTP-01, the Cloudflare token file and
the ZgoCloud unlock file. `install`, `upgrade`, `recover` and `rollback` run the
same checks first and stop before any change when one fails.

## Guided and unattended install

`bash install.sh` opens a menu. `bash install.sh install generic` starts the
guided Universal installer. Unattended installs pass `--yes` and explicit options;
see [the annotated example](../examples/noninteractive.md). The installer uses its
embedded accounting core; `--core`/`--binary` overrides are refused on this path.

## REALITY handshake target

When VLESS REALITY is enabled, the Universal wizard asks whether ordinary TLS on
the REALITY port should reach a remote website handshake target (default) or the
self-hosted SBOX Personal Cloud website on this VPS. The self-hosted option needs
DNS for your domain and a publicly trusted certificate. Unattended installs use
`--reality-fallback remote|self-hosted` and `--reality-fallback-port PORT`. See
[REALITY handshake target](reality-fallback.md).

## ZgoCloud

`bash install.sh install zgocloud` on a fresh authorized server, or `upgrade` for
existing protected state. Enter the separately held unlock at the private prompt
(no echo). For unattended use place it in a root-owned regular file with mode
0600 and set `SBOX_ZGO_UNLOCK_FILE` to the file's **path**. The protected domain,
REALITY identity, credentials, fixed ports, both UDP hopping ranges and the
original six-node client YAML (SHA-256
`f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b`) are
preserved. The SSH Fail2Ban jail is deferred until `sbox security setup` is run
from an SSH session (it needs a verified management source).

## Read-only verification

```bash
bash verify.sh generic
SBOX_ZGO_UNLOCK_FILE=/root/private/ZgoCloud-UNLOCK.txt bash verify.sh zgocloud
```

Verification checks every package file, then decodes the embedded manager,
WebUI archive and core and compares their SHA-256 digests; for ZgoCloud it also
authenticates and decrypts the envelope. It changes no services and needs no root.
