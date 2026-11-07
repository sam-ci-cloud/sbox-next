# Development and reproducible builds

## Requirements

Ordinary assembly uses Linux tooling, Python 3.11 or newer, Bash and standard core utilities. It has no npm or private-owner dependency and performs no core compilation. Git is used for development/release operations and a private-helper merge, not required on a target VPS.

On Ubuntu/Debian, the full regression environment uses ordinary distribution packages:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-yaml python3-h2 openssl qrencode libqrencode4 shellcheck nodejs fail2ban python3-systemd nftables python3-cryptography sudo git
```

Tests use synthetic temporary data and local listeners. Some native/systemd/network-namespace suites require disposable root fixtures and are distinct from the routine nonroot suite. Do not point test helpers at a live server.

The optional native browser regression checks use Node.js 20+ and the exact
Playwright version in package-lock.json. They exercise the real CSS, menu
scroll handler and usage chart tooltips with labelled temporary browser fixtures:

```bash
npm ci --ignore-scripts --no-audit --no-fund
node node_modules/playwright/cli.js install --with-deps chromium
npm run test:browser
```

CI runs these checks separately from the dependency-free JavaScript logic
tests. `SBOX_BROWSER_EXE` can select an existing compatible Chromium executable.
These fixtures do not establish live VPN, deployment or authenticated UI
acceptance. Node.js, npm and Playwright are not VPS application dependencies.

## Ordinary build

```bash
python3 shared_webui/tools/build_frontend.py --check
python3 tools/build.py
sha256sum -c install.sh.sha256
python3 tools/check_project.py
python3 tools/test.py
```

**Reproducible bytes need stock zlib.** The installer embeds gzip streams produced by Python's `zlib`. The recorded bytes come from Ubuntu 24.04's stock zlib 1.3 (`python3 -c 'import zlib;print(zlib.ZLIB_RUNTIME_VERSION)'` prints `1.3`). zlib-ng or another fork produces different, equally valid streams, so `tools/build.py` refuses to run when it detects one (`SBOX_ALLOW_NONSTANDARD_ZLIB=1` overrides for a non-release experiment only).

The builder writes `.build/`, BUILD.json and install.sh; it does not edit authoritative runtime source or reseal the private manager. The supplied wrapper, readable helpers, common frontend/backend, sealed envelope and compressed core determine its bytes. A clean copy of the supplied source must reproduce the installer recorded in the local metadata. The frontend is concatenated deterministically from frontend-src; use its builder without `--check` after an intentional edit, then review generated changes.

## Accounting core

```bash
bash core-source/build.sh
```

The separate core build downloads the SHA-256-pinned Go 1.27.3 toolchain from go.dev and go.sum-verified modules from proxy.golang.org only (no direct VCS/GitHub fallback), runs native accounting regressions and requires the exact manifest binary digest. It needs substantial temporary disk/cache space and network access. This is developer work; VPS installation uses the embedded binary. The complete upstream-derived source, patch and build provenance remain under core-source/ with original licenses and notices.

## Protected ZgoCloud reseal

Public assembly bundles the **existing sealed envelope reproducibly**. Resealing changed protected content is a separate owner operation with fresh encryption randomness:

```text
python3 tools/seal_zgo.py --manager /private/zgocloud-manager.sh --unlock-file /private/unlock --legacy-yaml-file /private/ZgoCloud-original.yaml
python3 tools/build.py
```

These are operator-controlled paths outside Git. The original supplied manager/YAML/unlock are not public fixtures. Do not substitute a generated approximation or rotate the six-node identity. The original YAML compatibility digest is `f42beb782d5f2207cd211ed0c43be33402d596ca5cb46a1ed5c757babe30070b`.

Public Generic helper baselines support a three-way merge into the private variant; conflicts stop before sealing without printing private source. A shared runtime edit must reach both products. Re-run protected verification, exact YAML comparison and relevant real traffic/upgrade regressions before releasing changed runtime bytes. A documentation-only change should not reseal or change the installer.

## Refreshing the sealed ZgoCloud manager

A shared runtime change (core source, WebUI, bridge, helpers) must reach the protected product too. With the owner unlock outside the tree:

```text
python3 tools/reseal_zgo.py --unlock-file /private/ZgoCloud-UNLOCK.txt
python3 tools/build.py && python3 tools/pin_release.py --sync-tree
```

The tool decrypts the envelope in memory, verifies its manager digest and the original YAML digest, re-integrates shared components through `tools/build.py`, refuses to seal if any protected literal or six-node identity value would change, and seals with fresh randomness.

## Standalone package

```text
python3 tools/make_standalone.py --output dist --doc INSTALLATION-GUIDE.md=PATH --doc TEST-REPORT.md=PATH --doc SECURITY-REVIEW.md=PATH
```

The archive is deterministic for equal inputs (sorted members, root ownership, fixed mtime, timestamp-free gzip; build with stock zlib).

## Generated output and releases

`.build/`, `.cache/`, dist/, private data, runtime databases and owner handoffs are ignored. `tools/package.py` creates a deterministic public source ZIP from the reviewed source tree without requiring Git metadata, then checks its archive layout. Private engineering logs and handoffs never enter the source archive or release. [Regression testing](testing.md) describes the maintained checks. Follow [releasing](releasing.md) for a new tag and asset checksums.
