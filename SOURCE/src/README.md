# Installer and manager source

Edit these sources, then run `python3 tools/build.py` from the repository root. The generated root install.sh is the single-file public distribution.

| Source | Purpose |
| --- | --- |
| install.template.sh | Stream buffering, menu, platform gates, integrity checks and product dispatch |
| manager.sh | Universal installation, CLI, owned state, upgrades and recovery |
| state.py / policy.py | Validated identities, quotas, durable transactions and client profiles |
| security.py / performance.py | Scoped security controls and reversible host settings |
| certificate_reuse.sh / snapshot_compare.inc | Certificate validation and interrupted-transaction recovery |
| unlock.py | Authenticated protected-file/TTY unlock and private cleanup |
| assets_writer.template | Integrity-checked shared application archive extraction |
| fallback-web/ | Universal-only self-hosted REALITY website: hardened loopback HTTPS server.py and the generated SBOX Personal Cloud site (build_site.py --check runs during the build); see [REALITY handshake target](../docs/reality-fallback.md) |
| helper-baselines/ | Three-way merge bases for the separately held private ZgoCloud variant |

Product versions are declared in assets/release.json (Universal 1.0.0 and protected 1.0.0-zgocloud). Public builds reuse its envelope. Original private manager source, identities, YAML and unlock remain outside Git. See [development](../docs/development.md), [architecture](../docs/architecture.md) and [release pins](../assets/release.json).
