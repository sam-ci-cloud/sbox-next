# Build and maintenance tools

Run from the repository root:

| Command | Purpose |
| --- | --- |
| `python3 tools/build.py` | Offline deterministic single-file assembly; reuses the sealed envelope |
| `python3 tools/check_project.py --verify-build` | Documentation, source, artifact, archive and deterministic-build gates |
| `python3 tools/test.py` | Native regression suites, with ignored logs and aggregate results |
| `python3 tools/package.py` | Deterministic public source ZIP and checksums from the reviewed source tree, with or without Git metadata |
| `python3 tools/scan_public.py --help` | Owner-aware leak gate using private references held outside Git |
| `python3 tools/seal_zgo.py --help` | Deliberate private owner reseal from the original private manager/YAML, not required for normal builds |
| `python3 tools/reseal_zgo.py --unlock-file PATH` | Owner-only: refresh the sealed ZgoCloud manager with current shared source; proves identity/YAML are unchanged |
| `python3 tools/make_standalone.py --output DIR --doc NAME=PATH` | Deterministic `SING-BOX.tar.gz` (single `SING-BOX/` directory, `install.sh` at its root) |
| `python3 tools/scan_runtime_github.py --installer install.sh [--unlock-file PATH]` | Fails on any GitHub/mirror/git-remote dependency in runtime files and decoded payloads |
| `tools/core_migration.py` | Shared, fail-closed migration from the removed network core download to the local core source (used by build.py) |
| `tools/lab/docker_lab.sh` | Disposable systemd lab machines (Ubuntu 24.04/26.04/26.10, Debian 12) as privileged Docker containers |

The focused CI secret gate and exact private-reference scanner have different scopes; neither is a comprehensive security audit. See [development](../docs/development.md) and [release process](../docs/releasing.md).
