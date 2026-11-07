# Self-contained delivery

The delivery archive contains the installer, application, patched core, licenses, documentation and tests. A clean machine needs the package plus supported operating-system packages (apt) and network access for certificate issuance when selected. No application component or VPN core is fetched at install or runtime, and nothing contacts GitHub: no repository, API, Release, raw URL, Actions artifact, Gist, Pages site or mirror.

## Local checks

Run these checks from the reviewed source root:

```bash
python3 tools/build.py
python3 tools/pin_release.py --sync-tree
python3 tools/check_repo_identity.py
python3 tools/test_check_docs.py
python3 tools/verify_independence.py
python3 tools/verify_independence.py --artifact dist
python3 tools/scan_runtime_github.py --installer install.sh [--unlock-file /private/ZgoCloud-UNLOCK.txt]
```

The scanner checks source, generated managers and recursively decoded gzip/ZIP/tar payloads. It rejects retired product-repository URLs, encoded dependencies, unresolved Git submodules and LFS pointers. It does not execute scanned content. `scan_runtime_github.py` additionally rejects any GitHub host, GitHub mirror (ghproxy, gh-proxy, ghfast, jsDelivr `/gh/`) or `git clone/fetch/pull` in every runtime file, in the generated installer with its embedded manager, WebUI archive and Personal Cloud bundle decoded, and — with the owner unlock — in the decrypted ZgoCloud manager. Documentation may cite the exact reviewed upstream provenance and public publication URLs. Runtime GitHub dependencies remain forbidden; the separate repository-root public bootstrap is the explicit download boundary. OS packages (apt), ACME and DNS are the documented network requirements; the VPN core is never downloaded.

The protected ZgoCloud envelope requires owner-held private input. `tools/reseal_zgo.py --unlock-file PATH` decrypts it in memory, re-integrates the shared components, proves that every protected literal and six-node identity value and the original YAML digest are unchanged, then reseals it. Its authorized owner must verify the decrypted manager privately, preserve its original identity and compare common application components with the Universal build. Do not publish the decrypted manager, unlock, original client configuration or diagnostic responses containing credentials.

## Archive checks

Build twice from a clean source tree and compare installer digests. Repeat the build and read-only installer verification without network access. Inspect the actual delivery archive for CRC errors, duplicate or unsafe member paths, symlinks, stale hashes and secret-bearing content. Extract it into a new directory and verify all hashes before delivery. These checks establish package integrity, not successful VPN traffic or a complete live deployment.

## Deployment acceptance

Use only authorized disposable systems. Verify fresh installation, trusted HTTPS, user creation and each advertised transport with an independent client and measured upload/download traffic. Then test matching upgrades, rollback, backup/restore and reboot using privately retained verified installers and state. Recheck identities, subscription links, quota enforcement and usage history after lifecycle operations. Any undocumented application download fails acceptance.

Retain sanitized observations and missing coverage in private acceptance records. Do not mark a candidate stable from static checks, fixture screenshots or a previous report alone.

## Recovery and licensing

Retain a complete known-good installer, its expected hash and a verified matching private backup before upgrading. Preserve backup authentication material, subscription recovery keys, certificate sources and protected ZgoCloud input separately from distributable artifacts.

Source deliveries include [corresponding modified core source](../core-source/README.md), patch/build inputs, [NOTICE](../NOTICE) and [third-party licenses](../THIRD_PARTY_LICENSES/README.md). Preserve upstream copyright and provenance when rebuilding dependencies.
