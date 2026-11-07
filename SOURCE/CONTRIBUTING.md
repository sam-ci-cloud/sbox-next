# Contributing to SBOX

Start with the [architecture](docs/architecture.md), [development setup](docs/development.md) and [testing guide](docs/testing.md). Keep changes focused and preserve the existing CLI, protocol identities, quota semantics and upgrade paths.

## Local checks

```bash
python3 shared_webui/tools/build_frontend.py --check
python3 tools/build.py
python3 tools/check_project.py
python3 tools/test.py
```

Distribution dependencies and optional core build prerequisites are in the development guide. Test results are generated under `.build/test-results/`, not committed as new product documentation. Record actual failures and skipped tests in your pull request.

Edit `src/` and `shared_webui/frontend-src/`, not the generated installer or frontend bundle. If changing a bundled component, regenerate its output and explain its integrity impact. Common runtime changes must also reach the protected ZgoCloud variant through the owner-held private reseal process. A public contribution must never include that private source, unlock or original plaintext YAML.

Run real authenticated traffic and upgrade/recovery checks when changing protocols, the core, accounting or transactional state. Configuration parsing and a listening port are not substitutes for VPN traffic. Do not weaken authentication, TLS, accounting, assertions or recovery guards to make a test pass.

## Pull requests and issues

Describe the concrete problem, final behavior, affected source and validation. Use reserved documentation addresses in examples. Remove credentials, tokens, subscriber identifiers, public deployment addresses and personal data from logs. Do not submit a database, profile, original ZgoCloud YAML or an owner handoff.

Discuss substantial architecture or compatibility changes before implementing them. Security reports follow [SECURITY.md](SECURITY.md). Contributions retain the repository's existing licensing; third-party code needs compatible provenance and notices.
