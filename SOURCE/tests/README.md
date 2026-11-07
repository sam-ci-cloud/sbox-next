# Tests

`python3 tools/test.py` runs every top-level test_*.py here and under shared_webui/tests, using the generated `.build/src/manager.sh`. It writes suite logs/results to ignored `.build/test-results/`. `SBOX_TEST_RESULTS_DIR` can select a directory outside the checkout.

These tests exercise real functions against synthetic temporary state and local listeners, including integrity rejection, authorization, persistence, transaction recovery, quotas, portal isolation and HTTP behavior. Some security tests substitute host commands; passing them is not a new public-VPS deployment result.

Disposable systemd, browser, network, traffic and fault harnesses under shared_webui/tests are separate integration tools; they must target explicitly disposable fixtures. Detailed test output and real deployment configurations stay private. See [regression testing](../docs/testing.md) and [development](../docs/development.md).

`test_reality_fallback.py` covers the Universal REALITY handshake target (state model, manager functions with stubbed systemctl/ss, the Personal Cloud server and site, renewal restart, rollback hooks and the ZgoCloud boundary). `reality_fixture.py` holds its synthetic state and throw-away lab PKI helpers. The isolated network-namespace lab is `shared_webui/tests/lab_reality_fallback.py` (root required).
