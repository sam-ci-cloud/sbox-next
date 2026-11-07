# Shared administration application

Common source for Universal and protected ZgoCloud: HTTPS administration, separate user portal, subscriptions, monitoring, MFA and persistent per-user accounting.

| Directory | Role |
| --- | --- |
| backend/ | HTTP API, authentication, database, accounting, quota policy and monitoring |
| frontend-src/ | Editable browser application and personal dashboard |
| frontend/ | Deterministically assembled deployed assets |
| privileged-bridge/ | Validated local operations, manager extension and service integration |
| api-spec/ | Public API schema and capability contract |
| licenses/ | Shipped dependency notices |
| tests/ | Synthetic regression suites and explicit disposable-fixture harnesses |
| tools/ | Frontend assembly and developer helpers |

Run `python3 shared_webui/tools/build_frontend.py --check` for source/generated parity. Ordinary assembly requires no npm packages. The root builder bundles backend, frontend, privileged-bridge, api-spec and licenses; avoid adding unrelated documents inside those runtime directories.

Real accounting requires the pinned patched core. NIC totals are not per-user billing. The HTTP console listens on 9443; the root bridge and authenticated statistics RPC stay local. See [WebUI](../docs/webui.md), [quotas](../docs/users-and-quotas.md), [security](../docs/security.md) and [testing](../docs/testing.md).

Panel display and product versions are declared for each release; API schema remains 1. Component hashes identify embedded content. See [release metadata](../assets/release.json).
