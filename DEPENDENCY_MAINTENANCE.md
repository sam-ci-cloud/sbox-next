# Dependency and core maintenance

## Automation policy

- Routine npm and GitHub Actions version-update PRs are disabled (`open-pull-requests-limit: 0`); review them during maintenance. Dependabot vulnerability alerts and security-fix PRs remain enabled.
- Go **version updates are controlled/manual**. The generic Go Modules updater previously failed on this patched sing-box graph; it has not been repaired. Its `gomod` version-update entry is intentionally omitted, rather than presenting a failing updater as a working update service.
- The three product CI jobs remain enabled. The security job checks declared Go/npm advisories and the compiled shipped core with a pinned govulncheck scanner. Go version-update scheduling and vulnerability checks are separate controls.
- Before each release and during a weekly maintenance review, inspect dependency alerts and run the existing advisory/core security checks. The complete workflow can be requested with `gh workflow run publication.yml --ref main`. A maintainer must perform this review; no background manual process is implied.

The observed updater problems included an anthropic-sdk-go transitive resolution error involving `cloud.google.com/go/compute/metadata`, a plain sagernet/tailscale release declaring `tailscale.com` instead of the patched fork's module path, and a cronet-go root release without the corresponding `/all` submodule revision. Some release-date queries also omitted the required `v` from pseudo-versions. Official proxy metadata confirmed the pinned fork/submodule versions existed; it did not prove a proposed new dependency graph builds. Detailed original logs are retained privately. No fork was rewritten or blindly upgraded for publication.

## Controlled Go updates

1. Create a candidate branch from current main. Review a coherent upstream sing-box graph, exact fork-specific revisions, licenses, API compatibility and the SBOX accounting patches. Never replace a patched fork merely because an unpatched semver sorts higher.
2. Inspect the exact module and submodule `.info`/`.mod` responses from the official Go proxy. Check actual module directives and `v` prefixes. A root tag is not proof of a matching submodule tag. Do not add a path-changing `replace` just to suppress a resolution error.
3. Review the complete `go.mod`/`go.sum` diff and advisories. Preserve the official toolchain checksum, `GOPROXY=https://proxy.golang.org`, `GOSUMDB=sum.golang.org` and read-only module mode in `SOURCE/core-source/build.sh`. Update an intentional lockfile/provenance digest only as a reviewed candidate change; never bypass a mismatch.
4. Build the candidate core with the existing exact tags/accounting patches. Run module verification, native/accounting tests and build checks. The current repository creation did not execute a new core build.
5. Run `SOURCE/tools/audit_dependencies.py` and the pinned binary govulncheck gate from `.github/workflows/publication.yml`. A known-advisory scan is not proof of absence of unknown vulnerabilities.
6. Run focused fail-first regressions for changed behavior. A changed core invalidates dependent protocol, DNS, routing and accounting fingerprints: revalidate affected real-host/client slices and minimal management smoke before accepting it. Reuse only genuinely unchanged test dependencies.
7. Publish source, new package pin, provenance, SBOM and content-addressed release together after the candidate gates pass. Keep rollback to the previous verified package. Do not replace an existing content-addressed asset with different bytes.

## Reproducible distribution

`SOURCE/tools/build.py`, the source manifest and `SOURCE/tools/make_standalone.py` verify/assemble the package. Packaging does not require rebuilding the core. The publication CI checks that deterministic assembly matches `PUBLIC_PAYLOAD.json`. Root presentation and repository-maintenance files are outside the packaged runtime source.

The public bootstrap accepts exactly the pinned release package and full SHA-256, validates archive paths and retains staged/offline installation. It uses only this repository for SBOX publication. The source and third-party notices are included in the package; see [LICENSE](LICENSE), [NOTICE](NOTICE) and `SOURCE/core-source/`.

Never commit owner keys, envelopes, server access information, customer exports or backups. Run `SOURCE/tools/public_guard.py` over the staged/public history and release artifacts before publishing. Private literal/identity lists must stay outside Git. Keep branch protection and status checks enabled; use ordinary candidate branches and pull requests for maintenance.
