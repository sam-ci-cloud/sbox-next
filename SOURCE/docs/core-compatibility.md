# Compatible accounting core updates

The bundled core is sing-box 1.14.4 with the SBOX accounting patch. Product 1.5.0 and engine versions are separate.

```bash
sbox update latest --yes
sbox update 1.14.4 --yes
sbox update beta --yes
sbox update pinned --force
```

The resolver reads stable versions from the official Go module proxy, orders semantic versions, filters prereleases for stable requests and caches metadata for one hour. Exact versions remain selectable. It never substitutes an unpatched upstream binary. Source ZIPs and module dependencies are checked by Go's checksum database. The compiler is the independently checksum-verified official Go 1.25.14 toolchain, which is validated with this patch; compiler pinning does not pin the engine.

Each new candidate must accept the full accounting patch, pass the real native Go tests, build with upstream linker flags and report its exact version and accounting build tag. SHA-256, source module sums, compiler, build tags, patch hash and coverage are recorded. The running configuration is checked before the existing manager's recoverable transaction replaces anything. A failed build or incompatible configuration keeps the running core. A cache is root-owned and private; cached binaries are rehashed before use. Failed compatibility observations expire after one day or when the patch changes.

Upstream 1.14.3 replaced `Server.Close` with a lifecycle scope. SBOX 1.1.x carried a patch for the older API, so its resolver rejected 1.14.3 and 1.14.4. The 1.2.0 patch is ported to the scope API: it applies to 1.14.3 and 1.14.4 and 1.14.4 passes the native tests, builds reproducibly and passed real five-protocol accounting tests on authorized VPS. Building 1.14.2 or older now needs the 1.1.x patch; an SBOX 1.1.x package rollback restores its own 1.14.2 core. A product upgrade activates the newer bundled core in one transactional restart. These results do not predict compatibility with an unseen future release. The public source includes the patch and complete corresponding source for the bundled core.

Source builds require distribution git and several GB of free disk/cache space. Small servers can use the already tested bundled core or a trusted release/cache rather than compile on the VPS. ARM64 source selection exists, but deployment/accounting activation remains limited to the validated amd64 platform. No ARM64 acceptance is claimed.

Before updating, keep an authenticated backup:

```bash
sbox backup
sbox update latest --yes
# Restore the exact backup path printed by backup, if needed:
sbox restore /var/backups/sbox-manager/YOUR-BACKUP.tar.gz --force
```

A deliberate downgrade requires explicit confirmation (`--force` for unattended use). Existing users, private identities, quotas and accounting databases are retained. Schema validation checks digest provenance rather than a single hardcoded engine version. An arbitrary stock binary is still refused while accounting is enabled.

The 1.5.0 binary is rebuilt with Go 1.27.3 and targeted security dependency updates. The accounting patch is unchanged. The new digest and complete corresponding source are recorded in core-source/BUILD_PROVENANCE.json. Baseline hashes are provenance, not valid replacement binary pins.

Explicit dynamic source builds now use the pinned Go1.27.3 compiler, security dependency minimums, OSV declared-module checks and compiled Go vulnerability scanning. Security floors never downgrade newer dependencies. Unqualified old cached binaries and old compiler caches are excluded. Unavailable security services or failed findings retain the running core. These builds require proxy.golang.org, sum.golang.org, go.dev/dl.google.com, api.osv.dev and vuln.go.dev. Compiled accounting coverage is not equivalent to a complete release protocol/client campaign; validate a custom future engine before production rollout. The shipped pinned binary has its own full acceptance evidence.
