# SBOX Control API v1

All API calls use the configured HTTPS origin. Cookies are Secure, HttpOnly,
SameSite=Strict. Cookie mutations require `X-CSRF-Token`; cross-origin requests
and mismatched Host headers are rejected. Proxy forwarding headers are ignored.
GET `/api/v1/health` exposes only `ok` and the API schema version. All other
`/api/v1/` routes require an account session or a scoped bearer token.

## Authentication

POST `auth/login`: `{username,password,code?}`. The optional code is a TOTP or
one-time recovery code. Returns `{csrf}` and a session cookie. Initial accounts
must POST `auth/change-password` with `{old,password}` before accessing server
data. The response rotates CSRF; other sessions and API tokens are revoked.
Passwords contain 12–256 characters and use salted scrypt N=32768,r=8,p=3.
Only two KDFs run concurrently. GET `auth/me` returns name, role, reset state,
MFA status, CSRF, schema and panel version, never a password hash.

POST `auth/logout`: `{}` revokes the current browser session. Sessions expire
after eight hours or 30 minutes idle. Sensitive operations require browser
authentication within five minutes. POST `auth/reauthenticate`: `{password}`.
POST `auth/totp/enroll`: `{}` returns a locally generated secret and otpauth URI;
POST `auth/totp/verify`: `{code}` enables it and returns eight recovery codes once.
Accepted time steps and recovery codes cannot be replayed. Root CLI reset revokes
all sessions/API tokens and removes MFA for local recovery.

## Authoritative manager changes

POST `changes/prepare` accepts `{kind,data,id?}`. Returns an expiring `token`,
redacted `diff`, `restart` boundary and warning. The manager holds its existing
lock, validates state, renders exports and executes the installed real core's
`check` before issuing the preview. No live server configuration is written.

Supported requests:

| kind | data | id |
|---|---|---|
| `inbounds` | protocol -> `{port?,enabled?}`; `vmess` also accepts boolean `multiplex` (connection reuse) | omitted; universal only |
| `policy` | `{primary?,smart_lazy?,probe_url?,expected_status?,smart_tolerance_ms?,dns?,rules?}` | omitted |
| `user-create` | `{name,tags?,protocols?}` | omitted |
| `users-import` | `{names,tags?}`; 1–100 unique names | omitted |
| `user-edit` | `{name?,tags?,enabled?}` | immutable 32-hex user ID |
| `user-disable` | `{}` | added user's ID |
| `user-revoke` | `{}` | added user's ID |

Protocols are `reality,vmess,hy2,tuic,anytls`. Names use 1–64 letters, digits,
dots, hyphens or underscores. Up to ten tags use 1–32 of the same characters.
New credentials are generated independently for each selected enabled protocol.
The original identity is protected in both adapters; all ZgoCloud listener edits
are denied. There are at most 1000 added users. On verified accounting cores, user creation may include a canonical quota plan and a separate personal portal login. Plan changes use the existing journalled preview/commit flow.

Policy `expected_status` is `200`, `204` or `200/204` and applies to both URLTest and Fallback. `smart_tolerance_ms` is an integer10–300 (default120), used by URLTest only. Probe URLs must be credential-free HTTPS without query/fragment; redirects are not health success.

Policy `dns` optionally maps `global,cn,bootstrap,proxy` to 1–8 resolvers each.
Bootstrap resolvers are IP literals. Other resolvers are IP literals or
credential-free HTTPS URLs. These are client settings; the server never fetches
them. Empty DNS overrides retain the original templates. `rules` accepts at
most 50 DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR or IP-CIDR6 rules, with
DIRECT, REJECT or `🚀 VPN` destinations. CIDR rules optionally use `no-resolve`.
Rules prepend GLOBAL/CN routing. INTERNAL retains its exact all-VPN MATCH rule.
The original LAN/CN defaults and final MATCH remain in their original order.

GET `changes/{token}` returns preview kind/expiry. POST `changes/commit` accepts
`{token}`. It consumes the token, rejects stale state, and commits through the
original journal, snapshot, validator, health check and rollback mechanism.
Core/user edits restart VPN; client policy edits use the original policy-only
transaction without a core restart. All added users are manager-state records,
never a separate SQLite copy of core configuration.

## Read routes

GET `system/status`, `system/capabilities`, `system/performance`, `inbounds`,
`users`, `policy`, `traffic`, `logs?search=...`, `security/firewall`,
`security/firewall-status`, `security/bans`, `security/status`, `certificates`,
`diagnostics/doctor`, `backups`, `client-profiles`, `subscriptions`.

Status samples have source/freshness and procfs/systemd observations. Network
totals include all host services. The traffic history is bounded to 24 hours;
the UI returns at most the most recent 360 ten-second buckets. These host-monitoring routes make no per-user or VPN-only byte attribution.
Separate authenticated accounting routes below provide per-user payload data. `logs/stream`
returns one bounded SSE event per connection; clients reconnect and reauthorize.
No public Clash/V2Ray/service API is enabled. Local sockets do not prove ISP or
provider reachability. Admin GET `audit` returns the most recent 200 events.

## Subscriptions and exports

POST `subscriptions/rotate-token`: `{id}` explicitly replaces the active link.
POST `subscriptions/reveal`: `{id}` returns the same active GLOBAL/CN/INTERNAL
URLs, format variants and setup page without rotation. Both require a fresh
administrator browser session plus CSRF. The original token-hash table remains;
an additive nonce table and a separate 0600 server key reproduce new versioned
bearers. The database alone cannot reveal a bearer. Legacy hash-only links stay
valid and are reported as active but nonrecoverable until explicitly replaced.
Missing/mismatched keys require restoration of a matching backup. POST `subscriptions/revoke`: `{id}`.
GET `/sub/{opaque-token}/{global|cn|internal}.{yaml|singbox|json|links}` uses only its
opaque token; it does not authenticate any admin route. Disabled/deleted users
and rotated/revoked tokens return 404. It has no-store, ETag/304 and a separate
120 requests/minute/IP limit. URLs contain a 256-bit secret, not a VPN UUID.

POST `client-profiles/export`: `{id,profile,format}` returns `{content}` after
fresh authentication. YAML uses the original complete manager templates;
JSON is a minimal sing-box localhost SOCKS client with native protocol
outbounds, not a translation of Mihomo geosite/rule policies. Share links use
the original manager format. None contains the REALITY private key.
POST `qr`: `{text}` returns a self-hosted qrencode SVG, with a 2048-character cap.

## Maintenance, administration and notifications

POST `actions`: `{action,arguments}`. Fixed allowlist: firewall-apply,
security-repair, unban `{ip}` (SSH only), webui-guard-repair `{}`,
webui-guard-unban `{ip}` (WebUI only), renew-test, certificate-renew, backup, recover,
restart, restore `{name,sha256}`, update-preview `{version}`, core-update
`{version}`. Restore/core update/restart/recovery/certificate renewal additionally
require `confirm_restart:true`. Versions must be explicit x.y.z. Update preview
is local only: it describes the verified pinned core retained from the installed
SBOX package (version and SHA-256) and returns 409 for any other version. No
network or GitHub request is made; newer cores ship inside SBOX installer
packages, and a root operator can import a local file with
`sbox update PATH --sha256 HEX`. The manager validates the actual candidate; it
never implicitly upgrades the ZgoCloud pin.
Backups are selected from the root-owned backup directory with a matching hash.
No arbitrary command, path, script, uploaded file or environment is accepted.

GET `security/webui-guard` returns structured local observations for the separate
WebUI login protection: owned configuration, Fail2Ban service, `sbox-webui` jail,
configured nftables action, observed kernel rules/sets and banned addresses. The
configured management TCP port is returned as `port`. Missing dependencies,
stopped services and configuration/action drift never report overall `ok`.
An idle kernel table is identified separately: the native action creates it on
the first ban. An unavailable ban list is distinct from an empty list.
`network_verification.status` remains `unknown`; local state is not proof of a
remote packet path. This protection covers admin and personal portal login,
not VPN authentication or SSH. GET is available to authenticated readers.

Both WebUI guard actions require an admin browser session reauthenticated within
five minutes and a matching CSRF token, checked again by the root bridge. Bearer
tokens cannot invoke them. Repair accepts no arguments and re-applies only the
owned WebUI jail/filter with the distribution's native nftables action; foreign
configuration is retained or refused. Unban accepts exactly one IP literal and
removes it only from `sbox-webui`. It does not modify the separate SSH jail.

GET/POST `accounts` lists/creates/disables operator accounts. Create with
`{name,password,role}` (admin or reader), disable with `{name,enabled}`. A user
cannot disable themselves. Read-only accounts can change their own password
and MFA but cannot modify manager settings. GET/POST `api-tokens` supports
`{name,scope,hours}` with read/write and 1–720 hours, or `{revoke_all:true}`.
Read tokens cannot mutate. Write tokens can prepare/commit client policy and
generate QR; sensitive secrets/core operations require a fresh browser session.

GET `notifications` returns only provider/enabled/configured flags. POST accepts
`{enabled,kind,url?,chat_id?}`. Telegram, Discord and generic webhook payloads
are redacted. Only public HTTPS port 443 destinations are accepted. Every DNS
answer must be global unicast; connections pin a validated IP and verify TLS
with the original hostname. Redirects, proxies, private addresses and metadata
destinations are forbidden. POST `notifications/test` sends a configured test.
Events are deduplicated/rate limited for five minutes. Automatic alerts observe
actual core service state and certificate expiry. No external recipient is
configured by the installer. Multi-VPS management is explicitly unavailable.

## Errors and limits

Errors return `{error}` with 400/413/415 for invalid requests, 401 for absent or
expired authentication, 403 for authorization/CSRF, 404 for unavailable routes
or user tokens, 409 for stale/concurrent changes, 422 for manager validation,
428 for initial-password/reauthentication gates, 429 for limits and 503 for
unavailable dependencies. JSON bodies are capped at 32768 bytes; no uploads.
The panel caps concurrent handlers at 24 and the root bridge at eight. Login
attempts are capped at eight per real TCP peer per 15 minutes. Authentication
headers, credential URLs and exception internals never enter HTTP access logs.

## Additions in panel 2026.10.24.1

All additions are additive; every earlier route and response field is kept.
`tools/api_inventory.py` derives the route list from the dispatcher and the test
suite fails if a route is missing from `openapi.json`.

Monitoring and diagnostics (read scope):

- GET `dashboard`: tiles `core`, `panel`, `certificate`, `listeners`, `external`
  (`external` is always `unknown` with a reason; the server cannot prove remote
  reachability), host resources with their source, open alerts, last committed
  change and a host traffic sparkline. `advanced` carries the raw bridge JSON.
- GET `system/version`: panel version, installed file integrity against the build
  manifest, manager version/build ID and core version (bridge op `version`, cached 60 s).
- GET `traffic?window=1h|24h|7d`: host-wide rates from `/proc/net/dev` counter
  deltas. Counter decreases and reboots are dropped (`resets_dropped`), missing
  samples are `gap` points, never a flat line. Not per-user VPN accounting.
- GET `protocols/health`; POST `protocols/probe` `{}` (6 per minute): loopback-only
  TCP/TLS probes; UDP inbounds are `not-probed`; `external_probe` is `not-run`.
- GET `certificates/readiness`: DNS, port-80 and renewal-timer prerequisites as
  observed on this host; public CA issuance is not claimed.
- GET `diagnostics/doctor`: the manager doctor grouped into layers with likely cause,
  next action and the equivalent CLI command; provider network and DNS/CA/ISP layers
  are `unknown`. GET `diagnostics/report`: redacted text report.
- GET `alerts`: open/recent alerts and timeline (change commits, out-of-band state
  changes, alert transitions). POST `alerts/evaluate` `{}`; POST `alerts/silence`
  `{minutes}` (admin, 0–1440; 0 clears) silences notifications panel-wide for that
  period; alerts still open and show. Notifications are sent only on state transitions.

Accounts and sessions:

- GET `auth/sessions`; POST `auth/sessions/revoke` `{id}` (one of your sessions),
  `{others:true}` (all your other sessions) or `{all_accounts:true}` (admin with a
  fresh session: every account's sessions except the caller's current one).
- POST `auth/totp/disable` `{code}`: fresh session plus a current TOTP code.
- POST `auth/reauthenticate` `{password, code?}`: `code` is required when TOTP is
  enrolled; failures are throttled per account.
- `accounts`: duplicate name 409, unknown account 404, the last enabled admin
  cannot be disabled or demoted; disabling revokes that account's sessions and tokens.
- `api-tokens`: GET lists `id, name, scope, expires, last_used` (never the secret);
  POST `{revoke: id}` revokes one token. Tokens are managed from a browser session only.

Changes:

- `changes/prepare` returns `summary` (`users` created/removed/disabled/enabled/renamed,
  `listeners`, `policy_fields`, `services`, `protected_identity`, before/after state
  fingerprints) in addition to `diff`, `restart` and `warning`. A request that would
  change the ZgoCloud legacy identity is refused with 403.
- New kind `users-bulk` `{action: disable|enable|revoke, ids:[...]}`; the legacy
  identity, duplicates and unknown IDs are refused.
- `changes/commit` returns `{committed, kind, committed_at, state_fingerprint,
  service_active, core_pid, restarted}` from the manager after verification.

Subscriptions:

- POST `subscriptions/settings` `{landing_page: bool}` (admin, fresh session).
  When enabled, GET `/sub/{token}/` serves a personal page (CSP `default-src 'none'`
  plus its own CSS/JS, QR codes as data URIs, no admin data, `?lang=en|zh`).
- Subscription YAML responses carry `Profile-Update-Interval: 24`.
- Unknown or revoked tokens return 404 without data; guessing is rate-limited per client (429).

Errors: every error body is `{error, status}`; 429 carries `Retry-After`;
database uniqueness conflicts map to 409.

## Personal dashboard and plan forms

GET `system/timezones` returns system IANA identifiers with ISO country hints.
POST `plans/preview` validates `{amount,unit,unlimited,period,reset_day,timezone,
no_expiry,expiry_local,expiry_fold?,original_expires_at?}`. Amount is a decimal
string; units are B/KB/KiB/MB/MiB/GB/GiB/TB/TiB. It returns canonical integer
bytes, the plan, explicit UTC/local expiry and next reset. Nonexistent local DST
times are rejected; repeated times require earlier/later selection. Unedited
existing expiry minutes retain their exact instant. This preview never changes
a stored plan. Admin and CSRF required.

GET `accounting/history?id=...&window=24h|7d|30d|90d|custom` and personal
GET `portal/me/history` share the same bounded builder. Custom selections use
`start=YYYY-MM-DD&end=YYYY-MM-DD` inclusive local dates and optional `timezone`.
Epoch start/end are explicit and end-exclusive; today is clipped to now. Short
windows use real hourly source buckets. Daily windows use sparse 15-minute bins
retained for 90 days plus a local-day edge margin. Missing/pre-collection values
are null; recorded zero is zero; partial values are measured lower bounds.
Frozen older UTC daily aggregates are disclosed separately without inventing
local-day splits. Range totals and current reset-cycle usage are distinct.

The personal API uses its own HttpOnly session bound at root to one user ID.
GET `portal/session` validates it and recovers CSRF for a new tab. After the
initial password change, POST `portal/me/connection` `{}`, `me/qr` and `me/export`
`{profile,format}` operate only on that user. No user ID is accepted. QR is
generated locally from the exact currently active URL. POST `me/replace-link`
and `me/revoke-link` require `{confirm:true}`; old subscription URLs immediately
stop working. Existing static VPN identities are unchanged. All these POSTs
require personal CSRF. Neither read-only operators nor API bearer tokens may
reveal personal connection secrets. Secrets use no-store/no-referrer responses
and are omitted from audit details and routine access logs. Backups pair the
panel database with its separate recovery key.

## NEXT connection intents

The API schema stays v1; panel/product version is 1.11.0 Copying a subscription link performs no export or QR request. `portal/me/qr` encodes the selected active subscription URL. `portal/me/export` returns the actual selected YAML / sing-box full profile / basic JSON / links content. Administrative equivalents remain `qr` and `client-profiles/export`.

POST `portal/me/node-qr`: `{profile,index}` (index 0–15, integer) returns a single-node URI QR. Root derives the user from the portal session and exports that user's nodes; HTTP callers cannot supply an identity, URI or arbitrary text. The portal cookie and matching CSRF header are required. A revoked/disabled session or forced password change blocks the request. Invalid selection is rejected; no matching node returns 404. QR SVG and exports use no-store responses. Individual-node exports are distinct from automatically updating subscriptions.


Network integration: GET /api/v1/network is admin-only and reports observations, not external reachability. POST changes/prepare accepts kind=network with explicit preset or four advanced policies, deployment scope, saved addresses and optional panel_family. Commit is single-use, backs up first and may restart VPN/HTTPS; reconnect and inspect outcome if the HTTP session ends. Protected network identities cannot migrate.

Client exports, portal exports/QR and subscription downloads accept optional endpoint=auto/domain/ipv4/ipv6. Only available listener families are allowed. The HTTPS subscription origin and bearer stay unchanged; TLS SNI stays the configured domain. No endpoint selector authorizes access to another user.

## Connect & Export Center (1.10.0)

All connection details are described by one catalog (`backend/export_catalog.py`) and rendered by one
shared component (`/export-center.js`, `/export-center.css`) in the console, the personal portal and the
subscription landing page.

- `POST subscriptions/reveal`, `POST portal/me/connection` and the onboarding result include `catalog`:
  clients (Mihomo: `yaml`; sing-box: `singbox` complete profile, `json` basic SOCKS proxy), routing
  profiles, server-address choices with addresses, connection methods, bilingual labels, file names and the
  subscription URLs (`urls[profile][format]`) when the active link can be shown.
- Format `singbox`: complete sing-box profile (sing-box 1.12+): the same nodes and groups as `json`
  plus DNS, routing for the selected profile (the same rules, in the same order, as the Mihomo profile: general browsing keeps private
  addresses and the administrator's custom rules; the internal profile has no direct rules; mainland
  China direct uses inline rule sets from the committed offline snapshot `backend/cn_rules.json`; no rule data is
  downloaded), a TUN inbound and a local mixed proxy on 127.0.0.1:2080. Nodes on a domain become URL-test groups of
  per-family (QUIC) and published-address candidates that keep the node tag.
  `json` (basic SOCKS bundle on 127.0.0.1:1080) is unchanged for existing consumers.
- GET `/sub/{opaque-token}/qr?kind=sub&profile=&format=&endpoint=` or `?kind=node&profile=&endpoint=&index=`
  (landing page only, opt-in like the page): returns `{svg}` for this token's own subscription URL or
  single-node link; free-form text is refused.
