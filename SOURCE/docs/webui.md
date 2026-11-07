# WebUI, portal and subscriptions

## Administrator console

The console serves HTTPS on TCP 9443. It accepts any source IP subject to authentication, MFA/session policy, rate limits and scoped temporary bans. It does not require an administrator CIDR allowlist, an SSH tunnel or a VPN-only network.

A trusted certificate and matching domain are prerequisites for a public console. A certificate-free or explicitly self-signed Universal VPN installation can retain CLI/VPN operation while the public panel waits for trusted TLS. Configure the certificate, then use `sbox webui install`; inspect `sbox webui doctor`. Do not bypass browser security warnings.

Initial credentials are root-only at `/etc/sbox-webui/bootstrap-admin.txt`. Change the initial password, enroll MFA and retain recovery codes privately. Root can reset the bootstrap administrator with `sbox webui reset-admin`; this is a deliberate credential recovery action, not routine maintenance.

The console manages independent users, per-user plans/usage, client exports, subscription tokens, QR codes, host monitoring, probes, alerts, notifications and diagnostics. Privileged changes use the validated local bridge; the browser does not execute arbitrary root commands. Administrative roles and API scopes remain enforced.

### Layout, forms and overlays

The console and portal use the full browser width after the sidebar and page padding; paragraphs, help text and form groups keep a readable measure. Data allowances use one decimal preset set (Unlimited, 10, 50, 100, 500 GB) with GB/TB as the primary units; MB, GiB, TiB and smaller units are under *Other units*, with a plain explanation that 1 GiB is about 7% more than 1 GB. Stored byte values are unchanged. The plan summary shows the selected amount and next reset; the exact byte count is an optional detail.

The time-zone search covers the server's complete IANA list (city, country/region, identifier, common localized names and current UTC offset such as `+8`), shows the number of matches and never truncates results. If that list cannot be loaded, the browser's own list is used and labelled, with a retry button. A saved time zone is kept when a plan is edited.

Layering uses one documented scale (`--z-topbar`, `--z-scrim`, `--z-sidebar`, `--z-dropdown`, `--z-skip`, `--z-toast`, `--z-overlay` in `css/00-tokens.css`). Dialogs and combobox lists use the browser top layer; lists are anchored to their input, flip upwards when there is no room below, stay inside the viewport, scroll internally and close with Escape or an outside click. Password fields leave room for password-manager icons, and new passwords are confirmed before anything is sent.

## User portal

The personal dashboard is `/portal` on the same HTTPS origin. It has Overview, Usage, My connection, Plan and Account sections. Portal credentials are separate from administrator and VPN authentication. Users must change an initial password before accessing personal data. Every request is scoped to the signed-in user; no administrator or other-user data is exposed.

Select 24 hours, 7/30/90 days or inclusive custom local dates. Charts distinguish measured zero from missing and partial observations, and provide a table and CSV. Quota-cycle totals can differ from historical date ranges.

See [users and quotas](users-and-quotas.md) for creation and CLI plan actions.

## Subscriptions and QR codes

Retrieve the same active subscription from the user Connection tab or personal My connection page. Viewing does not rotate credentials. Choose GLOBAL/CN/INTERNAL and YAML/JSON/protocol links; copy the URL, show its server-local QR, or download a static profile. Subscription URLs refresh in the client, while static files do not.

The legacy database stored only hashes, so older links remain active but cannot be reconstructed. Replace them explicitly only after warning affected users. New links use a separate server recovery key paired with the panel backup. If the key is unavailable, restore a matching backup instead of silently issuing a different link.

Issue subscriptions from the authenticated console. Tokens and export URLs are credentials: reveal/share them only with their intended recipient. Preserve token URLs during upgrades. Revoke a lost token explicitly rather than rotating the whole server identity.

A managed user gets unique credentials; protected legacy/global ZgoCloud YAML keeps the exact original bytes. Original shared credentials remain one accounting aggregate. QR codes encode actual exports/subscriptions and require the ordinary distribution qrencode dependency.

## Monitoring and notifications

Host history, service/certificate health, configured DNS/TLS probes and alert rules operate within bounded storage and validated destinations. Configure only authorized probe endpoints. Notifications require an explicitly configured destination; there is no default external reporting service and no implied cross-VPS federation.

The console and portal support English and Traditional Chinese, keyboard navigation and system/light/dark appearance. Privileged changes retain exact previews, restart warnings and confirmation. [BUILD.json](../BUILD.json) pins embedded content. See [architecture](architecture.md).

## Maintenance and accounting freshness

Doctor and the WebUI performance inventory show cached APT security/other update counts, metadata freshness and the reboot-required flag. These are bounded read-only observations; an unavailable command or timeout is unknown, not zero updates. No OS packages or reboot are triggered. Accounting health combines the last validated heartbeat with storage availability and collector service status. Stale, failed or unwritable/full storage cannot be shown as ready solely because an old health file says ready. Recovery does not fabricate missing usage.
