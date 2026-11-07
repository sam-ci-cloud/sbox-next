# Users, accounting and quotas

Managed users have unique credentials across the enabled protocol families. The patched sing-box core supplies authenticated per-user payload statistics; accounting does not guess subscriber usage from NIC totals.

## Plans and attribution

The console supports daily, weekly, monthly or non-resetting plans, independent numeric amount/unit inputs, searchable IANA city/country timezones, reset days, expiry, pause/resume and top-ups. Daily/weekly/monthly logic is tested at calendar and timezone boundaries; a synthetic boundary test is not a claim that an entire month elapsed during deployment testing.

Uploads and downloads contribute to payload usage. Host interface traffic, protocol overhead and provider billing are separate measurements. Original shared ZgoCloud credentials are deliberately reported as one aggregate: assigning one shared profile to multiple people cannot create recipient-level attribution.

## Enforcement

Finite or expiring plans reconcile at a one-second accounting cadence with work included in the interval; the core guard is separate. Collection, IPC, database work and revocation take time. A quota can overshoot, especially at high throughput, and no byte-exact or universal maximum is promised.

Since 1.2.1 the collector also publishes, for each finite-quota user, the absolute value of that user's own core counters at which the quota is exhausted; the patched core compares its live counters every 100 ms and closes the user's flows immediately. The live-limit check runs every 100 ms, while loading a changed policy occurs once per second. A newly lowered limit or manual block can therefore take longer than one live-limit interval to apply. Historical short overshoot measurements are specific to their traffic and policy state; they are not a universal bound. Treat quotas as access limits, not exact provider billing caps.

## CLI examples

Select a real managed user ID from your console/state. The angle-bracket value below is notation, not a literal user ID:

```text
sbox quota show
sbox quota set <user-id> --bytes '5 GiB' --period monthly --timezone UTC --reset-day 1
sbox quota topup <user-id> --bytes '1 GiB'
sbox quota pause <user-id>
sbox quota resume <user-id>
sbox quota reset <user-id>
```

Use `portal account` with `--password-stdin` or a protected password file rather than a secret-valued command argument. The WebUI provides the guided equivalent. Do not paste a password, user database, subscription or original YAML into a bug report.

Accounting/panel SQLite databases persist across matching upgrades. Complete backup/restore retains durable state; an explicit historical panel restore revokes active sessions/API tokens. See [recovery](upgrades-and-recovery.md).

## Historical usage

Short windows retain hourly resolution for seven days. Local-day-ready 15-minute aggregates are bounded to 90 days plus an edge margin. Local days follow the chosen IANA zone, including 23/25-hour DST days. Old UTC daily aggregates are disclosed separately where a local-day split is unavailable. New collection does not invent older data. Admin and personal views use the same history builder, scoped to the same user.

## Original protected shared usage

The original ZgoCloud Hysteria2 and AnyTLS entries use one internal StatsService name. Their measured bytes are counted once in the original shared aggregate and displayed together; a per-protocol split is unavailable. Existing credentials and client profiles stay unchanged. When upgrading a preceding collector that omitted this name, earlier shared history is marked incomplete. Any cumulative bytes still present in the running core are observed as a combined measurement; historical times are not reconstructed. Added users retain separate counters for all five protocol families.

## Quota entry (WebUI)

The **Create VPN user** and **Edit plan** forms use an **Unlimited data** checkbox.
When unchecked, enter a positive numeric allowance and select a unit in the
native scrolling **Unit** dropdown (GB, TB, GiB, TiB, MB, MiB, KB, KiB, B).
The time-zone picker remains a searchable, scrollable list of IANA zones.
The backend validates quota values and performs the byte conversion; this UI
change does not alter accounting, reset schedules or existing saved plans.
