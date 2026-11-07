"""Bounded, observation-aware history shared by admin and personal views.

Epochs are UTC and interval ends exclusive. Short selections align to UTC hour
boundaries, explicitly returned to the caller. New 15-minute payload bins make
local calendar-day grouping possible for current IANA offset rules. Older UTC
aggregates are disclosed separately; they cannot be retroactively split into
local days. Missing coverage is never converted into a zero measurement.
"""
import datetime as dt
import math
import json
import re
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from common import require

RETENTION_DAYS = 90
BIN_SECONDS = 900
WINDOWS = ('24h', '7d', '30d', '90d', 'custom')


def timezone(name):
    require(isinstance(name, str) and 0 < len(name) <= 80, 'Invalid timezone')
    try: return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError): require(False, 'Choose a valid IANA timezone')


def midnight(day, zone):
    # Some zones skip midnight. Use the first real minute of that date; refuse
    # an entirely skipped calendar date rather than silently moving its date.
    for minute in range(0, 1440):
        local = dt.datetime.combine(day, dt.time()) + dt.timedelta(minutes=minute)
        candidates = []
        for fold in (0, 1):
            value = local.replace(tzinfo=zone, fold=fold).timestamp()
            if dt.datetime.fromtimestamp(value, zone).replace(tzinfo=None) == local:
                candidates.append(value)
        if candidates: return min(candidates)
    require(False, 'Selected calendar date does not exist in this timezone')


def selection(params, default_zone, now):
    require(isinstance(params, dict) and set(params) <= {'window', 'start', 'end', 'timezone'}, 'Unknown history selection field')
    window = params.get('window', '30d'); require(window in WINDOWS, 'Invalid history window')
    name = params.get('timezone', default_zone); zone = timezone(name)
    today = dt.datetime.fromtimestamp(now, zone).date()
    oldest = today - dt.timedelta(days=RETENTION_DAYS - 1)
    if window == 'custom':
        require(set(params) >= {'start', 'end'}, 'Choose start and end dates')
        dates = []
        for key in ('start', 'end'):
            text = params[key]
            require(isinstance(text, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', text), 'Use calendar dates YYYY-MM-DD')
            try: dates.append(dt.date.fromisoformat(text))
            except ValueError: require(False, 'Invalid calendar date')
        first, last = dates
        require(oldest <= first <= last <= today, 'Choose dates within the last 90 calendar days, ending no later than today')
        start = midnight(first, zone); end = min(now, midnight(last + dt.timedelta(days=1), zone))
        resolution = 'hour' if end - start <= 7 * 86400 else 'day'
    else:
        require(not ({'start', 'end'} & set(params)), 'Custom dates require the custom window')
        end = now
        if window in ('24h', '7d'):
            seconds = 86400 if window == '24h' else 7 * 86400
            start = math.floor((now - seconds) / 3600) * 3600
            resolution = 'hour'
        else:
            start = midnight(today - dt.timedelta(days=int(window[:-1]) - 1), zone)
            resolution = 'day'
    require(start < end and end - start <= 91 * 86400, 'Invalid or oversized history interval')
    return dict(window=window, timezone=name, start=start, end=end, resolution=resolution,
                oldest_date=oldest.isoformat(), latest_date=today.isoformat())


def axis(chosen):
    start, end = chosen['start'], chosen['end']; zone = timezone(chosen['timezone'])
    if chosen['resolution'] == 'hour':
        point = math.floor(start / 3600) * 3600
        while point < end:
            yield max(point, start), max(point, start), min(point + 3600, end), dt.datetime.fromtimestamp(max(point, start), zone).isoformat()
            point += 3600
    else:
        day = dt.datetime.fromtimestamp(start, zone).date()
        while midnight(day, zone) < end:
            point = midnight(day, zone); following = midnight(day + dt.timedelta(days=1), zone)
            yield point, max(point, start), min(following, end), day.isoformat()
            day += dt.timedelta(days=1)


def begin_history(db, users, logical):
    # Freeze pre-migration aggregates before ingest adds any new delta. This
    # prevents the migration day's current data appearing twice as legacy.
    db.execute("INSERT OR IGNORE INTO meta VALUES('history_tracking_started_at',?)", (str(logical),))
    for ident in users:
        inserted = db.execute('INSERT OR IGNORE INTO history_users VALUES(?,?)', (ident, logical)).rowcount
        if inserted:
            for table, resolution in (('hourly', 'hour'), ('daily', 'day')):
                db.execute('INSERT OR IGNORE INTO history_legacy SELECT user_id,?,bucket,SUM(up),SUM(down) FROM '+table+' WHERE user_id=? AND bucket>=? GROUP BY user_id,bucket', (resolution, ident, logical-91*86400))


def record_coverage(db, users, old, logical, now, poll_seconds, discontinuity, user_gaps):
    """Called in the same transaction as watermarks and authenticated deltas."""
    saved=db.execute("SELECT value FROM meta WHERE key='history_last_sample'").fetchone()
    previous=json.loads(saved[0]).get('logical_time') if saved else None
    contiguous = (previous is not None and previous == old.get('logical_time') and not discontinuity and logical == now and
                  0 < logical - previous <= max(15, poll_seconds * 3))
    tracking = float(db.execute("SELECT value FROM meta WHERE key='history_tracking_started_at'").fetchone()[0])
    if contiguous:
        point = max(previous, tracking)
        while point < logical:
            bucket = int(point) // BIN_SECONDS * BIN_SECONDS
            stop = min(logical, bucket + BIN_SECONDS)
            db.execute('INSERT INTO history_coverage VALUES(?,?,?,?) ON CONFLICT(bucket) DO UPDATE SET observed_seconds=MIN(900,observed_seconds+excluded.observed_seconds),first=MIN(first,excluded.first),last=MAX(last,excluded.last)',
                       (bucket, stop - point, point, stop))
            point = stop
    db.execute("INSERT INTO meta VALUES('history_last_sample',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps({'logical_time':logical}),))
    for ident in user_gaps:
        db.execute('INSERT OR IGNORE INTO history_gaps VALUES(?,?)', (ident, int(logical) // BIN_SECONDS * BIN_SECONDS))


def history(store, user, params, now=None):
    now = time.time() if now is None else now
    chosen = selection(params, user.get('quota', {}).get('timezone', 'UTC'), now)
    ident = user['id']; start = chosen['start']; end = chosen['end']
    with store.db() as db:
        # One SQLite read snapshot for payload, coverage and metadata.
        db.execute('BEGIN')
        user_row = db.execute('SELECT started_at FROM history_users WHERE user_id=?', (ident,)).fetchone()
        began = user_row[0] if user_row else None
        points = [dict(r) for r in db.execute('SELECT bucket,up,down FROM history_bins WHERE user_id=? AND bucket>=? AND bucket<? ORDER BY bucket', (ident, math.floor(start / 900) * 900, end))]
        coverage = [dict(r) for r in db.execute('SELECT * FROM history_coverage WHERE bucket>=? AND bucket<? ORDER BY bucket', (math.floor(start / 900) * 900, end))]
        gaps = {r[0] for r in db.execute('SELECT bucket FROM history_gaps WHERE user_id=? AND bucket>=? AND bucket<?', (ident, math.floor(start / 900) * 900, end))}
        if began is None:
            legacy = [dict(r) for r in db.execute('SELECT bucket AS time,SUM(up) AS up,SUM(down) AS down FROM daily WHERE user_id=? AND bucket>=? AND bucket<? GROUP BY bucket ORDER BY bucket', (ident, math.floor(start/86400)*86400, end))]
            old_hourly = []
        else:
            legacy = [dict(r) for r in db.execute("SELECT bucket AS time,up,down FROM history_legacy WHERE user_id=? AND resolution='day' AND bucket>=? AND bucket<? ORDER BY bucket", (ident,math.floor(start/86400)*86400,end))]
            old_hourly = [dict(r) for r in db.execute("SELECT bucket,up,down FROM history_legacy WHERE user_id=? AND resolution='hour' AND bucket>=? AND bucket<? ORDER BY bucket", (ident,math.floor(start/3600)*3600,end))] if chosen['resolution']=='hour' else []
        sampled = db.execute("SELECT value FROM meta WHERE key='sample'").fetchone()
    import json
    sample = json.loads(sampled[0]) if sampled else {}
    rows = []
    for point, left, right, label in axis(chosen):
        values = [p for p in points if left <= p['bucket'] < right]
        # Custom dates have quarter-hour-aligned contemporary IANA boundaries.
        # Short rolling windows are explicitly hour-aligned by selection().
        prior = [p for p in old_hourly if left <= p['bucket'] < right]
        observed = 0.0
        for c in coverage:
            a = max(left, c['first'], began if began is not None else right)
            b = min(right, c['last'])
            if b > a:
                outside = max(0, a - c['first']) + max(0, c['last'] - b)
                observed += max(0, min(b - a, c['observed_seconds'] - outside))
        has_gap = any(left <= g < right for g in gaps)
        before = began is None or right <= began
        if values or prior or observed > 0:
            up = sum(p['up'] for p in values + prior); down = sum(p['down'] for p in values + prior)
            state = 'recorded' if not has_gap and observed >= right - left - 0.01 else 'partial'
        else:
            up = down = None; state = 'before_collection' if before else 'unobserved'
        rows.append(dict(time=point, start=left, end=right, label=label, up=up, down=down,
                         state=state, observed_seconds=round(observed, 3)))
    require(len(rows) <= 170, 'Too many history buckets')
    known = [r for r in rows if r['up'] is not None]
    return {**chosen, 'buckets': rows, 'totals': {'upload_bytes': sum(r['up'] for r in known) if known else None,
             'download_bytes': sum(r['down'] for r in known) if known else None},
            'incomplete': any(r['state'] != 'recorded' for r in rows), 'collection_started_at': began,
            'sampled_at': sample.get('sampled_at'), 'source': 'Authenticated VPN payload by collection timestamp; not host traffic',
            'retention': {'days': RETENTION_DAYS, 'hourly_days': 7, 'local_day_bins_days': 90},
            'legacy_utc_daily': legacy,
            'legacy_note': 'Earlier UTC daily aggregates cannot be split into local days; completeness is unknown. The migration day may overlap the new chart; do not add the two tables.',
            'totals_note': 'Selected-range measured lower bound. Separate from current quota-cycle totals.'}
