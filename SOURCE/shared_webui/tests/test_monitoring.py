"""Constructed-counter regressions for host rate aggregation.

These are deterministic unit tests, not evidence of a live traffic measurement.
"""
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('SBOX_WEBUI_ROOT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT / 'backend'))
import monitor  # noqa: E402


def sample(t, rx, tx=None, uptime=None):
    return {'sampled_at': t, 'uptime_seconds': t if uptime is None else uptime,
            'network': {'eth0': {'rx': rx, 'tx': rx if tx is None else tx}}}


def segments(points):
    """The chart consumes gap markers as breaks between line segments."""
    result = [[]]
    for point in points:
        if point.get('gap'):
            result.append([])
        else:
            result[-1].append(point)
    return [segment for segment in result if segment]


class HostRateAggregation(unittest.TestCase):
    def test_24h_gap_survives_a_bucket_containing_valid_data(self):
        history = [sample(100, 0), sample(130, 300), sample(280, 9000),
                   sample(310, 9600), sample(340, 10800)]
        rates = monitor.rate_series(history, 86400, now=350)
        self.assertEqual(rates['gaps'], 1)
        self.assertEqual(sum(bool(p.get('gap')) for p in rates['points']), 1,
                         'reported gap must reach the chart, even in a nonempty bucket')
        lines = segments(rates['points'])
        self.assertEqual(len(lines), 2, 'the chart must not connect across the outage')
        self.assertEqual([[p['rx_bps'] for p in line] for line in lines], [[10], [30]])
        self.assertEqual([p['t'] for p in rates['points']],
                         sorted(p['t'] for p in rates['points']))

    def test_both_sides_of_a_gap_in_one_bucket_keep_their_measurements(self):
        history = [sample(100, 0), sample(130, 300), sample(280, 9000), sample(295, 9300)]
        rates = monitor.rate_series(history, 86400, now=300)
        self.assertEqual([[p['rx_bps'] for p in line] for line in segments(rates['points'])],
                         [[10], [20]], 'averaging across the missing interval hides measured changes')
        self.assertEqual(sum(bool(p.get('gap')) for p in rates['points']), 1)

    def test_7d_bucket_preserves_multiple_outages(self):
        history = [sample(100, 0), sample(130, 300), sample(280, 9000),
                   sample(310, 9600), sample(460, 18000), sample(490, 18900)]
        rates = monitor.rate_series(history, 7 * 86400, now=500)
        self.assertEqual(rates['bucket_seconds'], 3600)
        self.assertEqual(rates['gaps'], 2)
        self.assertEqual(sum(bool(p.get('gap')) for p in rates['points']), 2)
        self.assertEqual([[p['rx_bps'] for p in line] for line in segments(rates['points'])],
                         [[10], [20], [30]])

    def test_latest_uses_actual_sample_time_and_rate_in_every_window(self):
        history = [sample(100, 0), sample(130, 300), sample(160, 1500, 900)]
        for window in (3600, 86400, 7 * 86400):
            with self.subTest(window=window):
                rates = monitor.rate_series(history, window, now=170)
                self.assertEqual(rates['latest'], {'t': 160, 'rx_bps': 40, 'tx_bps': 20})
                self.assertEqual(rates['latest_age_seconds'], 10,
                                 'bucket centres must not make a fresh sample appear future-dated')
                self.assertTrue(all(p['t'] <= 160 for p in rates['points']))

    def test_trailing_gap_does_not_refresh_latest_measurement(self):
        history = [sample(100, 0), sample(130, 300), sample(280, 9000)]
        rates = monitor.rate_series(history, 86400, now=300)
        self.assertTrue(rates['points'][-1].get('gap'), 'no line extends into an unmeasured interval')
        self.assertEqual(rates['latest']['t'], 130)
        self.assertEqual(rates['latest']['rx_bps'], 10)
        self.assertEqual(rates['latest_age_seconds'], 170)

    def test_gap_only_history_does_not_invent_a_rate(self):
        rates = monitor.rate_series([sample(100, 0), sample(280, 9000)], 86400, now=300)
        self.assertEqual(rates['gaps'], 1)
        self.assertEqual(len(rates['points']), 1)
        self.assertTrue(rates['points'][0].get('gap'))
        self.assertIsNone(rates['latest'])
        self.assertIsNone(rates['latest_age_seconds'])
        self.assertIsNone(rates['stats']['rx_max'])

    def test_uninterrupted_bucket_still_averages_valid_samples(self):
        history = [sample(100, 0), sample(130, 300, 600), sample(160, 1500, 900)]
        rates = monitor.rate_series(history, 86400, now=170)
        self.assertEqual(len(rates['points']), 1)
        self.assertEqual(rates['points'][0]['rx_bps'], 25)
        self.assertEqual(rates['points'][0]['tx_bps'], 15)
        self.assertEqual((rates['gaps'], rates['resets_dropped']), (0, 0))

    def test_counter_and_uptime_resets_still_drop_unsafe_deltas(self):
        history = [sample(100, 0, uptime=1000), sample(130, 300, uptime=1030),
                   sample(160, 10, uptime=1060), sample(190, 610, uptime=1090),
                   sample(220, 10, uptime=5), sample(250, 910, uptime=35)]
        rates = monitor.rate_series(history, 86400, now=260)
        self.assertEqual((rates['resets_dropped'], rates['gaps']), (2, 0))
        self.assertEqual(rates['points'][0]['rx_bps'], 20)
        self.assertEqual(rates['latest'], {'t': 250, 'rx_bps': 30, 'tx_bps': 30})
        self.assertEqual(rates['latest_age_seconds'], 10)
        self.assertTrue(all(p['rx_bps'] >= 0 and p['tx_bps'] >= 0 for p in rates['points']))

    @unittest.skipUnless(hasattr(time, 'tzset'), 'POSIX timezone switching is required')
    def test_bucket_and_gap_timestamps_do_not_depend_on_host_timezone(self):
        history = [sample(100, 0), sample(130, 300), sample(280, 9000), sample(310, 9600)]
        original = os.environ.get('TZ')
        outputs = []
        try:
            for zone in ('UTC', 'Asia/Hong_Kong', 'America/New_York'):
                with patch.dict(os.environ, {'TZ': zone}):
                    time.tzset()
                    outputs.append(monitor.rate_series(history, 86400, now=320))
        finally:
            if original is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = original
            time.tzset()
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])


if __name__ == '__main__':
    unittest.main()
