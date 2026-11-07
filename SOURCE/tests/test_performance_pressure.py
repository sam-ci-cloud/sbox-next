"""Pressure diagnostics use real counter semantics; fixtures are not VPS evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('performance', Path(__file__).resolve().parents[1] / 'src/performance.py')
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


class Pressure(unittest.TestCase):
    def test_guest_ticks_are_not_counted_twice(self):
        # guest/guest_nice already contribute to user/nice; steal is separate.
        a = 'cpu 100 0 0 800 0 0 0 100 90 0\n'
        b = 'cpu 200 0 0 1600 0 0 0 200 180 0\n'
        self.assertEqual(perf.cpu_delta(a, b), {'busy_percent': 20.0, 'steal_percent': 10.0})

    def test_missing_reset_or_zero_sample_is_unknown(self):
        for a, b in [(None, None), ('cpu 1', 'cpu 2'), ('cpu 9 0 0 0 0 0 0 0', 'cpu 1 0 0 0 0 0 0 0'), ('cpu 0 0 0 0 0 0 0 0', 'cpu 0 0 0 0 0 0 0 0')]:
            with self.subTest(a=a, b=b):
                self.assertIsNone(perf.cpu_delta(a, b))

    def test_throttle_is_fraction_of_elapsed_time_and_reset_is_unknown(self):
        before = {'nr_periods': 10, 'nr_throttled': 2, 'throttled_usec': 1000}
        after = {'nr_periods': 20, 'nr_throttled': 5, 'throttled_usec': 101000}
        self.assertEqual(perf.throttle_delta(before, after, 2), {'periods': 10, 'throttled_periods': 3, 'throttled_usec': 100000, 'throttled_wall_percent': 5.0})
        self.assertIsNone(perf.throttle_delta(after, before, 2))
        self.assertIsNone(perf.throttle_delta(before, after, 0))

    def test_cgroup_path_cannot_escape_mount_or_follow_link(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / 'cgroup'; base.mkdir()
            (base / 'unit').mkdir(); (base / 'link').symlink_to(Path(td))
            for name in ('/../', '/link', 'relative', '/system.slice/../../etc'):
                with self.subTest(name=name):
                    self.assertIsNone(perf.cgroup_directory(name, base))
            self.assertEqual(perf.cgroup_directory('/unit', base), base / 'unit')

    def test_missing_cgroup_reports_unavailable_not_zero(self):
        with patch.object(perf, 'run', return_value={'status': 'error', 'stderr': 'missing unit'}):
            row = perf.service_resources('sing-box.service')
        self.assertEqual(row['status'], 'unavailable')
        self.assertNotIn('cpu_stat', row)

    def test_manual_restart_cannot_look_like_positive_counter_growth(self):
        before={'service':{'InvocationID':'first'},'sample_monotonic':1,'cpu_stat':{'nr_periods':10,'nr_throttled':2,'throttled_usec':1000}}
        after={'service':{'InvocationID':'second'},'sample_monotonic':3,'cpu_stat':{'nr_periods':20,'nr_throttled':5,'throttled_usec':101000}}
        self.assertIsNone(perf.service_delta(before,after))
        after['service']['InvocationID']='first'
        self.assertEqual(perf.service_delta(before,after)['throttled_wall_percent'],5.0)

    def test_unit_name_allowlist(self):
        with self.assertRaises(ValueError):
            perf.service_resources('foreign.service')


if __name__ == '__main__':
    unittest.main(verbosity=2)
