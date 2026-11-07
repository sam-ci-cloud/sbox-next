"""Client health-check timing is an explicit, validated, end-to-end setting (D6, 1.8.0).

Fail-first: 1.7.1 hard-codes interval 60 s, probe timeout 5000 ms and max-failed-times 2
for both Anti-Block Auto and Smart Auto. The owner cannot tune failover detection, and
the UI/summary cannot show what the client will actually do.

Semantics (Mihomo): `interval` = seconds between health checks; `timeout` = per-probe
limit in ms; `max-failed-times` = failed *real connections* through the group that trigger
an immediate extra health check (not "probes before marking dead").
"""
import copy, json, subprocess, sys, unittest
import yaml
import reality_fixture as fx
sys.path[:0] = [str(fx.ROOT / 'shared_webui/backend'), str(fx.ROOT / 'shared_webui/privileged-bridge')]
from export_json import convert

SMART, ANTI = '🧠 Smart Auto', '🛡 Anti-Block Auto'


class HealthCheckSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private, public = fx.reality_keypair()
        s = fx.trusted_certificate(fx.base_state(private, public))
        for p in s['protocols'].values():
            p['enabled'] = True
        cls.base = s

    def render(self, **policy):
        s = copy.deepcopy(self.base)
        s['client_policy'].update(policy)
        out = fx.render(s)
        docs = {n: yaml.safe_load((out / f'mihomo-{n}.yaml').read_text()) for n in ('global', 'cn', 'internal')}
        return out, docs

    @staticmethod
    def groups(doc):
        return {g['name']: g for g in doc['proxy-groups']}

    def test_defaults_unchanged_from_1_7_1(self):
        out, docs = self.render()
        for doc in docs.values():
            for name in (SMART, ANTI):
                g = self.groups(doc)[name]
                self.assertEqual((g['interval'], g['timeout'], g['max-failed-times']), (60, 5000, 2))

    def test_custom_values_reach_both_groups_all_profiles_json_and_summary(self):
        out, docs = self.render(health_interval_s=30, health_timeout_ms=2500, health_max_failed=3)
        for name, doc in docs.items():
            with self.subTest(profile=name):
                for g in (self.groups(doc)[SMART], self.groups(doc)[ANTI]):
                    self.assertEqual((g['interval'], g['timeout'], g['max-failed-times']), (30, 2500, 3))
        j = next(o for o in convert(docs['global'])['outbounds'] if o['tag'] == SMART)
        self.assertEqual(j['interval'], '30s')
        summary = json.loads((out / 'summary.json').read_text())['client_policy']
        for key in ('smart_auto', 'anti_block_auto'):
            self.assertEqual(summary[key]['interval'], 30)
            self.assertEqual(summary[key]['timeout_ms'], 2500)
            self.assertEqual(summary[key]['max_failed_times'], 3)
        # periodic worst case: a node that dies right after a check is found at the next check + probe timeout
        self.assertEqual(summary['health_check']['worst_case_detection_s'], 32.5)

    def test_out_of_range_and_wrong_types_refused(self):
        bad = [dict(health_interval_s=10), dict(health_interval_s=601), dict(health_interval_s='60'),
               dict(health_timeout_ms=500), dict(health_timeout_ms=10001), dict(health_timeout_ms=5000.0),
               dict(health_max_failed=0), dict(health_max_failed=6), dict(health_max_failed=True),
               dict(health_interval_s=30, health_timeout_ms=30000)]
        for case in bad:
            with self.subTest(case=case):
                s = copy.deepcopy(self.base); s['client_policy'].update(case)
                with self.assertRaises(Exception):
                    fx.render(s)

    def test_one_field_change_keeps_everything_else(self):
        adv = dict(primary='reality', smart_tolerance_ms=45, smart_lazy=True, default_group='smart')
        _, before = self.render(**adv)
        _, after = self.render(health_interval_s=120, **adv)
        for n in before:
            gb, ga = self.groups(before[n]), self.groups(after[n])
            for name in (SMART, ANTI):
                self.assertEqual(ga[name]['interval'], 120)
                gb[name] = dict(gb[name], interval=120)
            self.assertEqual(ga, gb)
            self.assertEqual(after[n]['dns'], before[n]['dns']); self.assertEqual(after[n]['proxies'], before[n]['proxies'])

    def test_manager_bundle_validator_accepts_tuned_values(self):
        out, _ = self.render(health_interval_s=300, health_timeout_ms=8000, health_max_failed=5)
        text = (fx.ROOT / 'src/manager.sh').read_text()
        start = text.index('validate_client_bundle() {')
        body = text[text.index("<<'PY'\n", start) + len("<<'PY'\n"):text.index('\nPY\n', start)]
        files = ['mihomo.yaml', 'clmi.yaml', 'mihomo-global.yaml', 'mihomo-cn.yaml', 'mihomo-internal.yaml',
                 'clmi-global.yaml', 'clmi-cn.yaml', 'clmi-internal.yaml', 'internal.yaml']
        r = subprocess.run([sys.executable, '-c', body] + [str(out / f) for f in files], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])

    def test_controller_validates_and_preserves(self):
        from controller import candidate
        state = copy.deepcopy(self.base); state['client_policy'].update(primary='hy2', smart_tolerance_ms=60)
        after = candidate(state, {'kind': 'policy', 'data': {'health_interval_s': 90, 'health_timeout_ms': 3000, 'health_max_failed': 1}}, 'universal')
        self.assertEqual((after['client_policy']['health_interval_s'], after['client_policy']['health_timeout_ms'], after['client_policy']['health_max_failed']), (90, 3000, 1))
        self.assertEqual(after['client_policy']['primary'], 'hy2'); self.assertEqual(after['client_policy']['smart_tolerance_ms'], 60)
        for bad in ({'health_interval_s': 5}, {'health_timeout_ms': '3000'}, {'health_max_failed': 9}):
            with self.assertRaises(Exception):
                candidate(state, {'kind': 'policy', 'data': bad}, 'universal')


if __name__ == '__main__':
    unittest.main(verbosity=2)
