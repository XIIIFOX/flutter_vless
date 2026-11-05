"""Reject misleading timing evidence and prove timed-out children are reaped."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import measure_macos_endpoint_startup as timing


def rows(mode):
    result = []
    for case, count in timing.CASES.items():
        for sample in range(count):
            elapsed = {'terminal_unavailable_fallback': 2100 if mode == 'baseline' else 130,
                       'no_record_late_aaaa': 1500, 'silence_fallback': 2100,
                       'stop_cancel': 20, 'path_cancel': 80}.get(case, 30)
            result.append(dict(schema=1, case=case, sample=sample, elapsed_ms=elapsed,
                fallback_calls=int(case in ('terminal_unavailable_fallback', 'silence_fallback')),
                registered_refs=2, closed_refs=2, mode=mode, dns_only=True, live_ne_vpn=False,
                candidate_families={'terminal_unavailable_fallback': ['ipv4'],
                    'silence_fallback': ['ipv4'], 'no_record_late_aaaa': ['ipv6']}.get(case, [])))
    return result


def parse(values, mode='candidate'):
    return timing.parse_metrics('\n'.join(timing.PREFIX + json.dumps(r) for r in values), mode)


class TimingEvidenceTests(unittest.TestCase):
    def test_actual_provider_ready_budget_and_null_no_ready(self):
        old = []; new = []
        for profile in ('encrypted', 'literal', 'sealed-system'):
            common = dict(scenario='first-ready-' + profile, realNetworkExtension=False,
                          controlledBoundaries='NE-Core-HEV-DNS')
            old.append(dict(common, passed=False, outcome='noReady', startToReadyMs=None, finalForceToReadyMs=None))
            new.append(dict(common, passed=True, outcome='ready', startToReadyMs=400, finalForceToReadyMs=350))
        def text(values):
            return '\n'.join('APPLE_PROVIDER_STARTUP_METRIC ' + json.dumps(r) for r in values)
        self.assertEqual(len(timing.provider_metrics(text(old), False)), 3)
        self.assertEqual(len(timing.provider_metrics(text(new), True)), 3)
        for key, value in [('startToReadyMs', None), ('finalForceToReadyMs', 950),
                           ('passed', False), ('outcome', 'noReady'), ('realNetworkExtension', True)]:
            changed = [dict(r) for r in new]; changed[0][key] = value
            with self.assertRaises(ValueError): timing.provider_metrics(text(changed), True)
        old[0]['startToReadyMs'] = 0
        with self.assertRaises(ValueError): timing.provider_metrics(text(old), False)

    def test_measured_improvement_and_preserved_slow_windows(self):
        result = timing.compare(parse(rows('baseline'), 'baseline'), parse(rows('candidate')))
        self.assertEqual(result['terminal_gain_ms'], 1970)

    def test_missing_and_duplicate_samples_fail(self):
        values = rows('candidate')
        for changed in (values[:-1], values + [values[0]]):
            with self.assertRaises(ValueError):
                parse(changed)

    def test_bad_clock_scope_cleanup_or_family_fail(self):
        for key, value in [('elapsed_ms', None), ('elapsed_ms', float('nan')),
                ('elapsed_ms', float('inf')), ('elapsed_ms', -1), ('elapsed_ms', 3500),
                ('elapsed_ms', True), ('sample', False), ('closed_refs', 1),
                ('fallback_calls', True), ('live_ne_vpn', True), ('dns_only', False),
                ('mode', 'baseline'), ('candidate_families', ['ipv6'])]:
            with self.subTest(key=key, value=value):
                changed = rows('candidate'); changed[0][key] = value
                with self.assertRaises(ValueError):
                    parse(changed)

    def test_privacy_and_ipv6_only_fallback_regressions_fail(self):
        for case in ('private_name_no_fallback', 'ipv6_only_no_ipv4_fallback', 'stop_cancel'):
            changed = rows('candidate')
            next(r for r in changed if r['case'] == case)['fallback_calls'] = 1
            with self.assertRaises(ValueError):
                parse(changed)

    def test_fake_or_insufficient_speedup_fails(self):
        for before, after in [(130, 130), (2100, 901), (1800, 850)]:
            old, new = rows('baseline'), rows('candidate')
            for r in old:
                if r['case'] == 'terminal_unavailable_fallback': r['elapsed_ms'] = before
            for r in new:
                if r['case'] == 'terminal_unavailable_fallback': r['elapsed_ms'] = after
            with self.assertRaises(ValueError):
                timing.compare(old, new)

    def test_shortcutting_late_ipv6_silence_or_slow_cancel_fails(self):
        for case, elapsed in [('no_record_late_aaaa', 100), ('silence_fallback', 100), ('stop_cancel', 501)]:
            changed = rows('candidate'); next(r for r in changed if r['case'] == case)['elapsed_ms'] = elapsed
            with self.assertRaises(ValueError):
                timing.compare(rows('baseline'), changed)

    def test_timeout_reaps_its_own_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / 'pid'
            code = 'import os,time,pathlib;pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid()));time.sleep(10)'
            with self.assertRaises(subprocess.TimeoutExpired):
                timing.bounded_run([sys.executable, '-c', code], Path(tmp) / 'log', 0.2)
            import os
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
