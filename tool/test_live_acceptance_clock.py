#!/usr/bin/env python3
"""Pure parent-clock controls; no processes, sleeps, devices or real clocks."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "live_acceptance_clock", Path(__file__).with_name("live_acceptance_clock.py")
)
CLOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOCK)


class LiveAcceptanceClockTests(unittest.TestCase):
    def armed(self, launch=100.0, received=104.0):
        clock = CLOCK.LiveAcceptanceClock("current-run", launch)
        clock.acknowledge("current-run", received)
        return clock

    def rejects(self, code, action):
        with self.assertRaises(CLOCK.ClockError) as caught:
            action()
        self.assertEqual(str(caught.exception), code)

    def test_different_child_origins_never_supply_elapsed_time(self):
        # These are the old now-child_arm counterexamples, not input to the API.
        for child_arm in (-10_000.0, 20_000.0):
            with self.subTest(child_origin=child_arm):
                clock = self.armed()
                lower, upper = clock.elapsed_bounds(110.0)
                self.assertEqual((lower, upper), (6.0, 10.0))
                old_exact_elapsed = 110.0 - child_arm
                self.assertFalse(lower <= old_exact_elapsed <= upper)

    def test_delayed_ack_does_not_extend_cutoff(self):
        clock = self.armed(100.0, 170.0)
        self.assertEqual(clock.remaining(80.0, 175.0), 5.0)
        self.assertEqual(clock.elapsed_bounds(175.0), (5.0, 75.0))
        self.assertEqual(clock.deadline(80.0), 180.0)
        self.assertNotEqual(clock.deadline(80.0), 170.0 + 80.0)

    def test_late_ack_does_not_reopen_expired_budget(self):
        clock = self.armed(100.0, 200.0)
        self.assertEqual(clock.remaining(80.0, 200.0), 0.0)
        self.assertEqual(clock.elapsed_bounds(200.0), (0.0, 100.0))

    def test_elapsed_interval_contains_every_possible_arm(self):
        clock = self.armed(100.0, 104.0)
        lower, upper = clock.elapsed_bounds(110.0)
        for actual_arm in (100.0, 101.0, 103.5, 104.0):
            self.assertLessEqual(lower, 110.0 - actual_arm)
            self.assertGreaterEqual(upper, 110.0 - actual_arm)

    def test_equal_endpoints_are_the_only_exact_interval(self):
        self.assertEqual(self.armed(7.0, 7.0).elapsed_bounds(9.0), (2.0, 2.0))

    def test_cutoff_is_closed_at_boundary(self):
        clock = self.armed()
        self.assertEqual(clock.remaining(20.0, 119.0), 1.0)
        self.assertEqual(clock.remaining(20.0, 120.0), 0.0)
        self.assertEqual(clock.remaining(20.0, 121.0), 0.0)

    def test_deadline_and_wait_budget_exist_before_ack(self):
        clock = CLOCK.LiveAcceptanceClock("current-run", 100.0)
        self.assertEqual(clock.deadline(17.0), 117.0)
        self.assertEqual(clock.remaining(17.0, 105.0), 12.0)
        self.rejects("not_acknowledged", lambda: clock.elapsed_bounds(105.0))
        clock.acknowledge("current-run", 106.0)
        self.assertEqual(clock.elapsed_bounds(106.0), (0.0, 6.0))

    def test_stale_run_ack_is_rejected_without_adoption(self):
        clock = CLOCK.LiveAcceptanceClock("current-run", 100.0)
        self.rejects("stale_ack", lambda: clock.acknowledge("previous-run", 102.0))
        self.rejects("not_acknowledged", lambda: clock.elapsed_bounds(102.0))
        clock.acknowledge("current-run", 104.0)
        self.assertEqual(clock.elapsed_bounds(104.0), (0.0, 4.0))

    def test_duplicate_ack_cannot_rearm_or_extend_window(self):
        clock = self.armed()
        self.rejects("already_acknowledged", lambda: clock.acknowledge("current-run", 150.0))
        self.assertEqual(clock.deadline(80.0), 180.0)
        self.assertEqual(clock.elapsed_bounds(150.0), (46.0, 50.0))

    def test_ack_before_launch_is_rejected(self):
        clock = CLOCK.LiveAcceptanceClock("current-run", 100.0)
        self.rejects("clock_regression", lambda: clock.acknowledge("current-run", 99.0))
        clock.acknowledge("current-run", 104.0)
        self.assertEqual(clock.elapsed_bounds(104.0), (0.0, 4.0))

    def test_observation_regression_is_rejected(self):
        clock = self.armed()
        self.rejects("clock_regression", lambda: clock.elapsed_bounds(103.0))
        self.assertEqual(clock.remaining(80.0, 110.0), 70.0)
        self.rejects("clock_regression", lambda: clock.elapsed_bounds(109.0))
        self.assertEqual(clock.elapsed_bounds(110.0), (6.0, 10.0))

    def test_ack_cannot_precede_parent_observation(self):
        clock = CLOCK.LiveAcceptanceClock("current-run", 100.0)
        self.assertEqual(clock.remaining(80.0, 105.0), 75.0)
        self.rejects("clock_regression", lambda: clock.acknowledge("current-run", 104.0))
        clock.acknowledge("current-run", 106.0)
        self.assertEqual(clock.elapsed_bounds(106.0), (0.0, 6.0))

    def test_arbitrary_local_origin_is_supported(self):
        self.assertEqual(self.armed(-100.0, -96.0).elapsed_bounds(-90.0), (6.0, 10.0))

    def test_invalid_run_ids_are_rejected(self):
        for value in (None, "", 7, True):
            with self.subTest(value=value):
                self.rejects("invalid_run_id", lambda: CLOCK.LiveAcceptanceClock(value, 0.0))

    def test_invalid_timestamps_are_rejected(self):
        for value in (None, "100", True, float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                self.rejects("invalid_time", lambda: CLOCK.LiveAcceptanceClock("run", value))
                self.rejects("invalid_time", lambda: self.armed().elapsed_bounds(value))

    def test_invalid_budgets_are_rejected(self):
        for value in (-1.0, True, "80", float("nan"), float("inf")):
            with self.subTest(value=value):
                self.rejects("invalid_budget", lambda: self.armed().remaining(value, 110.0))

    def test_zero_budget_is_already_expired(self):
        self.assertEqual(self.armed().remaining(0.0, 104.0), 0.0)

    def test_public_errors_do_not_echo_run_ids(self):
        clock = CLOCK.LiveAcceptanceClock("private-run-canary", 0.0)
        self.rejects("stale_ack", lambda: clock.acknowledge("other-private-canary", 1.0))


if __name__ == "__main__":
    unittest.main()
