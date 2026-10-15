#!/usr/bin/env python3
"""Hand-checked cases for smoke_v1.expected_alerts()."""

from collections import Counter
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from smoke_v1 import clock_stability, expected_alerts, qualify_training, require_unambiguous_timing, source_frame  # noqa: E402


def frame(timestamp, payload):
    return dict(source_frame(payload), timestamp_us=timestamp)


def clocks(microseconds, step_us=0):
    monotonic = microseconds * 1000
    return {"monotonic_ns": monotonic, "realtime_ns": monotonic + 1000000000000 + step_us * 1000,
            "monotonic_before_ns": monotonic - 100, "monotonic_after_ns": monotonic + 100,
            "read_uncertainty_ns": 100}


class SmokeOracleTests(unittest.TestCase):
    def test_normal_is_zero_alerts(self):
        frames = [frame(index * 50000, f"{index:02X}00") for index in range(40)]
        self.assertEqual(expected_alerts(frames), [])

    def test_flood_has_hand_counted_thresholds(self):
        alerts = expected_alerts([frame(index * 1000, "1200") for index in range(12)])
        self.assertEqual(Counter(rule for _, rule in alerts),
                         {"PERIOD_VIOLATION": 11, "RATE_SPIKE": 6, "REPLAY_BURST": 9})
        self.assertEqual([index for index, rule in alerts if rule == "REPLAY_BURST"], list(range(3, 12)))
        self.assertEqual([index for index, rule in alerts if rule == "RATE_SPIKE"], list(range(6, 12)))

    def test_abab_loop_boundary_is_period_only(self):
        frames = [frame(0, "0000"), frame(50000, "0100"), frame(50000, "0000"), frame(100000, "0100")]
        self.assertEqual(expected_alerts(frames), [(2, "PERIOD_VIOLATION")])

    def test_same_changed_fuzz_payload_is_not_toggled_again(self):
        frames = [frame(index * 50000, "12FF") for index in range(4)]
        self.assertEqual(expected_alerts(frames),
                         [(0, "FIXED_BYTE_VIOLATION"), (1, "FIXED_BYTE_VIOLATION"),
                          (2, "FIXED_BYTE_VIOLATION"), (3, "FIXED_BYTE_VIOLATION"), (3, "REPLAY_BURST")])

    def test_rate_window_excludes_exactly_100ms_old_frame(self):
        times = [0, 1, 2, 3, 4, 5, 100000, 100000]
        frames = [frame(timestamp, f"{index:02X}00") for index, timestamp in enumerate(times)]
        self.assertEqual([index for index, rule in expected_alerts(frames) if rule == "RATE_SPIKE"], [7])

    def test_small_first_socket_offset_keeps_normal_verdict(self):
        observed = [frame(10000 + index * 50000, f"{index:02X}00") for index in range(40)]
        captured = [dict(row) for row in observed]
        captured[0]["timestamp_us"] += 55
        self.assertEqual(expected_alerts(captured), expected_alerts(observed))
        self.assertEqual(len(require_unambiguous_timing(observed)), 40)

    def test_period_near_boundary_is_rejected_as_ambiguous(self):
        with self.assertRaisesRegex(RuntimeError, "period verdict is ambiguous"):
            require_unambiguous_timing([frame(0, "0000"), frame(5000, "0100")])

    def test_period_uncertainty_applies_to_both_endpoints(self):
        with self.assertRaisesRegex(RuntimeError, "period verdict is ambiguous"):
            require_unambiguous_timing([frame(0, "0000"), frame(3000, "0100")])

    def test_rate_near_boundary_is_rejected_as_ambiguous(self):
        times = [0, 15000, 30000, 45000, 60000, 75000, 100000]
        frames = [frame(timestamp, f"{index:02X}00") for index, timestamp in enumerate(times)]
        with self.assertRaisesRegex(RuntimeError, "rate verdict is ambiguous"):
            require_unambiguous_timing(frames)

    def test_intended_modes_have_unambiguous_timing(self):
        scenarios = [
            [frame(index * 1000, "1200") for index in range(12)],
            [frame(0, "0000"), frame(50000, "0100"), frame(50000, "0000"), frame(100000, "0100")],
            [frame(index * 50000, "12FF") for index in range(4)],
        ]
        for frames in scenarios:
            self.assertEqual(len(require_unambiguous_timing(frames)), len(frames))

    def test_stable_clock_pairs_pass(self):
        result = clock_stability([clocks(index * 50000) for index in range(40)])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["comparisons"]), 39)

    def test_missing_clock_observations_are_not_stable(self):
        self.assertEqual(clock_stability([])["status"], "failed")
        self.assertEqual(clock_stability([clocks(0)])["status"], "failed")

    def test_realtime_clock_step_is_identified(self):
        result = clock_stability([clocks(0), clocks(50000), clocks(100000, step_us=1184388)])
        self.assertEqual(result["status"], "failed")
        self.assertIn("clock discontinuity", result["errors"][0])
        self.assertEqual(result["comparisons"][1]["clock_offset_change_ns"], 1184388000)

    def test_long_clock_read_is_uncertain(self):
        sample = clocks(0)
        sample.update(monotonic_before_ns=-1000000, monotonic_after_ns=1000000, read_uncertainty_ns=1000000)
        result = clock_stability([sample, clocks(50000)])
        self.assertEqual(result["status"], "failed")
        self.assertIn("clock read interval is too uncertain", result["errors"][0])

    def test_stable_observed_training_qualifies(self):
        samples = [clocks(index * 50000) for index in range(40)]
        frames = [frame(1000000000 + index * 50000, f"{index:02X}00") for index in range(40)]
        self.assertEqual(qualify_training(frames, frames, samples)["status"], "passed")

    def test_training_clock_step_cannot_be_profiled(self):
        samples = [clocks(index * 50000, step_us=1184388 if index >= 3 else 0) for index in range(40)]
        frames = [frame(sample["realtime_ns"] // 1000, f"{index:02X}00") for index, sample in enumerate(samples)]
        with self.assertRaisesRegex(RuntimeError, "training clock discontinuity"):
            qualify_training(frames, frames, samples)

    def test_long_received_training_gap_cannot_be_profiled(self):
        samples = [clocks(index * 50000) for index in range(40)]
        frames = [frame(1000000000 + index * 50000 + (1184388 if index >= 3 else 0), f"{index:02X}00")
                  for index in range(40)]
        with self.assertRaisesRegex(RuntimeError, "training is not normal"):
            qualify_training(frames, frames, samples)


if __name__ == "__main__":
    unittest.main()
