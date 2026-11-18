"""Supplied timing summary projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_side_channel_timing_projection import (
    SideChannelTimingProjectionError,
    SideChannelTimingProjectionReport,
    analyze_supplied_side_channel_timings,
    component_fixture,
    verify_supplied_side_channel_timings,
)


class SideChannelTimingProjectionTests(unittest.TestCase):
    def test_exact_summary_without_significance_or_leakage_claim(self) -> None:
        report = analyze_supplied_side_channel_timings(component_fixture()).to_dict()
        groups = {row["group_id"]: row for row in report["groups"]}
        self.assertEqual(groups["control"]["median_duration_ns_times_two"], 24)
        self.assertEqual(groups["variant"]["median_duration_ns_times_two"], 28)
        self.assertEqual(report["median_variant_minus_control_ns_times_two"], 4)
        self.assertTrue(report["duration_ranges_overlap_inclusive"])
        self.assertFalse(report["statistical_significance_claimed"])
        self.assertFalse(report["secret_dependent_leakage_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_even_median_and_disjoint_ranges(self) -> None:
        model = component_fixture()
        model["groups"][0]["samples"] = [
            {"sample_id": "c1", "duration_ns": 1},
            {"sample_id": "c2", "duration_ns": 2},
        ]
        report = analyze_supplied_side_channel_timings(model).to_dict()
        groups = {row["group_id"]: row for row in report["groups"]}
        self.assertEqual(groups["control"]["median_duration_ns_times_two"], 3)
        self.assertFalse(report["duration_ranges_overlap_inclusive"])

    def test_rejects_invalid_group_and_duration(self) -> None:
        model = component_fixture()
        model["groups"][1]["group_id"] = "control"
        with self.assertRaises(SideChannelTimingProjectionError):
            analyze_supplied_side_channel_timings(model)
        model = component_fixture()
        model["groups"][0]["samples"][0]["duration_ns"] = -1
        with self.assertRaises(SideChannelTimingProjectionError):
            analyze_supplied_side_channel_timings(model)

    def test_incomplete_inventory_and_original_model_replay(self) -> None:
        model = component_fixture()
        model["sample_inventory_complete"] = False
        report = analyze_supplied_side_channel_timings(model)
        self.assertEqual(report.to_dict()["disposition"], "unknown")
        self.assertEqual(
            verify_supplied_side_channel_timings(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["groups"][0]["samples"][0]["duration_ns"] = 9
        with self.assertRaises(SideChannelTimingProjectionError):
            verify_supplied_side_channel_timings(report, model=changed)
        with self.assertRaises(SideChannelTimingProjectionError):
            SideChannelTimingProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
