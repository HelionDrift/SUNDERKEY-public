"""Synthetic traffic cadence arithmetic boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_traffic_cadence_projection import (
    TrafficCadenceProjectionError,
    TrafficCadenceProjectionReport,
    analyze_supplied_traffic_cadence,
    component_fixture,
    verify_supplied_traffic_cadence,
)


class TrafficCadenceProjectionTests(unittest.TestCase):
    def test_perfect_positive_correlation_is_not_a_channel(self) -> None:
        report = analyze_supplied_traffic_cadence(component_fixture()).to_dict()
        self.assertEqual(report["absolute_correlation_basis_points"], 10000)
        self.assertEqual(report["correlation_direction"], "positive")
        self.assertTrue(report["declared_threshold_met"])
        self.assertFalse(report["channel_identified"])
        self.assertFalse(report["tunnel_identified"])
        self.assertFalse(report["exfiltration_inferred"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_negative_correlation_and_zero_variance(self) -> None:
        model = component_fixture()
        model["series"][1]["bucket_counts"] = [8, 6, 4, 2]
        report = analyze_supplied_traffic_cadence(model).to_dict()
        self.assertEqual(report["absolute_correlation_basis_points"], 10000)
        self.assertEqual(report["correlation_direction"], "negative")
        model["series"][1]["bucket_counts"] = [1, 1, 1, 1]
        report = analyze_supplied_traffic_cadence(model).to_dict()
        self.assertIsNone(report["absolute_correlation_basis_points"])
        self.assertIsNone(report["declared_threshold_met"])
        self.assertEqual(report["disposition"], "unknown")

    def test_incomplete_and_invalid_series(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        self.assertEqual(
            analyze_supplied_traffic_cadence(model).to_dict()["disposition"], "unknown"
        )
        model = component_fixture()
        model["series"][1]["bucket_counts"] = [1, 2, 3]
        with self.assertRaises(TrafficCadenceProjectionError):
            analyze_supplied_traffic_cadence(model)
        model = component_fixture()
        model["series"][1]["bucket_counts"][0] = 1001
        with self.assertRaises(TrafficCadenceProjectionError):
            analyze_supplied_traffic_cadence(model)
        model = component_fixture()
        model["aligned_equal_duration_buckets_asserted"] = False
        with self.assertRaises(TrafficCadenceProjectionError):
            analyze_supplied_traffic_cadence(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_traffic_cadence(model)
        self.assertEqual(
            verify_supplied_traffic_cadence(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["series"][1]["bucket_counts"] = [2, 4, 6, 7]
        with self.assertRaises(TrafficCadenceProjectionError):
            verify_supplied_traffic_cadence(report, model=changed)
        with self.assertRaises(TrafficCadenceProjectionError):
            TrafficCadenceProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
