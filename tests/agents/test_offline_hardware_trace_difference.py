"""Source-bound synthetic hardware trace difference tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_hardware_trace_difference import (
    HardwareTraceDifferenceError,
    HardwareTraceDifferenceReport,
    analyze_supplied_hardware_traces,
    component_fixture,
    verify_supplied_hardware_traces,
)


class HardwareTraceDifferenceTests(unittest.TestCase):
    def test_exact_difference_has_no_leakage_or_significance_claim(self) -> None:
        body = analyze_supplied_hardware_traces(component_fixture()).to_dict()
        self.assertEqual(body["mean_difference_numerator_by_index"], [0, 8, 0, 0])
        self.assertEqual(body["mean_difference_denominator"], 4)
        self.assertEqual(body["peak_absolute_difference_index"], 1)
        self.assertFalse(body["physical_leakage_claimed"])
        self.assertFalse(body["statistical_significance_claimed"])
        self.assertFalse(body["device_interacted"])
        self.assertEqual(body["candidate_count"], 0)

    def test_unaligned_and_incomplete_remain_unknown(self) -> None:
        model = component_fixture()
        model["aligned_trace_asserted"] = False
        model["sample_inventory_complete"] = False
        body = analyze_supplied_hardware_traces(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unknown_count"], 2)

    def test_length_mismatch_and_duplicate_ids_rejected(self) -> None:
        model = component_fixture()
        model["groups"][1]["traces"][0]["sample_values"].append(0)
        with self.assertRaises(HardwareTraceDifferenceError):
            analyze_supplied_hardware_traces(model)
        model = component_fixture()
        model["groups"][1]["traces"][0]["trace_id"] = "c1"
        with self.assertRaises(HardwareTraceDifferenceError):
            analyze_supplied_hardware_traces(model)

    def test_nonsynthetic_and_noninteger_samples_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(HardwareTraceDifferenceError):
            analyze_supplied_hardware_traces(model)
        model = component_fixture()
        model["groups"][0]["traces"][0]["sample_values"][0] = True
        with self.assertRaises(HardwareTraceDifferenceError):
            analyze_supplied_hardware_traces(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_hardware_traces(model)
        self.assertEqual(
            verify_supplied_hardware_traces(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["groups"][1]["traces"][0]["sample_values"][1] += 1
        with self.assertRaises(HardwareTraceDifferenceError):
            verify_supplied_hardware_traces(report, model=changed)
        with self.assertRaises(HardwareTraceDifferenceError):
            HardwareTraceDifferenceReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
