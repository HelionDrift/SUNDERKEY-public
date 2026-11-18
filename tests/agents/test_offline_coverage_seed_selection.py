"""Offline supplied-coverage seed ordering and source-replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_coverage_seed_selection import (
    CoverageSeedSelectionError,
    CoverageSeedSelectionReport,
    analyze_supplied_coverage_seeds,
    component_fixture,
    verify_supplied_coverage_seeds,
)


class CoverageSeedSelectionTests(unittest.TestCase):
    def test_greedy_novelty_order_has_no_target_effect(self) -> None:
        report = analyze_supplied_coverage_seeds(component_fixture()).to_dict()
        self.assertEqual(
            [row["seed_id"] for row in report["selected_seeds"]],
            ["seed_b", "seed_a", "seed_c"],
        )
        self.assertEqual(report["zero_gain_seed_ids"], ["seed_d"])
        self.assertEqual(report["baseline_coverage_bits"], 1)
        self.assertEqual(report["final_coverage_bits"], 4)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["target_executed"])
        self.assertFalse(report["crash_verified"])

    def test_input_order_does_not_change_selected_order(self) -> None:
        model = component_fixture()
        first = analyze_supplied_coverage_seeds(model).to_dict()["selected_seeds"]
        model["seeds"].reverse()
        second = analyze_supplied_coverage_seeds(model).to_dict()["selected_seeds"]
        self.assertEqual(first, second)

    def test_equal_ratio_uses_marginal_then_cost_then_id(self) -> None:
        model = component_fixture()
        model["baseline_hex"] = "00"
        model["seeds"] = [
            {"seed_id": "b", "coverage_hex": "03", "cost_units": 2},
            {"seed_id": "a", "coverage_hex": "0c", "cost_units": 2},
        ]
        report = analyze_supplied_coverage_seeds(model).to_dict()
        self.assertEqual(report["selected_seeds"][0]["seed_id"], "a")

    def test_incomplete_inventory_and_empty_input_are_unknown(self) -> None:
        model = component_fixture()
        model["seed_inventory_complete"] = False
        model["seeds"] = []
        report = analyze_supplied_coverage_seeds(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["candidate_count"], 0)

    def test_rejects_duplicate_seed_and_noncanonical_bitmap(self) -> None:
        model = component_fixture()
        model["seeds"].append(copy.deepcopy(model["seeds"][0]))
        with self.assertRaises(CoverageSeedSelectionError):
            analyze_supplied_coverage_seeds(model)
        model = component_fixture()
        model["seeds"][0]["coverage_hex"] = "0A"
        with self.assertRaises(CoverageSeedSelectionError):
            analyze_supplied_coverage_seeds(model)
        model = component_fixture()
        model["coverage_width_bits"] = 7
        with self.assertRaises(CoverageSeedSelectionError):
            analyze_supplied_coverage_seeds(model)
        model = component_fixture()
        model["seeds"][0]["cost_units"] = True
        with self.assertRaises(CoverageSeedSelectionError):
            analyze_supplied_coverage_seeds(model)

    def test_exact_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_coverage_seeds(model)
        self.assertEqual(
            verify_supplied_coverage_seeds(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["seeds"][0]["cost_units"] = 3
        with self.assertRaises(CoverageSeedSelectionError):
            verify_supplied_coverage_seeds(report, model=changed)
        with self.assertRaises(CoverageSeedSelectionError):
            CoverageSeedSelectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
