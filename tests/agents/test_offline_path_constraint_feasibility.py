"""Finite supplied path-condition feasibility and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_path_constraint_feasibility import (
    PathConstraintFeasibilityError,
    PathConstraintFeasibilityReport,
    analyze_supplied_path_constraints,
    component_fixture,
    verify_supplied_path_constraints,
)


class PathConstraintFeasibilityTests(unittest.TestCase):
    def test_counts_supplied_model_only(self) -> None:
        report = analyze_supplied_path_constraints(component_fixture()).to_dict()
        self.assertEqual(report["enumerated_assignment_count"], 8)
        self.assertEqual(report["satisfying_assignment_count"], 2)
        self.assertEqual(report["first_supplied_model_witness"], {"x": 2, "y": 1})
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["path_reachable_in_target"])
        self.assertFalse(report["program_executed"])

    def test_unsatisfiable_and_incomplete_are_distinct(self) -> None:
        model = component_fixture()
        model["constraints"][0]["constant"] = -8
        report = analyze_supplied_path_constraints(model).to_dict()
        self.assertEqual(report["disposition"], "supplied_model_unsatisfiable")
        self.assertIsNone(report["first_supplied_model_witness"])
        model["path_conditions_complete"] = False
        report = analyze_supplied_path_constraints(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["satisfying_assignment_count"], 0)

    def test_variable_order_does_not_change_witness(self) -> None:
        model = component_fixture()
        expected = analyze_supplied_path_constraints(model).to_dict()[
            "first_supplied_model_witness"
        ]
        model["variables"].reverse()
        actual = analyze_supplied_path_constraints(model).to_dict()[
            "first_supplied_model_witness"
        ]
        self.assertEqual(actual, expected)

    def test_rejects_invalid_domains_and_unknown_variables(self) -> None:
        model = component_fixture()
        model["variables"][0]["domain"] = [2, 1]
        with self.assertRaises(PathConstraintFeasibilityError):
            analyze_supplied_path_constraints(model)
        model = component_fixture()
        model["variables"][0]["domain"] = [False, 1]
        with self.assertRaises(PathConstraintFeasibilityError):
            analyze_supplied_path_constraints(model)
        model = component_fixture()
        model["constraints"][0]["coefficients"] = {"missing": 1}
        with self.assertRaises(PathConstraintFeasibilityError):
            analyze_supplied_path_constraints(model)
        model = component_fixture()
        model["constraints"][0]["coefficients"] = {"x": 0}
        with self.assertRaises(PathConstraintFeasibilityError):
            analyze_supplied_path_constraints(model)

    def test_rejects_non_linear_or_extra_fields(self) -> None:
        model = component_fixture()
        model["constraints"][0]["quadratic"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_path_constraints(model)
        model = component_fixture()
        model["variables"][0]["domain"] = list(range(17))
        with self.assertRaises(ValueError):
            analyze_supplied_path_constraints(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_path_constraints(model)
        self.assertEqual(
            verify_supplied_path_constraints(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["constraints"][0]["constant"] = -2
        with self.assertRaises(PathConstraintFeasibilityError):
            verify_supplied_path_constraints(report, model=changed)
        with self.assertRaises(PathConstraintFeasibilityError):
            PathConstraintFeasibilityReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
