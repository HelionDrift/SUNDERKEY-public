"""Synthetic endpoint assignment policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_endpoint_assignment_policy import (
    EndpointAssignmentPolicyError,
    EndpointAssignmentPolicyReport,
    analyze_supplied_endpoint_assignments,
    component_fixture,
    verify_supplied_endpoint_assignments,
)


class EndpointAssignmentPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_device_impact(self) -> None:
        report = analyze_supplied_endpoint_assignments(component_fixture()).to_dict()
        self.assertEqual(
            report["declared_policy_deviation_assignment_ids"], ["assignment-a"]
        )
        self.assertFalse(report["management_service_connected"])
        self.assertFalse(report["device_connected"])
        self.assertFalse(report["package_content_read"])
        self.assertFalse(report["package_delivered"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_disabled_assignment_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["assignments"][0]["enabled_declared"] = False
        report = analyze_supplied_endpoint_assignments(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_assignment_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_ring_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["assignments"][0]["ring_id"] = "unknown"
        with self.assertRaises(EndpointAssignmentPolicyError):
            analyze_supplied_endpoint_assignments(model)
        model = component_fixture()
        model["assignments"].append(copy.deepcopy(model["assignments"][0]))
        with self.assertRaises(EndpointAssignmentPolicyError):
            analyze_supplied_endpoint_assignments(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(EndpointAssignmentPolicyError):
            analyze_supplied_endpoint_assignments(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_endpoint_assignments(model)
        self.assertEqual(
            verify_supplied_endpoint_assignments(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["assignments"][0]["ring_id"] = "pilot"
        with self.assertRaises(EndpointAssignmentPolicyError):
            verify_supplied_endpoint_assignments(report, model=changed)
        with self.assertRaises(EndpointAssignmentPolicyError):
            EndpointAssignmentPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
