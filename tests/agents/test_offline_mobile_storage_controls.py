"""Synthetic mobile storage-control projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mobile_storage_controls import (
    MobileStorageControlError,
    MobileStorageControlReport,
    analyze_supplied_mobile_storage,
    component_fixture,
    verify_supplied_mobile_storage,
)


class MobileStorageControlTests(unittest.TestCase):
    def test_declared_gap_is_not_a_finding(self) -> None:
        report = analyze_supplied_mobile_storage(component_fixture()).to_dict()
        self.assertEqual(report["declared_control_gap_artifact_ids"], ["cached-profile"])
        self.assertEqual(
            report["artifact_projections"][0]["missing_declared_control_keys"],
            ["excluded_from_backup"],
        )
        self.assertFalse(report["application_inspected"])
        self.assertFalse(report["cryptography_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_no_gap_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["artifacts"][0]["excluded_from_backup"] = True
        report = analyze_supplied_mobile_storage(model).to_dict()
        self.assertEqual(report["declared_control_gap_artifact_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_policy_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["artifacts"][0]["policy_id"] = "missing"
        with self.assertRaises(MobileStorageControlError):
            analyze_supplied_mobile_storage(model)
        model = component_fixture()
        model["artifacts"].append(copy.deepcopy(model["artifacts"][0]))
        with self.assertRaises(MobileStorageControlError):
            analyze_supplied_mobile_storage(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MobileStorageControlError):
            analyze_supplied_mobile_storage(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mobile_storage(model)
        self.assertEqual(
            verify_supplied_mobile_storage(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["excluded_from_backup"] = True
        with self.assertRaises(MobileStorageControlError):
            verify_supplied_mobile_storage(report, model=changed)
        with self.assertRaises(MobileStorageControlError):
            MobileStorageControlReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
