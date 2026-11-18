"""Synthetic protected-material access projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_material_access import (
    WindowsMaterialAccessError,
    WindowsMaterialAccessReport,
    analyze_supplied_material_access,
    component_fixture,
    verify_supplied_material_access,
)


class WindowsMaterialAccessTests(unittest.TestCase):
    def test_approval_gap_is_not_secret_access(self) -> None:
        report = analyze_supplied_material_access(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_access_ids"], ["review-access"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["process_memory_read"])
        self.assertFalse(report["protected_blob_read"])
        self.assertFalse(report["secret_extracted"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["approved_access_ids"].append("review-access")
        report = analyze_supplied_material_access(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_access_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["access_declarations"].append(copy.deepcopy(model["access_declarations"][0]))
        with self.assertRaises(WindowsMaterialAccessError):
            analyze_supplied_material_access(model)
        model = component_fixture()
        model["access_declarations"][0]["material_kind"] = "unknown"
        with self.assertRaises(WindowsMaterialAccessError):
            analyze_supplied_material_access(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsMaterialAccessError):
            analyze_supplied_material_access(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_material_access(model)
        self.assertEqual(
            verify_supplied_material_access(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["access_declarations"][0]["access_declared"] = False
        with self.assertRaises(WindowsMaterialAccessError):
            verify_supplied_material_access(report, model=changed)
        with self.assertRaises(WindowsMaterialAccessError):
            WindowsMaterialAccessReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
