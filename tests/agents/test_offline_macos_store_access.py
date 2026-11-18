"""Synthetic macOS store-access projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_store_access import (
    MacosStoreAccessError,
    MacosStoreAccessReport,
    analyze_supplied_store_access,
    component_fixture,
    verify_supplied_store_access,
)


class MacosStoreAccessTests(unittest.TestCase):
    def test_binding_gap_is_not_secret_access(self) -> None:
        report = analyze_supplied_store_access(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_access_ids"], ["access-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["store_connected"])
        self.assertFalse(report["secret_read"])
        self.assertFalse(report["cloud_content_read"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_binding_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["access_declarations"][0]["app_id"] = "app-a"
        report = analyze_supplied_store_access(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_access_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["access_declarations"].append(copy.deepcopy(model["access_declarations"][0]))
        with self.assertRaises(MacosStoreAccessError):
            analyze_supplied_store_access(model)
        model = component_fixture()
        model["access_declarations"][0]["store_kind"] = "unknown"
        with self.assertRaises(MacosStoreAccessError):
            analyze_supplied_store_access(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosStoreAccessError):
            analyze_supplied_store_access(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_store_access(model)
        self.assertEqual(
            verify_supplied_store_access(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["access_declarations"][0]["access_declared"] = False
        with self.assertRaises(MacosStoreAccessError):
            verify_supplied_store_access(report, model=changed)
        with self.assertRaises(MacosStoreAccessError):
            MacosStoreAccessReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
