"""Synthetic macOS privilege item projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_privilege_items import (
    MacosPrivilegeItemError,
    MacosPrivilegeItemReport,
    analyze_supplied_macos_privilege_items,
    component_fixture,
    verify_supplied_macos_privilege_items,
)


class MacosPrivilegeItemTests(unittest.TestCase):
    def test_overlap_is_not_privilege_escalation(self) -> None:
        report = analyze_supplied_macos_privilege_items(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_item_ids"], ["helper-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["permissions_verified"])
        self.assertFalse(report["item_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_nonoverlap_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["items"][0]["user_writable_declared"] = False
        report = analyze_supplied_macos_privilege_items(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_item_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["items"].append(copy.deepcopy(model["items"][0]))
        with self.assertRaises(MacosPrivilegeItemError):
            analyze_supplied_macos_privilege_items(model)
        model = component_fixture()
        model["items"][0]["item_kind"] = "unknown"
        with self.assertRaises(MacosPrivilegeItemError):
            analyze_supplied_macos_privilege_items(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosPrivilegeItemError):
            analyze_supplied_macos_privilege_items(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_macos_privilege_items(model)
        self.assertEqual(
            verify_supplied_macos_privilege_items(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["items"][0]["user_writable_declared"] = False
        with self.assertRaises(MacosPrivilegeItemError):
            verify_supplied_macos_privilege_items(report, model=changed)
        with self.assertRaises(MacosPrivilegeItemError):
            MacosPrivilegeItemReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
