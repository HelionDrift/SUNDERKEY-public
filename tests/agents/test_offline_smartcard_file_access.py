"""Synthetic smartcard file-access projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_smartcard_file_access import (
    SmartcardFileAccessError,
    SmartcardFileAccessReport,
    analyze_supplied_smartcard_files,
    component_fixture,
    verify_supplied_smartcard_files,
)


class SmartcardFileAccessTests(unittest.TestCase):
    def test_declared_gap_is_not_card_finding(self) -> None:
        report = analyze_supplied_smartcard_files(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_file_ids"], ["file-a"])
        self.assertEqual(
            report["file_projections"][0]["declared_extra_read_role_ids"],
            ["anonymous"],
        )
        self.assertFalse(report["card_connected"])
        self.assertFalse(report["reader_connected"])
        self.assertFalse(report["apdu_sent"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_incomplete_inventory_is_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["files"][0]["declared_read_role_ids"] = ["cardholder"]
        report = analyze_supplied_smartcard_files(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_file_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_role_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["files"][0]["declared_write_role_ids"] = ["unknown"]
        with self.assertRaises(SmartcardFileAccessError):
            analyze_supplied_smartcard_files(model)
        model = component_fixture()
        model["roles"] = ["anonymous", "anonymous"]
        with self.assertRaises(SmartcardFileAccessError):
            analyze_supplied_smartcard_files(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SmartcardFileAccessError):
            analyze_supplied_smartcard_files(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_smartcard_files(model)
        self.assertEqual(
            verify_supplied_smartcard_files(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["files"][0]["declared_read_role_ids"] = ["cardholder"]
        with self.assertRaises(SmartcardFileAccessError):
            verify_supplied_smartcard_files(report, model=changed)
        with self.assertRaises(SmartcardFileAccessError):
            SmartcardFileAccessReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
