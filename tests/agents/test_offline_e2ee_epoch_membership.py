"""Supplied E2EE epoch membership projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_e2ee_epoch_membership import (
    E2eeEpochMembershipError,
    E2eeEpochMembershipReport,
    analyze_supplied_e2ee_epochs,
    component_fixture,
    verify_supplied_e2ee_epochs,
)


class E2eeEpochMembershipTests(unittest.TestCase):
    def test_projects_join_leave_and_envelope_gaps_without_security_claim(self) -> None:
        report = analyze_supplied_e2ee_epochs(component_fixture()).to_dict()
        self.assertEqual(report["supplied_epoch_count"], 2)
        self.assertEqual(report["epochs"][1]["joined_member_ids"], ["c"])
        self.assertEqual(report["epochs"][1]["departed_member_ids"], ["b"])
        self.assertEqual(report["epochs"][1]["members_without_supplied_envelope_ids"], ["c"])
        self.assertEqual(report["epochs"][1]["nonmembers_with_supplied_envelope_ids"], ["b"])
        self.assertFalse(report["e2ee_confidentiality_verified"])
        self.assertEqual(report["candidate_count"], 0)

    def test_incomplete_inventory_and_duplicate_ids(self) -> None:
        model = component_fixture()
        model["epoch_inventory_complete"] = False
        self.assertEqual(analyze_supplied_e2ee_epochs(model).to_dict()["disposition"], "unknown")
        model = component_fixture()
        model["epochs"][1]["epoch_id"] = "e1"
        with self.assertRaises(E2eeEpochMembershipError):
            analyze_supplied_e2ee_epochs(model)
        model = component_fixture()
        model["epochs"][0]["member_ids"] = ["a", "a"]
        with self.assertRaises(E2eeEpochMembershipError):
            analyze_supplied_e2ee_epochs(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_e2ee_epochs(model)
        self.assertEqual(
            verify_supplied_e2ee_epochs(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["epochs"][1]["envelope_recipient_ids"] = ["a", "c"]
        with self.assertRaises(E2eeEpochMembershipError):
            verify_supplied_e2ee_epochs(report, model=changed)
        with self.assertRaises(E2eeEpochMembershipError):
            E2eeEpochMembershipReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
