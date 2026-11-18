"""Synthetic collaboration-sharing projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_collaboration_sharing_policy import (
    CollaborationSharingPolicyError,
    CollaborationSharingPolicyReport,
    analyze_supplied_collaboration_sharing,
    component_fixture,
    verify_supplied_collaboration_sharing,
)


class CollaborationSharingPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_public_access_finding(self) -> None:
        report = analyze_supplied_collaboration_sharing(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_resource_ids"], ["document-a"])
        self.assertFalse(report["tenant_connected"])
        self.assertFalse(report["resource_content_read"])
        self.assertFalse(report["sharing_setting_verified"])
        self.assertFalse(report["sharing_change_performed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_policy_compliant_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["resources"][0]["share_mode_declared"] = "private"
        report = analyze_supplied_collaboration_sharing(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_resource_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_policy_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["resources"][0]["policy_id"] = "unknown"
        with self.assertRaises(CollaborationSharingPolicyError):
            analyze_supplied_collaboration_sharing(model)
        model = component_fixture()
        model["resources"].append(copy.deepcopy(model["resources"][0]))
        with self.assertRaises(CollaborationSharingPolicyError):
            analyze_supplied_collaboration_sharing(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(CollaborationSharingPolicyError):
            analyze_supplied_collaboration_sharing(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_collaboration_sharing(model)
        self.assertEqual(
            verify_supplied_collaboration_sharing(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["resources"][0]["share_mode_declared"] = "private"
        with self.assertRaises(CollaborationSharingPolicyError):
            verify_supplied_collaboration_sharing(report, model=changed)
        with self.assertRaises(CollaborationSharingPolicyError):
            CollaborationSharingPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
