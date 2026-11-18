"""Synthetic Windows privilege artifact projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_privilege_artifacts import (
    WindowsPrivilegeArtifactError,
    WindowsPrivilegeArtifactReport,
    analyze_supplied_privilege_artifacts,
    component_fixture,
    verify_supplied_privilege_artifacts,
)


class WindowsPrivilegeArtifactTests(unittest.TestCase):
    def test_overlap_is_not_privilege_escalation(self) -> None:
        report = analyze_supplied_privilege_artifacts(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], ["service-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["acl_verified"])
        self.assertFalse(report["artifact_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_nonoverlap_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["artifacts"][0]["low_privilege_write_declared"] = False
        report = analyze_supplied_privilege_artifacts(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_invalid_and_nonsynthetic_models(self) -> None:
        model = component_fixture()
        model["artifacts"][0]["artifact_kind"] = "unknown"
        with self.assertRaises(WindowsPrivilegeArtifactError):
            analyze_supplied_privilege_artifacts(model)
        model = component_fixture()
        model["artifacts"].append(copy.deepcopy(model["artifacts"][0]))
        with self.assertRaises(WindowsPrivilegeArtifactError):
            analyze_supplied_privilege_artifacts(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsPrivilegeArtifactError):
            analyze_supplied_privilege_artifacts(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_privilege_artifacts(model)
        self.assertEqual(
            verify_supplied_privilege_artifacts(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["low_privilege_write_declared"] = False
        with self.assertRaises(WindowsPrivilegeArtifactError):
            verify_supplied_privilege_artifacts(report, model=changed)
        with self.assertRaises(WindowsPrivilegeArtifactError):
            WindowsPrivilegeArtifactReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
