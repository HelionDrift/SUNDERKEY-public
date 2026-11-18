"""Synthetic Windows autostart policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_autostart_policy import (
    WindowsAutostartPolicyError,
    WindowsAutostartPolicyReport,
    analyze_supplied_autostarts,
    component_fixture,
    verify_supplied_autostarts,
)


class WindowsAutostartPolicyTests(unittest.TestCase):
    def test_allowlist_gap_is_not_persistence_proof(self) -> None:
        report = analyze_supplied_autostarts(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], ["unapproved-task"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["autostart_verified"])
        self.assertFalse(report["artifact_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_artifact_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["approved_artifact_ids"].append("unapproved-task")
        report = analyze_supplied_autostarts(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["artifacts"].append(copy.deepcopy(model["artifacts"][0]))
        with self.assertRaises(WindowsAutostartPolicyError):
            analyze_supplied_autostarts(model)
        model = component_fixture()
        model["artifacts"][0]["mechanism"] = "unknown"
        with self.assertRaises(WindowsAutostartPolicyError):
            analyze_supplied_autostarts(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsAutostartPolicyError):
            analyze_supplied_autostarts(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_autostarts(model)
        self.assertEqual(
            verify_supplied_autostarts(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["enabled_declared"] = False
        with self.assertRaises(WindowsAutostartPolicyError):
            verify_supplied_autostarts(report, model=changed)
        with self.assertRaises(WindowsAutostartPolicyError):
            WindowsAutostartPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
