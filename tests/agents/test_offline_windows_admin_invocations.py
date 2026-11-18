"""Synthetic Windows administration invocation projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_admin_invocations import (
    WindowsAdminInvocationError,
    WindowsAdminInvocationReport,
    analyze_supplied_admin_invocations,
    component_fixture,
    verify_supplied_admin_invocations,
)


class WindowsAdminInvocationTests(unittest.TestCase):
    def test_approval_gap_does_not_prove_activity(self) -> None:
        report = analyze_supplied_admin_invocations(component_fixture()).to_dict()
        self.assertEqual(
            report["declared_policy_deviation_invocation_ids"], ["review-invocation"]
        )
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["command_text_read"])
        self.assertFalse(report["invocation_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["approved_invocation_ids"].append("review-invocation")
        report = analyze_supplied_admin_invocations(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_invocation_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["invocations"].append(copy.deepcopy(model["invocations"][0]))
        with self.assertRaises(WindowsAdminInvocationError):
            analyze_supplied_admin_invocations(model)
        model = component_fixture()
        model["invocations"][0]["family"] = "unknown"
        with self.assertRaises(WindowsAdminInvocationError):
            analyze_supplied_admin_invocations(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsAdminInvocationError):
            analyze_supplied_admin_invocations(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_admin_invocations(model)
        self.assertEqual(
            verify_supplied_admin_invocations(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["invocations"][0]["privileged_context_declared"] = False
        with self.assertRaises(WindowsAdminInvocationError):
            verify_supplied_admin_invocations(report, model=changed)
        with self.assertRaises(WindowsAdminInvocationError):
            WindowsAdminInvocationReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
