"""Synthetic Linux shell-tool policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_linux_shell_policy import (
    LinuxShellPolicyError,
    LinuxShellPolicyReport,
    analyze_supplied_shell_tools,
    component_fixture,
    verify_supplied_shell_tools,
)


class LinuxShellPolicyTests(unittest.TestCase):
    def test_approval_gap_is_not_execution(self) -> None:
        report = analyze_supplied_shell_tools(component_fixture()).to_dict()
        self.assertEqual(
            report["declared_policy_deviation_invocation_ids"], ["review-invocation"]
        )
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["command_text_read"])
        self.assertFalse(report["command_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["approved_privileged_invocation_ids"].append("review-invocation")
        report = analyze_supplied_shell_tools(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_invocation_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["invocations"].append(copy.deepcopy(model["invocations"][0]))
        with self.assertRaises(LinuxShellPolicyError):
            analyze_supplied_shell_tools(model)
        model = component_fixture()
        model["invocations"][0]["tool_family"] = "unknown"
        with self.assertRaises(LinuxShellPolicyError):
            analyze_supplied_shell_tools(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(LinuxShellPolicyError):
            analyze_supplied_shell_tools(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_shell_tools(model)
        self.assertEqual(
            verify_supplied_shell_tools(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["invocations"][0]["privileged_context_declared"] = False
        with self.assertRaises(LinuxShellPolicyError):
            verify_supplied_shell_tools(report, model=changed)
        with self.assertRaises(LinuxShellPolicyError):
            LinuxShellPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
