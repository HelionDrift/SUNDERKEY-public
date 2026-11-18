"""Synthetic Windows security-control projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_control_state import (
    WindowsControlStateError,
    WindowsControlStateReport,
    analyze_supplied_control_states,
    component_fixture,
    verify_supplied_control_states,
)


class WindowsControlStateTests(unittest.TestCase):
    def test_declared_gap_is_not_control_impairment(self) -> None:
        report = analyze_supplied_control_states(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_control_ids"], ["control-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["control_state_verified"])
        self.assertFalse(report["control_changed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_enabled_control_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["controls"][0]["enabled_declared"] = True
        report = analyze_supplied_control_states(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_control_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_missing_required_control_remains_unknown(self) -> None:
        model = component_fixture()
        model["required_enabled_control_ids"].append("control-b")
        report = analyze_supplied_control_states(model).to_dict()
        self.assertEqual(report["missing_required_control_ids"], ["control-b"])
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["declared_policy_deviation_control_ids"], ["control-a"])

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["controls"].append(copy.deepcopy(model["controls"][0]))
        with self.assertRaises(WindowsControlStateError):
            analyze_supplied_control_states(model)
        model = component_fixture()
        model["controls"][0]["control_kind"] = "unknown"
        with self.assertRaises(WindowsControlStateError):
            analyze_supplied_control_states(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsControlStateError):
            analyze_supplied_control_states(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_control_states(model)
        self.assertEqual(
            verify_supplied_control_states(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["controls"][0]["enabled_declared"] = True
        with self.assertRaises(WindowsControlStateError):
            verify_supplied_control_states(report, model=changed)
        with self.assertRaises(WindowsControlStateError):
            WindowsControlStateReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
