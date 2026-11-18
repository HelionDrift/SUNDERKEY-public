"""Synthetic macOS security-control projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_security_controls import (
    MacosSecurityControlError,
    MacosSecurityControlReport,
    analyze_supplied_macos_controls,
    component_fixture,
    verify_supplied_macos_controls,
)


class MacosSecurityControlTests(unittest.TestCase):
    def test_declared_gap_is_not_control_bypass(self) -> None:
        report = analyze_supplied_macos_controls(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_control_ids"], ["sip"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["control_state_verified"])
        self.assertFalse(report["control_changed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_missing_required_remains_unknown(self) -> None:
        model = component_fixture()
        model["controls"] = [model["controls"][0]]
        report = analyze_supplied_macos_controls(model).to_dict()
        self.assertEqual(report["missing_required_control_ids"], ["gatekeeper"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["controls"].append(copy.deepcopy(model["controls"][0]))
        with self.assertRaises(MacosSecurityControlError):
            analyze_supplied_macos_controls(model)
        model = component_fixture()
        model["controls"][0]["control_id"] = "unknown"
        with self.assertRaises(MacosSecurityControlError):
            analyze_supplied_macos_controls(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosSecurityControlError):
            analyze_supplied_macos_controls(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_macos_controls(model)
        self.assertEqual(
            verify_supplied_macos_controls(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["controls"][0]["enabled_declared"] = True
        with self.assertRaises(MacosSecurityControlError):
            verify_supplied_macos_controls(report, model=changed)
        with self.assertRaises(MacosSecurityControlError):
            MacosSecurityControlReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
