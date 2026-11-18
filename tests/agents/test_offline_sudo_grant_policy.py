"""Synthetic sudo-grant projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_sudo_grant_policy import (
    SudoGrantPolicyError,
    SudoGrantPolicyReport,
    analyze_supplied_sudo_grants,
    component_fixture,
    verify_supplied_sudo_grants,
)


class SudoGrantPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_privilege_finding(self) -> None:
        report = analyze_supplied_sudo_grants(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_grant_ids"], ["grant-a"])
        self.assertEqual(len(report["grant_projections"][0]["declared_policy_flags"]), 2)
        self.assertFalse(report["sudoers_parsed"])
        self.assertFalse(report["command_executed"])
        self.assertFalse(report["privilege_change_attempted"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_incomplete_inventory_is_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["grants"][0]["root_run_declared"] = False
        report = analyze_supplied_sudo_grants(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_grant_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_principal_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["grants"][0]["principal_id"] = "unknown"
        with self.assertRaises(SudoGrantPolicyError):
            analyze_supplied_sudo_grants(model)
        model = component_fixture()
        model["principal_ids"] = ["operator", "operator"]
        with self.assertRaises(SudoGrantPolicyError):
            analyze_supplied_sudo_grants(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SudoGrantPolicyError):
            analyze_supplied_sudo_grants(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_sudo_grants(model)
        self.assertEqual(
            verify_supplied_sudo_grants(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["grants"][0]["root_run_declared"] = False
        with self.assertRaises(SudoGrantPolicyError):
            verify_supplied_sudo_grants(report, model=changed)
        with self.assertRaises(SudoGrantPolicyError):
            SudoGrantPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
