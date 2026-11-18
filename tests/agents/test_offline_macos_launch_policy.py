"""Synthetic macOS launch-job policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_launch_policy import (
    MacosLaunchPolicyError,
    MacosLaunchPolicyReport,
    analyze_supplied_launch_jobs,
    component_fixture,
    verify_supplied_launch_jobs,
)


class MacosLaunchPolicyTests(unittest.TestCase):
    def test_approval_gap_is_not_persistence_proof(self) -> None:
        report = analyze_supplied_launch_jobs(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_job_ids"], ["review-job"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["launchd_queried"])
        self.assertFalse(report["job_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["approved_job_ids"].append("review-job")
        report = analyze_supplied_launch_jobs(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_job_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["jobs"].append(copy.deepcopy(model["jobs"][0]))
        with self.assertRaises(MacosLaunchPolicyError):
            analyze_supplied_launch_jobs(model)
        model = component_fixture()
        model["jobs"][0]["job_domain"] = "unknown"
        with self.assertRaises(MacosLaunchPolicyError):
            analyze_supplied_launch_jobs(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosLaunchPolicyError):
            analyze_supplied_launch_jobs(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_launch_jobs(model)
        self.assertEqual(
            verify_supplied_launch_jobs(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["jobs"][0]["enabled_declared"] = False
        with self.assertRaises(MacosLaunchPolicyError):
            verify_supplied_launch_jobs(report, model=changed)
        with self.assertRaises(MacosLaunchPolicyError):
            MacosLaunchPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
