"""Synthetic scheduled-artifact policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_scheduled_artifact_policy import (
    ScheduledArtifactPolicyError,
    ScheduledArtifactPolicyReport,
    analyze_supplied_schedules,
    component_fixture,
    verify_supplied_schedules,
)


class ScheduledArtifactPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_persistence_finding(self) -> None:
        report = analyze_supplied_schedules(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_schedule_ids"], ["task-a"])
        self.assertEqual(len(report["schedule_projections"][0]["declared_policy_flags"]), 2)
        self.assertFalse(report["systemd_unit_parsed"])
        self.assertFalse(report["crontab_parsed"])
        self.assertFalse(report["service_started"])
        self.assertFalse(report["persistence_installed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_disabled_schedule_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["schedules"][0]["enabled_declared"] = False
        report = analyze_supplied_schedules(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_schedule_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_policy_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["schedules"][0]["policy_id"] = "unknown"
        with self.assertRaises(ScheduledArtifactPolicyError):
            analyze_supplied_schedules(model)
        model = component_fixture()
        model["schedules"].append(copy.deepcopy(model["schedules"][0]))
        with self.assertRaises(ScheduledArtifactPolicyError):
            analyze_supplied_schedules(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(ScheduledArtifactPolicyError):
            analyze_supplied_schedules(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_schedules(model)
        self.assertEqual(
            verify_supplied_schedules(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["schedules"][0]["enabled_declared"] = False
        with self.assertRaises(ScheduledArtifactPolicyError):
            verify_supplied_schedules(report, model=changed)
        with self.assertRaises(ScheduledArtifactPolicyError):
            ScheduledArtifactPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
