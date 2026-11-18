"""Tests for bounded supplied backup and restore metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_backup_recovery_posture import (
    BackupRecoveryPostureError,
    analyze_supplied_backup_recovery_posture,
    component_fixture,
    verify_supplied_backup_recovery_posture,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class BackupRecoveryPostureTests(unittest.TestCase):
    def test_declared_age_difference_is_not_recovery_proof(self) -> None:
        report = analyze_supplied_backup_recovery_posture(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["unknown_count"], 1)
        self.assertFalse(report["restore_executed"])
        self.assertFalse(report["asset_contacted"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_matching_complete_declarations_have_no_signal(self) -> None:
        model = component_fixture()
        asset = model["assets"][0]
        asset["latest_backup_age_seconds"] = 1800
        asset["latest_restore_test_age_seconds"] = 3600
        report = analyze_supplied_backup_recovery_posture(model).to_dict()
        self.assertEqual(report["disposition"], "no_declared_recovery_review_signal")
        self.assertEqual(report["unknown_count"], 0)

    def test_disabled_backup_and_stale_restore_are_signals(self) -> None:
        model = component_fixture()
        asset = model["assets"][0]
        asset["backup_enabled"] = False
        asset["latest_restore_test_age_seconds"] = 90_000
        report = analyze_supplied_backup_recovery_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 3)

    def test_missing_required_metadata_and_incomplete_inventory_are_unknown(self) -> None:
        model = component_fixture()
        asset = model["assets"][0]
        asset["backup_enabled"] = None
        asset["latest_backup_age_seconds"] = None
        model["inventory_complete"] = False
        report = analyze_supplied_backup_recovery_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_extra_fields_and_bad_age(self) -> None:
        model = component_fixture()
        model["assets"][0]["restore_command"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_backup_recovery_posture(model)
        model = component_fixture()
        model["assets"][0]["latest_backup_age_seconds"] = -1
        with self.assertRaises(BackupRecoveryPostureError):
            analyze_supplied_backup_recovery_posture(model)
        model = component_fixture()
        model["assets"][0]["backup_enabled"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_backup_recovery_posture(model)

    def test_duplicate_asset_and_replay_tamper_rejected(self) -> None:
        model = component_fixture()
        model["assets"].append(copy.deepcopy(model["assets"][0]))
        with self.assertRaises(BackupRecoveryPostureError):
            analyze_supplied_backup_recovery_posture(model)
        model = component_fixture()
        report = analyze_supplied_backup_recovery_posture(model)
        self.assertEqual(
            verify_supplied_backup_recovery_posture(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["assets"][0]["latest_backup_age_seconds"] = 1800
        with self.assertRaises(BackupRecoveryPostureError):
            verify_supplied_backup_recovery_posture(report, model=model)
        with self.assertRaises(BackupRecoveryPostureError):
            verify_supplied_backup_recovery_posture(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        path = ROOT / "examples/offline-backup-recovery-posture-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D16-S08")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
