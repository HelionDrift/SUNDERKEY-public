"""Bounded, inert key lifecycle posture projections and replay checks."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_key_lifecycle_posture import (
    KeyLifecyclePostureError,
    KeyLifecyclePostureReport,
    analyze_supplied_key_lifecycle,
    component_fixture,
    verify_supplied_key_lifecycle,
)


class KeyLifecyclePostureTests(unittest.TestCase):
    def test_elapsed_rotation_is_only_a_declared_review_signal(self) -> None:
        report = analyze_supplied_key_lifecycle(component_fixture()).to_dict()
        self.assertEqual(report["disposition"], "candidate_declared_key_lifecycle_review")
        self.assertEqual(report["signals"], [{
            "key_id": "key_a", "issue": "declared_rotation_interval_elapsed",
        }])
        self.assertFalse(report["kms_queried"])
        self.assertFalse(report["policy_effectiveness_verified"])
        self.assertFalse(report["qualification_claimed"])

    def test_exact_rotation_boundary_is_not_elapsed(self) -> None:
        model = component_fixture()
        model["snapshot_at"] = "2025-04-01T00:00:00Z"
        model["keys"][0]["last_use_at"] = "2025-03-01T00:00:00Z"
        report = analyze_supplied_key_lifecycle(model).to_dict()
        self.assertEqual(report["signals"], [])
        self.assertEqual(report["disposition"], "no_declared_key_lifecycle_signal")

    def test_declared_post_destruction_use_is_distinct_from_rotation(self) -> None:
        model = component_fixture()
        row = model["keys"][0]
        row["state"] = "destroyed"
        row["destroyed_at"] = "2025-06-01T00:00:00Z"
        report = analyze_supplied_key_lifecycle(model).to_dict()
        self.assertEqual(report["signals"], [{
            "key_id": "key_a", "issue": "declared_use_after_destruction",
        }])

    def test_incomplete_policy_cannot_be_promoted_to_signal(self) -> None:
        model = component_fixture()
        model["keys"][0]["policy_assertions_complete"] = False
        report = analyze_supplied_key_lifecycle(model).to_dict()
        self.assertEqual(report["signals"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_missing_rotation_policy_remains_unknown(self) -> None:
        model = component_fixture()
        model["keys"][0]["rotation_interval_days"] = None
        report = analyze_supplied_key_lifecycle(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["uncertainty"][0]["issue"], "rotation_policy_not_asserted")

    def test_incomplete_inventory_and_empty_inventory_remain_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["keys"] = []
        report = analyze_supplied_key_lifecycle(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertGreater(report["unknown_count"], 0)

    def test_rejects_duplicate_or_bad_lifecycle(self) -> None:
        duplicate = component_fixture()
        duplicate["keys"].append(copy.deepcopy(duplicate["keys"][0]))
        with self.assertRaises(KeyLifecyclePostureError):
            analyze_supplied_key_lifecycle(duplicate)
        bad = component_fixture()
        bad["keys"][0]["last_rotation_at"] = "2027-01-01T00:00:00Z"
        with self.assertRaises(KeyLifecyclePostureError):
            analyze_supplied_key_lifecycle(bad)
        bad = component_fixture()
        bad["keys"][0]["created_at"] = "2025-02-30T00:00:00Z"
        with self.assertRaises(KeyLifecyclePostureError):
            analyze_supplied_key_lifecycle(bad)

    def test_rejects_ambiguous_fields_and_boolean_interval(self) -> None:
        model = component_fixture()
        model["keys"][0]["effective_permission"] = "all"
        with self.assertRaises(ValueError):
            analyze_supplied_key_lifecycle(model)
        model = component_fixture()
        model["keys"][0]["rotation_interval_days"] = True
        with self.assertRaises(KeyLifecyclePostureError):
            analyze_supplied_key_lifecycle(model)

    def test_report_requires_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_key_lifecycle(model)
        self.assertEqual(
            verify_supplied_key_lifecycle(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["keys"][0]["last_use_at"] = None
        with self.assertRaises(KeyLifecyclePostureError):
            verify_supplied_key_lifecycle(report, model=changed)
        with self.assertRaises(KeyLifecyclePostureError):
            KeyLifecyclePostureReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
