"""Cloud inventory drift remains a supplied-data comparison only."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_cloud_inventory_drift import (
    CloudInventoryDriftAnalysis,
    CloudInventoryDriftError,
    analyze_supplied_cloud_inventory_drift,
    verify_supplied_cloud_inventory_drift,
)


def _record(record_id: str, resource_id: str, kind: str, source: str = "fixture-a") -> dict:
    return {
        "record_id": record_id,
        "provider": "gcp",
        "scope_id": "project-fixture",
        "resource_id": resource_id,
        "resource_type": kind,
        "region": "us-west1",
        "source_id": source,
    }


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-cloud-inventory-drift-v1",
        "snapshots": [
            {
                "snapshot_id": "earlier",
                "records": [
                    _record("e-change", "fixture-change", "compute.instance"),
                    _record("e-missing", "fixture-missing", "storage.bucket"),
                    _record("e-same", "fixture-same", "compute.instance"),
                ],
            },
            {
                "snapshot_id": "later",
                "records": [
                    _record("l-change", "fixture-change", "compute.group"),
                    _record("l-new", "fixture-new", "storage.bucket"),
                    _record("l-same", "fixture-same", "compute.instance"),
                    _record("l-conflict-a", "fixture-conflict", "compute.instance"),
                    _record("l-conflict-b", "fixture-conflict", "storage.bucket", "fixture-b"),
                ],
            },
        ],
    }


class CloudInventoryDriftTests(unittest.TestCase):
    def test_changed_new_missing_unchanged_and_conflicted_claims(self):
        model = _model()
        original = copy.deepcopy(model)
        analysis = analyze_supplied_cloud_inventory_drift(model)
        report = analysis.to_dict()
        rows = {row["resource_id"]: row for row in report["observations"]}
        self.assertEqual(rows["fixture-change"]["state"], "changed_supplied_claim")
        self.assertEqual(rows["fixture-new"]["state"], "new_in_supplied_latest")
        self.assertEqual(rows["fixture-missing"]["state"], "not_observed_in_supplied_latest")
        self.assertEqual(rows["fixture-same"]["state"], "unchanged_supplied_claim")
        self.assertEqual(rows["fixture-conflict"]["state"], "conflicted_supplied_latest")
        self.assertEqual(rows["fixture-conflict"]["later_source_ids"], ["fixture-a", "fixture-b"])
        self.assertFalse(report["flags"]["provider_resource_deletion_proven"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_cloud_inventory_drift(analysis, model=model).to_dict(), report
        )

    def test_prior_conflict_is_not_implicitly_resolved_by_latest_absence(self):
        model = _model()
        model["snapshots"][0]["records"].append(
            _record("e-missing-conflict", "fixture-missing", "compute.instance", "fixture-b")
        )
        row = next(
            row
            for row in analyze_supplied_cloud_inventory_drift(model).to_dict()["observations"]
            if row["resource_id"] == "fixture-missing"
        )
        self.assertEqual(row["state"], "incomparable_prior_conflict")

    def test_duplicate_source_identity_invalid_types_and_tamper_are_rejected(self):
        model = _model()
        model["snapshots"][1]["records"].append(
            _record("duplicate", "fixture-new", "storage.bucket")
        )
        with self.assertRaises(CloudInventoryDriftError):
            analyze_supplied_cloud_inventory_drift(model)
        model = _model()
        model["snapshots"][0]["records"][0]["provider"] = "GCP"
        with self.assertRaises(CloudInventoryDriftError):
            analyze_supplied_cloud_inventory_drift(model)
        model = _model()
        model["snapshots"][0]["records"][0]["region"] = True
        with self.assertRaises(CloudInventoryDriftError):
            analyze_supplied_cloud_inventory_drift(model)
        model = _model()
        model["snapshots"][0]["snapshot_id"] = "later"
        with self.assertRaises(CloudInventoryDriftError):
            analyze_supplied_cloud_inventory_drift(model)
        report = analyze_supplied_cloud_inventory_drift(_model()).to_dict()
        report["flags"]["provider_resource_existence_proven"] = True
        with self.assertRaises(CloudInventoryDriftError):
            CloudInventoryDriftAnalysis(report)
        analysis = analyze_supplied_cloud_inventory_drift(_model())
        model = _model()
        model["snapshots"][1]["records"][0]["resource_type"] = "compute.other"
        with self.assertRaises(CloudInventoryDriftError):
            verify_supplied_cloud_inventory_drift(analysis, model=model)


if __name__ == "__main__":
    unittest.main()
