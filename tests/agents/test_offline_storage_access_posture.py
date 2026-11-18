"""Tests for bounded supplied SAN and NAS access metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)
from sunderkey.offline_storage_access_posture import (
    StorageAccessPostureError,
    analyze_supplied_storage_access_posture,
    component_fixture,
    verify_supplied_storage_access_posture,
)

ROOT = Path(__file__).resolve().parents[2]


class StorageAccessPostureTests(unittest.TestCase):
    def test_declared_public_scope_is_not_reachability_proof(self) -> None:
        report = analyze_supplied_storage_access_posture(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["unknown_count"], 1)
        self.assertFalse(report["storage_access_verified"])
        self.assertFalse(report["storage_contacted"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_internal_complete_declarations_have_no_signal(self) -> None:
        model = component_fixture()
        resource = model["resources"][0]
        resource["exposure_scope"] = "internal"
        resource["write_scope"] = "approved"
        report = analyze_supplied_storage_access_posture(model).to_dict()
        self.assertEqual(report["disposition"], "no_declared_storage_access_review_signal")
        self.assertEqual(report["unknown_count"], 0)

    def test_public_write_scope_is_a_separate_signal(self) -> None:
        model = component_fixture()
        model["resources"][0]["write_scope"] = "public"
        report = analyze_supplied_storage_access_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 2)

    def test_incomplete_scope_does_not_assert_public_access(self) -> None:
        model = component_fixture()
        model["resources"][0]["scope_assertions_complete"] = False
        model["inventory_complete"] = False
        report = analyze_supplied_storage_access_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_extra_fields_and_bad_values(self) -> None:
        model = component_fixture()
        model["resources"][0]["credential"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_storage_access_posture(model)
        model = component_fixture()
        model["resources"][0]["protocol"] = []
        with self.assertRaises(ValueError):
            analyze_supplied_storage_access_posture(model)
        model = component_fixture()
        model["resources"][0]["data_sensitive"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_storage_access_posture(model)

    def test_duplicate_resource_and_replay_tamper_rejected(self) -> None:
        model = component_fixture()
        model["resources"].append(copy.deepcopy(model["resources"][0]))
        with self.assertRaises(StorageAccessPostureError):
            analyze_supplied_storage_access_posture(model)
        model = component_fixture()
        report = analyze_supplied_storage_access_posture(model)
        self.assertEqual(
            verify_supplied_storage_access_posture(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["resources"][0]["write_scope"] = "public"
        with self.assertRaises(StorageAccessPostureError):
            verify_supplied_storage_access_posture(report, model=model)
        with self.assertRaises(StorageAccessPostureError):
            verify_supplied_storage_access_posture(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        path = ROOT / "examples/offline-storage-access-posture-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D16-S09")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
