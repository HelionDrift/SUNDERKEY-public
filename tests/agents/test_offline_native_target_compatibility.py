"""Tests for bounded supplied native target metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_native_target_compatibility import (
    NativeTargetCompatibilityError,
    analyze_supplied_native_target_compatibility,
    component_fixture,
    verify_supplied_native_target_compatibility,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class NativeTargetCompatibilityTests(unittest.TestCase):
    def test_declared_difference_is_not_compatibility_proof(self) -> None:
        report = analyze_supplied_native_target_compatibility(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 2)
        self.assertFalse(report["target_compatibility_verified"])
        self.assertFalse(report["package_installed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_matching_complete_declarations_have_no_signal(self) -> None:
        model = component_fixture()
        item = model["artifacts"][0]
        item["supported_target_ids"].append(item["requested_target_id"])
        item["artifact_digest"] = item["pinned_digest"]
        report = analyze_supplied_native_target_compatibility(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 0)

    def test_incomplete_target_list_is_unknown(self) -> None:
        model = component_fixture()
        item = model["artifacts"][0]
        item["target_list_complete"] = False
        item["pinned_digest"] = None
        model["inventory_complete"] = False
        report = analyze_supplied_native_target_compatibility(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_commands_bad_digest_and_duplicates(self) -> None:
        model = component_fixture()
        model["artifacts"][0]["command"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_native_target_compatibility(model)
        model = component_fixture()
        model["artifacts"][0]["artifact_digest"] = "bad"
        with self.assertRaises(NativeTargetCompatibilityError):
            analyze_supplied_native_target_compatibility(model)
        model = component_fixture()
        model["artifacts"][0]["supported_target_ids"] = ["linux", "linux"]
        with self.assertRaises(NativeTargetCompatibilityError):
            analyze_supplied_native_target_compatibility(model)

    def test_duplicate_artifact_and_non_boolean_rejected(self) -> None:
        model = component_fixture()
        model["artifacts"].append(copy.deepcopy(model["artifacts"][0]))
        with self.assertRaises(NativeTargetCompatibilityError):
            analyze_supplied_native_target_compatibility(model)
        model = component_fixture()
        model["artifacts"][0]["target_list_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_native_target_compatibility(model)

    def test_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_native_target_compatibility(model)
        self.assertEqual(
            verify_supplied_native_target_compatibility(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        model["artifacts"][0]["requested_target_id"] = "windows_x86_64"
        with self.assertRaises(NativeTargetCompatibilityError):
            verify_supplied_native_target_compatibility(report, model=model)
        with self.assertRaises(NativeTargetCompatibilityError):
            verify_supplied_native_target_compatibility(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-native-target-compatibility-component.json").read_text()
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S07")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
