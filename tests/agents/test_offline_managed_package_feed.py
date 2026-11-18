"""Tests for bounded supplied managed-package metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_managed_package_feed import (
    ManagedPackageFeedError,
    analyze_supplied_managed_package_feed,
    component_fixture,
    verify_supplied_managed_package_feed,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class ManagedPackageFeedTests(unittest.TestCase):
    def test_declared_difference_is_not_a_finding(self) -> None:
        report = analyze_supplied_managed_package_feed(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual(report["unknown_count"], 1)
        self.assertFalse(report["feed_contacted"])
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_matching_complete_declarations_have_no_signal(self) -> None:
        model = component_fixture()
        item = model["packages"][0]
        item["selected_feed_id"] = item["intended_feed_id"]
        item["selected_artifact_sha256"] = item["pinned_artifact_sha256"]
        item["verification_state"] = "verified"
        report = analyze_supplied_managed_package_feed(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 0)

    def test_incomplete_declarations_remain_unknown(self) -> None:
        model = component_fixture()
        item = model["packages"][0]
        item["selected_feed_id"] = item["intended_feed_id"]
        item["pinned_artifact_sha256"] = None
        item["verification_state"] = "unknown"
        model["inventory_complete"] = False
        report = analyze_supplied_managed_package_feed(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["candidate_count"], 0)

    def test_asserted_verification_failure_is_only_a_signal(self) -> None:
        model = component_fixture()
        model["packages"][0]["verification_state"] = "failed"
        report = analyze_supplied_managed_package_feed(model).to_dict()
        self.assertIn("declared_verification_failure", {x["issue"] for x in report["signals"]})

    def test_closed_model_rejects_extra_fields_and_invalid_values(self) -> None:
        model = component_fixture()
        model["packages"][0]["command"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_managed_package_feed(model)
        model = component_fixture()
        model["packages"][0]["ecosystem"] = []
        with self.assertRaises(ValueError):
            analyze_supplied_managed_package_feed(model)
        model = component_fixture()
        model["packages"][0]["selected_artifact_sha256"] = "bad"
        with self.assertRaises(ManagedPackageFeedError):
            analyze_supplied_managed_package_feed(model)

    def test_rejects_duplicate_and_non_boolean(self) -> None:
        model = component_fixture()
        model["packages"].append(copy.deepcopy(model["packages"][0]))
        with self.assertRaises(ManagedPackageFeedError):
            analyze_supplied_managed_package_feed(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_managed_package_feed(model)

    def test_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_managed_package_feed(model)
        self.assertEqual(
            verify_supplied_managed_package_feed(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["packages"][0]["selected_feed_id"] = "internal"
        with self.assertRaises(ManagedPackageFeedError):
            verify_supplied_managed_package_feed(report, model=model)
        with self.assertRaises(ManagedPackageFeedError):
            verify_supplied_managed_package_feed(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-managed-package-feed-component.json").read_text()
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S06")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
