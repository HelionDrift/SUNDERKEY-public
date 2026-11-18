"""Supplied vendor update lineage projection tests."""

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
from sunderkey.offline_vendor_update_lineage import (
    VendorUpdateLineageError,
    analyze_supplied_vendor_update_lineage,
    component_fixture,
    verify_supplied_vendor_update_lineage,
)

ROOT = Path(__file__).resolve().parents[2]


class VendorUpdateLineageTests(unittest.TestCase):
    def test_supplied_rollback_and_expiration_are_replayable_candidates(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vendor_update_lineage(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "candidate_declared_update_lineage_conflict")
        self.assertEqual(body["candidate_count"], 3)
        self.assertEqual(
            {row["issue"] for row in body["signals"]},
            {
                "declared_metadata_version_rollback",
                "declared_release_version_rollback",
                "expired_at_supplied_observation_time",
            },
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        for key in (
            "source_authenticated",
            "metadata_signatures_verified",
            "artifact_bytes_read",
            "clock_authenticated",
            "update_installed",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(body[key])
        self.assertEqual(
            verify_supplied_vendor_update_lineage(report, model=model).to_json(),
            report.to_json(),
        )

    def test_same_version_digest_divergence_is_distinct_from_rollback(self) -> None:
        model = component_fixture()
        model["offers"][0]["release_version"] = 12
        model["offers"][0]["metadata_version"] = 8
        model["offers"][0]["expires_at"] = "2026-02-01T00:00:00Z"
        body = analyze_supplied_vendor_update_lineage(model).to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["signals"][0]["issue"], "same_version_digest_divergence")

    def test_cross_channel_and_incomplete_inventory_remain_unknown(self) -> None:
        model = component_fixture()
        model["offers"][0]["channel_id"] = "preview"
        body = analyze_supplied_vendor_update_lineage(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["signals"], [])
        self.assertEqual(body["uncertainty"][0]["issue"], "different_declared_channel")
        model["offers"] = []
        body = analyze_supplied_vendor_update_lineage(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertGreater(body["unknown_count"], 0)
        model["offers"] = [
            {
                "offer_id": "offer_ok",
                "channel_id": "stable",
                "release_version": 13,
                "artifact_sha256": "sha256:" + "c" * 64,
                "metadata_version": 9,
                "expires_at": "2026-02-01T00:00:00Z",
            }
        ]
        model["inventory_complete"] = False
        body = analyze_supplied_vendor_update_lineage(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unknown_count"], 1)

    def test_raw_payloads_bad_times_duplicate_ids_and_native_aliases_fail(self) -> None:
        cases = []
        model = component_fixture()
        model["offers"][0]["signature"] = "not accepted"
        cases.append(model)
        model = component_fixture()
        model["trusted"]["artifact_sha256"] = "not-a-digest"
        cases.append(model)
        model = component_fixture()
        model["observed_at"] = "2026-01-05T00:00:00+00:00"
        cases.append(model)
        model = component_fixture()
        model["offers"][0]["expires_at"] = "2026-02-30T00:00:00Z"
        cases.append(model)
        model = component_fixture()
        model["offers"].append(copy.deepcopy(model["offers"][0]))
        cases.append(model)
        model = component_fixture()
        model["trusted"]["release_version"] = True
        cases.append(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_vendor_update_lineage(model)

    def test_original_model_substitution_and_direct_report_forgery_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vendor_update_lineage(model)
        changed = copy.deepcopy(model)
        changed["offers"][0]["metadata_version"] = 8
        with self.assertRaises(VendorUpdateLineageError):
            verify_supplied_vendor_update_lineage(report, model=changed)
        with self.assertRaises(VendorUpdateLineageError):
            verify_supplied_vendor_update_lineage(report.to_dict(), model=model)

    def test_catalog_dispatch_is_nonqualifying_and_source_bound(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-vendor-update-lineage-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S14")
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["full_candidate_assembled"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["offers"][0]["metadata_version"] = 8
        with self.assertRaises(ValueError):
            verify_offline_specialist_component_result(
                result, request=changed, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
