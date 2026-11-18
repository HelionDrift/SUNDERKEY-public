"""Synthetic emerging-threat intake cannot authorize a live validation."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.emerging_threat_review import (
    EmergingThreatReviewError,
    build_emerging_threat_review,
    verify_emerging_threat_review,
)

NOW = "2026-10-03T22:00:00Z"


def sources() -> tuple[dict, dict]:
    advisory = {
        "schema_version": 1,
        "advisory_id": "ADV-SYNTHETIC-01",
        "source_kind": "vendor",
        "source_ref": "SOURCE-SYNTHETIC-01",
        "source_sha256": "sha256:" + "a" * 64,
        "published_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-10-10T00:00:00Z",
        "affected": [{
            "product_key": "sample.service",
            "exact_versions": ["1.0", "1.1"],
        }],
        "validation_content_sha256": "sha256:" + "b" * 64,
    }
    inventory = {
        "schema_version": 1,
        "snapshot_id": "INV-SYNTHETIC-01",
        "recorded_at": "2026-10-02T00:00:00Z",
        "assets": [
            {
                "asset_id": "asset-01", "product_key": "sample.service",
                "version": "1.0", "scope_state": "in_scope",
                "ownership_state": "confirmed",
            },
            {
                "asset_id": "asset-02", "product_key": "sample.service",
                "version": "1.0", "scope_state": "out_of_scope",
                "ownership_state": "confirmed",
            },
            {
                "asset_id": "asset-03", "product_key": "sample.service",
                "version": None, "scope_state": "in_scope",
                "ownership_state": "confirmed",
            },
            {
                "asset_id": "asset-04", "product_key": "sample.service",
                "version": "2.0", "scope_state": "in_scope",
                "ownership_state": "confirmed",
            },
            {
                "asset_id": "asset-05", "product_key": "other.service",
                "version": "1.0", "scope_state": "in_scope",
                "ownership_state": "confirmed",
            },
            {
                "asset_id": "asset-06", "product_key": "sample.service",
                "version": "1.0", "scope_state": "unknown",
                "ownership_state": "confirmed",
            },
        ],
    }
    return advisory, inventory


class EmergingThreatReviewTests(unittest.TestCase):
    def test_exact_matching_is_review_only_and_source_bound(self) -> None:
        advisory, inventory = sources()
        result = build_emerging_threat_review(advisory, inventory, NOW)
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(
            [item["disposition"] for item in result["assets"]],
            [
                "declared_exact_match_review_only", "out_of_scope",
                "version_unknown", "version_not_declared_affected",
                "product_not_declared_affected", "scope_or_owner_unknown",
            ],
        )
        self.assertEqual(result["review_status"], "independent_review_required")
        self.assertEqual(result["validation_content_state"], "hash_only_quarantined")
        self.assertEqual(result["effects"]["test_execution"], "none")
        self.assertEqual(result["effects"]["target_interaction"], "none")
        self.assertNotIn("sample.service", json.dumps(result))
        self.assertEqual(
            verify_emerging_threat_review(advisory, inventory, NOW, result)["status"],
            "valid",
        )

    def test_expiration_and_missing_content_never_select_an_asset(self) -> None:
        advisory, inventory = sources()
        advisory["validation_content_sha256"] = None
        result = build_emerging_threat_review(
            advisory, inventory, advisory["expires_at"]
        )
        self.assertEqual(result["advisory_state"], "expired")
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["validation_content_state"], "not_supplied")
        self.assertTrue(all(
            item["disposition"] == "expired_no_selection" for item in result["assets"]
        ))

    def test_unknown_owner_blocks_even_an_exact_match(self) -> None:
        advisory, inventory = sources()
        inventory["assets"][0]["ownership_state"] = "unknown"
        result = build_emerging_threat_review(advisory, inventory, NOW)
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["assets"][0]["disposition"], "scope_or_owner_unknown")

    def test_stale_inventory_blocks_all_current_candidates(self) -> None:
        advisory, inventory = sources()
        result = build_emerging_threat_review(
            advisory, inventory, NOW, maximum_inventory_age_seconds=3600
        )
        self.assertEqual(result["inventory_state"], "stale")
        self.assertEqual(result["inventory_age_seconds"], 165600)
        self.assertEqual(result["candidate_count"], 0)
        self.assertTrue(all(
            item["disposition"] == "stale_inventory_no_selection"
            for item in result["assets"]
        ))
        self.assertEqual(
            verify_emerging_threat_review(
                advisory, inventory, NOW, result,
                maximum_inventory_age_seconds=3600,
            )["status"],
            "valid",
        )
        with self.assertRaises(EmergingThreatReviewError):
            verify_emerging_threat_review(advisory, inventory, NOW, result)

    def test_stale_or_substituted_sources_and_results_fail(self) -> None:
        advisory, inventory = sources()
        result = build_emerging_threat_review(advisory, inventory, NOW)
        changed = copy.deepcopy(result)
        changed["candidate_count"] = True
        with self.assertRaises(EmergingThreatReviewError):
            verify_emerging_threat_review(advisory, inventory, NOW, changed)
        inventory["assets"][0]["version"] = "1.1"
        with self.assertRaises(EmergingThreatReviewError):
            verify_emerging_threat_review(advisory, inventory, NOW, result)

    def test_invalid_order_and_untrusted_source_shapes_fail(self) -> None:
        for mutate in (
            lambda a, i: a.update(schema_version=True),
            lambda a, i: a.update(source_kind=True),
            lambda a, i: a.update(source_sha256="not-a-digest"),
            lambda a, i: a.update(published_at="2026-11-01T00:00:00Z"),
            lambda a, i: a["affected"].append(copy.deepcopy(a["affected"][0])),
            lambda a, i: a["affected"][0]["exact_versions"].reverse(),
            lambda a, i: i["assets"].append(copy.deepcopy(i["assets"][0])),
            lambda a, i: i["assets"][0].update(scope_state="authorized"),
            lambda a, i: i["assets"][0].update(scope_state=True),
            lambda a, i: i.update(recorded_at="2026-11-01T00:00:00Z"),
        ):
            advisory, inventory = sources()
            mutate(advisory, inventory)
            with self.assertRaises(EmergingThreatReviewError):
                build_emerging_threat_review(advisory, inventory, NOW)

    def test_report_matches_closed_schema(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/emerging-threat-review-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        advisory, inventory = sources()
        Draft202012Validator(schema).validate(
            build_emerging_threat_review(advisory, inventory, NOW)
        )

    def test_synthetic_repository_example_replays(self) -> None:
        example_path = (
            Path(__file__).resolve().parents[2]
            / "examples/emerging-threat-review-v1.json"
        )
        example = json.loads(example_path.read_text(encoding="utf-8"))
        self.assertEqual(set(example), {"review_at", "advisory", "inventory"})
        report = build_emerging_threat_review(
            example["advisory"], example["inventory"], example["review_at"]
        )
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(
            verify_emerging_threat_review(
                example["advisory"], example["inventory"], example["review_at"],
                report,
            )["status"],
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
