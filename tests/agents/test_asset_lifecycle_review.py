from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from sunderkey.asset_lifecycle_review import (
    AssetLifecycleReviewError,
    build_asset_lifecycle_review,
    verify_asset_lifecycle_review,
)
from sunderkey.asset_reconciliation import (
    IdentifierKind,
    SourceKind,
    reconcile_asset_observations,
)

from .test_asset_reconciliation_phase208 import identifier, observation

TENANT = "tenant:alpha"
FIRST = "2026-09-21T10:00:00Z"
SECOND = "2026-09-21T11:00:00Z"
SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "registry/schemas/asset-lifecycle-review-v1.schema.json"
)


class AssetLifecycleReviewTests(unittest.TestCase):
    @staticmethod
    def _pair(prior_records, current_records):
        prior = reconcile_asset_observations(TENANT, FIRST, prior_records)
        current = reconcile_asset_observations(
            TENANT, SECOND, current_records, prior_snapshot=prior
        )
        return prior, current

    def test_retained_and_unobserved_assets_require_distinct_review(self) -> None:
        prior_records = (
            observation(SourceKind.CMDB, "asset-a", digest_index=1),
            observation(SourceKind.CMDB, "asset-b", digest_index=2),
        )
        current_records = (observation(SourceKind.CMDB, "asset-a", digest_index=3),)
        prior, current = self._pair(prior_records, current_records)
        report = build_asset_lifecycle_review(prior, current, prior_records, current_records)
        entries = {item["prior_asset_id"]: item for item in report["entries"]}
        retained = next(
            item for item in prior.assets
            if any(identifier.value == "asset-a" for identifier in item.identifiers)
        )
        missing = next(
            item for item in prior.assets
            if any(identifier.value == "asset-b" for identifier in item.identifiers)
        )
        self.assertEqual(entries[retained.asset_id]["disposition"], "retained")
        self.assertFalse(entries[retained.asset_id]["review_required"])
        self.assertEqual(
            entries[missing.asset_id]["disposition"], "unobserved_with_class_overlap"
        )
        self.assertTrue(entries[missing.asset_id]["tombstone_review_candidate"])
        self.assertFalse(entries[missing.asset_id]["tombstone_applied"])
        self.assertEqual(report["summary"]["retired_asset_count"], 0)
        self.assertFalse(report["effects"]["asset_retirement"])
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
        self.assertEqual(
            verify_asset_lifecycle_review(
                json.dumps(report), prior, current, prior_records, current_records
            ),
            report,
        )

    def test_missing_source_class_does_not_look_like_complete_coverage(self) -> None:
        prior_records = (observation(SourceKind.CMDB, "asset-a"),)
        current_records = (observation(SourceKind.ENDPOINT, "device-b", digest_index=2),)
        prior, current = self._pair(prior_records, current_records)
        report = build_asset_lifecycle_review(prior, current, prior_records, current_records)
        entry = report["entries"][0]
        self.assertEqual(entry["disposition"], "unobserved_with_source_gap")
        self.assertEqual(entry["missing_source_kinds"], ["cmdb"])
        self.assertTrue(entry["review_required"])

    def test_retained_asset_with_missing_source_class_still_requires_review(self) -> None:
        shared = (identifier(IdentifierKind.FQDN, "app.example.test"),)
        prior_records = (
            observation(SourceKind.CMDB, "asset-a", shared=shared, digest_index=1),
            observation(SourceKind.ENDPOINT, "device-a", shared=shared, digest_index=2),
        )
        current_records = (
            observation(SourceKind.CMDB, "asset-a", shared=shared, digest_index=3),
        )
        prior, current = self._pair(prior_records, current_records)
        entry = build_asset_lifecycle_review(
            prior, current, prior_records, current_records
        )["entries"][0]
        self.assertEqual(entry["disposition"], "retained")
        self.assertEqual(entry["missing_source_kinds"], ["endpoint"])
        self.assertTrue(entry["review_required"])

    def test_split_lineage_is_not_silently_retired(self) -> None:
        shared = (identifier(IdentifierKind.FQDN, "app.example.test"),)
        prior_records = (
            observation(SourceKind.CMDB, "asset-a", shared=shared, digest_index=1),
            observation(SourceKind.ENDPOINT, "device-a", shared=shared, digest_index=2),
        )
        current_records = (
            observation(SourceKind.CMDB, "asset-a", digest_index=3),
            observation(SourceKind.ENDPOINT, "device-a", digest_index=4),
        )
        prior, current = self._pair(prior_records, current_records)
        report = build_asset_lifecycle_review(prior, current, prior_records, current_records)
        self.assertEqual(len(prior.assets), 1)
        self.assertEqual(len(current.assets), 2)
        self.assertEqual(report["entries"][0]["disposition"], "ambiguous_continuity")
        self.assertEqual(len(report["entries"][0]["successor_asset_ids"]), 2)
        self.assertFalse(report["entries"][0]["tombstone_review_candidate"])

    def test_merge_lineage_is_ambiguous_for_both_prior_assets(self) -> None:
        shared = (identifier(IdentifierKind.FQDN, "app.example.test"),)
        prior_records = (
            observation(SourceKind.CMDB, "asset-a", digest_index=1),
            observation(SourceKind.ENDPOINT, "device-b", digest_index=2),
        )
        current_records = (
            observation(SourceKind.CMDB, "asset-a", shared=shared, digest_index=3),
            observation(SourceKind.ENDPOINT, "device-b", shared=shared, digest_index=4),
        )
        prior, current = self._pair(prior_records, current_records)
        report = build_asset_lifecycle_review(prior, current, prior_records, current_records)
        self.assertEqual(len(prior.assets), 2)
        self.assertEqual(len(current.assets), 1)
        self.assertEqual(
            {item["disposition"] for item in report["entries"]},
            {"ambiguous_continuity"},
        )
        self.assertEqual(report["summary"]["tombstone_candidate_count"], 0)

    def test_explicit_predecessor_preserves_longer_snapshot_lineage(self) -> None:
        ancestor_records = (observation(SourceKind.CMDB, "asset-a", digest_index=1),)
        prior_records = (observation(SourceKind.CMDB, "asset-a", digest_index=2),)
        current_records = (observation(SourceKind.CMDB, "asset-a", digest_index=3),)
        ancestor = reconcile_asset_observations(
            TENANT, "2026-09-21T09:00:00Z", ancestor_records
        )
        prior = reconcile_asset_observations(
            TENANT, FIRST, prior_records, prior_snapshot=ancestor
        )
        current = reconcile_asset_observations(
            TENANT, SECOND, current_records, prior_snapshot=prior
        )
        with self.assertRaises(AssetLifecycleReviewError):
            build_asset_lifecycle_review(prior, current, prior_records, current_records)
        report = build_asset_lifecycle_review(
            prior, current, prior_records, current_records,
            prior_predecessor_snapshot=ancestor,
        )
        self.assertEqual(
            report["prior_predecessor_snapshot_sha256"], ancestor.snapshot_sha256
        )
        self.assertEqual(
            verify_asset_lifecycle_review(
                report, prior, current, prior_records, current_records,
                prior_predecessor_snapshot=ancestor,
            ),
            report,
        )

    def test_replay_rejects_substitution_tampering_and_duplicate_keys(self) -> None:
        prior_records = (observation(SourceKind.CMDB, "asset-a", digest_index=1),)
        current_records = (observation(SourceKind.CMDB, "asset-a", digest_index=2),)
        prior, current = self._pair(prior_records, current_records)
        report = build_asset_lifecycle_review(prior, current, prior_records, current_records)
        with self.assertRaises(AssetLifecycleReviewError):
            build_asset_lifecycle_review(
                prior, current, prior_records, (observation(SourceKind.CMDB, "other"),)
            )
        changed = copy.deepcopy(report)
        changed["entries"][0]["disposition"] = "unobserved_with_class_overlap"
        with self.assertRaises(AssetLifecycleReviewError):
            verify_asset_lifecycle_review(
                changed, prior, current, prior_records, current_records
            )
        changed = copy.deepcopy(report)
        changed["effects"]["asset_retirement"] = True
        with self.assertRaises(AssetLifecycleReviewError):
            verify_asset_lifecycle_review(
                changed, prior, current, prior_records, current_records
            )
        changed = copy.deepcopy(report)
        changed["summary"]["retired_asset_count"] = True
        with self.assertRaises(AssetLifecycleReviewError):
            verify_asset_lifecycle_review(
                changed, prior, current, prior_records, current_records
            )
        changed = copy.deepcopy(report)
        changed["extra"] = object()
        with self.assertRaises(AssetLifecycleReviewError):
            verify_asset_lifecycle_review(
                changed, prior, current, prior_records, current_records
            )
        with self.assertRaises(AssetLifecycleReviewError):
            verify_asset_lifecycle_review(
                '{"schema_version":1,"schema_version":1}',
                prior, current, prior_records, current_records,
            )


if __name__ == "__main__":
    unittest.main()
