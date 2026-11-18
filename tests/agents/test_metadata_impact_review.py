"""Metadata-only impact triage with explicit uncertainty and no content."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.metadata_impact_review import (
    DataMetadataObservation,
    MetadataImpactError,
    ReviewStatus,
    review_data_metadata,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
PATH = "sha256:" + "c" * 64
DATASET = "dataset:sha256:" + "d" * 64
OTHER_DATASET = "dataset:sha256:" + "e" * 64
AT = "2026-09-23T13:00:00Z"


def observation(
    record="source:one", *, category="personal_identifier",
    reachability="verified_path_asserted", dataset=DATASET,
    expires_at="2026-09-24T12:00:00Z", tenant="tenant:one",
    scope=SCOPE, observed_at="2026-09-23T12:00:00Z",
):
    return DataMetadataObservation(
        tenant_id=tenant, scope_sha256=scope, dataset_ref=dataset,
        source_record_id=record, source_sha256=SOURCE,
        observed_at=observed_at, expires_at=expires_at,
        category=category, reachability=reachability,
        path_evidence_sha256=(None if reachability == "not_assessed" else PATH),
        record_count_bucket="101_10000", business_criticality="high",
    )


def review(items, **changes):
    values = {
        "observations": tuple(items), "tenant_id": "tenant:one",
        "scope_sha256": SCOPE, "reviewed_at": AT,
    }
    values.update(changes)
    return review_data_metadata(**values)


class MetadataImpactReviewTests(unittest.TestCase):
    def test_sensitive_category_and_path_are_review_signal_not_breach_proof(self):
        output = review((observation(),))
        self.assertEqual(output.signals[0].review_status, ReviewStatus.REVIEW_REQUIRED)
        self.assertIn(
            "sensitive_category_and_path_asserted", output.signals[0].review_reasons,
        )
        self.assertEqual(output.to_dict()["effects"]["content_access"], "none")
        self.assertEqual(output.to_dict()["effects"]["exfiltration_verdict"], "none")
        self.assertNotIn("data_value", str(output.to_dict()))

    def test_hypothesis_public_and_unknown_remain_conservative(self):
        hypothesis = review((observation(reachability="hypothesis"),))
        self.assertEqual(hypothesis.signals[0].review_status, ReviewStatus.TRIAGE_REQUIRED)
        public = review((observation(category="public", reachability="not_assessed"),))
        self.assertEqual(public.signals[0].review_status, ReviewStatus.INCONCLUSIVE)
        self.assertEqual(review(()).signals, ())

    def test_conflicting_public_and_sensitive_declarations_require_triage(self):
        output = review((
            observation("source:sensitive"),
            observation("source:public", category="public"),
        ))
        self.assertEqual(output.signals[0].review_status, ReviewStatus.TRIAGE_REQUIRED)
        self.assertIn(
            "public_sensitive_declaration_conflict", output.signals[0].review_reasons,
        )

    def test_stale_metadata_is_not_a_current_impact_claim(self):
        output = review((observation(expires_at="2026-09-23T12:30:00Z"),))
        self.assertEqual(output.signals[0].review_status, ReviewStatus.STALE_METADATA)
        self.assertIn("all_metadata_expired", output.signals[0].review_reasons)

    def test_input_order_is_deterministic_and_scope_exact(self):
        left = observation("source:left", dataset=DATASET)
        right = observation("source:right", dataset=OTHER_DATASET)
        self.assertEqual(review((left, right)).to_dict(), review((right, left)).to_dict())
        with self.assertRaisesRegex(MetadataImpactError, "tenant or scope differs"):
            review((observation(scope="sha256:" + "f" * 64),))
        with self.assertRaisesRegex(MetadataImpactError, "tenant or scope differs"):
            review((observation(tenant="tenant:two"),))

    def test_future_old_conflicting_and_tampered_records_fail_closed(self):
        with self.assertRaisesRegex(MetadataImpactError, "future-dated"):
            review((observation(observed_at="2026-09-23T13:30:00Z",
                                expires_at="2026-09-24T13:30:00Z"),))
        with self.assertRaisesRegex(MetadataImpactError, "too old"):
            review((observation(observed_at="2026-08-01T12:00:00Z",
                                expires_at="2026-08-02T12:00:00Z"),))
        with self.assertRaisesRegex(MetadataImpactError, "conflicting metadata"):
            review((observation(), observation(category="financial")))
        with self.assertRaisesRegex(MetadataImpactError, "observation_sha256"):
            replace(observation(), category="financial")
        with self.assertRaisesRegex(MetadataImpactError, "review_sha256"):
            replace(review((observation(),)), reviewed_at="2026-09-23T13:01:00Z")
        valid = review((observation(),))
        with self.assertRaisesRegex(MetadataImpactError, "signals are not canonical"):
            replace(valid, signals=(valid.signals[0], valid.signals[0]), review_sha256="")

    def test_content_and_long_retention_cannot_enter_metadata_contract(self):
        with self.assertRaisesRegex(MetadataImpactError, "opaque digest"):
            observation(dataset="dataset:customers")
        with self.assertRaisesRegex(MetadataImpactError, "retention limit"):
            observation(expires_at="2026-11-01T12:00:00Z")
        with self.assertRaisesRegex(MetadataImpactError, "cannot carry path evidence"):
            replace(observation(), reachability="not_assessed", observation_sha256="")


if __name__ == "__main__":
    unittest.main()
