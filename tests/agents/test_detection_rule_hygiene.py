"""Read-only rule hygiene remains metadata, not detection-effectiveness proof."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.detection_rule_hygiene import (
    DetectionRuleHygieneError,
    HygieneStatus,
    RedactedRuleSnapshot,
    RuleSourceObservation,
    review_detection_rule_hygiene,
)

SCOPE = "sha256:" + "a" * 64
EVIDENCE = "sha256:" + "b" * 64
RULE = "rule:sha256:" + "c" * 64
SOURCE_ONE = "source:sha256:" + "d" * 64
SOURCE_TWO = "source:sha256:" + "e" * 64
AT = "2026-09-23T13:00:00Z"


def snapshot(
    *, enabled=True, query="valid_asserted", mapping="current_asserted",
    sources=(SOURCE_ONE,), tenant="tenant:one", scope=SCOPE,
    observed_at="2026-09-23T12:00:00Z",
    expires_at="2026-09-24T12:00:00Z",
):
    return RedactedRuleSnapshot(
        tenant_id=tenant, scope_sha256=scope, rule_ref=RULE,
        enabled=enabled, query_health=query, mapping_state=mapping,
        required_source_refs=sources, source_sha256=EVIDENCE,
        observed_at=observed_at, expires_at=expires_at,
    )


def source(
    ref=SOURCE_ONE, *, state="available_asserted", tenant="tenant:one",
    scope=SCOPE, observed_at="2026-09-23T12:00:00Z",
    expires_at="2026-09-24T12:00:00Z",
):
    return RuleSourceObservation(
        tenant_id=tenant, scope_sha256=scope, rule_ref=RULE,
        source_ref=ref, state=state, evidence_sha256=EVIDENCE,
        observed_at=observed_at, expires_at=expires_at,
    )


def review(items=(), *, selected_snapshot=None, reviewed_at=AT):
    return review_detection_rule_hygiene(
        snapshot=selected_snapshot or snapshot(),
        observations=tuple(items), reviewed_at=reviewed_at,
    )


class DetectionRuleHygieneTests(unittest.TestCase):
    def test_complete_healthy_assertions_do_not_prove_detection(self):
        output = review((source(),))
        self.assertEqual(output.status, HygieneStatus.METADATA_HEALTHY)
        rendered = output.to_dict()
        self.assertFalse(rendered["detection_effectiveness_proven"])
        self.assertTrue(rendered["independent_review_required"])
        self.assertEqual(rendered["effects"]["rule_change"], "none")
        self.assertEqual(rendered["effects"]["connector_read"], "none")
        self.assertNotIn("query_text", rendered)

    def test_disabled_query_error_stale_mapping_and_missing_source_need_attention(self):
        for selected, observations, reason in (
            (snapshot(enabled=False), (source(),), "rule_disabled"),
            (snapshot(query="error_asserted"), (source(),), "query_error_asserted"),
            (snapshot(mapping="stale_asserted"), (source(),), "mapping_stale_asserted"),
            (snapshot(), (source(state="missing_asserted"),), "source_missing_asserted"),
        ):
            with self.subTest(reason=reason):
                result = review(observations, selected_snapshot=selected)
                self.assertEqual(result.status, HygieneStatus.ATTENTION_REQUIRED)
                self.assertIn(reason, result.reasons)

    def test_missing_unknown_and_stale_sources_remain_conservative(self):
        self.assertEqual(review().status, HygieneStatus.INCONCLUSIVE)
        self.assertEqual(
            review((source(state="unknown"),)).status, HygieneStatus.INCONCLUSIVE,
        )
        stale = source(expires_at="2026-09-23T12:30:00Z")
        self.assertEqual(review((stale,)).status, HygieneStatus.STALE_EVIDENCE)
        old_snapshot = snapshot(expires_at="2026-09-23T12:30:00Z")
        self.assertEqual(
            review((source(),), selected_snapshot=old_snapshot).status,
            HygieneStatus.STALE_EVIDENCE,
        )
        self.assertEqual(
            review((source(),), selected_snapshot=snapshot(
                enabled=False, expires_at="2026-09-23T12:30:00Z",
            )).status,
            HygieneStatus.STALE_EVIDENCE,
        )

    def test_required_sources_are_exact_and_order_independent(self):
        selected = snapshot(sources=(SOURCE_ONE, SOURCE_TWO))
        first = source(SOURCE_ONE)
        second = source(SOURCE_TWO)
        self.assertEqual(
            review((first, second), selected_snapshot=selected).to_dict(),
            review((second, first), selected_snapshot=selected).to_dict(),
        )
        self.assertEqual(
            review((first,), selected_snapshot=selected).status,
            HygieneStatus.INCONCLUSIVE,
        )

    def test_conflicting_and_cross_bound_source_evidence_fails_closed(self):
        with self.assertRaisesRegex(DetectionRuleHygieneError, "conflicting evidence"):
            review((source(), source(state="missing_asserted")))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "crosses snapshot binding"):
            review((source(SOURCE_TWO),))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "crosses snapshot binding"):
            review((source(tenant="tenant:two"),))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "crosses snapshot binding"):
            review((source(scope="sha256:" + "f" * 64),))

    def test_future_retention_and_raw_query_input_fail_closed(self):
        with self.assertRaisesRegex(DetectionRuleHygieneError, "opaque reference"):
            snapshot(sources=("https://siem.example/query",))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "bounded and canonical"):
            snapshot(sources=(SOURCE_ONE, SOURCE_ONE))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "hard limit"):
            snapshot(expires_at="2026-10-01T12:00:00Z")
        with self.assertRaisesRegex(DetectionRuleHygieneError, "hard limit"):
            source(expires_at="2026-10-01T12:00:00Z")
        with self.assertRaisesRegex(DetectionRuleHygieneError, "future-dated"):
            review((source(observed_at="2026-09-23T14:00:00Z",
                           expires_at="2026-09-24T14:00:00Z"),))

    def test_hash_tampering_and_detached_effects(self):
        with self.assertRaisesRegex(DetectionRuleHygieneError, "snapshot_sha256"):
            replace(snapshot(), enabled=False)
        with self.assertRaisesRegex(DetectionRuleHygieneError, "observation_sha256"):
            replace(source(), state="unknown")
        output = review((source(),))
        with self.assertRaisesRegex(DetectionRuleHygieneError, "review_sha256"):
            replace(output, reviewed_at="2026-09-23T13:01:00Z")
        with self.assertRaisesRegex(DetectionRuleHygieneError, "conflicts with reasons"):
            replace(output, status="inconclusive", review_sha256="")
        detached = output.to_dict()
        detached["effects"]["rule_change"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["rule_change"], "none")


if __name__ == "__main__":
    unittest.main()
