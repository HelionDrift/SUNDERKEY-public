"""Restricted asset metadata never becomes successful exploitation proof."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.restricted_asset_inference import (
    InferenceStatus,
    RestrictedAssetCase,
    RestrictedAssetInferenceError,
    RestrictedAssetObservation,
    infer_restricted_asset,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
ASSET = "asset:sha256:" + "c" * 64
OTHER_ASSET = "asset:sha256:" + "d" * 64
AT = "2026-09-23T13:00:00Z"


def case(*, asset=ASSET, tenant="tenant:one", scope=SCOPE,
         expires_at="2026-09-24T12:00:00Z"):
    return RestrictedAssetCase(
        tenant_id=tenant, scope_sha256=scope, asset_ref=asset,
        technique_id="T1234", restriction_reason="unsafe_to_exploit",
        prerequisites=("asset_reachability", "identity_precondition"),
        mapping_source_sha256=SOURCE, restriction_source_sha256=SOURCE,
        recorded_at="2026-09-23T12:00:00Z", expires_at=expires_at,
    )


def observation(
    facet="asset_reachability", *, state="supported_asserted", asset=ASSET,
    tenant="tenant:one", scope=SCOPE,
    observed_at="2026-09-23T12:00:00Z",
    expires_at="2026-09-24T12:00:00Z",
):
    return RestrictedAssetObservation(
        tenant_id=tenant, scope_sha256=scope, asset_ref=asset,
        technique_id="T1234", facet=facet, state=state,
        source_sha256=SOURCE, observed_at=observed_at, expires_at=expires_at,
    )


def complete():
    return (
        observation("asset_reachability"),
        observation("identity_precondition"),
        observation("control_observation"),
    )


def review(items=(), *, selected_case=None, reviewed_at=AT):
    return infer_restricted_asset(
        case=selected_case or case(), observations=tuple(items),
        reviewed_at=reviewed_at,
    )


class RestrictedAssetInferenceTests(unittest.TestCase):
    def test_complete_assertions_stay_low_confidence_inference(self):
        output = review(complete())
        self.assertEqual(output.status, InferenceStatus.BOUNDED_INFERENCE)
        rendered = output.to_dict()
        self.assertEqual(rendered["evidence_class"], "restricted_asset_inference")
        self.assertEqual(rendered["confidence"], "low")
        self.assertFalse(rendered["successful_exploitation"])
        self.assertTrue(rendered["independent_review_required"])
        self.assertEqual(rendered["effects"]["target_interaction"], "none")

    def test_missing_unknown_and_no_control_remain_insufficient(self):
        self.assertEqual(review().status, InferenceStatus.INSUFFICIENT)
        self.assertEqual(
            review(complete()[:2]).status, InferenceStatus.INSUFFICIENT,
        )
        unknown = (
            observation("asset_reachability", state="unknown"),
            *complete()[1:],
        )
        self.assertEqual(review(unknown).status, InferenceStatus.INSUFFICIENT)

    def test_current_counterevidence_prevents_positive_inference(self):
        items = (
            observation("asset_reachability", state="contradicted_asserted"),
            *complete()[1:],
        )
        result = review(items)
        self.assertEqual(result.status, InferenceStatus.COUNTEREVIDENCE)
        self.assertIn("prerequisite_counterevidence", result.reasons)
        control = (
            *complete()[:2],
            observation("control_observation", state="contradicted_asserted"),
        )
        self.assertEqual(review(control).status, InferenceStatus.COUNTEREVIDENCE)

    def test_stale_case_or_observation_is_not_current_inference(self):
        result = review(complete(), selected_case=case(
            expires_at="2026-09-23T12:30:00Z",
        ))
        self.assertEqual(result.status, InferenceStatus.STALE)
        stale = (
            observation("asset_reachability", expires_at="2026-09-23T12:30:00Z"),
            *complete()[1:],
        )
        self.assertEqual(review(stale).status, InferenceStatus.STALE)

    def test_order_and_duplicate_input_are_deterministic(self):
        items = complete()
        self.assertEqual(
            review((items[0], *items, items[2])).to_dict(),
            review(tuple(reversed(items))).to_dict(),
        )
        self.assertEqual(len(review(items).observation_sha256), 3)

    def test_conflicting_or_cross_bound_evidence_fails_closed(self):
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "conflicting evidence"):
            review((observation(), observation(state="contradicted_asserted")))
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "crosses case binding"):
            review((observation(asset=OTHER_ASSET),))
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "crosses case binding"):
            review((observation(tenant="tenant:other"),))
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "crosses case binding"):
            review((observation(scope="sha256:" + "e" * 64),))

    def test_future_long_lived_or_nonopaque_records_fail_closed(self):
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "opaque"):
            case(asset="asset:database")
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "hard limit"):
            case(expires_at="2026-11-01T12:00:00Z")
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "hard limit"):
            observation(expires_at="2026-10-01T12:00:00Z")
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "future-dated"):
            review((observation(observed_at="2026-09-23T14:00:00Z",
                                expires_at="2026-09-24T14:00:00Z"),))
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "future-dated"):
            review((), selected_case=replace(
                case(), recorded_at="2026-09-23T14:00:00Z",
                expires_at="2026-09-24T14:00:00Z", case_sha256="",
            ))

    def test_tampering_and_detached_effects(self):
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "case_sha256"):
            replace(case(), restriction_reason="operational_constraint")
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "observation_sha256"):
            replace(observation(), state="unknown")
        output = review(complete())
        with self.assertRaisesRegex(RestrictedAssetInferenceError, "inference_sha256"):
            replace(output, reviewed_at="2026-09-23T13:01:00Z")
        detached = output.to_dict()
        detached["effects"]["execution"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["execution"], "none")


if __name__ == "__main__":
    unittest.main()
