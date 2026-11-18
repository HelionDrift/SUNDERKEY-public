"""Offline release-delta checks with no approval or target action effect."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from sunderkey.api_release_delta_review import (
    ApiReleaseDeltaError,
    compare_api_release_inventories,
    verify_api_release_delta_from_sources,
)
from sunderkey.service_contract_extractor import extract_service_contract_endpoints
from sunderkey.traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    build_traffic_api_inventory,
)

CONTEXT_SHA = "sha256:" + "c" * 64
SCOPE_SHA = "sha256:" + "d" * 64
SOURCE_SHA = "sha256:" + "e" * 64
RELEASE_SHA = "sha256:" + "f" * 64
RELEASE_AT = "2026-09-23T12:00:00Z"


def observation(
    event_id: str,
    *,
    observed_at: str,
    path_shape: str = "/v1/users/{user_id}",
    method: str = "GET",
    role_ref: str = "role:reader",
    status_code: int = 200,
    scope_sha256: str = SCOPE_SHA,
) -> SanitizedApiTrafficObservation:
    return SanitizedApiTrafficObservation(
        event_id=event_id,
        tenant_id="tenant:one",
        context_id="context:assessment-1",
        context_sha256=CONTEXT_SHA,
        scope_id="scope:assessment-1",
        scope_sha256=scope_sha256,
        collector_id="collector:approved-metadata",
        source_sha256=SOURCE_SHA,
        observed_at=observed_at,
        origin="https://api.example.test",
        method=method,
        path_shape=path_shape,
        role_ref=role_ref,
        status_code=status_code,
    )


def snapshot(*events, at: str, scope_sha256: str = SCOPE_SHA, contract_bundle=None):
    return build_traffic_api_inventory(
        observations=tuple(events),
        tenant_id="tenant:one",
        context_id="context:assessment-1",
        context_sha256=CONTEXT_SHA,
        scope_id="scope:assessment-1",
        scope_sha256=scope_sha256,
        snapshot_at=at,
        contract_bundle=contract_bundle,
    )


def compare(baseline, current, **changes):
    values = {
        "baseline": baseline,
        "current": current,
        "release_id": "release:web-api-17",
        "release_artifact_sha256": RELEASE_SHA,
        "release_at": RELEASE_AT,
    }
    values.update(changes)
    return compare_api_release_inventories(**values)


class ApiReleaseDeltaReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = snapshot(
            observation("event:before", observed_at="2026-09-23T11:55:00Z"),
            at="2026-09-23T11:59:00Z",
        )

    def test_new_endpoint_requires_review_but_never_approves_release(self) -> None:
        current = snapshot(
            observation("event:after-1", observed_at="2026-09-23T12:05:00Z"),
            observation(
                "event:after-2",
                observed_at="2026-09-23T12:06:00Z",
                path_shape="/v1/admin",
                method="POST",
            ),
            at="2026-09-23T12:10:00Z",
        )
        result = compare(self.baseline, current)
        self.assertEqual(result.gate_status, "review_required")
        self.assertEqual(
            result.new_endpoints,
            ("POST https://api.example.test/v1/admin",),
        )
        self.assertEqual(result.review_reasons, ("new_endpoint_observed",))
        self.assertEqual(result.to_dict()["release_approval_effect"], "none")
        self.assertFalse(result.to_dict()["network_call_performed"])

    def test_role_and_status_expansion_are_separate_review_signals(self) -> None:
        current = snapshot(
            observation(
                "event:after",
                observed_at="2026-09-23T12:05:00Z",
                role_ref="role:writer",
                status_code=403,
            ),
            at="2026-09-23T12:10:00Z",
        )
        result = compare(self.baseline, current)
        self.assertEqual(result.gate_status, "review_required")
        self.assertEqual(result.expanded_roles[0][1], ("role:writer",))
        self.assertEqual(result.new_status_codes[0][1], (403,))
        self.assertEqual(
            result.review_reasons,
            ("new_role_observed", "new_status_observed"),
        )

    def test_no_observed_change_is_inconclusive_not_pass(self) -> None:
        current = snapshot(
            observation("event:after", observed_at="2026-09-23T12:05:00Z"),
            at="2026-09-23T12:10:00Z",
        )
        result = compare(self.baseline, current)
        self.assertEqual(result.gate_status, "inconclusive")
        self.assertEqual(
            result.review_reasons,
            ("no_difference_observed_without_coverage_proof",),
        )
        self.assertNotEqual(result.baseline_inventory_sha256, result.current_inventory_sha256)

    def test_absence_after_release_is_not_reported_as_deletion(self) -> None:
        current = snapshot(at="2026-09-23T12:10:00Z")
        result = compare(self.baseline, current)
        self.assertEqual(result.gate_status, "review_required")
        self.assertEqual(
            result.not_reobserved_endpoints,
            ("GET https://api.example.test/v1/users/{user_id}",),
        )
        self.assertEqual(result.review_reasons, ("prior_endpoint_not_reobserved",))

    def test_contract_bundle_change_requires_review_even_with_same_endpoint(self) -> None:
        document = {
            "openapi": "3.0.0",
            "info": {"title": "Example", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.test"}],
            "paths": {
                "/v1/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}
            },
        }
        content = json.dumps(document).encode("utf-8")
        before_contract = extract_service_contract_endpoints(
            content, source_id="contract:before", media_type="application/json"
        )
        after_contract = extract_service_contract_endpoints(
            content, source_id="contract:after", media_type="application/json"
        )
        baseline = snapshot(
            observation("event:before", observed_at="2026-09-23T11:55:00Z"),
            at="2026-09-23T11:59:00Z",
            contract_bundle=before_contract,
        )
        current = snapshot(
            observation("event:after", observed_at="2026-09-23T12:05:00Z"),
            at="2026-09-23T12:10:00Z",
            contract_bundle=after_contract,
        )
        result = compare(baseline, current)
        self.assertTrue(result.contract_bundle_changed)
        self.assertEqual(result.changed_contract_mappings, ())
        self.assertEqual(result.review_reasons, ("contract_bundle_changed",))

    def test_scope_revision_change_is_rejected(self) -> None:
        changed = snapshot(
            observation(
                "event:after",
                observed_at="2026-09-23T12:05:00Z",
                scope_sha256=SOURCE_SHA,
            ),
            at="2026-09-23T12:10:00Z",
            scope_sha256=SOURCE_SHA,
        )
        with self.assertRaisesRegex(ApiReleaseDeltaError, "lineage differs"):
            compare(self.baseline, changed)

    def test_mixed_time_windows_and_invalid_release_order_are_rejected(self) -> None:
        mixed = snapshot(
            observation("event:after", observed_at="2026-09-23T11:58:00Z"),
            at="2026-09-23T12:10:00Z",
        )
        with self.assertRaisesRegex(ApiReleaseDeltaError, "pre-release event"):
            compare(self.baseline, mixed)
        current = snapshot(
            observation("event:after", observed_at="2026-09-23T12:05:00Z"),
            at="2026-09-23T12:10:00Z",
        )
        with self.assertRaisesRegex(ApiReleaseDeltaError, "outside snapshot order"):
            compare(self.baseline, current, release_at="2026-09-23T11:50:00Z")

    def test_digest_and_gate_tampering_are_rejected(self) -> None:
        current = snapshot(
            observation("event:after", observed_at="2026-09-23T12:05:00Z"),
            at="2026-09-23T12:10:00Z",
        )
        result = compare(self.baseline, current)
        with self.assertRaisesRegex(ApiReleaseDeltaError, "overclaims"):
            replace(result, gate_status="approved")
        with self.assertRaisesRegex(ApiReleaseDeltaError, "does not match content"):
            replace(result, delta_sha256=SOURCE_SHA)
        with self.assertRaisesRegex(ApiReleaseDeltaError, "metadata is invalid"):
            compare(self.baseline, current, release_id="invalid release id")

    def test_release_delta_replays_from_both_source_observation_sets(self) -> None:
        before = observation("event:before", observed_at="2026-09-23T11:55:00Z")
        after = observation("event:after", observed_at="2026-09-23T12:05:00Z")
        current = snapshot(after, at="2026-09-23T12:10:00Z")
        result = compare(self.baseline, current)
        self.assertEqual(
            verify_api_release_delta_from_sources(
                result,
                baseline=self.baseline,
                current=current,
                baseline_observations=(before,),
                current_observations=(after,),
            ),
            result,
        )
        with self.assertRaisesRegex(ApiReleaseDeltaError, "inventory source replay"):
            verify_api_release_delta_from_sources(
                result,
                baseline=self.baseline,
                current=current,
                baseline_observations=(before,),
                current_observations=(),
            )

    def test_release_delta_rejects_wrong_contract_source(self) -> None:
        document = {
            "openapi": "3.0.0",
            "info": {"title": "Example", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.test"}],
            "paths": {"/v1/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
        content = json.dumps(document).encode("utf-8")
        bundle = extract_service_contract_endpoints(
            content, source_id="contract:before", media_type="application/json"
        )
        before = observation("event:before", observed_at="2026-09-23T11:55:00Z")
        after = observation("event:after", observed_at="2026-09-23T12:05:00Z")
        baseline = snapshot(before, at="2026-09-23T11:59:00Z", contract_bundle=bundle)
        current = snapshot(after, at="2026-09-23T12:10:00Z")
        result = compare(baseline, current)
        with self.assertRaisesRegex(ApiReleaseDeltaError, "inventory source replay"):
            verify_api_release_delta_from_sources(
                result,
                baseline=baseline,
                current=current,
                baseline_observations=(before,),
                current_observations=(after,),
            )
        self.assertEqual(
            verify_api_release_delta_from_sources(
                result,
                baseline=baseline,
                current=current,
                baseline_observations=(before,),
                current_observations=(after,),
                baseline_contract_bundle=bundle,
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
