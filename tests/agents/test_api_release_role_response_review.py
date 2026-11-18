"""Offline matrix-bound release review with no collection or adapter calls."""

from __future__ import annotations

import copy
import json
import unittest
from collections import UserDict
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey.api_release_role_response_review as review_module
from sunderkey.api_release_delta_review import compare_api_release_inventories
from sunderkey.api_release_role_response_review import (
    ApiReleaseRoleResponseReview,
    ApiReleaseRoleResponseReviewError,
    compare_api_release_role_responses,
    verify_api_release_role_response_review,
)
from sunderkey.event_assessment_planning import (
    CandidateDisposition,
    EventAssessmentError,
    EventKind,
    event_from_evidence,
    plan_event_assessments,
)
from sunderkey.service_contract_extractor import extract_service_contract_endpoints
from sunderkey.traffic_derived_api_inventory import (
    MAX_OBSERVATIONS,
    SanitizedApiTrafficObservation,
    _canonical_sha,
    build_traffic_api_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
CONTEXT_SHA = "sha256:" + "c" * 64
SCOPE_SHA = "sha256:" + "d" * 64
SOURCE_SHA = "sha256:" + "e" * 64
RELEASE_SHA = "sha256:" + "f" * 64
RELEASE_AT = "2026-09-23T12:00:00Z"
SNAPSHOTS = {"before": "2026-09-23T11:59:00Z", "after": "2026-09-23T12:10:00Z"}
OBSERVED = {"before": "2026-09-23T11:55:00Z", "after": "2026-09-23T12:05:00Z"}


def observation(event_id, role="role:reader", status=200, *, side="before", **changes):
    values = {
        "event_id": event_id,
        "tenant_id": "tenant:one",
        "context_id": "context:one",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:one",
        "scope_sha256": SCOPE_SHA,
        "collector_id": "collector:metadata",
        "source_sha256": SOURCE_SHA,
        "observed_at": OBSERVED[side],
        "origin": "https://api.example.test",
        "method": "GET",
        "path_shape": "/records/{id}",
        "role_ref": role,
        "status_code": status,
    }
    values.update(changes)
    return SanitizedApiTrafficObservation(**values)


def inventory(events, *, side, **changes):
    values = {
        "observations": tuple(events),
        "tenant_id": "tenant:one",
        "context_id": "context:one",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:one",
        "scope_sha256": SCOPE_SHA,
        "snapshot_at": SNAPSHOTS[side],
    }
    values.update(changes)
    return build_traffic_api_inventory(**values)


def sources(before, after):
    return {
        "baseline": inventory(before, side="before"),
        "current": inventory(after, side="after"),
        "baseline_observations": tuple(before),
        "current_observations": tuple(after),
        "release_id": "release:one",
        "release_artifact_sha256": RELEASE_SHA,
        "release_at": RELEASE_AT,
    }


def legacy(options):
    return compare_api_release_inventories(
        **{
            name: options[name]
            for name in (
                "baseline",
                "current",
                "release_id",
                "release_artifact_sha256",
                "release_at",
            )
        }
    )


def rehash(document):
    body = {key: value for key, value in document.items() if key != "review_sha256"}
    document["review_sha256"] = _canonical_sha(review_module.DOMAIN, body)
    return document


class ApiReleaseRoleResponseReviewTests(unittest.TestCase):
    def setUp(self):
        self.before = (
            observation("event:before-reader", "role:reader", 200),
            observation("event:before-writer", "role:writer", 403),
        )
        self.after = (
            observation("event:after-reader", "role:reader", 403, side="after"),
            observation("event:after-writer", "role:writer", 200, side="after"),
        )
        self.options = sources(self.before, self.after)

    def test_hidden_role_status_swap_requires_review_and_keeps_legacy_bytes(self):
        prior = legacy(self.options)
        prior_json = json.dumps(prior.to_dict(), sort_keys=True, separators=(",", ":"))
        result = compare_api_release_role_responses(**self.options)
        self.assertEqual(prior.gate_status, "inconclusive")
        self.assertEqual(result.inventory_delta_sha256, prior.delta_sha256)
        self.assertEqual(result.inventory_delta_review_reasons, prior.review_reasons)
        self.assertEqual(result.gate_status, "review_required")
        self.assertEqual(len(result.new_associations), 2)
        self.assertEqual(len(result.not_reobserved_associations), 2)
        self.assertEqual(result.reobserved_count, 0)
        self.assertNotIn(review_module.NO_DIFFERENCE_REASON, result.review_reasons)
        self.assertEqual(
            json.dumps(legacy(self.options).to_dict(), sort_keys=True, separators=(",", ":")),
            prior_json,
        )

    def test_missing_only_association_is_inconclusive_not_denial_or_removal(self):
        before = (*self.before, observation("event:before-reader-denial", "role:reader", 403))
        after = (
            observation("event:after-reader", "role:reader", 200, side="after"),
            observation("event:after-writer", "role:writer", 403, side="after"),
        )
        result = compare_api_release_role_responses(**sources(before, after))
        self.assertEqual(result.inventory_delta_gate_status, "inconclusive")
        self.assertEqual(result.gate_status, "inconclusive")
        self.assertEqual(result.new_associations, ())
        self.assertEqual(len(result.not_reobserved_associations), 1)
        self.assertEqual(result.reobserved_count, 2)
        self.assertEqual(result.review_reasons, (review_module.MISSING_ASSOCIATION_REASON,))
        self.assertEqual(result.to_dict()["effects"]["authorization_verdict"], "none")

    def test_missing_endpoint_preserves_substantive_legacy_review(self):
        result = compare_api_release_role_responses(**sources(self.before, ()))
        self.assertEqual(result.inventory_delta_gate_status, "review_required")
        self.assertEqual(result.gate_status, "review_required")
        self.assertIn("prior_endpoint_not_reobserved", result.review_reasons)
        self.assertIn(review_module.MISSING_ASSOCIATION_REASON, result.review_reasons)

    def test_unchanged_associations_never_pass_the_release(self):
        after = (
            observation("event:after-reader", "role:reader", 200, side="after"),
            observation("event:after-writer", "role:writer", 403, side="after"),
        )
        result = compare_api_release_role_responses(**sources(self.before, after))
        self.assertEqual(result.gate_status, "inconclusive")
        self.assertEqual(result.review_reasons, (review_module.NO_DIFFERENCE_REASON,))
        self.assertEqual(result.reobserved_count, 2)
        self.assertEqual(result.new_associations, ())
        self.assertEqual(result.not_reobserved_associations, ())

    def test_repeated_responses_and_multiple_statuses_count_associations_not_events(self):
        before = (
            observation("event:b1", "anonymous", 200),
            observation("event:b2", "anonymous", 200),
            observation("event:b3", "anonymous", 403),
        )
        after = (
            observation("event:a1", "anonymous", 200, side="after"),
            observation("event:a2", "anonymous", 403, side="after"),
            observation("event:a3", "anonymous", 403, side="after"),
        )
        result = compare_api_release_role_responses(**sources(before, after))
        self.assertEqual(result.reobserved_count, 2)
        self.assertEqual(result.gate_status, "inconclusive")

    def test_contract_only_change_preserves_legacy_reason(self):
        content = json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Synthetic", "version": "1.0.0"},
                "servers": [{"url": "https://api.example.test"}],
                "paths": {"/records/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
            }
        ).encode("ascii")
        before = (self.before[0],)
        after = (observation("event:after", side="after"),)
        options = sources(before, after)
        for side, field, events in (("before", "baseline", before), ("after", "current", after)):
            bundle = extract_service_contract_endpoints(
                content, source_id=f"contract:{side}", media_type="application/json"
            )
            options[field] = inventory(events, side=side, contract_bundle=bundle)
        result = compare_api_release_role_responses(**options)
        self.assertEqual(result.new_associations, ())
        self.assertEqual(result.not_reobserved_associations, ())
        self.assertEqual(result.gate_status, "review_required")
        self.assertIn("contract_bundle_changed", result.review_reasons)

    def test_permutations_and_identical_duplicates_replay_identically(self):
        result = compare_api_release_role_responses(**self.options)
        reordered = {
            **self.options,
            "baseline_observations": (*reversed(self.before), self.before[0]),
            "current_observations": (*reversed(self.after), self.after[0]),
        }
        self.assertEqual(compare_api_release_role_responses(**reordered), result)
        self.assertEqual(
            verify_api_release_role_response_review(review=result.to_dict(), **reordered), result
        )

    def test_incomplete_extra_conflicting_and_untyped_sources_are_rejected(self):
        invalid = (
            (),
            self.before[:1],
            (*self.before, observation("event:extra")),
            (*self.before, replace(self.before[0], status_code=201)),
            list(self.before),
        )
        for observations in invalid:
            with self.subTest(observations=type(observations).__name__, count=len(observations)):
                with self.assertRaises(ApiReleaseRoleResponseReviewError):
                    compare_api_release_role_responses(
                        **{**self.options, "baseline_observations": observations}
                    )

    def test_context_scope_and_temporal_windows_fail_closed(self):
        changed = tuple(replace(item, scope_sha256=SOURCE_SHA) for item in self.after)
        options = {
            **self.options,
            "current": inventory(changed, side="after", scope_sha256=SOURCE_SHA),
            "current_observations": changed,
        }
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(**options)
        pre_release = tuple(replace(item, observed_at=OBSERVED["before"]) for item in self.after)
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(**sources(self.before, pre_release))
        future = tuple(replace(item, observed_at="2026-09-23T12:11:00Z") for item in self.after)
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(**{**self.options, "current_observations": future})
        for boundary in ("2026-09-23T11:59:00Z", "2026-09-23T12:11:00Z"):
            with self.subTest(boundary=boundary):
                with self.assertRaises(ApiReleaseRoleResponseReviewError):
                    compare_api_release_role_responses(**{**self.options, "release_at": boundary})

    def test_stale_observation_digest_cannot_bind_a_reconstructed_matrix(self):
        # Source integrity is implemented by the two existing source builders.
        # A changed collector leaves endpoint marginals unchanged, so only the
        # reconstructed observation digest can detect this substitution.
        object.__setattr__(self.before[0], "collector_id", "collector:changed")
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(**self.options)

    def test_exact_full_capacity_round_trips_without_trace_limits(self):
        before = tuple(
            observation(f"event:b{i:05d}", f"role:r{i:05d}", 200) for i in range(MAX_OBSERVATIONS)
        )
        after = tuple(
            observation(f"event:a{i:05d}", f"role:r{i:05d}", 403, side="after")
            for i in range(MAX_OBSERVATIONS)
        )
        options = sources(before, after)
        result = compare_api_release_role_responses(**options)
        self.assertEqual(len(result.new_associations), MAX_OBSERVATIONS)
        self.assertEqual(len(result.not_reobserved_associations), MAX_OBSERVATIONS)
        self.assertEqual(result.reobserved_count, 0)
        document = result.to_dict()
        self.assertGreater(len(json.dumps(document).encode("ascii")), 1_000_000)
        self.assertEqual(ApiReleaseRoleResponseReview.from_dict(document), result)
        self.assertEqual(
            verify_api_release_role_response_review(review=document, **options), result
        )

    def test_overlimit_sources_and_wire_associations_are_rejected(self):
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(
                **{
                    **self.options,
                    "baseline_observations": (self.before[0],) * (MAX_OBSERVATIONS + 1),
                }
            )
        document = compare_api_release_role_responses(**self.options).to_dict()
        document["new_associations"] = [document["new_associations"][0]] * (MAX_OBSERVATIONS + 1)
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            ApiReleaseRoleResponseReview.from_dict(document)

    def test_closed_wire_shape_rejects_python_coercions(self):
        original = compare_api_release_role_responses(**self.options).to_dict()

        class Text(str):
            pass

        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("reobserved_count", False),
            ("reobserved_count", 0.0),
            ("reobserved_count", Decimal(0)),
            ("release_id", Text("release:one")),
            ("new_associations", tuple(original["new_associations"])),
            ("review_reasons", tuple(original["review_reasons"])),
            ("effects", UserDict(original["effects"])),
        ):
            with self.subTest(field=field, value_type=type(value).__name__):
                document = copy.deepcopy(original)
                document[field] = value
                with self.assertRaises(ApiReleaseRoleResponseReviewError):
                    ApiReleaseRoleResponseReview.from_dict(document)
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            ApiReleaseRoleResponseReview.from_dict(UserDict(original))
        for value in (True, 403.0, Decimal(403), 99, 600):
            with self.subTest(status=value):
                document = copy.deepcopy(original)
                document["new_associations"][0]["status_code"] = value
                with self.assertRaises(ApiReleaseRoleResponseReviewError):
                    ApiReleaseRoleResponseReview.from_dict(document)
        for mutate in (
            lambda value: value.update(extra="unknown"),
            lambda value: value["new_associations"][0].update(extra="unknown"),
            lambda value: value["effects"].update(authority="grant"),
            lambda value: value.update(review_sha256=""),
        ):
            document = copy.deepcopy(original)
            mutate(document)
            with self.assertRaises(ApiReleaseRoleResponseReviewError):
                ApiReleaseRoleResponseReview.from_dict(document)

    def test_rehashed_semantic_forgery_cannot_change_accounting_or_gate(self):
        original = compare_api_release_role_responses(**self.options).to_dict()
        for mutate in (
            lambda value: value.update(gate_status="inconclusive"),
            lambda value: value.update(reobserved_count=-1),
            lambda value: value.update(reobserved_count=MAX_OBSERVATIONS),
            lambda value: value.update(new_associations=list(reversed(value["new_associations"]))),
            lambda value: value["new_associations"].append(value["new_associations"][0]),
            lambda value: value.update(
                not_reobserved_associations=copy.deepcopy(value["new_associations"])
            ),
            lambda value: value.update(review_reasons=[review_module.NO_DIFFERENCE_REASON]),
            lambda value: value.update(baseline_snapshot_at=RELEASE_AT),
        ):
            document = copy.deepcopy(original)
            mutate(document)
            with self.assertRaises(ApiReleaseRoleResponseReviewError):
                ApiReleaseRoleResponseReview.from_dict(rehash(document))

    def test_intact_substituted_bindings_and_associations_require_source_replay(self):
        result = compare_api_release_role_responses(**self.options)
        for field in review_module._DIGEST_FIELDS:
            with self.subTest(field=field):
                document = result.to_dict()
                document[field] = "sha256:" + "1" * 64
                rehash(document)
                ApiReleaseRoleResponseReview.from_dict(document)
                with self.assertRaisesRegex(ApiReleaseRoleResponseReviewError, "source replay"):
                    verify_api_release_role_response_review(review=document, **self.options)
        for mutate in (
            lambda value: value.update(reobserved_count=1),
            lambda value: value["new_associations"][0].update(status_code=404),
        ):
            document = result.to_dict()
            mutate(document)
            ApiReleaseRoleResponseReview.from_dict(rehash(document))
            with self.assertRaisesRegex(ApiReleaseRoleResponseReviewError, "source replay"):
                verify_api_release_role_response_review(review=document, **self.options)

    def test_output_and_parser_own_detached_effects_and_associations(self):
        result = compare_api_release_role_responses(**self.options)
        document = result.to_dict()
        parsed = ApiReleaseRoleResponseReview.from_dict(document)
        document["effects"]["authority"] = "grant"
        document["new_associations"][0]["status_code"] = 404
        self.assertEqual(parsed.to_dict(), result.to_dict())
        self.assertTrue(all(value == "none" for value in result.to_dict()["effects"].values()))
        with self.assertRaises(FrozenInstanceError):
            result.new_associations[0].status_code = 404
        with self.assertRaises(TypeError):
            review_module.NO_EFFECTS["authority"] = "grant"

    def test_schema_accepts_closed_output_and_rejects_unknown_fields(self):
        schema = json.loads(
            (
                ROOT / "registry" / "schemas" / "api-release-role-response-review-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        document = compare_api_release_role_responses(**self.options).to_dict()
        validator.validate(document)
        self.assertFalse(validator.is_valid({**document, "unknown": "extra"}))

    def test_new_event_binds_review_hash_and_requires_current_snapshot_time(self):
        result = compare_api_release_role_responses(**self.options)
        event = event_from_evidence(result, observed_at=SNAPSHOTS["after"])
        self.assertEqual(event.kind, EventKind.API_RELEASE_DELTA)
        self.assertEqual(event.evidence_sha256, result.review_sha256)
        self.assertEqual(event.reason_codes, result.review_reasons)
        self.assertTrue(event.change_signal)
        for at in (None, "2026-09-23T12:09:59Z"):
            with self.subTest(observed_at=at):
                with self.assertRaises(EventAssessmentError):
                    event_from_evidence(result, observed_at=at)

    def test_missing_only_event_does_not_schedule_a_review_candidate(self):
        before = (*self.before, observation("event:before-extra", "role:reader", 403))
        after = (
            observation("event:after-reader", "role:reader", 200, side="after"),
            observation("event:after-writer", "role:writer", 403, side="after"),
        )
        result = compare_api_release_role_responses(**sources(before, after))
        event = event_from_evidence(result, observed_at=SNAPSHOTS["after"])
        batch = plan_event_assessments(
            events=(event,), scope_sha256=SCOPE_SHA, as_of="2026-09-23T12:11:00Z"
        )
        self.assertFalse(event.change_signal)
        self.assertEqual(batch.candidates[0].disposition, CandidateDisposition.NO_CHANGE_SIGNAL)

    def test_legacy_event_binding_and_post_release_time_rule_are_unchanged(self):
        delta = legacy(self.options)
        event = event_from_evidence(delta, observed_at="2026-09-23T12:05:00Z")
        self.assertEqual(event.kind, EventKind.API_RELEASE_DELTA)
        self.assertEqual(event.evidence_sha256, delta.delta_sha256)
        self.assertEqual(event.reason_codes, delta.review_reasons)
        self.assertFalse(event.change_signal)


if __name__ == "__main__":
    unittest.main()
