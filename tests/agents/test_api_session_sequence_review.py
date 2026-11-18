"""Offline review tests for caller-declared API session sequences."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.api_session_sequence_review import (
    ApiSessionSequenceReviewError,
    build_api_session_sequence_review,
    verify_api_session_sequence_review_from_sources,
)
from sunderkey.traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    build_traffic_api_inventory,
)

SHA = "sha256:" + "a" * 64
CONTEXT_SHA = "sha256:" + "b" * 64
SCOPE_SHA = "sha256:" + "c" * 64
REDACTION_SHA = "sha256:" + "d" * 64
SESSION = "sessionref:uuidv4:123e4567-e89b-42d3-a456-426614174000"
OTHER_SESSION = "sessionref:uuidv4:123e4567-e89b-42d3-a456-426614174001"


def event(event_id: str, **changes: object) -> SanitizedApiTrafficObservation:
    fields = {
        "event_id": event_id,
        "tenant_id": "tenant:one",
        "context_id": "context:one",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:one",
        "scope_sha256": SCOPE_SHA,
        "collector_id": "collector:one",
        "source_sha256": SHA,
        "observed_at": "2026-09-23T11:59:00Z",
        "origin": "https://one.example.test",
        "method": "GET",
        "path_shape": "/v1/items/{id}",
        "role_ref": "role:reader",
        "status_code": 200,
    }
    fields.update(changes)
    return SanitizedApiTrafficObservation(**fields)


def inventory(*events: SanitizedApiTrafficObservation):
    return build_traffic_api_inventory(
        observations=tuple(events),
        tenant_id="tenant:one",
        context_id="context:one",
        context_sha256=CONTEXT_SHA,
        scope_id="scope:one",
        scope_sha256=SCOPE_SHA,
        snapshot_at="2026-09-23T12:00:00Z",
    )


def claim(
    item: SanitizedApiTrafficObservation,
    position: int,
    session_ref: str = SESSION,
) -> dict[str, object]:
    return {
        "event_id": item.event_id,
        "observation_sha256": item.observation_sha256,
        "session_ref": session_ref,
        "position": position,
    }


class ApiSessionSequenceReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.first = event("event:one")
        self.second = event(
            "event:two", observed_at="2026-09-23T11:59:01Z",
            origin="https://two.example.test", role_ref="role:writer",
        )
        self.third = event("event:three", observed_at="2026-09-23T11:59:01Z")
        self.observations = (self.first, self.second, self.third)
        self.inventory = inventory(*self.observations)
        self.claims = (claim(self.first, 0), claim(self.second, 1))

    def review(self, *, claims=None, observations=None, current_inventory=None):
        return build_api_session_sequence_review(
            inventory=self.inventory if current_inventory is None else current_inventory,
            observations=self.observations if observations is None else observations,
            claims=self.claims if claims is None else claims,
            redaction_review_sha256=REDACTION_SHA,
        )

    def test_sequence_is_bounded_nonqualifying_and_source_replayable(self) -> None:
        report = self.review()
        self.assertEqual(report["observation_count"], 3)
        self.assertEqual(report["bound_event_count"], 2)
        self.assertEqual(report["unbound_event_count"], 1)
        self.assertEqual(report["session_count"], 1)
        self.assertEqual(report["edge_count"], 1)
        self.assertEqual(report["role_label_change_edge_count"], 1)
        self.assertEqual(report["cross_origin_edge_count"], 1)
        self.assertEqual(report["same_second_order_uncertain_edge_count"], 0)
        self.assertFalse(report["session_linkage_authenticated"])
        self.assertFalse(report["redaction_assurance_verified"])
        self.assertFalse(report["network_call_performed"])
        self.assertEqual(report["release_gate_effect"], "none")
        self.assertEqual(report["qualification_effect"], "none")
        self.assertEqual(report["sessions"][0]["edges"][0]["to_observation_sha256"],
                         self.second.observation_sha256)
        self.assertEqual(
            verify_api_session_sequence_review_from_sources(
                report, inventory=self.inventory,
                observations=self.observations, claims=self.claims,
            ),
            report,
        )

    def test_claim_input_order_does_not_change_report(self) -> None:
        self.assertEqual(
            self.review(),
            self.review(claims=tuple(reversed(self.claims))),
        )

    def test_equal_timestamp_order_is_not_claimed_temporally_certain(self) -> None:
        result = self.review(claims=(claim(self.second, 0), claim(self.third, 1)))
        self.assertEqual(result["same_second_order_uncertain_edge_count"], 1)
        self.assertTrue(result["sessions"][0]["edges"][0]["same_second_order_uncertain"])

    def test_disjoint_sessions_do_not_create_cross_session_edges(self) -> None:
        result = self.review(claims=(
            claim(self.first, 0), claim(self.second, 0, OTHER_SESSION),
        ))
        self.assertEqual(result["session_count"], 2)
        self.assertEqual(result["edge_count"], 0)

    def test_unknown_conflicting_or_raw_session_binding_fails_closed(self) -> None:
        invalid_version = (
            "sessionref:uuidv4:123e4567-e89b-12d3-a456-426614174000"
        )
        bad_claims = (
            (claim(self.first, 0), claim(self.first, 1)),
            (claim(self.first, 0), claim(self.second, 0)),
            (claim(self.first, 0), {**claim(self.second, 1), "observation_sha256": SHA}),
            ({**claim(self.first, 0), "event_id": "event:missing"},),
            ({**claim(self.first, 0), "session_ref": "Cookie: secret"},),
            ({**claim(self.first, 0), "session_ref": invalid_version},),
            ({**claim(self.first, 0), "extra": "value"},),
            ({**claim(self.first, 0), "position": True},),
        )
        for supplied in bad_claims:
            with self.subTest(supplied=supplied), self.assertRaises(ApiSessionSequenceReviewError):
                self.review(claims=supplied)

    def test_sequence_gaps_and_backwards_time_fail_closed(self) -> None:
        for supplied in (
            (claim(self.first, 0), claim(self.second, 2)),
            (claim(self.second, 0), claim(self.first, 1)),
        ):
            with self.subTest(supplied=supplied), self.assertRaises(ApiSessionSequenceReviewError):
                self.review(claims=supplied)

    def test_inventory_source_or_review_mutation_fails_replay(self) -> None:
        report = self.review()
        with self.assertRaises(ApiSessionSequenceReviewError):
            self.review(observations=(self.first, self.second))
        with self.assertRaises(ApiSessionSequenceReviewError):
            self.review(observations=(event("event:one", status_code=403), self.second, self.third))
        changed = copy.deepcopy(report)
        changed["session_linkage_authenticated"] = True
        with self.assertRaises(ApiSessionSequenceReviewError):
            verify_api_session_sequence_review_from_sources(
                changed, inventory=self.inventory,
                observations=self.observations, claims=self.claims,
            )
        changed = copy.deepcopy(report)
        changed["sessions"][0]["edges"] = []
        with self.assertRaises(ApiSessionSequenceReviewError):
            verify_api_session_sequence_review_from_sources(
                changed, inventory=self.inventory,
                observations=self.observations, claims=self.claims,
            )

    def test_output_matches_closed_schema(self) -> None:
        path = Path("registry/schemas/api-session-sequence-review-v1.schema.json")
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        report = self.review()
        validator.validate(report)
        changed = {**report, "authenticated": True}
        self.assertFalse(validator.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
