"""Tests for nonqualifying control-health window reconciliation."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import tests.agents.test_detection_validation_contracts_phase163 as detection_fixture
from sunderkey.control_health_window_review import (
    DECLARATION_DOMAIN,
    ControlHealthWindowReviewError,
    build_control_health_window_review,
    verify_control_health_window_review_from_sources,
)

SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64


def declaration(contract, **changes: object) -> dict[str, object]:
    objective = contract.objectives[0]
    body = {
        "objective_id": objective.objective_id,
        "control_id": objective.control_id,
        "control_config_sha256": objective.control_config_sha256,
        "scope_sha256": contract.binding.scope_sha256,
        "action_sha256": contract.binding.action_sha256,
        "valid_from": "2026-09-20T09:59:59Z",
        "valid_through": "2026-09-20T10:00:11Z",
        "health_state": "operational",
        "source_sha256": SHA,
    }
    body.update(changes)
    encoded = json.dumps(
        {"domain": DECLARATION_DOMAIN, "body": body},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    return {
        **body,
        "declaration_sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
    }


class ControlHealthWindowReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = detection_fixture.DetectionValidationContractsPhase163Tests().contract()

    def review(self, declarations=()):
        return build_control_health_window_review(
            contract=self.contract,
            health_declarations=tuple(declarations),
            as_of="2026-09-20T10:07:00Z",
        )

    def test_healthy_declaration_is_still_not_authenticated(self) -> None:
        supplied = (declaration(self.contract),)
        review = self.review(supplied)
        self.assertEqual(review["objective_count"], 1)
        self.assertEqual(review["missing_or_partial_count"], 0)
        self.assertEqual(review["effective_claim_health_review_count"], 0)
        self.assertEqual(review["objectives"][0]["health_disposition"], "declared_operational")
        self.assertFalse(review["control_health_authenticated"])
        self.assertEqual(review["source_provenance"], "caller_asserted_not_authenticated")
        self.assertEqual(review["qualification_effect"], "none")
        self.assertEqual(review["authorization_effect"], "none")
        self.assertFalse(review["network_call_performed"])
        self.assertEqual(
            verify_control_health_window_review_from_sources(
                review, contract=self.contract, health_declarations=supplied,
            ),
            review,
        )

    def test_missing_partial_and_degraded_are_review_flags(self) -> None:
        missing = self.review()
        self.assertEqual(missing["objectives"][0]["health_disposition"], "missing")
        self.assertEqual(missing["missing_or_partial_count"], 1)
        self.assertEqual(missing["effective_claim_health_review_count"], 1)
        partial = self.review((declaration(
            self.contract, valid_through="2026-09-20T10:00:05Z",
        ),))
        self.assertEqual(partial["objectives"][0]["health_disposition"], "partial_coverage")
        degraded = self.review((declaration(self.contract, health_state="degraded"),))
        self.assertEqual(degraded["objectives"][0]["health_disposition"], "declared_degraded")
        self.assertEqual(degraded["effective_claim_health_review_count"], 1)

    def test_conflicting_covering_declarations_are_not_treated_as_healthy(self) -> None:
        first = declaration(self.contract)
        second = declaration(self.contract, health_state="unavailable", source_sha256=OTHER_SHA)
        left = self.review((first, second))
        right = self.review((second, first))
        self.assertEqual(left, right)
        self.assertEqual(left["conflict_count"], 1)
        self.assertEqual(left["objectives"][0]["health_disposition"], "conflict")
        self.assertTrue(left["objectives"][0]["full_window_coverage_declared"])
        self.assertEqual(left["effective_claim_health_review_count"], 1)
        partial_conflict = self.review((
            first,
            declaration(
                self.contract,
                health_state="degraded",
                valid_from="2026-09-20T10:00:05Z",
                source_sha256=OTHER_SHA,
            ),
        ))
        self.assertEqual(partial_conflict["objectives"][0]["health_disposition"], "conflict")
        self.assertEqual(
            len(partial_conflict["objectives"][0]["overlapping_declaration_sha256"]), 2,
        )
        no_cover_conflict = self.review((
            declaration(self.contract, valid_through="2026-09-20T10:00:05Z"),
            declaration(
                self.contract,
                valid_from="2026-09-20T10:00:06Z",
                health_state="degraded",
                source_sha256=OTHER_SHA,
            ),
        ))
        self.assertEqual(no_cover_conflict["conflict_count"], 1)
        self.assertEqual(no_cover_conflict["missing_or_partial_count"], 1)

    def test_wrong_binding_bad_interval_and_tampering_fail_closed(self) -> None:
        bad = (
            declaration(self.contract, scope_sha256=OTHER_SHA),
            declaration(self.contract, control_config_sha256=OTHER_SHA),
            declaration(self.contract, valid_from="2026-09-20T10:00:20Z",
                        valid_through="2026-09-20T10:00:10Z"),
            declaration(self.contract, valid_through="2026-09-20T10:08:00Z"),
            {**declaration(self.contract), "source_sha256": OTHER_SHA},
            {**declaration(self.contract), "extra": "value"},
        )
        for supplied in bad:
            with self.subTest(supplied=supplied), self.assertRaises(ControlHealthWindowReviewError):
                self.review((supplied,))
        with self.assertRaises(ControlHealthWindowReviewError):
            self.review((declaration(self.contract), declaration(self.contract)))

    def test_replay_rejects_changed_claims_and_output(self) -> None:
        supplied = (declaration(self.contract),)
        report = self.review(supplied)
        with self.assertRaises(ControlHealthWindowReviewError):
            verify_control_health_window_review_from_sources(
                report, contract=self.contract,
                health_declarations=(declaration(self.contract, health_state="degraded"),),
            )
        changed = copy.deepcopy(report)
        changed["control_health_authenticated"] = True
        with self.assertRaises(ControlHealthWindowReviewError):
            verify_control_health_window_review_from_sources(
                changed, contract=self.contract, health_declarations=supplied,
            )
        changed = copy.deepcopy(report)
        changed["objectives"][0]["health_disposition"] = "verified_effective"
        with self.assertRaises(ControlHealthWindowReviewError):
            verify_control_health_window_review_from_sources(
                changed, contract=self.contract, health_declarations=supplied,
            )

    def test_output_has_closed_schema(self) -> None:
        path = Path("registry/schemas/control-health-window-review-v1.schema.json")
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        report = self.review((declaration(self.contract),))
        validator.validate(report)
        self.assertFalse(validator.is_valid({**report, "extra": "value"}))


if __name__ == "__main__":
    unittest.main()
