"""Delivery metadata and deadlines must never stand in for remediation proof."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

from sunderkey.remediation_validation_contracts import RemediationValidationError
from sunderkey.remediation_workflow_visibility import (
    NO_EFFECTS,
    RemediationDeliveryObservation,
    RemediationServiceTarget,
    RemediationWorkflowError,
    review_remediation_workflow,
    verify_remediation_workflow_review,
)
from tests.agents.test_remediation_validation_contracts_phase168 import HASHES, _plan

AT = "2026-09-20T12:30:00Z"


def target(item, **changes):
    values = {
        "item_ref": item.item_ref,
        "owner_ref": item.owner_ref,
        "policy_sha256": HASHES[8],
        "recorded_at": "2026-09-20T10:06:00Z",
        "due_at": "2026-09-20T13:00:00Z",
    }
    values.update(changes)
    return RemediationServiceTarget(**values)


def observation(item, **changes):
    values = {
        "observation_ref": "deliveryref:" + item.item_ref.split(":", 1)[1],
        "item_ref": item.item_ref,
        "owner_ref": item.owner_ref,
        "observer_ref": "principalref:connector-observer",
        "ticket_ref": "ticketref:" + item.item_ref.split(":", 1)[1],
        "delivery_state": "delivered",
        "ticket_state": "open",
        "observed_at": "2026-09-20T12:00:00Z",
        "source_sha256": HASHES[9],
    }
    values.update(changes)
    return RemediationDeliveryObservation(**values)


class RemediationWorkflowVisibilityTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_closed_schema_rejects_claim_and_effect_inflation(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry"
            / "schemas"
            / "remediation-workflow-review-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        review = review_remediation_workflow(_plan(), targets=(), observations=(), as_of=AT)
        validator.validate(review)
        for section, field, value in (
            ("claims", "remediation_verified", True),
            ("claims", "owner_authenticated", 0),
            ("effects", "ticketing", "create"),
        ):
            altered = copy.deepcopy(review)
            altered[section][field] = value
            with self.assertRaises(ValidationError):
                validator.validate(altered)

    def test_complete_asserted_delivery_remains_unverified(self) -> None:
        plan = _plan()
        targets = tuple(target(item) for item in plan.items)
        observations = tuple(observation(item) for item in plan.items)
        review = review_remediation_workflow(
            plan, targets=targets, observations=observations, as_of=AT
        )
        verify_remediation_workflow_review(
            review, plan, targets=targets, observations=observations, as_of=AT
        )
        self.assertEqual(review["effects"], dict(NO_EFFECTS))
        self.assertTrue(all(value is False for value in review["claims"].values()))
        for item in review["items"]:
            self.assertEqual(item["delivery_state"], "delivered")
            self.assertEqual(item["deadline_state"], "not_due")
            self.assertEqual(item["remediation_state"], "unverified")
            self.assertIs(item["review_required"], True)

    def test_missing_sources_preserve_every_plan_item(self) -> None:
        plan = _plan()
        review = review_remediation_workflow(plan, targets=(), observations=(), as_of=AT)
        self.assertEqual(len(review["items"]), len(plan.items))
        for item in review["items"]:
            self.assertEqual(item["deadline_state"], "unknown")
            self.assertEqual(item["delivery_state"], "unknown")
            self.assertEqual(
                item["reason_codes"], ["delivery_evidence_missing", "service_target_missing"]
            )

    def test_closed_ticket_does_not_remove_exact_due_deadline(self) -> None:
        plan = _plan()
        first = plan.items[0]
        review = review_remediation_workflow(
            plan,
            targets=(target(first),),
            observations=(observation(first, ticket_state="closed"),),
            as_of="2026-09-20T13:00:00Z",
        )
        item = review["items"][0]
        self.assertEqual(item["deadline_state"], "overdue")
        self.assertEqual(item["remediation_state"], "unverified")
        self.assertIn("ticket_closed_is_not_remediation_evidence", item["reason_codes"])

    def test_same_time_conflicts_are_retained(self) -> None:
        plan = _plan()
        first = plan.items[0]
        records = (
            observation(first),
            observation(
                first,
                observation_ref="deliveryref:conflict",
                delivery_state="failed",
                ticket_state="closed",
            ),
        )
        review = review_remediation_workflow(plan, targets=(), observations=records, as_of=AT)
        item = review["items"][0]
        self.assertEqual(item["delivery_state"], "conflict")
        self.assertEqual(item["ticket_state"], "conflict")
        self.assertEqual(len(item["latest_observation_sha256s"]), 2)
        self.assertIn("delivery_metadata_conflict", item["reason_codes"])

    def test_distinct_ticket_references_need_explicit_lineage(self) -> None:
        plan = _plan()
        first = plan.items[0]
        records = (
            observation(first),
            observation(
                first,
                observation_ref="deliveryref:later",
                ticket_ref="ticketref:another",
                observed_at="2026-09-20T12:10:00Z",
            ),
        )
        item = review_remediation_workflow(plan, targets=(), observations=records, as_of=AT)[
            "items"
        ][0]
        self.assertEqual(item["ticket_state"], "conflict")
        self.assertIn("ticket_lineage_ambiguous", item["reason_codes"])
        self.assertEqual(len(item["observation_sha256s"]), 2)

    def test_freshness_boundary_and_stale_plan_remain_explicit(self) -> None:
        plan = _plan()
        records = (observation(plan.items[0]),)
        boundary = review_remediation_workflow(
            plan,
            targets=(),
            observations=records,
            as_of="2026-09-20T13:00:00Z",
            max_observation_age_seconds=3_600,
        )
        self.assertEqual(boundary["items"][0]["delivery_state"], "delivered")
        stale = review_remediation_workflow(
            plan,
            targets=(),
            observations=records,
            as_of="2026-09-20T13:00:01Z",
            max_observation_age_seconds=3_600,
        )
        self.assertEqual(stale["items"][0]["delivery_state"], "stale")
        expired = review_remediation_workflow(
            plan, targets=(), observations=records, as_of=plan.expires_at
        )
        self.assertIs(expired["source_plan_stale"], True)
        self.assertIn("source_plan_stale", expired["items"][0]["reason_codes"])

    def test_source_item_owner_and_window_substitution_fail_closed(self) -> None:
        plan = _plan()
        first = plan.items[0]
        for record in (
            observation(first, owner_ref="principalref:other"),
            observation(first, item_ref="itemref:unknown"),
            observation(first, observed_at="2026-09-20T10:04:00Z"),
            observation(first, observed_at="2026-09-20T12:31:00Z"),
        ):
            with self.subTest(record=record.observation_ref):
                with self.assertRaises(RemediationWorkflowError):
                    review_remediation_workflow(plan, targets=(), observations=(record,), as_of=AT)
        with self.assertRaises(RemediationWorkflowError):
            review_remediation_workflow(
                plan,
                targets=(target(first, recorded_at="2026-09-20T12:31:00Z"),),
                observations=(),
                as_of=AT,
            )

    def test_duplicates_and_invalid_limits_are_rejected(self) -> None:
        plan = _plan()
        first = plan.items[0]
        record = observation(first)
        for targets, observations in (((target(first), target(first)), ()), ((), (record, record))):
            with self.assertRaises(RemediationWorkflowError):
                review_remediation_workflow(
                    plan, targets=targets, observations=observations, as_of=AT
                )
        for limit in (True, 0, 604_801):
            with self.assertRaises(RemediationWorkflowError):
                review_remediation_workflow(
                    plan, targets=(), observations=(), as_of=AT, max_observation_age_seconds=limit
                )

    def test_collection_bounds_and_untyped_inputs_fail_closed(self) -> None:
        plan = _plan()
        first = plan.items[0]
        for targets, observations in (
            ((target(first),) * 2_049, ()),
            ((), (observation(first),) * 4_097),
            ([target(first)], ()),
            ((), (object(),)),
        ):
            with self.assertRaisesRegex(RemediationWorkflowError, "bounded typed"):
                review_remediation_workflow(
                    plan, targets=targets, observations=observations, as_of=AT
                )
        with self.assertRaisesRegex(RemediationWorkflowError, "predates"):
            review_remediation_workflow(
                plan, targets=(), observations=(), as_of="2026-09-20T10:04:00Z"
            )

    def test_ticket_metadata_cannot_include_urls_or_unbound_outcomes(self) -> None:
        first = _plan().items[0]
        for changes in (
            {"ticket_ref": "https://tickets.example/item/1"},
            {"ticket_ref": None},
            {"delivery_state": []},
            {"ticket_state": "resolved"},
        ):
            with self.assertRaises(RemediationValidationError):
                observation(first, **changes)
        pending = observation(
            first, ticket_ref=None, delivery_state="pending", ticket_state="unknown"
        )
        self.assertIsNone(pending.ticket_ref)

    def test_typed_record_tampering_is_detected(self) -> None:
        plan = _plan()
        record = observation(plan.items[0])
        object.__setattr__(record, "delivery_state", "failed")
        with self.assertRaisesRegex(RemediationWorkflowError, "content address"):
            review_remediation_workflow(plan, targets=(), observations=(record,), as_of=AT)
        target_record = target(plan.items[0])
        object.__setattr__(target_record, "due_at", "2026-09-20T14:00:00Z")
        with self.assertRaisesRegex(RemediationWorkflowError, "content address"):
            review_remediation_workflow(plan, targets=(target_record,), observations=(), as_of=AT)

    def test_source_order_is_deterministic_and_inputs_are_not_mutated(self) -> None:
        plan = _plan()
        targets = tuple(target(item) for item in plan.items)
        observations = tuple(observation(item) for item in plan.items)
        before = copy.deepcopy(plan.to_dict())
        first = review_remediation_workflow(
            plan, targets=targets, observations=observations, as_of=AT
        )
        second = review_remediation_workflow(
            plan, targets=targets[::-1], observations=observations[::-1], as_of=AT
        )
        self.assertEqual(first, second)
        self.assertEqual(plan.to_dict(), before)
        first["effects"]["ticketing"] = "create"
        third = review_remediation_workflow(
            plan, targets=targets, observations=observations, as_of=AT
        )
        self.assertEqual(third["effects"]["ticketing"], "none")

    def test_verifier_rejects_type_inflation_and_source_omission(self) -> None:
        plan = _plan()
        records = (observation(plan.items[0]),)
        review = review_remediation_workflow(plan, targets=(), observations=records, as_of=AT)
        tampered = copy.deepcopy(review)
        tampered["claims"]["remediation_verified"] = 0
        with self.assertRaisesRegex(RemediationWorkflowError, "replay"):
            verify_remediation_workflow_review(
                tampered, plan, targets=(), observations=records, as_of=AT
            )
        with self.assertRaisesRegex(RemediationWorkflowError, "replay"):
            verify_remediation_workflow_review(review, plan, targets=(), observations=(), as_of=AT)
        changed_plan = replace(plan, idempotency_key="idemref:another", plan_id="", plan_sha256="")
        with self.assertRaisesRegex(RemediationWorkflowError, "replay"):
            verify_remediation_workflow_review(
                review, changed_plan, targets=(), observations=records, as_of=AT
            )


if __name__ == "__main__":
    unittest.main()
