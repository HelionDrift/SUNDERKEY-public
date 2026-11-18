"""A complete source join must distinguish an old recommendation from a current fix."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None

from sunderkey.remediation_case_review import (
    NO_EFFECTS,
    RemediationCaseReviewError,
    build_remediation_case_review,
    verify_remediation_case_review,
)
from sunderkey.remediation_validation_contracts import (
    ClosureDisposition,
    GateDisposition,
    RemediationValidationError,
    build_remediation_plan,
    verify_retest_observation,
)
from tests.agents.test_remediation_validation_contracts_phase168 import (
    HASHES,
    _context,
    _decide,
    _exception,
    _handoff,
    _observation,
    _plan,
    _retest,
)
from tests.agents.test_remediation_workflow_visibility import observation, target

AT = "2026-09-20T12:40:00Z"


class RemediationCaseReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = _context()
        self.plan = _plan(self.context)
        self.retest = _retest(self.plan)
        self.observation = _observation(self.plan, self.retest)
        self.closure = _decide(self.plan, self.retest, self.observation)

    def sources(self, **changes):
        values = {
            "targets": (),
            "delivery_observations": (),
            "as_of": AT,
            "retest": self.retest,
            "retest_observation": self.observation,
            "closure": self.closure,
        }
        values.update(changes)
        return values

    def review(self, **changes):
        return build_remediation_case_review(self.context, self.plan, **self.sources(**changes))

    def test_full_source_chain_is_replayed_without_claiming_a_fix(self) -> None:
        records = (self.context, self.plan, self.retest, self.observation, self.closure)
        before = tuple(copy.deepcopy(record.to_dict()) for record in records)
        result = self.review()
        verify_remediation_case_review(result, self.context, self.plan, **self.sources())
        self.assertEqual(result["review_stage"], "historical_recommendation_replayed")
        self.assertEqual(result["historical_closure_disposition"], "closed_nonqualified")
        self.assertEqual(result["case_status"], "review_required")
        self.assertEqual(result["live_source_freshness"], "not_established")
        self.assertTrue(all(value is False for value in result["claims"].values()))
        self.assertEqual(result["effects"], dict(NO_EFFECTS))
        self.assertEqual(tuple(record.to_dict() for record in records), before)
        self.assertEqual(
            result["proposed_risk_points"], {"inherent": 180, "residual": 30, "reduction": 150}
        )
        self.assertTrue(
            all(item["remediation_state"] == "unverified" for item in result["workflow"]["items"])
        )

    def test_missing_stages_are_explicit_and_do_not_infer_closure(self) -> None:
        for changes, stage, reason in (
            (
                {"retest": None, "retest_observation": None, "closure": None},
                "planning_only",
                "retest_plan_not_supplied",
            ),
            (
                {"retest_observation": None, "closure": None},
                "awaiting_retest_observation",
                "retest_observation_not_supplied",
            ),
            ({"closure": None}, "awaiting_closure_review", "closure_recommendation_not_supplied"),
        ):
            with self.subTest(stage=stage):
                result = self.review(**changes)
                self.assertEqual(result["review_stage"], stage)
                self.assertIn(reason, result["reason_codes"])
                self.assertEqual(result["historical_closure_disposition"], "not_supplied")

    def test_closed_ticket_and_historical_recommendation_do_not_clear_deadline(self) -> None:
        first = self.plan.items[0]
        result = self.review(
            targets=(target(first, due_at=AT),),
            delivery_observations=(observation(first, ticket_state="closed"),),
        )
        item = result["workflow"]["items"][0]
        self.assertEqual(item["deadline_state"], "overdue")
        self.assertEqual(item["remediation_state"], "unverified")
        self.assertIn("ticket_closed_is_not_remediation_evidence", item["reason_codes"])

    def test_nonpassing_observations_remain_reviewable_without_missing_coverage(self) -> None:
        for disposition in (
            GateDisposition.FAIL,
            GateDisposition.INCONCLUSIVE,
            GateDisposition.NOT_OBSERVED,
        ):
            with self.subTest(disposition=disposition):
                record = _observation(
                    self.plan,
                    self.retest,
                    disposition=disposition,
                    include_evidence=False,
                    include_restoration=False,
                )
                verify_retest_observation(self.plan, self.retest, record)
                result = self.review(retest_observation=record, closure=None)
                self.assertEqual(result["retest_gate_summary"][disposition.value], 2)
                self.assertIs(result["retest_gate_summary"]["required_evidence_complete"], False)
                self.assertIs(result["retest_gate_summary"]["restoration_evidence_complete"], False)
                for reason in (
                    "required_retest_evidence_missing",
                    "regression_gate_not_passed",
                    "rollback_cleanup_evidence_missing",
                ):
                    self.assertIn(reason, result["reason_codes"])

    def test_pass_without_evidence_does_not_get_inferred_recommendation(self) -> None:
        record = _observation(self.plan, self.retest, include_evidence=False)
        result = self.review(retest_observation=record, closure=None)
        self.assertEqual(result["retest_gate_summary"]["pass"], 2)
        self.assertIs(result["retest_gate_summary"]["required_evidence_complete"], False)
        self.assertEqual(result["historical_closure_disposition"], "not_supplied")

    def test_dependent_sources_cannot_be_used_without_their_predecessors(self) -> None:
        for changes in (
            {"retest": None},
            {"retest_observation": None},
            {"retest": None, "retest_observation": None},
        ):
            with self.assertRaisesRegex(RemediationCaseReviewError, "requires"):
                self.review(**changes)

    def test_original_context_is_required_and_substitution_is_rejected(self) -> None:
        with self.assertRaises(RemediationValidationError):
            build_remediation_case_review(
                _context(tenant_ref="tenantref:other"), self.plan, **self.sources()
            )
        object.__setattr__(self.context, "observed_at", "2026-09-20T09:00:00Z")
        with self.assertRaises(RemediationValidationError):
            self.review()

    def test_self_consistent_partial_retest_is_not_enough_for_case_join(self) -> None:
        partial = replace(
            self.retest,
            item_refs=(self.plan.items[0].item_ref,),
            gates=self.retest.gates[:1],
            retest_plan_id="",
            retest_plan_sha256="",
        )
        with self.assertRaisesRegex(RemediationValidationError, "exactly all"):
            self.review(retest=partial, retest_observation=None, closure=None)

    def test_wrong_observation_coverage_and_binding_fail_closed(self) -> None:
        for record in (
            replace(
                self.observation,
                gate_observations=self.observation.gate_observations[:1],
                observation_id="",
                observation_sha256="",
            ),
            replace(
                self.observation,
                retest_plan_sha256=HASHES[15],
                observation_id="",
                observation_sha256="",
            ),
        ):
            with self.assertRaises(RemediationValidationError):
                self.review(retest_observation=record, closure=None)

    def test_observation_outside_retest_window_is_rejected(self) -> None:
        for at in ("2026-09-20T10:59:59Z", "2026-09-21T09:00:01Z"):
            record = replace(
                self.observation, observed_at=at, observation_id="", observation_sha256=""
            )
            with self.assertRaisesRegex(RemediationValidationError, "outside"):
                verify_retest_observation(self.plan, self.retest, record)
        boundary = replace(
            self.observation,
            observed_at=self.retest.expires_at,
            observation_id="",
            observation_sha256="",
        )
        verify_retest_observation(self.plan, self.retest, boundary)

    def test_typed_observation_mutation_and_untyped_sources_are_rejected(self) -> None:
        object.__setattr__(self.observation, "observed_at", "2026-09-20T12:01:00Z")
        with self.assertRaises(RemediationValidationError):
            self.review()
        with self.assertRaisesRegex(RemediationCaseReviewError, "typed"):
            build_remediation_case_review(self.context.to_dict(), self.plan, **self.sources())
        with self.assertRaisesRegex(RemediationValidationError, "typed"):
            verify_retest_observation(self.plan, self.retest, {})

    def test_forged_closure_disposition_cannot_replay(self) -> None:
        changed = replace(
            self.closure, disposition=ClosureDisposition.OPEN, decision_id="", decision_sha256=""
        )
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            self.review(closure=changed)

    def test_future_sources_are_rejected_relative_to_explicit_case_time(self) -> None:
        for at, changes in (
            ("2026-09-20T10:30:00Z", {"retest_observation": None, "closure": None}),
            ("2026-09-20T11:45:00Z", {"closure": None}),
            ("2026-09-20T12:15:00Z", {}),
            (
                "2026-09-20T11:15:00Z",
                {"retest_observation": None, "closure": None, "exception": _exception(self.plan)},
            ),
        ):
            with self.subTest(at=at):
                with self.assertRaisesRegex(RemediationCaseReviewError, "after"):
                    self.review(as_of=at, **changes)

    def test_expired_source_window_preserves_only_historical_disposition(self) -> None:
        result = self.review(as_of="2026-09-22T10:00:00Z")
        self.assertEqual(result["historical_closure_disposition"], "closed_nonqualified")
        self.assertIs(result["declared_source_windows_open"], False)
        self.assertIn("declared_source_window_expired", result["reason_codes"])
        self.assertEqual(result["live_source_freshness"], "not_established")
        boundary = self.review(as_of=self.retest.expires_at)
        self.assertIs(boundary["declared_source_windows_open"], False)

    def test_expired_exception_is_not_renewed_by_historical_closure(self) -> None:
        record = _observation(self.plan, self.retest, disposition=GateDisposition.FAIL)
        exception = _exception(self.plan, expires_at="2026-09-20T12:45:00Z")
        closure = _decide(self.plan, self.retest, record, exception=exception)
        result = self.review(
            retest_observation=record,
            closure=closure,
            exception=exception,
            as_of="2026-09-20T13:00:00Z",
        )
        self.assertEqual(result["historical_closure_disposition"], "exception_active_nonqualified")
        summary = result["exception_summary"]
        self.assertIs(summary["used_by_historical_closure"], True)
        self.assertIs(summary["declared_exception_window_open"], False)
        self.assertIs(summary["effective_risk_acceptance_verified"], False)
        self.assertIn("declared_exception_window_expired", result["reason_codes"])
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            self.review(retest_observation=record, closure=closure)

    def test_compensating_control_expiry_is_not_laundered_by_review_time(self) -> None:
        control = replace(self.plan.compensating_controls[0], expires_at="2026-09-20T12:35:00Z")
        plan = build_remediation_plan(
            self.context,
            self.plan.items,
            (control,),
            tuple(_handoff(item) for item in self.plan.items),
            idempotency_key="idemref:short-control",
            proposed_by=self.plan.proposed_by,
            created_at=self.plan.created_at,
            expires_at=self.plan.expires_at,
        )
        retest = _retest(plan)
        record = _observation(plan, retest, disposition=GateDisposition.FAIL)
        exception = _exception(plan)
        closure = _decide(plan, retest, record, exception=exception)
        result = build_remediation_case_review(
            self.context,
            plan,
            targets=(),
            delivery_observations=(),
            as_of=AT,
            retest=retest,
            retest_observation=record,
            closure=closure,
            exception=exception,
        )
        self.assertIs(result["exception_summary"]["declared_control_windows_open"], False)
        self.assertIn("declared_compensating_control_window_expired", result["reason_codes"])

    def test_unreferenced_or_cross_context_exception_sources_are_rejected(self) -> None:
        for exception in (
            _exception(self.plan, item_refs=("itemref:absent",)),
            _exception(self.plan, control_refs=("controlref:absent",)),
            _exception(self.plan, context_sha256=HASHES[15]),
        ):
            with self.assertRaises(RemediationCaseReviewError):
                self.review(exception=exception)

    def test_incomplete_asserted_control_coverage_remains_visible(self) -> None:
        control = replace(
            self.plan.compensating_controls[0], item_refs=(self.plan.items[0].item_ref,)
        )
        plan = build_remediation_plan(
            self.context,
            self.plan.items,
            (control,),
            tuple(_handoff(item) for item in self.plan.items),
            idempotency_key="idemref:partial-control",
            proposed_by=self.plan.proposed_by,
            created_at=self.plan.created_at,
            expires_at=self.plan.expires_at,
        )
        result = build_remediation_case_review(
            self.context,
            plan,
            targets=(),
            delivery_observations=(),
            as_of=AT,
            exception=_exception(plan),
        )
        self.assertIs(result["exception_summary"]["asserted_control_coverage_complete"], False)
        self.assertIn("asserted_exception_control_coverage_incomplete", result["reason_codes"])

    def test_exact_replay_rejects_type_inflation_omission_and_extra_fields(self) -> None:
        result = self.review()
        for section, field, value in (
            ("claims", "remediation_verified", 0),
            ("effects", "closure", "allowed"),
            ("workflow", "source_plan_stale", 0),
        ):
            changed = copy.deepcopy(result)
            changed[section][field] = value
            with self.assertRaisesRegex(RemediationCaseReviewError, "replay"):
                verify_remediation_case_review(changed, self.context, self.plan, **self.sources())
        with self.assertRaisesRegex(RemediationCaseReviewError, "replay"):
            verify_remediation_case_review(
                result, self.context, self.plan, **self.sources(closure=None)
            )
        with self.assertRaisesRegex(RemediationCaseReviewError, "replay"):
            verify_remediation_case_review(
                {**result, "verified": True}, self.context, self.plan, **self.sources()
            )

    def test_effects_and_nested_results_are_fresh_and_order_independent(self) -> None:
        targets = tuple(target(item) for item in self.plan.items)
        observations = tuple(observation(item) for item in self.plan.items)
        result = self.review(targets=targets, delivery_observations=observations)
        second = self.review(targets=targets[::-1], delivery_observations=observations[::-1])
        self.assertEqual(result, second)
        result["effects"]["ticketing"] = "create"
        result["workflow"]["claims"]["remediation_verified"] = True
        self.assertEqual(self.review()["effects"]["ticketing"], "none")
        with self.assertRaises(TypeError):
            NO_EFFECTS["execution"] = "allowed"

    def test_package_exports_observation_source_verifier(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.verify_remediation_retest_observation, verify_retest_observation)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_closed_schema_validates_each_stage_and_rejects_inflation(self) -> None:
        root = Path(__file__).resolve().parents[2] / "registry" / "schemas"
        schema = json.loads((root / "remediation-case-review-v1.schema.json").read_text("utf-8"))
        workflow = json.loads(
            (root / "remediation-workflow-review-v1.schema.json").read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        registry = Registry().with_resource(workflow["$id"], Resource.from_contents(workflow))
        validator = Draft202012Validator(schema, registry=registry)
        for changes in (
            {},
            {"closure": None},
            {"closure": None, "retest_observation": None},
            {"closure": None, "retest_observation": None, "retest": None},
            {"exception": _exception(self.plan)},
        ):
            validator.validate(self.review(**changes))
        result = self.review()
        for section, field, value in (
            ("claims", "remediation_verified", True),
            ("claims", "identity_authenticated", 0),
            ("effects", "closure", "allow"),
            ("workflow", "unexpected", True),
        ):
            changed = copy.deepcopy(result)
            changed[section][field] = value
            with self.assertRaises(ValidationError):
                validator.validate(changed)


if __name__ == "__main__":
    unittest.main()
