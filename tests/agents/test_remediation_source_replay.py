"""Source replay must precede any offline remediation closure recommendation."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from sunderkey.remediation_validation_contracts import (
    NO_EFFECTS,
    ClosureDisposition,
    GateDisposition,
    RemediationValidationError,
    build_retest_plan,
    decide_closure,
    verify_closure_decision,
    verify_retest_plan,
)
from tests.agents.test_remediation_validation_contracts_phase168 import (
    _decide,
    _exception,
    _observation,
    _plan,
    _retest,
)


class RemediationSourceReplayTests(unittest.TestCase):
    def test_exact_sources_replay_without_mutation_or_effects(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observation = _observation(plan, retest)
        decision = _decide(plan, retest, observation)
        records = (plan, retest, observation, decision)
        before = tuple(copy.deepcopy(record.to_dict()) for record in records)
        verify_retest_plan(plan, retest)
        verify_closure_decision(plan, retest, observation, decision)
        self.assertEqual(tuple(record.to_dict() for record in records), before)
        self.assertEqual(decision.disposition, ClosureDisposition.CLOSED_NONQUALIFIED)
        self.assertEqual(decision.to_dict()["effects"], dict(NO_EFFECTS))

    def test_self_consistent_partial_retest_cannot_close_full_plan(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        partial = replace(
            retest,
            item_refs=(plan.items[0].item_ref,),
            gates=retest.gates[:1],
            rollback_evidence_digests=retest.rollback_evidence_digests[:1],
            cleanup_evidence_digests=retest.cleanup_evidence_digests[:1],
            retest_plan_id="",
            retest_plan_sha256="",
        )
        observation = _observation(plan, partial)
        with self.assertRaisesRegex(RemediationValidationError, "exactly all"):
            verify_retest_plan(plan, partial)
        with self.assertRaisesRegex(RemediationValidationError, "exactly all"):
            _decide(plan, partial, observation)

    def test_self_consistent_weakened_restoration_is_rejected(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        for field in ("rollback_evidence_digests", "cleanup_evidence_digests"):
            with self.subTest(field=field):
                altered = replace(
                    retest,
                    **{
                        field: getattr(retest, field)[:1],
                        "retest_plan_id": "",
                        "retest_plan_sha256": "",
                    },
                )
                with self.assertRaisesRegex(RemediationValidationError, "replay"):
                    _decide(plan, altered, _observation(plan, altered))

    def test_retest_window_cannot_escape_source_plan(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        for changes, message in (
            ({"created_at": "2026-09-20T10:04:00Z"}, "predates"),
            ({"expires_at": "2026-09-21T09:31:00Z"}, "outlives"),
        ):
            with self.subTest(changes=changes):
                altered = replace(
                    retest, **changes, retest_plan_id="", retest_plan_sha256=""
                )
                with self.assertRaisesRegex(RemediationValidationError, message):
                    _decide(plan, altered, _observation(plan, altered))

    def test_mutated_typed_sources_are_not_trusted(self) -> None:
        for source, field, value in (
            ("plan", "proposed_by", "principalref:substituted"),
            ("retest", "proposed_by", "principalref:substituted"),
            ("observation", "observed_by", "principalref:substituted"),
        ):
            with self.subTest(source=source):
                plan = _plan()
                retest = _retest(plan)
                observation = _observation(plan, retest)
                record = {"plan": plan, "retest": retest, "observation": observation}[source]
                object.__setattr__(record, field, value)
                with self.assertRaisesRegex(RemediationValidationError, "content address"):
                    _decide(plan, retest, observation)

    def test_retest_builder_rechecks_nested_source_and_gate_contracts(self) -> None:
        for change in ("source_item", "gate"):
            with self.subTest(change=change):
                plan = _plan()
                retest = _retest(plan)
                if change == "source_item":
                    object.__setattr__(plan.items[0], "owner_ref", "principalref:substituted")
                else:
                    object.__setattr__(retest.gates[0], "failure_code", "invalid code")
                with self.assertRaises(RemediationValidationError):
                    build_retest_plan(
                        plan,
                        retest.gates,
                        idempotency_key=retest.idempotency_key,
                        proposed_by=retest.proposed_by,
                        created_at=retest.created_at,
                        expires_at=retest.expires_at,
                    )

    def test_self_consistent_rebound_decision_fails_source_replay(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observation = _observation(plan, retest)
        decision = _decide(plan, retest, observation)
        altered = replace(
            decision,
            disposition=ClosureDisposition.OPEN,
            reason_codes=("repository_only_nonqualified",),
            decision_id="",
            decision_sha256="",
        )
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            verify_closure_decision(plan, retest, observation, altered)

    def test_changed_observation_cannot_reuse_original_closure(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observation = _observation(plan, retest)
        decision = _decide(plan, retest, observation)
        failed = _observation(plan, retest, disposition=GateDisposition.FAIL)
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            verify_closure_decision(plan, retest, failed, decision)

    def test_exception_recommendation_requires_its_exact_exception_source(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observation = _observation(plan, retest, disposition=GateDisposition.FAIL)
        exception = _exception(plan)
        decision = _decide(plan, retest, observation, exception=exception)
        verify_closure_decision(plan, retest, observation, decision, exception=exception)
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            verify_closure_decision(plan, retest, observation, decision)
        object.__setattr__(exception, "approved_by", "principalref:substituted")
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            _decide(plan, retest, observation, exception=exception)

    def test_untyped_inputs_fail_closed_at_public_boundaries(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observation = _observation(plan, retest)
        with self.assertRaises(RemediationValidationError):
            verify_retest_plan(plan, object())
        with self.assertRaises(RemediationValidationError):
            verify_closure_decision(plan, retest, observation, object())
        with self.assertRaises(RemediationValidationError):
            decide_closure(
                plan,
                retest,
                object(),
                reviewer_ref="principalref:reviewer",
                reviewed_at="2026-09-20T12:30:00Z",
                idempotency_key="idemref:closure",
            )

    def test_source_replay_helpers_are_exported(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.verify_remediation_retest_plan, verify_retest_plan)
        self.assertIs(sunderkey.verify_remediation_closure_decision, verify_closure_decision)


if __name__ == "__main__":
    unittest.main()
