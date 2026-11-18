"""An original context must replay before its plan can claim source consistency."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from sunderkey.remediation_validation_contracts import (
    RemediationValidationError,
    build_remediation_plan,
    verify_remediation_plan,
)
from tests.agents.test_remediation_validation_contracts_phase168 import _context, _plan


class RemediationPlanContextReplayTests(unittest.TestCase):
    def test_exact_context_plan_replay_is_read_only(self) -> None:
        context = _context()
        plan = _plan(context)
        before = copy.deepcopy((context.to_dict(), plan.to_dict()))
        verify_remediation_plan(context, plan)
        self.assertEqual((context.to_dict(), plan.to_dict()), before)
        self.assertTrue(all(value == "none" for value in plan.effects.values()))

    def test_context_timestamp_mutation_cannot_create_predating_plan(self) -> None:
        context = _context(observed_at="2026-09-20T10:10:00Z")
        with self.assertRaisesRegex(RemediationValidationError, "predates"):
            _plan(context)
        object.__setattr__(context, "observed_at", "2026-09-20T10:00:00Z")
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            _plan(context)

    def test_context_expiry_mutation_cannot_extend_source_window(self) -> None:
        context = _context(expires_at="2026-09-20T12:00:00Z")
        object.__setattr__(context, "expires_at", "2026-09-22T10:00:00Z")
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            _plan(context)

    def test_self_consistent_plan_cannot_predate_or_outlive_original_context(self) -> None:
        context = _context()
        plan = _plan(context)
        later_context = _context(observed_at="2026-09-20T10:10:00Z")
        rebound = replace(
            plan,
            context_id=later_context.context_id,
            context_sha256=later_context.context_sha256,
            plan_id="",
            plan_sha256="",
        )
        with self.assertRaisesRegex(RemediationValidationError, "predates"):
            verify_remediation_plan(later_context, rebound)
        escaped = replace(plan, expires_at="2026-09-21T10:01:00Z", plan_id="", plan_sha256="")
        with self.assertRaisesRegex(RemediationValidationError, "outlives"):
            verify_remediation_plan(context, escaped)

    def test_self_consistent_context_substitution_does_not_replay(self) -> None:
        context = _context()
        plan = _plan(context)
        other = _context(tenant_ref="tenantref:other")
        with self.assertRaisesRegex(RemediationValidationError, "replay"):
            verify_remediation_plan(other, plan)

    def test_old_address_plan_mutation_fails_before_replay(self) -> None:
        context = _context()
        plan = _plan(context)
        object.__setattr__(plan, "proposed_by", "principalref:substituted")
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            verify_remediation_plan(context, plan)

    def test_nested_source_records_are_reconstructed(self) -> None:
        for source, field, value in (
            ("item", "owner_ref", "not a principal reference"),
            ("control", "expected_risk_reduction_points", True),
            ("handoff", "accepted_at", "invalid time"),
        ):
            with self.subTest(source=source):
                context = _context()
                plan = _plan(context)
                record = {
                    "item": plan.items[0],
                    "control": plan.compensating_controls[0],
                    "handoff": plan.ownership_handoffs[0],
                }[source]
                object.__setattr__(record, field, value)
                with self.assertRaises(RemediationValidationError):
                    build_remediation_plan(
                        context,
                        plan.items,
                        plan.compensating_controls,
                        plan.ownership_handoffs,
                        idempotency_key=plan.idempotency_key,
                        proposed_by=plan.proposed_by,
                        created_at=plan.created_at,
                        expires_at=plan.expires_at,
                    )

    def test_untyped_and_oversized_source_sequences_fail_closed(self) -> None:
        context = _context()
        plan = _plan(context)
        for items, controls, handoffs in (
            ((object(),), plan.compensating_controls, plan.ownership_handoffs),
            (plan.items * 2_049, plan.compensating_controls, plan.ownership_handoffs),
            (plan.items, "not a sequence of controls", plan.ownership_handoffs),
        ):
            with self.assertRaisesRegex(RemediationValidationError, "bounded typed"):
                build_remediation_plan(
                    context,
                    items,
                    controls,
                    handoffs,
                    idempotency_key=plan.idempotency_key,
                    proposed_by=plan.proposed_by,
                    created_at=plan.created_at,
                    expires_at=plan.expires_at,
                )
        with self.assertRaises(RemediationValidationError):
            verify_remediation_plan(object(), plan)
        with self.assertRaises(RemediationValidationError):
            verify_remediation_plan(context, object())

    def test_context_replay_verifier_is_exported(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.verify_remediation_plan, verify_remediation_plan)


if __name__ == "__main__":
    unittest.main()
