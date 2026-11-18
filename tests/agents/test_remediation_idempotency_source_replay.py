"""An old digest or a typed object alone cannot establish exact remediation replay."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from sunderkey.remediation_validation_contracts import (
    RemediationPlan,
    RemediationValidationError,
    ensure_idempotent,
)
from tests.agents.test_remediation_validation_contracts_phase168 import (
    HASHES,
    _context,
    _decide,
    _exception,
    _observation,
    _plan,
    _retest,
)


def records():
    plan = _plan()
    retest = _retest(plan)
    observed = _observation(plan, retest)
    return plan, retest, _decide(plan, retest, observed)


def replay(record):
    return type(record).from_dict(record.to_dict())


def changed(record):
    fields_by_type = {
        "RemediationPlan": ("proposed_by", "plan_id", "plan_sha256"),
        "RetestPlan": ("proposed_by", "retest_plan_id", "retest_plan_sha256"),
        "ClosureDecision": ("reviewer_ref", "decision_id", "decision_sha256"),
    }
    actor, identity, digest = fields_by_type[type(record).__name__]
    return replace(record, **{actor: "principalref:other", identity: "", digest: ""})


class RemediationIdempotencySourceReplayTests(unittest.TestCase):
    def test_exact_replay_accepts_each_supported_type_without_mutation_or_effects(self) -> None:
        for record in records():
            candidate = replay(record)
            before = copy.deepcopy((record.to_dict(), candidate.to_dict()))
            with self.subTest(record_type=type(record).__name__):
                ensure_idempotent(record, candidate)
                self.assertEqual((record.to_dict(), candidate.to_dict()), before)
                self.assertTrue(all(value == "none" for value in candidate.effects.values()))

    def test_old_address_candidate_mutation_fails_for_all_supported_types(self) -> None:
        for record in records():
            candidate = replay(record)
            field = "reviewer_ref" if type(record).__name__ == "ClosureDecision" else "proposed_by"
            object.__setattr__(candidate, field, "principalref:substituted")
            with self.subTest(record_type=type(record).__name__):
                with self.assertRaisesRegex(RemediationValidationError, "content address"):
                    ensure_idempotent(record, candidate)

    def test_old_address_existing_record_mutation_also_fails(self) -> None:
        for record in records():
            candidate = replay(record)
            field = "reviewer_ref" if type(record).__name__ == "ClosureDecision" else "proposed_by"
            object.__setattr__(record, field, "principalref:substituted")
            with self.subTest(record_type=type(record).__name__):
                with self.assertRaisesRegex(RemediationValidationError, "content address"):
                    ensure_idempotent(record, candidate)

    def test_two_identically_mutated_records_do_not_become_a_valid_replay(self) -> None:
        record = _plan()
        candidate = replay(record)
        for value in (record, candidate):
            object.__setattr__(value, "proposed_by", "principalref:substituted")
        self.assertEqual(record.to_dict(), candidate.to_dict())
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            ensure_idempotent(record, candidate)

    def test_actual_no_effect_fields_cannot_be_hidden_by_canonical_serialization(self) -> None:
        for field in ("existing", "candidate"):
            for record in records():
                candidate = replay(record)
                changed_record = record if field == "existing" else candidate
                object.__setattr__(changed_record, "effects", {"network": "allowed"})
                with self.subTest(field=field, record_type=type(record).__name__):
                    with self.assertRaisesRegex(RemediationValidationError, "no-effect"):
                        ensure_idempotent(record, candidate)

    def test_nested_plan_items_and_batches_are_revalidated(self) -> None:
        for source, attribute, value in (
            ("item", "owner_ref", "principalref:substituted"),
            ("batch", "risk_reduction_points", 1),
        ):
            record = _plan()
            candidate = replay(record)
            nested = candidate.items[0] if source == "item" else candidate.batches[0]
            object.__setattr__(nested, attribute, value)
            with self.subTest(source=source):
                with self.assertRaises(RemediationValidationError):
                    ensure_idempotent(record, candidate)

    def test_nested_retest_gate_is_not_trusted_under_its_original_address(self) -> None:
        record = _retest(_plan())
        candidate = replay(record)
        object.__setattr__(candidate.gates[0], "required_evidence_digests", (HASHES[15],))
        with self.assertRaisesRegex(RemediationValidationError, "content address"):
            ensure_idempotent(record, candidate)

    def test_valid_different_content_cannot_reuse_any_supported_record_key(self) -> None:
        for record in records():
            with self.subTest(record_type=type(record).__name__):
                candidate = changed(record)
                self.assertEqual(candidate.idempotency_key, record.idempotency_key)
                with self.assertRaisesRegex(RemediationValidationError, "different content"):
                    ensure_idempotent(record, candidate)

    def test_valid_different_key_is_rejected_after_reconstruction(self) -> None:
        plan = _plan()
        candidate = replace(
            plan, idempotency_key="idemref:other", plan_id="", plan_sha256=""
        )
        with self.assertRaisesRegex(RemediationValidationError, "keys do not match"):
            ensure_idempotent(plan, candidate)

    def test_type_substitution_fails_without_an_attribute_error(self) -> None:
        plan, retest, decision = records()
        for left, right in ((plan, retest), (retest, decision), (decision, plan), (plan, None)):
            with self.assertRaisesRegex(RemediationValidationError, "same type"):
                ensure_idempotent(left, right)

    def test_unsupported_records_fail_before_any_untrusted_serialization(self) -> None:
        class PretendRecord:
            idempotency_key = "idemref:pretend"

            def to_dict(self):
                raise AssertionError("unsupported serializer must not be invoked")

        for left, right in (
            ({}, {}),
            (None, None),
            (object(), object()),
            (_context(), _context()),
            (_exception(_plan()), _exception(_plan())),
            (PretendRecord(), PretendRecord()),
        ):
            with self.assertRaisesRegex(RemediationValidationError, "supported exact type"):
                ensure_idempotent(left, right)

    def test_a_subclass_cannot_override_the_supported_record_parser(self) -> None:
        class SubstitutePlan(RemediationPlan):
            def to_dict(self):
                raise AssertionError("unsupported subclass must not be serialized")

        plan = _plan()
        values = {
            key: getattr(plan, key)
            for key in plan.__dataclass_fields__
            if key not in {"DOMAIN"}
        }
        candidate = SubstitutePlan(**values)
        with self.assertRaisesRegex(RemediationValidationError, "supported exact type"):
            ensure_idempotent(candidate, candidate)

    def test_package_export_uses_the_reconstructing_checker(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.ensure_remediation_idempotent, ensure_idempotent)


if __name__ == "__main__":
    unittest.main()
