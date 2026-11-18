"""Phase 192 semantic completion and explicit retry authorization coverage."""

from __future__ import annotations

import json
import unicodedata
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.build_semantic_completion_retry import semantic_completion_retry_schema
from sunderkey.expert_model_execution_custody import (
    DeterministicExpertModelProviderFixture,
    InMemoryExpertBudgetCustody,
    ProviderOutcomeIndeterminate,
    execute_expert_model,
)
from sunderkey.expert_runtime import content_address_work_product
from sunderkey.multi_model_routing import canonical_json
from sunderkey.semantic_completion_retry import (
    InMemoryRetryReplayGuard,
    RequirementDisposition,
    RetryAuthorizationAuthority,
    RetryAuthorizationReceipt,
    RetryReplayCommit,
    SemanticCompletionAssessment,
    SemanticCompletionEvidence,
    SemanticCompletionRequirements,
    SemanticCompletionRetryError,
    assess_semantic_completion,
    authorize_retry,
)
from tests.agents import test_expert_model_execution_custody_phase189 as phase189

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "semantic-completion-retry-v1.schema.json"
PHASE_FILES = (
    ROOT / "docs" / "phase192-semantic-completion-and-retry.md",
    SCHEMA_PATH,
    ROOT / "scripts" / "build_semantic_completion_retry.py",
    ROOT / "src" / "sunderkey" / "semantic_completion_retry.py",
    Path(__file__),
)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
THREE = "sha256:" + "3" * 64
FOUR = "sha256:" + "4" * 64
FIVE = "sha256:" + "5" * 64
NOW = phase189.NOW


class SemanticCompletionRetryPhase192Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase189.ExpertModelExecutionCustodyPhase189Tests.setUpClass()
        cls.base = phase189.ExpertModelExecutionCustodyPhase189Tests()
        cls.catalog = cls.base.catalog
        cls.pack = cls.base.pack

    def product_json(self, envelope, product_type: str = "observation") -> str:
        body = json.loads(self.base.product_json(envelope))
        body.pop("product_id")
        body.pop("product_sha256")
        body["product_type"] = product_type
        if product_type == "abstention":
            body["evidence_refs"] = []
            body["payload"] = {
                "reason": "Required evidence is unavailable.",
                "missing_requirement_ids": ["evidence-001"],
                "safe_alternative": "Request current evidence from the owner.",
            }
        elif product_type == "blocker":
            body["evidence_refs"] = []
            body["payload"] = {
                "blocker_kind": "missing_evidence",
                "blocked_requirement_ids": ["evidence-001"],
                "resolution_needed": "Provide current independently verified evidence.",
            }
        return canonical_json(content_address_work_product(body))

    def execution(self, *, state: str = "completed", product_type: str = "observation"):
        envelope, decision, capability, budget, authority = self.base.fixtures()

        def outcome(plan):
            if state == "indeterminate":
                raise ProviderOutcomeIndeterminate("fixture uncertainty")
            if state == "failed":
                return self.base.observation(
                    plan,
                    envelope,
                    terminal_state="failed",
                    structured_output_json=None,
                )
            if state == "incomplete":
                return self.base.observation(
                    plan,
                    envelope,
                    terminal_state="incomplete",
                    structured_output_json=None,
                    incomplete_reason="provider stopped at its explicit output ceiling",
                )
            raw = (
                '{"unexpected":true}'
                if state == "malformed"
                else self.product_json(envelope, product_type)
            )
            return self.base.observation(plan, envelope, structured_output_json=raw)

        result = execute_expert_model(
            self.catalog,
            self.pack,
            envelope,
            decision,
            capability,
            budget,
            authority,
            InMemoryExpertBudgetCustody(budget),
            DeterministicExpertModelProviderFixture("adapter.fixture", outcome),
            now=NOW,
        )
        return envelope, decision, capability, budget, authority, result

    def requirements(self, envelope, *, review_required: bool = True, **changes):
        values = {
            "mission_id": envelope.mission_id,
            "plan_id": envelope.plan_id,
            "work_id": envelope.work_id,
            "target_scope_sha256": envelope.target_scope_sha256,
            "authority_snapshot_sha256": envelope.authority_snapshot_sha256,
            "evidence_snapshot_sha256": envelope.evidence_snapshot_sha256,
            "runtime_catalog_sha256": self.catalog.catalog_sha256,
            "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
            "execution_envelope_sha256": envelope.envelope_sha256,
            "dependency_ids": ("dependency-001",),
            "evidence_requirement_ids": tuple(sorted(envelope.evidence_requirement_ids)),
            "cleanup_requirement_ids": tuple(sorted(envelope.cleanup_requirement_ids)),
            "approval_requirement_ids": tuple(sorted(envelope.approval_requirement_ids)),
            "independent_review_required": review_required,
            "requirements_source_sha256": THREE,
        }
        values.update(changes)
        return SemanticCompletionRequirements(**values)

    def disposition(self, requirement_id: str, state: str = "satisfied"):
        proof = () if state in {"missing", "pending", "stale", "invalid", "blocked"} else (FOUR,)
        return RequirementDisposition(requirement_id, state, proof)

    def evidence(
        self,
        requirements,
        result,
        *,
        dependency_state: str = "satisfied",
        evidence_state: str = "satisfied",
        cleanup_state: str = "satisfied",
        approval_state: str = "satisfied",
        review_state: str = "accepted",
        **changes,
    ):
        product = result.work_product
        lineage = (
            tuple(sorted(product.to_dict()["lineage_product_ids"])) if product is not None else ()
        )
        values = {
            "requirements_id": requirements.requirements_id,
            "requirements_sha256": requirements.requirements_sha256,
            "execution_receipt_id": result.receipt.receipt_id,
            "execution_receipt_sha256": result.receipt.receipt_sha256,
            "work_product_id": result.receipt.work_product_id,
            "work_product_sha256": result.receipt.work_product_sha256,
            "lineage_product_ids": lineage,
            "dependency_dispositions": (self.disposition("dependency-001", dependency_state),),
            "evidence_dispositions": (self.disposition("evidence-001", evidence_state),),
            "cleanup_dispositions": (self.disposition("cleanup-001", cleanup_state),),
            "approval_dispositions": (self.disposition("approval-001", approval_state),),
            "independent_review_state": review_state,
            "independent_review_record_sha256": (
                FIVE if review_state in {"accepted", "rejected"} else None
            ),
            "verifier_principal_id": "assurance.semantic.verifier",
            "verifier_assertion_sha256": ZERO,
            "authentication_verification_sha256": ONE,
            "verification_sha256": FOUR,
            "verified_at": NOW,
            "expires_at": "2026-09-20T12:20:00Z",
        }
        values.update(changes)
        return SemanticCompletionEvidence(**values)

    def assess(self, execution, **evidence_changes):
        envelope, decision, _, _, authority, result = execution
        requirements = self.requirements(envelope)
        evidence = self.evidence(requirements, result, **evidence_changes)
        assessment = assess_semantic_completion(
            self.catalog,
            self.pack,
            envelope,
            decision,
            authority,
            result.invocation_plan,
            result.reservation_commit,
            result.observation,
            result.settlement,
            result.receipt,
            result.work_product,
            requirements,
            evidence,
            now=NOW,
        )
        return requirements, evidence, assessment

    def retry_fixture(self):
        execution = self.execution()
        requirements, evidence, assessment = self.assess(
            execution, evidence_state="missing", review_state="pending"
        )
        envelope, decision, _, budget, authority, result = execution
        new_capability = self.base.capability(model_version="2026-08-16.1")
        new_decision, _, _ = self.base.route(capability=new_capability, budget=budget)
        new_authority = self.base.authority(envelope, new_decision, new_capability)
        retry_authority = self.retry_authority(
            assessment,
            envelope,
            decision,
            authority,
            result.receipt,
            envelope,
            new_decision,
            new_authority,
            budget,
        )
        return (
            execution,
            requirements,
            evidence,
            assessment,
            new_capability,
            new_decision,
            new_authority,
            retry_authority,
        )

    def retry_authority(
        self,
        assessment,
        prior_envelope,
        prior_decision,
        prior_authority,
        prior_receipt,
        new_envelope,
        new_decision,
        new_authority,
        budget,
        **changes,
    ):
        remaining = (
            budget.aggregate_input_token_limit - budget.aggregate_input_tokens_reserved,
            budget.aggregate_output_token_limit - budget.aggregate_output_tokens_reserved,
            budget.aggregate_cost_limit_micros - budget.aggregate_cost_reserved_micros,
        )
        values = {
            "assessment_id": assessment.assessment_id,
            "assessment_sha256": assessment.assessment_sha256,
            "prior_execution_receipt_id": prior_receipt.receipt_id,
            "prior_execution_receipt_sha256": prior_receipt.receipt_sha256,
            "prior_failure_class": assessment.failure_class,
            "prior_routing_decision_sha256": prior_decision.decision_sha256,
            "prior_execution_authority_sha256": prior_authority.authority_sha256,
            "prior_execution_envelope_sha256": prior_envelope.envelope_sha256,
            "previous_retry_receipt_id": None,
            "previous_retry_receipt_sha256": None,
            "new_routing_decision_id": new_decision.decision_id,
            "new_routing_decision_sha256": new_decision.decision_sha256,
            "new_execution_authority_id": new_authority.authority_id,
            "new_execution_authority_sha256": new_authority.authority_sha256,
            "new_execution_envelope_sha256": new_envelope.envelope_sha256,
            "runtime_catalog_sha256": self.catalog.catalog_sha256,
            "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
            "mission_id": prior_envelope.mission_id,
            "plan_id": prior_envelope.plan_id,
            "work_id": prior_envelope.work_id,
            "target_scope_sha256": prior_envelope.target_scope_sha256,
            "authority_snapshot_sha256": prior_envelope.authority_snapshot_sha256,
            "budget_id": budget.budget_id,
            "budget_sha256": budget.budget_sha256,
            "budget_revision": budget.budget_revision,
            "remaining_input_tokens": remaining[0],
            "remaining_output_tokens": remaining[1],
            "remaining_cost_micros": remaining[2],
            "changed_condition_codes": ("evidence_changed", "route_changed"),
            "changed_condition_evidence_sha256": FIVE,
            "attempt_number": 2,
            "maximum_attempts": 3,
            "cooldown_until": NOW,
            "issued_at": NOW,
            "valid_from": "2026-09-20T12:07:00Z",
            "expires_at": "2026-09-20T12:30:00Z",
            "issuer_principal_id": "control.retry.approver",
            "subject_principal_id": new_authority.subject_principal_id,
            "producer_principal_id": prior_authority.expert_profile_id,
            "requester_principal_id": new_authority.requester_principal_id,
            "provider_adapter_principal_id": new_authority.provider_adapter_principal_id,
            "model_principal_id": new_authority.model_principal_id,
            "issuer_assertion_sha256": ZERO,
            "authentication_verification_sha256": ONE,
        }
        values.update(changes)
        return RetryAuthorizationAuthority(**values)

    def authorize(self, fixture, guard=None, *, retry_authority=None, **changes):
        (
            execution,
            _,
            _,
            assessment,
            new_capability,
            new_decision,
            new_authority,
            default_retry_authority,
        ) = fixture
        envelope, decision, _, budget, authority, result = execution
        values = {
            "runtime_catalog": self.catalog,
            "runtime_pack": self.pack,
            "prior_envelope": envelope,
            "prior_decision": decision,
            "prior_execution_authority": authority,
            "prior_receipt": result.receipt,
            "assessment": assessment,
            "new_envelope": envelope,
            "new_decision": new_decision,
            "new_capability": new_capability,
            "new_execution_authority": new_authority,
            "budget": budget,
            "retry_authority": retry_authority or default_retry_authority,
            "replay_guard": guard or InMemoryRetryReplayGuard(),
            "now": NOW,
        }
        values.update(changes)
        return authorize_retry(**values)

    def test_completion_is_evidence_based_and_content_addressed(self) -> None:
        requirements, evidence, assessment = self.assess(self.execution())
        self.assertEqual(assessment.completion_state, "completed")
        self.assertEqual(assessment.failure_class, "none")
        self.assertFalse(assessment.retry_eligible)
        self.assertEqual(assessment.reason_codes, ("all_requirements_satisfied",))
        self.assertEqual(assessment.dependency_ids, ("dependency-001",))
        self.assertEqual(
            assessment.to_dict()["effects"],
            {
                "action": "none",
                "authorization": "none",
                "budget_mutation": "none",
                "finding": "none",
                "independent_review": "none",
                "provider_call": "none",
                "qualification": "none",
                "retry_execution": "none",
                "target": "none",
                "tools": "none",
            },
        )
        self.assertEqual(
            requirements, SemanticCompletionRequirements.from_dict(requirements.to_dict())
        )
        self.assertEqual(evidence, SemanticCompletionEvidence.from_dict(evidence.to_dict()))
        self.assertEqual(assessment, SemanticCompletionAssessment.from_dict(assessment.to_dict()))

    def test_all_closed_completion_states_are_deterministic(self) -> None:
        cases = (
            (self.execution(), {}, "completed"),
            (self.execution(), {"review_state": "pending"}, "pending_independent_review"),
            (self.execution(), {"evidence_state": "missing"}, "partial"),
            (self.execution(product_type="blocker"), {}, "blocked"),
            (self.execution(product_type="abstention"), {}, "abstained"),
            (self.execution(state="malformed"), {}, "malformed"),
            (self.execution(state="incomplete"), {}, "incomplete"),
            (self.execution(state="failed"), {}, "failed"),
            (self.execution(state="indeterminate"), {}, "indeterminate"),
        )
        for execution, evidence_changes, expected in cases:
            with self.subTest(expected=expected):
                _, _, assessment = self.assess(execution, **evidence_changes)
                self.assertEqual(assessment.completion_state, expected)

    def test_model_summary_cannot_override_missing_evidence(self) -> None:
        _, _, assessment = self.assess(self.execution(), evidence_state="missing")
        self.assertEqual(assessment.completion_state, "partial")
        self.assertIn("evidence_unsatisfied", assessment.blocker_codes)

    def test_cross_context_lineage_and_execution_chain_substitution_fail(self) -> None:
        execution = self.execution()
        envelope, decision, _, _, authority, result = execution
        requirements = self.requirements(envelope, work_id="work-other")
        evidence = self.evidence(requirements, result)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "cross-context"):
            assess_semantic_completion(
                self.catalog,
                self.pack,
                envelope,
                decision,
                authority,
                result.invocation_plan,
                result.reservation_commit,
                result.observation,
                result.settlement,
                result.receipt,
                result.work_product,
                requirements,
                evidence,
                now=NOW,
            )
        bad_receipt = replace(
            result.receipt,
            execution_state="provider_failed_settled",
            output_status="no_output",
            work_product_id=None,
            work_product_sha256=None,
        )
        requirements = self.requirements(envelope)
        evidence = self.evidence(
            requirements,
            result,
            execution_receipt_id=bad_receipt.receipt_id,
            execution_receipt_sha256=bad_receipt.receipt_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "chain binding"):
            assess_semantic_completion(
                self.catalog,
                self.pack,
                envelope,
                decision,
                authority,
                result.invocation_plan,
                result.reservation_commit,
                result.observation,
                result.settlement,
                bad_receipt,
                result.work_product,
                requirements,
                evidence,
                now=NOW,
            )

    def test_execution_chain_rejects_route_charge_and_time_readdressing(self) -> None:
        execution = self.execution()
        envelope, decision, _, _, authority, result = execution
        requirements = self.requirements(envelope)

        def assess_chain(
            observation,
            settlement,
            receipt,
            invocation_plan=result.invocation_plan,
            reservation_commit=result.reservation_commit,
        ):
            evidence = self.evidence(
                requirements,
                result,
                execution_receipt_id=receipt.receipt_id,
                execution_receipt_sha256=receipt.receipt_sha256,
            )
            return assess_semantic_completion(
                self.catalog,
                self.pack,
                envelope,
                decision,
                authority,
                invocation_plan,
                reservation_commit,
                observation,
                settlement,
                receipt,
                result.work_product,
                requirements,
                evidence,
                now=NOW,
            )

        identity_plan = replace(result.invocation_plan, authority_id="EEA-FORGED")
        identity_commit = replace(
            result.reservation_commit,
            invocation_plan_id=identity_plan.plan_id,
            invocation_plan_sha256=identity_plan.plan_sha256,
        )
        identity_observation = replace(
            result.observation,
            invocation_plan_id=identity_plan.plan_id,
            invocation_plan_sha256=identity_plan.plan_sha256,
        )
        identity_settlement = replace(
            result.settlement,
            reservation_commit_id=identity_commit.commit_id,
            reservation_commit_sha256=identity_commit.commit_sha256,
            provider_observation_id=identity_observation.observation_id,
            provider_observation_sha256=identity_observation.observation_sha256,
        )
        identity_receipt = replace(
            result.receipt,
            invocation_plan_id=identity_plan.plan_id,
            invocation_plan_sha256=identity_plan.plan_sha256,
            reservation_commit_id=identity_commit.commit_id,
            reservation_commit_sha256=identity_commit.commit_sha256,
            provider_observation_id=identity_observation.observation_id,
            provider_observation_sha256=identity_observation.observation_sha256,
            settlement_id=identity_settlement.settlement_id,
            settlement_sha256=identity_settlement.settlement_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "binding substitution"):
            assess_chain(
                identity_observation,
                identity_settlement,
                identity_receipt,
                identity_plan,
                identity_commit,
            )

        product_observation = replace(
            result.observation,
            structured_output_json=self.product_json(envelope, "blocker"),
        )
        product_settlement = replace(
            result.settlement,
            provider_observation_id=product_observation.observation_id,
            provider_observation_sha256=product_observation.observation_sha256,
        )
        product_receipt = replace(
            result.receipt,
            provider_observation_id=product_observation.observation_id,
            provider_observation_sha256=product_observation.observation_sha256,
            settlement_id=product_settlement.settlement_id,
            settlement_sha256=product_settlement.settlement_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "provider output"):
            assess_chain(product_observation, product_settlement, product_receipt)

        route_observation = replace(result.observation, model_version="route-substitution-1")
        route_settlement = replace(
            result.settlement,
            provider_observation_id=route_observation.observation_id,
            provider_observation_sha256=route_observation.observation_sha256,
        )
        route_receipt = replace(
            result.receipt,
            provider_observation_id=route_observation.observation_id,
            provider_observation_sha256=route_observation.observation_sha256,
            settlement_id=route_settlement.settlement_id,
            settlement_sha256=route_settlement.settlement_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "route substitution"):
            assess_chain(route_observation, route_settlement, route_receipt)

        changed_charge = 0 if result.settlement.charged_input_tokens != 0 else 1
        charge_settlement = replace(
            result.settlement,
            charged_input_tokens=changed_charge,
        )
        charge_receipt = replace(
            result.receipt,
            settlement_id=charge_settlement.settlement_id,
            settlement_sha256=charge_settlement.settlement_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "usage provenance|exceeds"):
            assess_chain(result.observation, charge_settlement, charge_receipt)

        full_settlement = replace(
            result.settlement,
            charged_input_tokens=result.reservation_commit.reserved_input_tokens,
            charged_output_tokens=result.reservation_commit.reserved_output_tokens,
            charged_cost_micros=result.reservation_commit.reserved_cost_micros,
            usage_basis="full_reservation",
        )
        full_receipt = replace(
            result.receipt,
            settlement_id=full_settlement.settlement_id,
            settlement_sha256=full_settlement.settlement_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "usage provenance"):
            assess_chain(result.observation, full_settlement, full_receipt)

        time_receipt = replace(result.receipt, recorded_at="2026-09-20T12:09:00Z")
        with self.assertRaisesRegex(SemanticCompletionRetryError, "time ordering"):
            assess_chain(result.observation, result.settlement, time_receipt)

    def test_evidence_is_fresh_independent_exact_and_immutable(self) -> None:
        execution = self.execution()
        envelope, decision, _, _, authority, result = execution
        requirements = self.requirements(envelope)
        original = self.evidence(requirements, result)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "mutable"):
            replace(original, dependency_dispositions=[])
        evidence = self.evidence(
            requirements,
            result,
            verifier_principal_id=authority.requester_principal_id,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "not independent"):
            assess_semantic_completion(
                self.catalog,
                self.pack,
                envelope,
                decision,
                authority,
                result.invocation_plan,
                result.reservation_commit,
                result.observation,
                result.settlement,
                result.receipt,
                result.work_product,
                requirements,
                evidence,
                now=NOW,
            )
        evidence = self.evidence(
            requirements,
            result,
            expires_at="2026-09-20T12:11:00Z",
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "stale"):
            assess_semantic_completion(
                self.catalog,
                self.pack,
                envelope,
                decision,
                authority,
                result.invocation_plan,
                result.reservation_commit,
                result.observation,
                result.settlement,
                result.receipt,
                result.work_product,
                requirements,
                evidence,
                now="2026-09-20T12:11:00Z",
            )

    def test_explicit_retry_authorization_has_no_execution_or_budget_effect(self) -> None:
        fixture = self.retry_fixture()
        execution = fixture[0]
        budget = execution[3]
        receipt = self.authorize(fixture)
        self.assertEqual(receipt.attempt_number, 2)
        self.assertEqual(receipt.to_dict()["effects"]["provider_call"], "none")
        self.assertEqual(receipt.to_dict()["effects"]["budget_mutation"], "none")
        self.assertEqual(budget, execution[3])

    def test_retry_replay_is_one_time_and_concurrent_safe(self) -> None:
        fixture = self.retry_fixture()
        guard = InMemoryRetryReplayGuard()

        def attempt() -> str:
            try:
                self.authorize(fixture, guard)
            except SemanticCompletionRetryError:
                return "blocked"
            return "authorized"

        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(4)))
        self.assertEqual(outcomes.count("authorized"), 1)
        self.assertEqual(outcomes.count("blocked"), 3)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "already consumed"):
            self.authorize(fixture, guard)
        later_identity = replace(
            fixture[-1],
            changed_condition_evidence_sha256=FOUR,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "clock rollback"):
            guard.consume(later_identity, "2026-09-20T12:09:59Z")

    def test_completed_and_indeterminate_retry_are_rejected(self) -> None:
        fixture = self.retry_fixture()
        completed = self.assess(self.execution())[2]
        with self.assertRaisesRegex(SemanticCompletionRetryError, "cannot be retried"):
            self.authorize(fixture, assessment=completed)
        indeterminate = self.assess(self.execution(state="indeterminate"))[2]
        with self.assertRaisesRegex(SemanticCompletionRetryError, "cannot be retried"):
            self.authorize(fixture, assessment=indeterminate)

    def test_retry_rejects_a_content_addressed_assessment_that_contradicts_receipt(self) -> None:
        fixture = self.retry_fixture()
        assessment = fixture[3]
        forged = replace(
            assessment,
            completion_state="failed",
            failure_class="transient_provider",
            reason_codes=("provider_failed",),
            blocker_codes=("provider_failed",),
            retry_eligible=True,
        )
        retry_authority = replace(
            fixture[-1],
            assessment_id=forged.assessment_id,
            assessment_sha256=forged.assessment_sha256,
            prior_failure_class=forged.failure_class,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "contradicts"):
            self.authorize(
                fixture,
                assessment=forged,
                retry_authority=retry_authority,
            )

    def test_retry_authority_separation_time_attempt_and_budget_are_fail_closed(self) -> None:
        fixture = self.retry_fixture()
        retry_authority = fixture[-1]
        with self.assertRaisesRegex(SemanticCompletionRetryError, "not independent"):
            replace(
                retry_authority,
                issuer_principal_id=retry_authority.requester_principal_id,
            )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "not independent"):
            replace(
                retry_authority,
                issuer_principal_id=retry_authority.subject_principal_id,
            )
        execution_issuer = replace(
            retry_authority,
            issuer_principal_id=fixture[6].issuer_principal_id,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "independently separated"):
            self.authorize(fixture, retry_authority=execution_issuer)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "attempt ceiling"):
            replace(retry_authority, attempt_number=4, maximum_attempts=3)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "attempt chain"):
            replace(retry_authority, attempt_number=3)
        future = replace(
            retry_authority,
            issued_at="2026-09-20T12:11:00Z",
            cooldown_until="2026-09-20T12:12:00Z",
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "cooldown|issue time"):
            self.authorize(fixture, retry_authority=future)
        too_small = replace(retry_authority, remaining_cost_micros=1)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "binding substitution"):
            self.authorize(fixture, retry_authority=too_small)
        irrelevant_change = replace(
            retry_authority,
            changed_condition_codes=("route_changed",),
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "prior failure"):
            self.authorize(fixture, retry_authority=irrelevant_change)
        receipt = self.authorize(fixture)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "attempt ceiling"):
            replace(receipt, maximum_attempts=11)

    def test_retry_rejects_arbitrary_replay_guard_before_side_effect(self) -> None:
        fixture = self.retry_fixture()

        class CallerGuard:
            qualifying = False
            durability = "caller_asserted"

            def __init__(self) -> None:
                self.calls = 0

            def consume(self, authority, now):
                self.calls += 1
                return RetryReplayCommit(
                    authority.replay_identity_sha256,
                    authority.retry_authority_id,
                    authority.retry_authority_sha256,
                    now,
                )

        guard = CallerGuard()
        with self.assertRaisesRegex(SemanticCompletionRetryError, "production retry"):
            self.authorize(fixture, guard=guard)
        self.assertEqual(guard.calls, 0)

    def test_later_attempt_requires_prior_replay_custody(self) -> None:
        fixture = self.retry_fixture()
        execution = fixture[0]
        envelope, decision, _, budget, authority, result = execution
        forged_previous = RetryAuthorizationReceipt(
            assessment_id=fixture[3].assessment_id,
            assessment_sha256=fixture[3].assessment_sha256,
            prior_execution_receipt_id=result.receipt.receipt_id,
            prior_execution_receipt_sha256=result.receipt.receipt_sha256,
            retry_authority_id="RAA-FORGED",
            retry_authority_sha256=ZERO,
            replay_identity_sha256=ONE,
            replay_commit_id="RRC-FORGED",
            replay_commit_sha256=TWO,
            new_routing_decision_id=decision.decision_id,
            new_routing_decision_sha256=decision.decision_sha256,
            new_execution_authority_id=authority.authority_id,
            new_execution_authority_sha256=authority.authority_sha256,
            new_execution_envelope_sha256=envelope.envelope_sha256,
            budget_sha256=budget.budget_sha256,
            changed_condition_evidence_sha256=THREE,
            attempt_number=2,
            maximum_attempts=3,
            authorized_at=NOW,
        )
        chained_authority = replace(
            fixture[-1],
            attempt_number=3,
            previous_retry_receipt_id=forged_previous.receipt_id,
            previous_retry_receipt_sha256=forged_previous.receipt_sha256,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "lacks replay custody"):
            self.authorize(
                fixture,
                retry_authority=chained_authority,
                previous_retry_receipt=forged_previous,
            )

    def test_alias_cross_context_and_blind_same_input_retry_are_rejected(self) -> None:
        fixture = self.retry_fixture()
        execution = fixture[0]
        envelope, decision, _, budget, authority, result = execution
        assessment = fixture[3]
        with self.assertRaisesRegex(ValueError, "moving alias"):
            self.base.capability(model_version="latest")
        moving_capability = self.base.capability(model_version="v2.latest")
        moving_decision, _, _ = self.base.route(capability=moving_capability, budget=budget)
        moving_authority = self.base.authority(envelope, moving_decision, moving_capability)
        moving_retry_authority = self.retry_authority(
            assessment,
            envelope,
            decision,
            authority,
            result.receipt,
            envelope,
            moving_decision,
            moving_authority,
            budget,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "moving alias"):
            self.authorize(
                fixture,
                retry_authority=moving_retry_authority,
                new_decision=moving_decision,
                new_capability=moving_capability,
                new_execution_authority=moving_authority,
            )
        other_envelope = self.base.envelope()
        other_envelope = replace(other_envelope, mission_id="mission-other")
        with self.assertRaisesRegex(SemanticCompletionRetryError, "invalid|cross-context"):
            self.authorize(fixture, new_envelope=other_envelope)
        same_route_decision = replace(decision, decided_at="2026-09-20T12:01:00Z")
        same_route_capability = self.base.capability()
        same_route_authority = self.base.authority(
            envelope, same_route_decision, same_route_capability
        )
        same_input_authority = self.retry_authority(
            assessment,
            envelope,
            decision,
            authority,
            result.receipt,
            envelope,
            same_route_decision,
            same_route_authority,
            budget,
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "blind same-input"):
            self.authorize(
                fixture,
                retry_authority=same_input_authority,
                new_decision=same_route_decision,
                new_capability=same_route_capability,
                new_execution_authority=same_route_authority,
            )

    def test_closed_json_schema_unknown_duplicate_and_oversized_records(self) -> None:
        checked = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(checked, semantic_completion_retry_schema())
        Draft202012Validator.check_schema(checked)
        validator = Draft202012Validator(checked)
        fixture = self.retry_fixture()
        requirements, evidence, assessment = fixture[1:4]
        retry_authority = fixture[-1]
        replay_commit = RetryReplayCommit(
            retry_authority.replay_identity_sha256,
            retry_authority.retry_authority_id,
            retry_authority.retry_authority_sha256,
            NOW,
        )
        retry_receipt = self.authorize(fixture)
        records = (
            requirements,
            evidence,
            assessment,
            retry_authority,
            replay_commit,
            retry_receipt,
        )
        for record in records:
            with self.subTest(record=type(record).__name__):
                validator.validate(record.to_dict())
                encoded = canonical_json(record.to_dict())
                self.assertEqual(record, type(record).from_json(encoded))
                extra = {**record.to_dict(), "unexpected": True}
                self.assertTrue(tuple(validator.iter_errors(extra)))
                with self.assertRaises(SemanticCompletionRetryError):
                    type(record).from_dict(extra)
                boolean_version = {**record.to_dict(), "schema_version": True}
                with self.assertRaisesRegex(SemanticCompletionRetryError, "type is invalid"):
                    type(record).from_dict(boolean_version)
                floating_version = {**record.to_dict(), "schema_version": 1.0}
                with self.assertRaisesRegex(SemanticCompletionRetryError, "type is invalid"):
                    type(record).from_dict(floating_version)
        unchained_attempt = {**retry_authority.to_dict(), "attempt_number": 3}
        self.assertTrue(tuple(validator.iter_errors(unchained_attempt)))
        invalid_cooldown = {**retry_authority.to_dict(), "cooldown_until": "not-a-time"}
        self.assertTrue(tuple(validator.iter_errors(invalid_cooldown)))
        duplicate = canonical_json(assessment.to_dict()).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaisesRegex(SemanticCompletionRetryError, "JSON is invalid"):
            SemanticCompletionAssessment.from_json(duplicate)
        with self.assertRaisesRegex(SemanticCompletionRetryError, "byte ceiling"):
            SemanticCompletionAssessment.from_json("x" * (524_288 + 1))

    def test_public_exports_and_phase_file_hygiene(self) -> None:
        import sunderkey

        expected = {
            "InMemoryRetryReplayGuard",
            "RequirementDisposition",
            "RetryAuthorizationAuthority",
            "RetryAuthorizationReceipt",
            "RetryReplayCommit",
            "RetryReplayGuard",
            "SemanticCompletionAssessment",
            "SemanticCompletionEvidence",
            "SemanticCompletionRequirements",
            "SemanticCompletionRetryError",
            "assess_semantic_completion",
            "authorize_retry",
        }
        self.assertTrue(expected.issubset(sunderkey.__all__))
        self.assertTrue(all(hasattr(sunderkey, name) for name in expected))
        markers = (
            "Chat" + "GPT",
            "Generated" + " by",
            "Co-authored" + "-by:",
            "\u2013",
            "\u2014",
        )
        for path in PHASE_FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertTrue(all(marker not in text for marker in markers))
                self.assertFalse(
                    any(
                        unicodedata.category(character) in {"Cf", "Cs"}
                        or (unicodedata.category(character) == "Cc" and character not in "\t\n\r")
                        for character in text
                    )
                )


if __name__ == "__main__":
    unittest.main()
