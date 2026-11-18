from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None
    Registry = None
    Resource = None

from sunderkey.action_admission_contracts import (
    ArtifactBinding,
    ContextBinding,
    CredentialLease,
    TargetBinding,
    TargetEnvironment,
    WorkerSession,
)
from sunderkey.target_health_gate_contracts import (
    TARGET_HEALTH_GATE_RESUME_OPERATION,
    TargetHealthGateClassification,
    TargetHealthGateContractError,
    TargetHealthGateDecision,
    TargetHealthGateDecisionStatus,
    TargetHealthGateHead,
    TargetHealthGateObservation,
    TargetHealthGateRecoveryIntent,
    TargetHealthGateResumption,
    TargetHealthGateState,
    TargetHealthGateTransition,
    TargetHealthGateTransitionKind,
    build_target_health_execution_binding,
    build_target_health_gate_head,
    build_target_health_gate_observation,
    build_target_health_gate_transition,
    canonical_json,
    canonical_sha256,
    execution_binding_sha256,
    parse_target_health_gate_document,
    target_health_gate_inspection_context_sha256,
    target_health_gate_subject,
)
from tests.agents import test_target_health_custody_inspection_phase199 as custody_fixture

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "target_health_gate_contracts.py"
SCHEMA = ROOT / "registry" / "schemas" / "target-health-gate-v1.schema.json"
CUSTODY_SCHEMA = ROOT / "registry" / "schemas" / "target-health-custody-v1.schema.json"
RECEIPT_SCHEMA = (
    ROOT / "registry" / "schemas" / "authorized-target-health-observation-v1.schema.json"
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


class TargetHealthGateContractsPhase199Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = custody_fixture.TargetHealthCustodyInspectionPhase199Tests(
            "test_inspection_returns_exact_current_material_in_one_read_transaction"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.healthy_populated, self.healthy_inspection = self._inspection(
            "healthy", "gate-healthy"
        )
        _, self.adverse_inspection = self._inspection("rejected", "gate-rejected")
        self.healthy_successor_inspection = self._successor_inspection(self.healthy_populated)
        self.healthy_preparation_inspection = self._reinspect(
            self.healthy_populated,
            "2026-09-20T12:00:13Z",
        )
        self.healthy_fresh_inspection = self._reinspect(
            self.healthy_populated,
            "2026-09-20T12:00:14Z",
        )
        self.healthy = build_target_health_gate_observation(
            inspection=self._contextual_inspection(
                self.healthy_inspection,
                sequence=1,
                previous_sha256=None,
            ),
            observation_sequence=1,
            previous_observation_sha256=None,
            evidence_advanced=False,
            recorded_at=self.healthy_inspection.inspected_at,
        )
        self.adverse = build_target_health_gate_observation(
            inspection=self._contextual_inspection(
                self.adverse_inspection,
                sequence=1,
                previous_sha256=None,
            ),
            observation_sequence=1,
            previous_observation_sha256=None,
            evidence_advanced=False,
            recorded_at=self.adverse_inspection.inspected_at,
        )

    def _inspection(self, state: str, name: str):
        populated = self.fixture._populate(
            name,
            receipt=self.fixture._receipt(state),
            clock="2026-09-20T12:00:10Z",
        )
        return populated, self.fixture._inspect(populated)

    def _successor_inspection(self, populated):
        prior = populated.envelope
        observed = datetime.strptime(
            prior.receipt.observed_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC) + timedelta(seconds=1)
        observed_at = observed.strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt = replace(
            prior.receipt,
            observed_at=observed_at,
            monotonic_tick=prior.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = populated.factory.make_envelope(
            populated.policy,
            sequence=2,
            observed_at=observed_at,
            monotonic_tick=receipt.monotonic_tick,
            predecessor=prior,
            receipt=receipt,
        )
        populated.store._trusted_clock.value = datetime.strptime(
            "2026-09-20T12:00:12Z",
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        populated.store.append_envelope(envelope)
        return self.fixture._inspect(populated)

    def _reinspect(self, populated, inspected_at: str):
        populated.store._trusted_clock.value = datetime.strptime(
            inspected_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        return self.fixture._inspect(populated)

    def _gap_successor_inspection(self):
        prior = self.healthy_successor_inspection.envelope
        observed = datetime.strptime(
            prior.receipt.observed_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC) + timedelta(seconds=1)
        observed_at = observed.strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt = replace(
            prior.receipt,
            observed_at=observed_at,
            monotonic_tick=prior.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = self.healthy_populated.factory.make_envelope(
            self.healthy_populated.policy,
            sequence=3,
            observed_at=observed_at,
            monotonic_tick=receipt.monotonic_tick,
            predecessor=prior,
            receipt=receipt,
        )
        self.healthy_populated.store._trusted_clock.value = datetime.strptime(
            "2026-09-20T12:00:15Z",
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        self.healthy_populated.store.append_envelope(envelope)
        return self.fixture._inspect(self.healthy_populated)

    @staticmethod
    def _contextual_inspection(
        inspection,
        *,
        sequence: int,
        previous_sha256: str | None,
    ):
        binding = inspection.envelope.receipt.binding
        return replace(
            inspection,
            inspection_context_sha256=target_health_gate_inspection_context_sha256(
                subject=target_health_gate_subject(binding),
                binding_sha256=execution_binding_sha256(binding),
                observation_sequence=sequence,
                previous_observation_sha256=previous_sha256,
            ),
            inspection_id="",
            inspection_sha256="",
        )

    @staticmethod
    def _next_observation(
        previous: TargetHealthGateObservation,
        *,
        inspection,
        advanced: bool,
    ) -> TargetHealthGateObservation:
        sequence = previous.observation_sequence + 1
        contextual_inspection = TargetHealthGateContractsPhase199Tests._contextual_inspection(
            inspection,
            sequence=sequence,
            previous_sha256=previous.observation_sha256,
        )
        return build_target_health_gate_observation(
            inspection=contextual_inspection,
            observation_sequence=sequence,
            previous_observation_sha256=previous.observation_sha256,
            evidence_advanced=advanced,
            recorded_at=inspection.inspected_at,
        )

    def _recovery_head(
        self,
    ) -> tuple[TargetHealthGateHead, tuple[TargetHealthGateObservation, ...]]:
        initial = build_target_health_gate_transition(
            previous_head=None,
            observation=self.adverse,
        )
        paused = build_target_health_gate_head(
            transition=initial,
            observation=self.adverse,
            resumption=None,
            previous_head=None,
        )
        first = self._next_observation(
            self.adverse,
            inspection=self.healthy_inspection,
            advanced=True,
        )
        started = build_target_health_gate_transition(
            previous_head=paused,
            observation=first,
        )
        recovery_one = build_target_health_gate_head(
            transition=started,
            observation=first,
            resumption=None,
            previous_head=paused,
        )
        second = self._next_observation(
            first,
            inspection=self.healthy_successor_inspection,
            advanced=True,
        )
        advanced = build_target_health_gate_transition(
            previous_head=recovery_one,
            observation=second,
        )
        self.assertEqual(
            advanced.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_ADVANCED,
        )
        recovery_two = build_target_health_gate_head(
            transition=advanced,
            observation=second,
            resumption=None,
            previous_head=recovery_one,
        )
        return recovery_two, (self.adverse, first, second)

    def test_exact_execution_binding_bridge_rejects_cross_context_and_revocation(self) -> None:
        context = ContextBinding(
            tenant_id="tenant:acme",
            mission_id="mission:one",
            scope_id="scope:one",
            scope_sha256=DIGEST_A,
            policy=ArtifactBinding("policy:one", DIGEST_B, "1.0.0"),
        )
        session = WorkerSession(
            worker_id="worker:one",
            worker_profile_id="profile:one",
            session_id="session:one",
            tenant_id=context.tenant_id,
            mission_id=context.mission_id,
            fence_token_sha256=DIGEST_C,
            leader_epoch=7,
            issued_at="2026-09-22T10:00:00Z",
            expires_at="2026-09-22T11:00:00Z",
        )
        lease = CredentialLease(
            lease_id="lease:one",
            credential_ref_sha256=DIGEST_D,
            tenant_id=context.tenant_id,
            mission_id=context.mission_id,
            scope_sha256=context.scope_sha256,
            worker_id=session.worker_id,
            session_id=session.session_id,
            fence_token_sha256=session.fence_token_sha256,
            leader_epoch=session.leader_epoch,
            permitted_action_sha256=DIGEST_A,
            revoked=False,
            issued_at="2026-09-22T10:00:00Z",
            expires_at="2026-09-22T11:00:00Z",
        )
        target = TargetBinding(
            target_id="target:one",
            target_sha256=DIGEST_B,
            authority_sha256=DIGEST_C,
            tenant_id=context.tenant_id,
            mission_id=context.mission_id,
            scope_sha256=context.scope_sha256,
            environment=TargetEnvironment.LIVE,
        )
        binding = build_target_health_execution_binding(
            context=context,
            worker_session=session,
            credential_lease=lease,
            target=target,
        )
        self.assertEqual(binding.context_sha256, canonical_sha256(context.to_dict()))
        self.assertEqual(binding.fence_epoch, session.leader_epoch)
        for changed in (
            replace(lease, tenant_id="tenant:other"),
            replace(lease, mission_id="mission:other"),
            replace(lease, scope_sha256=DIGEST_D),
            replace(lease, worker_id="worker:other"),
            replace(lease, session_id="session:other"),
            replace(lease, fence_token_sha256=DIGEST_D),
            replace(lease, leader_epoch=8),
            replace(lease, revoked=True),
        ):
            with self.subTest(changed=changed), self.assertRaises(TargetHealthGateContractError):
                build_target_health_execution_binding(
                    context=context,
                    worker_session=session,
                    credential_lease=changed,
                    target=target,
                )

    def test_observation_exposes_exact_inspection_lineage_and_nullable_rejection(self) -> None:
        self.assertEqual(self.healthy.classification, TargetHealthGateClassification.HEALTHY)
        self.assertEqual(
            self.healthy.head_binding_id, self.healthy_inspection.head_binding.head_binding_id
        )
        self.assertEqual(self.healthy.chain_id, self.healthy_inspection.chain_id)
        self.assertEqual(self.healthy.envelope_id, self.healthy_inspection.envelope.envelope_id)
        self.assertEqual(self.healthy.receipt_status, "completed")
        self.assertEqual(self.healthy.overall_health, "healthy")
        self.assertEqual(self.adverse.receipt_status, "rejected")
        self.assertIsNone(self.adverse.overall_health)
        self.assertEqual(
            TargetHealthGateObservation.from_dict(self.healthy.to_dict()),
            self.healthy,
        )

    def test_observation_binds_exact_contextual_inspection_position(self) -> None:
        expected_context = target_health_gate_inspection_context_sha256(
            subject=self.healthy.subject,
            binding_sha256=self.healthy.binding_sha256,
            observation_sequence=self.healthy.observation_sequence,
            previous_observation_sha256=self.healthy.previous_observation_sha256,
        )
        self.assertEqual(
            self.healthy.inspection.inspection_context_sha256,
            expected_context,
        )

        substituted = replace(
            self.healthy.inspection,
            inspection_context_sha256=DIGEST_D,
            inspection_id="",
            inspection_sha256="",
        )
        with self.assertRaisesRegex(
            TargetHealthGateContractError,
            "inspection context does not match observation position",
        ):
            build_target_health_gate_observation(
                inspection=substituted,
                observation_sequence=1,
                previous_observation_sha256=None,
                evidence_advanced=False,
                recorded_at=substituted.inspected_at,
            )

    def test_legacy_observation_parses_but_new_builder_requires_context(self) -> None:
        binding = self.healthy_inspection.envelope.receipt.binding
        legacy = TargetHealthGateObservation(
            subject=target_health_gate_subject(binding),
            observation_sequence=1,
            previous_observation_sha256=None,
            binding=binding,
            binding_sha256=execution_binding_sha256(binding),
            inspection=self.healthy_inspection,
            classification=TargetHealthGateClassification.HEALTHY,
            evidence_advanced=False,
            recorded_at=self.healthy_inspection.inspected_at,
        )
        self.assertIsNone(legacy.inspection.inspection_context_sha256)
        self.assertEqual(
            parse_target_health_gate_document(canonical_json(legacy.to_dict())),
            legacy,
        )

        with self.assertRaisesRegex(
            TargetHealthGateContractError,
            "new observation requires an inspection context",
        ):
            build_target_health_gate_observation(
                inspection=self.healthy_inspection,
                observation_sequence=1,
                previous_observation_sha256=None,
                evidence_advanced=False,
                recorded_at=self.healthy_inspection.inspected_at,
            )

    def test_observation_rejects_substitution_and_effect_escalation(self) -> None:
        forged = copy.deepcopy(self.healthy.to_dict())
        forged["binding_sha256"] = DIGEST_D
        with self.assertRaises(TargetHealthGateContractError):
            TargetHealthGateObservation.from_dict(forged)
        forged = copy.deepcopy(self.healthy.to_dict())
        forged["evidence_advanced"] = 1
        with self.assertRaises(TargetHealthGateContractError):
            TargetHealthGateObservation.from_dict(forged)
        forged = copy.deepcopy(self.healthy.to_dict())
        forged["network_call_performed"] = 0
        with self.assertRaises(TargetHealthGateContractError):
            TargetHealthGateObservation.from_dict(forged)

    def test_transition_vocabulary_and_initial_derivation_match_schema35(self) -> None:
        active = build_target_health_gate_transition(
            previous_head=None,
            observation=self.healthy,
        )
        paused = build_target_health_gate_transition(
            previous_head=None,
            observation=self.adverse,
        )
        self.assertEqual(active.transition_kind, TargetHealthGateTransitionKind.INITIALIZED_ACTIVE)
        self.assertEqual((active.to_state, active.pause_epoch), (TargetHealthGateState.ACTIVE, 0))
        self.assertEqual(paused.transition_kind, TargetHealthGateTransitionKind.INITIALIZED_PAUSED)
        self.assertEqual((paused.to_state, paused.pause_epoch), (TargetHealthGateState.PAUSED, 1))
        self.assertEqual(TargetHealthGateTransition.from_dict(active.to_dict()), active)

    def test_head_projection_rejects_substituted_transition_source(self) -> None:
        active = build_target_health_gate_transition(
            previous_head=None,
            observation=self.healthy,
        )
        self.assertEqual(self.healthy.subject, self.adverse.subject)
        with self.assertRaisesRegex(
            TargetHealthGateContractError,
            "head transition does not match its exact source",
        ):
            build_target_health_gate_head(
                transition=active,
                observation=self.adverse,
                resumption=None,
                previous_head=None,
            )

    def test_recovery_never_auto_resumes_and_saturates_at_two(self) -> None:
        head, observations = self._recovery_head()
        self.assertEqual(head.latch_state, TargetHealthGateState.RECOVERY_PENDING)
        self.assertEqual(head.recovery_healthy_count, 2)
        held_observation = self._next_observation(
            observations[-1],
            inspection=self.healthy_inspection,
            advanced=False,
        )
        held = build_target_health_gate_transition(
            previous_head=head,
            observation=held_observation,
        )
        self.assertEqual(held.transition_kind, TargetHealthGateTransitionKind.RECOVERY_HELD)
        self.assertEqual(held.recovery_healthy_count, 2)
        self.assertEqual(held.to_state, TargetHealthGateState.RECOVERY_PENDING)
        with self.assertRaises(TargetHealthGateContractError):
            build_target_health_gate_transition(
                previous_head=head,
                observation=replace(held_observation, evidence_advanced=True),
            )

    def test_transition_rejects_incorrect_evidence_advance_classification(self) -> None:
        with self.assertRaises(TargetHealthGateContractError):
            build_target_health_gate_transition(
                previous_head=None,
                observation=replace(self.healthy, evidence_advanced=True),
            )
        initial = build_target_health_gate_transition(
            previous_head=None,
            observation=self.adverse,
        )
        paused = build_target_health_gate_head(
            transition=initial,
            observation=self.adverse,
            resumption=None,
            previous_head=None,
        )
        recovery = self._next_observation(
            self.adverse,
            inspection=self.healthy_inspection,
            advanced=False,
        )
        with self.assertRaises(TargetHealthGateContractError):
            build_target_health_gate_transition(
                previous_head=paused,
                observation=recovery,
            )

    def test_recovery_advance_requires_strict_chronology_and_allows_gaps(self) -> None:
        initial = build_target_health_gate_transition(
            previous_head=None,
            observation=self.adverse,
        )
        paused = build_target_health_gate_head(
            transition=initial,
            observation=self.adverse,
            resumption=None,
            previous_head=None,
        )
        first = self._next_observation(
            self.adverse,
            inspection=self.healthy_inspection,
            advanced=True,
        )
        started = build_target_health_gate_transition(
            previous_head=paused,
            observation=first,
        )
        recovery_one = build_target_health_gate_head(
            transition=started,
            observation=first,
            resumption=None,
            previous_head=paused,
        )
        successor = self._next_observation(
            first,
            inspection=self.healthy_successor_inspection,
            advanced=True,
        )
        advanced = build_target_health_gate_transition(
            previous_head=recovery_one,
            observation=successor,
        )
        self.assertEqual(
            advanced.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_ADVANCED,
        )
        regressing_heads = (
            replace(
                recovery_one,
                last_global_transition_sequence=successor.global_transition_sequence,
                head_id="",
                head_sha256="",
            ),
            replace(
                recovery_one,
                recovery_observed_at=successor.observed_at,
                head_id="",
                head_sha256="",
            ),
            replace(
                recovery_one,
                recovery_envelope_sequence=successor.envelope_sequence,
                head_id="",
                head_sha256="",
            ),
        )
        for head in regressing_heads:
            with self.subTest(head=head), self.assertRaises(TargetHealthGateContractError):
                build_target_health_gate_transition(
                    previous_head=head,
                    observation=successor,
                )
        gap_inspection = self._gap_successor_inspection()
        gap = self._next_observation(
            first,
            inspection=gap_inspection,
            advanced=True,
        )
        restarted = build_target_health_gate_transition(
            previous_head=recovery_one,
            observation=gap,
        )
        self.assertEqual(
            restarted.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_RESTARTED,
        )

    def test_recovery_intent_contains_no_control_assertion(self) -> None:
        head, observations = self._recovery_head()
        intent = self._intent(head, observations)
        document = intent.to_dict()
        self.assertNotIn("assertion_id", document)
        self.assertNotIn("control_assertion_id", document)
        self.assertEqual(
            intent.qualifying_observation_ids,
            tuple(item.observation_id for item in observations[-2:]),
        )
        self.assertEqual(TargetHealthGateRecoveryIntent.from_dict(document), intent)

    def _intent(
        self,
        head: TargetHealthGateHead,
        observations: tuple[TargetHealthGateObservation, ...],
    ) -> TargetHealthGateRecoveryIntent:
        return TargetHealthGateRecoveryIntent(
            subject=head.subject,
            pause_epoch=head.pause_epoch,
            current_head_id=head.head_id,
            current_head_sha256=head.head_sha256,
            qualifying_observation_ids=tuple(item.observation_id for item in observations[-2:]),
            qualifying_observation_sha256s=tuple(
                item.observation_sha256 for item in observations[-2:]
            ),
            latest_head_binding_sha256=head.last_head_binding_sha256,
            latest_head_binding_id=head.last_head_binding_id,
            global_transition_sequence=head.last_global_transition_sequence,
            current_envelope_id=head.recovery_envelope_id,
            current_envelope_sha256=head.recovery_envelope_sha256,
            current_inspection_id=self.healthy_preparation_inspection.inspection_id,
            current_inspection_sha256=(self.healthy_preparation_inspection.inspection_sha256),
            current_material_sha256=(self.healthy_preparation_inspection.current_material_sha256),
            head_last_inspection_id=head.last_inspection_id,
            head_last_inspection_sha256=head.last_inspection_sha256,
            head_last_current_material_sha256=head.last_current_material_sha256,
            prepared_at=self.healthy_preparation_inspection.inspected_at,
            authority_expires_at="2026-09-20T12:00:50Z",
        )

    def test_resumption_binds_fresh_health_and_exact_operation(self) -> None:
        head, observations = self._recovery_head()
        intent = self._intent(head, observations)
        resumption = TargetHealthGateResumption(
            subject=head.subject,
            pause_epoch=head.pause_epoch,
            recovery_intent=intent,
            qualifying_observation_ids=intent.qualifying_observation_ids,
            qualifying_observation_sha256s=intent.qualifying_observation_sha256s,
            fresh_inspection=self.healthy_fresh_inspection,
            authorization={
                "assertion_id": "assertion:one",
                "assertion_issuer": "issuer:control",
                "assertion_sha256": DIGEST_A,
                "authority_use_sequence": 1,
                "canonical_replay_key_sha256": DIGEST_B,
                "decision": "approved",
                "expires_at": "2026-09-20T12:00:40Z",
                "issued_at": "2026-09-20T12:00:13Z",
                "mission_id": head.subject.mission_id,
                "operation": TARGET_HEALTH_GATE_RESUME_OPERATION,
                "operation_intent_sha256": DIGEST_C,
                "pause_epoch": head.pause_epoch,
                "principal_profile_id": "profile:control",
                "principal_subject": "subject:control",
                "recovery_intent_id": intent.recovery_intent_id,
                "recovery_intent_sha256": intent.recovery_intent_sha256,
                "role": "independent_control",
                "scope_sha256": head.subject.scope_sha256,
                "target_sha256": head.subject.target_sha256,
                "tenant_id": head.subject.tenant_id,
            },
            assertion_issuer="issuer:control",
            assertion_id="assertion:one",
            assertion_sha256=DIGEST_A,
            authority_use_sequence=1,
            canonical_replay_key_sha256=DIGEST_B,
            operation_intent_sha256=DIGEST_C,
            resumed_at=self.healthy_fresh_inspection.inspected_at,
        )
        self.assertEqual(resumption.resume_effect, "permit_health_gate_evaluation")
        self.assertEqual(TargetHealthGateResumption.from_dict(resumption.to_dict()), resumption)
        with self.assertRaises(TargetHealthGateContractError):
            replace(
                resumption,
                authorization={**dict(resumption.authorization), "operation": "wrong.operation"},
            )
        with self.assertRaisesRegex(
            TargetHealthGateContractError,
            "authorization principal is not independent",
        ):
            replace(
                resumption,
                authorization={
                    **dict(resumption.authorization),
                    "principal_subject": resumption.assertion_issuer,
                },
            )
        transition = build_target_health_gate_transition(
            previous_head=head,
            resumption=resumption,
        )
        self.assertEqual(transition.transition_kind, TargetHealthGateTransitionKind.CONTROL_RESUMED)
        self.assertIsNone(transition.observation_id)
        self.assertEqual(transition.resume_effect, "permit_health_gate_evaluation")

    def test_head_projection_has_every_schema35_field_and_count_invariant(self) -> None:
        initial = build_target_health_gate_transition(
            previous_head=None,
            observation=self.healthy,
        )
        head = build_target_health_gate_head(
            transition=initial,
            observation=self.healthy,
            resumption=None,
            previous_head=None,
        )
        expected = {
            "latch_state",
            "pause_epoch",
            "observation_count",
            "observation_head_sha256",
            "transition_count",
            "transition_head_sha256",
            "resumption_count",
            "recovery_healthy_count",
            "recovery_chain_id",
            "recovery_envelope_id",
            "recovery_envelope_sha256",
            "recovery_envelope_sequence",
            "recovery_observed_at",
            "last_observation_id",
            "last_observation_sha256",
            "last_binding_sha256",
            "last_inspection_id",
            "last_inspection_sha256",
            "last_head_binding_id",
            "last_head_binding_sha256",
            "last_global_transition_sequence",
            "last_current_material_sha256",
            "last_adverse_observation_id",
            "last_adverse_observation_sha256",
            "last_resumption_id",
            "last_resumption_sha256",
            "version",
            "updated_at",
        }
        self.assertTrue(expected.issubset(head.to_dict()))
        self.assertEqual(head.transition_count, head.observation_count + head.resumption_count)
        self.assertEqual(TargetHealthGateHead.from_dict(head.to_dict()), head)

    def test_decision_can_only_deny_or_permit_health_gate_evaluation(self) -> None:
        initial = build_target_health_gate_transition(
            previous_head=None,
            observation=self.healthy,
        )
        head = build_target_health_gate_head(
            transition=initial,
            observation=self.healthy,
            resumption=None,
            previous_head=None,
        )
        decision = TargetHealthGateDecision(
            subject=head.subject,
            binding=self.healthy.binding,
            binding_sha256=execution_binding_sha256(self.healthy.binding),
            head=head,
            current_observation=self.healthy,
            evaluated_at=self.healthy.inspected_at,
            status=TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION,
            reason="health_gate_current",
            pause_effect="none",
            resume_effect="none",
        )
        self.assertEqual(decision.to_dict()["authority_effect"], "none")
        with self.assertRaises(TargetHealthGateContractError):
            replace(decision, status=TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK)

    def test_parser_is_canonical_closed_and_identity_checked(self) -> None:
        document = canonical_json(self.healthy.to_dict())
        self.assertEqual(parse_target_health_gate_document(document), self.healthy)
        with self.assertRaises(TargetHealthGateContractError):
            parse_target_health_gate_document(json.dumps(self.healthy.to_dict(), indent=2))
        forged = copy.deepcopy(self.healthy.to_dict())
        forged["unexpected"] = True
        with self.assertRaises(TargetHealthGateContractError):
            parse_target_health_gate_document(canonical_json(forged))
        forged = copy.deepcopy(self.healthy.to_dict())
        forged["observation_id"] = "THGO-" + "F" * 32
        with self.assertRaises(TargetHealthGateContractError):
            parse_target_health_gate_document(canonical_json(forged))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_records_and_rejects_bool_integer_confusion(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        custody = json.loads(CUSTODY_SCHEMA.read_text(encoding="utf-8"))
        receipt = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
        registry = Registry().with_resources(
            [
                (custody["$id"], Resource.from_contents(custody)),
                (receipt["$id"], Resource.from_contents(receipt)),
            ]
        )
        validator = Draft202012Validator(schema, registry=registry)
        transition = build_target_health_gate_transition(
            previous_head=None,
            observation=self.healthy,
        )
        head = build_target_health_gate_head(
            transition=transition,
            observation=self.healthy,
            resumption=None,
            previous_head=None,
        )
        for record in (self.healthy.subject, self.healthy, transition, head):
            with self.subTest(record=type(record).__name__):
                self.assertEqual(list(validator.iter_errors(record.to_dict())), [])
        for field, value in (
            ("schema_version", True),
            ("network_call_performed", 0),
            ("target_effect_performed", 1),
        ):
            forged = copy.deepcopy(self.healthy.to_dict())
            forged[field] = value
            self.assertTrue(list(validator.iter_errors(forged)))

    def test_owned_files_have_no_prohibited_markers_or_dash_characters(self) -> None:
        for path in (MODULE, SCHEMA):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)
            self.assertNotIn("generated" + " by", text.lower())
            self.assertNotIn("co-authored" + "-by", text.lower())


if __name__ == "__main__":
    unittest.main()
