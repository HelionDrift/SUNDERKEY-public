"""MissionStore target-health gate service tests."""

from __future__ import annotations

import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.authorized_target_health_runtime import (
    HealthSignalState,
    TargetHealthReceipt,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    TrustKeyUse,
    compute_operation_intent_hash,
)
from sunderkey.mission_store_target_health_gate import (
    MissionStoreTargetHealthGateService,
    TargetHealthGateObservationResult,
    TargetHealthGateResumptionResult,
    TargetHealthGateStoreVerificationReport,
    verify_target_health_gate_store,
)
from sunderkey.store import canonical_json, principal_assertion_entry_hash, sha256_text
from sunderkey.target_health_custody import (
    SQLiteTargetHealthCustody,
    TargetHealthCustodyBusyError,
    TargetHealthCustodyConflictError,
    TargetHealthCustodyIntegrityError,
    TargetHealthCustodyNotFoundError,
)
from sunderkey.target_health_custody_contracts import execution_binding_sha256
from sunderkey.target_health_gate_contracts import (
    TARGET_HEALTH_GATE_RESUME_OPERATION,
    TargetHealthGateDecisionStatus,
    TargetHealthGateState,
    TargetHealthGateTransitionKind,
    canonical_sha256,
)

from . import test_authorized_target_health_runtime_phase175 as phase175
from . import test_mission_store_action_admission_phase195b as phase195b
from . import test_target_health_custody_phase198 as phase198

NO_EFFECTS = {
    "authority_effect": "none",
    "budget_effect": "none",
    "credential_effect": "none",
    "dispatch_effect": "none",
    "network_call_performed": False,
    "qualification_effect": "none",
    "scope_effect": "none",
    "target_effect_performed": False,
    "tier_effect": "none",
}


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rebound_receipt(
    binding,  # type: ignore[no-untyped-def]
    *,
    state: str,
) -> TargetHealthReceipt:
    """Build the real Phase 175 receipt graph around one exact mission binding."""

    fixture = phase175.AuthorizedTargetHealthRuntimePhase175Tests(methodName="runTest")
    fixture.setUp()
    fixture.binding = binding
    fixture.policy = replace(
        fixture.policy,
        binding=binding,
        policy_id="",
        policy_sha256="",
    )
    fixture.request = replace(
        fixture.request,
        binding=binding,
        payload_sha256=fixture.policy.policy_sha256,
        payload_size_bytes=len(canonical_json(fixture.policy.to_dict()).encode("ascii")),
        request_id="",
        request_sha256="",
    )
    fixture.admission = replace(
        fixture.admission,
        request_id=fixture.request.request_id,
        request_sha256=fixture.request.request_sha256,
        receipt_id="",
        receipt_sha256="",
    )
    binding_sha256 = execution_binding_sha256(binding)
    fixture.safety = replace(
        fixture.safety,
        binding_sha256=binding_sha256,
        execution_request_sha256=fixture.request.request_sha256,
        attestation_sha256="",
    )
    fixture.budget = replace(
        fixture.budget,
        binding_sha256=binding_sha256,
        execution_request_sha256=fixture.request.request_sha256,
        state_id="",
        state_sha256="",
    )
    fixture.http_receipt = fixture.make_http_receipt()
    fixture.browser_receipt = fixture.make_browser_receipt()
    fixture.session_receipt = fixture.make_session_receipt()
    fixture.receipts = (
        fixture.http_receipt,
        fixture.browser_receipt,
        fixture.session_receipt,
    )
    fixture.observations = fixture.make_observations()
    if state == "healthy":
        return fixture.observe()
    if state == "degraded":
        return fixture.observe(
            observations=fixture.make_observations(
                latency=250,
                latency_state=HealthSignalState.DEGRADED,
                latency_detail="above_healthy_latency_threshold",
            )
        )
    if state == "rejected":
        return fixture.observe(safety_snapshot=None)
    raise AssertionError(f"unsupported health state: {state}")


class MissionStoreTargetHealthGatePhase199Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def setUp(self) -> None:
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

        source = phase175.AuthorizedTargetHealthRuntimePhase175Tests(methodName="runTest")
        source.setUp()
        self.binding = replace(source.binding, context_id=fixture.mission_id)
        self.healthy_receipt = _rebound_receipt(self.binding, state="healthy")
        self.adverse_receipt = _rebound_receipt(self.binding, state="rejected")

        self.now = _parse_time("2026-09-20T12:00:10Z")
        fixture.root.now = self.now
        self.custody_clock = phase198.FixedClock(_format_time(self.now))
        self.custody_factory = phase198.ContractFactory(mission_id=fixture.mission_id)
        self.custody_factory.binding = self.binding
        self.custody_factory.binding_sha256 = execution_binding_sha256(self.binding)
        self.custody_factory.root = replace(
            self.custody_factory.root,
            effective_at="2026-09-19T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        self.custody = SQLiteTargetHealthCustody(
            fixture.root.directory / "phase199c-target-health.sqlite3",
            trust_root=self.custody_factory.root,
            trusted_clock=self.custody_clock,
        )
        self.policy = self.custody_factory.make_policy(
            issued_at="2026-09-19T10:59:00Z",
            effective_at="2026-09-19T11:00:00Z",
            expires_at="2026-09-20T18:00:00Z",
            runtime_policy_id=self.healthy_receipt.runtime_policy_id,
            runtime_policy_sha256=self.healthy_receipt.runtime_policy_sha256,
        )
        self.custody.publish_policy(self.policy)
        self.current_envelope = self.custody_factory.make_envelope(
            self.policy,
            sequence=1,
            observed_at=self.healthy_receipt.observed_at,
            monotonic_tick=self.healthy_receipt.monotonic_tick,
            receipt=self.healthy_receipt,
        )
        self.custody.append_envelope(self.current_envelope)
        self._install_resume_authority()
        self.service = MissionStoreTargetHealthGateService(
            fixture.store,
            self.custody,
            fixture.registry,
            clock=lambda: fixture.root.now,
        )
        self.service.initialize()

    def _set_now(self, value: str) -> None:
        self.now = _parse_time(value)
        self.fixture.root.now = self.now
        self.custody_clock.value = self.now

    def _tick(self, seconds: int = 1) -> str:
        self.now += timedelta(seconds=seconds)
        self.fixture.root.now = self.now
        self.custody_clock.value = self.now
        return _format_time(self.now)

    def _install_resume_authority(self) -> None:
        document = self.fixture.policy.to_dict()
        operation = PrincipalOperation.TARGET_HEALTH_GATE_RESUME.value
        document.update(
            {
                "policy_version": self.fixture.policy.policy_version + 1,
                "issued_at": "2026-09-19T09:00:00Z",
                "not_before": "2026-09-19T09:00:00Z",
                "expires_at": "2026-09-20T14:00:00Z",
            }
        )
        document["allowed_operations"] = sorted(
            {*document["allowed_operations"], operation}
        )
        for key in document["keys"]:
            key["not_before"] = "2026-09-19T09:00:00Z"
            key["not_after"] = "2026-09-20T14:00:00Z"
            key["allowed_operations"] = sorted(
                {*key["allowed_operations"], operation}
            )
        assertion_template = next(
            key
            for key in document["keys"]
            if key["key_use"] == TrustKeyUse.PRINCIPAL_ASSERTION.value
        )
        self.equal_issuer_private = Ed25519PrivateKey.generate()
        equal_issuer_key = {
            **assertion_template,
            "key_id": "principal-key:phase199c-equal-issuer",
            "issuer": phase195b.CONTROL_REVIEW_SUBJECT,
            "public_key": phase195b.b64url(
                phase195b.public_bytes(self.equal_issuer_private)
            ),
            "allowed_profiles": [self.fixture.control_profile],
            "allowed_subjects": [phase195b.CONTROL_REVIEW_SUBJECT],
            "allowed_operations": [operation],
        }
        document["keys"].append(equal_issuer_key)
        document["keys"] = sorted(document["keys"], key=lambda value: value["key_id"])
        unsigned = PrincipalTrustPolicy.from_dict(document)
        policy = replace(
            unsigned,
            signature=phase195b.b64url(
                self.fixture.factory.root_private.sign(unsigned.signing_bytes())
            ),
        )
        self.fixture.root.trust.apply_policy(policy)
        self.fixture.policy = policy
        self.fixture.policy_version = policy.policy_version
        def grant(
            marker: str,
            profile_id: str,
            subject: str,
            operations: list[str],
        ):  # type: ignore[no-untyped-def]
            value = self.fixture.factory.grant(
                grant_id="SGR-" + marker * 16,
                profile_id=profile_id,
                subject=subject,
                store_id=self.fixture.root.store_id,
                mission_id=self.fixture.mission_id,
                mission_context_hash=self.fixture.root.stored.context_hash,
                scope_reference=self.fixture.mission.scope_reference,
                scope_document_hash=self.fixture.mission.scope_document_hash,
                environment=self.fixture.mission.environment.value,
                max_action_tier=self.fixture.mission.max_action_tier.value,
                constraints_hash=sha256_text(
                    canonical_json(self.fixture.mission.to_dict()["constraints"])
                ),
                operations=operations,
                issued_at="2026-09-20T11:55:00Z",
                not_before="2026-09-20T11:55:00Z",
                expires_at="2026-09-20T12:55:00Z",
                policy_version=policy.policy_version,
            )
            self.fixture.acceptance.accept(value)
            return value

        self.fixture.grants["health_control"] = grant(
            "97",
            self.fixture.control_profile,
            phase195b.CONTROL_REVIEW_SUBJECT,
            [operation],
        )
        self.fixture.grants["health_noncontrol"] = grant(
            "95",
            self.fixture.owner_profile,
            phase195b.SUBJECT,
            [operation],
        )
        owner_grant = grant(
            "A3",
            self.fixture.owner_profile,
            phase195b.SUBJECT,
            [PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value],
        )
        control_grant = grant(
            "A4",
            self.fixture.control_profile,
            phase195b.CONTROL_REVIEW_SUBJECT,
            [PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value],
        )
        self._install_current_control_policy(owner_grant, control_grant)

    def _install_current_control_policy(
        self, owner_grant, control_grant
    ) -> None:  # type: ignore[no-untyped-def]
        with self.fixture.store._read_connection() as connection:
            row = connection.execute(
                "SELECT policy_json FROM collaboration_mission_policy_commits "
                "WHERE mission_id=? ORDER BY policy_version DESC LIMIT 1",
                (self.fixture.mission_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        previous = phase195b.json.loads(row["policy_json"])

        def build(owner_binding, control_binding):  # type: ignore[no-untyped-def]
            selected = previous["selected_parameters"]
            return phase195b.build_collaboration_mission_reconfiguration_policy(
                authority_policy=self.fixture.root.authority,
                policy_version=previous["policy_version"] + 1,
                previous_policy_sha256=previous["policy_sha256"],
                mission_id=self.fixture.mission_id,
                collaboration_plan_id=self.fixture.plan.plan_id,
                collaboration_plan_sha256=self.fixture.plan.content_sha256,
                maximum_delegation_depth=selected["maximum_delegation_depth"],
                reconfiguration_validity_seconds=selected[
                    "reconfiguration_validity_seconds"
                ],
                execution_ack_timeout_seconds=selected[
                    "execution_ack_timeout_seconds"
                ],
                maximum_plan_replacement_items=selected[
                    "maximum_plan_replacement_items"
                ],
                transition_activation=previous["transition_activation"],
                mission_owner_approval=owner_binding,
                independent_control_approval=control_binding,
                effective_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T12:50:00Z",
            )

        def placeholder(profile_id: str, marker: str) -> dict[str, str]:
            return {
                "profile_id": profile_id,
                "assertion_id": "PAS-" + marker * 16,
                "assertion_sha256": "sha256:" + marker[0].lower() * 64,
            }

        provisional = build(
            placeholder(self.fixture.owner_profile, "A5"),
            placeholder(self.fixture.control_profile, "A6"),
        )
        selection = phase195b.collaboration_mission_reconfiguration_selection_sha256(
            provisional
        )

        def assertion(grant_value, marker, operation):  # type: ignore[no-untyped-def]
            return self.fixture.factory.assertion(
                grant=grant_value,
                assertion_id="PAS-" + marker * 16,
                policy_version=self.fixture.policy_version,
                scope_grant_id=grant_value.grant_id,
                subject=grant_value.subject,
                profile_id=grant_value.profile_id,
                audience=phase195b.AUDIENCE,
                store_id=self.fixture.root.store_id,
                mission_id=self.fixture.mission_id,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(
                    operation,
                    {
                        "mission_id": self.fixture.mission_id,
                        "policy_selection_sha256": selection,
                        "principal_profile_id": grant_value.profile_id,
                    },
                ),
                issued_at="2026-09-20T12:00:00Z",
                not_before="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T12:20:00Z",
            )

        owner = assertion(
            owner_grant,
            "A5",
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        control = assertion(
            control_grant,
            "A6",
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )

        def binding(value: PrincipalAssertion) -> dict[str, str]:
            return {
                "profile_id": value.profile_id,
                "assertion_id": value.assertion_id,
                "assertion_sha256": value.content_sha256,
            }

        phase195b.AuthenticatedCollaborationMissionPolicyService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.root.now,
        ).commit(
            build(binding(owner), binding(control)),
            authority_policy=self.fixture.root.authority,
            mission_owner_assertion=owner,
            independent_control_assertion=control,
        )

    def _assertion(
        self,
        intent,  # type: ignore[no-untyped-def]
        replay_key: str,
        *,
        marker: str = "98",
        grant_name: str = "health_control",
        issued_at: str = "2026-09-20T12:00:00Z",
        expires_at: str = "2026-09-20T12:10:00Z",
    ) -> PrincipalAssertion:
        return self.fixture._assertion(
            grant_name,
            marker,
            PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
            {
                "idempotency_key_sha256": replay_key,
                "mission_id": self.fixture.mission_id,
                "principal_profile_id": self.fixture.grants[grant_name].profile_id,
                "recovery_intent_sha256": intent.recovery_intent_sha256,
                "role": "independent_control",
            },
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=expires_at,
        )

    def _append(self, state: str = "healthy", *, observe: bool = True):
        observed_at = self._tick()
        template = self.healthy_receipt if state == "healthy" else self.adverse_receipt
        receipt = replace(
            template,
            observed_at=observed_at,
            monotonic_tick=self.current_envelope.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = self.custody_factory.make_envelope(
            self.policy,
            sequence=self.current_envelope.sequence + 1,
            observed_at=receipt.observed_at,
            monotonic_tick=receipt.monotonic_tick,
            predecessor=self.current_envelope,
            receipt=receipt,
        )
        self.custody.append_envelope(envelope)
        self.current_envelope = envelope
        return self.service.observe_current(self.binding) if observe else envelope

    def _pause(self):  # type: ignore[no-untyped-def]
        if self.service.load_head(self.binding) is not None:
            self._tick()
        self.service.observe_current(self.binding)
        result = self._append("rejected")
        self.assertEqual(result.head.latch_state, TargetHealthGateState.PAUSED)
        return result

    def _recover_two(self):  # type: ignore[no-untyped-def]
        self._pause()
        first = self._append("healthy")
        second = self._append("healthy")
        self.assertEqual(
            first.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_STARTED,
        )
        self.assertEqual(
            second.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_ADVANCED,
        )
        return first, second

    def _prepare(self):  # type: ignore[no-untyped-def]
        self._recover_two()
        self._tick()
        return self.service.prepare_recovery(self.binding)

    def _gate_counts(self) -> tuple[int, int, int, int]:
        with self.fixture.store._read_connection() as connection:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "target_health_gate_observations",
                    "target_health_gate_resumptions",
                    "target_health_gate_transitions",
                    "target_health_gate_heads",
                )
            )

    def _resume(
        self, intent=None, *, replay_key=None, assertion=None
    ):  # type: ignore[no-untyped-def]
        intent = intent or self._prepare()
        replay_key = replay_key or canonical_sha256({"phase199c": "resume"})
        assertion = assertion or self._assertion(intent, replay_key)
        self._tick()
        return self.service.resume(
            assertion,
            intent,
            canonical_replay_key_sha256=replay_key,
        )

    def test_initialize_is_idempotent_and_result_records_are_immutable(self) -> None:
        self.service.initialize()
        result = self.service.observe_current(self.binding)
        self.assertIs(type(result), TargetHealthGateObservationResult)
        self.assertEqual(result.head.latch_state, TargetHealthGateState.ACTIVE)
        self.assertEqual(
            result.transition.transition_kind,
            TargetHealthGateTransitionKind.INITIALIZED_ACTIVE,
        )
        self.assertEqual(
            result.decision.status,
            TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION,
        )
        with self.assertRaises(FrozenInstanceError):
            result.head = result.head  # type: ignore[misc]

        restarted = MissionStoreTargetHealthGateService(
            self.fixture.store,
            self.custody,
            self.fixture.registry,
            clock=lambda: self.fixture.root.now,
        )
        restarted.initialize()
        self._tick()
        replay = restarted.observe_current(self.binding)
        self.assertEqual(replay.observation.observation_sequence, 2)
        self.assertEqual(
            replay.transition.transition_kind,
            TargetHealthGateTransitionKind.ACTIVE_HEALTH_CONFIRMED,
        )
        self.assertEqual(replay.head.observation_count, 2)
        self.assertEqual(restarted.load_head(self.binding), replay.head)

    def test_adverse_health_commits_pause_before_returning_denial(self) -> None:
        active = self.service.observe_current(self.binding)
        result = self._append("rejected")
        self.assertEqual(active.head.latch_state, TargetHealthGateState.ACTIVE)
        self.assertEqual(
            result.transition.transition_kind,
            TargetHealthGateTransitionKind.PAUSE_ASSERTED,
        )
        self.assertEqual(result.head.latch_state, TargetHealthGateState.PAUSED)
        self.assertEqual(result.head.pause_epoch, 1)
        self.assertEqual(
            result.decision.status,
            TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK,
        )
        self.assertEqual(self.service.load_head(self.binding), result.head)
        self.assertEqual(self.service.verify_store().paused_count, 1)

    def test_observation_uses_the_final_fresh_inspection(self) -> None:
        original = self.custody.inspect_unique_current_binding_head
        calls = 0

        def change_before_final(**arguments):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls == 2:
                self._append("rejected", observe=False)
            return original(**arguments)

        with mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            side_effect=change_before_final,
        ):
            result = self.service.observe_current(self.binding)
        self.assertEqual(calls, 2)
        self.assertEqual(
            result.transition.transition_kind,
            TargetHealthGateTransitionKind.INITIALIZED_PAUSED,
        )
        self.assertEqual(result.head.latch_state, TargetHealthGateState.PAUSED)
        self.assertEqual(
            result.decision.status,
            TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK,
        )

    def test_transaction_observation_uses_two_inspections_without_nested_writer(
        self,
    ) -> None:
        original = self.custody.inspect_unique_current_binding_head
        calls = 0

        def counted_inspection(**arguments):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            return original(**arguments)

        with mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            side_effect=counted_inspection,
        ), mock.patch(
            "sunderkey.mission_store_target_health_gate."
            "verify_target_health_gate_store",
            wraps=verify_target_health_gate_store,
        ) as historical_verifier, self.fixture.store._write_connection() as connection:
            result = self.service.observe_current_in_transaction(
                connection,
                self.binding,
            )
            self.assertTrue(connection.in_transaction)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM target_health_gate_observations"
                ).fetchone()[0],
                1,
            )

        self.assertEqual(calls, 2)
        self.assertEqual(historical_verifier.call_count, 2)
        self.assertEqual(
            result.decision.status,
            TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION,
        )
        self.assertEqual(self._gate_counts(), (1, 0, 1, 1))

    def test_transaction_observation_returns_adverse_denial_for_outer_commit(self) -> None:
        self.service.observe_current(self.binding)
        self._append("rejected", observe=False)

        with self.fixture.store._write_connection() as connection:
            result = self.service.observe_current_in_transaction(
                connection,
                self.binding,
            )
            self.assertEqual(
                result.decision.status,
                TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK,
            )
            self.assertEqual(result.head.latch_state, TargetHealthGateState.PAUSED)

        self.assertEqual(self.service.load_head(self.binding), result.head)
        self.assertEqual(self.service.verify_store().paused_count, 1)

    def test_transaction_observation_rejects_unowned_or_inactive_connection(self) -> None:
        inactive = sqlite3.connect(self.fixture.store.path)
        foreign = sqlite3.connect(self.fixture.root.directory / "phase199d-foreign.sqlite3")
        try:
            with self.assertRaisesRegex(StoreError, "active MissionStore transaction"):
                self.service.observe_current_in_transaction(inactive, self.binding)

            foreign.execute("BEGIN")
            with self.assertRaisesRegex(StoreError, "owned MissionStore transaction"):
                self.service.observe_current_in_transaction(foreign, self.binding)
        finally:
            inactive.close()
            foreign.rollback()
            foreign.close()
        self.assertEqual(self._gate_counts(), (0, 0, 0, 0))

    def test_transaction_observation_rejects_read_only_store_connection(self) -> None:
        read_only = sqlite3.connect(
            self.fixture.store.path.as_uri() + "?mode=ro",
            isolation_level=None,
            uri=True,
        )
        try:
            read_only.execute("BEGIN")
            with self.assertRaisesRegex(StoreError, "writable MissionStore transaction"):
                self.service.observe_current_in_transaction(read_only, self.binding)
        finally:
            read_only.rollback()
            read_only.close()
        self.assertEqual(self._gate_counts(), (0, 0, 0, 0))

    def test_transaction_observation_respects_outer_rollback(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "phase199d outer rollback",
        ), self.fixture.store._write_connection() as connection:
            result = self.service.observe_current_in_transaction(
                connection,
                self.binding,
            )
            self.assertEqual(
                result.decision.status,
                TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION,
            )
            raise RuntimeError("phase199d outer rollback")
        self.assertEqual(self._gate_counts(), (0, 0, 0, 0))

    def test_recovery_start_advance_hold_restart_and_reset(self) -> None:
        self._pause()
        started = self._append("healthy")
        self._tick()
        held = self.service.observe_current(self.binding)
        self.assertEqual(started.head.recovery_healthy_count, 1)
        self.assertEqual(
            held.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_HELD,
        )
        self.assertEqual(held.head.recovery_healthy_count, 1)

        self._append("healthy", observe=False)
        self._append("healthy", observe=False)
        restarted = self.service.observe_current(self.binding)
        self.assertEqual(
            restarted.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_RESTARTED,
        )
        self.assertEqual(restarted.head.recovery_healthy_count, 1)
        advanced = self._append("healthy")
        self.assertEqual(
            advanced.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_ADVANCED,
        )
        self.assertEqual(advanced.head.recovery_healthy_count, 2)
        reset = self._append("rejected")
        self.assertEqual(
            reset.transition.transition_kind,
            TargetHealthGateTransitionKind.RECOVERY_RESET,
        )
        self.assertEqual(reset.head.latch_state, TargetHealthGateState.PAUSED)
        self.assertEqual(reset.head.recovery_healthy_count, 0)

    def test_prepare_recovery_is_read_only_and_binds_a_fresh_inspection(self) -> None:
        _, recovered = self._recover_two()
        before = self._gate_counts()
        self._tick()
        intent = self.service.prepare_recovery(self.binding)
        self.assertEqual(self._gate_counts(), before)
        self.assertEqual(intent.current_head_id, recovered.head.head_id)
        self.assertEqual(intent.current_head_sha256, recovered.head.head_sha256)
        self.assertNotEqual(intent.current_inspection_id, recovered.head.last_inspection_id)
        self.assertEqual(intent.pause_effect, "deny_new_target_work")
        self.assertEqual(intent.resume_effect, "permit_health_gate_evaluation")

    def test_resume_uses_final_fresh_inspection_and_rejects_exact_replay(self) -> None:
        intent = self._prepare()
        replay_key = canonical_sha256({"phase199c": "resume-replay"})
        assertion = self._assertion(intent, replay_key)
        self._tick()
        with mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            wraps=self.custody.inspect_unique_current_binding_head,
        ) as inspect_current:
            result = self.service.resume(
                assertion,
                intent,
                canonical_replay_key_sha256=replay_key,
            )
        self.assertIs(type(result), TargetHealthGateResumptionResult)
        self.assertEqual(inspect_current.call_count, 1)
        self.assertEqual(result.head.latch_state, TargetHealthGateState.ACTIVE)
        self.assertEqual(
            result.transition.transition_kind,
            TargetHealthGateTransitionKind.CONTROL_RESUMED,
        )
        self.assertEqual(result.resumption.resume_effect, "permit_health_gate_evaluation")
        counts = self._gate_counts()
        with self.assertRaises(StoreConflictError):
            self.service.resume(
                assertion,
                intent,
                canonical_replay_key_sha256=replay_key,
            )
        self.assertEqual(self._gate_counts(), counts)
        with self.fixture.store._read_connection() as connection:
            use = connection.execute(
                "SELECT * FROM principal_assertion_uses WHERE assertion_id=?",
                (assertion.assertion_id,),
            ).fetchone()
            effect = connection.execute(
                "SELECT * FROM principal_assertion_effects WHERE assertion_id=?",
                (assertion.assertion_id,),
            ).fetchone()
        self.assertEqual(use["operation"], TARGET_HEALTH_GATE_RESUME_OPERATION)
        self.assertEqual(use["idempotency_key_hash"], replay_key)
        self.assertEqual(effect["effect_kind"], TARGET_HEALTH_GATE_RESUME_OPERATION)
        self.assertEqual(effect["effect_id"], result.resumption.resumption_id)

    def test_historical_resumption_cannot_override_a_later_adverse_pause(self) -> None:
        intent = self._prepare()
        replay_key = canonical_sha256({"phase199c": "stale-resumption"})
        assertion = self._assertion(intent, replay_key)
        self._tick()
        resumed = self.service.resume(
            assertion,
            intent,
            canonical_replay_key_sha256=replay_key,
        )
        self.assertEqual(resumed.head.latch_state, TargetHealthGateState.ACTIVE)

        paused = self._append("rejected")
        self.assertEqual(paused.head.latch_state, TargetHealthGateState.PAUSED)
        counts = self._gate_counts()
        with self.assertRaises(StoreConflictError):
            self.service.resume(
                assertion,
                intent,
                canonical_replay_key_sha256=replay_key,
            )
        self.assertEqual(self._gate_counts(), counts)
        self.assertEqual(self.service.load_head(self.binding), paused.head)

    def test_resume_rejects_wrong_role_expiry_issuer_and_replay_atomically(self) -> None:
        intent = self._prepare()
        replay_key = canonical_sha256({"phase199c": "resume-adverse"})
        good = self._assertion(intent, replay_key)
        baseline = self._gate_counts()

        wrong_role = self._assertion(
            intent,
            replay_key,
            marker="95",
            grant_name="health_noncontrol",
        )
        expired = self._assertion(
            intent,
            replay_key,
            marker="96",
            issued_at="2026-09-20T11:50:00Z",
            expires_at="2026-09-20T11:59:59Z",
        )
        equal_document = good.to_dict()
        equal_document.update(
            {
                "issuer": phase195b.CONTROL_REVIEW_SUBJECT,
                "key_id": "principal-key:phase199c-equal-issuer",
            }
        )
        unsigned = PrincipalAssertion.from_dict(equal_document)
        equal_issuer = replace(
            unsigned,
            signature=phase195b.b64url(
                self.equal_issuer_private.sign(unsigned.signing_bytes())
            ),
        )
        for label, assertion in (
            ("role", wrong_role),
            ("expired", expired),
            ("issuer", equal_issuer),
        ):
            self._tick()
            with self.subTest(label=label), self.assertRaises(PrincipalAuthenticationError):
                self.service.resume(
                    assertion,
                    intent,
                    canonical_replay_key_sha256=replay_key,
                )
            self.assertEqual(self._gate_counts(), baseline)

        result = self._resume(intent, replay_key=replay_key, assertion=good)
        replay_assertion = self._assertion(intent, replay_key, marker="94")
        with self.assertRaises(StoreConflictError):
            self.service.resume(
                replay_assertion,
                intent,
                canonical_replay_key_sha256=replay_key,
            )
        self.assertEqual(self.service.load_head(self.binding), result.head)

    def test_missing_stale_busy_unavailable_and_tampered_custody_never_mutate(self) -> None:
        baseline = self._gate_counts()
        missing = replace(self.binding, target_id="target:missing")
        with self.assertRaises(TargetHealthCustodyNotFoundError):
            self.service.observe_current(missing)
        self.assertEqual(self._gate_counts(), baseline)

        for error in (
            TargetHealthCustodyBusyError("custody busy"),
            TargetHealthCustodyIntegrityError("custody unavailable"),
            TargetHealthCustodyIntegrityError("custody tampered"),
            TargetHealthCustodyConflictError("custody stale"),
        ):
            with self.subTest(error=str(error)), mock.patch.object(
                self.custody,
                "inspect_unique_current_binding_head",
                side_effect=error,
            ), self.assertRaises(type(error)):
                self.service.observe_current(self.binding)
            self.assertEqual(self._gate_counts(), baseline)

        self._set_now("2026-09-20T18:00:01Z")
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.service.observe_current(self.binding)
        self.assertEqual(self._gate_counts(), baseline)

    def test_actual_custody_tamper_is_rejected_without_gate_rows(self) -> None:
        phase198.TargetHealthCustodyPhase198Tests.rewrite_with_triggers_restored(
            self.custody.path,
            ("target_health_envelopes",),
            lambda connection: connection.execute(
                "UPDATE target_health_envelopes SET envelope_json='{}'"
            ),
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.service.observe_current(self.binding)
        self.assertEqual(self._gate_counts(), (0, 0, 0, 0))

    def test_subject_and_source_substitution_fail_before_mutation(self) -> None:
        inspection = self.custody.inspect_unique_current_binding_head(
            tenant_id=self.binding.tenant_id,
            mission_id=self.binding.context_id,
            binding_sha256=execution_binding_sha256(self.binding),
        )
        baseline = self._gate_counts()
        substitutions = (
            replace(self.binding, target_id="target:substituted"),
            replace(self.binding, target_sha256="sha256:" + "e" * 64),
            replace(self.binding, context_id="MISSION-SUBSTITUTED"),
        )
        for binding in substitutions:
            with self.subTest(binding=binding), mock.patch.object(
                self.custody,
                "inspect_unique_current_binding_head",
                return_value=inspection,
            ), self.assertRaises(StoreConflictError):
                self.service.observe_current(binding)
            self.assertEqual(self._gate_counts(), baseline)

    def test_concurrent_observations_serialize_without_losing_lineage(self) -> None:
        second = MissionStoreTargetHealthGateService(
            self.fixture.store,
            self.custody,
            self.fixture.registry,
            clock=lambda: self.fixture.root.now,
        )
        second.initialize()
        barrier = threading.Barrier(2)
        clock_lock = threading.Lock()

        def advancing_clock() -> datetime:
            with clock_lock:
                self.now += timedelta(seconds=1)
                return self.now

        self.custody._trusted_clock = advancing_clock

        def observe(service):  # type: ignore[no-untyped-def]
            barrier.wait(timeout=10)
            return service.observe_current(self.binding)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                future.result(timeout=20)
                for future in (
                    executor.submit(observe, self.service),
                    executor.submit(observe, second),
                )
            )
        self.assertEqual(
            sorted(result.observation.observation_sequence for result in results),
            [1, 2],
        )
        report = self.service.verify_store()
        self.assertEqual(report.observation_count, 2)
        self.assertEqual(report.transition_count, 2)
        self.assertEqual(report.active_count, 1)

    def test_atomic_rollback_if_transition_persistence_aborts(self) -> None:
        with mock.patch.object(
            self.service,
            "_insert_transition",
            side_effect=sqlite3.IntegrityError("phase199c injected failure"),
        ), self.assertRaises(StoreConflictError):
            self.service.observe_current(self.binding)
        self.assertEqual(self._gate_counts(), (0, 0, 0, 0))

    def test_resumption_rolls_back_authority_and_gate_state_on_late_failure(self) -> None:
        intent = self._prepare()
        replay_key = canonical_sha256({"phase199c": "rollback-resumption"})
        assertion = self._assertion(intent, replay_key)
        before_counts = self._gate_counts()
        before_head = self.service.load_head(self.binding)
        with self.fixture.store._read_connection() as connection:
            before_principal = (
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
                tuple(
                    connection.execute(
                        "SELECT head_hash, assertion_count, effect_count, updated_at "
                        "FROM mission_principal_ledgers WHERE mission_id=?",
                        (self.fixture.mission_id,),
                    ).fetchone()
                ),
            )
        self._tick()
        with mock.patch.object(
            self.service,
            "_store_head",
            side_effect=sqlite3.IntegrityError("phase199c injected late failure"),
        ), self.assertRaises(StoreConflictError):
            self.service.resume(
                assertion,
                intent,
                canonical_replay_key_sha256=replay_key,
            )
        with self.fixture.store._read_connection() as connection:
            after_principal = (
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
                tuple(
                    connection.execute(
                        "SELECT head_hash, assertion_count, effect_count, updated_at "
                        "FROM mission_principal_ledgers WHERE mission_id=?",
                        (self.fixture.mission_id,),
                    ).fetchone()
                ),
            )
        self.assertEqual(after_principal, before_principal)
        self.assertEqual(self._gate_counts(), before_counts)
        self.assertEqual(self.service.load_head(self.binding), before_head)

    def test_historical_verification_ignores_current_custody_but_detects_store_tamper(self) -> None:
        self.service.observe_current(self.binding)
        self._append("rejected", observe=False)
        with mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            side_effect=AssertionError("historical verification read current custody"),
        ):
            report = self.service.verify_store(self.fixture.mission_id)
        self.assertIs(type(report), TargetHealthGateStoreVerificationReport)
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.mission_id, self.fixture.mission_id)
        with self.fixture.store._read_connection() as connection:
            direct = verify_target_health_gate_store(connection, self.fixture.mission_id)
        self.assertEqual(direct, report)

        phase198.TargetHealthCustodyPhase198Tests.rewrite_with_triggers_restored(
            self.fixture.store.path,
            ("target_health_gate_observations",),
            lambda connection: connection.execute(
                "UPDATE target_health_gate_observations SET inspection_json='{}'"
            ),
        )
        with self.assertRaises(StoreIntegrityError):
            self.service.verify_store()

    def test_historical_verification_rejects_resumption_custody_substitution(self) -> None:
        resumed = self._resume()
        assertion_issuer = resumed.resumption.assertion_issuer
        assertion_id = resumed.resumption.assertion_id
        mission_id = resumed.resumption.subject.mission_id
        store_path = self.fixture.store.path

        baseline = sqlite3.connect(":memory:")
        self.addCleanup(baseline.close)
        source = sqlite3.connect(store_path)
        try:
            source.backup(baseline)
        finally:
            source.close()

        def effect_payload(connection: sqlite3.Connection) -> None:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT effect_json FROM principal_assertion_effects "
                "WHERE issuer=? AND assertion_id=?",
                (assertion_issuer, assertion_id),
            ).fetchone()
            self.assertIsNotNone(row)
            effect = phase195b.json.loads(row["effect_json"])
            effect["payload"]["subject_id"] = "substituted-subject"
            effect_json = canonical_json(effect)
            connection.execute(
                "UPDATE principal_assertion_effects SET effect_json=?, effect_hash=? "
                "WHERE issuer=? AND assertion_id=?",
                (effect_json, sha256_text(effect_json), assertion_issuer, assertion_id),
            )

        def effects_hash(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE principal_assertion_uses SET effects_hash=? "
                "WHERE issuer=? AND assertion_id=?",
                (sha256_text("substituted-effects"), assertion_issuer, assertion_id),
            )

        def entry_hash(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE principal_assertion_uses SET entry_hash=? "
                "WHERE issuer=? AND assertion_id=?",
                (sha256_text("substituted-entry"), assertion_issuer, assertion_id),
            )

        def predecessor_link(connection: sqlite3.Connection) -> None:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM principal_assertion_uses WHERE issuer=? AND assertion_id=?",
                (assertion_issuer, assertion_id),
            ).fetchone()
            self.assertIsNotNone(row)
            material = {
                key: row[key]
                for key in row.keys()  # noqa: SIM118
                if key not in {"assertion_json", "entry_hash"}
            }
            material["previous_hash"] = sha256_text("substituted-predecessor")
            substituted_entry = principal_assertion_entry_hash(material)
            connection.execute(
                "UPDATE principal_assertion_uses SET previous_hash=?, entry_hash=? "
                "WHERE issuer=? AND assertion_id=?",
                (
                    material["previous_hash"],
                    substituted_entry,
                    assertion_issuer,
                    assertion_id,
                ),
            )
            connection.execute(
                "UPDATE mission_principal_ledgers SET head_hash=? WHERE mission_id=?",
                (substituted_entry, mission_id),
            )

        def successor_link(connection: sqlite3.Connection) -> None:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM principal_assertion_uses WHERE issuer=? AND assertion_id=?",
                (assertion_issuer, assertion_id),
            ).fetchone()
            self.assertIsNotNone(row)
            values = {key: row[key] for key in row.keys()}  # noqa: SIM118
            values.update(
                {
                    "assertion_id": "PAS-" + "F0" * 16,
                    "entry_hash": sha256_text("substituted-successor-entry"),
                    "issuer": "issuer:substituted-successor",
                    "previous_hash": sha256_text("substituted-successor-link"),
                    "use_sequence": row["use_sequence"] + 1,
                }
            )
            columns = tuple(values)
            connection.execute(
                "INSERT INTO principal_assertion_uses(" + ",".join(columns) + ") VALUES("
                + ",".join("?" for _ in columns)
                + ")",
                tuple(values[column] for column in columns),
            )
            connection.execute(
                "UPDATE mission_principal_ledgers SET assertion_count=?, head_hash=?, "
                "updated_at=? WHERE mission_id=?",
                (
                    values["use_sequence"],
                    values["entry_hash"],
                    values["consumed_at"],
                    mission_id,
                ),
            )

        def ledger_count(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE mission_principal_ledgers SET assertion_count=assertion_count+1 "
                "WHERE mission_id=?",
                (mission_id,),
            )

        def ledger_head(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE mission_principal_ledgers SET head_hash=? WHERE mission_id=?",
                (sha256_text("substituted-ledger-head"), mission_id),
            )

        def assertion_json(connection: sqlite3.Connection) -> None:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT assertion_json FROM principal_assertion_uses "
                "WHERE issuer=? AND assertion_id=?",
                (assertion_issuer, assertion_id),
            ).fetchone()
            self.assertIsNotNone(row)
            document = phase195b.json.loads(row["assertion_json"])
            document["subject"] = "subject:substituted"
            connection.execute(
                "UPDATE principal_assertion_uses SET assertion_json=? "
                "WHERE issuer=? AND assertion_id=?",
                (canonical_json(document), assertion_issuer, assertion_id),
            )

        def use_subject(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE principal_assertion_uses SET subject=? "
                "WHERE issuer=? AND assertion_id=?",
                ("subject:substituted", assertion_issuer, assertion_id),
            )

        def operation_intent(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE principal_assertion_uses SET operation_intent_json=? "
                "WHERE issuer=? AND assertion_id=?",
                (
                    canonical_json({"role": "substituted"}),
                    assertion_issuer,
                    assertion_id,
                ),
            )

        def transition_projection(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_gate_transitions SET transition_json='{}' "
                "WHERE resumption_id=?",
                (resumed.resumption.resumption_id,),
            )

        def head_projection(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_gate_heads SET head_sha256=? WHERE subject_id=?",
                (
                    sha256_text("substituted-gate-head"),
                    resumed.resumption.subject.subject_id,
                ),
            )

        mutations = (
            ("effect payload", ("principal_assertion_effects",), effect_payload),
            ("effects hash", ("principal_assertion_uses",), effects_hash),
            ("entry hash", ("principal_assertion_uses",), entry_hash),
            (
                "predecessor link",
                ("principal_assertion_uses", "mission_principal_ledgers"),
                predecessor_link,
            ),
            (
                "successor link",
                ("principal_assertion_uses", "mission_principal_ledgers"),
                successor_link,
            ),
            ("ledger count", ("mission_principal_ledgers",), ledger_count),
            ("ledger head", ("mission_principal_ledgers",), ledger_head),
            ("assertion json", ("principal_assertion_uses",), assertion_json),
            ("use subject", ("principal_assertion_uses",), use_subject),
            ("operation intent", ("principal_assertion_uses",), operation_intent),
            (
                "resumption transition",
                ("target_health_gate_transitions",),
                transition_projection,
            ),
            ("gate head", ("target_health_gate_heads",), head_projection),
        )
        for label, tables, mutation in mutations:
            with self.subTest(label=label):
                phase198.TargetHealthCustodyPhase198Tests.rewrite_with_triggers_restored(
                    store_path,
                    tables,
                    mutation,
                )
                with self.assertRaises(StoreIntegrityError):
                    self.service.verify_store()
                destination = sqlite3.connect(store_path)
                try:
                    baseline.backup(destination)
                finally:
                    destination.close()

    def test_report_counts_resumption_and_all_records_claim_no_external_effects(self) -> None:
        result = self.service.observe_current(self.binding)
        documents = (
            result.observation.to_dict(),
            result.transition.to_dict(),
            result.head.to_dict(),
            result.decision.to_dict(),
        )
        for document in documents:
            for field, expected in NO_EFFECTS.items():
                self.assertEqual(document[field], expected)

        resumed = self._resume()
        for record in (resumed.resumption, resumed.transition, resumed.head):
            document = record.to_dict()
            for field, expected in NO_EFFECTS.items():
                self.assertEqual(document[field], expected)
        report = self.service.verify_store()
        self.assertEqual(report.mission_count, 1)
        self.assertEqual(report.subject_count, 1)
        self.assertEqual(report.resumption_count, 1)
        self.assertEqual(report.active_count, 1)
        self.assertEqual(report.paused_count, 0)
        self.assertEqual(report.recovery_pending_count, 0)


if __name__ == "__main__":
    unittest.main()
