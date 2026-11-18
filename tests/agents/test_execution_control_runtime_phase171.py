"""Phase 171 fail-closed execution-control runtime coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
import sunderkey.execution_control_runtime as runtime
from sunderkey.execution_control_runtime import (
    AdmissionStatus,
    AllowedUtcWindow,
    BlockReason,
    CleanupStatus,
    ClockObservation,
    ControlState,
    ExecutionBinding,
    ExecutionControlError,
    ExecutionControlPolicy,
    ExecutionRequest,
    ExecutionStatus,
    HealthState,
    RateMode,
    RetryDisposition,
    StateTransition,
    StoredExecution,
    TransportObservation,
    execute_with_controls,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "execution-control-receipt-v1.schema.json"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def binding(**changes: object) -> ExecutionBinding:
    values: dict[str, object] = {
        "tenant_id": "tenant:alpha",
        "context_id": "context:assessment-001",
        "context_sha256": digest("1"),
        "scope_id": "scope:approved-001",
        "scope_sha256": digest("2"),
        "target_id": "target:api-001",
        "target_sha256": digest("3"),
        "session_id": "session:worker-001",
        "lease_id": "lease:execution-001",
        "fence_epoch": 7,
    }
    values.update(changes)
    return ExecutionBinding(**values)


def policy(mode: RateMode = RateMode.FIXED_WINDOW, **changes: object) -> ExecutionControlPolicy:
    values: dict[str, object] = {
        "allowed_windows": (AllowedUtcWindow("2026-09-20T11:00:00Z", "2026-09-20T13:00:00Z"),),
        "rate_mode": mode,
        "request_ceiling": 3,
        "period_seconds": 60,
        "token_capacity": 0 if mode is RateMode.FIXED_WINDOW else 3,
        "token_refill_amount": 0 if mode is RateMode.FIXED_WINDOW else 1,
        "byte_ceiling": 1024,
        "maximum_concurrent_sessions": 2,
        "sequential_only": True,
        "maximum_attempts": 2,
        "retryable_failure_codes": ("temporary_failure", "transport_exception"),
        "cleanup_required": True,
    }
    values.update(changes)
    return ExecutionControlPolicy.build(**values)


def request(control_policy: ExecutionControlPolicy, **changes: object) -> ExecutionRequest:
    values: dict[str, object] = {
        "binding": binding(),
        "policy_id": control_policy.policy_id,
        "policy_sha256": control_policy.policy_sha256,
        "idempotency_key": "idempotency:001",
        "operation_code": "http.request",
        "payload_sha256": digest("4"),
        "payload_size_bytes": 100,
        "attempt_number": 1,
        "prior_execution_sha256": None,
        "cleanup_obligation_sha256": digest("5"),
    }
    values.update(changes)
    return ExecutionRequest(**values)


def state(control_policy: ExecutionControlPolicy, **changes: object) -> ControlState:
    values: dict[str, object] = {
        "binding": binding(),
        "lease_expires_at": "2026-09-20T12:30:00Z",
        "health": HealthState.HEALTHY,
        "canceled": False,
        "emergency_stop": False,
        "active_sessions": (),
        "active_executions": 0,
        "fixed_window_started_at": "2026-09-20T11:59:30Z",
        "requests_used": 0,
        "bytes_used": 0,
        "tokens_available": (
            control_policy.token_capacity
            if control_policy.rate_mode is RateMode.INTEGER_TOKEN_BUCKET
            else 0
        ),
        "token_refill_tick": 100,
        "last_observed_at": "2026-09-20T11:59:30Z",
        "last_monotonic_tick": 100,
        "state_version": 4,
    }
    values.update(changes)
    return ControlState(**values)


class FakeClock:
    def __init__(self, *observations: ClockObservation) -> None:
        self.observations = list(observations)

    def observe(self) -> ClockObservation:
        if not self.observations:
            raise AssertionError("unexpected clock observation")
        return self.observations.pop(0)


class FakeRepository:
    def __init__(self, initial: ControlState) -> None:
        self.state = initial
        self.stored: dict[str, StoredExecution] = {}
        self.reserve_calls = 0
        self.complete_calls = 0
        self.tamper_reservation = False
        self.tamper_completion = False
        self.fail_lookup = False
        self.fail_completion_commit = False

    def lookup(self, _binding: ExecutionBinding, idempotency_key: str) -> StoredExecution | None:
        if self.fail_lookup:
            raise RuntimeError("repository unavailable")
        return self.stored.get(idempotency_key)

    def reserve(
        self,
        item: ExecutionRequest,
        control_policy: ExecutionControlPolicy,
        observation: ClockObservation,
    ) -> StateTransition:
        self.reserve_calls += 1
        before = self.state
        after, _ = runtime._expected_reservation(before, item, control_policy, observation)
        if after is None:
            after = before
        elif self.tamper_reservation:
            after = replace(after, requests_used=after.requests_used + 1, state_sha256="")
        else:
            self.state = after
        return StateTransition(before, after)

    def complete(
        self,
        item: ExecutionRequest,
        reservation: ControlState,
        observation: ClockObservation,
        outcome: StoredExecution,
    ) -> StateTransition:
        self.complete_calls += 1
        if self.fail_completion_commit:
            raise RuntimeError("completion commit unavailable")
        after = runtime._expected_completion(reservation, item, observation)
        if self.tamper_completion:
            after = replace(after, bytes_used=after.bytes_used + 1, state_sha256="")
        else:
            self.state = after
            self.stored[item.idempotency_key] = outcome
        return StateTransition(reservation, after)


class FakeTransport:
    def __init__(self, succeeded: bool = True, failure_code: str | None = None) -> None:
        self.succeeded = succeeded
        self.failure_code = failure_code
        self.calls = 0
        self.envelopes: list[object] = []

    def execute(self, envelope: object) -> TransportObservation:
        self.calls += 1
        self.envelopes.append(envelope)
        return TransportObservation(
            succeeded=self.succeeded,
            failure_code=self.failure_code,
            response_sha256=digest("9"),
            response_size_bytes=17,
        )


def clock() -> FakeClock:
    return FakeClock(
        ClockObservation("2026-09-20T12:00:00Z", 110),
        ClockObservation("2026-09-20T12:00:01Z", 111),
    )


class ExecutionControlRuntimeTests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.ExecutionControlPolicy, ExecutionControlPolicy)
        self.assertIs(sunderkey.ExecutionRequest, ExecutionRequest)
        self.assertIs(sunderkey.ExecutionBinding, ExecutionBinding)
        self.assertIs(sunderkey.execute_with_controls, execute_with_controls)

    def run_case(
        self,
        *,
        control_policy: ExecutionControlPolicy | None = None,
        control_state: ControlState | None = None,
        item: ExecutionRequest | None = None,
        execution_clock: FakeClock | None = None,
        transport: FakeTransport | None = None,
        repository: FakeRepository | None = None,
    ) -> tuple[object, FakeRepository, FakeTransport]:
        selected_policy = control_policy or policy()
        selected_state = control_state or state(selected_policy)
        selected_request = item or request(selected_policy)
        selected_repository = repository or FakeRepository(selected_state)
        selected_transport = transport or FakeTransport()
        result = execute_with_controls(
            selected_request,
            selected_policy,
            execution_clock or clock(),
            selected_repository,
            selected_transport,
        )
        return result, selected_repository, selected_transport

    def test_success_uses_only_injected_transport_and_records_cleanup_obligation(self) -> None:
        result, repository, transport = self.run_case()
        self.assertEqual(result.admission.status, AdmissionStatus.ADMITTED)
        self.assertEqual(result.execution.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(
            result.execution.cleanup_status, CleanupStatus.PENDING_EXTERNAL_VERIFICATION
        )
        self.assertEqual(result.execution.enforcement_boundary, "injected_adapter_boundary_only")
        self.assertEqual(transport.calls, 1)
        self.assertEqual(repository.reserve_calls, 1)
        self.assertEqual(repository.complete_calls, 1)
        self.assertFalse(result.idempotent_replay)

    def test_exact_idempotent_replay_does_not_call_transport_or_clock(self) -> None:
        control_policy = policy()
        item = request(control_policy)
        repository = FakeRepository(state(control_policy))
        transport = FakeTransport()
        first = execute_with_controls(item, control_policy, clock(), repository, transport)
        replay = execute_with_controls(item, control_policy, FakeClock(), repository, transport)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(first.execution, replay.execution)
        self.assertEqual(transport.calls, 1)

    def test_idempotency_rebinding_is_blocked(self) -> None:
        control_policy = policy()
        first = request(control_policy)
        repository = FakeRepository(state(control_policy))
        transport = FakeTransport()
        execute_with_controls(first, control_policy, clock(), repository, transport)
        rebound = request(control_policy, payload_sha256=digest("8"))
        result = execute_with_controls(
            rebound,
            control_policy,
            FakeClock(ClockObservation("2026-09-20T12:01:00Z", 120)),
            repository,
            transport,
        )
        self.assertEqual(result.admission.reason, BlockReason.IDEMPOTENCY_REBINDING.value)
        self.assertEqual(transport.calls, 1)

    def test_transport_failure_is_distinct_and_retry_is_not_automatic(self) -> None:
        result, _, transport = self.run_case(transport=FakeTransport(False, "temporary_failure"))
        self.assertEqual(result.admission.status, AdmissionStatus.ADMITTED)
        self.assertEqual(result.execution.status, ExecutionStatus.TRANSPORT_FAILED)
        self.assertEqual(result.execution.retry_disposition, RetryDisposition.RETRY_PERMITTED)
        self.assertEqual(transport.calls, 1)

    def test_nonretryable_and_exhausted_failures_are_distinguished(self) -> None:
        control_policy = policy()
        first, _, _ = self.run_case(
            control_policy=control_policy,
            transport=FakeTransport(False, "permanent_failure"),
        )
        self.assertEqual(first.execution.retry_disposition, RetryDisposition.FAILURE_NOT_RETRYABLE)
        retry = request(
            control_policy,
            attempt_number=2,
            prior_execution_sha256=digest("a"),
        )
        second, _, _ = self.run_case(
            control_policy=control_policy,
            item=retry,
            transport=FakeTransport(False, "temporary_failure"),
        )
        self.assertEqual(second.execution.retry_disposition, RetryDisposition.RETRY_EXHAUSTED)

    def test_fixed_window_rolls_counters_at_exact_boundary(self) -> None:
        control_policy = policy(request_ceiling=1, byte_ceiling=100)
        control_state = state(
            control_policy,
            fixed_window_started_at="2026-09-20T11:59:00Z",
            requests_used=1,
            bytes_used=100,
        )
        result, repository, _ = self.run_case(
            control_policy=control_policy, control_state=control_state
        )
        self.assertEqual(result.admission.status, AdmissionStatus.ADMITTED)
        self.assertEqual(repository.state.requests_used, 1)
        self.assertEqual(repository.state.bytes_used, 100)

    def test_integer_token_bucket_refills_only_whole_tokens(self) -> None:
        control_policy = policy(RateMode.INTEGER_TOKEN_BUCKET)
        control_state = state(control_policy, tokens_available=0, token_refill_tick=50)
        result, repository, _ = self.run_case(
            control_policy=control_policy, control_state=control_state
        )
        self.assertEqual(result.admission.status, AdmissionStatus.ADMITTED)
        self.assertEqual(repository.state.tokens_available, 0)
        self.assertEqual(repository.state.token_refill_tick, 110)

    def test_integer_token_bucket_exhaustion_blocks_before_transport(self) -> None:
        control_policy = policy(RateMode.INTEGER_TOKEN_BUCKET)
        control_state = state(control_policy, tokens_available=0, token_refill_tick=100)
        transport = FakeTransport()
        result, _, _ = self.run_case(
            control_policy=control_policy,
            control_state=control_state,
            execution_clock=FakeClock(ClockObservation("2026-09-20T12:00:00Z", 110)),
            transport=transport,
        )
        self.assertEqual(result.admission.reason, BlockReason.RATE_EXHAUSTED.value)
        self.assertEqual(transport.calls, 0)

    def test_every_pretransport_denial_keeps_transport_idle(self) -> None:
        base_policy = policy()
        cases = (
            (
                state(base_policy, lease_expires_at="2026-09-20T14:00:00Z"),
                request(base_policy),
                ClockObservation("2026-09-20T13:00:00Z", 110),
                BlockReason.OUTSIDE_ALLOWED_WINDOW,
            ),
            (
                state(base_policy, requests_used=3),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.RATE_EXHAUSTED,
            ),
            (
                state(base_policy, bytes_used=1000),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.BYTE_BUDGET_EXHAUSTED,
            ),
            (
                state(base_policy, active_sessions=("session:a", "session:b")),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.SESSION_LIMIT_EXHAUSTED,
            ),
            (
                state(base_policy, active_executions=1),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.SEQUENTIAL_CONFLICT,
            ),
            (
                state(base_policy, lease_expires_at="2026-09-20T12:00:00Z"),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.LEASE_EXPIRED,
            ),
            (
                state(base_policy, health=HealthState.PAUSED),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.HEALTH_PAUSED,
            ),
            (
                state(base_policy, health=HealthState.UNHEALTHY),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.HEALTH_UNHEALTHY,
            ),
            (
                state(base_policy, canceled=True),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.CANCELED,
            ),
            (
                state(base_policy, emergency_stop=True),
                request(base_policy),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.EMERGENCY_STOP,
            ),
            (
                state(base_policy),
                request(
                    base_policy,
                    attempt_number=3,
                    prior_execution_sha256=digest("a"),
                ),
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.ATTEMPT_BUDGET_EXHAUSTED,
            ),
        )
        for control_state, item, observation, expected in cases:
            with self.subTest(reason=expected.value):
                transport = FakeTransport()
                result, _, _ = self.run_case(
                    control_policy=base_policy,
                    control_state=control_state,
                    item=item,
                    execution_clock=FakeClock(observation),
                    transport=transport,
                )
                self.assertEqual(result.admission.reason, expected.value)
                self.assertEqual(transport.calls, 0)

    def test_time_rollback_stale_fence_cross_context_and_policy_rebinding_fail_closed(self) -> None:
        control_policy = policy()
        stale_fence_request = request(control_policy, binding=binding(fence_epoch=8))
        cross_context_request = request(
            control_policy,
            binding=binding(context_id="context:other"),
        )
        other_policy = policy(byte_ceiling=2048)
        policy_rebound = request(
            control_policy,
            policy_id=other_policy.policy_id,
            policy_sha256=other_policy.policy_sha256,
        )
        cases = (
            (
                state(control_policy),
                request(control_policy),
                ClockObservation("2026-09-20T11:59:29Z", 99),
                BlockReason.TIME_ROLLBACK,
            ),
            (
                state(control_policy),
                stale_fence_request,
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.STALE_FENCE,
            ),
            (
                state(control_policy),
                cross_context_request,
                ClockObservation("2026-09-20T12:00:00Z", 110),
                BlockReason.BINDING_MISMATCH,
            ),
        )
        for control_state, item, observation, expected in cases:
            transport = FakeTransport()
            result, _, _ = self.run_case(
                control_policy=control_policy,
                control_state=control_state,
                item=item,
                execution_clock=FakeClock(observation),
                transport=transport,
            )
            self.assertEqual(result.admission.reason, expected.value)
            self.assertEqual(transport.calls, 0)
        rebound, _, rebound_transport = self.run_case(
            control_policy=control_policy,
            item=policy_rebound,
            execution_clock=FakeClock(ClockObservation("2026-09-20T12:00:00Z", 110)),
        )
        self.assertEqual(rebound.admission.reason, BlockReason.BINDING_MISMATCH.value)
        self.assertEqual(rebound_transport.calls, 0)

    def test_reservation_tampering_blocks_and_completion_tampering_is_explicit(self) -> None:
        control_policy = policy()
        tampered = FakeRepository(state(control_policy))
        tampered.tamper_reservation = True
        before, _, before_transport = self.run_case(
            control_policy=control_policy, repository=tampered
        )
        self.assertEqual(before.admission.reason, BlockReason.STATE_TAMPERING.value)
        self.assertEqual(before_transport.calls, 0)

        completion = FakeRepository(state(control_policy))
        completion.tamper_completion = True
        after, _, after_transport = self.run_case(
            control_policy=control_policy, repository=completion
        )
        self.assertEqual(after.admission.status, AdmissionStatus.ADMITTED)
        self.assertEqual(after.execution.status, ExecutionStatus.COMPLETION_FAILED)
        self.assertIsNone(after.execution.completion_state_sha256)
        self.assertEqual(after_transport.calls, 1)

        failed_completion = FakeRepository(state(control_policy))
        failed_completion.tamper_completion = True
        failed, _, _ = self.run_case(
            control_policy=control_policy,
            repository=failed_completion,
            transport=FakeTransport(False, "temporary_failure"),
        )
        self.assertEqual(failed.execution.status, ExecutionStatus.COMPLETION_FAILED)
        self.assertFalse(failed.execution.transport_succeeded)
        self.assertEqual(failed.execution.transport_failure_code, "temporary_failure")
        self.assertEqual(failed.execution.retry_disposition, RetryDisposition.RETRY_PERMITTED)

    def test_repository_failure_blocks_before_transport_and_store_failure_is_explicit(self) -> None:
        control_policy = policy()
        lookup = FakeRepository(state(control_policy))
        lookup.fail_lookup = True
        result, _, transport = self.run_case(
            control_policy=control_policy,
            repository=lookup,
            execution_clock=FakeClock(ClockObservation("2026-09-20T12:00:00Z", 110)),
        )
        self.assertEqual(result.admission.reason, BlockReason.STATE_REPOSITORY_FAILURE.value)
        self.assertEqual(transport.calls, 0)

        store = FakeRepository(state(control_policy))
        store.fail_completion_commit = True
        result, _, transport = self.run_case(control_policy=control_policy, repository=store)
        self.assertEqual(result.execution.status, ExecutionStatus.COMPLETION_FAILED)
        self.assertEqual(store.state.active_executions, 1)
        self.assertEqual(transport.calls, 1)
        duplicate = execute_with_controls(
            request(control_policy),
            control_policy,
            FakeClock(ClockObservation("2026-09-20T12:00:02Z", 112)),
            store,
            transport,
        )
        self.assertEqual(duplicate.admission.reason, BlockReason.SEQUENTIAL_CONFLICT.value)
        self.assertEqual(transport.calls, 1)

    def test_content_addresses_reject_receipt_and_state_tampering(self) -> None:
        result, repository, _ = self.run_case()
        with self.assertRaisesRegex(ExecutionControlError, "receipt_id"):
            replace(result.admission, status=AdmissionStatus.BLOCKED, reason="canceled")
        with self.assertRaisesRegex(ExecutionControlError, "state_sha256"):
            replace(repository.state, requests_used=99)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipts_conform_to_schema_and_schema_rejects_unknown_fields(self) -> None:
        result, _, _ = self.run_case()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        validator.validate(result.admission.to_dict())
        validator.validate(result.execution.to_dict())
        altered = copy.deepcopy(result.execution.to_dict())
        altered["authorization"] = "granted"
        self.assertTrue(list(validator.iter_errors(altered)))

    def test_policy_windows_and_identifiers_are_exact_and_immutable(self) -> None:
        with self.assertRaises(ExecutionControlError):
            policy(
                allowed_windows=(
                    AllowedUtcWindow("2026-09-20T12:00:00Z", "2026-09-20T13:00:00Z"),
                    AllowedUtcWindow("2026-09-20T11:00:00Z", "2026-09-20T11:30:00Z"),
                )
            )
        with self.assertRaises(ExecutionControlError):
            ExecutionControlPolicy(
                policy_id="ECP-FORGED",
                allowed_windows=(AllowedUtcWindow("2026-09-20T11:00:00Z", "2026-09-20T13:00:00Z"),),
                rate_mode=RateMode.FIXED_WINDOW,
                request_ceiling=1,
                period_seconds=60,
                token_capacity=0,
                token_refill_amount=0,
                byte_ceiling=100,
                maximum_concurrent_sessions=1,
                sequential_only=True,
                maximum_attempts=1,
                retryable_failure_codes=("temporary_failure",),
                cleanup_required=True,
            )


if __name__ == "__main__":
    unittest.main()
