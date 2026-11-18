"""Disposable native fixtures for local sequential execution-state storage."""

from __future__ import annotations

import copy
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from sunderkey import execution_control_runtime as runtime
from sunderkey import sqlite_execution_state_repository as leaf
from tests.agents.test_execution_control_runtime_phase171 import (
    FakeClock,
    FakeRepository,
    FakeTransport,
    binding,
    clock,
    digest,
    policy,
    request,
    state,
)


@contextmanager
def database(path: Path):
    with closing(sqlite3.connect(path)) as connection, connection:
        yield connection


class SQLiteExecutionStateRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sunderkey-execution-state-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "execution.sqlite"
        self.policy = policy()
        self.binding = binding()
        self.initial = state(self.policy)

    def repository(self, **changes: object) -> leaf.SQLiteExecutionStateRepository:
        values: dict[str, object] = {
            "database_path": self.path,
            "namespace": "namespace:synthetic",
            "tenant_id": self.binding.tenant_id,
            "expected_binding": self.binding,
            "expected_policy": self.policy,
            "initial_state": self.initial,
        }
        values.update(changes)
        return leaf.SQLiteExecutionStateRepository(**values)

    def run_request(
        self,
        repository: leaf.SQLiteExecutionStateRepository,
        *,
        item: runtime.ExecutionRequest | None = None,
        observations: FakeClock | None = None,
        transport: FakeTransport | None = None,
    ) -> runtime.ExecutionControlResult:
        return leaf.execute_with_durable_controls(
            item or request(self.policy),
            self.policy,
            observations or clock(),
            repository,
            transport or FakeTransport(),
        )

    def logical_dump(self) -> str:
        with database(self.path) as connection:
            return "\n".join(connection.iterdump())

    def candidate(self, item: runtime.ExecutionRequest | None = None) -> runtime.StoredExecution:
        item = item or request(self.policy)
        result = runtime.execute_with_controls(
            item, self.policy, clock(), FakeRepository(self.initial), FakeTransport()
        )
        return runtime.StoredExecution(item.request_sha256, result.admission, result.execution)

    def pending(self, repository: leaf.SQLiteExecutionStateRepository) -> runtime.ControlState:
        return repository.reserve(
            request(self.policy), self.policy, runtime.ClockObservation("2026-09-20T12:00:00Z", 110)
        ).after

    def test_original_receipt_goldens_and_both_rate_modes(self) -> None:
        for mode in runtime.RateMode:
            with self.subTest(mode=mode):
                self.path = self.directory / f"{mode.value}.sqlite"
                self.policy = policy(mode)
                self.initial = state(self.policy)
                original = runtime.execute_with_controls(
                    request(self.policy),
                    self.policy,
                    clock(),
                    FakeRepository(self.initial),
                    FakeTransport(),
                )
                durable = self.run_request(self.repository())
                self.assertEqual(durable.admission.to_dict(), original.admission.to_dict())
                self.assertEqual(durable.execution.to_dict(), original.execution.to_dict())
                self.assertEqual(
                    durable.admission.receipt_id,
                    "ECAR-" + original.admission.receipt_sha256[7:39].upper(),
                )
                if mode is runtime.RateMode.FIXED_WINDOW:
                    self.assertEqual(
                        durable.execution.receipt_id, "ECER-724E39D5FE3939BE0D74E11176E0D53B"
                    )
                self.assertEqual(self.repository().current_state().state_version, 6)

    def test_exact_old_result_replay_uses_no_clock_or_second_transport(self) -> None:
        transport = FakeTransport()
        original = self.run_request(self.repository(), transport=transport)
        reopened = self.repository()
        replay = self.run_request(reopened, observations=FakeClock(), transport=transport)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(replay.execution.to_dict(), original.execution.to_dict())
        self.assertEqual(transport.calls, 1)
        returned = reopened.lookup(self.binding, request(self.policy).idempotency_key)
        object.__setattr__(returned.execution, "response_size_bytes", 999)
        self.assertEqual(
            reopened.lookup(
                self.binding, request(self.policy).idempotency_key
            ).execution.response_size_bytes,
            17,
        )

    def test_historical_lookup_does_not_require_an_unexpired_plan_or_clock(self) -> None:
        repository = self.repository()
        original = self.run_request(repository)
        # A later caller declaration cannot reseed the stored lease. Lookup and
        # original receipt replay are historical and do not call a new clock.
        self.assertEqual(
            repository.lookup(self.binding, "idempotency:001").execution, original.execution
        )
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository(
                initial_state=replace(
                    self.initial, lease_expires_at="2026-09-20T14:00:00Z", state_sha256=""
                )
            )
        replay = self.run_request(self.repository(), observations=FakeClock())
        self.assertTrue(replay.idempotent_replay)

    def test_budgets_remain_spent_across_reopen_and_reset_only_by_original_algorithm(self) -> None:
        for index in range(3):
            outcome = self.run_request(
                self.repository(),
                item=request(self.policy, idempotency_key=f"idempotency:{index}"),
                observations=FakeClock(
                    runtime.ClockObservation(f"2026-09-20T12:00:0{index * 2}Z", 110 + index * 2),
                    runtime.ClockObservation(
                        f"2026-09-20T12:00:0{index * 2 + 1}Z", 111 + index * 2
                    ),
                ),
            )
            self.assertEqual(outcome.execution.status, runtime.ExecutionStatus.SUCCEEDED)
        transport = FakeTransport()
        denied = self.run_request(
            self.repository(),
            item=request(self.policy, idempotency_key="idempotency:blocked"),
            observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:06Z", 116)),
            transport=transport,
        )
        self.assertEqual(denied.admission.reason, runtime.BlockReason.RATE_EXHAUSTED.value)
        self.assertEqual(transport.calls, 0)
        after_roll = self.run_request(
            self.repository(),
            item=request(self.policy, idempotency_key="idempotency:next-window"),
            observations=FakeClock(
                runtime.ClockObservation("2026-09-20T12:01:00Z", 170),
                runtime.ClockObservation("2026-09-20T12:01:01Z", 171),
            ),
        )
        self.assertIsNotNone(after_roll.execution)
        self.assertEqual(self.repository().current_state().bytes_used, 100)

    def test_integer_token_refill_is_persisted_without_floating_point(self) -> None:
        self.policy = policy(
            runtime.RateMode.INTEGER_TOKEN_BUCKET, request_ceiling=1, token_capacity=1
        )
        self.initial = state(self.policy)
        self.run_request(self.repository())
        transport = FakeTransport()
        denied = self.run_request(
            self.repository(),
            item=request(self.policy, idempotency_key="idempotency:bucket-2"),
            observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:02Z", 112)),
            transport=transport,
        )
        self.assertEqual(denied.admission.reason, runtime.BlockReason.RATE_EXHAUSTED.value)
        self.assertEqual(transport.calls, 0)
        result = self.run_request(
            self.repository(),
            item=request(self.policy, idempotency_key="idempotency:bucket-2"),
            observations=FakeClock(
                runtime.ClockObservation("2026-09-20T12:00:20Z", 160),
                runtime.ClockObservation("2026-09-20T12:00:21Z", 161),
            ),
        )
        self.assertIsNotNone(result.execution)
        after = self.repository().current_state()
        self.assertEqual((after.tokens_available, after.token_refill_tick), (0, 160))
        self.assertIs(type(after.tokens_available), int)

    def test_byte_budget_and_declared_health_blocks_do_not_write(self) -> None:
        cases = (
            ({"bytes_used": 1000}, runtime.BlockReason.BYTE_BUDGET_EXHAUSTED),
            ({"health": runtime.HealthState.PAUSED}, runtime.BlockReason.HEALTH_PAUSED),
            ({"health": runtime.HealthState.UNHEALTHY}, runtime.BlockReason.HEALTH_UNHEALTHY),
            ({"canceled": True}, runtime.BlockReason.CANCELED),
            ({"emergency_stop": True}, runtime.BlockReason.EMERGENCY_STOP),
            ({"lease_expires_at": "2026-09-20T11:59:59Z"}, runtime.BlockReason.LEASE_EXPIRED),
        )
        for index, (changes, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                self.path = self.directory / f"denial-{index}.sqlite"
                self.initial = state(self.policy, **changes)
                repository = self.repository()
                before = self.logical_dump()
                transport = FakeTransport()
                result = self.run_request(
                    repository,
                    observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:00Z", 110)),
                    transport=transport,
                )
                self.assertEqual(result.admission.reason, reason.value)
                self.assertEqual(transport.calls, 0)
                self.assertEqual(self.logical_dump(), before)

    def test_one_idle_binding_sequential_policy_and_original_config_are_mandatory(self) -> None:
        cases = (
            {"expected_policy": policy(sequential_only=False)},
            {"tenant_id": "tenant:foreign"},
            {"initial_state": state(self.policy, active_executions=1)},
            {"initial_state": state(self.policy, active_sessions=(self.binding.session_id,))},
            {"initial_state": state(self.policy, reservation_request_sha256=digest("a"))},
            {"initial_state": state(self.policy, binding=binding(fence_epoch=8))},
            {"initial_state": state(self.policy, bytes_used=1025)},
            {"initial_state": state(self.policy, token_refill_tick=101)},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(leaf.SQLiteExecutionStateError):
                self.repository(**changes)
            self.assertFalse(self.path.exists())
        self.repository()
        before = self.logical_dump()
        for changes in (
            {"namespace": "namespace:other"},
            {"initial_state": state(self.policy, state_version=5)},
            {"expected_policy": policy(byte_ceiling=2048)},
        ):
            with self.subTest(changes=changes), self.assertRaises(leaf.SQLiteExecutionStateError):
                self.repository(**changes)
            self.assertEqual(self.logical_dump(), before)

    def test_supported_helper_validates_actual_native_input_before_cached_lookup(self) -> None:
        repository = self.repository()
        transport = FakeTransport()
        self.run_request(repository, transport=transport)
        original = request(self.policy)
        for field, value in (
            ("payload_size_bytes", 100.0),
            ("attempt_number", True),
            ("request_id", ""),
            ("request_sha256", ""),
        ):
            changed = copy.deepcopy(original)
            object.__setattr__(changed, field, value)
            with self.subTest(field=field), patch.object(repository, "lookup") as lookup:
                with self.assertRaises(leaf.SQLiteExecutionStateError):
                    self.run_request(
                        repository, item=changed, observations=FakeClock(), transport=transport
                    )
                lookup.assert_not_called()
        self.assertEqual(transport.calls, 1)

    def test_original_lookup_only_port_cannot_observe_actual_request_alias(self) -> None:
        repository = self.repository()
        self.run_request(repository)
        changed = copy.deepcopy(request(self.policy))
        object.__setattr__(changed, "payload_size_bytes", 100.0)
        # This control documents why the additive supported helper is needed.
        original_port_result = runtime.execute_with_controls(
            changed, self.policy, FakeClock(), repository, FakeTransport()
        )
        self.assertTrue(original_port_result.idempotent_replay)
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.run_request(repository, item=changed, observations=FakeClock())

    def test_changed_request_context_or_policy_cannot_reuse_or_dispatch(self) -> None:
        repository = self.repository()
        self.run_request(repository)
        for changed in (
            request(self.policy, binding=binding(tenant_id="tenant:other")),
            request(self.policy, binding=binding(fence_epoch=8)),
            request(self.policy, binding=binding(context_id="context:other")),
        ):
            transport = FakeTransport()
            with self.assertRaises(leaf.SQLiteExecutionStateError):
                self.run_request(repository, item=changed, transport=transport)
            self.assertEqual(transport.calls, 0)
        transport = FakeTransport()
        result = self.run_request(
            repository,
            item=request(self.policy, payload_size_bytes=101),
            observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:02Z", 112)),
            transport=transport,
        )
        self.assertEqual(result.admission.reason, runtime.BlockReason.IDEMPOTENCY_REBINDING.value)
        self.assertEqual(transport.calls, 0)
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            leaf.execute_with_durable_controls(
                request(self.policy), policy(byte_ceiling=2048), clock(), repository, transport
            )

    def test_native_aliases_and_custom_enum_hook_are_rejected_without_normalization(self) -> None:
        class Hook:
            @property
            def value(self) -> str:
                raise AssertionError("Custom enum normalization must not run")

        variants = (
            ("sequential_only", 1),
            ("byte_ceiling", 1024.0),
            ("rate_mode", Hook()),
            ("allowed_windows", list(self.policy.allowed_windows)),
        )
        for field, value in variants:
            changed = copy.deepcopy(self.policy)
            object.__setattr__(changed, field, value)
            with self.subTest(field=field), self.assertRaises(leaf.SQLiteExecutionStateError):
                self.repository(expected_policy=changed)

        class DerivedBinding(runtime.ExecutionBinding):
            pass

        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository(expected_binding=DerivedBinding(**self.binding.to_dict()))
        self.assertFalse(self.path.exists())

    def test_supplied_sources_are_owned_and_late_configuration_changes_fail_before_io(self) -> None:
        repository = self.repository()
        object.__setattr__(self.binding, "tenant_id", "tenant:late-change")
        self.assertEqual(repository.current_state().binding.tenant_id, "tenant:alpha")
        original = repository._configuration
        repository._configuration = (original[0], original[1], digest("f"))
        with patch.object(repository, "_connect") as connect:
            with self.assertRaises(leaf.SQLiteExecutionStateError):
                repository.lookup(binding(), "idempotency:001")
            connect.assert_not_called()

    def test_reservation_is_durable_before_callback_and_competing_worker_is_blocked(self) -> None:
        first, second = self.repository(), self.repository()
        called = threading.Event()
        release = threading.Event()
        transport = FakeTransport()
        original_execute = transport.execute

        def delayed(envelope: runtime.TransportEnvelope) -> runtime.TransportObservation:
            current = second.current_state()
            self.assertEqual(current.active_executions, 1)
            self.assertEqual(current.bytes_used, 100)
            called.set()
            if not release.wait(5):
                raise AssertionError("Test worker did not release transport")
            return original_execute(envelope)

        with (
            patch.object(transport, "execute", side_effect=delayed),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            pending = executor.submit(self.run_request, first, transport=transport)
            try:
                self.assertTrue(called.wait(5))
                other_transport = FakeTransport()
                denied = self.run_request(
                    second,
                    observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:02Z", 112)),
                    transport=other_transport,
                )
                self.assertEqual(
                    denied.admission.reason, runtime.BlockReason.SEQUENTIAL_CONFLICT.value
                )
                self.assertEqual(other_transport.calls, 0)
            finally:
                release.set()
            self.assertEqual(
                pending.result(timeout=5).execution.status, runtime.ExecutionStatus.SUCCEEDED
            )
        self.assertEqual(transport.calls, 1)
        self.assertTrue(self.run_request(second, observations=FakeClock()).idempotent_replay)

    def test_completion_time_failure_holds_budget_permanently_without_refund(self) -> None:
        repository = self.repository()
        transport = FakeTransport()
        result = self.run_request(
            repository,
            observations=FakeClock(
                runtime.ClockObservation("2026-09-20T12:00:00Z", 110),
                runtime.ClockObservation("2026-09-20T11:59:59Z", 111),
            ),
            transport=transport,
        )
        self.assertEqual(result.execution.status, runtime.ExecutionStatus.COMPLETION_FAILED)
        self.assertIsNone(repository.lookup(binding(), "idempotency:001"))
        before = self.logical_dump()
        for key in ("idempotency:001", "idempotency:new"):
            denied = self.run_request(
                self.repository(),
                item=request(self.policy, idempotency_key=key),
                observations=FakeClock(runtime.ClockObservation("2026-09-20T12:01:00Z", 170)),
                transport=transport,
            )
            self.assertEqual(denied.admission.reason, runtime.BlockReason.SEQUENTIAL_CONFLICT.value)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(self.logical_dump(), before)

    def test_lost_reservation_acknowledgement_never_calls_transport(self) -> None:
        repository = self.repository()
        original = repository._transaction

        @contextmanager
        def lose_ack(*, write: bool):
            with original(write=write) as connection:
                yield connection
            if write:
                raise leaf.SQLiteExecutionStateError(
                    "Synthetic acknowledgement was lost after commit"
                )

        transport = FakeTransport()
        with patch.object(repository, "_transaction", side_effect=lose_ack):
            result = self.run_request(
                repository,
                observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:00Z", 110)),
                transport=transport,
            )
        self.assertEqual(
            result.admission.reason, runtime.BlockReason.STATE_REPOSITORY_FAILURE.value
        )
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.repository().current_state().active_executions, 1)

    def test_lost_completion_acknowledgement_retains_terminal_record_without_second_call(
        self,
    ) -> None:
        repository = self.repository()
        original = repository.complete

        def lose_ack(*arguments: object) -> runtime.StateTransition:
            original(*arguments)
            raise leaf.SQLiteExecutionStateError(
                "Synthetic completion acknowledgement lost after commit"
            )

        transport = FakeTransport()
        with patch.object(repository, "complete", side_effect=lose_ack):
            uncertain = self.run_request(repository, transport=transport)
        self.assertEqual(uncertain.execution.status, runtime.ExecutionStatus.COMPLETION_FAILED)
        stored = repository.lookup(binding(), "idempotency:001")
        self.assertEqual(stored.execution.status, runtime.ExecutionStatus.SUCCEEDED)
        replay = self.run_request(self.repository(), observations=FakeClock(), transport=transport)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(replay.execution, stored.execution)
        self.assertEqual(transport.calls, 1)

    def test_retry_dispositions_and_adverse_terminal_evidence_are_preserved(self) -> None:
        for index, (attempt, failure, expected) in enumerate(
            (
                (1, "temporary_failure", runtime.RetryDisposition.RETRY_PERMITTED),
                (2, "temporary_failure", runtime.RetryDisposition.RETRY_EXHAUSTED),
                (1, "permanent_failure", runtime.RetryDisposition.FAILURE_NOT_RETRYABLE),
            )
        ):
            with self.subTest(attempt=attempt, failure=failure):
                self.path = self.directory / f"retry-{index}.sqlite"
                item = request(
                    self.policy,
                    attempt_number=attempt,
                    prior_execution_sha256=digest("a") if attempt > 1 else None,
                )
                transport = FakeTransport(False, failure)
                result = self.run_request(self.repository(), item=item, transport=transport)
                self.assertEqual(result.execution.retry_disposition, expected)
                self.assertEqual(
                    result.execution.cleanup_status,
                    runtime.CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
                )
                self.assertEqual(
                    self.repository().lookup(binding(), item.idempotency_key).execution,
                    result.execution,
                )
                self.assertEqual(transport.calls, 1)

    def test_transport_callback_mutation_isolated_and_not_reported_as_success(self) -> None:
        repository = self.repository()
        transport = FakeTransport()

        def mutate(envelope: runtime.TransportEnvelope) -> runtime.TransportObservation:
            object.__setattr__(envelope.binding, "tenant_id", "tenant:mutated")
            return runtime.TransportObservation(True, None, digest("9"), 17)

        with patch.object(transport, "execute", side_effect=mutate) as execute:
            result = self.run_request(repository, transport=transport)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(result.execution.status, runtime.ExecutionStatus.TRANSPORT_FAILED)
        self.assertEqual(result.execution.transport_failure_code, "transport_exception")
        self.assertEqual(repository.current_state().binding.tenant_id, "tenant:alpha")
        self.assertEqual(repository.current_state().active_executions, 0)

    def test_impossible_completion_relationships_reject_atomically_and_keep_hold(self) -> None:
        repository = self.repository()
        reserved = self.pending(repository)
        original = self.candidate()
        changes = (
            {"request_id": "request:other"},
            {"request_sha256": digest("a")},
            {"admission_receipt_sha256": digest("b")},
            {"completed_at": "2026-09-20T12:00:02Z"},
            {"monotonic_tick": 112},
            {"reservation_state_sha256": digest("c")},
            {"completion_state_sha256": digest("d")},
            {"retry_disposition": runtime.RetryDisposition.RETRY_PERMITTED},
            {"cleanup_required": False, "cleanup_status": runtime.CleanupStatus.NOT_REQUIRED},
            {"status": runtime.ExecutionStatus.COMPLETION_FAILED, "completion_state_sha256": None},
        )
        before = self.logical_dump()
        for change in changes:
            altered = replace(
                original,
                execution=replace(original.execution, **change, receipt_id="", receipt_sha256=""),
            )
            with self.subTest(change=change), self.assertRaises(leaf.SQLiteExecutionStateError):
                repository.complete(
                    request(self.policy),
                    reserved,
                    runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                    altered,
                )
            self.assertEqual(self.logical_dump(), before)
        valid = repository.complete(
            request(self.policy),
            reserved,
            runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
            original,
        )
        self.assertEqual(valid.after.active_executions, 0)

    def test_native_receipt_aliases_and_original_addresses_are_required(self) -> None:
        repository = self.repository()
        reserved = self.pending(repository)
        original = self.candidate()
        before = self.logical_dump()
        for field, value in (
            ("response_size_bytes", 17.0),
            ("transport_succeeded", 1),
            ("cleanup_required", 1),
            ("monotonic_tick", 111.0),
            ("receipt_id", ""),
            ("receipt_sha256", ""),
        ):
            altered = copy.deepcopy(original)
            object.__setattr__(altered.execution, field, value)
            with self.subTest(field=field), self.assertRaises(leaf.SQLiteExecutionStateError):
                repository.complete(
                    request(self.policy),
                    reserved,
                    runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                    altered,
                )
            self.assertEqual(self.logical_dump(), before)

    def test_stale_cas_foreign_request_and_repeated_completion_do_not_change_history(self) -> None:
        repository = self.repository()
        reserved = self.pending(repository)
        before = self.logical_dump()
        for item, selected_state in (
            (request(self.policy, idempotency_key="idempotency:other"), reserved),
            (
                request(self.policy),
                replace(reserved, state_version=reserved.state_version + 1, state_sha256=""),
            ),
        ):
            with self.assertRaises(leaf.SQLiteExecutionStateError):
                repository.complete(
                    item,
                    selected_state,
                    runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                    self.candidate(),
                )
            self.assertEqual(self.logical_dump(), before)
        repository.complete(
            request(self.policy),
            reserved,
            runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
            self.candidate(),
        )
        before = self.logical_dump()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            repository.complete(
                request(self.policy),
                reserved,
                runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                self.candidate(),
            )
        self.assertEqual(self.logical_dump(), before)

    def test_raw_sql_immutable_rows_and_replace_are_denied(self) -> None:
        self.run_request(self.repository())
        with database(self.path) as connection:
            for table in ("execution_metadata", "reservations", "completions", "control_head"):
                with self.subTest(table=table):
                    for sql in (
                        f"DELETE FROM {table}",
                        f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}",
                    ):
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(sql)
                    if table != "control_head":
                        field = (
                            "config_sha256" if table == "execution_metadata" else "record_sha256"
                        )
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(f"UPDATE {table} SET {field}={field}")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE control_head SET state_version=state_version+2")

    def test_rehashed_impossible_historical_completion_and_head_are_rejected(self) -> None:
        repository = self.repository()
        self.run_request(repository)
        before = repository.current_state()
        with database(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TRIGGER completions_no_update")
            row = dict(connection.execute("SELECT * FROM completions").fetchone())
            altered = replace(
                self.candidate().execution,
                completed_at="2026-09-20T12:00:02Z",
                receipt_id="",
                receipt_sha256="",
            )
            row["outcome_json"] = leaf._dump(
                replace(self.candidate(), execution=altered), runtime.StoredExecution
            )
            row["record_sha256"] = leaf._record_digest(
                "completion",
                {name: value for name, value in row.items() if name != "record_sha256"},
                repository._config()[2],
            )
            connection.execute(
                "UPDATE completions SET outcome_json=?,record_sha256=?",
                (row["outcome_json"], row["record_sha256"]),
            )
            connection.execute(leaf._SCHEMA_OBJECTS["completions_no_update"])
            with self.assertRaises(leaf.SQLiteExecutionStateError):
                repository._history(connection)
            connection.rollback()
        self.assertEqual(repository.current_state(), before)
        with database(self.path) as connection:
            connection.execute("DROP TRIGGER control_head_step")
            changed = replace(before, bytes_used=101, state_sha256="")
            connection.execute(
                "UPDATE control_head SET state_sha256=?,state_json=?",
                (changed.state_sha256, leaf._dump(changed, runtime.ControlState)),
            )
            connection.execute(leaf._SCHEMA_OBJECTS["control_head_step"])
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            repository.lookup(binding(), "idempotency:001")

    def test_orphan_and_missing_reciprocal_records_are_rejected(self) -> None:
        repository = self.repository()
        self.run_request(repository)
        with database(self.path) as connection:
            connection.row_factory = sqlite3.Row
            for table in ("reservations", "completions"):
                connection.execute("BEGIN")
                connection.execute(f"DROP TRIGGER {table}_no_delete")
                connection.execute(f"DELETE FROM {table}")
                connection.execute(leaf._SCHEMA_OBJECTS[f"{table}_no_delete"])
                with self.subTest(table=table), self.assertRaises(leaf.SQLiteExecutionStateError):
                    repository._history(connection)
                connection.rollback()
        self.assertIsNotNone(repository.lookup(binding(), "idempotency:001"))

    def test_parser_rejects_duplicate_noncanonical_float_and_oversized_inputs(self) -> None:
        for document in (
            '{"x":1,"x":1}',
            '{"x":1.0}',
            '{"x":NaN}',
            '{"x": true}',
            '{"x":9223372036854775808}',
            '{"x":' + "[" * 20 + "0" + "]" * 20 + "}",
            " " * (leaf.MAX_DOCUMENT_BYTES + 1),
        ):
            with (
                self.subTest(prefix=document[:40]),
                self.assertRaises(leaf.SQLiteExecutionStateError),
            ):
                leaf._load(document)
        changed = copy.deepcopy(request(self.policy))
        object.__setattr__(changed, "payload_size_bytes", 1 << 100000)
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.run_request(self.repository(), item=changed)

    def test_sql_projection_and_aggregate_ceiling_precede_raw_document_decode(self) -> None:
        repository = self.repository()
        self.pending(repository)
        with database(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            connection.execute("DROP TRIGGER reservations_no_update")
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE reservations SET request_json=?", ("x" * (leaf.MAX_DOCUMENT_BYTES + 1),)
            )
            connection.execute(leaf._SCHEMA_OBJECTS["reservations_no_update"])
            original_load = leaf._load

            def bounded(document: str) -> dict[str, object]:
                self.assertLessEqual(len(document), leaf.MAX_DOCUMENT_BYTES)
                return original_load(document)

            with (
                patch.object(leaf, "_load", side_effect=bounded),
                self.assertRaises(leaf.SQLiteExecutionStateError),
            ):
                repository._history(connection)
            connection.rollback()
            with (
                patch.object(leaf, "MAX_HISTORY_BYTES", 1),
                patch.object(repository, "_rows") as rows,
            ):
                with self.assertRaises(leaf.SQLiteExecutionStateError):
                    repository._history(connection)
                rows.assert_not_called()

    def test_busy_transaction_fails_closed_without_dispatch_or_retry(self) -> None:
        repository = self.repository()
        with database(self.path) as holder:
            holder.execute("BEGIN IMMEDIATE")
            transport = FakeTransport()
            result = self.run_request(
                repository,
                observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:00Z", 110)),
                transport=transport,
            )
            self.assertEqual(
                result.admission.reason, runtime.BlockReason.STATE_REPOSITORY_FAILURE.value
            )
            self.assertEqual(transport.calls, 0)
            holder.rollback()
        self.assertEqual(repository.current_state(), self.initial)

    def test_existing_empty_foreign_and_wrong_identity_databases_are_not_adopted(self) -> None:
        for kind in ("empty", "foreign", "wrong_application", "wrong_version", "unknown_table"):
            with self.subTest(kind=kind):
                self.path = self.directory / f"{kind}.sqlite"
                if kind in ("wrong_application", "wrong_version", "unknown_table"):
                    self.repository()
                else:
                    with database(self.path) as connection:
                        if kind == "foreign":
                            connection.execute("CREATE TABLE unrelated(value TEXT)")
                            connection.execute("INSERT INTO unrelated VALUES('foreign')")
                with database(self.path) as connection:
                    if kind == "wrong_application":
                        connection.execute("PRAGMA application_id=123")
                    elif kind == "wrong_version":
                        connection.execute("PRAGMA user_version=900")
                    elif kind == "unknown_table":
                        connection.execute("CREATE TABLE unrelated(value TEXT)")
                before = self.path.read_bytes()
                with self.assertRaises(leaf.SQLiteExecutionStateError):
                    self.repository()
                self.assertEqual(self.path.read_bytes(), before)

    def test_actual_mission_store_is_refused_without_logical_writes(self) -> None:
        from sunderkey.store import MissionStore

        MissionStore(self.path).initialize()
        before = self.logical_dump()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository()
        self.assertEqual(self.logical_dump(), before)

    def test_foreign_hot_journal_is_not_recovered_before_refusal(self) -> None:
        with database(self.path) as connection:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
            connection.executemany("INSERT INTO unrelated VALUES(?)", [("a" * 4000,)] * 128)
        script = (
            "import os, sqlite3, sys; c=sqlite3.connect(sys.argv[1]); "
            "c.execute('PRAGMA journal_mode=DELETE'); c.execute('PRAGMA synchronous=FULL'); "
            "c.execute('PRAGMA cache_size=5'); c.execute('BEGIN IMMEDIATE'); "
            "c.execute(\"UPDATE unrelated SET value=replace(value,'a','b')\"); os._exit(0)"
        )
        subprocess.run([sys.executable, "-B", "-c", script, str(self.path)], check=True)
        journal = Path(str(self.path) + "-journal")
        self.assertTrue(journal.is_file())
        self.assertEqual(journal.read_bytes()[:8], bytes.fromhex("d9d505f920a163d7"))
        before = (hashlib.sha256(self.path.read_bytes()).digest(), journal.read_bytes())
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository()
        self.assertEqual(
            (hashlib.sha256(self.path.read_bytes()).digest(), journal.read_bytes()), before
        )

    def test_persistent_wal_is_rejected_without_switching_or_dispatch(self) -> None:
        repository = self.repository()
        with database(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        before = self.path.read_bytes()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository()
        transport = FakeTransport()
        result = self.run_request(
            repository,
            observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:00Z", 110)),
            transport=transport,
        )
        self.assertEqual(
            result.admission.reason, runtime.BlockReason.STATE_REPOSITORY_FAILURE.value
        )
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.path.read_bytes(), before)
        with database(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_owned_connections_pin_delete_full_foreign_keys_and_zero_wait(self) -> None:
        repository = self.repository()
        with repository._transaction(write=True) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 0)

    def test_absence_race_empty_file_is_not_adopted(self) -> None:
        original = leaf.SQLiteExecutionStateRepository._exclusive_create

        def race(path: str) -> None:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
            original(path)

        with (
            patch.object(
                leaf.SQLiteExecutionStateRepository, "_exclusive_create", side_effect=race
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertEqual(self.path.read_bytes(), b"")

    def test_absence_race_hardlink_substitution_does_not_initialize_foreign_file(self) -> None:
        foreign = self.directory / "foreign.sqlite"
        with database(foreign):
            pass
        original = leaf.SQLiteExecutionStateRepository._exclusive_create

        def race(path: str) -> None:
            os.link(foreign, path)
            original(path)

        before = foreign.read_bytes()
        with (
            patch.object(
                leaf.SQLiteExecutionStateRepository, "_exclusive_create", side_effect=race
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(foreign.read_bytes(), before)

    def test_real_final_symlink_is_refused_where_os_privileges_allow(self) -> None:
        foreign = self.directory / "foreign.sqlite"
        with database(foreign):
            pass
        try:
            self.path.symlink_to(foreign)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows account lacks native symlink creation privilege")
            raise
        before = foreign.read_bytes()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository()
        self.assertEqual(foreign.read_bytes(), before)

    def test_mocked_late_final_symlink_flag_denies_open_not_os_containment(self) -> None:
        repository = self.repository()
        with (
            patch.object(Path, "is_symlink", return_value=True),
            patch.object(leaf.sqlite3, "connect") as connect,
        ):
            with self.assertRaises(leaf.SQLiteExecutionStateError):
                repository.current_state()
            connect.assert_not_called()

    def test_path_subset_rejects_uri_unc_device_relative_and_missing_parent(self) -> None:
        values = [
            "relative.sqlite",
            "file:execution.sqlite?mode=rwc",
            "//host/share/db.sqlite",
            "\\\\host\\share\\db.sqlite",
            str(self.directory / "missing" / "db.sqlite"),
        ]
        if os.name == "nt":
            values.extend(
                [
                    "C:relative.sqlite",
                    "C:\\NUL",
                    "C:\\db.sqlite:stream",
                    "C:\\a\\..\\db.sqlite",
                    "C:\\a\\\\db.sqlite",
                    "C:\\db.sqlite.",
                ]
            )
        for value in values:
            with self.subTest(path=value), self.assertRaises(leaf.SQLiteExecutionStateError):
                self.repository(database_path=value)
        self.assertFalse((self.directory / "missing").exists())

    def test_timestamp_spelling_and_integer_boundary_preserve_existing_domains(self) -> None:
        self.initial = state(self.policy, last_observed_at="2026-09-20T11:59:30.000001Z")
        repository = self.repository()
        result = self.run_request(
            repository,
            observations=FakeClock(
                runtime.ClockObservation("2026-09-20T12:00:00.123456Z", 110),
                runtime.ClockObservation("2026-09-20T12:00:01.234567Z", 111),
            ),
        )
        self.assertEqual(result.admission.observed_at, "2026-09-20T12:00:00.123456Z")
        self.assertEqual(result.execution.completed_at, "2026-09-20T12:00:01.234567Z")
        self.assertEqual(
            self.repository().lookup(binding(), "idempotency:001").execution, result.execution
        )

    def test_admission_and_outer_outcome_are_reciprocally_bound(self) -> None:
        repository = self.repository()
        reserved = self.pending(repository)
        original = self.candidate()
        before = self.logical_dump()
        variants = (
            replace(original, request_sha256=digest("e")),
            *(
                replace(
                    original,
                    admission=replace(
                        original.admission, **change, receipt_id="", receipt_sha256=""
                    ),
                )
                for change in (
                    {"observed_at": "2026-09-20T12:00:00.000001Z"},
                    {"monotonic_tick": 109},
                    {"state_before_sha256": digest("b")},
                    {"state_after_sha256": digest("c")},
                    {"policy_sha256": digest("d")},
                    {
                        "status": runtime.AdmissionStatus.BLOCKED,
                        "reason": runtime.BlockReason.RATE_EXHAUSTED.value,
                    },
                )
            ),
        )
        for altered in variants:
            with (
                self.subTest(admission=altered.admission.receipt_id),
                self.assertRaises(leaf.SQLiteExecutionStateError),
            ):
                repository.complete(
                    request(self.policy),
                    reserved,
                    runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                    altered,
                )
            self.assertEqual(self.logical_dump(), before)

    def test_rehashed_reservation_budget_and_clock_corruption_fail_reconstruction(self) -> None:
        repository = self.repository()
        self.pending(repository)
        with database(self.path) as connection:
            connection.row_factory = sqlite3.Row
            for field, changed in (
                ("before_json", replace(self.initial, bytes_used=1, state_sha256="")),
                (
                    "reserved_json",
                    replace(repository.current_state(), requests_used=2, state_sha256=""),
                ),
                ("observation_json", runtime.ClockObservation("2026-09-20T11:59:00Z", 110)),
            ):
                connection.execute("BEGIN")
                row = dict(connection.execute("SELECT * FROM reservations").fetchone())
                row[field] = leaf._dump(changed, type(changed))
                row["record_sha256"] = leaf._record_digest(
                    "reservation",
                    {name: value for name, value in row.items() if name != "record_sha256"},
                    repository._config()[2],
                )
                connection.execute("DROP TRIGGER reservations_no_update")
                connection.execute(
                    f"UPDATE reservations SET {field}=?,record_sha256=?",
                    (row[field], row["record_sha256"]),
                )
                connection.execute(leaf._SCHEMA_OBJECTS["reservations_no_update"])
                with self.subTest(field=field), self.assertRaises(leaf.SQLiteExecutionStateError):
                    repository._history(connection)
                connection.rollback()
        self.assertEqual(repository.current_state().bytes_used, 100)

    def test_atomic_write_failure_rolls_back_reservation_and_completion_rows(self) -> None:
        repository = self.repository()
        before = self.logical_dump()
        with (
            patch.object(
                repository,
                "_advance",
                side_effect=leaf.SQLiteExecutionStateError("Synthetic CAS failed"),
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.pending(repository)
        self.assertEqual(self.logical_dump(), before)
        reserved = self.pending(repository)
        before = self.logical_dump()
        with (
            patch.object(
                repository,
                "_advance",
                side_effect=leaf.SQLiteExecutionStateError("Synthetic CAS failed"),
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            repository.complete(
                request(self.policy),
                reserved,
                runtime.ClockObservation("2026-09-20T12:00:01Z", 111),
                self.candidate(),
            )
        self.assertEqual(self.logical_dump(), before)
        self.assertEqual(repository.current_state().active_executions, 1)

    def test_invalid_native_clock_never_authorizes_transport_or_releases_hold(self) -> None:
        repository = self.repository()
        invalid = runtime.ClockObservation("2026-09-20T12:00:01Z", 111)
        object.__setattr__(invalid, "monotonic_tick", 111.0)
        transport = FakeTransport()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.run_request(repository, observations=FakeClock(invalid), transport=transport)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(repository.current_state(), self.initial)
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.run_request(
                repository,
                observations=FakeClock(
                    runtime.ClockObservation("2026-09-20T12:00:00Z", 110), invalid
                ),
                transport=transport,
            )
        self.assertEqual(transport.calls, 1)
        self.assertEqual(repository.current_state().active_executions, 1)

    def test_uncertain_initialization_file_is_preserved_and_never_reinitialized(self) -> None:
        with (
            patch.object(
                leaf.SQLiteExecutionStateRepository,
                "_history",
                side_effect=leaf.SQLiteExecutionStateError("Synthetic initialization failure"),
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertTrue(self.path.is_file())
        before = self.path.read_bytes()
        with self.assertRaises(leaf.SQLiteExecutionStateError):
            self.repository()
        self.assertEqual(self.path.read_bytes(), before)

    def test_record_hashes_bind_namespace_without_changing_original_receipts(self) -> None:
        first = self.repository()
        first_result = self.run_request(first)
        self.path = self.directory / "different-namespace.sqlite"
        second = self.repository(namespace="namespace:other")
        second_result = self.run_request(second)
        self.assertEqual(first_result.execution, second_result.execution)
        with (
            first._transaction(write=False) as first_connection,
            second._transaction(write=False) as second_connection,
        ):
            first_hash = first_connection.execute(
                "SELECT record_sha256 FROM reservations"
            ).fetchone()[0]
            second_hash = second_connection.execute(
                "SELECT record_sha256 FROM reservations"
            ).fetchone()[0]
        self.assertNotEqual(first_hash, second_hash)

    def test_capacity_and_arithmetic_overflow_refuse_new_transport(self) -> None:
        repository = self.repository()
        self.run_request(repository)
        before = self.logical_dump()
        transport = FakeTransport()
        with patch.object(leaf, "MAX_HISTORY_RECORDS", 1):
            blocked = self.run_request(
                repository,
                item=request(self.policy, idempotency_key="idempotency:second"),
                observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:02Z", 112)),
                transport=transport,
            )
        self.assertEqual(
            blocked.admission.reason, runtime.BlockReason.STATE_REPOSITORY_FAILURE.value
        )
        self.assertEqual(self.logical_dump(), before)
        self.assertEqual(transport.calls, 0)
        self.path = self.directory / "version-overflow.sqlite"
        self.initial = state(self.policy, state_version=leaf.MAX_INTEGER)
        before = self.repository().current_state()
        blocked = self.run_request(
            self.repository(),
            observations=FakeClock(runtime.ClockObservation("2026-09-20T12:00:00Z", 110)),
            transport=transport,
        )
        self.assertEqual(
            blocked.admission.reason, runtime.BlockReason.STATE_REPOSITORY_FAILURE.value
        )
        self.assertEqual(self.repository().current_state(), before)
        self.assertEqual(transport.calls, 0)

    def test_foreign_ownership_preflight_never_opens_rw_or_writes_pragmas(self) -> None:
        with database(self.path) as connection:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
            connection.execute("INSERT INTO unrelated VALUES('foreign')")
        before = self.path.read_bytes()
        original = sqlite3.connect
        modes: list[str] = []
        statements: list[str] = []

        def traced(path: str, **options: object) -> sqlite3.Connection:
            modes.append(path.split("?mode=")[-1])
            connection = original(path, **options)
            connection.set_trace_callback(statements.append)
            return connection

        with (
            patch.object(leaf.sqlite3, "connect", side_effect=traced),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertEqual(modes, ["ro"])
        self.assertFalse(any("=" in sql for sql in statements if sql.startswith("PRAGMA")))
        self.assertEqual(self.path.read_bytes(), before)

    def test_exclusive_file_identity_survives_until_first_sqlite_open(self) -> None:
        original = leaf.SQLiteExecutionStateRepository._exclusive_create
        captured = self.directory / "captured-original.sqlite"

        def substitute(path: str):
            identity = original(path)
            os.rename(path, captured)
            with database(Path(path)):
                pass
            return identity

        with (
            patch.object(
                leaf.SQLiteExecutionStateRepository, "_exclusive_create", side_effect=substitute
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertEqual(self.path.read_bytes(), b"")
        self.assertEqual(captured.read_bytes(), b"")

    def test_same_inode_foreign_hot_journal_after_exclusive_create_is_preserved(self) -> None:
        original = leaf.SQLiteExecutionStateRepository._exclusive_create
        captured: list[tuple[bytes, bytes]] = []
        journal = Path(str(self.path) + "-journal")

        def substitute(path: str):
            identity = original(path)
            with database(Path(path)) as connection:
                connection.execute("CREATE TABLE unrelated(value TEXT)")
                connection.executemany("INSERT INTO unrelated VALUES(?)", [("a" * 4000,)] * 128)
            script = (
                "import os, sqlite3, sys; c=sqlite3.connect(sys.argv[1]); "
                "c.execute('PRAGMA journal_mode=DELETE'); c.execute('PRAGMA synchronous=FULL'); "
                "c.execute('PRAGMA cache_size=5'); c.execute('BEGIN IMMEDIATE'); "
                "c.execute(\"UPDATE unrelated SET value=replace(value,'a','b')\"); os._exit(0)"
            )
            subprocess.run([sys.executable, "-B", "-c", script, path], check=True)
            captured.append((hashlib.sha256(self.path.read_bytes()).digest(), journal.read_bytes()))
            return identity

        with (
            patch.object(
                leaf.SQLiteExecutionStateRepository, "_exclusive_create", side_effect=substitute
            ),
            self.assertRaises(leaf.SQLiteExecutionStateError),
        ):
            self.repository()
        self.assertTrue(journal.exists())
        self.assertEqual(
            (hashlib.sha256(self.path.read_bytes()).digest(), journal.read_bytes()), captured[0]
        )

    @unittest.skipUnless(os.name == "nt", "Windows-specific conservative device path grammar")
    def test_all_device_spellings_are_rejected_before_file_or_sqlite_open(self) -> None:
        values = (
            "CONIN$",
            "CONOUT$.sqlite",
            "CLOCK$",
            "COM1",
            "LPT9.sqlite",
            "COM\u00b9",
            "LPT\u00b2",
        )
        for value in values:
            with (
                self.subTest(value=value),
                patch.object(leaf.os, "open") as open_file,
                patch.object(leaf.sqlite3, "connect") as connect,
            ):
                with self.assertRaises(leaf.SQLiteExecutionStateError):
                    leaf._local_path(str(self.directory / value))
                open_file.assert_not_called()
                connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
