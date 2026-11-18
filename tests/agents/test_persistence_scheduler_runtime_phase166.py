from __future__ import annotations

import json
import socket
import sqlite3
import tempfile
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from sunderkey.durable_scheduler_contracts import (
    CompletionResolution,
    CompletionStatus,
    MisfirePolicy,
    create_retry_backoff_plan,
    create_schedule_definition,
)
from sunderkey.persistence_port_contracts import (
    AggregateVersionBinding,
    FenceBinding,
    IsolationLevel,
    OperationKind,
    TransactionBatch,
    TransactionOperation,
)
from sunderkey.persistence_scheduler_runtime import (
    SQLITE_MIGRATION_ID,
    SQLITE_MIGRATION_SHA256,
    ConcurrencyConflict,
    IdempotencyConflict,
    MigrationIdentityError,
    SQLitePersistenceSchedulerRuntime,
    StoreBusyError,
    TenantIsolationError,
    postgresql_conformance_metadata,
    runtime_manifest,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


@dataclass
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


def _schedule(tenant: str = "tenant-a"):
    retry = create_retry_backoff_plan(
        max_attempts=3,
        retry_budget_units=2,
        retry_cost_units=1,
        base_delay_seconds=5,
        multiplier=2,
        maximum_delay_seconds=60,
    )
    return create_schedule_definition(
        tenant_id=tenant,
        assessment_template_ref="template-main",
        scope_sha256=DIGEST_A,
        authority_evidence_sha256=DIGEST_B,
        definition_version=1,
        starts_at="2026-01-01T00:00:00Z",
        ends_at=None,
        interval_seconds=60,
        max_occurrences=4,
        max_occurrences_per_evaluation=4,
        concurrency_limit=2,
        lease_duration_seconds=30,
        clock_skew_tolerance_seconds=0,
        misfire_policy=MisfirePolicy.CATCH_UP_BOUNDED,
        max_catch_up_occurrences=4,
        retry_plan=retry,
    )


def _batch(
    *,
    key: str = "idem:transaction:0000000000000001",
    expected: int = 0,
    digest: str = DIGEST_A,
    event: str = "outboxref:event-1",
) -> TransactionBatch:
    aggregate = "aggregateref:assessment-1"
    return TransactionBatch(
        tenant_ref="tenantref:tenant-a",
        assessment_ref="assessmentref:assessment-1",
        scope_ref="scoperef:scope-1",
        idempotency_key=key,
        isolation_level=IsolationLevel.SERIALIZABLE,
        created_at="2026-01-01T00:00:00Z",
        operations=(
            TransactionOperation(
                operation_ref="operationref:append-" + key[-1],
                kind=OperationKind.APPEND,
                aggregate_ref=aggregate,
                content_sha256=digest,
            ),
            TransactionOperation(
                operation_ref="operationref:outbox-" + key[-1],
                kind=OperationKind.OUTBOX_ENQUEUE,
                aggregate_ref=aggregate,
                content_sha256=digest,
            ),
        ),
        version_bindings=(AggregateVersionBinding(aggregate, expected),),
        fence_bindings=(
            FenceBinding(
                resource_ref="resourceref:assessment-1",
                fence_token="fence:assessment-000000000001",
                fence_epoch=1,
            ),
        ),
        outbox_event_refs=(event,),
    )


class PersistenceSchedulerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "runtime.sqlite3"
        self.clock = FixedClock(datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC))
        self.runtime = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)

    def test_migration_identity_is_stable_across_reopen(self) -> None:
        self.assertEqual(
            self.runtime.migration_identity(),
            (SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256),
        )
        reopened = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
        self.assertEqual(reopened.migration_identity(), self.runtime.migration_identity())

    def test_migration_identity_tampering_fails_closed(self) -> None:
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE schema_migrations SET migration_sha256=? WHERE version=1", (DIGEST_C,)
        )
        connection.commit()
        connection.close()
        with self.assertRaises(MigrationIdentityError):
            SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)

    def test_transaction_is_atomic_and_idempotent(self) -> None:
        self.runtime.install_fence(
            "tenantref:tenant-a",
            "resourceref:assessment-1",
            "fence:assessment-000000000001",
            1,
        )
        batch = _batch()
        first = self.runtime.apply_transaction(batch)
        replay = self.runtime.apply_transaction(batch)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(
            self.runtime.aggregate_version("tenantref:tenant-a", "aggregateref:assessment-1"),
            1,
        )
        self.assertEqual(self.runtime.outbox_events("tenantref:tenant-a"), ("outboxref:event-1",))

    def test_duplicate_idempotency_and_stale_fence_are_rejected(self) -> None:
        self.runtime.install_fence(
            "tenantref:tenant-a",
            "resourceref:assessment-1",
            "fence:assessment-000000000001",
            1,
        )
        self.runtime.apply_transaction(_batch())
        with self.assertRaises(IdempotencyConflict):
            self.runtime.apply_transaction(_batch(digest=DIGEST_B))
        self.runtime.install_fence(
            "tenantref:tenant-a",
            "resourceref:assessment-1",
            "fence:assessment-000000000002",
            2,
        )
        with self.assertRaises(ConcurrencyConflict):
            self.runtime.apply_transaction(
                _batch(
                    key="idem:transaction:0000000000000002", expected=1, event="outboxref:event-2"
                )
            )

    def test_outbox_conflict_rolls_back_aggregate(self) -> None:
        self.runtime.install_fence(
            "tenantref:tenant-a",
            "resourceref:assessment-1",
            "fence:assessment-000000000001",
            1,
        )
        self.runtime.apply_transaction(_batch())
        conflicting = _batch(
            key="idem:transaction:0000000000000002",
            expected=1,
            digest=DIGEST_B,
            event="outboxref:event-1",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.runtime.apply_transaction(conflicting)
        self.assertEqual(
            self.runtime.aggregate_version("tenantref:tenant-a", "aggregateref:assessment-1"),
            1,
        )

    def test_tenant_crossover_is_rejected(self) -> None:
        self.runtime.install_fence(
            "tenantref:tenant-a",
            "resourceref:assessment-1",
            "fence:assessment-000000000001",
            1,
        )
        self.runtime.apply_transaction(_batch())
        with self.assertRaises(TenantIsolationError):
            self.runtime.aggregate_version("tenantref:tenant-b", "aggregateref:assessment-1")

    def test_multiple_connections_and_bounded_lock_contention(self) -> None:
        contender = SQLitePersistenceSchedulerRuntime(
            self.path, clock=self.clock, busy_timeout_seconds=0.01
        )
        holder = sqlite3.connect(self.path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(StoreBusyError):
                contender.install_fence(
                    "tenantref:tenant-a",
                    "resourceref:locked",
                    "fence:locked-0000000000000001",
                    1,
                )
        finally:
            holder.rollback()
            holder.close()

    def test_claim_heartbeat_completion_and_reopen(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        due = self.runtime.materialize_due(
            schedule.tenant_id, schedule.schedule_id, evaluated_at="2026-01-01T00:00:10Z"
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000001",
            claimed_at="2026-01-01T00:00:10Z",
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        heartbeat = self.runtime.heartbeat(
            schedule.tenant_id,
            lease.lease_id,
            expected_lease_version=1,
            expected_fence_epoch=1,
            idempotency_key="idem:heartbeat:0000000000001",
            observed_at="2026-01-01T00:00:20Z",
        )
        completion = self.runtime.complete(
            schedule.tenant_id,
            lease.lease_id,
            expected_lease_version=heartbeat.lease_version,
            expected_fence_epoch=heartbeat.fence_epoch,
            status=CompletionStatus.SUCCEEDED,
            evidence_sha256s=(DIGEST_C,),
            idempotency_key="idem:completion:0000000000001",
            observed_at="2026-01-01T00:00:25Z",
        )
        self.assertEqual(completion.resolution, CompletionResolution.COMPLETED)
        reopened = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
        self.assertEqual(
            reopened.occurrence_state(schedule.tenant_id, due[0].occurrence_id), ("completed", 2)
        )

    def test_transactional_claim_is_visible_to_independent_connection(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        self.runtime.materialize_due(
            schedule.tenant_id,
            schedule.schedule_id,
            evaluated_at="2026-01-01T00:00:10Z",
        )
        second = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
        claimed = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000010",
            claimed_at="2026-01-01T00:00:10Z",
        )
        self.assertIsNotNone(claimed)
        self.assertIsNone(
            second.claim_due(
                schedule.tenant_id,
                schedule.schedule_id,
                worker_ref="worker-2",
                idempotency_key="idem:claim:0000000000000011",
                claimed_at="2026-01-01T00:00:10Z",
            )
        )

    def test_completion_rejects_stale_fence(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        self.runtime.materialize_due(
            schedule.tenant_id, schedule.schedule_id, evaluated_at="2026-01-01T00:00:10Z"
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000002",
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert lease is not None
        with self.assertRaises(ConcurrencyConflict):
            self.runtime.complete(
                schedule.tenant_id,
                lease.lease_id,
                expected_lease_version=1,
                expected_fence_epoch=2,
                status=CompletionStatus.SUCCEEDED,
                evidence_sha256s=(),
                idempotency_key="idem:completion:0000000000002",
                observed_at="2026-01-01T00:00:20Z",
            )

    def test_retry_dead_letter_and_expired_lease_recovery(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        due = self.runtime.materialize_due(
            schedule.tenant_id, schedule.schedule_id, evaluated_at="2026-01-01T00:00:10Z"
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000003",
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert lease is not None
        completion = self.runtime.complete(
            schedule.tenant_id,
            lease.lease_id,
            expected_lease_version=1,
            expected_fence_epoch=1,
            status=CompletionStatus.RETRYABLE_FAILURE,
            evidence_sha256s=(),
            idempotency_key="idem:completion:0000000000003",
            observed_at="2026-01-01T00:00:20Z",
        )
        self.assertEqual(completion.resolution, CompletionResolution.RETRY_PLANNED)
        second = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-2",
            idempotency_key="idem:claim:0000000000000004",
            claimed_at=completion.retry_at,
        )
        assert second is not None
        recovered = self.runtime.recover_expired(
            schedule.tenant_id, recovered_at="2026-01-01T00:01:00Z"
        )
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].next_fence_epoch, second.fence_epoch + 1)
        self.assertEqual(
            self.runtime.occurrence_state(schedule.tenant_id, due[0].occurrence_id)[0], "retry"
        )

    def test_permanent_failure_is_dead_lettered(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        due = self.runtime.materialize_due(
            schedule.tenant_id,
            schedule.schedule_id,
            evaluated_at="2026-01-01T00:00:10Z",
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000012",
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert lease is not None
        completion = self.runtime.complete(
            schedule.tenant_id,
            lease.lease_id,
            expected_lease_version=1,
            expected_fence_epoch=1,
            status=CompletionStatus.PERMANENT_FAILURE,
            evidence_sha256s=(),
            idempotency_key="idem:completion:0000000000012",
            observed_at="2026-01-01T00:00:20Z",
        )
        self.assertEqual(completion.resolution, CompletionResolution.DEAD_LETTERED)
        self.assertEqual(
            self.runtime.occurrence_state(schedule.tenant_id, due[0].occurrence_id)[0],
            "dead_lettered",
        )

    def test_cancellation_revokes_active_lease(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        due = self.runtime.materialize_due(
            schedule.tenant_id, schedule.schedule_id, evaluated_at="2026-01-01T00:00:10Z"
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000005",
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert lease is not None
        cancellation = self.runtime.cancel_occurrence(
            schedule.tenant_id,
            due[0].occurrence_id,
            reason_code="operator_stop",
            idempotency_key="idem:cancellation:00000000001",
            requested_at="2026-01-01T00:00:20Z",
        )
        self.assertEqual(cancellation.revoked_lease_ids, (lease.lease_id,))
        self.assertEqual(
            self.runtime.occurrence_state(schedule.tenant_id, due[0].occurrence_id)[0], "cancelled"
        )

    def test_schedule_cancellation_is_atomic_and_replay_safe(self) -> None:
        schedule = self.runtime.register_schedule(_schedule())
        due = self.runtime.materialize_due(
            schedule.tenant_id,
            schedule.schedule_id,
            evaluated_at="2026-01-01T00:00:10Z",
        )
        lease = self.runtime.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key="idem:claim:0000000000000013",
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert lease is not None
        cancelled = self.runtime.cancel_schedule(
            schedule.tenant_id,
            schedule.schedule_id,
            reason_code="scope_revoked",
            idempotency_key="idem:cancellation:00000000013",
            requested_at="2026-01-01T00:00:20Z",
        )
        replay = self.runtime.cancel_schedule(
            schedule.tenant_id,
            schedule.schedule_id,
            reason_code="scope_revoked",
            idempotency_key="idem:cancellation:00000000013",
            requested_at="2026-01-01T00:00:20Z",
        )
        self.assertEqual(replay, cancelled)
        self.assertEqual(cancelled.revoked_lease_ids, (lease.lease_id,))
        self.assertEqual(
            self.runtime.occurrence_state(schedule.tenant_id, due[0].occurrence_id)[0],
            "cancelled",
        )

    def test_postgresql_metadata_is_environment_gated_and_nonqualifying(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            metadata = postgresql_conformance_metadata()
        self.assertFalse(metadata.configured)
        self.assertFalse(metadata.network_call_performed)
        self.assertFalse(metadata.live_proof)
        self.assertIn("skip-locked-due-claim", metadata.required_checks)

    def test_runtime_performs_no_network_calls(self) -> None:
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            reopened = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
            self.assertEqual(reopened.migration_identity()[0], SQLITE_MIGRATION_ID)

    def test_public_package_exports_runtime_boundary(self) -> None:
        import sunderkey

        self.assertIs(
            sunderkey.SQLitePersistenceSchedulerRuntime,
            SQLitePersistenceSchedulerRuntime,
        )
        self.assertIs(
            sunderkey.postgresql_conformance_metadata,
            postgresql_conformance_metadata,
        )
        self.assertEqual(sunderkey.persistence_runtime_manifest(), runtime_manifest())

    def test_schema_json_is_valid(self) -> None:
        schema = json.loads(
            Path("registry/schemas/persistence-scheduler-runtime-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(runtime_manifest())


if __name__ == "__main__":
    unittest.main()
