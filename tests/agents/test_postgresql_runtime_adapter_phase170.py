"""Phase 170 PostgreSQL runtime adapter coverage."""

from __future__ import annotations

import copy
import json
import re
import socket
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.durable_artifact_recorder import (
    ArtifactMetadata,
    ArtifactRecordingRequest,
    OutboxEventMetadata,
    plan_artifact_recording,
    record_artifact,
)
from sunderkey.durable_scheduler_contracts import (
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
    ConcurrencyConflict,
    IdempotencyConflict,
    MigrationIdentityError,
    PersistenceRepository,
    PostgreSQLAdapter,
)
from sunderkey.postgresql_runtime_adapter import (
    POSTGRESQL_MIGRATION_ID,
    POSTGRESQL_MIGRATION_SHA256,
    POSTGRESQL_MIGRATION_VERSION,
    FailureDisposition,
    PostgreSQLAdapterError,
    PostgreSQLHealthObservation,
    PostgreSQLPersistenceSchedulerAdapter,
    PostgreSQLRetriableError,
    PostgreSQLTerminalError,
    PostgreSQLTransactionReceipt,
    classify_postgresql_failure,
    parse_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "postgresql-runtime-adapter-receipt-v1.schema.json"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class FakeDatabaseError(RuntimeError):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("redacted fake database failure")
        self.sqlstate = sqlstate


class FakeStore:
    def __init__(self) -> None:
        self.data: dict[str, Any] = {
            "migrations": {
                POSTGRESQL_MIGRATION_VERSION: {
                    "migration_id": POSTGRESQL_MIGRATION_ID,
                    "migration_sha256": POSTGRESQL_MIGRATION_SHA256,
                }
            },
            "fences": {},
            "aggregates": {},
            "batches": {},
            "outbox": {},
            "receipts": {},
            "schedules": {},
            "occurrences": {},
            "leases": {},
            "scheduler_results": {},
        }
        self.failures: dict[str, FakeDatabaseError] = {}
        self.executed_tags: list[str] = []
        self.commit_count = 0
        self.rollback_count = 0
        self.close_count = 0

    def factory(self) -> FakeConnection:
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, store: FakeStore) -> None:
        self.store = store
        self.working = copy.deepcopy(store.data)
        self.closed = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.store.data = self.working
        self.store.commit_count += 1

    def rollback(self) -> None:
        self.store.rollback_count += 1

    def close(self) -> None:
        self.closed = True
        self.store.close_count += 1


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.rowcount = -1
        self.rows: list[Any] = []
        self.closed = False

    def execute(self, operation: str, parameters: tuple[Any, ...] = ()) -> None:
        match = re.match(r"/\*sunderkey:([a-z-]+)\*/", operation)
        if match is None:
            raise AssertionError("SQL statement has no deterministic operation tag")
        tag = match.group(1)
        self.connection.store.executed_tags.append(tag)
        if tag in self.connection.store.failures:
            raise self.connection.store.failures[tag]
        handler = getattr(self, "_" + tag.replace("-", "_"), None)
        if handler is None:
            raise AssertionError(f"fake connection does not support {tag}")
        self.rows = []
        self.rowcount = -1
        handler(parameters)

    def fetchone(self) -> Any:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[Any]:
        return list(self.rows)

    def close(self) -> None:
        self.closed = True

    @property
    def data(self) -> dict[str, Any]:
        return self.connection.working

    def _transaction_isolation(self, parameters: tuple[Any, ...]) -> None:
        self.rowcount = 0

    def _migration_identity(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["migrations"].get(parameters[0])
        self.rows = [] if row is None else [row]

    def _health(self, parameters: tuple[Any, ...]) -> None:
        self.rows = [{"health": 1}]

    def _aggregate_version(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["aggregates"].get((parameters[0], parameters[1]))
        self.rows = [] if row is None else [{"version": row["version"]}]

    def _transaction_prior(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["batches"].get((parameters[0], parameters[1]))
        self.rows = (
            []
            if row is None
            else [{"tenant_ref": parameters[0], "idempotency_key": parameters[1], **row}]
        )

    def _fence_check(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["fences"].get((parameters[0], parameters[1]))
        self.rows = [] if row is None else [row]

    def _aggregate_lock(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["aggregates"].get((parameters[0], parameters[1]))
        self.rows = [] if row is None else [{"version": row["version"]}]

    def _aggregate_upsert(self, parameters: tuple[Any, ...]) -> None:
        tenant, aggregate, version, digest, expected = parameters
        key = (tenant, aggregate)
        prior = self.data["aggregates"].get(key)
        current = 0 if prior is None else prior["version"]
        if current != expected:
            self.rowcount = 0
            return
        self.data["aggregates"][key] = {"version": version, "content_sha256": digest}
        self.rowcount = 1

    def _outbox_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, event_ref, batch_id, document, created_at = parameters
        key = (tenant, event_ref)
        if key in self.data["outbox"]:
            raise FakeDatabaseError("23505")
        self.data["outbox"][key] = {
            "batch_id": batch_id,
            "event_json": document,
            "created_at": created_at,
        }
        self.rowcount = 1

    def _transaction_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, assessment, scope, key, batch_id, digest, document = parameters
        self.data["batches"][(tenant, key)] = {
            "assessment_ref": assessment,
            "scope_ref": scope,
            "batch_id": batch_id,
            "batch_sha256": digest,
            "batch_json": document,
        }
        self.rowcount = 1

    def _receipt_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, receipt_id, digest, document, created_at = parameters
        self.data["receipts"][(tenant, receipt_id)] = {
            "receipt_sha256": digest,
            "receipt_json": document,
            "created_at": created_at,
        }
        self.rowcount = 1

    def _schedule_prior(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["schedules"].get((parameters[0], parameters[1]))
        self.rows = (
            []
            if row is None
            else [{"tenant_id": parameters[0], "schedule_id": parameters[1], **row}]
        )

    def _schedule_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, schedule_id, digest, version, document = parameters
        self.data["schedules"][(tenant, schedule_id)] = {
            "schedule_sha256": digest,
            "definition_version": version,
            "schedule_json": document,
            "cancelled": False,
        }
        self.rowcount = 1

    def _schedule_load(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["schedules"].get((parameters[0], parameters[1]))
        self.rows = (
            []
            if row is None
            else [{"tenant_id": parameters[0], "schedule_id": parameters[1], **row}]
        )

    def _occurrence_indices(self, parameters: tuple[Any, ...]) -> None:
        tenant, schedule_id = parameters
        rows = [
            {"occurrence_index": row["occurrence_index"]}
            for (row_tenant, _), row in self.data["occurrences"].items()
            if row_tenant == tenant and row["schedule_id"] == schedule_id
        ]
        self.rows = sorted(rows, key=lambda row: row["occurrence_index"])

    def _occurrence_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, occurrence_id, schedule_id, index, document, version, ready_at = parameters
        duplicate = any(
            row_tenant == tenant
            and row["schedule_id"] == schedule_id
            and row["occurrence_index"] == index
            for (row_tenant, _), row in self.data["occurrences"].items()
        )
        if duplicate:
            self.rowcount = 0
            return
        self.data["occurrences"][(tenant, occurrence_id)] = {
            "occurrence_id": occurrence_id,
            "schedule_id": schedule_id,
            "occurrence_index": index,
            "occurrence_json": document,
            "occurrence_version": version,
            "state": "pending",
            "ready_at": ready_at,
            "attempt_number": 0,
            "fence_epoch": 0,
            "lease_id": None,
        }
        self.rowcount = 1

    def _scheduler_result(self, parameters: tuple[Any, ...]) -> None:
        row = self.data["scheduler_results"].get((parameters[0], parameters[1]))
        self.rows = (
            []
            if row is None
            else [{"tenant_id": parameters[0], "idempotency_key": parameters[1], **row}]
        )

    def _claim_candidate(self, parameters: tuple[Any, ...]) -> None:
        tenant, schedule_id, claimed = parameters
        candidates = [
            {"tenant_id": row_tenant, **row}
            for (row_tenant, _), row in self.data["occurrences"].items()
            if row_tenant == tenant
            and row["schedule_id"] == schedule_id
            and row["state"] in {"pending", "retry"}
            and row["ready_at"] <= claimed
        ]
        candidates.sort(key=lambda row: (row["ready_at"], row["occurrence_index"]))
        self.rows = candidates[:1]

    def _lease_snapshot(self, parameters: tuple[Any, ...]) -> None:
        tenant, lease_id, version = parameters
        row = self.data["leases"].get((tenant, lease_id, version))
        self.rows = (
            []
            if row is None
            else [{"tenant_id": tenant, "lease_id": lease_id, "lease_version": version, **row}]
        )

    def _lease_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, lease_id, version, occurrence_id, fence_epoch, expires_at, document = parameters
        self.data["leases"][(tenant, lease_id, version)] = {
            "occurrence_id": occurrence_id,
            "fence_epoch": fence_epoch,
            "expires_at": expires_at,
            "active": True,
            "lease_json": document,
        }
        self.rowcount = 1

    def _occurrence_claim(self, parameters: tuple[Any, ...]) -> None:
        attempt, fence, lease_id, tenant, occurrence_id, expected_version = parameters
        row = self.data["occurrences"].get((tenant, occurrence_id))
        if (
            row is None
            or row["occurrence_version"] != expected_version
            or row["state"] not in {"pending", "retry"}
        ):
            self.rowcount = 0
            return
        row.update(
            {
                "state": "leased",
                "attempt_number": attempt,
                "fence_epoch": fence,
                "lease_id": lease_id,
            }
        )
        self.rowcount = 1

    def _scheduler_result_insert(self, parameters: tuple[Any, ...]) -> None:
        tenant, key, digest, document = parameters
        self.data["scheduler_results"][(tenant, key)] = {
            "result_kind": "claim",
            "result_sha256": digest,
            "result_json": document,
        }
        self.rowcount = 1


@dataclass
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


def _batch(
    *,
    tenant: str = "tenantref:tenant-a",
    assessment: str = "assessmentref:assessment-1",
    scope: str = "scoperef:scope-1",
    key: str = "idem:postgresql-transaction-0001",
    expected: int = 0,
    digest: str = DIGEST_A,
    event_ref: str = "outboxref:event-1",
) -> TransactionBatch:
    aggregate = "aggregateref:assessment-1"
    return TransactionBatch(
        tenant_ref=tenant,
        assessment_ref=assessment,
        scope_ref=scope,
        idempotency_key=key,
        isolation_level=IsolationLevel.SERIALIZABLE,
        created_at="2026-09-20T12:00:00Z",
        operations=(
            TransactionOperation(
                operation_ref="operationref:append-1",
                kind=OperationKind.APPEND,
                aggregate_ref=aggregate,
                content_sha256=digest,
            ),
            TransactionOperation(
                operation_ref="operationref:outbox-1",
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
        outbox_event_refs=(event_ref,),
    )


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
        starts_at="2026-09-20T12:00:00Z",
        ends_at=None,
        interval_seconds=60,
        max_occurrences=3,
        max_occurrences_per_evaluation=3,
        concurrency_limit=2,
        lease_duration_seconds=30,
        clock_skew_tolerance_seconds=0,
        misfire_policy=MisfirePolicy.CATCH_UP_BOUNDED,
        max_catch_up_occurrences=3,
        retry_plan=retry,
    )


class PostgreSQLRuntimeAdapterPhase170Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = FakeStore()
        self.clock = FixedClock(datetime(2026, 9, 20, 12, 2, tzinfo=UTC))
        self.adapter = PostgreSQLPersistenceSchedulerAdapter(
            self.store.factory,
            clock=self.clock,
        )
        self.store.data["fences"][("tenantref:tenant-a", "resourceref:assessment-1")] = {
            "fence_token": "fence:assessment-000000000001",
            "fence_epoch": 1,
        }

    def test_adapter_satisfies_repository_and_postgresql_protocols(self) -> None:
        self.assertIsInstance(self.adapter, PersistenceRepository)
        self.assertIsInstance(self.adapter, PostgreSQLAdapter)

    def test_health_observation_binds_capabilities_and_migration_identity(self) -> None:
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            observation = self.adapter.observe_health(observed_at="2026-09-20T12:00:00Z")
        self.assertFalse(observation.live_deployment_proof)
        self.assertEqual(observation.to_dict()["qualification_effect"], "none")
        self.assertEqual(parse_receipt(observation.to_dict()), observation)
        self.assertIn("migration-identity", self.store.executed_tags)
        self.assertIn("health", self.store.executed_tags)

    def test_migration_absence_or_identity_mismatch_fails_closed(self) -> None:
        self.store.data["migrations"].clear()
        with self.assertRaises(MigrationIdentityError):
            self.adapter.migration_identity()
        self.store.data["migrations"][POSTGRESQL_MIGRATION_VERSION] = {
            "migration_id": POSTGRESQL_MIGRATION_ID,
            "migration_sha256": DIGEST_C,
        }
        with self.assertRaises(MigrationIdentityError):
            self.adapter.migration_identity()
        self.assertEqual(self.store.commit_count, 0)
        self.assertEqual(self.store.rollback_count, 2)

    def test_transaction_commit_replay_outbox_and_receipt_are_atomic(self) -> None:
        batch = _batch()
        first = self.adapter.apply_transaction_receipt(batch)
        replay = self.adapter.apply_transaction_receipt(batch)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.batch_id, replay.batch_id)
        self.assertNotEqual(first.receipt_id, replay.receipt_id)
        self.assertEqual(
            self.adapter.aggregate_version(batch.tenant_ref, "aggregateref:assessment-1"),
            1,
        )
        self.assertIn((batch.tenant_ref, "outboxref:event-1"), self.store.data["outbox"])
        self.assertIn((batch.tenant_ref, first.receipt_id), self.store.data["receipts"])
        self.assertEqual(parse_receipt(first.to_dict()), first)

    def test_idempotency_context_rebinding_is_terminal_and_rolled_back(self) -> None:
        batch = _batch()
        self.adapter.apply_transaction(batch)
        rebound = _batch(scope="scoperef:scope-2")
        with self.assertRaisesRegex(IdempotencyConflict, "context"):
            self.adapter.apply_transaction(rebound)
        aggregate = self.store.data["aggregates"][(batch.tenant_ref, "aggregateref:assessment-1")]
        self.assertEqual(aggregate["version"], 1)

    def test_stale_fence_and_version_fail_before_persistence(self) -> None:
        stale_fence = _batch(key="idem:postgresql-transaction-0002")
        self.store.data["fences"][(stale_fence.tenant_ref, "resourceref:assessment-1")][
            "fence_epoch"
        ] = 2
        with self.assertRaises(ConcurrencyConflict):
            self.adapter.apply_transaction(stale_fence)
        self.assertEqual(self.store.data["aggregates"], {})
        self.store.data["fences"][(stale_fence.tenant_ref, "resourceref:assessment-1")][
            "fence_epoch"
        ] = 1
        self.store.data["aggregates"][(stale_fence.tenant_ref, "aggregateref:assessment-1")] = {
            "version": 1,
            "content_sha256": DIGEST_A,
        }
        with self.assertRaises(ConcurrencyConflict):
            self.adapter.apply_transaction(stale_fence)
        self.assertEqual(self.store.data["outbox"], {})

    def test_database_failure_rolls_back_and_is_safely_classified(self) -> None:
        self.store.failures["outbox-insert"] = FakeDatabaseError("23505")
        with self.assertRaises(PostgreSQLTerminalError):
            self.adapter.apply_transaction(_batch())
        self.assertEqual(self.store.data["aggregates"], {})
        self.assertEqual(self.store.data["outbox"], {})
        self.assertEqual(self.store.data["batches"], {})
        self.assertEqual(self.store.rollback_count, 1)

    def test_retriable_and_terminal_sqlstate_classification_is_deterministic(self) -> None:
        retryable = classify_postgresql_failure(FakeDatabaseError("40001"))
        connection = classify_postgresql_failure(FakeDatabaseError("08006"))
        terminal = classify_postgresql_failure(FakeDatabaseError("42501"))
        unknown = classify_postgresql_failure(RuntimeError("unknown"))
        self.assertEqual(retryable.disposition, FailureDisposition.RETRIABLE)
        self.assertEqual(connection.disposition, FailureDisposition.RETRIABLE)
        self.assertEqual(terminal.disposition, FailureDisposition.TERMINAL)
        self.assertEqual(unknown.reason_code, "unclassified_database_failure")
        self.store.failures["transaction-prior"] = FakeDatabaseError("40P01")
        with self.assertRaises(PostgreSQLRetriableError):
            self.adapter.apply_transaction(_batch())

    def test_tenant_queries_do_not_cross_context_boundaries(self) -> None:
        self.adapter.apply_transaction(_batch())
        self.assertEqual(
            self.adapter.aggregate_version("tenantref:tenant-b", "aggregateref:assessment-1"),
            0,
        )
        schedule = self.adapter.register_schedule(_schedule("tenant-a"))
        with self.assertRaisesRegex(PostgreSQLAdapterError, "tenant-bound"):
            self.adapter.materialize_due(
                "tenant-b", schedule.schedule_id, evaluated_at="2026-09-20T12:00:00Z"
            )

    def test_scheduler_register_materialize_claim_and_replay(self) -> None:
        schedule = self.adapter.register_schedule(_schedule())
        self.assertEqual(self.adapter.register_schedule(schedule), schedule)
        due = self.adapter.materialize_due(
            schedule.tenant_id,
            schedule.schedule_id,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        self.assertEqual(len(due), 1)
        lease = self.adapter.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            "worker-1",
            "idem:postgresql-claim-000001",
            claimed_at="2026-09-20T12:00:00Z",
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        replay = self.adapter.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            "worker-1",
            "idem:postgresql-claim-000001",
            claimed_at="2026-09-20T12:00:10Z",
        )
        self.assertEqual(replay, lease)
        self.assertIn("claim-candidate", self.store.executed_tags)
        self.assertEqual(
            self.store.data["occurrences"][(schedule.tenant_id, due[0].occurrence_id)]["state"],
            "leased",
        )

    def test_scheduler_claim_context_rebinding_fails_closed(self) -> None:
        schedule = self.adapter.register_schedule(_schedule())
        self.adapter.materialize_due(
            schedule.tenant_id,
            schedule.schedule_id,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        key = "idem:postgresql-claim-000002"
        self.adapter.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            "worker-1",
            key,
            claimed_at="2026-09-20T12:00:00Z",
        )
        with self.assertRaises(IdempotencyConflict):
            self.adapter.claim_due(
                schedule.tenant_id,
                schedule.schedule_id,
                "worker-2",
                key,
                claimed_at="2026-09-20T12:00:01Z",
            )

    def test_artifact_recorder_boundary_receives_complete_observation(self) -> None:
        request = ArtifactRecordingRequest(
            tenant_ref="tenantref:tenant-a",
            assessment_ref="assessmentref:assessment-1",
            scope_ref="scoperef:scope-1",
            artifact=ArtifactMetadata(
                artifact_ref="artifactref:evidence-1",
                content_sha256=DIGEST_A,
                media_type="application/json",
                size_bytes=128,
                retention_class="assessment_1_year",
                custody_ref="custodyref:evidence-1",
                prior_custody_sha256=None,
            ),
            expected_artifact_version=0,
            expected_custody_version=0,
            fence_resource_ref="resourceref:assessment-1",
            fence_token="fence:assessment-000000000001",
            fence_epoch=1,
            idempotency_key="idem:artifact-postgresql-0001",
            recorded_at="2026-09-20T12:00:00Z",
            outbox_event=OutboxEventMetadata(
                outbox_event_ref="outboxref:artifact-1",
                event_type="artifact.recorded",
                content_sha256=DIGEST_B,
                expected_version=0,
            ),
        )
        plan = plan_artifact_recording(request)
        receipt = record_artifact(plan, self.adapter)
        replay = record_artifact(plan, self.adapter)
        self.assertEqual(receipt.status.value, "observed_commit")
        self.assertEqual(replay.status.value, "observed_replay")
        self.assertEqual(receipt.adapter_ref, self.adapter.config.adapter_ref)

    def test_receipts_are_content_addressed_and_schema_valid(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        receipt = self.adapter.apply_transaction_receipt(_batch())
        health = self.adapter.observe_health(observed_at="2026-09-20T12:00:00Z")
        validator.validate(receipt.to_dict())
        validator.validate(health.to_dict())
        tampered = receipt.to_dict()
        tampered["scope_ref"] = "scoperef:tampered"
        with self.assertRaises(PostgreSQLAdapterError):
            PostgreSQLTransactionReceipt.from_dict(tampered)
        health_tampered = health.to_dict()
        health_tampered["live_deployment_proof"] = True
        with self.assertRaises(PostgreSQLAdapterError):
            parse_receipt(health_tampered)

    def test_health_record_type_is_explicit(self) -> None:
        observation = self.adapter.observe_health(observed_at="2026-09-20T12:00:00Z")
        self.assertIsInstance(observation, PostgreSQLHealthObservation)
        self.assertRegex(observation.observation_id, r"^PGH-[0-9A-F]{32}$")

    def test_public_package_exports_postgresql_runtime_boundary(self) -> None:
        self.assertIs(
            sunderkey.PostgreSQLPersistenceSchedulerAdapter,
            PostgreSQLPersistenceSchedulerAdapter,
        )
        self.assertIs(
            sunderkey.classify_postgresql_failure,
            classify_postgresql_failure,
        )
        self.assertIs(sunderkey.parse_postgresql_runtime_receipt, parse_receipt)


if __name__ == "__main__":
    unittest.main()
