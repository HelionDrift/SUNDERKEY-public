"""SQLite persistence and durable scheduler runtime for local development.

The SQLite adapter is deliberately limited to local and development use. The
PostgreSQL declarations in this module are interfaces and migration plans only.
They do not establish a connection or provide production qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .durable_scheduler_contracts import (
    CancellationRecord,
    CancellationTarget,
    CompletionObservation,
    CompletionStatus,
    DueOccurrence,
    DurableLease,
    LeaseTransition,
    RecoveryPlan,
    ScheduleDefinition,
    _digests,
    _enum,
    claim_due_occurrence,
    create_cancellation_record,
    derive_due_occurrences,
    heartbeat_lease,
    observe_completion,
    plan_expired_lease_recovery,
)
from .persistence_port_contracts import TransactionBatch

SCHEMA_VERSION = 1


class PersistenceRuntimeError(RuntimeError):
    """Base error for fail-closed runtime behavior."""


class ConcurrencyConflict(PersistenceRuntimeError):
    """Raised when an optimistic version, lease, or fence is stale."""


class IdempotencyConflict(PersistenceRuntimeError):
    """Raised when an idempotency key is rebound to different content."""


class TenantIsolationError(PersistenceRuntimeError):
    """Raised when a requested object belongs to another tenant."""


class StoreBusyError(PersistenceRuntimeError):
    """Raised when SQLite cannot acquire its bounded writer lock."""


class MigrationIdentityError(PersistenceRuntimeError):
    """Raised when an applied migration does not match the embedded artifact."""


class Clock(Protocol):
    """Injectable UTC clock."""

    def now(self) -> datetime:
        """Return an aware UTC instant."""


@dataclass(frozen=True, slots=True)
class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class TransactionResult:
    batch_id: str
    aggregate_versions: Mapping[str, int]
    outbox_event_refs: tuple[str, ...]
    replayed: bool


@dataclass(frozen=True, slots=True)
class PostgreSQLMigrationStep:
    version: int
    migration_id: str
    sha256: str
    statements: tuple[str, ...]
    mode: str = "expand_contract"


@dataclass(frozen=True, slots=True)
class ConformanceHarnessMetadata:
    adapter: str
    environment_variable: str
    configured: bool
    network_call_performed: bool
    live_proof: bool
    required_checks: tuple[str, ...]


@runtime_checkable
class PersistenceRepository(Protocol):
    def apply_transaction(self, batch: TransactionBatch) -> TransactionResult:
        """Atomically apply optimistic mutations and enqueue outbox events."""

    def aggregate_version(self, tenant_ref: str, aggregate_ref: str) -> int:
        """Return the tenant-bound aggregate version."""


@runtime_checkable
class DurableSchedulerRepository(Protocol):
    def register_schedule(self, schedule: ScheduleDefinition) -> ScheduleDefinition:
        """Persist a content-addressed schedule."""

    def materialize_due(
        self, tenant_id: str, schedule_id: str, *, evaluated_at: str | None = None
    ) -> tuple[DueOccurrence, ...]:
        """Persist due occurrences exactly once."""


@runtime_checkable
class PostgreSQLAdapter(Protocol):
    """Production adapter interface. No concrete network adapter is bundled."""

    def apply_transaction(self, batch: TransactionBatch) -> TransactionResult:
        """Apply a transaction using PostgreSQL serializable semantics."""

    def claim_due(
        self, tenant_id: str, schedule_id: str, worker_ref: str, idempotency_key: str
    ) -> DurableLease | None:
        """Claim with row locking and skip-locked selection."""


_SQLITE_MIGRATION_1 = """
CREATE TABLE aggregate_heads(
 tenant_ref TEXT NOT NULL, aggregate_ref TEXT NOT NULL, version INTEGER NOT NULL,
 content_sha256 TEXT NOT NULL, PRIMARY KEY(tenant_ref, aggregate_ref));
CREATE TABLE resource_fences(
 tenant_ref TEXT NOT NULL, resource_ref TEXT NOT NULL, fence_token TEXT NOT NULL,
 fence_epoch INTEGER NOT NULL, PRIMARY KEY(tenant_ref, resource_ref));
CREATE TABLE transaction_batches(
 tenant_ref TEXT NOT NULL, idempotency_key TEXT NOT NULL, batch_id TEXT NOT NULL,
 batch_sha256 TEXT NOT NULL, batch_json TEXT NOT NULL,
 PRIMARY KEY(tenant_ref, idempotency_key));
CREATE TABLE outbox_events(
 tenant_ref TEXT NOT NULL, event_ref TEXT NOT NULL, batch_id TEXT NOT NULL,
 event_json TEXT NOT NULL, created_at TEXT NOT NULL, published_at TEXT,
 PRIMARY KEY(tenant_ref, event_ref));
CREATE TABLE schedules(
 tenant_id TEXT NOT NULL, schedule_id TEXT NOT NULL, schedule_sha256 TEXT NOT NULL,
 definition_version INTEGER NOT NULL, schedule_json TEXT NOT NULL,
 cancelled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant_id, schedule_id));
CREATE TABLE occurrences(
 tenant_id TEXT NOT NULL, occurrence_id TEXT NOT NULL, schedule_id TEXT NOT NULL,
 occurrence_index INTEGER NOT NULL, occurrence_json TEXT NOT NULL,
 occurrence_version INTEGER NOT NULL, state TEXT NOT NULL, ready_at TEXT NOT NULL,
 attempt_number INTEGER NOT NULL DEFAULT 0, fence_epoch INTEGER NOT NULL DEFAULT 0,
 lease_id TEXT, PRIMARY KEY(tenant_id, occurrence_id),
 UNIQUE(tenant_id, schedule_id, occurrence_index));
CREATE INDEX occurrence_due_idx ON occurrences(tenant_id, schedule_id, state, ready_at);
CREATE TABLE lease_snapshots(
 tenant_id TEXT NOT NULL, lease_id TEXT NOT NULL, lease_version INTEGER NOT NULL,
 occurrence_id TEXT NOT NULL, fence_epoch INTEGER NOT NULL, expires_at TEXT NOT NULL,
 active INTEGER NOT NULL, lease_json TEXT NOT NULL,
 PRIMARY KEY(tenant_id, lease_id, lease_version));
CREATE UNIQUE INDEX one_active_occurrence_lease
 ON lease_snapshots(tenant_id, occurrence_id) WHERE active = 1;
CREATE TABLE scheduler_results(
 tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, result_kind TEXT NOT NULL,
 result_sha256 TEXT NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY(tenant_id, idempotency_key));
CREATE TABLE completions(
 tenant_id TEXT NOT NULL, completion_id TEXT NOT NULL, lease_id TEXT NOT NULL,
 completion_json TEXT NOT NULL, PRIMARY KEY(tenant_id, completion_id));
CREATE TABLE recoveries(
 tenant_id TEXT NOT NULL, recovery_id TEXT NOT NULL, expired_lease_id TEXT NOT NULL,
 recovery_json TEXT NOT NULL, PRIMARY KEY(tenant_id, recovery_id));
CREATE TABLE cancellations(
 tenant_id TEXT NOT NULL, cancellation_id TEXT NOT NULL, cancellation_json TEXT NOT NULL,
 PRIMARY KEY(tenant_id, cancellation_id));
""".strip()


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


SQLITE_MIGRATION_ID = "migrationref:persistence-scheduler-runtime.sqlite.0001"
SQLITE_MIGRATION_SHA256 = _sha256_text(_SQLITE_MIGRATION_1)

POSTGRESQL_MIGRATION_PLAN = (
    PostgreSQLMigrationStep(
        version=1,
        migration_id="migrationref:persistence-scheduler-runtime.postgresql.0001-expand",
        sha256=_sha256_text(
            "tenant-scoped aggregates, fences, scheduler records, and transactional outbox"
        ),
        statements=(
            "create tenant-scoped aggregate, fence, idempotency, and outbox tables",
            "create scheduler schedule, occurrence, lease, completion, recovery tables",
            "add unique active-lease and tenant-scoped idempotency constraints",
            "use SELECT FOR UPDATE SKIP LOCKED for due claims",
        ),
    ),
)


def postgresql_conformance_metadata(
    environment_variable: str = "SUNDERKEY_POSTGRES_CONFORMANCE_DSN",
) -> ConformanceHarnessMetadata:
    """Describe the opt-in live harness without opening a socket."""

    configured = bool(os.environ.get(environment_variable))
    return ConformanceHarnessMetadata(
        adapter="postgresql-interface-only",
        environment_variable=environment_variable,
        configured=configured,
        network_call_performed=False,
        live_proof=False,
        required_checks=(
            "serializable-conflict-retry",
            "skip-locked-due-claim",
            "tenant-row-policy",
            "stale-fence-rejection",
            "atomic-outbox-rollback",
            "connection-loss-recovery",
            "expand-contract-migration",
        ),
    )


def runtime_manifest() -> dict[str, Any]:
    """Return machine-readable implementation and qualification boundaries."""

    return {
        "backend": "sqlite",
        "deployment_scope": "local_development_only",
        "effects": {
            "database": "caller_selected_local_sqlite_file",
            "network": "none",
            "postgresql": "interface_and_migration_plan_only",
            "production_qualification": "none",
        },
        "kind": "sunderkey.persistence-scheduler-runtime.v1",
        "migration": {
            "migration_id": SQLITE_MIGRATION_ID,
            "migration_sha256": SQLITE_MIGRATION_SHA256,
            "version": 1,
        },
        "postgresql_conformance": {
            "environment_variable": "SUNDERKEY_POSTGRES_CONFORMANCE_DSN",
            "live_proof": False,
            "network_call_performed": False,
            "required_checks": list(postgresql_conformance_metadata().required_checks),
        },
        "schema_version": SCHEMA_VERSION,
    }


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise PersistenceRuntimeError("clock must return an aware datetime")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )


def _validate_scheduler_replay(
    raw: Mapping[str, Any],
    reconstructed: Mapping[str, Any],
    requested_context: Mapping[str, Any],
) -> None:
    if _json(raw) != _json(reconstructed):
        raise PersistenceRuntimeError("cached scheduler result does not reproduce exactly")
    actual_context = {field: reconstructed[field] for field in requested_context}
    if _json(actual_context) != _json(requested_context):
        raise IdempotencyConflict("scheduler idempotency context was rebound")


def _validate_replay_versions(lease_version: int, fence_epoch: int) -> None:
    for value in (lease_version, fence_epoch):
        if type(value) is not int or not 1 <= value <= 2_147_483_647:
            raise IdempotencyConflict("scheduler replay version or fence is invalid")


class SQLitePersistenceSchedulerRuntime:
    """Crash-safe local runtime backed by a file-based SQLite database."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Clock | None = None,
        busy_timeout_seconds: float = 1.0,
    ) -> None:
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise PersistenceRuntimeError("file-based SQLite is required for crash-safe restart")
        self.clock = clock or SystemClock()
        self.busy_timeout_seconds = busy_timeout_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise StoreBusyError("SQLite writer lock was not acquired") from exc
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migrate(self) -> None:
        with self._read() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations("
                "version INTEGER PRIMARY KEY, migration_id TEXT NOT NULL, "
                "migration_sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT migration_id, migration_sha256 FROM schema_migrations WHERE version = 1"
            ).fetchone()
            if row is not None:
                if (
                    row["migration_id"] != SQLITE_MIGRATION_ID
                    or row["migration_sha256"] != SQLITE_MIGRATION_SHA256
                ):
                    raise MigrationIdentityError("SQLite migration identity does not match")
                return
            try:
                connection.executescript("BEGIN IMMEDIATE;\n" + _SQLITE_MIGRATION_1)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES(1, ?, ?, ?)",
                    (SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256, _utc_text(self.clock.now())),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def migration_identity(self) -> tuple[str, str]:
        with self._read() as connection:
            row = connection.execute(
                "SELECT migration_id, migration_sha256 FROM schema_migrations WHERE version = 1"
            ).fetchone()
        if row is None:
            raise MigrationIdentityError("SQLite migration is absent")
        return row["migration_id"], row["migration_sha256"]

    def install_fence(
        self, tenant_ref: str, resource_ref: str, fence_token: str, fence_epoch: int
    ) -> None:
        with self._write() as connection:
            row = connection.execute(
                "SELECT fence_epoch FROM resource_fences WHERE tenant_ref=? AND resource_ref=?",
                (tenant_ref, resource_ref),
            ).fetchone()
            if row is not None and fence_epoch <= row["fence_epoch"]:
                raise ConcurrencyConflict("fence epoch must advance")
            connection.execute(
                "INSERT INTO resource_fences VALUES(?,?,?,?) "
                "ON CONFLICT(tenant_ref,resource_ref) DO UPDATE SET "
                "fence_token=excluded.fence_token,fence_epoch=excluded.fence_epoch",
                (tenant_ref, resource_ref, fence_token, fence_epoch),
            )

    def aggregate_version(self, tenant_ref: str, aggregate_ref: str) -> int:
        with self._read() as connection:
            row = connection.execute(
                "SELECT version FROM aggregate_heads WHERE tenant_ref=? AND aggregate_ref=?",
                (tenant_ref, aggregate_ref),
            ).fetchone()
            if row is None:
                other = connection.execute(
                    "SELECT 1 FROM aggregate_heads WHERE aggregate_ref=? LIMIT 1",
                    (aggregate_ref,),
                ).fetchone()
                if other is not None:
                    raise TenantIsolationError("aggregate belongs to another tenant")
                return 0
            return int(row["version"])

    def apply_transaction(self, batch: TransactionBatch) -> TransactionResult:
        tenant = batch.tenant_ref
        with self._write() as connection:
            prior = connection.execute(
                "SELECT batch_sha256,batch_id,batch_json FROM transaction_batches "
                "WHERE tenant_ref=? AND idempotency_key=?",
                (tenant, batch.idempotency_key),
            ).fetchone()
            if prior is not None:
                if prior["batch_sha256"] != batch.batch_sha256:
                    raise IdempotencyConflict("transaction idempotency key was rebound")
                return TransactionResult(
                    batch_id=prior["batch_id"],
                    aggregate_versions={
                        item.aggregate_ref: item.expected_version + 1
                        for item in batch.version_bindings
                    },
                    outbox_event_refs=batch.outbox_event_refs,
                    replayed=True,
                )
            for fence in batch.fence_bindings:
                row = connection.execute(
                    "SELECT fence_token,fence_epoch FROM resource_fences "
                    "WHERE tenant_ref=? AND resource_ref=?",
                    (tenant, fence.resource_ref),
                ).fetchone()
                if row is None or (
                    row["fence_token"] != fence.fence_token
                    or row["fence_epoch"] != fence.fence_epoch
                ):
                    raise ConcurrencyConflict("stale or unknown fence binding")
            digests: dict[str, str] = {}
            for operation in batch.operations:
                digests[operation.aggregate_ref] = operation.content_sha256
            versions: dict[str, int] = {}
            for binding in batch.version_bindings:
                row = connection.execute(
                    "SELECT version FROM aggregate_heads WHERE tenant_ref=? AND aggregate_ref=?",
                    (tenant, binding.aggregate_ref),
                ).fetchone()
                current = 0 if row is None else int(row["version"])
                if current != binding.expected_version:
                    raise ConcurrencyConflict("aggregate version is stale")
                next_version = current + 1
                versions[binding.aggregate_ref] = next_version
                connection.execute(
                    "INSERT INTO aggregate_heads VALUES(?,?,?,?) "
                    "ON CONFLICT(tenant_ref,aggregate_ref) DO UPDATE SET "
                    "version=excluded.version,content_sha256=excluded.content_sha256",
                    (tenant, binding.aggregate_ref, next_version, digests[binding.aggregate_ref]),
                )
            for event_ref in batch.outbox_event_refs:
                connection.execute(
                    "INSERT INTO outbox_events VALUES(?,?,?,?,?,NULL)",
                    (
                        tenant,
                        event_ref,
                        batch.batch_id,
                        _json({"batch_id": batch.batch_id, "event_ref": event_ref}),
                        batch.created_at,
                    ),
                )
            connection.execute(
                "INSERT INTO transaction_batches VALUES(?,?,?,?,?)",
                (
                    tenant,
                    batch.idempotency_key,
                    batch.batch_id,
                    batch.batch_sha256,
                    batch.to_json(),
                ),
            )
        return TransactionResult(batch.batch_id, versions, batch.outbox_event_refs, False)

    def outbox_events(self, tenant_ref: str) -> tuple[str, ...]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT event_ref FROM outbox_events WHERE tenant_ref=? ORDER BY event_ref",
                (tenant_ref,),
            ).fetchall()
        return tuple(row["event_ref"] for row in rows)

    def register_schedule(self, schedule: ScheduleDefinition) -> ScheduleDefinition:
        with self._write() as connection:
            other = connection.execute(
                "SELECT tenant_id FROM schedules WHERE schedule_id=? AND tenant_id<>? LIMIT 1",
                (schedule.schedule_id, schedule.tenant_id),
            ).fetchone()
            if other is not None:
                raise TenantIsolationError("schedule identifier belongs to another tenant")
            row = connection.execute(
                "SELECT schedule_sha256,schedule_json FROM schedules "
                "WHERE tenant_id=? AND schedule_id=?",
                (schedule.tenant_id, schedule.schedule_id),
            ).fetchone()
            if row is not None:
                if row["schedule_sha256"] != schedule.schedule_sha256:
                    raise ConcurrencyConflict("schedule identifier has conflicting content")
                return ScheduleDefinition.from_dict(json.loads(row["schedule_json"]))
            connection.execute(
                "INSERT INTO schedules VALUES(?,?,?,?,?,0)",
                (
                    schedule.tenant_id,
                    schedule.schedule_id,
                    schedule.schedule_sha256,
                    schedule.definition_version,
                    _json(schedule.to_dict()),
                ),
            )
        return schedule

    def _schedule(
        self, connection: sqlite3.Connection, tenant_id: str, schedule_id: str
    ) -> ScheduleDefinition:
        row = connection.execute(
            "SELECT schedule_json,cancelled FROM schedules WHERE tenant_id=? AND schedule_id=?",
            (tenant_id, schedule_id),
        ).fetchone()
        if row is None:
            other = connection.execute(
                "SELECT 1 FROM schedules WHERE schedule_id=? LIMIT 1", (schedule_id,)
            ).fetchone()
            if other is not None:
                raise TenantIsolationError("schedule belongs to another tenant")
            raise PersistenceRuntimeError("schedule was not found")
        if row["cancelled"]:
            raise PersistenceRuntimeError("schedule is cancelled")
        return ScheduleDefinition.from_dict(json.loads(row["schedule_json"]))

    def materialize_due(
        self, tenant_id: str, schedule_id: str, *, evaluated_at: str | None = None
    ) -> tuple[DueOccurrence, ...]:
        evaluated = evaluated_at or _utc_text(self.clock.now())
        with self._write() as connection:
            schedule = self._schedule(connection, tenant_id, schedule_id)
            indices = tuple(
                int(row["occurrence_index"])
                for row in connection.execute(
                    "SELECT occurrence_index FROM occurrences WHERE tenant_id=? AND schedule_id=?",
                    (tenant_id, schedule_id),
                )
            )
            due = derive_due_occurrences(
                schedule, evaluated_at=evaluated, materialized_occurrence_indices=indices
            )
            for occurrence in due:
                connection.execute(
                    "INSERT INTO occurrences VALUES(?,?,?,?,?,?, 'pending', ?,0,0,NULL)",
                    (
                        tenant_id,
                        occurrence.occurrence_id,
                        schedule_id,
                        occurrence.occurrence_index,
                        _json(occurrence.to_dict()),
                        occurrence.occurrence_version,
                        occurrence.nominal_at,
                    ),
                )
        return due

    def _idempotent_result(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        key: str,
        kind: str,
    ) -> Mapping[str, Any] | None:
        row = connection.execute(
            "SELECT result_kind,result_json,result_sha256 FROM scheduler_results "
            "WHERE tenant_id=? AND idempotency_key=?",
            (tenant_id, key),
        ).fetchone()
        if row is None:
            return None
        if row["result_kind"] != kind:
            raise IdempotencyConflict("scheduler idempotency key was rebound")
        document = row["result_json"]
        digest = row["result_sha256"]
        if type(document) is not str or type(digest) is not str:
            raise PersistenceRuntimeError("cached scheduler result metadata is invalid")
        try:
            if _sha256_text(document) != digest:
                raise PersistenceRuntimeError("cached scheduler result digest does not match")
            parsed = json.loads(document)
            if type(parsed) is not dict or _json(parsed) != document:
                raise PersistenceRuntimeError("cached scheduler result JSON is not canonical")
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise PersistenceRuntimeError("cached scheduler result JSON is invalid") from exc
        return parsed

    def _save_result(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        key: str,
        kind: str,
        result: Mapping[str, Any],
    ) -> None:
        document = _json(result)
        connection.execute(
            "INSERT INTO scheduler_results VALUES(?,?,?,?,?)",
            (tenant_id, key, kind, _sha256_text(document), document),
        )
        event_ref = "outboxref:scheduler." + _sha256_text(document).removeprefix("sha256:")
        connection.execute(
            "INSERT INTO outbox_events VALUES(?,?,?,?,?,NULL)",
            (
                tenant_id,
                event_ref,
                result.get("lease_id")
                or result.get("occurrence_id")
                or result.get("schedule_id")
                or kind,
                document,
                _utc_text(self.clock.now()),
            ),
        )

    def claim_due(
        self,
        tenant_id: str,
        schedule_id: str,
        *,
        worker_ref: str,
        idempotency_key: str,
        claimed_at: str | None = None,
    ) -> DurableLease | None:
        claimed = claimed_at or _utc_text(self.clock.now())
        with self._write() as connection:
            replay = self._idempotent_result(connection, tenant_id, idempotency_key, "claim")
            if replay is not None:
                lease = DurableLease.from_dict(replay)
                _validate_scheduler_replay(
                    replay,
                    lease.to_dict(),
                    {
                        "tenant_id": tenant_id,
                        "schedule_id": schedule_id,
                        "worker_ref": worker_ref,
                        "idempotency_key": idempotency_key,
                        "transition": LeaseTransition.CLAIM.value,
                    },
                )
                return lease
            schedule = self._schedule(connection, tenant_id, schedule_id)
            row = connection.execute(
                "SELECT * FROM occurrences WHERE tenant_id=? AND schedule_id=? "
                "AND state IN ('pending','retry') AND ready_at<=? "
                "ORDER BY ready_at,occurrence_index LIMIT 1",
                (tenant_id, schedule_id, claimed),
            ).fetchone()
            if row is None:
                return None
            occurrence = DueOccurrence.from_dict(json.loads(row["occurrence_json"]))
            occurrence = replace(occurrence, occurrence_version=int(row["occurrence_version"]))
            expires = _utc_text(
                datetime.strptime(claimed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                + timedelta(seconds=schedule.lease_duration_seconds)
            )
            lease = claim_due_occurrence(
                schedule,
                occurrence,
                worker_ref=worker_ref,
                attempt_number=int(row["attempt_number"]) + 1,
                fence_epoch=int(row["fence_epoch"]) + 1,
                expected_occurrence_version=occurrence.occurrence_version,
                claimed_at=claimed,
                expires_at=expires,
                idempotency_key=idempotency_key,
            )
            connection.execute(
                "INSERT INTO lease_snapshots VALUES(?,?,?,?,?,?,1,?)",
                (
                    tenant_id,
                    lease.lease_id,
                    lease.lease_version,
                    lease.occurrence_id,
                    lease.fence_epoch,
                    lease.expires_at,
                    _json(lease.to_dict()),
                ),
            )
            connection.execute(
                "UPDATE occurrences SET state='leased',attempt_number=?,fence_epoch=?,lease_id=? "
                "WHERE tenant_id=? AND occurrence_id=? AND state IN ('pending','retry')",
                (
                    lease.attempt_number,
                    lease.fence_epoch,
                    lease.lease_id,
                    tenant_id,
                    lease.occurrence_id,
                ),
            )
            self._save_result(connection, tenant_id, idempotency_key, "claim", lease.to_dict())
        return lease

    def heartbeat(
        self,
        tenant_id: str,
        lease_id: str,
        *,
        expected_lease_version: int,
        expected_fence_epoch: int,
        idempotency_key: str,
        observed_at: str | None = None,
    ) -> DurableLease:
        observed = observed_at or _utc_text(self.clock.now())
        with self._write() as connection:
            replay = self._idempotent_result(connection, tenant_id, idempotency_key, "heartbeat")
            if replay is not None:
                _validate_replay_versions(expected_lease_version, expected_fence_epoch)
                lease = DurableLease.from_dict(replay)
                _validate_scheduler_replay(
                    replay,
                    lease.to_dict(),
                    {
                        "tenant_id": tenant_id,
                        "lease_id": lease_id,
                        "lease_version": expected_lease_version + 1,
                        "fence_epoch": expected_fence_epoch,
                        "idempotency_key": idempotency_key,
                        "transition": LeaseTransition.HEARTBEAT.value,
                    },
                )
                return lease
            row = connection.execute(
                "SELECT lease_json,active FROM lease_snapshots WHERE tenant_id=? AND lease_id=? "
                "ORDER BY lease_version DESC LIMIT 1",
                (tenant_id, lease_id),
            ).fetchone()
            if row is None or not row["active"]:
                raise ConcurrencyConflict("lease is not active")
            lease = DurableLease.from_dict(json.loads(row["lease_json"]))
            if (
                lease.lease_version != expected_lease_version
                or lease.fence_epoch != expected_fence_epoch
            ):
                raise ConcurrencyConflict("lease version or fence is stale")
            schedule = self._schedule(connection, tenant_id, lease.schedule_id)
            expires = _utc_text(
                datetime.strptime(observed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                + timedelta(seconds=schedule.lease_duration_seconds)
            )
            updated = heartbeat_lease(
                schedule,
                lease,
                expected_lease_version=expected_lease_version,
                expected_fence_epoch=expected_fence_epoch,
                observed_at=observed,
                expires_at=expires,
                idempotency_key=idempotency_key,
            )
            connection.execute(
                "UPDATE lease_snapshots SET active=0 WHERE tenant_id=? AND lease_id=?",
                (tenant_id, lease_id),
            )
            connection.execute(
                "INSERT INTO lease_snapshots VALUES(?,?,?,?,?,?,1,?)",
                (
                    tenant_id,
                    updated.lease_id,
                    updated.lease_version,
                    updated.occurrence_id,
                    updated.fence_epoch,
                    updated.expires_at,
                    _json(updated.to_dict()),
                ),
            )
            self._save_result(
                connection, tenant_id, idempotency_key, "heartbeat", updated.to_dict()
            )
        return updated

    def complete(
        self,
        tenant_id: str,
        lease_id: str,
        *,
        expected_lease_version: int,
        expected_fence_epoch: int,
        status: CompletionStatus | str,
        evidence_sha256s: Sequence[str],
        idempotency_key: str,
        observed_at: str | None = None,
    ) -> CompletionObservation:
        observed = observed_at or _utc_text(self.clock.now())
        with self._write() as connection:
            replay = self._idempotent_result(connection, tenant_id, idempotency_key, "completion")
            if replay is not None:
                _validate_replay_versions(expected_lease_version, expected_fence_epoch)
                completion = CompletionObservation.from_dict(replay)
                _validate_scheduler_replay(
                    replay,
                    completion.to_dict(),
                    {
                        "tenant_id": tenant_id,
                        "lease_id": lease_id,
                        "expected_lease_version": expected_lease_version,
                        "expected_fence_epoch": expected_fence_epoch,
                        "status": _enum(status, CompletionStatus, "status").value,
                        "evidence_sha256s": list(_digests(evidence_sha256s, "evidence_sha256s")),
                        "idempotency_key": idempotency_key,
                    },
                )
                return completion
            lease_row = connection.execute(
                "SELECT lease_json,active FROM lease_snapshots WHERE tenant_id=? AND lease_id=? "
                "ORDER BY lease_version DESC LIMIT 1",
                (tenant_id, lease_id),
            ).fetchone()
            if lease_row is None or not lease_row["active"]:
                raise ConcurrencyConflict("lease is not active")
            lease = DurableLease.from_dict(json.loads(lease_row["lease_json"]))
            if (
                lease.lease_version != expected_lease_version
                or lease.fence_epoch != expected_fence_epoch
            ):
                raise ConcurrencyConflict("lease version or fence is stale")
            occurrence_row = connection.execute(
                "SELECT * FROM occurrences WHERE tenant_id=? AND occurrence_id=?",
                (tenant_id, lease.occurrence_id),
            ).fetchone()
            if occurrence_row is None or occurrence_row["fence_epoch"] != expected_fence_epoch:
                raise ConcurrencyConflict("occurrence fence is stale")
            occurrence = DueOccurrence.from_dict(json.loads(occurrence_row["occurrence_json"]))
            occurrence = replace(
                occurrence, occurrence_version=int(occurrence_row["occurrence_version"])
            )
            schedule = self._schedule(connection, tenant_id, lease.schedule_id)
            completion = observe_completion(
                schedule,
                occurrence,
                lease,
                expected_lease_version=expected_lease_version,
                expected_fence_epoch=expected_fence_epoch,
                expected_occurrence_version=occurrence.occurrence_version,
                status=status,
                observed_at=observed,
                evidence_sha256s=evidence_sha256s,
                idempotency_key=idempotency_key,
            )
            state = {
                "completed": "completed",
                "retry_planned": "retry",
                "dead_lettered": "dead_lettered",
                "cancelled": "cancelled",
            }[completion.resolution.value]
            ready_at = completion.retry_at or observed
            connection.execute(
                "UPDATE occurrences SET occurrence_version=?,state=?,ready_at=?,lease_id=NULL "
                "WHERE tenant_id=? AND occurrence_id=? AND occurrence_version=?",
                (
                    completion.new_occurrence_version,
                    state,
                    ready_at,
                    tenant_id,
                    occurrence.occurrence_id,
                    completion.expected_occurrence_version,
                ),
            )
            connection.execute(
                "UPDATE lease_snapshots SET active=0 WHERE tenant_id=? AND lease_id=?",
                (tenant_id, lease_id),
            )
            connection.execute(
                "INSERT INTO completions VALUES(?,?,?,?)",
                (tenant_id, completion.completion_id, lease_id, _json(completion.to_dict())),
            )
            self._save_result(
                connection, tenant_id, idempotency_key, "completion", completion.to_dict()
            )
        return completion

    def cancel_occurrence(
        self,
        tenant_id: str,
        occurrence_id: str,
        *,
        reason_code: str,
        idempotency_key: str,
        requested_at: str | None = None,
    ) -> CancellationRecord:
        requested = requested_at or _utc_text(self.clock.now())
        with self._write() as connection:
            replay = self._idempotent_result(connection, tenant_id, idempotency_key, "cancellation")
            if replay is not None:
                cancellation = CancellationRecord.from_dict(replay)
                _validate_scheduler_replay(
                    replay,
                    cancellation.to_dict(),
                    {
                        "tenant_id": tenant_id,
                        "occurrence_id": occurrence_id,
                        "reason_code": reason_code,
                        "target": CancellationTarget.OCCURRENCE.value,
                        "idempotency_key": idempotency_key,
                    },
                )
                return cancellation
            row = connection.execute(
                "SELECT * FROM occurrences WHERE tenant_id=? AND occurrence_id=?",
                (tenant_id, occurrence_id),
            ).fetchone()
            if row is None:
                other = connection.execute(
                    "SELECT 1 FROM occurrences WHERE occurrence_id=? LIMIT 1", (occurrence_id,)
                ).fetchone()
                if other is not None:
                    raise TenantIsolationError("occurrence belongs to another tenant")
                raise PersistenceRuntimeError("occurrence was not found")
            occurrence = DueOccurrence.from_dict(json.loads(row["occurrence_json"]))
            occurrence = replace(occurrence, occurrence_version=int(row["occurrence_version"]))
            schedule = self._schedule(connection, tenant_id, occurrence.schedule_id)
            leases = tuple(
                DurableLease.from_dict(json.loads(item["lease_json"]))
                for item in connection.execute(
                    "SELECT lease_json FROM lease_snapshots WHERE tenant_id=? AND occurrence_id=? "
                    "AND active=1",
                    (tenant_id, occurrence_id),
                )
            )
            cancellation = create_cancellation_record(
                schedule,
                target=CancellationTarget.OCCURRENCE,
                expected_version=occurrence.occurrence_version,
                requested_at=requested,
                reason_code=reason_code,
                active_leases=leases,
                idempotency_key=idempotency_key,
                occurrence=occurrence,
            )
            connection.execute(
                "UPDATE occurrences SET occurrence_version=?,state='cancelled',lease_id=NULL "
                "WHERE tenant_id=? AND occurrence_id=?",
                (cancellation.new_version, tenant_id, occurrence_id),
            )
            connection.execute(
                "UPDATE lease_snapshots SET active=0 WHERE tenant_id=? AND occurrence_id=?",
                (tenant_id, occurrence_id),
            )
            connection.execute(
                "INSERT INTO cancellations VALUES(?,?,?)",
                (tenant_id, cancellation.cancellation_id, _json(cancellation.to_dict())),
            )
            self._save_result(
                connection, tenant_id, idempotency_key, "cancellation", cancellation.to_dict()
            )
        return cancellation

    def cancel_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        *,
        reason_code: str,
        idempotency_key: str,
        requested_at: str | None = None,
    ) -> CancellationRecord:
        requested = requested_at or _utc_text(self.clock.now())
        with self._write() as connection:
            replay = self._idempotent_result(connection, tenant_id, idempotency_key, "cancellation")
            if replay is not None:
                cancellation = CancellationRecord.from_dict(replay)
                _validate_scheduler_replay(
                    replay,
                    cancellation.to_dict(),
                    {
                        "tenant_id": tenant_id,
                        "schedule_id": schedule_id,
                        "reason_code": reason_code,
                        "target": CancellationTarget.SCHEDULE.value,
                        "idempotency_key": idempotency_key,
                    },
                )
                return cancellation
            schedule = self._schedule(connection, tenant_id, schedule_id)
            active = (
                DurableLease.from_dict(json.loads(item["lease_json"]))
                for item in connection.execute(
                    "SELECT lease_json FROM lease_snapshots WHERE tenant_id=? "
                    "AND active=1 ORDER BY lease_id,lease_version",
                    (tenant_id,),
                )
            )
            leases = tuple(item for item in active if item.schedule_id == schedule_id)
            cancellation = create_cancellation_record(
                schedule,
                target=CancellationTarget.SCHEDULE,
                expected_version=schedule.definition_version,
                requested_at=requested,
                reason_code=reason_code,
                active_leases=leases,
                idempotency_key=idempotency_key,
            )
            connection.execute(
                "UPDATE schedules SET cancelled=1 WHERE tenant_id=? AND schedule_id=?",
                (tenant_id, schedule_id),
            )
            connection.execute(
                "UPDATE occurrences SET state='cancelled',occurrence_version=occurrence_version+1,"
                "lease_id=NULL WHERE tenant_id=? AND schedule_id=? "
                "AND state NOT IN ('completed','dead_lettered','cancelled')",
                (tenant_id, schedule_id),
            )
            for lease_id in cancellation.revoked_lease_ids:
                connection.execute(
                    "UPDATE lease_snapshots SET active=0 WHERE tenant_id=? AND lease_id=?",
                    (tenant_id, lease_id),
                )
            connection.execute(
                "INSERT INTO cancellations VALUES(?,?,?)",
                (tenant_id, cancellation.cancellation_id, _json(cancellation.to_dict())),
            )
            self._save_result(
                connection, tenant_id, idempotency_key, "cancellation", cancellation.to_dict()
            )
        return cancellation

    def recover_expired(
        self, tenant_id: str, *, recovered_at: str | None = None
    ) -> tuple[RecoveryPlan, ...]:
        recovered = recovered_at or _utc_text(self.clock.now())
        results: list[RecoveryPlan] = []
        with self._write() as connection:
            rows = connection.execute(
                "SELECT lease_json FROM lease_snapshots WHERE tenant_id=? AND active=1 "
                "AND expires_at<? ORDER BY expires_at,lease_id",
                (tenant_id, recovered),
            ).fetchall()
            for row in rows:
                lease = DurableLease.from_dict(json.loads(row["lease_json"]))
                occurrence_row = connection.execute(
                    "SELECT * FROM occurrences WHERE tenant_id=? AND occurrence_id=?",
                    (tenant_id, lease.occurrence_id),
                ).fetchone()
                if occurrence_row is None or occurrence_row["state"] != "leased":
                    continue
                occurrence = DueOccurrence.from_dict(json.loads(occurrence_row["occurrence_json"]))
                occurrence = replace(
                    occurrence, occurrence_version=int(occurrence_row["occurrence_version"])
                )
                schedule = self._schedule(connection, tenant_id, lease.schedule_id)
                key = "idem:recovery:" + lease.lease_sha256.removeprefix("sha256:")
                plan = plan_expired_lease_recovery(
                    schedule,
                    occurrence,
                    lease,
                    expected_occurrence_version=occurrence.occurrence_version,
                    recovered_at=recovered,
                    idempotency_key=key,
                )
                state = "retry" if plan.disposition.value == "requeue" else "dead_lettered"
                connection.execute(
                    "UPDATE occurrences SET occurrence_version=?,state=?,ready_at=?,"
                    "fence_epoch=?,lease_id=NULL WHERE tenant_id=? AND occurrence_id=?",
                    (
                        plan.new_occurrence_version,
                        state,
                        plan.retry_at or recovered,
                        plan.next_fence_epoch,
                        tenant_id,
                        occurrence.occurrence_id,
                    ),
                )
                connection.execute(
                    "UPDATE lease_snapshots SET active=0 WHERE tenant_id=? AND lease_id=?",
                    (tenant_id, lease.lease_id),
                )
                connection.execute(
                    "INSERT INTO recoveries VALUES(?,?,?,?)",
                    (tenant_id, plan.recovery_id, lease.lease_id, _json(plan.to_dict())),
                )
                self._save_result(connection, tenant_id, key, "recovery", plan.to_dict())
                results.append(plan)
        return tuple(results)

    def occurrence_state(self, tenant_id: str, occurrence_id: str) -> tuple[str, int]:
        with self._read() as connection:
            row = connection.execute(
                "SELECT state,occurrence_version FROM occurrences "
                "WHERE tenant_id=? AND occurrence_id=?",
                (tenant_id, occurrence_id),
            ).fetchone()
        if row is None:
            raise PersistenceRuntimeError("occurrence was not found")
        return row["state"], int(row["occurrence_version"])


__all__ = [
    "Clock",
    "ConcurrencyConflict",
    "ConformanceHarnessMetadata",
    "DurableSchedulerRepository",
    "IdempotencyConflict",
    "MigrationIdentityError",
    "POSTGRESQL_MIGRATION_PLAN",
    "PersistenceRepository",
    "PersistenceRuntimeError",
    "PostgreSQLAdapter",
    "PostgreSQLMigrationStep",
    "SCHEMA_VERSION",
    "SQLITE_MIGRATION_ID",
    "SQLITE_MIGRATION_SHA256",
    "SQLitePersistenceSchedulerRuntime",
    "StoreBusyError",
    "SystemClock",
    "TenantIsolationError",
    "TransactionResult",
    "postgresql_conformance_metadata",
    "runtime_manifest",
]
