"""Injected PostgreSQL persistence and scheduler adapter.

The adapter executes PostgreSQL-compatible statements only through a caller
supplied DB-API connection factory. Importing this module does not discover
credentials, open a socket, migrate a database, or qualify a deployment.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

from .durable_artifact_recorder import (
    ArtifactCommitObservation,
    ArtifactRecordingPlan,
    CommitDisposition,
    DurableArtifactRecorderError,
    _capture_recording_plan,
    custody_entry_sha256,
)
from .durable_scheduler_contracts import (
    DueOccurrence,
    DurableLease,
    LeaseTransition,
    ScheduleDefinition,
    claim_due_occurrence,
    derive_due_occurrences,
)
from .persistence_port_contracts import (
    IsolationLevel,
    TransactionBatch,
    canonical_json,
    canonical_sha256,
    postgresql_production_capabilities,
)
from .persistence_scheduler_runtime import (
    POSTGRESQL_MIGRATION_PLAN,
    ConcurrencyConflict,
    IdempotencyConflict,
    MigrationIdentityError,
    PersistenceRuntimeError,
    SystemClock,
    TransactionResult,
)

SCHEMA_VERSION = 1
# Local serialization-cost limits, not schedule or lease authority.
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DOCUMENT_DEPTH = 24
MAX_DOCUMENT_NODES = 50_000
POSTGRESQL_MIGRATION_VERSION = POSTGRESQL_MIGRATION_PLAN[0].version
POSTGRESQL_MIGRATION_ID = POSTGRESQL_MIGRATION_PLAN[0].migration_id
POSTGRESQL_MIGRATION_SHA256 = POSTGRESQL_MIGRATION_PLAN[0].sha256

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
ADAPTER_RE = re.compile(r"adapterref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
RECEIPT_ID_RE = re.compile(r"PGR-[0-9A-F]{32}\Z")
HEALTH_ID_RE = re.compile(r"PGH-[0-9A-F]{32}\Z")
BATCH_ID_RE = re.compile(r"PTB-[0-9A-F]{32}\Z")
CAPABILITY_ID_RE = re.compile(r"PBD-[0-9A-F]{32}\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|scoperef|aggregateref|outboxref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SCHEDULER_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SCHEDULE_ID_RE = re.compile(r"DSD-[0-9A-F]{32}\Z")
SCHEDULER_KEY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}\Z")

RECEIPT_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "deployment_qualification": "none",
        "network": "injected_connection_factory_only",
        "persistence": "observed_database_transaction",
    }
)
HEALTH_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "deployment_qualification": "none",
        "health_check": "injected_connection_factory_only",
        "migration": "identity_observation_only",
    }
)


class PostgreSQLAdapterError(PersistenceRuntimeError):
    """Base error for concrete adapter failures."""


class PostgreSQLRetriableError(PostgreSQLAdapterError):
    """A database failure that a bounded caller retry may resolve."""


class PostgreSQLTerminalError(PostgreSQLAdapterError):
    """A database failure that must not be retried automatically."""


class FailureDisposition(StrEnum):
    RETRIABLE = "retriable"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class FailureClassification:
    disposition: FailureDisposition
    reason_code: str
    sqlstate: str | None


class DBAPICursor(Protocol):
    rowcount: int

    def execute(self, operation: str, parameters: Sequence[Any] = ()) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> Sequence[Any]: ...

    def close(self) -> Any: ...


class DBAPIConnection(Protocol):
    def cursor(self) -> DBAPICursor: ...

    def commit(self) -> Any: ...

    def rollback(self) -> Any: ...

    def close(self) -> Any: ...


ConnectionFactory = Callable[[], DBAPIConnection]


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _timestamp(value: str, label: str) -> str:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise PostgreSQLAdapterError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise PostgreSQLAdapterError(f"{label} is invalid") from exc
    return value


def _digest(value: str, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise PostgreSQLAdapterError(f"{label} must be a SHA-256 content address")
    return value


def _row_value(row: Any, key: str, index: int) -> Any:
    try:
        if isinstance(row, Mapping):
            if any(type(item) is not str for item in row):
                raise PostgreSQLAdapterError("database row keys must be native strings")
            return row[key]
        return row[index]
    except (KeyError, IndexError, TypeError) as exc:
        raise PostgreSQLAdapterError("database row projection is incomplete") from exc


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 1024:
        raise PostgreSQLAdapterError(f"{label} must be bounded native text")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9_223_372_036_854_775_807:
        raise PostgreSQLAdapterError(f"{label} must be a native database integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise PostgreSQLAdapterError(f"{label} must be a native boolean")
    return value


_INTEGER_FIELDS = frozenset(
    {
        "schema_version",
        "version",
        "expected_version",
        "fence_epoch",
        "definition_version",
        "interval_seconds",
        "max_occurrences",
        "max_occurrences_per_evaluation",
        "concurrency_limit",
        "lease_duration_seconds",
        "clock_skew_tolerance_seconds",
        "max_catch_up_occurrences",
        "max_attempts",
        "retry_budget_units",
        "retry_cost_units",
        "base_delay_seconds",
        "multiplier",
        "maximum_delay_seconds",
        "occurrence_index",
        "occurrence_version",
        "attempt_number",
        "lease_version",
        "expected_occurrence_version",
    }
)


def _document(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    """Capture bounded native JSON before contract normalization or hashing."""

    if not isinstance(raw, Mapping):
        raise PostgreSQLAdapterError(f"{label} must be a document")
    remaining = MAX_DOCUMENT_BYTES
    nodes = 0

    def charge(size: int) -> None:
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise PostgreSQLAdapterError(f"{label} exceeds the local document byte bound")

    def string(value: str) -> str:
        charge(2)
        if len(value) > remaining:
            raise PostgreSQLAdapterError(f"{label} exceeds the local document byte bound")
        for character in value:
            code = ord(character)
            if 0xD800 <= code <= 0xDFFF:
                raise PostgreSQLAdapterError(f"{label} contains invalid Unicode")
            charge(
                2
                if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}
                else 12
                if code > 0xFFFF
                else 6
                if code < 32 or code >= 127
                else 1
            )
        return value

    def visit(value: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise PostgreSQLAdapterError(f"{label} exceeds local document structure bounds")
        if type(value) is dict or (depth == 0 and isinstance(value, Mapping)):
            keys = list(value)
            if any(type(key) is not str for key in keys):
                raise PostgreSQLAdapterError(f"{label} requires native string keys")
            charge(2 + max(0, len(keys) - 1) + len(keys))
            result = {}
            for key in keys:
                string(key)
                item = value[key]
                if key in _INTEGER_FIELDS and type(item) is not int:
                    raise PostgreSQLAdapterError(f"{label} {key} must be a native integer")
                result[key] = visit(item, depth + 1)
            return result
        if type(value) is list:
            charge(2 + max(0, len(value) - 1))
            return [visit(item, depth + 1) for item in value]
        if type(value) is str:
            return string(value)
        if type(value) is int:
            if value.bit_length() > 4096:
                raise PostgreSQLAdapterError(f"{label} contains an overlarge integer")
            charge(len(str(value)))
            return value
        if type(value) is bool or value is None:
            charge(4 if value is None or value is True else 5)
            return value
        raise PostgreSQLAdapterError(f"{label} contains a non-native JSON value")

    return visit(raw, 0)


def _stored_document(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not str or len(value) > MAX_DOCUMENT_BYTES:
        raise PostgreSQLAdapterError(f"{label} must be bounded JSON text")
    try:
        if len(value.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise PostgreSQLAdapterError(f"{label} exceeds the local document byte bound")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in items:
                if key in result:
                    raise PostgreSQLAdapterError(f"{label} contains duplicate fields")
                result[key] = item
            return result

        def invalid_number(_: str) -> Any:
            raise PostgreSQLAdapterError(f"{label} contains unsupported numbers")

        raw = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_float=invalid_number,
            parse_constant=invalid_number,
        )
        document = _document(raw, label)
        if canonical_json(document) != value:
            raise PostgreSQLAdapterError(f"{label} is not canonical JSON")
        return document
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise PostgreSQLAdapterError(f"{label} is invalid JSON") from exc


def _replay_document(raw: Mapping[str, Any], family: Any, label: str) -> Any:
    document = _document(raw, label)
    try:
        result = family.from_dict(document)
        if canonical_json(result.to_dict()) != canonical_json(document):
            raise PostgreSQLAdapterError(f"{label} does not reproduce its native document")
        return result
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise PostgreSQLAdapterError(f"{label} does not reproduce its content") from exc


def _capture_contract(value: Any, family: Any, label: str) -> Any:
    if type(value) is not family:
        raise PostgreSQLAdapterError(f"{label} must be an exact {family.__name__}")
    try:
        return _replay_document(value.to_dict(), family, label)
    except (AttributeError, TypeError, ValueError) as exc:
        raise PostgreSQLAdapterError(f"{label} is malformed") from exc


def _scheduler_context(
    tenant_id: str,
    schedule_id: str,
    worker_ref: str | None = None,
    idempotency_key: str | None = None,
) -> None:
    for value, label, pattern in (
        (tenant_id, "tenant_id", SCHEDULER_IDENTIFIER_RE),
        (schedule_id, "schedule_id", SCHEDULE_ID_RE),
    ):
        if type(value) is not str or pattern.fullmatch(value) is None:
            raise PostgreSQLAdapterError(f"{label} is invalid")
    if worker_ref is not None and (
        type(worker_ref) is not str or SCHEDULER_IDENTIFIER_RE.fullmatch(worker_ref) is None
    ):
        raise PostgreSQLAdapterError("worker_ref is invalid")
    if idempotency_key is not None and (
        type(idempotency_key) is not str or SCHEDULER_KEY_RE.fullmatch(idempotency_key) is None
    ):
        raise PostgreSQLAdapterError("idempotency_key is invalid")


def _sqlstate(exc: BaseException) -> str | None:
    value = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    return value if isinstance(value, str) and re.fullmatch(r"[0-9A-Z]{5}", value) else None


def classify_postgresql_failure(exc: BaseException) -> FailureClassification:
    """Classify a driver failure without exposing its message or parameters."""

    state = _sqlstate(exc)
    if state in {"40001", "40P01", "55P03"}:
        return FailureClassification(FailureDisposition.RETRIABLE, "transaction_contention", state)
    if state is not None and state.startswith("08"):
        return FailureClassification(FailureDisposition.RETRIABLE, "connection_interrupted", state)
    if state in {"23503", "23505", "23514"}:
        return FailureClassification(FailureDisposition.TERMINAL, "integrity_constraint", state)
    if state in {"42501", "42P01"}:
        return FailureClassification(
            FailureDisposition.TERMINAL, "configuration_or_privilege", state
        )
    return FailureClassification(
        FailureDisposition.TERMINAL, "unclassified_database_failure", state
    )


@dataclass(frozen=True, slots=True)
class PostgreSQLRuntimeConfig:
    """Static adapter identity with no credentials or endpoint locators."""

    adapter_ref: str = "adapterref:persistence.postgresql-production"
    migration_version: int = POSTGRESQL_MIGRATION_VERSION
    migration_id: str = POSTGRESQL_MIGRATION_ID
    migration_sha256: str = POSTGRESQL_MIGRATION_SHA256

    def __post_init__(self) -> None:
        if type(self.adapter_ref) is not str or ADAPTER_RE.fullmatch(self.adapter_ref) is None:
            raise PostgreSQLAdapterError("adapter_ref must be an opaque adapter reference")
        if (
            type(self.migration_version) is not int
            or self.migration_version != POSTGRESQL_MIGRATION_VERSION
        ):
            raise PostgreSQLAdapterError("migration_version is unsupported")
        if type(self.migration_id) is not str or self.migration_id != POSTGRESQL_MIGRATION_ID:
            raise PostgreSQLAdapterError("migration_id is unsupported")
        _digest(self.migration_sha256, "migration_sha256")
        if self.migration_sha256 != POSTGRESQL_MIGRATION_SHA256:
            raise PostgreSQLAdapterError("migration_sha256 is unsupported")


@dataclass(frozen=True, slots=True)
class PostgreSQLTransactionReceipt:
    adapter_ref: str
    migration_id: str
    migration_sha256: str
    tenant_ref: str
    assessment_ref: str
    scope_ref: str
    batch_id: str
    batch_sha256: str
    aggregate_versions: tuple[tuple[str, int], ...]
    outbox_event_refs: tuple[str, ...]
    replayed: bool
    recorded_at: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.postgresql-transaction-receipt.v1"

    def __post_init__(self) -> None:
        if type(self.adapter_ref) is not str or ADAPTER_RE.fullmatch(self.adapter_ref) is None:
            raise PostgreSQLAdapterError("receipt adapter_ref is invalid")
        if type(self.migration_id) is not str or self.migration_id != POSTGRESQL_MIGRATION_ID:
            raise PostgreSQLAdapterError("receipt migration_id is invalid")
        _digest(self.migration_sha256, "migration_sha256")
        if self.migration_sha256 != POSTGRESQL_MIGRATION_SHA256:
            raise PostgreSQLAdapterError("receipt migration_sha256 is invalid")
        for name, namespace in (
            ("tenant_ref", "tenantref:"),
            ("assessment_ref", "assessmentref:"),
            ("scope_ref", "scoperef:"),
        ):
            value = getattr(self, name)
            if (
                type(value) is not str
                or REFERENCE_RE.fullmatch(value) is None
                or not value.startswith(namespace)
            ):
                raise PostgreSQLAdapterError(f"{name} is invalid")
        if type(self.batch_id) is not str or BATCH_ID_RE.fullmatch(self.batch_id) is None:
            raise PostgreSQLAdapterError("batch_id is invalid")
        _digest(self.batch_sha256, "batch_sha256")
        if type(self.replayed) is not bool:
            raise PostgreSQLAdapterError("replayed must be boolean")
        _timestamp(self.recorded_at, "recorded_at")
        if (
            type(self.aggregate_versions) is not tuple
            or len(self.aggregate_versions) > MAX_DOCUMENT_NODES
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not int
                or item[1] < 1
                for item in self.aggregate_versions
            )
        ):
            raise PostgreSQLAdapterError(
                "aggregate_versions must contain native reference/integer pairs"
            )
        if tuple(sorted(self.aggregate_versions)) != self.aggregate_versions:
            raise PostgreSQLAdapterError("aggregate_versions must be sorted")
        if len({item[0] for item in self.aggregate_versions}) != len(self.aggregate_versions):
            raise PostgreSQLAdapterError("aggregate_versions must be unique")
        if any(
            REFERENCE_RE.fullmatch(aggregate_ref) is None
            or not aggregate_ref.startswith("aggregateref:")
            for aggregate_ref, _ in self.aggregate_versions
        ):
            raise PostgreSQLAdapterError("aggregate references are invalid")
        if any(type(version) is not int or version < 1 for _, version in self.aggregate_versions):
            raise PostgreSQLAdapterError("aggregate versions must be positive integers")
        if (
            type(self.outbox_event_refs) is not tuple
            or len(self.outbox_event_refs) > MAX_DOCUMENT_NODES
            or any(type(item) is not str for item in self.outbox_event_refs)
        ):
            raise PostgreSQLAdapterError("outbox_event_refs must contain native references")
        if tuple(sorted(set(self.outbox_event_refs))) != self.outbox_event_refs:
            raise PostgreSQLAdapterError("outbox_event_refs must be unique and sorted")
        if any(
            REFERENCE_RE.fullmatch(event_ref) is None or not event_ref.startswith("outboxref:")
            for event_ref in self.outbox_event_refs
        ):
            raise PostgreSQLAdapterError("outbox event references are invalid")
        body = _document(self._body(), "transaction receipt")
        identifier, digest = _identity("PGR", self.KIND, body)
        object.__setattr__(self, "receipt_id", identifier)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "aggregate_versions": [
                {"aggregate_ref": aggregate_ref, "version": version}
                for aggregate_ref, version in self.aggregate_versions
            ],
            "assessment_ref": self.assessment_ref,
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
            "effects": dict(RECEIPT_EFFECTS),
            "kind": self.KIND,
            "migration_id": self.migration_id,
            "migration_sha256": self.migration_sha256,
            "outbox_event_refs": list(self.outbox_event_refs),
            "qualification_effect": "none",
            "recorded_at": self.recorded_at,
            "replayed": self.replayed,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    def transaction_result(self) -> TransactionResult:
        return TransactionResult(
            batch_id=self.batch_id,
            aggregate_versions=dict(self.aggregate_versions),
            outbox_event_refs=self.outbox_event_refs,
            replayed=self.replayed,
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PostgreSQLTransactionReceipt:
        raw = _document(raw, "transaction receipt")
        expected = {
            "adapter_ref",
            "aggregate_versions",
            "assessment_ref",
            "batch_id",
            "batch_sha256",
            "effects",
            "kind",
            "migration_id",
            "migration_sha256",
            "outbox_event_refs",
            "qualification_effect",
            "receipt_id",
            "receipt_sha256",
            "recorded_at",
            "replayed",
            "schema_version",
            "scope_ref",
            "tenant_ref",
        }
        if set(raw) != expected:
            raise PostgreSQLAdapterError("transaction receipt fields are invalid")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(RECEIPT_EFFECTS)
            or raw["qualification_effect"] != "none"
        ):
            raise PostgreSQLAdapterError("transaction receipt metadata is invalid")
        if (
            type(raw["aggregate_versions"]) is not list
            or any(
                type(item) is not dict or set(item) != {"aggregate_ref", "version"}
                for item in raw["aggregate_versions"]
            )
            or type(raw["outbox_event_refs"]) is not list
        ):
            raise PostgreSQLAdapterError("transaction receipt collections are invalid")
        result = cls(
            adapter_ref=raw["adapter_ref"],
            migration_id=raw["migration_id"],
            migration_sha256=raw["migration_sha256"],
            tenant_ref=raw["tenant_ref"],
            assessment_ref=raw["assessment_ref"],
            scope_ref=raw["scope_ref"],
            batch_id=raw["batch_id"],
            batch_sha256=raw["batch_sha256"],
            aggregate_versions=tuple(
                (item["aggregate_ref"], item["version"]) for item in raw["aggregate_versions"]
            ),
            outbox_event_refs=tuple(raw["outbox_event_refs"]),
            replayed=raw["replayed"],
            recorded_at=raw["recorded_at"],
        )
        if canonical_json(result.to_dict()) != canonical_json(raw):
            raise PostgreSQLAdapterError("transaction receipt content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class PostgreSQLHealthObservation:
    adapter_ref: str
    migration_id: str
    migration_sha256: str
    capability_declaration_id: str
    capability_declaration_sha256: str
    observed_at: str
    status: str = "healthy"
    connection_factory_invoked: bool = True
    live_deployment_proof: bool = False
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.postgresql-health-observation.v1"

    def __post_init__(self) -> None:
        if type(self.adapter_ref) is not str or ADAPTER_RE.fullmatch(self.adapter_ref) is None:
            raise PostgreSQLAdapterError("health adapter_ref is invalid")
        if type(self.migration_id) is not str or self.migration_id != POSTGRESQL_MIGRATION_ID:
            raise PostgreSQLAdapterError("health migration_id is invalid")
        for name in ("migration_sha256", "capability_declaration_sha256"):
            _digest(getattr(self, name), name)
        if self.migration_sha256 != POSTGRESQL_MIGRATION_SHA256:
            raise PostgreSQLAdapterError("health migration_sha256 is invalid")
        if (
            type(self.capability_declaration_id) is not str
            or CAPABILITY_ID_RE.fullmatch(self.capability_declaration_id) is None
        ):
            raise PostgreSQLAdapterError("capability_declaration_id is invalid")
        _timestamp(self.observed_at, "observed_at")
        if type(self.status) is not str or self.status != "healthy":
            raise PostgreSQLAdapterError("only validated healthy observations may be emitted")
        if self.connection_factory_invoked is not True or self.live_deployment_proof is not False:
            raise PostgreSQLAdapterError("health observation qualification boundary is invalid")
        identifier, digest = _identity("PGH", self.KIND, self._body())
        object.__setattr__(self, "observation_id", identifier)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "capability_declaration_id": self.capability_declaration_id,
            "capability_declaration_sha256": self.capability_declaration_sha256,
            "connection_factory_invoked": self.connection_factory_invoked,
            "effects": dict(HEALTH_EFFECTS),
            "kind": self.KIND,
            "live_deployment_proof": self.live_deployment_proof,
            "migration_id": self.migration_id,
            "migration_sha256": self.migration_sha256,
            "observed_at": self.observed_at,
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def parse_receipt(
    raw: Mapping[str, Any],
) -> PostgreSQLTransactionReceipt | PostgreSQLHealthObservation:
    raw = _document(raw, "PostgreSQL receipt")
    kind = raw.get("kind")
    if kind == PostgreSQLTransactionReceipt.KIND:
        return PostgreSQLTransactionReceipt.from_dict(raw)
    if kind == PostgreSQLHealthObservation.KIND:
        expected = {
            "adapter_ref",
            "capability_declaration_id",
            "capability_declaration_sha256",
            "connection_factory_invoked",
            "effects",
            "kind",
            "live_deployment_proof",
            "migration_id",
            "migration_sha256",
            "observation_id",
            "observation_sha256",
            "observed_at",
            "qualification_effect",
            "schema_version",
            "status",
        }
        if set(raw) != expected:
            raise PostgreSQLAdapterError("health observation fields are invalid")
        result = PostgreSQLHealthObservation(
            adapter_ref=raw["adapter_ref"],
            migration_id=raw["migration_id"],
            migration_sha256=raw["migration_sha256"],
            capability_declaration_id=raw["capability_declaration_id"],
            capability_declaration_sha256=raw["capability_declaration_sha256"],
            observed_at=raw["observed_at"],
            status=raw["status"],
            connection_factory_invoked=raw["connection_factory_invoked"],
            live_deployment_proof=raw["live_deployment_proof"],
        )
        if canonical_json(result.to_dict()) != canonical_json(raw):
            raise PostgreSQLAdapterError("health observation content address is invalid")
        return result
    raise PostgreSQLAdapterError("unsupported PostgreSQL adapter receipt kind")


class PostgreSQLPersistenceSchedulerAdapter:
    """Concrete SQL adapter over an explicitly injected DB-API factory."""

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        config: PostgreSQLRuntimeConfig | None = None,
        clock: Any | None = None,
    ) -> None:
        if not callable(connection_factory):
            raise PostgreSQLAdapterError("connection_factory must be callable")
        self._connection_factory = connection_factory
        self.config = PostgreSQLRuntimeConfig() if config is None else config
        if type(self.config) is not PostgreSQLRuntimeConfig:
            raise PostgreSQLAdapterError("config must be PostgreSQLRuntimeConfig")
        self.config.__post_init__()
        self.clock = clock or SystemClock()

    @contextmanager
    def _transaction(self) -> Iterator[DBAPICursor]:
        connection: DBAPIConnection | None = None
        cursor: DBAPICursor | None = None
        failure: Exception | None = None
        rollback_failure: Exception | None = None
        cleanup_failure: Exception | None = None
        commit_attempted = False
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            cursor.execute(
                "/*sunderkey:transaction-isolation*/ "
                "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE"
            )
            yield cursor
            commit_attempted = True
            connection.commit()
        except Exception as exc:
            failure = exc
            if connection is not None:
                try:
                    connection.rollback()
                except Exception as rollback_exc:
                    rollback_failure = rollback_exc
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception as close_exc:
                    cleanup_failure = close_exc
            if connection is not None:
                try:
                    connection.close()
                except Exception as close_exc:
                    cleanup_failure = cleanup_failure or close_exc
        if commit_attempted and (failure is not None or cleanup_failure is not None):
            raise PostgreSQLTerminalError(
                "PostgreSQL transaction outcome is uncertain after commit was attempted"
            ) from (failure or cleanup_failure)
        if rollback_failure is not None:
            raise PostgreSQLTerminalError(
                "PostgreSQL transaction outcome is uncertain because rollback failed"
            ) from rollback_failure
        if cleanup_failure is not None:
            raise PostgreSQLTerminalError("PostgreSQL cleanup failed closed") from cleanup_failure
        if failure is not None:
            if isinstance(
                failure,
                (
                    ConcurrencyConflict,
                    IdempotencyConflict,
                    MigrationIdentityError,
                    PostgreSQLAdapterError,
                ),
            ):
                raise failure
            classification = classify_postgresql_failure(failure)
            error_type = (
                PostgreSQLRetriableError
                if classification.disposition is FailureDisposition.RETRIABLE
                else PostgreSQLTerminalError
            )
            raise error_type(
                f"PostgreSQL operation failed closed: {classification.reason_code}"
            ) from failure

    def _migration_identity(self, cursor: DBAPICursor) -> tuple[str, str]:
        cursor.execute(
            "/*sunderkey:migration-identity*/ "
            "SELECT migration_id, migration_sha256 FROM schema_migrations WHERE version=%s",
            (self.config.migration_version,),
        )
        row = cursor.fetchone()
        if row is None:
            raise MigrationIdentityError("required PostgreSQL migration identity is absent")
        identity = (_row_value(row, "migration_id", 0), _row_value(row, "migration_sha256", 1))
        if any(type(item) is not str for item in identity) or identity != (
            self.config.migration_id,
            self.config.migration_sha256,
        ):
            raise MigrationIdentityError("PostgreSQL migration identity does not match")
        return identity

    def migration_identity(self) -> tuple[str, str]:
        with self._transaction() as cursor:
            return self._migration_identity(cursor)

    def observe_health(self, *, observed_at: str | None = None) -> PostgreSQLHealthObservation:
        timestamp = (
            _utc_text(self.clock.now())
            if observed_at is None
            else _timestamp(observed_at, "observed_at")
        )
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            cursor.execute("/*sunderkey:health*/ SELECT 1")
            row = cursor.fetchone()
            if row is None or _integer(_row_value(row, "health", 0), "health") != 1:
                raise PostgreSQLAdapterError("PostgreSQL health probe failed closed")
        declaration = postgresql_production_capabilities()
        return PostgreSQLHealthObservation(
            adapter_ref=self.config.adapter_ref,
            migration_id=self.config.migration_id,
            migration_sha256=self.config.migration_sha256,
            capability_declaration_id=declaration.declaration_id,
            capability_declaration_sha256=declaration.declaration_sha256,
            observed_at=timestamp,
        )

    def aggregate_version(self, tenant_ref: str, aggregate_ref: str) -> int:
        for value, namespace in ((tenant_ref, "tenantref:"), (aggregate_ref, "aggregateref:")):
            if (
                type(value) is not str
                or REFERENCE_RE.fullmatch(value) is None
                or not value.startswith(namespace)
            ):
                raise PostgreSQLAdapterError("aggregate query context is invalid")
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            cursor.execute(
                "/*sunderkey:aggregate-version*/ "
                "SELECT version FROM aggregate_heads "
                "WHERE tenant_ref=%s AND aggregate_ref=%s",
                (tenant_ref, aggregate_ref),
            )
            row = cursor.fetchone()
            return (
                0
                if row is None
                else _integer(_row_value(row, "version", 0), "aggregate version", 1)
            )

    def apply_transaction(self, batch: TransactionBatch) -> TransactionResult:
        return self.apply_transaction_receipt(batch).transaction_result()

    def apply_transaction_receipt(self, batch: TransactionBatch) -> PostgreSQLTransactionReceipt:
        batch = _capture_contract(batch, TransactionBatch, "batch")
        if batch.isolation_level is not IsolationLevel.SERIALIZABLE:
            raise PostgreSQLAdapterError("adapter requires serializable transaction batches")
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            cursor.execute(
                "/*sunderkey:transaction-prior*/ "
                "SELECT assessment_ref, scope_ref, batch_id, batch_sha256, "
                "tenant_ref, idempotency_key, batch_json "
                "FROM transaction_batches WHERE tenant_ref=%s AND idempotency_key=%s FOR UPDATE",
                (batch.tenant_ref, batch.idempotency_key),
            )
            prior = cursor.fetchone()
            if prior is not None:
                context = tuple(
                    _text(_row_value(prior, key, index), key)
                    for index, key in enumerate(("assessment_ref", "scope_ref"))
                )
                if context != (batch.assessment_ref, batch.scope_ref):
                    raise IdempotencyConflict("transaction context was rebound")
                if (
                    _text(_row_value(prior, "batch_id", 2), "batch_id") != batch.batch_id
                    or _digest(_row_value(prior, "batch_sha256", 3), "batch_sha256")
                    != batch.batch_sha256
                    or _text(_row_value(prior, "tenant_ref", 4), "tenant_ref") != batch.tenant_ref
                    or _text(_row_value(prior, "idempotency_key", 5), "idempotency_key")
                    != batch.idempotency_key
                ):
                    raise IdempotencyConflict("transaction idempotency key was rebound")
                stored = _replay_document(
                    _stored_document(_row_value(prior, "batch_json", 6), "stored batch"),
                    TransactionBatch,
                    "stored batch",
                )
                if stored.to_json() != batch.to_json():
                    raise IdempotencyConflict("transaction document was rebound")
                return self._transaction_receipt(batch, replayed=True)

            for fence in batch.fence_bindings:
                cursor.execute(
                    "/*sunderkey:fence-check*/ "
                    "SELECT fence_token, fence_epoch FROM resource_fences "
                    "WHERE tenant_ref=%s AND resource_ref=%s FOR UPDATE",
                    (batch.tenant_ref, fence.resource_ref),
                )
                row = cursor.fetchone()
                if row is None or (
                    _text(_row_value(row, "fence_token", 0), "fence_token") != fence.fence_token
                    or _integer(_row_value(row, "fence_epoch", 1), "fence_epoch", 1)
                    != fence.fence_epoch
                ):
                    raise ConcurrencyConflict("stale or unknown PostgreSQL fence binding")

            digests = {item.aggregate_ref: item.content_sha256 for item in batch.operations}
            for binding in batch.version_bindings:
                cursor.execute(
                    "/*sunderkey:aggregate-lock*/ "
                    "SELECT version FROM aggregate_heads "
                    "WHERE tenant_ref=%s AND aggregate_ref=%s FOR UPDATE",
                    (batch.tenant_ref, binding.aggregate_ref),
                )
                row = cursor.fetchone()
                current = (
                    0
                    if row is None
                    else _integer(_row_value(row, "version", 0), "aggregate version", 1)
                )
                if current != binding.expected_version:
                    raise ConcurrencyConflict("PostgreSQL aggregate version is stale")
                cursor.execute(
                    "/*sunderkey:aggregate-upsert*/ "
                    "INSERT INTO aggregate_heads"
                    "(tenant_ref,aggregate_ref,version,content_sha256) VALUES(%s,%s,%s,%s) "
                    "ON CONFLICT(tenant_ref,aggregate_ref) DO UPDATE SET "
                    "version=EXCLUDED.version,content_sha256=EXCLUDED.content_sha256 "
                    "WHERE aggregate_heads.version=%s",
                    (
                        batch.tenant_ref,
                        binding.aggregate_ref,
                        current + 1,
                        digests[binding.aggregate_ref],
                        current,
                    ),
                )
                if _integer(cursor.rowcount, "aggregate rowcount") != 1:
                    raise ConcurrencyConflict("PostgreSQL aggregate update lost concurrency race")

            for event_ref in batch.outbox_event_refs:
                payload = canonical_json({"batch_id": batch.batch_id, "event_ref": event_ref})
                cursor.execute(
                    "/*sunderkey:outbox-insert*/ "
                    "INSERT INTO outbox_events"
                    "(tenant_ref,event_ref,batch_id,event_json,created_at,published_at) "
                    "VALUES(%s,%s,%s,%s,%s,NULL)",
                    (
                        batch.tenant_ref,
                        event_ref,
                        batch.batch_id,
                        payload,
                        batch.created_at,
                    ),
                )

            receipt = self._transaction_receipt(batch, replayed=False)
            cursor.execute(
                "/*sunderkey:transaction-insert*/ "
                "INSERT INTO transaction_batches"
                "(tenant_ref,assessment_ref,scope_ref,idempotency_key,"
                "batch_id,batch_sha256,batch_json) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (
                    batch.tenant_ref,
                    batch.assessment_ref,
                    batch.scope_ref,
                    batch.idempotency_key,
                    batch.batch_id,
                    batch.batch_sha256,
                    batch.to_json(),
                ),
            )
            cursor.execute(
                "/*sunderkey:receipt-insert*/ "
                "INSERT INTO runtime_receipts"
                "(tenant_ref,receipt_id,receipt_sha256,receipt_json,created_at) "
                "VALUES(%s,%s,%s,%s,%s)",
                (
                    batch.tenant_ref,
                    receipt.receipt_id,
                    receipt.receipt_sha256,
                    receipt.to_json(),
                    batch.created_at,
                ),
            )
            return receipt

    def _transaction_receipt(
        self, batch: TransactionBatch, *, replayed: bool
    ) -> PostgreSQLTransactionReceipt:
        return PostgreSQLTransactionReceipt(
            adapter_ref=self.config.adapter_ref,
            migration_id=self.config.migration_id,
            migration_sha256=self.config.migration_sha256,
            tenant_ref=batch.tenant_ref,
            assessment_ref=batch.assessment_ref,
            scope_ref=batch.scope_ref,
            batch_id=batch.batch_id,
            batch_sha256=batch.batch_sha256,
            aggregate_versions=tuple(
                sorted(
                    (item.aggregate_ref, item.expected_version + 1)
                    for item in batch.version_bindings
                )
            ),
            outbox_event_refs=tuple(sorted(batch.outbox_event_refs)),
            replayed=replayed,
            recorded_at=batch.created_at,
        )

    def commit_artifact(self, plan: ArtifactRecordingPlan) -> ArtifactCommitObservation:
        try:
            owned = _capture_recording_plan(plan)
        except DurableArtifactRecorderError as exc:
            raise PostgreSQLAdapterError("artifact recording plan failed closed") from exc
        request = owned.request
        receipt = self.apply_transaction_receipt(owned.transaction_batch)
        return ArtifactCommitObservation(
            adapter_ref=self.config.adapter_ref,
            batch_id=receipt.batch_id,
            batch_sha256=receipt.batch_sha256,
            tenant_ref=request.tenant_ref,
            assessment_ref=request.assessment_ref,
            scope_ref=request.scope_ref,
            idempotency_key=request.idempotency_key,
            artifact_ref=request.artifact.artifact_ref,
            stored_content_sha256=request.artifact.content_sha256,
            custody_ref=request.artifact.custody_ref,
            prior_custody_sha256=request.artifact.prior_custody_sha256,
            custody_entry_sha256=custody_entry_sha256(request),
            expected_artifact_version=request.expected_artifact_version,
            observed_artifact_version=request.expected_artifact_version + 1,
            expected_custody_version=request.expected_custody_version,
            observed_custody_version=request.expected_custody_version + 1,
            fence_resource_ref=request.fence_resource_ref,
            fence_token=request.fence_token,
            fence_epoch=request.fence_epoch,
            outbox_event_ref=(
                None if request.outbox_event is None else request.outbox_event.outbox_event_ref
            ),
            disposition=(
                CommitDisposition.REPLAYED if receipt.replayed else CommitDisposition.COMMITTED
            ),
            observed_at=request.recorded_at,
        )

    def register_schedule(self, schedule: ScheduleDefinition) -> ScheduleDefinition:
        schedule = _capture_contract(schedule, ScheduleDefinition, "schedule")
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            cursor.execute(
                "/*sunderkey:schedule-prior*/ "
                "SELECT schedule_json,cancelled,tenant_id,schedule_id,schedule_sha256,"
                "definition_version FROM schedules "
                "WHERE tenant_id=%s AND schedule_id=%s FOR UPDATE",
                (schedule.tenant_id, schedule.schedule_id),
            )
            row = cursor.fetchone()
            if row is not None:
                stored = self._schedule_row(row, schedule.tenant_id, schedule.schedule_id)
                if canonical_json(stored.to_dict()) != canonical_json(schedule.to_dict()):
                    raise ConcurrencyConflict("schedule identifier has conflicting content")
                return stored
            cursor.execute(
                "/*sunderkey:schedule-insert*/ "
                "INSERT INTO schedules"
                "(tenant_id,schedule_id,schedule_sha256,definition_version,"
                "schedule_json,cancelled) "
                "VALUES(%s,%s,%s,%s,%s,FALSE)",
                (
                    schedule.tenant_id,
                    schedule.schedule_id,
                    schedule.schedule_sha256,
                    schedule.definition_version,
                    canonical_json(schedule.to_dict()),
                ),
            )
        return schedule

    def materialize_due(
        self, tenant_id: str, schedule_id: str, *, evaluated_at: str | None = None
    ) -> tuple[DueOccurrence, ...]:
        _scheduler_context(tenant_id, schedule_id)
        evaluated = (
            _utc_text(self.clock.now())
            if evaluated_at is None
            else _timestamp(evaluated_at, "evaluated_at")
        )
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            schedule = self._load_schedule(cursor, tenant_id, schedule_id)
            cursor.execute(
                "/*sunderkey:occurrence-indices*/ "
                "SELECT occurrence_index FROM occurrences "
                "WHERE tenant_id=%s AND schedule_id=%s ORDER BY occurrence_index",
                (tenant_id, schedule_id),
            )
            indices = tuple(
                _integer(_row_value(row, "occurrence_index", 0), "occurrence_index")
                for row in cursor.fetchall()
            )
            due = derive_due_occurrences(
                schedule,
                evaluated_at=evaluated,
                materialized_occurrence_indices=indices,
            )
            for occurrence in due:
                cursor.execute(
                    "/*sunderkey:occurrence-insert*/ "
                    "INSERT INTO occurrences"
                    "(tenant_id,occurrence_id,schedule_id,occurrence_index,occurrence_json,"
                    "occurrence_version,state,ready_at,attempt_number,fence_epoch,lease_id) "
                    "VALUES(%s,%s,%s,%s,%s,%s,'pending',%s,0,0,NULL) "
                    "ON CONFLICT(tenant_id,schedule_id,occurrence_index) DO NOTHING",
                    (
                        tenant_id,
                        occurrence.occurrence_id,
                        schedule_id,
                        occurrence.occurrence_index,
                        canonical_json(occurrence.to_dict()),
                        occurrence.occurrence_version,
                        occurrence.nominal_at,
                    ),
                )
                if _integer(cursor.rowcount, "occurrence rowcount") != 1:
                    raise ConcurrencyConflict("occurrence materialization lost concurrency race")
        return due

    def claim_due(
        self,
        tenant_id: str,
        schedule_id: str,
        worker_ref: str,
        idempotency_key: str,
        *,
        claimed_at: str | None = None,
    ) -> DurableLease | None:
        _scheduler_context(tenant_id, schedule_id, worker_ref, idempotency_key)
        if worker_ref is None or idempotency_key is None:
            raise PostgreSQLAdapterError("claim context is incomplete")
        claimed = (
            _utc_text(self.clock.now())
            if claimed_at is None
            else _timestamp(claimed_at, "claimed_at")
        )
        with self._transaction() as cursor:
            self._migration_identity(cursor)
            cursor.execute(
                "/*sunderkey:scheduler-result*/ "
                "SELECT result_kind,result_json,tenant_id,idempotency_key,result_sha256 "
                "FROM scheduler_results "
                "WHERE tenant_id=%s AND idempotency_key=%s FOR UPDATE",
                (tenant_id, idempotency_key),
            )
            prior = cursor.fetchone()
            if prior is not None:
                if _text(_row_value(prior, "result_kind", 0), "result_kind") != "claim":
                    raise IdempotencyConflict("scheduler idempotency key was rebound")
                lease = _replay_document(
                    _stored_document(_row_value(prior, "result_json", 1), "claim result"),
                    DurableLease,
                    "claim result",
                )
                if (
                    _text(_row_value(prior, "tenant_id", 2), "result tenant_id") != tenant_id
                    or _text(_row_value(prior, "idempotency_key", 3), "result idempotency_key")
                    != idempotency_key
                    or lease.tenant_id != tenant_id
                    or lease.schedule_id != schedule_id
                    or lease.worker_ref != worker_ref
                    or lease.idempotency_key != idempotency_key
                ):
                    raise IdempotencyConflict("scheduler claim context was rebound")
                if _digest(
                    _row_value(prior, "result_sha256", 4), "result_sha256"
                ) != canonical_sha256(lease.to_dict()):
                    raise PostgreSQLAdapterError("claim result hash does not match stored bytes")
                if (
                    lease.transition is not LeaseTransition.CLAIM
                    or lease.lease_version != 1
                    or lease.parent_lease_sha256 is not None
                    or lease.observed_at != lease.leased_at
                ):
                    raise PostgreSQLAdapterError("stored result is not an original claim")
                schedule = self._load_schedule(cursor, tenant_id, schedule_id, require_active=False)
                if lease.schedule_sha256 != schedule.schedule_sha256:
                    raise PostgreSQLAdapterError("claim result schedule content was rebound")
                self._verify_claim_snapshot(cursor, lease)
                return lease

            schedule = self._load_schedule(cursor, tenant_id, schedule_id)
            cursor.execute(
                "/*sunderkey:claim-candidate*/ "
                "SELECT occurrence_json,occurrence_version,attempt_number,fence_epoch,"
                "tenant_id,occurrence_id,schedule_id,occurrence_index,state,ready_at,lease_id "
                "FROM occurrences WHERE tenant_id=%s AND schedule_id=%s "
                "AND state IN ('pending','retry') AND ready_at<=%s "
                "ORDER BY ready_at,occurrence_index FOR UPDATE SKIP LOCKED LIMIT 1",
                (tenant_id, schedule_id, claimed),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            occurrence = _replay_document(
                _stored_document(_row_value(row, "occurrence_json", 0), "occurrence"),
                DueOccurrence,
                "occurrence",
            )
            occurrence_version = _integer(
                _row_value(row, "occurrence_version", 1), "occurrence_version", 1
            )
            attempt = _integer(_row_value(row, "attempt_number", 2), "attempt_number") + 1
            fence_epoch = _integer(_row_value(row, "fence_epoch", 3), "fence_epoch") + 1
            if (
                _text(_row_value(row, "tenant_id", 4), "occurrence tenant_id") != tenant_id
                or _text(_row_value(row, "occurrence_id", 5), "occurrence_id")
                != occurrence.occurrence_id
                or _text(_row_value(row, "schedule_id", 6), "occurrence schedule_id") != schedule_id
                or _integer(_row_value(row, "occurrence_index", 7), "occurrence_index")
                != occurrence.occurrence_index
                or occurrence.tenant_id != tenant_id
                or occurrence.schedule_id != schedule_id
                or occurrence.schedule_sha256 != schedule.schedule_sha256
                or _text(_row_value(row, "state", 8), "occurrence state")
                not in {"pending", "retry"}
                or _timestamp(_row_value(row, "ready_at", 9), "ready_at") > claimed
                or _row_value(row, "lease_id", 10) is not None
            ):
                raise PostgreSQLAdapterError(
                    "selected occurrence is not bound to its row and schedule"
                )
            occurrence = _occurrence_with_version(occurrence, occurrence_version)
            expires = _utc_text(
                _parse_utc(claimed) + timedelta(seconds=schedule.lease_duration_seconds)
            )
            lease = claim_due_occurrence(
                schedule,
                occurrence,
                worker_ref=worker_ref,
                attempt_number=attempt,
                fence_epoch=fence_epoch,
                expected_occurrence_version=occurrence.occurrence_version,
                claimed_at=claimed,
                expires_at=expires,
                idempotency_key=idempotency_key,
            )
            cursor.execute(
                "/*sunderkey:lease-insert*/ "
                "INSERT INTO lease_snapshots"
                "(tenant_id,lease_id,lease_version,occurrence_id,fence_epoch,"
                "expires_at,active,lease_json) "
                "VALUES(%s,%s,%s,%s,%s,%s,TRUE,%s)",
                (
                    tenant_id,
                    lease.lease_id,
                    lease.lease_version,
                    lease.occurrence_id,
                    lease.fence_epoch,
                    lease.expires_at,
                    canonical_json(lease.to_dict()),
                ),
            )
            cursor.execute(
                "/*sunderkey:occurrence-claim*/ "
                "UPDATE occurrences SET state='leased',attempt_number=%s,"
                "fence_epoch=%s,lease_id=%s "
                "WHERE tenant_id=%s AND occurrence_id=%s "
                "AND occurrence_version=%s AND state IN ('pending','retry')",
                (
                    attempt,
                    fence_epoch,
                    lease.lease_id,
                    tenant_id,
                    occurrence.occurrence_id,
                    occurrence.occurrence_version,
                ),
            )
            if _integer(cursor.rowcount, "claim rowcount") != 1:
                raise ConcurrencyConflict("scheduler claim lost concurrency race")
            document = canonical_json(lease.to_dict())
            cursor.execute(
                "/*sunderkey:scheduler-result-insert*/ "
                "INSERT INTO scheduler_results"
                "(tenant_id,idempotency_key,result_kind,result_sha256,result_json) "
                "VALUES(%s,%s,'claim',%s,%s)",
                (tenant_id, idempotency_key, canonical_sha256(lease.to_dict()), document),
            )
            event_ref = "outboxref:scheduler." + lease.lease_sha256.removeprefix("sha256:")
            cursor.execute(
                "/*sunderkey:outbox-insert*/ "
                "INSERT INTO outbox_events"
                "(tenant_ref,event_ref,batch_id,event_json,created_at,published_at) "
                "VALUES(%s,%s,%s,%s,%s,NULL)",
                (tenant_id, event_ref, lease.lease_id, document, claimed),
            )
            return lease

    def _load_schedule(
        self, cursor: DBAPICursor, tenant_id: str, schedule_id: str, *, require_active: bool = True
    ) -> ScheduleDefinition:
        cursor.execute(
            "/*sunderkey:schedule-load*/ "
            "SELECT schedule_json,cancelled,tenant_id,schedule_id,schedule_sha256,"
            "definition_version FROM schedules "
            "WHERE tenant_id=%s AND schedule_id=%s FOR UPDATE",
            (tenant_id, schedule_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise PostgreSQLAdapterError("tenant-bound schedule was not found")
        schedule = self._schedule_row(row, tenant_id, schedule_id)
        if require_active and _row_value(row, "cancelled", 1):
            raise PostgreSQLAdapterError("tenant-bound schedule is cancelled")
        return schedule

    def _schedule_row(self, row: Any, tenant_id: str, schedule_id: str) -> ScheduleDefinition:
        _boolean(_row_value(row, "cancelled", 1), "cancelled")
        schedule = _replay_document(
            _stored_document(_row_value(row, "schedule_json", 0), "schedule"),
            ScheduleDefinition,
            "schedule",
        )
        if (
            _text(_row_value(row, "tenant_id", 2), "schedule tenant_id") != tenant_id
            or _text(_row_value(row, "schedule_id", 3), "schedule_id") != schedule_id
            or schedule.tenant_id != tenant_id
            or schedule.schedule_id != schedule_id
            or _digest(_row_value(row, "schedule_sha256", 4), "schedule_sha256")
            != schedule.schedule_sha256
            or _integer(_row_value(row, "definition_version", 5), "definition_version", 1)
            != schedule.definition_version
        ):
            raise PostgreSQLAdapterError("schedule document does not match its selected row")
        return schedule

    def _verify_claim_snapshot(self, cursor: DBAPICursor, lease: DurableLease) -> None:
        cursor.execute(
            "/*sunderkey:lease-snapshot*/ "
            "SELECT tenant_id,lease_id,lease_version,occurrence_id,fence_epoch,"
            "expires_at,active,lease_json FROM lease_snapshots "
            "WHERE tenant_id=%s AND lease_id=%s AND lease_version=%s FOR UPDATE",
            (lease.tenant_id, lease.lease_id, lease.lease_version),
        )
        row = cursor.fetchone()
        if row is None:
            raise PostgreSQLAdapterError("original claim snapshot is absent")
        _boolean(_row_value(row, "active", 6), "snapshot active")
        snapshot = _replay_document(
            _stored_document(_row_value(row, "lease_json", 7), "lease snapshot"),
            DurableLease,
            "lease snapshot",
        )
        if (
            _text(_row_value(row, "tenant_id", 0), "snapshot tenant_id") != lease.tenant_id
            or _text(_row_value(row, "lease_id", 1), "snapshot lease_id") != lease.lease_id
            or _integer(_row_value(row, "lease_version", 2), "snapshot lease_version", 1)
            != lease.lease_version
            or _text(_row_value(row, "occurrence_id", 3), "snapshot occurrence_id")
            != lease.occurrence_id
            or _integer(_row_value(row, "fence_epoch", 4), "snapshot fence_epoch", 1)
            != lease.fence_epoch
            or _timestamp(_row_value(row, "expires_at", 5), "snapshot expires_at")
            != lease.expires_at
            or canonical_json(snapshot.to_dict()) != canonical_json(lease.to_dict())
        ):
            raise PostgreSQLAdapterError("claim result does not match its original snapshot")


def _parse_utc(value: str) -> datetime:
    _timestamp(value, "timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PostgreSQLAdapterError("clock must return an aware datetime")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _occurrence_with_version(occurrence: DueOccurrence, version: int) -> DueOccurrence:
    raw = occurrence.to_dict()
    raw["occurrence_version"] = version
    if version == occurrence.occurrence_version:
        return occurrence
    return DueOccurrence(
        occurrence_id=occurrence.occurrence_id,
        occurrence_sha256=occurrence.occurrence_sha256,
        tenant_id=occurrence.tenant_id,
        schedule_id=occurrence.schedule_id,
        schedule_sha256=occurrence.schedule_sha256,
        occurrence_index=occurrence.occurrence_index,
        nominal_at=occurrence.nominal_at,
        evaluated_at=occurrence.evaluated_at,
        due_reason=occurrence.due_reason,
        occurrence_version=version,
        idempotency_key=occurrence.idempotency_key,
    )
