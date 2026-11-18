"""Deterministic persistence port contracts with no database effects.

The records in this module describe storage capabilities, migrations, and
atomic transaction intent. They do not connect to a database, execute SQL,
persist records, migrate state, grant authority, or qualify a deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "database_connection": "none",
        "deployment": "none",
        "migration": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "sql_execution": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|scoperef|adapterref|storeref|migrationref|"
    r"rollbackref|artifactref|aggregateref|operationref|outboxref|resourceref|"
    r"verificationref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
FENCE_RE = re.compile(r"fence:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")


class PersistenceContractError(ValueError):
    """Raised when a persistence port record fails closed."""


class BackendKind(StrEnum):
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


class DeploymentClass(StrEnum):
    LOCAL_DEVELOPMENT = "local_development"
    SINGLE_WORKER_TEST = "single_worker_test"
    MULTI_WORKER_PRODUCTION = "multi_worker_production"
    HIGH_AVAILABILITY_PRODUCTION = "high_availability_production"


class IsolationLevel(StrEnum):
    SERIALIZABLE = "serializable"
    REPEATABLE_READ = "repeatable_read"
    READ_COMMITTED = "read_committed"


class OperationKind(StrEnum):
    APPEND = "append"
    RESERVATION = "reservation"
    STATE_TRANSITION = "state_transition"
    OUTBOX_ENQUEUE = "outbox_enqueue"


class MigrationMode(StrEnum):
    OFFLINE = "offline"
    EXPAND_CONTRACT = "expand_contract"


class SuitabilityStatus(StrEnum):
    INCOMPATIBLE = "incompatible"
    CONTRACT_COMPATIBLE_UNVERIFIED = "contract_compatible_unverified"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    _validate_json(value, "value")
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 12:
        raise PersistenceContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PersistenceContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise PersistenceContractError(f"{label} has an unsupported value")


def _exact(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise PersistenceContractError(f"{label} fields are invalid")


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise PersistenceContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise PersistenceContractError(f"{label} must use the {namespace} namespace")
    return value


def _references(
    values: Sequence[str], label: str, namespace: str, *, minimum: int = 0
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise PersistenceContractError(f"{label} must be a sequence")
    normalized = tuple(_reference(item, f"{label} item", namespace) for item in values)
    if len(normalized) < minimum or len(normalized) != len(set(normalized)):
        raise PersistenceContractError(f"{label} has invalid cardinality")
    return tuple(sorted(normalized))


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PersistenceContractError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise PersistenceContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise PersistenceContractError(f"{label} must be valid") from exc
    return value


def _positive(value: Any, label: str, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise PersistenceContractError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PersistenceContractError(f"{label} must be a non-negative integer")
    return value


def _enum_tuple(values: Sequence[Any], enum: type[StrEnum], label: str) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise PersistenceContractError(f"{label} must be a non-empty sequence")
    try:
        normalized = tuple(sorted((enum(item) for item in values), key=str))
    except ValueError as exc:
        raise PersistenceContractError(f"{label} contains an unsupported value") from exc
    if len(normalized) != len(set(normalized)):
        raise PersistenceContractError(f"{label} must contain unique values")
    return normalized


def _addressed_dict(instance: Any, id_field: str, digest_field: str) -> dict[str, Any]:
    body = instance._body()
    return {
        **body,
        id_field: getattr(instance, id_field),
        digest_field: getattr(instance, digest_field),
    }


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise PersistenceContractError("record content address does not match content")


@dataclass(frozen=True, slots=True)
class BackendCapabilityDeclaration:
    """Immutable backend capability claim for compatibility planning."""

    backend: BackendKind
    adapter_ref: str
    adapter_version: str
    deployment_classes: tuple[DeploymentClass, ...]
    isolation_levels: tuple[IsolationLevel, ...]
    max_concurrent_workers: int
    atomic_transaction_batches: bool
    atomic_outbox_enqueue: bool
    optimistic_concurrency: bool
    fencing_tokens: bool
    idempotency_keys: bool
    multi_writer: bool
    high_availability: bool
    tenant_isolation: bool
    online_migrations: bool
    declaration_id: str = field(init=False)
    declaration_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.persistence-backend-capability.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "backend", BackendKind(self.backend))
        object.__setattr__(
            self, "adapter_ref", _reference(self.adapter_ref, "adapter_ref", "adapterref")
        )
        if (
            not isinstance(self.adapter_version, str)
            or VERSION_RE.fullmatch(self.adapter_version) is None
        ):
            raise PersistenceContractError("adapter_version must be an exact numeric version")
        object.__setattr__(
            self,
            "deployment_classes",
            _enum_tuple(self.deployment_classes, DeploymentClass, "deployment_classes"),
        )
        object.__setattr__(
            self,
            "isolation_levels",
            _enum_tuple(self.isolation_levels, IsolationLevel, "isolation_levels"),
        )
        _positive(self.max_concurrent_workers, "max_concurrent_workers", 100_000)
        for name in (
            "atomic_transaction_batches",
            "atomic_outbox_enqueue",
            "optimistic_concurrency",
            "fencing_tokens",
            "idempotency_keys",
            "multi_writer",
            "high_availability",
            "tenant_isolation",
            "online_migrations",
        ):
            if not isinstance(getattr(self, name), bool):
                raise PersistenceContractError(f"{name} must be boolean")
        if self.backend is BackendKind.SQLITE:
            allowed = {
                DeploymentClass.LOCAL_DEVELOPMENT,
                DeploymentClass.SINGLE_WORKER_TEST,
            }
            if (
                not set(self.deployment_classes).issubset(allowed)
                or self.max_concurrent_workers != 1
                or self.multi_writer
                or self.high_availability
                or self.tenant_isolation
                or self.online_migrations
            ):
                raise PersistenceContractError(
                    "SQLite capabilities must remain single-worker development or test only"
                )
        identifier, digest = _identity("PBD", self.KIND, self._body())
        object.__setattr__(self, "declaration_id", identifier)
        object.__setattr__(self, "declaration_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "adapter_version": self.adapter_version,
            "atomic_outbox_enqueue": self.atomic_outbox_enqueue,
            "atomic_transaction_batches": self.atomic_transaction_batches,
            "backend": self.backend.value,
            "deployment_classes": [item.value for item in self.deployment_classes],
            "effects": dict(NO_EFFECTS),
            "fencing_tokens": self.fencing_tokens,
            "high_availability": self.high_availability,
            "idempotency_keys": self.idempotency_keys,
            "isolation_levels": [item.value for item in self.isolation_levels],
            "kind": self.KIND,
            "max_concurrent_workers": self.max_concurrent_workers,
            "multi_writer": self.multi_writer,
            "online_migrations": self.online_migrations,
            "optimistic_concurrency": self.optimistic_concurrency,
            "schema_version": SCHEMA_VERSION,
            "tenant_isolation": self.tenant_isolation,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed_dict(self, "declaration_id", "declaration_sha256")

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> BackendCapabilityDeclaration:
        expected = {
            "adapter_ref",
            "adapter_version",
            "atomic_outbox_enqueue",
            "atomic_transaction_batches",
            "backend",
            "declaration_id",
            "declaration_sha256",
            "deployment_classes",
            "effects",
            "fencing_tokens",
            "high_availability",
            "idempotency_keys",
            "isolation_levels",
            "kind",
            "max_concurrent_workers",
            "multi_writer",
            "online_migrations",
            "optimistic_concurrency",
            "schema_version",
            "tenant_isolation",
        }
        _exact(raw, expected, "backend capability declaration")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(NO_EFFECTS)
        ):
            raise PersistenceContractError("backend capability metadata is invalid")
        _verify_address(raw, "declaration_id", "declaration_sha256", "PBD", cls.KIND)
        result = cls(
            backend=raw["backend"],
            adapter_ref=raw["adapter_ref"],
            adapter_version=raw["adapter_version"],
            deployment_classes=tuple(raw["deployment_classes"]),
            isolation_levels=tuple(raw["isolation_levels"]),
            max_concurrent_workers=raw["max_concurrent_workers"],
            atomic_transaction_batches=raw["atomic_transaction_batches"],
            atomic_outbox_enqueue=raw["atomic_outbox_enqueue"],
            optimistic_concurrency=raw["optimistic_concurrency"],
            fencing_tokens=raw["fencing_tokens"],
            idempotency_keys=raw["idempotency_keys"],
            multi_writer=raw["multi_writer"],
            high_availability=raw["high_availability"],
            tenant_isolation=raw["tenant_isolation"],
            online_migrations=raw["online_migrations"],
        )
        if result.to_dict() != dict(raw):
            raise PersistenceContractError("backend capability serialization is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> BackendCapabilityDeclaration:
        return cls.from_dict(_canonical_document(document))


def sqlite_development_capabilities() -> BackendCapabilityDeclaration:
    """Return the bounded local SQLite capability declaration."""

    return BackendCapabilityDeclaration(
        backend=BackendKind.SQLITE,
        adapter_ref="adapterref:persistence.sqlite-local",
        adapter_version="1.0.0",
        deployment_classes=(DeploymentClass.LOCAL_DEVELOPMENT, DeploymentClass.SINGLE_WORKER_TEST),
        isolation_levels=(IsolationLevel.SERIALIZABLE,),
        max_concurrent_workers=1,
        atomic_transaction_batches=True,
        atomic_outbox_enqueue=True,
        optimistic_concurrency=True,
        fencing_tokens=True,
        idempotency_keys=True,
        multi_writer=False,
        high_availability=False,
        tenant_isolation=False,
        online_migrations=False,
    )


def postgresql_production_capabilities() -> BackendCapabilityDeclaration:
    """Return the intended PostgreSQL port contract, not a deployed adapter claim."""

    return BackendCapabilityDeclaration(
        backend=BackendKind.POSTGRESQL,
        adapter_ref="adapterref:persistence.postgresql-production",
        adapter_version="1.0.0",
        deployment_classes=(
            DeploymentClass.HIGH_AVAILABILITY_PRODUCTION,
            DeploymentClass.MULTI_WORKER_PRODUCTION,
        ),
        isolation_levels=(
            IsolationLevel.READ_COMMITTED,
            IsolationLevel.REPEATABLE_READ,
            IsolationLevel.SERIALIZABLE,
        ),
        max_concurrent_workers=10_000,
        atomic_transaction_batches=True,
        atomic_outbox_enqueue=True,
        optimistic_concurrency=True,
        fencing_tokens=True,
        idempotency_keys=True,
        multi_writer=True,
        high_availability=True,
        tenant_isolation=True,
        online_migrations=True,
    )


@dataclass(frozen=True, slots=True)
class MigrationStep:
    sequence: int
    migration_ref: str
    artifact_sha256: str
    from_version: int
    to_version: int
    mode: MigrationMode
    rollback_ref: str | None

    def __post_init__(self) -> None:
        _positive(self.sequence, "migration sequence", 100_000)
        object.__setattr__(
            self, "migration_ref", _reference(self.migration_ref, "migration_ref", "migrationref")
        )
        object.__setattr__(
            self, "artifact_sha256", _digest(self.artifact_sha256, "artifact_sha256")
        )
        _nonnegative(self.from_version, "from_version")
        _positive(self.to_version, "to_version")
        if self.to_version != self.from_version + 1:
            raise PersistenceContractError("migration versions must advance by exactly one")
        object.__setattr__(self, "mode", MigrationMode(self.mode))
        if self.rollback_ref is not None:
            object.__setattr__(
                self, "rollback_ref", _reference(self.rollback_ref, "rollback_ref", "rollbackref")
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "from_version": self.from_version,
            "migration_ref": self.migration_ref,
            "mode": self.mode.value,
            "rollback_ref": self.rollback_ref,
            "sequence": self.sequence,
            "to_version": self.to_version,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> MigrationStep:
        _exact(
            raw,
            {
                "artifact_sha256",
                "from_version",
                "migration_ref",
                "mode",
                "rollback_ref",
                "sequence",
                "to_version",
            },
            "migration step",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class MigrationManifest:
    """Ordered, content-addressed migration plan with no executable SQL."""

    backend: BackendKind
    store_ref: str
    generated_at: str
    steps: tuple[MigrationStep, ...]
    precondition_refs: tuple[str, ...]
    postcondition_refs: tuple[str, ...]
    manifest_id: str = field(init=False)
    manifest_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.persistence-migration-manifest.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "backend", BackendKind(self.backend))
        object.__setattr__(self, "store_ref", _reference(self.store_ref, "store_ref", "storeref"))
        object.__setattr__(self, "generated_at", _timestamp(self.generated_at, "generated_at"))
        if (
            not isinstance(self.steps, tuple)
            or not self.steps
            or not all(isinstance(item, MigrationStep) for item in self.steps)
        ):
            raise PersistenceContractError(
                "steps must be a non-empty tuple of MigrationStep records"
            )
        for index, step in enumerate(self.steps, start=1):
            if step.sequence != index:
                raise PersistenceContractError("migration sequences must be contiguous")
            if index > 1 and self.steps[index - 2].to_version != step.from_version:
                raise PersistenceContractError("migration version chain is not contiguous")
            if self.backend is BackendKind.POSTGRESQL and step.mode is MigrationMode.OFFLINE:
                raise PersistenceContractError(
                    "PostgreSQL production migrations must use expand_contract"
                )
        object.__setattr__(
            self,
            "precondition_refs",
            _references(self.precondition_refs, "precondition_refs", "verificationref", minimum=1),
        )
        object.__setattr__(
            self,
            "postcondition_refs",
            _references(
                self.postcondition_refs, "postcondition_refs", "verificationref", minimum=1
            ),
        )
        identifier, digest = _identity("PMM", self.KIND, self._body())
        object.__setattr__(self, "manifest_id", identifier)
        object.__setattr__(self, "manifest_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "backend": self.backend.value,
            "effects": dict(NO_EFFECTS),
            "generated_at": self.generated_at,
            "kind": self.KIND,
            "postcondition_refs": list(self.postcondition_refs),
            "precondition_refs": list(self.precondition_refs),
            "schema_version": SCHEMA_VERSION,
            "steps": [step.to_dict() for step in self.steps],
            "store_ref": self.store_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed_dict(self, "manifest_id", "manifest_sha256")

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> MigrationManifest:
        expected = {
            "backend",
            "effects",
            "generated_at",
            "kind",
            "manifest_id",
            "manifest_sha256",
            "postcondition_refs",
            "precondition_refs",
            "schema_version",
            "steps",
            "store_ref",
        }
        _exact(raw, expected, "migration manifest")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(NO_EFFECTS)
        ):
            raise PersistenceContractError("migration manifest metadata is invalid")
        _verify_address(raw, "manifest_id", "manifest_sha256", "PMM", cls.KIND)
        result = cls(
            backend=raw["backend"],
            store_ref=raw["store_ref"],
            generated_at=raw["generated_at"],
            steps=tuple(MigrationStep.from_dict(item) for item in raw["steps"]),
            precondition_refs=tuple(raw["precondition_refs"]),
            postcondition_refs=tuple(raw["postcondition_refs"]),
        )
        if result.to_dict() != dict(raw):
            raise PersistenceContractError("migration manifest serialization is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> MigrationManifest:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class TransactionOperation:
    operation_ref: str
    kind: OperationKind
    aggregate_ref: str
    content_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "operation_ref", _reference(self.operation_ref, "operation_ref", "operationref")
        )
        object.__setattr__(self, "kind", OperationKind(self.kind))
        object.__setattr__(
            self, "aggregate_ref", _reference(self.aggregate_ref, "aggregate_ref", "aggregateref")
        )
        object.__setattr__(self, "content_sha256", _digest(self.content_sha256, "content_sha256"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_ref": self.aggregate_ref,
            "content_sha256": self.content_sha256,
            "kind": self.kind.value,
            "operation_ref": self.operation_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TransactionOperation:
        _exact(
            raw,
            {"aggregate_ref", "content_sha256", "kind", "operation_ref"},
            "transaction operation",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class AggregateVersionBinding:
    aggregate_ref: str
    expected_version: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "aggregate_ref", _reference(self.aggregate_ref, "aggregate_ref", "aggregateref")
        )
        _nonnegative(self.expected_version, "expected_version")

    def to_dict(self) -> dict[str, Any]:
        return {"aggregate_ref": self.aggregate_ref, "expected_version": self.expected_version}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AggregateVersionBinding:
        _exact(raw, {"aggregate_ref", "expected_version"}, "aggregate version binding")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class FenceBinding:
    resource_ref: str
    fence_token: str
    fence_epoch: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "resource_ref", _reference(self.resource_ref, "resource_ref", "resourceref")
        )
        if not isinstance(self.fence_token, str) or FENCE_RE.fullmatch(self.fence_token) is None:
            raise PersistenceContractError("fence_token is invalid")
        _positive(self.fence_epoch, "fence_epoch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "fence_epoch": self.fence_epoch,
            "fence_token": self.fence_token,
            "resource_ref": self.resource_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FenceBinding:
        _exact(raw, {"fence_epoch", "fence_token", "resource_ref"}, "fence binding")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class TransactionBatch:
    """Atomic mutation intent bound to tenant, scope, versions, and fences."""

    tenant_ref: str
    assessment_ref: str
    scope_ref: str
    idempotency_key: str
    isolation_level: IsolationLevel
    created_at: str
    operations: tuple[TransactionOperation, ...]
    version_bindings: tuple[AggregateVersionBinding, ...]
    fence_bindings: tuple[FenceBinding, ...]
    outbox_event_refs: tuple[str, ...]
    batch_id: str = field(init=False)
    batch_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.persistence-transaction-batch.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("scope_ref", "scoperef"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise PersistenceContractError("idempotency_key is invalid")
        object.__setattr__(self, "isolation_level", IsolationLevel(self.isolation_level))
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        if (
            not isinstance(self.operations, tuple)
            or not self.operations
            or not all(isinstance(item, TransactionOperation) for item in self.operations)
        ):
            raise PersistenceContractError("operations must be a non-empty tuple")
        if (
            not isinstance(self.version_bindings, tuple)
            or not self.version_bindings
            or not all(isinstance(item, AggregateVersionBinding) for item in self.version_bindings)
        ):
            raise PersistenceContractError("version_bindings must be a non-empty tuple")
        if (
            not isinstance(self.fence_bindings, tuple)
            or not self.fence_bindings
            or not all(isinstance(item, FenceBinding) for item in self.fence_bindings)
        ):
            raise PersistenceContractError("fence_bindings must be a non-empty tuple")
        operation_refs = [item.operation_ref for item in self.operations]
        aggregates = {item.aggregate_ref for item in self.operations}
        version_aggregates = [item.aggregate_ref for item in self.version_bindings]
        fence_resources = [item.resource_ref for item in self.fence_bindings]
        if len(operation_refs) != len(set(operation_refs)):
            raise PersistenceContractError("operation_ref values must be unique")
        if (
            len(version_aggregates) != len(set(version_aggregates))
            or set(version_aggregates) != aggregates
        ):
            raise PersistenceContractError("every operation aggregate requires one version binding")
        if len(fence_resources) != len(set(fence_resources)):
            raise PersistenceContractError("fence resources must be unique")
        object.__setattr__(
            self,
            "outbox_event_refs",
            _references(self.outbox_event_refs, "outbox_event_refs", "outboxref"),
        )
        has_outbox = any(item.kind is OperationKind.OUTBOX_ENQUEUE for item in self.operations)
        if has_outbox != bool(self.outbox_event_refs):
            raise PersistenceContractError(
                "outbox operation and event references must appear together"
            )
        identifier, digest = _identity("PTB", self.KIND, self._body())
        object.__setattr__(self, "batch_id", identifier)
        object.__setattr__(self, "batch_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "atomicity": "all_or_nothing_with_outbox",
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "fence_bindings": [item.to_dict() for item in self.fence_bindings],
            "idempotency_key": self.idempotency_key,
            "isolation_level": self.isolation_level.value,
            "kind": self.KIND,
            "operations": [item.to_dict() for item in self.operations],
            "outbox_event_refs": list(self.outbox_event_refs),
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
            "version_bindings": [item.to_dict() for item in self.version_bindings],
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed_dict(self, "batch_id", "batch_sha256")

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TransactionBatch:
        expected = {
            "assessment_ref",
            "atomicity",
            "batch_id",
            "batch_sha256",
            "created_at",
            "effects",
            "fence_bindings",
            "idempotency_key",
            "isolation_level",
            "kind",
            "operations",
            "outbox_event_refs",
            "schema_version",
            "scope_ref",
            "tenant_ref",
            "version_bindings",
        }
        _exact(raw, expected, "transaction batch")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(NO_EFFECTS)
            or raw["atomicity"] != "all_or_nothing_with_outbox"
        ):
            raise PersistenceContractError("transaction batch metadata is invalid")
        _verify_address(raw, "batch_id", "batch_sha256", "PTB", cls.KIND)
        result = cls(
            tenant_ref=raw["tenant_ref"],
            assessment_ref=raw["assessment_ref"],
            scope_ref=raw["scope_ref"],
            idempotency_key=raw["idempotency_key"],
            isolation_level=raw["isolation_level"],
            created_at=raw["created_at"],
            operations=tuple(TransactionOperation.from_dict(item) for item in raw["operations"]),
            version_bindings=tuple(
                AggregateVersionBinding.from_dict(item) for item in raw["version_bindings"]
            ),
            fence_bindings=tuple(FenceBinding.from_dict(item) for item in raw["fence_bindings"]),
            outbox_event_refs=tuple(raw["outbox_event_refs"]),
        )
        if result.to_dict() != dict(raw):
            raise PersistenceContractError("transaction batch serialization is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> TransactionBatch:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class DeploymentRequirements:
    deployment_class: DeploymentClass
    worker_count: int
    required_isolation: IsolationLevel
    require_high_availability: bool
    require_tenant_isolation: bool
    require_atomic_outbox: bool
    require_online_migrations: bool
    require_fencing: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "deployment_class", DeploymentClass(self.deployment_class))
        object.__setattr__(self, "required_isolation", IsolationLevel(self.required_isolation))
        _positive(self.worker_count, "worker_count", 100_000)
        for name in (
            "require_high_availability",
            "require_tenant_isolation",
            "require_atomic_outbox",
            "require_online_migrations",
            "require_fencing",
        ):
            if not isinstance(getattr(self, name), bool):
                raise PersistenceContractError(f"{name} must be boolean")
        production = self.deployment_class in {
            DeploymentClass.MULTI_WORKER_PRODUCTION,
            DeploymentClass.HIGH_AVAILABILITY_PRODUCTION,
        }
        if production and self.worker_count < 2:
            raise PersistenceContractError("production deployment requires at least two workers")
        if (
            self.deployment_class is DeploymentClass.HIGH_AVAILABILITY_PRODUCTION
            and not self.require_high_availability
        ):
            raise PersistenceContractError(
                "high availability deployment must require high availability"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "deployment_class": self.deployment_class.value,
            "require_atomic_outbox": self.require_atomic_outbox,
            "require_fencing": self.require_fencing,
            "require_high_availability": self.require_high_availability,
            "require_online_migrations": self.require_online_migrations,
            "require_tenant_isolation": self.require_tenant_isolation,
            "required_isolation": self.required_isolation.value,
            "worker_count": self.worker_count,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DeploymentRequirements:
        _exact(
            raw,
            {
                "deployment_class",
                "require_atomic_outbox",
                "require_fencing",
                "require_high_availability",
                "require_online_migrations",
                "require_tenant_isolation",
                "required_isolation",
                "worker_count",
            },
            "deployment requirements",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class DeploymentSuitabilityReport:
    """Fail-closed compatibility result that never authorizes deployment."""

    declaration_id: str
    declaration_sha256: str
    requirements: DeploymentRequirements
    status: SuitabilityStatus
    blocker_codes: tuple[str, ...]
    report_id: str = field(init=False)
    report_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.persistence-deployment-suitability.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.declaration_id, str)
            or re.fullmatch(r"PBD-[0-9A-F]{32}", self.declaration_id) is None
        ):
            raise PersistenceContractError("declaration_id is invalid")
        object.__setattr__(
            self, "declaration_sha256", _digest(self.declaration_sha256, "declaration_sha256")
        )
        if not isinstance(self.requirements, DeploymentRequirements):
            raise PersistenceContractError("requirements must be DeploymentRequirements")
        object.__setattr__(self, "status", SuitabilityStatus(self.status))
        if not isinstance(self.blocker_codes, tuple) or not self.blocker_codes:
            raise PersistenceContractError("blocker_codes must be a non-empty tuple")
        for code in self.blocker_codes:
            if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
                raise PersistenceContractError("blocker code is invalid")
        normalized = tuple(sorted(set(self.blocker_codes)))
        if normalized != self.blocker_codes:
            raise PersistenceContractError("blocker_codes must be sorted and unique")
        if "live_backend_verification_required" not in self.blocker_codes:
            raise PersistenceContractError("live backend verification must remain required")
        identifier, digest = _identity("PDS", self.KIND, self._body())
        object.__setattr__(self, "report_id", identifier)
        object.__setattr__(self, "report_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "authorization_effect": "none",
            "blocker_codes": list(self.blocker_codes),
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "deployment_effect": "none",
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "qualification_effect": "none",
            "requirements": self.requirements.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed_dict(self, "report_id", "report_sha256")

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DeploymentSuitabilityReport:
        expected = {
            "authorization_effect",
            "blocker_codes",
            "declaration_id",
            "declaration_sha256",
            "deployment_effect",
            "effects",
            "kind",
            "qualification_effect",
            "report_id",
            "report_sha256",
            "requirements",
            "schema_version",
            "status",
        }
        _exact(raw, expected, "deployment suitability report")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(NO_EFFECTS)
            or raw["authorization_effect"] != "none"
            or raw["deployment_effect"] != "none"
            or raw["qualification_effect"] != "none"
        ):
            raise PersistenceContractError("deployment suitability metadata is invalid")
        _verify_address(raw, "report_id", "report_sha256", "PDS", cls.KIND)
        result = cls(
            declaration_id=raw["declaration_id"],
            declaration_sha256=raw["declaration_sha256"],
            requirements=DeploymentRequirements.from_dict(raw["requirements"]),
            status=raw["status"],
            blocker_codes=tuple(raw["blocker_codes"]),
        )
        if result.to_dict() != dict(raw):
            raise PersistenceContractError("deployment suitability serialization is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> DeploymentSuitabilityReport:
        return cls.from_dict(_canonical_document(document))


def evaluate_deployment_suitability(
    declaration: BackendCapabilityDeclaration,
    requirements: DeploymentRequirements,
) -> DeploymentSuitabilityReport:
    """Compare declared capabilities while keeping deployment blocked on verification."""

    if not isinstance(declaration, BackendCapabilityDeclaration) or not isinstance(
        requirements, DeploymentRequirements
    ):
        raise PersistenceContractError("declaration and requirements are required")
    blockers: set[str] = {"live_backend_verification_required"}
    if requirements.deployment_class not in declaration.deployment_classes:
        blockers.add("deployment_class_unsupported")
    if requirements.worker_count > declaration.max_concurrent_workers:
        blockers.add("worker_capacity_unsupported")
    if requirements.worker_count > 1 and not declaration.multi_writer:
        blockers.add("multi_writer_unsupported")
    if requirements.required_isolation not in declaration.isolation_levels:
        blockers.add("isolation_level_unsupported")
    checks = (
        (
            requirements.require_high_availability,
            declaration.high_availability,
            "high_availability_unsupported",
        ),
        (
            requirements.require_tenant_isolation,
            declaration.tenant_isolation,
            "tenant_isolation_unsupported",
        ),
        (
            requirements.require_atomic_outbox,
            declaration.atomic_outbox_enqueue,
            "atomic_outbox_unsupported",
        ),
        (
            requirements.require_online_migrations,
            declaration.online_migrations,
            "online_migrations_unsupported",
        ),
        (requirements.require_fencing, declaration.fencing_tokens, "fencing_unsupported"),
    )
    for required, supported, code in checks:
        if required and not supported:
            blockers.add(code)
    production = requirements.deployment_class in {
        DeploymentClass.MULTI_WORKER_PRODUCTION,
        DeploymentClass.HIGH_AVAILABILITY_PRODUCTION,
    }
    if declaration.backend is BackendKind.SQLITE and production:
        blockers.update({"sqlite_production_forbidden", "sqlite_single_writer_only"})
    status = (
        SuitabilityStatus.CONTRACT_COMPATIBLE_UNVERIFIED
        if blockers == {"live_backend_verification_required"}
        else SuitabilityStatus.INCOMPATIBLE
    )
    return DeploymentSuitabilityReport(
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        requirements=requirements,
        status=status,
        blocker_codes=tuple(sorted(blockers)),
    )


def parse_contract(
    raw: Mapping[str, Any],
) -> (
    BackendCapabilityDeclaration
    | MigrationManifest
    | TransactionBatch
    | DeploymentSuitabilityReport
):
    """Parse a supported top-level persistence contract by its closed kind."""

    if not isinstance(raw, Mapping):
        raise PersistenceContractError("contract must be a mapping")
    parsers = {
        BackendCapabilityDeclaration.KIND: BackendCapabilityDeclaration.from_dict,
        MigrationManifest.KIND: MigrationManifest.from_dict,
        TransactionBatch.KIND: TransactionBatch.from_dict,
        DeploymentSuitabilityReport.KIND: DeploymentSuitabilityReport.from_dict,
    }
    parser = parsers.get(raw.get("kind"))
    if parser is None:
        raise PersistenceContractError("contract kind is unsupported")
    return parser(raw)


def _canonical_document(document: str) -> Mapping[str, Any]:
    try:
        raw = json.loads(document)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PersistenceContractError("document is not valid JSON") from exc
    if not isinstance(raw, Mapping) or canonical_json(raw) != document:
        raise PersistenceContractError("document is not canonical JSON")
    return raw
