"""Content-addressed artifact recording over an injected persistence port.

This module plans deterministic persistence batches and validates adapter
observations. It never accepts artifact bytes or filesystem paths, opens no
database, executes no SQL, performs no network calls, grants no authority, and
does not qualify or independently prove durable storage.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

from .persistence_port_contracts import (
    AggregateVersionBinding,
    FenceBinding,
    IsolationLevel,
    OperationKind,
    TransactionBatch,
    TransactionOperation,
)

SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
# Per-document local metadata cost bounds, not artifact or storage authority.
MAX_RECORD_DOCUMENT_BYTES = 65_536
MAX_RECORD_DOCUMENT_NODES = 4096
MAX_RECORD_DOCUMENT_DEPTH = 12

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\Z")
EVENT_TYPE_RE = re.compile(r"[a-z][a-z0-9_.]{2,95}\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|scoperef|artifactref|custodyref|outboxref|"
    r"adapterref|aggregateref|operationref|resourceref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
FENCE_RE = re.compile(r"fence:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")

PLAN_EFFECTS = MappingProxyType(
    {
        "artifact_bytes": "not_accepted",
        "authorization": "none",
        "database_connection": "none",
        "filesystem": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "sql_execution": "none",
    }
)

RECEIPT_EFFECTS = MappingProxyType(
    {
        "artifact_bytes": "not_observed",
        "authorization": "none",
        "database_connection": "injected_adapter_only",
        "durability": "adapter_observation_only",
        "filesystem": "none",
        "network": "none",
        "qualification": "none",
        "sql_execution": "none",
    }
)


class DurableArtifactRecorderError(ValueError):
    """Raised when artifact planning or an adapter observation fails closed."""


class RetentionClass(StrEnum):
    TRANSIENT_30_DAYS = "transient_30_days"
    ASSESSMENT_1_YEAR = "assessment_1_year"
    ARCHIVE_7_YEARS = "archive_7_years"


class CommitDisposition(StrEnum):
    COMMITTED = "committed"
    REPLAYED = "replayed"


class ReceiptStatus(StrEnum):
    OBSERVED_COMMIT = "observed_commit"
    OBSERVED_REPLAY = "observed_replay"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after bounded validation."""

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
        raise DurableArtifactRecorderError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DurableArtifactRecorderError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise DurableArtifactRecorderError(f"{label} has an unsupported value")


_INTEGER_FIELDS = frozenset(
    {
        "schema_version",
        "size_bytes",
        "expected_artifact_version",
        "expected_custody_version",
        "observed_artifact_version",
        "observed_custody_version",
        "expected_version",
        "fence_epoch",
    }
)


def _native_document(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    """Detach bounded native JSON before any normalization or content hashing."""

    if not isinstance(raw, Mapping):
        raise DurableArtifactRecorderError(f"{label} must be an object")
    remaining = MAX_RECORD_DOCUMENT_BYTES
    nodes = 0

    def charge(size: int) -> None:
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise DurableArtifactRecorderError(f"{label} exceeds the document byte bound")

    def string(value: str) -> str:
        charge(2)
        if len(value) > remaining:
            raise DurableArtifactRecorderError(f"{label} exceeds the document byte bound")
        for character in value:
            code = ord(character)
            if 0xD800 <= code <= 0xDFFF:
                raise DurableArtifactRecorderError(f"{label} contains invalid Unicode")
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
        if depth > MAX_RECORD_DOCUMENT_DEPTH or nodes > MAX_RECORD_DOCUMENT_NODES:
            raise DurableArtifactRecorderError(f"{label} exceeds document structure bounds")
        if type(value) is dict or (depth == 0 and isinstance(value, Mapping)):
            if len(value) > MAX_RECORD_DOCUMENT_NODES:
                raise DurableArtifactRecorderError(f"{label} exceeds document structure bounds")
            keys = list(value)
            if any(type(key) is not str for key in keys):
                raise DurableArtifactRecorderError(f"{label} requires native string keys")
            charge(2 + len(keys) + max(0, len(keys) - 1))
            result = {}
            for key in keys:
                string(key)
                item = value[key]
                if key in _INTEGER_FIELDS and type(item) is not int:
                    raise DurableArtifactRecorderError(f"{label} {key} must be a native integer")
                result[key] = visit(item, depth + 1)
            return result
        if type(value) is list:
            if len(value) > MAX_RECORD_DOCUMENT_NODES:
                raise DurableArtifactRecorderError(f"{label} exceeds document structure bounds")
            charge(2 + max(0, len(value) - 1))
            return [visit(item, depth + 1) for item in value]
        if type(value) is str:
            return string(value)
        if type(value) is int:
            if value.bit_length() > 4096:
                raise DurableArtifactRecorderError(f"{label} contains an overlarge integer")
            charge(len(str(value)))
            return value
        if value is None or type(value) is bool:
            charge(4 if value is None or value is True else 5)
            return value
        raise DurableArtifactRecorderError(f"{label} contains a non-native JSON value")

    return visit(raw, 0)


def _exact(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise DurableArtifactRecorderError(f"{label} fields are invalid")


def _reference(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise DurableArtifactRecorderError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DurableArtifactRecorderError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DurableArtifactRecorderError(f"{label} must be canonical UTC")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DurableArtifactRecorderError(f"{label} must be a non-negative integer")
    return value


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DurableArtifactRecorderError(f"{label} must be between 1 and {maximum}")
    return value


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise DurableArtifactRecorderError("record content address does not match content")


def _canonical_document(document: str) -> Mapping[str, Any]:
    if type(document) is not str:
        raise DurableArtifactRecorderError("document must be text")
    if len(document) > MAX_RECORD_DOCUMENT_BYTES:
        raise DurableArtifactRecorderError("document exceeds the document byte bound")
    try:
        if len(document.encode("utf-8")) > MAX_RECORD_DOCUMENT_BYTES:
            raise DurableArtifactRecorderError("document exceeds the document byte bound")

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise DurableArtifactRecorderError("document has duplicate fields")
                result[key] = value
            return result

        def invalid_number(value):
            raise DurableArtifactRecorderError("document contains unsupported numbers")

        raw = _native_document(
            json.loads(
                document,
                object_pairs_hook=pairs,
                parse_float=invalid_number,
                parse_constant=invalid_number,
            ),
            "document",
        )
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, DurableArtifactRecorderError):
            raise
        raise DurableArtifactRecorderError("document must be valid JSON") from exc
    if canonical_json(raw) != document:
        raise DurableArtifactRecorderError("document must be canonical JSON")
    return raw


def _stable_suffix(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    """Artifact metadata only. Artifact bytes and path locators are not accepted."""

    artifact_ref: str
    content_sha256: str
    media_type: str
    size_bytes: int
    retention_class: RetentionClass
    custody_ref: str
    prior_custody_sha256: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "artifact_ref", _reference(self.artifact_ref, "artifact_ref", "artifactref")
        )
        object.__setattr__(self, "content_sha256", _digest(self.content_sha256, "content_sha256"))
        if not isinstance(self.media_type, str) or MEDIA_TYPE_RE.fullmatch(self.media_type) is None:
            raise DurableArtifactRecorderError("media_type must be a normalized media type")
        _positive(self.size_bytes, "size_bytes", MAX_ARTIFACT_BYTES)
        object.__setattr__(self, "retention_class", RetentionClass(self.retention_class))
        object.__setattr__(
            self, "custody_ref", _reference(self.custody_ref, "custody_ref", "custodyref")
        )
        if self.prior_custody_sha256 is not None:
            object.__setattr__(
                self,
                "prior_custody_sha256",
                _digest(self.prior_custody_sha256, "prior_custody_sha256"),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "content_sha256": self.content_sha256,
            "custody_ref": self.custody_ref,
            "media_type": self.media_type,
            "prior_custody_sha256": self.prior_custody_sha256,
            "retention_class": self.retention_class.value,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactMetadata:
        _exact(
            raw,
            {
                "artifact_ref",
                "content_sha256",
                "custody_ref",
                "media_type",
                "prior_custody_sha256",
                "retention_class",
                "size_bytes",
            },
            "artifact metadata",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class OutboxEventMetadata:
    outbox_event_ref: str
    event_type: str
    content_sha256: str
    expected_version: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "outbox_event_ref",
            _reference(self.outbox_event_ref, "outbox_event_ref", "outboxref"),
        )
        if not isinstance(self.event_type, str) or EVENT_TYPE_RE.fullmatch(self.event_type) is None:
            raise DurableArtifactRecorderError("event_type is invalid")
        object.__setattr__(
            self, "content_sha256", _digest(self.content_sha256, "outbox content_sha256")
        )
        _nonnegative(self.expected_version, "outbox expected_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_sha256": self.content_sha256,
            "event_type": self.event_type,
            "expected_version": self.expected_version,
            "outbox_event_ref": self.outbox_event_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> OutboxEventMetadata:
        _exact(
            raw,
            {"content_sha256", "event_type", "expected_version", "outbox_event_ref"},
            "outbox event metadata",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class ArtifactRecordingRequest:
    tenant_ref: str
    assessment_ref: str
    scope_ref: str
    artifact: ArtifactMetadata
    expected_artifact_version: int
    expected_custody_version: int
    fence_resource_ref: str
    fence_token: str
    fence_epoch: int
    idempotency_key: str
    recorded_at: str
    outbox_event: OutboxEventMetadata | None

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("scope_ref", "scoperef"),
            ("fence_resource_ref", "resourceref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        if not isinstance(self.artifact, ArtifactMetadata):
            raise DurableArtifactRecorderError("artifact must be ArtifactMetadata")
        _nonnegative(self.expected_artifact_version, "expected_artifact_version")
        _nonnegative(self.expected_custody_version, "expected_custody_version")
        if not isinstance(self.fence_token, str) or FENCE_RE.fullmatch(self.fence_token) is None:
            raise DurableArtifactRecorderError("fence_token is invalid")
        _positive(self.fence_epoch, "fence_epoch", 9_223_372_036_854_775_807)
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DurableArtifactRecorderError("idempotency_key is invalid")
        object.__setattr__(self, "recorded_at", _timestamp(self.recorded_at, "recorded_at"))
        if self.outbox_event is not None and not isinstance(self.outbox_event, OutboxEventMetadata):
            raise DurableArtifactRecorderError("outbox_event must be OutboxEventMetadata or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "assessment_ref": self.assessment_ref,
            "expected_artifact_version": self.expected_artifact_version,
            "expected_custody_version": self.expected_custody_version,
            "fence_epoch": self.fence_epoch,
            "fence_resource_ref": self.fence_resource_ref,
            "fence_token": self.fence_token,
            "idempotency_key": self.idempotency_key,
            "outbox_event": None if self.outbox_event is None else self.outbox_event.to_dict(),
            "recorded_at": self.recorded_at,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactRecordingRequest:
        _exact(
            raw,
            {
                "artifact",
                "assessment_ref",
                "expected_artifact_version",
                "expected_custody_version",
                "fence_epoch",
                "fence_resource_ref",
                "fence_token",
                "idempotency_key",
                "outbox_event",
                "recorded_at",
                "scope_ref",
                "tenant_ref",
            },
            "artifact recording request",
        )
        return cls(
            tenant_ref=raw["tenant_ref"],
            assessment_ref=raw["assessment_ref"],
            scope_ref=raw["scope_ref"],
            artifact=ArtifactMetadata.from_dict(raw["artifact"]),
            expected_artifact_version=raw["expected_artifact_version"],
            expected_custody_version=raw["expected_custody_version"],
            fence_resource_ref=raw["fence_resource_ref"],
            fence_token=raw["fence_token"],
            fence_epoch=raw["fence_epoch"],
            idempotency_key=raw["idempotency_key"],
            recorded_at=raw["recorded_at"],
            outbox_event=(
                None
                if raw["outbox_event"] is None
                else OutboxEventMetadata.from_dict(raw["outbox_event"])
            ),
        )


def custody_entry_sha256(request: ArtifactRecordingRequest) -> str:
    """Bind an append-only custody entry to identity, scope, and prior entry."""

    return canonical_sha256(
        {
            "artifact": request.artifact.to_dict(),
            "assessment_ref": request.assessment_ref,
            "kind": "sunderkey.artifact-custody-entry.v1",
            "recorded_at": request.recorded_at,
            "scope_ref": request.scope_ref,
            "tenant_ref": request.tenant_ref,
        }
    )


def _aggregate_refs(request: ArtifactRecordingRequest) -> tuple[str, str, str | None]:
    suffix = _stable_suffix(request.artifact.artifact_ref)
    artifact = f"aggregateref:durable-artifact.{suffix}"
    custody = f"aggregateref:artifact-custody.{suffix}"
    if request.outbox_event is None:
        return artifact, custody, None
    outbox = f"aggregateref:artifact-outbox.{_stable_suffix(request.outbox_event.outbox_event_ref)}"
    return artifact, custody, outbox


def _build_batch(request: ArtifactRecordingRequest) -> TransactionBatch:
    artifact_aggregate, custody_aggregate, outbox_aggregate = _aggregate_refs(request)
    operations = [
        TransactionOperation(
            operation_ref=f"operationref:artifact-append.{_stable_suffix(request.idempotency_key)}",
            kind=OperationKind.APPEND,
            aggregate_ref=artifact_aggregate,
            content_sha256=canonical_sha256(request.artifact.to_dict()),
        ),
        TransactionOperation(
            operation_ref=f"operationref:custody-append.{_stable_suffix(request.idempotency_key)}",
            kind=OperationKind.APPEND,
            aggregate_ref=custody_aggregate,
            content_sha256=custody_entry_sha256(request),
        ),
    ]
    versions = [
        AggregateVersionBinding(artifact_aggregate, request.expected_artifact_version),
        AggregateVersionBinding(custody_aggregate, request.expected_custody_version),
    ]
    outbox_refs: tuple[str, ...] = ()
    if request.outbox_event is not None and outbox_aggregate is not None:
        operations.append(
            TransactionOperation(
                operation_ref=f"operationref:outbox-enqueue.{_stable_suffix(request.idempotency_key)}",
                kind=OperationKind.OUTBOX_ENQUEUE,
                aggregate_ref=outbox_aggregate,
                content_sha256=request.outbox_event.content_sha256,
            )
        )
        versions.append(
            AggregateVersionBinding(outbox_aggregate, request.outbox_event.expected_version)
        )
        outbox_refs = (request.outbox_event.outbox_event_ref,)
    return TransactionBatch(
        tenant_ref=request.tenant_ref,
        assessment_ref=request.assessment_ref,
        scope_ref=request.scope_ref,
        idempotency_key=request.idempotency_key,
        isolation_level=IsolationLevel.SERIALIZABLE,
        created_at=request.recorded_at,
        operations=tuple(operations),
        version_bindings=tuple(versions),
        fence_bindings=(
            FenceBinding(
                resource_ref=request.fence_resource_ref,
                fence_token=request.fence_token,
                fence_epoch=request.fence_epoch,
            ),
        ),
        outbox_event_refs=outbox_refs,
    )


@dataclass(frozen=True, slots=True)
class ArtifactRecordingPlan:
    request: ArtifactRecordingRequest
    transaction_batch: TransactionBatch
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.durable-artifact-recording-plan.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.request, ArtifactRecordingRequest):
            raise DurableArtifactRecorderError("request must be ArtifactRecordingRequest")
        if not isinstance(self.transaction_batch, TransactionBatch):
            raise DurableArtifactRecorderError("transaction_batch must be TransactionBatch")
        if self.transaction_batch != _build_batch(self.request):
            raise DurableArtifactRecorderError("transaction batch does not match recording request")
        identifier, digest = _identity("DAP", self.KIND, self._body())
        object.__setattr__(self, "plan_id", identifier)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "effects": dict(PLAN_EFFECTS),
            "kind": self.KIND,
            "request": self.request.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "transaction_batch": self.transaction_batch.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactRecordingPlan:
        raw = _native_document(raw, "artifact recording plan")
        _exact(
            raw,
            {
                "effects",
                "kind",
                "plan_id",
                "plan_sha256",
                "request",
                "schema_version",
                "transaction_batch",
            },
            "artifact recording plan",
        )
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(PLAN_EFFECTS)
        ):
            raise DurableArtifactRecorderError("artifact recording plan metadata is invalid")
        _verify_address(raw, "plan_id", "plan_sha256", "DAP", cls.KIND)
        try:
            result = cls(
                request=ArtifactRecordingRequest.from_dict(raw["request"]),
                transaction_batch=TransactionBatch.from_dict(raw["transaction_batch"]),
            )
        except (TypeError, ValueError) as exc:
            raise DurableArtifactRecorderError("artifact recording plan is invalid") from exc
        if canonical_json(result.to_dict()) != canonical_json(raw):
            raise DurableArtifactRecorderError("artifact recording plan is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> ArtifactRecordingPlan:
        return cls.from_dict(_canonical_document(document))


def plan_artifact_recording(request: ArtifactRecordingRequest) -> ArtifactRecordingPlan:
    """Produce a deterministic non-executing transaction plan."""

    if not isinstance(request, ArtifactRecordingRequest):
        raise DurableArtifactRecorderError("request must be ArtifactRecordingRequest")
    return ArtifactRecordingPlan(request=request, transaction_batch=_build_batch(request))


@dataclass(frozen=True, slots=True)
class ArtifactCommitObservation:
    adapter_ref: str
    batch_id: str
    batch_sha256: str
    tenant_ref: str
    assessment_ref: str
    scope_ref: str
    idempotency_key: str
    artifact_ref: str
    stored_content_sha256: str
    custody_ref: str
    prior_custody_sha256: str | None
    custody_entry_sha256: str
    expected_artifact_version: int
    observed_artifact_version: int
    expected_custody_version: int
    observed_custody_version: int
    fence_resource_ref: str
    fence_token: str
    fence_epoch: int
    outbox_event_ref: str | None
    disposition: CommitDisposition
    observed_at: str
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.durable-artifact-commit-observation.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("adapter_ref", "adapterref"),
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("scope_ref", "scoperef"),
            ("artifact_ref", "artifactref"),
            ("custody_ref", "custodyref"),
            ("fence_resource_ref", "resourceref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        if (
            not isinstance(self.batch_id, str)
            or re.fullmatch(r"PTB-[0-9A-F]{32}", self.batch_id) is None
        ):
            raise DurableArtifactRecorderError("batch_id is invalid")
        object.__setattr__(self, "batch_sha256", _digest(self.batch_sha256, "batch_sha256"))
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DurableArtifactRecorderError("idempotency_key is invalid")
        for name in ("stored_content_sha256", "custody_entry_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        if self.prior_custody_sha256 is not None:
            object.__setattr__(
                self,
                "prior_custody_sha256",
                _digest(self.prior_custody_sha256, "prior_custody_sha256"),
            )
        for name in (
            "expected_artifact_version",
            "observed_artifact_version",
            "expected_custody_version",
            "observed_custody_version",
        ):
            _nonnegative(getattr(self, name), name)
        if self.observed_artifact_version != self.expected_artifact_version + 1:
            raise DurableArtifactRecorderError(
                "artifact optimistic concurrency observation is invalid"
            )
        if self.observed_custody_version != self.expected_custody_version + 1:
            raise DurableArtifactRecorderError(
                "custody optimistic concurrency observation is invalid"
            )
        if not isinstance(self.fence_token, str) or FENCE_RE.fullmatch(self.fence_token) is None:
            raise DurableArtifactRecorderError("fence_token is invalid")
        _positive(self.fence_epoch, "fence_epoch", 9_223_372_036_854_775_807)
        if self.outbox_event_ref is not None:
            object.__setattr__(
                self,
                "outbox_event_ref",
                _reference(self.outbox_event_ref, "outbox_event_ref", "outboxref"),
            )
        object.__setattr__(self, "disposition", CommitDisposition(self.disposition))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        identifier, digest = _identity("DAO", self.KIND, self._body())
        object.__setattr__(self, "observation_id", identifier)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "artifact_ref": self.artifact_ref,
            "assessment_ref": self.assessment_ref,
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
            "custody_entry_sha256": self.custody_entry_sha256,
            "custody_ref": self.custody_ref,
            "disposition": self.disposition.value,
            "expected_artifact_version": self.expected_artifact_version,
            "expected_custody_version": self.expected_custody_version,
            "fence_epoch": self.fence_epoch,
            "fence_resource_ref": self.fence_resource_ref,
            "fence_token": self.fence_token,
            "idempotency_key": self.idempotency_key,
            "kind": self.KIND,
            "observed_artifact_version": self.observed_artifact_version,
            "observed_at": self.observed_at,
            "observed_custody_version": self.observed_custody_version,
            "outbox_event_ref": self.outbox_event_ref,
            "prior_custody_sha256": self.prior_custody_sha256,
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "stored_content_sha256": self.stored_content_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactCommitObservation:
        raw = _native_document(raw, "artifact commit observation")
        expected = {
            "adapter_ref",
            "artifact_ref",
            "assessment_ref",
            "batch_id",
            "batch_sha256",
            "custody_entry_sha256",
            "custody_ref",
            "disposition",
            "expected_artifact_version",
            "expected_custody_version",
            "fence_epoch",
            "fence_resource_ref",
            "fence_token",
            "idempotency_key",
            "kind",
            "observation_id",
            "observation_sha256",
            "observed_artifact_version",
            "observed_at",
            "observed_custody_version",
            "outbox_event_ref",
            "prior_custody_sha256",
            "qualification_effect",
            "schema_version",
            "scope_ref",
            "stored_content_sha256",
            "tenant_ref",
        }
        _exact(raw, expected, "artifact commit observation")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["qualification_effect"] != "none"
        ):
            raise DurableArtifactRecorderError("artifact commit observation metadata is invalid")
        _verify_address(raw, "observation_id", "observation_sha256", "DAO", cls.KIND)
        arguments = {
            key: value
            for key, value in raw.items()
            if key
            not in {
                "kind",
                "observation_id",
                "observation_sha256",
                "qualification_effect",
                "schema_version",
            }
        }
        result = cls(**arguments)
        if canonical_json(result.to_dict()) != canonical_json(raw):
            raise DurableArtifactRecorderError("artifact commit observation is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> ArtifactCommitObservation:
        return cls.from_dict(_canonical_document(document))


class ArtifactPersistenceAdapter(Protocol):
    """Injected boundary that may submit one prevalidated transaction plan."""

    def commit_artifact(self, plan: ArtifactRecordingPlan) -> ArtifactCommitObservation: ...


@dataclass(frozen=True, slots=True)
class ArtifactRecordingReceipt:
    plan_id: str
    plan_sha256: str
    batch_id: str
    batch_sha256: str
    observation_id: str
    observation_sha256: str
    adapter_ref: str
    status: ReceiptStatus
    recorded_at: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.durable-artifact-recording-receipt.v1"

    def __post_init__(self) -> None:
        for name, prefix in (
            ("plan_id", "DAP"),
            ("batch_id", "PTB"),
            ("observation_id", "DAO"),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or re.fullmatch(prefix + r"-[0-9A-F]{32}", value) is None:
                raise DurableArtifactRecorderError(f"{name} is invalid")
        for name in ("plan_sha256", "batch_sha256", "observation_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(
            self, "adapter_ref", _reference(self.adapter_ref, "adapter_ref", "adapterref")
        )
        object.__setattr__(self, "status", ReceiptStatus(self.status))
        object.__setattr__(self, "recorded_at", _timestamp(self.recorded_at, "recorded_at"))
        identifier, digest = _identity("DAR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", identifier)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
            "effects": dict(RECEIPT_EFFECTS),
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "qualification_effect": "none",
            "recorded_at": self.recorded_at,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactRecordingReceipt:
        raw = _native_document(raw, "artifact recording receipt")
        _exact(
            raw,
            {
                "adapter_ref",
                "batch_id",
                "batch_sha256",
                "effects",
                "kind",
                "observation_id",
                "observation_sha256",
                "plan_id",
                "plan_sha256",
                "qualification_effect",
                "receipt_id",
                "receipt_sha256",
                "recorded_at",
                "schema_version",
                "status",
            },
            "artifact recording receipt",
        )
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(RECEIPT_EFFECTS)
            or raw["qualification_effect"] != "none"
        ):
            raise DurableArtifactRecorderError("artifact recording receipt metadata is invalid")
        _verify_address(raw, "receipt_id", "receipt_sha256", "DAR", cls.KIND)
        arguments = {
            key: value
            for key, value in raw.items()
            if key
            not in {
                "effects",
                "kind",
                "qualification_effect",
                "receipt_id",
                "receipt_sha256",
                "schema_version",
            }
        }
        result = cls(**arguments)
        if canonical_json(result.to_dict()) != canonical_json(raw):
            raise DurableArtifactRecorderError("artifact recording receipt is not canonical")
        return result

    @classmethod
    def from_json(cls, document: str) -> ArtifactRecordingReceipt:
        return cls.from_dict(_canonical_document(document))


def _capture_record(value: Any, family: Any, label: str) -> Any:
    """Replay only the existing exact wrapper families before handing off data."""

    if type(value) is not family:
        raise DurableArtifactRecorderError(f"{label} must be an exact {family.__name__}")
    wrappers = {
        ArtifactRecordingPlan,
        ArtifactRecordingRequest,
        ArtifactMetadata,
        OutboxEventMetadata,
        ArtifactCommitObservation,
        ArtifactRecordingReceipt,
        TransactionBatch,
        TransactionOperation,
        AggregateVersionBinding,
        FenceBinding,
    }
    enums = {RetentionClass, CommitDisposition, ReceiptStatus, IsolationLevel, OperationKind}
    nodes = 0

    def check(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_RECORD_DOCUMENT_NODES or depth > MAX_RECORD_DOCUMENT_DEPTH:
            raise DurableArtifactRecorderError(f"{label} exceeds wrapper structure bounds")
        selected_type = type(item)
        if selected_type in wrappers:
            for selected_field in fields(selected_type):
                try:
                    selected = getattr(item, selected_field.name)
                except AttributeError as exc:
                    raise DurableArtifactRecorderError(
                        f"{label} has incomplete wrapper slots"
                    ) from exc
                check(selected, depth + 1)
        elif selected_type is tuple:
            if len(item) > MAX_RECORD_DOCUMENT_NODES:
                raise DurableArtifactRecorderError(f"{label} exceeds wrapper structure bounds")
            for selected in item:
                check(selected, depth + 1)
        elif selected_type is str:
            if len(item) > MAX_RECORD_DOCUMENT_BYTES:
                raise DurableArtifactRecorderError(f"{label} exceeds the document byte bound")
        elif selected_type is int:
            if item.bit_length() > 4096:
                raise DurableArtifactRecorderError(f"{label} contains an overlarge integer")
        elif item is not None and selected_type not in enums:
            raise DurableArtifactRecorderError(f"{label} contains a non-native wrapper field")

    check(value, 0)
    try:
        document = _native_document(value.to_dict(), label)
        result = family.from_dict(document)
        if canonical_json(result.to_dict()) != canonical_json(document):
            raise DurableArtifactRecorderError(f"{label} does not reproduce its original document")
        return result
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, DurableArtifactRecorderError):
            raise
        raise DurableArtifactRecorderError(f"{label} is malformed") from exc


def _capture_recording_plan(plan: ArtifactRecordingPlan) -> ArtifactRecordingPlan:
    return _capture_record(plan, ArtifactRecordingPlan, "artifact recording plan")


def _observation_expectation(plan: ArtifactRecordingPlan) -> Mapping[str, Any]:
    request = plan.request
    return MappingProxyType(
        {
            "artifact_ref": request.artifact.artifact_ref,
            "assessment_ref": request.assessment_ref,
            "batch_id": plan.transaction_batch.batch_id,
            "batch_sha256": plan.transaction_batch.batch_sha256,
            "custody_entry_sha256": custody_entry_sha256(request),
            "custody_ref": request.artifact.custody_ref,
            "expected_artifact_version": request.expected_artifact_version,
            "expected_custody_version": request.expected_custody_version,
            "fence_epoch": request.fence_epoch,
            "fence_resource_ref": request.fence_resource_ref,
            "fence_token": request.fence_token,
            "idempotency_key": request.idempotency_key,
            "outbox_event_ref": (
                None if request.outbox_event is None else request.outbox_event.outbox_event_ref
            ),
            "prior_custody_sha256": request.artifact.prior_custody_sha256,
            "scope_ref": request.scope_ref,
            "stored_content_sha256": request.artifact.content_sha256,
            "tenant_ref": request.tenant_ref,
        }
    )


def _validate_observation(
    expected: Mapping[str, Any], observation: ArtifactCommitObservation
) -> None:
    for field_name, expected_value in expected.items():
        if getattr(observation, field_name) != expected_value:
            raise DurableArtifactRecorderError(
                f"adapter observation {field_name} does not match the planned recording"
            )


def record_artifact(
    plan: ArtifactRecordingPlan, adapter: ArtifactPersistenceAdapter
) -> ArtifactRecordingReceipt:
    """Invoke an injected adapter once and validate its complete observation."""

    original = _capture_recording_plan(plan)
    expected = _observation_expectation(original)
    identities = (
        original.plan_id,
        original.plan_sha256,
        original.transaction_batch.batch_id,
        original.transaction_batch.batch_sha256,
    )
    # The private original and its expectation are never handed to the port.
    delivered = _capture_recording_plan(original)
    commit = getattr(adapter, "commit_artifact", None)
    if not callable(commit):
        raise DurableArtifactRecorderError("adapter must provide commit_artifact")
    returned = commit(delivered)
    if type(returned) is not ArtifactCommitObservation:
        raise DurableArtifactRecorderError("adapter returned an invalid commit observation")
    observation = _capture_record(
        returned, ArtifactCommitObservation, "artifact commit observation"
    )
    _validate_observation(expected, observation)
    status = (
        ReceiptStatus.OBSERVED_REPLAY
        if observation.disposition is CommitDisposition.REPLAYED
        else ReceiptStatus.OBSERVED_COMMIT
    )
    return ArtifactRecordingReceipt(
        plan_id=identities[0],
        plan_sha256=identities[1],
        batch_id=identities[2],
        batch_sha256=identities[3],
        observation_id=observation.observation_id,
        observation_sha256=observation.observation_sha256,
        adapter_ref=observation.adapter_ref,
        status=status,
        recorded_at=observation.observed_at,
    )


def parse_record(
    raw: Mapping[str, Any],
) -> ArtifactRecordingPlan | ArtifactCommitObservation | ArtifactRecordingReceipt:
    """Parse one exact top-level durable artifact record."""

    if not isinstance(raw, Mapping):
        raise DurableArtifactRecorderError("record must be an object")
    kind = raw.get("kind")
    if kind == ArtifactRecordingPlan.KIND:
        return ArtifactRecordingPlan.from_dict(raw)
    if kind == ArtifactCommitObservation.KIND:
        return ArtifactCommitObservation.from_dict(raw)
    if kind == ArtifactRecordingReceipt.KIND:
        return ArtifactRecordingReceipt.from_dict(raw)
    raise DurableArtifactRecorderError("unsupported durable artifact record kind")
