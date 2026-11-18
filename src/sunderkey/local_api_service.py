"""Deterministic in-process product service with injected policy and storage ports.

This module provides a runtime core for product-facing service operations. It
does not create a listening socket, authenticate a principal, persist data,
deliver an integration event, or execute a mission. Those effects remain
behind injected ports.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

from .target_context import TargetContextBundle, TargetContextError

SCHEMA_VERSION = 1
MAX_PAGE_SIZE = 100

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
CONCURRENCY_RE = re.compile(r"ct:[0-9a-f]{64}\Z")
CURSOR_RE = re.compile(r"cursor:[A-Za-z0-9_-]+\.[0-9a-f]{64}\Z")
AUDIT_REF_RE = re.compile(r"auditref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
DECISION_REF_RE = re.compile(r"(?:authzref|admitref):[A-Za-z0-9][A-Za-z0-9._:/-]{0,246}\Z")


class LocalApiServiceError(ValueError):
    """Raised when the local service fails a request closed."""


class ResourceKind(StrEnum):
    ASSET = "asset"
    MISSION = "mission"
    FINDING = "finding"
    EVIDENCE = "evidence"
    REPORT = "report"
    REMEDIATION = "remediation"
    APPROVAL = "approval"
    HEALTH = "health"
    OPERATOR_PROJECTION = "operator_projection"
    TARGET_CONTEXT = "target_context"


class Operation(StrEnum):
    GET_RESOURCE = "get_resource"
    LIST_RESOURCES = "list_resources"
    CREATE_ASSET = "create_asset"
    UPDATE_ASSET = "update_asset"
    CREATE_MISSION = "create_mission"
    TRANSITION_MISSION = "transition_mission"
    UPSERT_FINDING = "upsert_finding"
    APPEND_EVIDENCE = "append_evidence"
    CREATE_REPORT = "create_report"
    RECORD_REMEDIATION = "record_remediation"
    RECORD_APPROVAL = "record_approval"
    UPDATE_HEALTH = "update_health"
    PUBLISH_OPERATOR_PROJECTION = "publish_operator_projection"
    ATTACH_TARGET_CONTEXT = "attach_target_context"


class MissionState(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DecisionStatus(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class AdmissionStatus(StrEnum):
    ADMITTED = "admitted"
    REJECTED = "rejected"


class ResponseStatus(StrEnum):
    COMPLETED = "completed"
    REPLAYED = "replayed"


RESOURCE_BY_OPERATION = {
    Operation.CREATE_ASSET: ResourceKind.ASSET,
    Operation.UPDATE_ASSET: ResourceKind.ASSET,
    Operation.CREATE_MISSION: ResourceKind.MISSION,
    Operation.TRANSITION_MISSION: ResourceKind.MISSION,
    Operation.UPSERT_FINDING: ResourceKind.FINDING,
    Operation.APPEND_EVIDENCE: ResourceKind.EVIDENCE,
    Operation.CREATE_REPORT: ResourceKind.REPORT,
    Operation.RECORD_REMEDIATION: ResourceKind.REMEDIATION,
    Operation.RECORD_APPROVAL: ResourceKind.APPROVAL,
    Operation.UPDATE_HEALTH: ResourceKind.HEALTH,
    Operation.PUBLISH_OPERATOR_PROJECTION: ResourceKind.OPERATOR_PROJECTION,
    Operation.ATTACH_TARGET_CONTEXT: ResourceKind.TARGET_CONTEXT,
}

PERMISSION_BY_OPERATION = {
    Operation.GET_RESOURCE: "resource:read",
    Operation.LIST_RESOURCES: "resource:read",
    Operation.CREATE_ASSET: "asset:write",
    Operation.UPDATE_ASSET: "asset:write",
    Operation.CREATE_MISSION: "mission:write",
    Operation.TRANSITION_MISSION: "mission:write",
    Operation.UPSERT_FINDING: "finding:write",
    Operation.APPEND_EVIDENCE: "evidence:append",
    Operation.CREATE_REPORT: "report:write",
    Operation.RECORD_REMEDIATION: "remediation:write",
    Operation.RECORD_APPROVAL: "approval:write",
    Operation.UPDATE_HEALTH: "health:write",
    Operation.PUBLISH_OPERATOR_PROJECTION: "projection:write",
    Operation.ATTACH_TARGET_CONTEXT: "context:attach",
}

CREATE_ONLY_OPERATIONS = frozenset(
    {
        Operation.CREATE_ASSET,
        Operation.CREATE_MISSION,
        Operation.APPEND_EVIDENCE,
        Operation.CREATE_REPORT,
        Operation.RECORD_REMEDIATION,
        Operation.RECORD_APPROVAL,
        Operation.PUBLISH_OPERATOR_PROJECTION,
        Operation.ATTACH_TARGET_CONTEXT,
    }
)

UPDATE_ONLY_OPERATIONS = frozenset({Operation.UPDATE_ASSET, Operation.TRANSITION_MISSION})

UPSERT_OPERATIONS = frozenset({Operation.UPSERT_FINDING, Operation.UPDATE_HEALTH})

MISSION_TRANSITIONS = {
    MissionState.DRAFT: frozenset({MissionState.READY, MissionState.CANCELLED}),
    MissionState.READY: frozenset({MissionState.RUNNING, MissionState.CANCELLED}),
    MissionState.RUNNING: frozenset(
        {MissionState.PAUSED, MissionState.STOPPING, MissionState.COMPLETED, MissionState.FAILED}
    ),
    MissionState.PAUSED: frozenset(
        {MissionState.RUNNING, MissionState.STOPPING, MissionState.CANCELLED}
    ),
    MissionState.STOPPING: frozenset(
        {MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED}
    ),
    MissionState.COMPLETED: frozenset(),
    MissionState.FAILED: frozenset(),
    MissionState.CANCELLED: frozenset(),
}

REQUIRED_FIELDS = {
    Operation.CREATE_ASSET: frozenset(
        {
            "name",
            "target_refs",
            "environment",
            "owner_ref",
            "credential_refs",
            "eligibility",
            "exclusion_refs",
        }
    ),
    Operation.UPDATE_ASSET: frozenset(
        {
            "name",
            "target_refs",
            "environment",
            "owner_ref",
            "credential_refs",
            "eligibility",
            "exclusion_refs",
        }
    ),
    Operation.CREATE_MISSION: frozenset(
        {"state", "asset_refs", "scope_ref", "schedule_ref", "budget_ref"}
    ),
    Operation.TRANSITION_MISSION: frozenset(
        {"state", "asset_refs", "scope_ref", "schedule_ref", "budget_ref"}
    ),
    Operation.UPSERT_FINDING: frozenset(
        {
            "title",
            "status",
            "severity",
            "affected_asset_refs",
            "evidence_refs",
            "validation_ref",
            "remediation_ref",
            "retest_refs",
            "owner_ref",
        }
    ),
    Operation.APPEND_EVIDENCE: frozenset(
        {"finding_ref", "action_ref", "authorization_ref", "result_ref", "cleanup_ref"}
    ),
    Operation.CREATE_REPORT: frozenset(
        {"report_type", "record_set_sha256", "finding_refs", "evidence_refs"}
    ),
    Operation.RECORD_REMEDIATION: frozenset(
        {
            "finding_ref",
            "guidance_ref",
            "developer_evidence_refs",
            "retest_ref",
            "regression_ref",
            "closure_status",
        }
    ),
    Operation.RECORD_APPROVAL: frozenset(
        {"subject_ref", "decision", "approver_ref", "decision_evidence_ref"}
    ),
    Operation.UPDATE_HEALTH: frozenset(
        {"component_ref", "state", "observation_ref", "observed_at"}
    ),
    Operation.PUBLISH_OPERATOR_PROJECTION: frozenset(
        {
            "mission_ref",
            "coverage_ref",
            "worker_ref",
            "approval_refs",
            "health_refs",
            "budget_ref",
            "graph_ref",
            "blocker_refs",
        }
    ),
    Operation.ATTACH_TARGET_CONTEXT: frozenset({"bundle"}),
}


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(
    value: Any, label: str, *, depth: int = 0, count: list[int] | None = None
) -> None:
    if depth > 12:
        raise LocalApiServiceError(f"{label} exceeds the nesting limit")
    counter = [0] if count is None else count
    counter[0] += 1
    if counter[0] > 20_000:
        raise LocalApiServiceError(f"{label} exceeds the item limit")
    if value is None or isinstance(value, (str, int, bool)):
        return
    if isinstance(value, float):
        raise LocalApiServiceError(f"{label} must not contain floating point values")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1, count=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise LocalApiServiceError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1, count=counter)
        return
    raise LocalApiServiceError(f"{label} contains an unsupported value")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise LocalApiServiceError(f"{label} must be a safe identifier")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise LocalApiServiceError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise LocalApiServiceError(f"{label} is not a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LocalApiServiceError(f"{label} must be a SHA-256 content address")
    return value


def _audit_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or AUDIT_REF_RE.fullmatch(value) is None:
        raise LocalApiServiceError(f"{label} must be an audit reference")
    return value


def _closed_token(value: Any, label: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise LocalApiServiceError(f"{label} is outside the closed vocabulary")
    return value


def _reference_sequence(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LocalApiServiceError(f"{label} must be a reference list")
    references = tuple(_identifier(item, f"{label} item") for item in value)
    if len(references) > 1_000 or len(references) != len(set(references)):
        raise LocalApiServiceError(f"{label} must be bounded and unique")
    return references


def _canonical_payload(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    if not isinstance(payload, Mapping):
        raise LocalApiServiceError("payload must be an object")
    document = canonical_json(dict(payload))
    value = json.loads(document)
    return MappingProxyType(value), document


@dataclass(frozen=True)
class AccessContext:
    tenant_id: str
    context_id: str
    principal_id: str
    session_ref: str

    def __post_init__(self) -> None:
        for field_name in ("tenant_id", "context_id", "principal_id", "session_ref"):
            _identifier(getattr(self, field_name), field_name)


@dataclass(frozen=True)
class ServiceRequest:
    request_id: str
    operation: Operation | str
    access: AccessContext
    requested_at: str
    resource_kind: ResourceKind | str
    resource_id: str | None = None
    payload: Mapping[str, Any] | None = None
    expected_concurrency_token: str | None = None
    idempotency_key: str | None = None
    cursor: str | None = None
    page_size: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        object.__setattr__(self, "operation", Operation(self.operation))
        object.__setattr__(self, "resource_kind", ResourceKind(self.resource_kind))
        _timestamp(self.requested_at, "requested_at")
        if self.resource_id is not None:
            _identifier(self.resource_id, "resource_id")
        if self.payload is not None:
            payload, _ = _canonical_payload(self.payload)
            object.__setattr__(self, "payload", payload)
        if (
            self.expected_concurrency_token is not None
            and CONCURRENCY_RE.fullmatch(self.expected_concurrency_token) is None
        ):
            raise LocalApiServiceError("expected_concurrency_token is invalid")
        if (
            self.idempotency_key is not None
            and IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise LocalApiServiceError("idempotency_key is invalid")
        if self.cursor is not None and CURSOR_RE.fullmatch(self.cursor) is None:
            raise LocalApiServiceError("cursor is invalid")
        if self.page_size is not None and (
            isinstance(self.page_size, bool)
            or not isinstance(self.page_size, int)
            or not 1 <= self.page_size <= MAX_PAGE_SIZE
        ):
            raise LocalApiServiceError("page_size is outside its allowed range")
        self._validate_shape()

    @property
    def is_mutation(self) -> bool:
        return self.operation not in {Operation.GET_RESOURCE, Operation.LIST_RESOURCES}

    @property
    def request_sha256(self) -> str:
        return canonical_sha256(self.to_dict(include_idempotency=False))

    @property
    def idempotency_sha256(self) -> str | None:
        if self.idempotency_key is None:
            return None
        return canonical_sha256({"idempotency_key": self.idempotency_key})

    def _validate_shape(self) -> None:
        if self.operation in RESOURCE_BY_OPERATION:
            if self.resource_kind is not RESOURCE_BY_OPERATION[self.operation]:
                raise LocalApiServiceError("operation and resource_kind do not match")
            if self.resource_id is None or self.payload is None or self.idempotency_key is None:
                raise LocalApiServiceError(
                    "mutation requires resource, payload, and idempotency key"
                )
            if self.cursor is not None or self.page_size is not None:
                raise LocalApiServiceError("mutation must not carry pagination")
        elif self.operation is Operation.GET_RESOURCE:
            if self.resource_id is None:
                raise LocalApiServiceError("get requires resource_id")
            if any(
                value is not None
                for value in (
                    self.payload,
                    self.idempotency_key,
                    self.cursor,
                    self.page_size,
                    self.expected_concurrency_token,
                )
            ):
                raise LocalApiServiceError("get carries mutation or pagination fields")
        else:
            if self.resource_id is not None or self.payload is not None:
                raise LocalApiServiceError("list must not carry resource data")
            if self.idempotency_key is not None or self.expected_concurrency_token is not None:
                raise LocalApiServiceError("list must not carry mutation controls")
            if self.page_size is None:
                raise LocalApiServiceError("list requires page_size")

    def to_dict(self, *, include_idempotency: bool = True) -> dict[str, Any]:
        value = {
            "access": {
                "context_id": self.access.context_id,
                "principal_id": self.access.principal_id,
                "session_ref": self.access.session_ref,
                "tenant_id": self.access.tenant_id,
            },
            "cursor": self.cursor,
            "expected_concurrency_token": self.expected_concurrency_token,
            "idempotency_key": self.idempotency_key if include_idempotency else None,
            "operation": self.operation.value,
            "page_size": self.page_size,
            "payload": dict(self.payload) if self.payload is not None else None,
            "request_id": self.request_id,
            "requested_at": self.requested_at,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind.value,
        }
        return value


@dataclass(frozen=True)
class AccessCheck:
    request_sha256: str
    tenant_id: str
    context_id: str
    principal_id: str
    session_ref: str
    permission: str
    requested_at: str


@dataclass(frozen=True)
class AccessDecision:
    decision_ref: str
    status: DecisionStatus | str
    request_sha256: str
    tenant_id: str
    context_id: str
    principal_id: str
    session_ref: str
    permission: str
    valid_through: str
    audit_ref: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.decision_ref, str)
            or DECISION_REF_RE.fullmatch(self.decision_ref) is None
        ):
            raise LocalApiServiceError("authorization decision_ref is invalid")
        object.__setattr__(self, "status", DecisionStatus(self.status))
        _digest(self.request_sha256, "authorization request_sha256")
        for field_name in ("tenant_id", "context_id", "principal_id", "session_ref"):
            _identifier(getattr(self, field_name), f"authorization {field_name}")
        if (
            not isinstance(self.permission, str)
            or re.fullmatch(r"[a-z]+:[a-z]+", self.permission) is None
        ):
            raise LocalApiServiceError("authorization permission is invalid")
        _timestamp(self.valid_through, "authorization valid_through")
        _audit_ref(self.audit_ref, "authorization audit_ref")


@dataclass(frozen=True)
class MutationCheck:
    request_sha256: str
    idempotency_sha256: str
    authorization_ref: str
    tenant_id: str
    context_id: str
    principal_id: str
    operation: Operation
    resource_kind: ResourceKind
    resource_id: str
    expected_concurrency_token: str | None
    requested_at: str


@dataclass(frozen=True)
class MutationAdmission:
    admission_ref: str
    status: AdmissionStatus | str
    request_sha256: str
    idempotency_sha256: str
    authorization_ref: str
    tenant_id: str
    context_id: str
    principal_id: str
    operation: Operation | str
    resource_kind: ResourceKind | str
    resource_id: str
    expected_concurrency_token: str | None
    valid_through: str
    audit_ref: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.admission_ref, str)
            or DECISION_REF_RE.fullmatch(self.admission_ref) is None
        ):
            raise LocalApiServiceError("admission_ref is invalid")
        object.__setattr__(self, "status", AdmissionStatus(self.status))
        object.__setattr__(self, "operation", Operation(self.operation))
        object.__setattr__(self, "resource_kind", ResourceKind(self.resource_kind))
        _digest(self.request_sha256, "admission request_sha256")
        _digest(self.idempotency_sha256, "admission idempotency_sha256")
        for field_name in ("tenant_id", "context_id", "principal_id", "resource_id"):
            _identifier(getattr(self, field_name), f"admission {field_name}")
        if (
            not isinstance(self.authorization_ref, str)
            or DECISION_REF_RE.fullmatch(self.authorization_ref) is None
        ):
            raise LocalApiServiceError("admission authorization_ref is invalid")
        if (
            self.expected_concurrency_token is not None
            and CONCURRENCY_RE.fullmatch(self.expected_concurrency_token) is None
        ):
            raise LocalApiServiceError("admission concurrency token is invalid")
        _timestamp(self.valid_through, "admission valid_through")
        _audit_ref(self.audit_ref, "admission audit_ref")


@dataclass(frozen=True)
class ResourceRecord:
    resource_kind: ResourceKind | str
    resource_id: str
    tenant_id: str
    context_id: str
    version: int
    concurrency_token: str
    payload: Mapping[str, Any]
    payload_sha256: str
    audit_refs: tuple[str, ...]
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "resource_kind", ResourceKind(self.resource_kind))
        for field_name in ("resource_id", "tenant_id", "context_id"):
            _identifier(getattr(self, field_name), field_name)
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise LocalApiServiceError("version must be positive")
        if CONCURRENCY_RE.fullmatch(self.concurrency_token) is None:
            raise LocalApiServiceError("concurrency_token is invalid")
        payload, document = _canonical_payload(self.payload)
        object.__setattr__(self, "payload", payload)
        _digest(self.payload_sha256, "payload_sha256")
        if canonical_sha256(json.loads(document)) != self.payload_sha256:
            raise LocalApiServiceError("payload_sha256 does not match payload")
        if not self.audit_refs or len(set(self.audit_refs)) != len(self.audit_refs):
            raise LocalApiServiceError("audit_refs must be unique and non-empty")
        for reference in self.audit_refs:
            _audit_ref(reference, "resource audit_ref")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        expected_token = _concurrency_token(
            self.resource_kind,
            self.resource_id,
            self.tenant_id,
            self.context_id,
            self.version,
            self.payload_sha256,
            self.audit_refs,
        )
        if self.concurrency_token != expected_token:
            raise LocalApiServiceError("concurrency_token does not match resource")

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_refs": list(self.audit_refs),
            "concurrency_token": self.concurrency_token,
            "context_id": self.context_id,
            "created_at": self.created_at,
            "payload": dict(self.payload),
            "payload_sha256": self.payload_sha256,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind.value,
            "tenant_id": self.tenant_id,
            "updated_at": self.updated_at,
            "version": self.version,
        }


@dataclass(frozen=True)
class AuditEntry:
    audit_ref: str
    request_sha256: str
    authorization_ref: str
    admission_ref: str
    admission_audit_ref: str
    prior_concurrency_token: str | None
    resulting_concurrency_token: str
    resource_kind: ResourceKind
    resource_id: str
    tenant_id: str
    context_id: str
    principal_id: str
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "admission_audit_ref": self.admission_audit_ref,
            "admission_ref": self.admission_ref,
            "audit_ref": self.audit_ref,
            "authorization_ref": self.authorization_ref,
            "context_id": self.context_id,
            "principal_id": self.principal_id,
            "prior_concurrency_token": self.prior_concurrency_token,
            "recorded_at": self.recorded_at,
            "request_sha256": self.request_sha256,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind.value,
            "resulting_concurrency_token": self.resulting_concurrency_token,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class IntegrationEvent:
    event_id: str
    event_type: str
    tenant_id: str
    context_id: str
    resource_kind: ResourceKind
    resource_id: str
    resource_version: int
    resource_sha256: str
    audit_ref: str
    occurred_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_ref": self.audit_ref,
            "context_id": self.context_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind.value,
            "resource_sha256": self.resource_sha256,
            "resource_version": self.resource_version,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class CommitCommand:
    request_sha256: str
    idempotency_sha256: str
    expected_concurrency_token: str | None
    prior_record: ResourceRecord | None
    record: ResourceRecord
    audit_entry: AuditEntry
    integration_event: IntegrationEvent


@dataclass(frozen=True)
class CommitResult:
    request_sha256: str
    idempotency_sha256: str
    record: ResourceRecord
    audit_entry: AuditEntry
    integration_event: IntegrationEvent
    replayed: bool


@dataclass(frozen=True)
class ServicePage:
    items: tuple[ResourceRecord, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class ServiceResponse:
    request_id: str
    request_sha256: str
    status: ResponseStatus | str
    authorization_ref: str
    authorization_audit_ref: str
    resource: ResourceRecord | None = None
    page: ServicePage | None = None
    mutation_audit_ref: str | None = None
    integration_event: IntegrationEvent | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ResponseStatus(self.status))
        _identifier(self.request_id, "response request_id")
        _digest(self.request_sha256, "response request_sha256")
        if (self.resource is None) == (self.page is None):
            raise LocalApiServiceError("response requires exactly one resource or page")
        if self.mutation_audit_ref is not None:
            _audit_ref(self.mutation_audit_ref, "response mutation_audit_ref")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_audit_ref": self.authorization_audit_ref,
            "authorization_ref": self.authorization_ref,
            "integration_event": (
                None if self.integration_event is None else self.integration_event.to_dict()
            ),
            "mutation_audit_ref": self.mutation_audit_ref,
            "page": (
                None
                if self.page is None
                else {
                    "items": [item.to_dict() for item in self.page.items],
                    "next_cursor": self.page.next_cursor,
                }
            ),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "resource": None if self.resource is None else self.resource.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }


class AccessAuthorizer(Protocol):
    def authorize(self, check: AccessCheck) -> AccessDecision: ...


class MutationAdmitter(Protocol):
    def admit(self, check: MutationCheck) -> MutationAdmission: ...


class ServiceRepository(Protocol):
    """Injected durable boundary. Commit must be atomic and idempotent."""

    def get(
        self, resource_kind: ResourceKind, tenant_id: str, context_id: str, resource_id: str
    ) -> ResourceRecord | None: ...

    def list_after(
        self,
        resource_kind: ResourceKind,
        tenant_id: str,
        context_id: str,
        after_resource_id: str | None,
        limit: int,
    ) -> Sequence[ResourceRecord]: ...

    def lookup_idempotency(
        self, tenant_id: str, context_id: str, idempotency_sha256: str
    ) -> CommitResult | None: ...

    def commit(self, command: CommitCommand) -> CommitResult: ...


class LocalApiService:
    """In-process product service. All authority and state are injected."""

    def __init__(
        self,
        repository: ServiceRepository,
        authorizer: AccessAuthorizer,
        admitter: MutationAdmitter,
    ) -> None:
        self._repository = repository
        self._authorizer = authorizer
        self._admitter = admitter

    def handle(self, request: ServiceRequest) -> ServiceResponse:
        decision = self._authorize(request)
        if request.operation is Operation.GET_RESOURCE:
            return self._get(request, decision)
        if request.operation is Operation.LIST_RESOURCES:
            return self._list(request, decision)
        return self._mutate(request, decision)

    def _authorize(self, request: ServiceRequest) -> AccessDecision:
        check = AccessCheck(
            request_sha256=request.request_sha256,
            tenant_id=request.access.tenant_id,
            context_id=request.access.context_id,
            principal_id=request.access.principal_id,
            session_ref=request.access.session_ref,
            permission=PERMISSION_BY_OPERATION[request.operation],
            requested_at=request.requested_at,
        )
        decision = self._authorizer.authorize(check)
        expected = (
            check.request_sha256,
            check.tenant_id,
            check.context_id,
            check.principal_id,
            check.session_ref,
            check.permission,
        )
        actual = (
            decision.request_sha256,
            decision.tenant_id,
            decision.context_id,
            decision.principal_id,
            decision.session_ref,
            decision.permission,
        )
        if decision.status is not DecisionStatus.ALLOWED or actual != expected:
            raise LocalApiServiceError("authorization was denied or rebound")
        if _instant(decision.valid_through) < _instant(request.requested_at):
            raise LocalApiServiceError("authorization is expired")
        return decision

    def _get(self, request: ServiceRequest, decision: AccessDecision) -> ServiceResponse:
        assert request.resource_id is not None
        record = self._repository.get(
            request.resource_kind,
            request.access.tenant_id,
            request.access.context_id,
            request.resource_id,
        )
        if record is None:
            raise LocalApiServiceError("resource was not found")
        _validate_record_binding(record, request)
        return ServiceResponse(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status=ResponseStatus.COMPLETED,
            authorization_ref=decision.decision_ref,
            authorization_audit_ref=decision.audit_ref,
            resource=record,
        )

    def _list(self, request: ServiceRequest, decision: AccessDecision) -> ServiceResponse:
        assert request.page_size is not None
        after = None
        if request.cursor is not None:
            after = _decode_cursor(
                request.cursor,
                request.resource_kind,
                request.access.tenant_id,
                request.access.context_id,
            )
        records = tuple(
            self._repository.list_after(
                request.resource_kind,
                request.access.tenant_id,
                request.access.context_id,
                after,
                request.page_size + 1,
            )
        )
        if len(records) > request.page_size + 1:
            raise LocalApiServiceError("repository exceeded the requested page boundary")
        prior_id = after
        for record in records:
            _validate_record_binding(record, request)
            if prior_id is not None and record.resource_id <= prior_id:
                raise LocalApiServiceError("repository page is not strictly ordered")
            prior_id = record.resource_id
        page_items = records[: request.page_size]
        next_cursor = None
        if len(records) > request.page_size:
            next_cursor = _encode_cursor(
                request.resource_kind,
                request.access.tenant_id,
                request.access.context_id,
                page_items[-1].resource_id,
            )
        return ServiceResponse(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status=ResponseStatus.COMPLETED,
            authorization_ref=decision.decision_ref,
            authorization_audit_ref=decision.audit_ref,
            page=ServicePage(page_items, next_cursor),
        )

    def _mutate(self, request: ServiceRequest, decision: AccessDecision) -> ServiceResponse:
        assert request.resource_id is not None
        assert request.payload is not None
        assert request.idempotency_sha256 is not None
        existing = self._repository.get(
            request.resource_kind,
            request.access.tenant_id,
            request.access.context_id,
            request.resource_id,
        )
        if existing is not None:
            _validate_record_binding(existing, request)
        _validate_payload(request.operation, request.payload, existing)
        if (
            request.operation is Operation.ATTACH_TARGET_CONTEXT
            and request.resource_id != request.payload["bundle"]["bundle_id"]
        ):
            raise LocalApiServiceError(
                "target context resource_id must equal its content-addressed bundle_id"
            )
        admission_check = MutationCheck(
            request_sha256=request.request_sha256,
            idempotency_sha256=request.idempotency_sha256,
            authorization_ref=decision.decision_ref,
            tenant_id=request.access.tenant_id,
            context_id=request.access.context_id,
            principal_id=request.access.principal_id,
            operation=request.operation,
            resource_kind=request.resource_kind,
            resource_id=request.resource_id,
            expected_concurrency_token=request.expected_concurrency_token,
            requested_at=request.requested_at,
        )
        admission = self._admitter.admit(admission_check)
        _validate_admission(admission, admission_check, request.requested_at)
        replay = self._repository.lookup_idempotency(
            request.access.tenant_id,
            request.access.context_id,
            request.idempotency_sha256,
        )
        if replay is not None:
            _validate_commit_result(replay, request)
            return ServiceResponse(
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                status=ResponseStatus.REPLAYED,
                authorization_ref=decision.decision_ref,
                authorization_audit_ref=decision.audit_ref,
                resource=replay.record,
                mutation_audit_ref=replay.audit_entry.audit_ref,
                integration_event=replay.integration_event,
            )
        _validate_mutation_preconditions(request, existing)
        audit_ref = _make_audit_ref(request, decision, admission, existing)
        record = _build_record(request, existing, audit_ref)
        audit_entry = AuditEntry(
            audit_ref=audit_ref,
            request_sha256=request.request_sha256,
            authorization_ref=decision.decision_ref,
            admission_ref=admission.admission_ref,
            admission_audit_ref=admission.audit_ref,
            prior_concurrency_token=(None if existing is None else existing.concurrency_token),
            resulting_concurrency_token=record.concurrency_token,
            resource_kind=record.resource_kind,
            resource_id=record.resource_id,
            tenant_id=record.tenant_id,
            context_id=record.context_id,
            principal_id=request.access.principal_id,
            recorded_at=request.requested_at,
        )
        event = _build_event(request, record, audit_ref)
        command = CommitCommand(
            request_sha256=request.request_sha256,
            idempotency_sha256=request.idempotency_sha256,
            expected_concurrency_token=request.expected_concurrency_token,
            prior_record=existing,
            record=record,
            audit_entry=audit_entry,
            integration_event=event,
        )
        result = self._repository.commit(command)
        _validate_commit_result(result, request)
        if not result.replayed and any(
            canonical_json(getattr(result, field).to_dict())
            != canonical_json(getattr(command, field).to_dict())
            for field in ("record", "audit_entry", "integration_event")
        ):
            raise LocalApiServiceError("repository changed the newly committed evidence")
        return ServiceResponse(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status=ResponseStatus.REPLAYED if result.replayed else ResponseStatus.COMPLETED,
            authorization_ref=decision.decision_ref,
            authorization_audit_ref=decision.audit_ref,
            resource=result.record,
            mutation_audit_ref=result.audit_entry.audit_ref,
            integration_event=result.integration_event,
        )


def _validate_record_binding(record: ResourceRecord, request: ServiceRequest) -> None:
    if (
        record.resource_kind is not request.resource_kind
        or record.tenant_id != request.access.tenant_id
        or record.context_id != request.access.context_id
    ):
        raise LocalApiServiceError("repository returned a cross-context resource")
    if request.resource_id is not None and record.resource_id != request.resource_id:
        raise LocalApiServiceError("repository returned a different resource identity")


def _validate_mutation_preconditions(
    request: ServiceRequest, existing: ResourceRecord | None
) -> None:
    if existing is not None:
        _validate_record_binding(existing, request)
    if request.operation in CREATE_ONLY_OPERATIONS:
        if existing is not None or request.expected_concurrency_token is not None:
            raise LocalApiServiceError("create operation conflicts with existing state")
    elif request.operation in UPDATE_ONLY_OPERATIONS:
        if existing is None or request.expected_concurrency_token is None:
            raise LocalApiServiceError("update operation requires existing state and token")
        if request.expected_concurrency_token != existing.concurrency_token:
            raise LocalApiServiceError("expected concurrency token is stale")
    elif request.operation in UPSERT_OPERATIONS:
        if existing is None and request.expected_concurrency_token is not None:
            raise LocalApiServiceError("finding create must not carry a token")
        if (
            existing is not None
            and request.expected_concurrency_token != existing.concurrency_token
        ):
            raise LocalApiServiceError("finding update requires the current token")


def _validate_payload(
    operation: Operation, payload: Mapping[str, Any], existing: ResourceRecord | None
) -> None:
    required = REQUIRED_FIELDS[operation]
    if set(payload) != required:
        raise LocalApiServiceError("payload fields do not match the operation contract")
    if operation in {Operation.CREATE_ASSET, Operation.UPDATE_ASSET}:
        _closed_token(
            payload["eligibility"],
            "asset eligibility",
            frozenset({"admitted", "excluded", "pending"}),
        )
        for field_name in ("target_refs", "credential_refs", "exclusion_refs"):
            _reference_sequence(payload[field_name], f"asset {field_name}")
    if operation in {Operation.CREATE_MISSION, Operation.TRANSITION_MISSION}:
        try:
            target = MissionState(payload["state"])
        except (TypeError, ValueError) as exc:
            raise LocalApiServiceError("mission state is invalid") from exc
        _reference_sequence(payload["asset_refs"], "mission asset_refs")
        if operation is Operation.CREATE_MISSION and target is not MissionState.DRAFT:
            raise LocalApiServiceError("mission must be created in draft state")
        if existing is not None:
            current = MissionState(existing.payload["state"])
            if target not in MISSION_TRANSITIONS[current]:
                raise LocalApiServiceError("mission state transition is not allowed")
    if operation is Operation.UPSERT_FINDING:
        _closed_token(
            payload["severity"],
            "finding severity",
            frozenset({"info", "low", "medium", "high", "critical"}),
        )
        _closed_token(
            payload["status"],
            "finding status",
            frozenset(
                {
                    "discovered",
                    "triaged",
                    "validated",
                    "accepted_risk",
                    "false_positive",
                    "remediated",
                    "closed",
                }
            ),
        )
        for field_name in ("affected_asset_refs", "evidence_refs", "retest_refs"):
            _reference_sequence(payload[field_name], f"finding {field_name}")
    if operation is Operation.CREATE_REPORT:
        _digest(payload["record_set_sha256"], "report record_set_sha256")
        _closed_token(
            payload["report_type"],
            "report type",
            frozenset({"technical", "executive", "compliance", "machine_readable"}),
        )
        _reference_sequence(payload["finding_refs"], "report finding_refs")
        _reference_sequence(payload["evidence_refs"], "report evidence_refs")
    if operation is Operation.RECORD_REMEDIATION:
        _closed_token(
            payload["closure_status"],
            "remediation closure_status",
            frozenset({"guidance_ready", "resubmitted", "retest_pending", "closed", "reopened"}),
        )
        _reference_sequence(
            payload["developer_evidence_refs"], "remediation developer_evidence_refs"
        )
    if operation is Operation.RECORD_APPROVAL:
        _closed_token(
            payload["decision"],
            "approval decision",
            frozenset({"approved", "denied", "revoked"}),
        )
    if operation is Operation.UPDATE_HEALTH:
        _timestamp(payload["observed_at"], "health observed_at")
        _closed_token(
            payload["state"],
            "health state",
            frozenset({"healthy", "degraded", "unhealthy", "unknown"}),
        )
    if operation is Operation.PUBLISH_OPERATOR_PROJECTION:
        for field_name in ("approval_refs", "health_refs", "blocker_refs"):
            _reference_sequence(payload[field_name], f"projection {field_name}")
    if operation is Operation.ATTACH_TARGET_CONTEXT:
        try:
            TargetContextBundle.from_dict(payload["bundle"])
        except TargetContextError as exc:
            raise LocalApiServiceError("target context bundle is invalid") from exc


def _validate_admission(
    admission: MutationAdmission, check: MutationCheck, requested_at: str
) -> None:
    expected = (
        check.request_sha256,
        check.idempotency_sha256,
        check.authorization_ref,
        check.tenant_id,
        check.context_id,
        check.principal_id,
        check.operation,
        check.resource_kind,
        check.resource_id,
        check.expected_concurrency_token,
    )
    actual = (
        admission.request_sha256,
        admission.idempotency_sha256,
        admission.authorization_ref,
        admission.tenant_id,
        admission.context_id,
        admission.principal_id,
        admission.operation,
        admission.resource_kind,
        admission.resource_id,
        admission.expected_concurrency_token,
    )
    if admission.status is not AdmissionStatus.ADMITTED or actual != expected:
        raise LocalApiServiceError("mutation admission was rejected or rebound")
    if _instant(admission.valid_through) < _instant(requested_at):
        raise LocalApiServiceError("mutation admission is expired")


def _make_audit_ref(
    request: ServiceRequest,
    decision: AccessDecision,
    admission: MutationAdmission,
    existing: ResourceRecord | None,
) -> str:
    digest = canonical_sha256(
        {
            "admission_ref": admission.admission_ref,
            "authorization_ref": decision.decision_ref,
            "prior_token": None if existing is None else existing.concurrency_token,
            "request_sha256": request.request_sha256,
        }
    )
    return "auditref:" + digest[7:]


def _concurrency_token(
    kind: ResourceKind,
    resource_id: str,
    tenant_id: str,
    context_id: str,
    version: int,
    payload_sha256: str,
    audit_refs: Sequence[str],
) -> str:
    digest = canonical_sha256(
        {
            "audit_refs": list(audit_refs),
            "context_id": context_id,
            "payload_sha256": payload_sha256,
            "resource_id": resource_id,
            "resource_kind": kind.value,
            "tenant_id": tenant_id,
            "version": version,
        }
    )
    return "ct:" + digest[7:]


def _build_record(
    request: ServiceRequest, existing: ResourceRecord | None, audit_ref: str
) -> ResourceRecord:
    assert request.resource_id is not None
    assert request.payload is not None
    version = 1 if existing is None else existing.version + 1
    audit_refs = (audit_ref,) if existing is None else (*existing.audit_refs, audit_ref)
    created_at = request.requested_at if existing is None else existing.created_at
    payload_sha256 = canonical_sha256(dict(request.payload))
    concurrency_token = _concurrency_token(
        request.resource_kind,
        request.resource_id,
        request.access.tenant_id,
        request.access.context_id,
        version,
        payload_sha256,
        audit_refs,
    )
    return ResourceRecord(
        resource_kind=request.resource_kind,
        resource_id=request.resource_id,
        tenant_id=request.access.tenant_id,
        context_id=request.access.context_id,
        version=version,
        concurrency_token=concurrency_token,
        payload=request.payload,
        payload_sha256=payload_sha256,
        audit_refs=audit_refs,
        created_at=created_at,
        updated_at=request.requested_at,
    )


def _build_event(
    request: ServiceRequest, record: ResourceRecord, audit_ref: str
) -> IntegrationEvent:
    return _expected_event(record, audit_ref, request.operation, request.requested_at)


def _expected_event(
    record: ResourceRecord, audit_ref: str, operation: Operation, occurred_at: str
) -> IntegrationEvent:
    resource_sha256 = canonical_sha256(record.to_dict())
    event_type = f"{record.resource_kind.value}.{operation.value}"
    digest = canonical_sha256(
        {
            "audit_ref": audit_ref,
            "event_type": event_type,
            "resource_sha256": resource_sha256,
        }
    )
    return IntegrationEvent(
        event_id="event:" + digest[7:],
        event_type=event_type,
        tenant_id=record.tenant_id,
        context_id=record.context_id,
        resource_kind=record.resource_kind,
        resource_id=record.resource_id,
        resource_version=record.version,
        resource_sha256=resource_sha256,
        audit_ref=audit_ref,
        occurred_at=occurred_at,
    )


def _validate_atomic_commit_result(result: CommitResult) -> None:
    """Validate retained commit joins without inventing an absent prior snapshot."""

    if not isinstance(result, CommitResult) or not isinstance(result.record, ResourceRecord):
        raise LocalApiServiceError("atomic commit result is invalid")
    record, audit, event = result.record, result.audit_entry, result.integration_event
    if not isinstance(audit, AuditEntry) or not isinstance(event, IntegrationEvent):
        raise LocalApiServiceError("atomic commit evidence is invalid")
    _digest(result.request_sha256, "committed request_sha256")
    _digest(result.idempotency_sha256, "committed idempotency_sha256")
    if type(result.replayed) is not bool:
        raise LocalApiServiceError("atomic replay flag is invalid")
    if type(record.version) is not int or record.version != len(record.audit_refs):
        raise LocalApiServiceError("atomic record version and audit chain differ")
    for name in ("authorization_ref", "admission_ref"):
        value = getattr(audit, name)
        if not isinstance(value, str) or DECISION_REF_RE.fullmatch(value) is None:
            raise LocalApiServiceError("atomic audit decision reference is invalid")
    _audit_ref(audit.audit_ref, "atomic audit_ref")
    _audit_ref(audit.admission_audit_ref, "atomic admission_audit_ref")
    _identifier(audit.principal_id, "atomic audit principal_id")
    _timestamp(audit.recorded_at, "atomic audit recorded_at")
    if record.version == 1:
        if audit.prior_concurrency_token is not None or record.created_at != record.updated_at:
            raise LocalApiServiceError("initial atomic commit carries prior state")
    elif (
        not isinstance(audit.prior_concurrency_token, str)
        or CONCURRENCY_RE.fullmatch(audit.prior_concurrency_token) is None
    ):
        raise LocalApiServiceError("updated atomic commit requires its original prior token")
    actual_audit = {
        "context_id": audit.context_id,
        "recorded_at": audit.recorded_at,
        "request_sha256": audit.request_sha256,
        "resource_id": audit.resource_id,
        "resource_kind": audit.resource_kind.value,
        "resulting_concurrency_token": audit.resulting_concurrency_token,
        "tenant_id": audit.tenant_id,
    }
    expected_audit = {
        "context_id": record.context_id,
        "recorded_at": record.updated_at,
        "request_sha256": result.request_sha256,
        "resource_id": record.resource_id,
        "resource_kind": record.resource_kind.value,
        "resulting_concurrency_token": record.concurrency_token,
        "tenant_id": record.tenant_id,
    }
    expected_audit_ref = (
        "auditref:"
        + canonical_sha256(
            {
                "admission_ref": audit.admission_ref,
                "authorization_ref": audit.authorization_ref,
                "prior_token": audit.prior_concurrency_token,
                "request_sha256": result.request_sha256,
            }
        )[7:]
    )
    if (
        canonical_json(actual_audit) != canonical_json(expected_audit)
        or audit.audit_ref != record.audit_refs[-1]
        or audit.audit_ref != expected_audit_ref
    ):
        raise LocalApiServiceError("audit entry is not bound to the atomic commit")
    try:
        prefix, operation_name = event.event_type.split(".", 1)
        operation = Operation(operation_name)
    except (AttributeError, TypeError, ValueError) as exc:
        raise LocalApiServiceError("atomic event type is invalid") from exc
    if (
        prefix != record.resource_kind.value
        or RESOURCE_BY_OPERATION.get(operation) is not record.resource_kind
    ):
        raise LocalApiServiceError("atomic event type does not match resource kind")
    if (
        operation in CREATE_ONLY_OPERATIONS
        and record.version != 1
        or operation in UPDATE_ONLY_OPERATIONS
        and record.version == 1
    ):
        raise LocalApiServiceError("atomic event operation does not match resource history")
    expected_event = _expected_event(record, audit.audit_ref, operation, record.updated_at)
    if canonical_json(event.to_dict()) != canonical_json(expected_event.to_dict()):
        raise LocalApiServiceError("integration event is not bound to the atomic commit")


def _validate_commit_result(result: CommitResult, request: ServiceRequest) -> None:
    if not isinstance(result, CommitResult) or not isinstance(result.record, ResourceRecord):
        raise LocalApiServiceError("atomic commit result is invalid")
    if result.request_sha256 != request.request_sha256:
        raise LocalApiServiceError("repository rebound the committed request")
    if result.idempotency_sha256 != request.idempotency_sha256:
        raise LocalApiServiceError("repository rebound the idempotency key")
    _validate_record_binding(result.record, request)
    _validate_atomic_commit_result(result)
    if (
        result.record.resource_id != request.resource_id
        or result.audit_entry.principal_id != request.access.principal_id
        or result.audit_entry.prior_concurrency_token != request.expected_concurrency_token
        or result.record.updated_at != request.requested_at
        or canonical_json(dict(result.record.payload))
        != canonical_json(dict(request.payload or {}))
        or (request.expected_concurrency_token is None) != (result.record.version == 1)
        or canonical_json(result.integration_event.to_dict())
        != canonical_json(
            _build_event(request, result.record, result.audit_entry.audit_ref).to_dict()
        )
    ):
        raise LocalApiServiceError("repository returned an incoherent atomic commit")


def _encode_cursor(kind: ResourceKind, tenant_id: str, context_id: str, after: str) -> str:
    body = canonical_json(
        {
            "after": after,
            "context_id": context_id,
            "resource_kind": kind.value,
            "tenant_id": tenant_id,
        }
    ).encode("ascii")
    encoded = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    digest = hashlib.sha256(body).hexdigest()
    return f"cursor:{encoded}.{digest}"


def _decode_cursor(cursor: str, kind: ResourceKind, tenant_id: str, context_id: str) -> str:
    if CURSOR_RE.fullmatch(cursor) is None:
        raise LocalApiServiceError("cursor is invalid")
    encoded, supplied_digest = cursor[7:].rsplit(".", 1)
    try:
        padding = "=" * (-len(encoded) % 4)
        body = base64.urlsafe_b64decode(encoded + padding)
        raw = json.loads(body.decode("ascii"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalApiServiceError("cursor cannot be decoded") from exc
    if hashlib.sha256(body).hexdigest() != supplied_digest:
        raise LocalApiServiceError("cursor integrity check failed")
    if canonical_json(raw).encode("ascii") != body:
        raise LocalApiServiceError("cursor is not canonical")
    expected = {
        "after": raw.get("after"),
        "context_id": context_id,
        "resource_kind": kind.value,
        "tenant_id": tenant_id,
    }
    if raw != expected:
        raise LocalApiServiceError("cursor was rebound across a service context")
    return _identifier(raw["after"], "cursor after")


def service_capability_manifest() -> dict[str, Any]:
    """Return the honest, deterministic boundary declaration."""

    return {
        "capability_packages": [f"P5.{index}" for index in range(1, 10)],
        "effects": {
            "authentication": "injected",
            "authorization": "injected",
            "integration_delivery": "none",
            "mission_execution": "none",
            "network": "none",
            "persistence": "injected",
            "server": "none",
        },
        "resource_kinds": [kind.value for kind in ResourceKind],
        "runtime_kind": "deterministic_in_process_service_core",
        "schema_version": SCHEMA_VERSION,
    }
