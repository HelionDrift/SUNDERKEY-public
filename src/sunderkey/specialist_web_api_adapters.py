"""Fail-closed specialist adapter contracts for web, API, and auth testing.

This module defines repository-only request, adapter, replay, and receipt
boundaries for roadmap packages A2.5 through A2.11. It does not implement a
network client, browser, proxy, scanner, credential resolver, or exploit. An
infrastructure-specific adapter must be injected by the caller.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .types import ActionTier

SCHEMA_VERSION = 1
MAX_WINDOW_SECONDS = 86_400
MAX_OPERATIONS = 64
MAX_BYTES = 100_000_000

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|scoperef|targetref|workerref|actionref|approvalref|"
    r"evidenceref|sessionref|principalref|authctxref|toolref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._/-]{7,190}\Z")
ADAPTER_ID_RE = re.compile(r"adapter:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")

SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie)\s*[:=]|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)

REPOSITORY_ONLY_EFFECTS = MappingProxyType(
    {
        "authority_grant": "none",
        "credential_resolution": "none",
        "network_client": "not_included",
        "qualification": "none",
        "remote_execution": "injected_adapter_only",
        "tool_implementation": "not_included",
    }
)


class SpecialistAdapterError(ValueError):
    """Raised when a specialist adapter contract fails closed."""


class SpecialistFamily(StrEnum):
    HTTP_PROTOCOL = "http_protocol"
    AUTHENTICATION = "authentication"
    OAUTH_FEDERATION = "oauth_federation"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    API_TECHNOLOGY = "api_technology"
    INPUT_SERVICE_INTERACTION = "input_service_interaction"


class SpecialistOperation(StrEnum):
    HTTP_REQUEST_CONSTRUCTION = "http_request_construction"
    HTTP_PROXY_CACHE_PARSER = "http_proxy_cache_parser"
    AUTH_LOGIN_SESSION = "auth_login_session"
    AUTH_REFRESH_LOGOUT_MFA_RECOVERY = "auth_refresh_logout_mfa_recovery"
    OAUTH_REDIRECT_CLAIM_AUDIENCE_SCOPE = "oauth_redirect_claim_audience_scope"
    OAUTH_EXCHANGE_FEDERATION = "oauth_exchange_federation"
    AUTHZ_OBJECT_FUNCTION_FIELD = "authz_object_function_field"
    AUTHZ_TENANT_ROLE = "authz_tenant_role"
    BUSINESS_STATE_ORDER_LIMIT = "business_state_order_limit"
    BUSINESS_CONCURRENCY_WORKFLOW = "business_concurrency_workflow"
    API_REST_GRAPHQL_ASYNC = "api_rest_graphql_async"
    API_FILE_SERIALIZATION = "api_file_serialization"
    INPUT_PARSER_TEMPLATE = "input_parser_template"
    INPUT_INJECTION_SSRF_DESERIALIZATION = "input_injection_ssrf_deserialization"


class ResultState(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class OperationPolicy:
    package_id: str
    family: SpecialistFamily
    minimum_tier: ActionTier
    authenticated_session_required: bool
    minimum_principals: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated_session_required": self.authenticated_session_required,
            "family": self.family.value,
            "minimum_principals": self.minimum_principals,
            "minimum_tier": self.minimum_tier.value,
            "package_id": self.package_id,
        }


OPERATION_POLICIES = MappingProxyType(
    {
        SpecialistOperation.HTTP_REQUEST_CONSTRUCTION: OperationPolicy(
            "A2.5", SpecialistFamily.HTTP_PROTOCOL, ActionTier.R1, False, 0
        ),
        SpecialistOperation.HTTP_PROXY_CACHE_PARSER: OperationPolicy(
            "A2.5", SpecialistFamily.HTTP_PROTOCOL, ActionTier.R1, False, 0
        ),
        SpecialistOperation.AUTH_LOGIN_SESSION: OperationPolicy(
            "A2.6", SpecialistFamily.AUTHENTICATION, ActionTier.R1, True, 1
        ),
        SpecialistOperation.AUTH_REFRESH_LOGOUT_MFA_RECOVERY: OperationPolicy(
            "A2.6", SpecialistFamily.AUTHENTICATION, ActionTier.R2, True, 1
        ),
        SpecialistOperation.OAUTH_REDIRECT_CLAIM_AUDIENCE_SCOPE: OperationPolicy(
            "A2.7", SpecialistFamily.OAUTH_FEDERATION, ActionTier.R1, True, 1
        ),
        SpecialistOperation.OAUTH_EXCHANGE_FEDERATION: OperationPolicy(
            "A2.7", SpecialistFamily.OAUTH_FEDERATION, ActionTier.R2, True, 1
        ),
        SpecialistOperation.AUTHZ_OBJECT_FUNCTION_FIELD: OperationPolicy(
            "A2.8", SpecialistFamily.AUTHORIZATION, ActionTier.R1, True, 2
        ),
        SpecialistOperation.AUTHZ_TENANT_ROLE: OperationPolicy(
            "A2.8", SpecialistFamily.AUTHORIZATION, ActionTier.R2, True, 2
        ),
        SpecialistOperation.BUSINESS_STATE_ORDER_LIMIT: OperationPolicy(
            "A2.9", SpecialistFamily.BUSINESS_LOGIC, ActionTier.R1, True, 1
        ),
        SpecialistOperation.BUSINESS_CONCURRENCY_WORKFLOW: OperationPolicy(
            "A2.9", SpecialistFamily.BUSINESS_LOGIC, ActionTier.R2, True, 1
        ),
        SpecialistOperation.API_REST_GRAPHQL_ASYNC: OperationPolicy(
            "A2.10", SpecialistFamily.API_TECHNOLOGY, ActionTier.R1, False, 0
        ),
        SpecialistOperation.API_FILE_SERIALIZATION: OperationPolicy(
            "A2.10", SpecialistFamily.API_TECHNOLOGY, ActionTier.R2, False, 0
        ),
        SpecialistOperation.INPUT_PARSER_TEMPLATE: OperationPolicy(
            "A2.11", SpecialistFamily.INPUT_SERVICE_INTERACTION, ActionTier.R1, False, 0
        ),
        SpecialistOperation.INPUT_INJECTION_SSRF_DESERIALIZATION: OperationPolicy(
            "A2.11", SpecialistFamily.INPUT_SERVICE_INTERACTION, ActionTier.R2, False, 0
        ),
    }
)


def canonical_json(value: Any) -> str:
    """Return stable printable ASCII JSON after secret-pattern checks."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if SECRET_RE.search(encoded):
        raise SpecialistAdapterError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise SpecialistAdapterError(f"{label} exceeds nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SpecialistAdapterError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise SpecialistAdapterError(f"{label} has unsupported content")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SpecialistAdapterError(f"{label} must be a SHA-256 digest")
    return value


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise SpecialistAdapterError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise SpecialistAdapterError(f"{label} must use the {namespace} namespace")
    if SECRET_RE.search(value):
        raise SpecialistAdapterError(f"{label} contains secret material")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise SpecialistAdapterError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SpecialistAdapterError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _instant(_timestamp(issued_at, f"{label} issued_at"))
    expires = _instant(_timestamp(expires_at, f"{label} expires_at"))
    seconds = (expires - issued).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS:
        raise SpecialistAdapterError(f"{label} window is invalid")


def _at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SpecialistAdapterError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _references(
    values: Sequence[str], label: str, namespace: str, *, minimum: int = 0, maximum: int = 64
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise SpecialistAdapterError(f"{label} must be a sequence")
    result = tuple(_reference(value, f"{label} item", namespace) for value in values)
    if not minimum <= len(result) <= maximum or len(set(result)) != len(result):
        raise SpecialistAdapterError(f"{label} count or uniqueness is invalid")
    return tuple(sorted(result))


def _positive(value: Any, label: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
        raise SpecialistAdapterError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityDeclaration:
    package_id: str
    family: SpecialistFamily
    operations: tuple[SpecialistOperation, ...]
    repository_only: bool = True
    qualification_status: str = "not_qualified"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"A2\.(?:5|6|7|8|9|10|11)", self.package_id):
            raise SpecialistAdapterError("capability package_id is invalid")
        operations = tuple(SpecialistOperation(value) for value in self.operations)
        if not operations or len(operations) != len(set(operations)):
            raise SpecialistAdapterError("capability operations are invalid")
        if any(OPERATION_POLICIES[item].package_id != self.package_id for item in operations):
            raise SpecialistAdapterError("capability operation package mismatch")
        if any(OPERATION_POLICIES[item].family is not self.family for item in operations):
            raise SpecialistAdapterError("capability operation family mismatch")
        if self.repository_only is not True or self.qualification_status != "not_qualified":
            raise SpecialistAdapterError("capability cannot claim deployment or qualification")
        object.__setattr__(self, "operations", tuple(sorted(operations, key=str)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "operations": [item.value for item in self.operations],
            "package_id": self.package_id,
            "qualification_status": self.qualification_status,
            "repository_only": self.repository_only,
        }


def specialist_capability_declarations() -> tuple[SpecialistCapabilityDeclaration, ...]:
    """Return the fixed A2.5 through A2.11 specialist declaration set."""

    grouped: dict[tuple[str, SpecialistFamily], list[SpecialistOperation]] = {}
    for operation, policy in OPERATION_POLICIES.items():
        grouped.setdefault((policy.package_id, policy.family), []).append(operation)
    return tuple(
        SpecialistCapabilityDeclaration(package, family, tuple(operations))
        for (package, family), operations in sorted(grouped.items())
    )


@dataclass(frozen=True, slots=True)
class SpecialistContext:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    target_ref: str
    worker_ref: str
    action_ref: str
    action_admission_sha256: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
            ("worker_ref", "workerref"),
            ("action_ref", "actionref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _digest(self.action_admission_sha256, "action_admission_sha256")

    @property
    def context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_admission_sha256": self.action_admission_sha256,
            "action_ref": self.action_ref,
            "mission_ref": self.mission_ref,
            "scope_ref": self.scope_ref,
            "target_ref": self.target_ref,
            "tenant_ref": self.tenant_ref,
            "worker_ref": self.worker_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SpecialistContext:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "specialist context"))


@dataclass(frozen=True, slots=True)
class PrincipalSessionBinding:
    session_ref: str
    principal_ref: str
    authenticated_context_ref: str
    authenticated_context_sha256: str
    context_sha256: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("session_ref", "sessionref"),
            ("principal_ref", "principalref"),
            ("authenticated_context_ref", "authctxref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _digest(self.authenticated_context_sha256, "authenticated_context_sha256")
        _digest(self.context_sha256, "session context_sha256")
        _window(self.issued_at, self.expires_at, "principal session")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated_context_ref": self.authenticated_context_ref,
            "authenticated_context_sha256": self.authenticated_context_sha256,
            "context_sha256": self.context_sha256,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "principal_ref": self.principal_ref,
            "session_ref": self.session_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PrincipalSessionBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "principal session"))


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    approval_ref: str
    approval_sha256: str
    context_sha256: str
    operation: SpecialistOperation
    maximum_tier: ActionTier
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "approval_ref",
            _reference(self.approval_ref, "approval_ref", "approvalref"),
        )
        _digest(self.approval_sha256, "approval_sha256")
        _digest(self.context_sha256, "approval context_sha256")
        object.__setattr__(self, "operation", SpecialistOperation(self.operation))
        object.__setattr__(self, "maximum_tier", ActionTier(self.maximum_tier))
        _window(self.issued_at, self.expires_at, "approval")

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "context_sha256": self.context_sha256,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "maximum_tier": self.maximum_tier.value,
            "operation": self.operation.value,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ApprovalBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "approval binding"))


@dataclass(frozen=True, slots=True)
class SpecialistBudget:
    max_operations: int
    max_request_bytes: int
    max_response_bytes: int
    max_evidence_items: int
    max_redirects: int

    def __post_init__(self) -> None:
        _positive(self.max_operations, "max_operations", MAX_OPERATIONS)
        _positive(self.max_request_bytes, "max_request_bytes", MAX_BYTES)
        _positive(self.max_response_bytes, "max_response_bytes", MAX_BYTES)
        _positive(self.max_evidence_items, "max_evidence_items", 256)
        if isinstance(self.max_redirects, bool) or not 0 <= self.max_redirects <= 32:
            raise SpecialistAdapterError("max_redirects is invalid")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_evidence_items": self.max_evidence_items,
            "max_operations": self.max_operations,
            "max_redirects": self.max_redirects,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SpecialistBudget:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "specialist budget"))


@dataclass(frozen=True, slots=True)
class SpecialistActionRequest:
    context: SpecialistContext
    operation: SpecialistOperation
    requested_tier: ActionTier
    approval: ApprovalBinding
    sessions: tuple[PrincipalSessionBinding, ...]
    evidence_refs: tuple[str, ...]
    tool_input_ref: str
    tool_input_sha256: str
    idempotency_key: str
    budget: SpecialistBudget
    issued_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.context, SpecialistContext):
            raise SpecialistAdapterError("request context is invalid")
        object.__setattr__(self, "operation", SpecialistOperation(self.operation))
        object.__setattr__(self, "requested_tier", ActionTier(self.requested_tier))
        if not isinstance(self.approval, ApprovalBinding):
            raise SpecialistAdapterError("request approval is invalid")
        sessions = tuple(self.sessions)
        if any(not isinstance(value, PrincipalSessionBinding) for value in sessions):
            raise SpecialistAdapterError("request sessions are invalid")
        session_refs = [value.session_ref for value in sessions]
        principals = [value.principal_ref for value in sessions]
        if len(session_refs) != len(set(session_refs)) or len(principals) != len(set(principals)):
            raise SpecialistAdapterError("request sessions must isolate unique principals")
        object.__setattr__(
            self,
            "sessions",
            tuple(sorted(sessions, key=lambda item: item.principal_ref)),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _references(self.evidence_refs, "evidence_refs", "evidenceref", minimum=1),
        )
        object.__setattr__(
            self,
            "tool_input_ref",
            _reference(self.tool_input_ref, "tool_input_ref", "toolref"),
        )
        _digest(self.tool_input_sha256, "tool_input_sha256")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise SpecialistAdapterError("idempotency_key is invalid")
        if not isinstance(self.budget, SpecialistBudget):
            raise SpecialistAdapterError("request budget is invalid")
        _window(self.issued_at, self.expires_at, "request")
        self._validate_bindings()
        body = self._body()
        request_id, request_sha256 = _identity("SAR", "specialist-action-request.v1", body)
        if self.request_id and self.request_id != request_id:
            raise SpecialistAdapterError("request_id does not match content")
        if self.request_sha256 and self.request_sha256 != request_sha256:
            raise SpecialistAdapterError("request_sha256 does not match content")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "request_sha256", request_sha256)

    def _validate_bindings(self) -> None:
        policy = OPERATION_POLICIES[self.operation]
        if self.requested_tier.rank < policy.minimum_tier.rank:
            raise SpecialistAdapterError("requested tier is below the operation minimum")
        if self.approval.context_sha256 != self.context.context_sha256:
            raise SpecialistAdapterError("approval has a cross-context binding")
        if self.approval.operation is not self.operation:
            raise SpecialistAdapterError("approval operation does not match")
        if not self.approval.maximum_tier.allows(self.requested_tier):
            raise SpecialistAdapterError("approval tier does not allow the request")
        if len(self.sessions) < policy.minimum_principals:
            raise SpecialistAdapterError("operation lacks required isolated principals")
        if not policy.authenticated_session_required and len(self.sessions) > 8:
            raise SpecialistAdapterError("request has too many sessions")
        if any(value.context_sha256 != self.context.context_sha256 for value in self.sessions):
            raise SpecialistAdapterError("session has a cross-context binding")

    def _body(self) -> dict[str, Any]:
        return {
            "approval": self.approval.to_dict(),
            "budget": self.budget.to_dict(),
            "context": self.context.to_dict(),
            "effects": dict(REPOSITORY_ONLY_EFFECTS),
            "evidence_refs": list(self.evidence_refs),
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
            "issued_at": self.issued_at,
            "kind": "specialist_action_request",
            "operation": self.operation.value,
            "policy": OPERATION_POLICIES[self.operation].to_dict(),
            "requested_tier": self.requested_tier.value,
            "schema_version": SCHEMA_VERSION,
            "sessions": [value.to_dict() for value in self.sessions],
            "tool_input_ref": self.tool_input_ref,
            "tool_input_sha256": self.tool_input_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SpecialistActionRequest:
        value = dict(_exact(raw, _REQUEST_FIELDS, "specialist action request"))
        _metadata(value, "specialist_action_request")
        operation = SpecialistOperation(value.pop("operation"))
        if canonical_json(value.pop("policy")) != canonical_json(
            OPERATION_POLICIES[operation].to_dict()
        ):
            raise SpecialistAdapterError("request policy does not match the operation")
        value.pop("kind")
        value.pop("schema_version")
        value.pop("effects")
        value["operation"] = operation
        value["context"] = SpecialistContext.from_dict(value["context"])
        value["approval"] = ApprovalBinding.from_dict(value["approval"])
        value["sessions"] = tuple(
            PrincipalSessionBinding.from_dict(item) for item in value["sessions"]
        )
        value["evidence_refs"] = tuple(value["evidence_refs"])
        value["budget"] = SpecialistBudget.from_dict(value["budget"])
        candidate = cls(**value)
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise SpecialistAdapterError("request does not match exact canonical content")
        return candidate


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    adapter_id: str
    version: str
    supported_operations: tuple[SpecialistOperation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or ADAPTER_ID_RE.fullmatch(self.adapter_id) is None:
            raise SpecialistAdapterError("adapter_id is invalid")
        if not isinstance(self.version, str) or VERSION_RE.fullmatch(self.version) is None:
            raise SpecialistAdapterError("adapter version is invalid")
        operations = tuple(SpecialistOperation(value) for value in self.supported_operations)
        if not operations or len(operations) != len(set(operations)):
            raise SpecialistAdapterError("supported_operations are invalid")
        object.__setattr__(self, "supported_operations", tuple(sorted(operations, key=str)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "supported_operations": [value.value for value in self.supported_operations],
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class AdapterObservation:
    request_id: str
    request_sha256: str
    context_sha256: str
    idempotency_key: str
    state: ResultState
    operations_performed: int
    request_bytes: int
    response_bytes: int
    redirect_count: int
    evidence_refs: tuple[str, ...]
    evidence_sha256: tuple[str, ...]
    observed_at: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"SAR-[0-9A-F]{32}", self.request_id):
            raise SpecialistAdapterError("observation request_id is invalid")
        _digest(self.request_sha256, "observation request_sha256")
        _digest(self.context_sha256, "observation context_sha256")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise SpecialistAdapterError("observation idempotency_key is invalid")
        object.__setattr__(self, "state", ResultState(self.state))
        for name, ceiling in (
            ("operations_performed", MAX_OPERATIONS),
            ("request_bytes", MAX_BYTES),
            ("response_bytes", MAX_BYTES),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ceiling:
                raise SpecialistAdapterError(f"observation {name} is invalid")
        if isinstance(self.redirect_count, bool) or not 0 <= self.redirect_count <= 32:
            raise SpecialistAdapterError("observation redirect_count is invalid")
        refs = _references(
            self.evidence_refs,
            "observation evidence_refs",
            "evidenceref",
            minimum=1,
        )
        digests = tuple(
            _digest(value, "observation evidence_sha256 item") for value in self.evidence_sha256
        )
        if len(refs) != len(digests) or len(set(digests)) != len(digests):
            raise SpecialistAdapterError("observation evidence is invalid")
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "evidence_sha256", tuple(sorted(digests)))
        _timestamp(self.observed_at, "observed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_sha256": self.context_sha256,
            "evidence_refs": list(self.evidence_refs),
            "evidence_sha256": list(self.evidence_sha256),
            "idempotency_key": self.idempotency_key,
            "observed_at": self.observed_at,
            "operations_performed": self.operations_performed,
            "redirect_count": self.redirect_count,
            "request_bytes": self.request_bytes,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "response_bytes": self.response_bytes,
            "state": self.state.value,
        }


@runtime_checkable
class SpecialistExecutionAdapter(Protocol):
    """Injected execution boundary. Implementations live outside this module."""

    @property
    def identity(self) -> AdapterIdentity: ...

    def execute(self, request: SpecialistActionRequest) -> AdapterObservation: ...


class SpecialistReplayGuard:
    """Process-local replay guard for a single injected execution runtime."""

    def __init__(self) -> None:
        self._reservations: dict[str, tuple[str, str]] = {}

    def reserve(self, request: SpecialistActionRequest) -> None:
        if request.idempotency_key in self._reservations:
            raise SpecialistAdapterError("idempotency key replay is forbidden")
        self._reservations[request.idempotency_key] = (
            request.request_sha256,
            request.context.context_sha256,
        )

    def contains(self, idempotency_key: str) -> bool:
        return idempotency_key in self._reservations


@dataclass(frozen=True, slots=True)
class SpecialistActionReceipt:
    request_id: str
    request_sha256: str
    context_sha256: str
    adapter: AdapterIdentity
    state: ResultState
    operations_performed: int
    request_bytes: int
    response_bytes: int
    redirect_count: int
    evidence_refs: tuple[str, ...]
    evidence_sha256: tuple[str, ...]
    observed_at: str
    receipt_id: str = ""
    receipt_sha256: str = ""

    def __post_init__(self) -> None:
        if not re.fullmatch(r"SAR-[0-9A-F]{32}", self.request_id):
            raise SpecialistAdapterError("receipt request_id is invalid")
        _digest(self.request_sha256, "receipt request_sha256")
        _digest(self.context_sha256, "receipt context_sha256")
        if not isinstance(self.adapter, AdapterIdentity):
            raise SpecialistAdapterError("receipt adapter is invalid")
        object.__setattr__(self, "state", ResultState(self.state))
        observation = AdapterObservation(
            request_id=self.request_id,
            request_sha256=self.request_sha256,
            context_sha256=self.context_sha256,
            idempotency_key="idem:receipt-normalization",
            state=self.state,
            operations_performed=self.operations_performed,
            request_bytes=self.request_bytes,
            response_bytes=self.response_bytes,
            redirect_count=self.redirect_count,
            evidence_refs=self.evidence_refs,
            evidence_sha256=self.evidence_sha256,
            observed_at=self.observed_at,
        )
        object.__setattr__(self, "evidence_refs", observation.evidence_refs)
        object.__setattr__(self, "evidence_sha256", observation.evidence_sha256)
        body = self._body()
        receipt_id, receipt_sha256 = _identity("SRR", "specialist-action-receipt.v1", body)
        if self.receipt_id and self.receipt_id != receipt_id:
            raise SpecialistAdapterError("receipt_id does not match content")
        if self.receipt_sha256 and self.receipt_sha256 != receipt_sha256:
            raise SpecialistAdapterError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", receipt_sha256)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter.to_dict(),
            "context_sha256": self.context_sha256,
            "effects": dict(REPOSITORY_ONLY_EFFECTS),
            "evidence_refs": list(self.evidence_refs),
            "evidence_sha256": list(self.evidence_sha256),
            "kind": "specialist_action_receipt",
            "observed_at": self.observed_at,
            "operations_performed": self.operations_performed,
            "redirect_count": self.redirect_count,
            "request_bytes": self.request_bytes,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "response_bytes": self.response_bytes,
            "schema_version": SCHEMA_VERSION,
            "state": self.state.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SpecialistActionReceipt:
        value = dict(_exact(raw, _RECEIPT_FIELDS, "specialist action receipt"))
        _metadata(value, "specialist_action_receipt")
        value.pop("kind")
        value.pop("schema_version")
        value.pop("effects")
        adapter = _exact(
            value["adapter"],
            {"adapter_id", "supported_operations", "version"},
            "receipt adapter",
        )
        value["adapter"] = AdapterIdentity(
            adapter_id=adapter["adapter_id"],
            version=adapter["version"],
            supported_operations=tuple(adapter["supported_operations"]),
        )
        value["evidence_refs"] = tuple(value["evidence_refs"])
        value["evidence_sha256"] = tuple(value["evidence_sha256"])
        candidate = cls(**value)
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise SpecialistAdapterError("receipt does not match exact canonical content")
        return candidate


def execute_specialist_action(
    request: SpecialistActionRequest,
    *,
    expected_context: SpecialistContext,
    adapter: SpecialistExecutionAdapter,
    replay_guard: SpecialistReplayGuard,
    evaluated_at: datetime,
) -> SpecialistActionReceipt:
    """Validate and dispatch one action through an explicitly injected adapter."""

    if not isinstance(request, SpecialistActionRequest):
        raise SpecialistAdapterError("request is invalid")
    if request.context != expected_context:
        raise SpecialistAdapterError("request has a cross-context binding")
    now = _at(evaluated_at)
    if not _instant(request.issued_at) <= now < _instant(request.expires_at):
        raise SpecialistAdapterError("request is stale")
    if not _instant(request.approval.issued_at) <= now < _instant(request.approval.expires_at):
        raise SpecialistAdapterError("approval is stale")
    if any(
        not _instant(value.issued_at) <= now < _instant(value.expires_at)
        for value in request.sessions
    ):
        raise SpecialistAdapterError("authenticated session is stale")
    if not isinstance(adapter, SpecialistExecutionAdapter):
        raise SpecialistAdapterError("adapter does not implement the execution protocol")
    if request.operation not in adapter.identity.supported_operations:
        raise SpecialistAdapterError("adapter does not declare the requested operation")
    replay_guard.reserve(request)
    observation = adapter.execute(request)
    if not isinstance(observation, AdapterObservation):
        raise SpecialistAdapterError("adapter returned an invalid observation")
    expected = (
        request.request_id,
        request.request_sha256,
        request.context.context_sha256,
        request.idempotency_key,
    )
    actual = (
        observation.request_id,
        observation.request_sha256,
        observation.context_sha256,
        observation.idempotency_key,
    )
    if actual != expected:
        raise SpecialistAdapterError("adapter observation binding mismatch")
    observed = _instant(observation.observed_at)
    if not _instant(request.issued_at) <= observed <= now < _instant(request.expires_at):
        raise SpecialistAdapterError("adapter observation time is invalid")
    budget = request.budget
    if (
        observation.operations_performed > budget.max_operations
        or observation.request_bytes > budget.max_request_bytes
        or observation.response_bytes > budget.max_response_bytes
        or observation.redirect_count > budget.max_redirects
        or len(observation.evidence_refs) > budget.max_evidence_items
    ):
        raise SpecialistAdapterError("adapter observation exceeds the request budget")
    if not set(observation.evidence_refs).issuperset(request.evidence_refs):
        raise SpecialistAdapterError("adapter observation omits required evidence")
    return SpecialistActionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        context_sha256=request.context.context_sha256,
        adapter=adapter.identity,
        state=observation.state,
        operations_performed=observation.operations_performed,
        request_bytes=observation.request_bytes,
        response_bytes=observation.response_bytes,
        redirect_count=observation.redirect_count,
        evidence_refs=observation.evidence_refs,
        evidence_sha256=observation.evidence_sha256,
        observed_at=observation.observed_at,
    )


def parse_specialist_contract(
    raw: Mapping[str, Any],
) -> SpecialistActionRequest | SpecialistActionReceipt:
    """Parse a published request or receipt with runtime integrity checks."""

    if not isinstance(raw, Mapping):
        raise SpecialistAdapterError("contract must be a mapping")
    if raw.get("kind") == "specialist_action_request":
        return SpecialistActionRequest.from_dict(raw)
    if raw.get("kind") == "specialist_action_receipt":
        return SpecialistActionReceipt.from_dict(raw)
    raise SpecialistAdapterError("contract kind is invalid")


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if (
        raw.get("kind") != kind
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != SCHEMA_VERSION
    ):
        raise SpecialistAdapterError("contract metadata is invalid")
    if raw.get("effects") != dict(REPOSITORY_ONLY_EFFECTS):
        raise SpecialistAdapterError("contract effects are invalid")


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise SpecialistAdapterError(f"{label} fields are invalid")
    return dict(raw)


_REQUEST_FIELDS = {
    "approval",
    "budget",
    "context",
    "effects",
    "evidence_refs",
    "expires_at",
    "idempotency_key",
    "issued_at",
    "kind",
    "operation",
    "policy",
    "request_id",
    "request_sha256",
    "requested_tier",
    "schema_version",
    "sessions",
    "tool_input_ref",
    "tool_input_sha256",
}

_RECEIPT_FIELDS = {
    "adapter",
    "context_sha256",
    "effects",
    "evidence_refs",
    "evidence_sha256",
    "kind",
    "observed_at",
    "operations_performed",
    "receipt_id",
    "receipt_sha256",
    "redirect_count",
    "request_bytes",
    "request_id",
    "request_sha256",
    "response_bytes",
    "schema_version",
    "state",
}
