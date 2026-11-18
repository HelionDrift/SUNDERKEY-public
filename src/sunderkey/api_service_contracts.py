"""Deterministic external API and webhook contracts with no runtime effects.

The types in this module describe a service boundary. They do not run a server,
open a client connection, authorize a principal, schedule execution, deliver a
webhook, or resolve an endpoint, key, secret, evidence, finding, or report.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

SCHEMA_VERSION = 1

NO_EFFECTS = {
    "authorization": "external",
    "authority": "none",
    "client": "none",
    "delivery": "none",
    "execution": "none",
    "network": "none",
    "routing": "none",
    "scheduling": "none",
    "server": "none",
}

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
CURSOR_RE = re.compile(r"cursor:[A-Za-z0-9_-]{16,512}\Z")
REFERENCE_RE = re.compile(
    r"(?:evidref|findingref|reportref|scoperef|schedref|statusref|assessmentref):"
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z"
)
ENDPOINT_REF_RE = re.compile(r"endpointref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,243}\Z")
SECRET_REF_RE = re.compile(r"secretref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,245}\Z")
NONCE_RE = re.compile(r"nonce:[A-Za-z0-9_-]{22,128}\Z")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{43,684}\Z")


class ApiContractError(ValueError):
    """Raised when an API or webhook contract fails closed."""


class ApiOperation(StrEnum):
    """Closed external API operation vocabulary."""

    CREATE_ASSESSMENT = "create_assessment"
    ADMIT_SCOPE = "admit_scope"
    CREATE_SCHEDULE = "create_schedule"
    GET_STATUS = "get_status"
    LIST_EVIDENCE = "list_evidence"
    LIST_FINDINGS = "list_findings"
    GET_REPORT = "get_report"
    CANCEL_ASSESSMENT = "cancel_assessment"
    EMERGENCY_STOP = "emergency_stop"


class ResourceKind(StrEnum):
    """Resources exposed by reference through the service boundary."""

    ASSESSMENT = "assessment"
    SCOPE_ADMISSION = "scope_admission"
    SCHEDULE = "schedule"
    STATUS = "status"
    EVIDENCE = "evidence"
    FINDING = "finding"
    REPORT = "report"
    CANCELLATION = "cancellation"
    EMERGENCY_STOP = "emergency_stop"


class ResponseStatus(StrEnum):
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    REJECTED = "rejected"


class ErrorCode(StrEnum):
    """Stable, non-sensitive service error taxonomy."""

    AUTHENTICATION_REQUIRED = "authentication_required"
    AUTHORIZATION_EXTERNAL = "authorization_external"
    BODY_LIMIT_EXCEEDED = "body_limit_exceeded"
    CONFLICT = "conflict"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    INVALID_CURSOR = "invalid_cursor"
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    RATE_BUDGET_EXCEEDED = "rate_budget_exceeded"
    RESOURCE_VERSION_CONFLICT = "resource_version_conflict"
    SCOPE_NOT_ADMITTED = "scope_not_admitted"
    SERVICE_UNAVAILABLE = "service_unavailable"
    STOP_ALREADY_RECORDED = "stop_already_recorded"


class WebhookEventType(StrEnum):
    ASSESSMENT_CREATED = "assessment.created"
    SCOPE_ADMISSION_RECORDED = "scope_admission.recorded"
    SCHEDULE_CREATED = "schedule.created"
    STATUS_CHANGED = "status.changed"
    EVIDENCE_AVAILABLE = "evidence.available"
    FINDING_CHANGED = "finding.changed"
    REPORT_AVAILABLE = "report.available"
    ASSESSMENT_CANCELLED = "assessment.cancelled"
    EMERGENCY_STOP_RECORDED = "emergency_stop.recorded"


class DeliveryState(StrEnum):
    PLANNED = "planned"
    ATTEMPTED = "attempted"
    ACKNOWLEDGED = "acknowledged"
    DEAD_LETTERED = "dead_lettered"


MUTATING_OPERATIONS = frozenset(
    {
        ApiOperation.CREATE_ASSESSMENT,
        ApiOperation.ADMIT_SCOPE,
        ApiOperation.CREATE_SCHEDULE,
        ApiOperation.CANCEL_ASSESSMENT,
        ApiOperation.EMERGENCY_STOP,
    }
)
VERSION_REQUIRED_OPERATIONS = frozenset(
    {
        ApiOperation.CREATE_SCHEDULE,
        ApiOperation.CANCEL_ASSESSMENT,
        ApiOperation.EMERGENCY_STOP,
    }
)
PAGINATED_OPERATIONS = frozenset({ApiOperation.LIST_EVIDENCE, ApiOperation.LIST_FINDINGS})
RESOURCE_KIND_BY_OPERATION = {
    ApiOperation.CREATE_ASSESSMENT: ResourceKind.ASSESSMENT,
    ApiOperation.ADMIT_SCOPE: ResourceKind.SCOPE_ADMISSION,
    ApiOperation.CREATE_SCHEDULE: ResourceKind.SCHEDULE,
    ApiOperation.GET_STATUS: ResourceKind.STATUS,
    ApiOperation.LIST_EVIDENCE: ResourceKind.EVIDENCE,
    ApiOperation.LIST_FINDINGS: ResourceKind.FINDING,
    ApiOperation.GET_REPORT: ResourceKind.REPORT,
    ApiOperation.CANCEL_ASSESSMENT: ResourceKind.CANCELLATION,
    ApiOperation.EMERGENCY_STOP: ResourceKind.EMERGENCY_STOP,
}
REQUEST_REFERENCE_KINDS = {
    ApiOperation.CREATE_ASSESSMENT: frozenset({ResourceKind.SCOPE_ADMISSION}),
    ApiOperation.ADMIT_SCOPE: frozenset({ResourceKind.SCOPE_ADMISSION}),
    ApiOperation.CREATE_SCHEDULE: frozenset(
        {ResourceKind.ASSESSMENT, ResourceKind.SCOPE_ADMISSION}
    ),
}
REFERENCE_PREFIX_BY_KIND = {
    ResourceKind.ASSESSMENT: "assessmentref:",
    ResourceKind.SCOPE_ADMISSION: "scoperef:",
    ResourceKind.SCHEDULE: "schedref:",
    ResourceKind.STATUS: "statusref:",
    ResourceKind.EVIDENCE: "evidref:",
    ResourceKind.FINDING: "findingref:",
    ResourceKind.REPORT: "reportref:",
    ResourceKind.CANCELLATION: "statusref:",
    ResourceKind.EMERGENCY_STOP: "statusref:",
}
RESOURCE_KIND_BY_EVENT = {
    WebhookEventType.ASSESSMENT_CREATED: ResourceKind.ASSESSMENT,
    WebhookEventType.SCOPE_ADMISSION_RECORDED: ResourceKind.SCOPE_ADMISSION,
    WebhookEventType.SCHEDULE_CREATED: ResourceKind.SCHEDULE,
    WebhookEventType.STATUS_CHANGED: ResourceKind.STATUS,
    WebhookEventType.EVIDENCE_AVAILABLE: ResourceKind.EVIDENCE,
    WebhookEventType.FINDING_CHANGED: ResourceKind.FINDING,
    WebhookEventType.REPORT_AVAILABLE: ResourceKind.REPORT,
    WebhookEventType.ASSESSMENT_CANCELLED: ResourceKind.CANCELLATION,
    WebhookEventType.EMERGENCY_STOP_RECORDED: ResourceKind.EMERGENCY_STOP,
}


def canonical_json(value: Any) -> str:
    """Serialize bounded JSON deterministically as printable ASCII."""

    _validate_json(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ApiContractError("value cannot be canonicalized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _canonical_document(document: str, label: str) -> Any:
    try:
        raw = json.loads(document)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ApiContractError(f"{label} is not valid JSON") from exc
    if canonical_json(raw) != document:
        raise ApiContractError(f"{label} JSON is not canonical")
    return raw


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(
    value: Any, label: str, *, depth: int = 0, items: list[int] | None = None
) -> None:
    if depth > 12:
        raise ApiContractError(f"{label} exceeds the nesting limit")
    counter = [0] if items is None else items
    counter[0] += 1
    if counter[0] > 20_000:
        raise ApiContractError(f"{label} exceeds the item limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ApiContractError(f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1, items=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ApiContractError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1, items=counter)
        return
    raise ApiContractError(f"{label} contains an unsupported value")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise ApiContractError(f"{label} must be a safe identifier")
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise ApiContractError(f"{label} must be a token")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ApiContractError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ApiContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ApiContractError(f"{label} is not a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _text(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ApiContractError(f"{label} must be bounded non-empty text")
    if any(ord(character) < 32 for character in value):
        raise ApiContractError(f"{label} contains control characters")
    return value


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ApiContractError(f"{label} is outside its allowed range")
    return value


def _non_negative(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ApiContractError(f"{label} is outside its allowed range")
    return value


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ApiContractError(f"{label} fields are invalid")
    return raw


def _list(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ApiContractError(f"{label} must be an array")
    return raw


def _no_effects(raw: Any) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != NO_EFFECTS:
        raise ApiContractError("contract attempts effect escalation")


@dataclass(frozen=True)
class TenantPrincipalBinding:
    """Identity context asserted by an external authentication layer."""

    tenant_id: str
    principal_id: str
    principal_role: str
    authentication_context_ref: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "principal_id", "authentication_context_ref"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "principal_role", _token(self.principal_role, "principal_role"))

    def to_dict(self) -> dict[str, str]:
        return {
            "authentication_context_ref": self.authentication_context_ref,
            "principal_id": self.principal_id,
            "principal_role": self.principal_role,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TenantPrincipalBinding:
        _exact(
            raw,
            {"authentication_context_ref", "principal_id", "principal_role", "tenant_id"},
            "tenant principal binding",
        )
        return cls(**raw)


@dataclass(frozen=True)
class RequestBudget:
    """Caller-visible request and collection ceilings."""

    max_body_bytes: int
    max_reference_count: int
    max_page_size: int
    max_requests_per_minute: int

    def __post_init__(self) -> None:
        _positive(self.max_body_bytes, "max_body_bytes", 10_000_000)
        _positive(self.max_reference_count, "max_reference_count", 10_000)
        _positive(self.max_page_size, "max_page_size", 1_000)
        _positive(self.max_requests_per_minute, "max_requests_per_minute", 100_000)

    def to_dict(self) -> dict[str, int]:
        return {
            "max_body_bytes": self.max_body_bytes,
            "max_page_size": self.max_page_size,
            "max_reference_count": self.max_reference_count,
            "max_requests_per_minute": self.max_requests_per_minute,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RequestBudget:
        _exact(
            raw,
            {
                "max_body_bytes",
                "max_page_size",
                "max_reference_count",
                "max_requests_per_minute",
            },
            "request budget",
        )
        return cls(**raw)


@dataclass(frozen=True)
class PageRequest:
    size: int
    cursor: str | None = None

    def __post_init__(self) -> None:
        _positive(self.size, "page size", 1_000)
        if self.cursor is not None and (
            not isinstance(self.cursor, str) or CURSOR_RE.fullmatch(self.cursor) is None
        ):
            raise ApiContractError("cursor is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {"cursor": self.cursor, "size": self.size}

    @classmethod
    def from_dict(cls, raw: Any) -> PageRequest:
        _exact(raw, {"cursor", "size"}, "page request")
        return cls(**raw)


@dataclass(frozen=True)
class PageResult:
    returned_count: int
    next_cursor: str | None = None

    def __post_init__(self) -> None:
        _non_negative(self.returned_count, "returned_count", 1_000)
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str) or CURSOR_RE.fullmatch(self.next_cursor) is None
        ):
            raise ApiContractError("next_cursor is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {"next_cursor": self.next_cursor, "returned_count": self.returned_count}

    @classmethod
    def from_dict(cls, raw: Any) -> PageResult:
        _exact(raw, {"next_cursor", "returned_count"}, "page result")
        return cls(**raw)


@dataclass(frozen=True)
class ResourceReference:
    """Opaque content-addressed resource reference."""

    kind: ResourceKind | str
    reference: str
    content_sha256: str
    resource_version: int

    def __post_init__(self) -> None:
        try:
            kind = ResourceKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise ApiContractError("resource kind is invalid") from exc
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.reference, str) or REFERENCE_RE.fullmatch(self.reference) is None:
            raise ApiContractError("resource reference is invalid")
        if not self.reference.startswith(REFERENCE_PREFIX_BY_KIND[kind]):
            raise ApiContractError("resource reference prefix does not match its kind")
        object.__setattr__(self, "content_sha256", _digest(self.content_sha256, "content_sha256"))
        _positive(self.resource_version, "resource_version", 2_147_483_647)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_sha256": self.content_sha256,
            "kind": self.kind.value,
            "reference": self.reference,
            "resource_version": self.resource_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ResourceReference:
        _exact(raw, {"content_sha256", "kind", "reference", "resource_version"}, "resource")
        return cls(**raw)


@dataclass(frozen=True)
class ApiError:
    code: ErrorCode | str
    message: str
    retryable: bool
    detail_ref: str | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "code", ErrorCode(self.code))
        except (TypeError, ValueError) as exc:
            raise ApiContractError("error code is invalid") from exc
        object.__setattr__(self, "message", _text(self.message, "error message", 256))
        if not isinstance(self.retryable, bool):
            raise ApiContractError("retryable must be boolean")
        if self.detail_ref is not None:
            object.__setattr__(self, "detail_ref", _identifier(self.detail_ref, "detail_ref"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "detail_ref": self.detail_ref,
            "message": self.message,
            "retryable": self.retryable,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ApiError:
        _exact(raw, {"code", "detail_ref", "message", "retryable"}, "API error")
        return cls(**raw)


@dataclass(frozen=True)
class ApiRequestEnvelope:
    """Versioned request envelope for all external API operations."""

    operation: ApiOperation | str
    request_id: str
    binding: TenantPrincipalBinding
    issued_at: str
    body_size_bytes: int
    budget: RequestBudget
    resource_id: str | None = None
    content_references: tuple[ResourceReference, ...] = ()
    idempotency_key: str | None = None
    expected_resource_version: int | None = None
    page: PageRequest | None = None
    reason_code: str | None = None
    request_contract_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.api-request.v1"

    def __post_init__(self) -> None:
        try:
            operation = ApiOperation(self.operation)
        except (TypeError, ValueError) as exc:
            raise ApiContractError("API operation is invalid") from exc
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "request_id", _identifier(self.request_id, "request_id"))
        if not isinstance(self.binding, TenantPrincipalBinding):
            raise ApiContractError("binding must be TenantPrincipalBinding")
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "issued_at"))
        _non_negative(self.body_size_bytes, "body_size_bytes", 10_000_000)
        if not isinstance(self.budget, RequestBudget):
            raise ApiContractError("budget must be RequestBudget")
        if self.body_size_bytes > self.budget.max_body_bytes:
            raise ApiContractError("request body exceeds its budget")
        if self.resource_id is not None:
            object.__setattr__(self, "resource_id", _identifier(self.resource_id, "resource_id"))
        if not isinstance(self.content_references, tuple) or not all(
            isinstance(item, ResourceReference) for item in self.content_references
        ):
            raise ApiContractError("content_references must contain ResourceReference values")
        references = tuple(sorted(self.content_references, key=lambda item: item.reference))
        if len(references) != len({item.reference for item in references}):
            raise ApiContractError("content references must be unique")
        if len(references) > self.budget.max_reference_count:
            raise ApiContractError("content reference count exceeds its budget")
        object.__setattr__(self, "content_references", references)
        if operation in MUTATING_OPERATIONS:
            if (
                not isinstance(self.idempotency_key, str)
                or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
            ):
                raise ApiContractError("mutating operation requires an idempotency key")
        elif self.idempotency_key is not None:
            raise ApiContractError("read operation must not carry an idempotency key")
        if operation in VERSION_REQUIRED_OPERATIONS:
            _positive(
                self.expected_resource_version,
                "expected_resource_version",
                2_147_483_647,
            )
        elif self.expected_resource_version is not None:
            raise ApiContractError("operation does not accept expected_resource_version")
        if operation in PAGINATED_OPERATIONS:
            if not isinstance(self.page, PageRequest):
                raise ApiContractError("list operation requires pagination")
            if self.page.size > self.budget.max_page_size:
                raise ApiContractError("requested page exceeds its budget")
        elif self.page is not None:
            raise ApiContractError("operation does not accept pagination")
        if operation in {ApiOperation.CANCEL_ASSESSMENT, ApiOperation.EMERGENCY_STOP}:
            if self.reason_code is None:
                raise ApiContractError("control operation requires reason_code")
            object.__setattr__(self, "reason_code", _token(self.reason_code, "reason_code"))
        elif self.reason_code is not None:
            raise ApiContractError("operation does not accept reason_code")
        if operation is ApiOperation.CREATE_ASSESSMENT:
            if self.resource_id is not None or not references:
                raise ApiContractError("create_assessment requires references and no resource_id")
        elif self.resource_id is None:
            raise ApiContractError("operation requires resource_id")
        allowed_reference_kinds = REQUEST_REFERENCE_KINDS.get(operation, frozenset())
        if references and any(item.kind not in allowed_reference_kinds for item in references):
            raise ApiContractError("reference kind does not match operation")
        if operation in REQUEST_REFERENCE_KINDS and not references:
            raise ApiContractError("operation requires content references")
        request_id, digest = _identity("ASR", self.KIND, self._body())
        object.__setattr__(self, "request_contract_id", request_id)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "body_size_bytes": self.body_size_bytes,
            "budget": self.budget.to_dict(),
            "content_references": [item.to_dict() for item in self.content_references],
            "expected_resource_version": self.expected_resource_version,
            "idempotency_key": self.idempotency_key,
            "issued_at": self.issued_at,
            "operation": self.operation.value,
            "page": None if self.page is None else self.page.to_dict(),
            "reason_code": self.reason_code,
            "request_id": self.request_id,
            "resource_id": self.resource_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "request_contract_id": self.request_contract_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> ApiRequestEnvelope:
        fields = {
            "binding",
            "body_size_bytes",
            "budget",
            "content_references",
            "effects",
            "expected_resource_version",
            "idempotency_key",
            "issued_at",
            "kind",
            "operation",
            "page",
            "reason_code",
            "request_contract_id",
            "request_id",
            "request_sha256",
            "resource_id",
            "schema_version",
        }
        _exact(raw, fields, "API request")
        _no_effects(raw["effects"])
        if (
            raw["kind"] != cls.KIND
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != SCHEMA_VERSION
        ):
            raise ApiContractError("API request kind or version is invalid")
        candidate = cls(
            operation=raw["operation"],
            request_id=raw["request_id"],
            binding=TenantPrincipalBinding.from_dict(raw["binding"]),
            issued_at=raw["issued_at"],
            body_size_bytes=raw["body_size_bytes"],
            budget=RequestBudget.from_dict(raw["budget"]),
            resource_id=raw["resource_id"],
            content_references=tuple(
                ResourceReference.from_dict(item)
                for item in _list(raw["content_references"], "content_references")
            ),
            idempotency_key=raw["idempotency_key"],
            expected_resource_version=raw["expected_resource_version"],
            page=None if raw["page"] is None else PageRequest.from_dict(raw["page"]),
            reason_code=raw["reason_code"],
        )
        if candidate.to_dict() != dict(raw):
            raise ApiContractError("API request identity or contents are invalid")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> ApiRequestEnvelope:
        return cls.from_dict(_canonical_document(document, "API request"))


@dataclass(frozen=True)
class ApiResponseEnvelope:
    """Versioned response envelope containing references, never execution results."""

    operation: ApiOperation | str
    request_contract_id: str
    request_sha256: str
    binding: TenantPrincipalBinding
    responded_at: str
    status: ResponseStatus | str
    resources: tuple[ResourceReference, ...] = ()
    page: PageResult | None = None
    error: ApiError | None = None
    response_contract_id: str = field(init=False)
    response_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.api-response.v1"

    def __post_init__(self) -> None:
        try:
            operation = ApiOperation(self.operation)
            status = ResponseStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ApiContractError("response operation or status is invalid") from exc
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "status", status)
        object.__setattr__(
            self,
            "request_contract_id",
            _identifier(self.request_contract_id, "request_contract_id"),
        )
        object.__setattr__(self, "request_sha256", _digest(self.request_sha256, "request_sha256"))
        if not isinstance(self.binding, TenantPrincipalBinding):
            raise ApiContractError("binding must be TenantPrincipalBinding")
        object.__setattr__(self, "responded_at", _timestamp(self.responded_at, "responded_at"))
        if not isinstance(self.resources, tuple) or not all(
            isinstance(item, ResourceReference) for item in self.resources
        ):
            raise ApiContractError("resources must contain ResourceReference values")
        resources = tuple(sorted(self.resources, key=lambda item: item.reference))
        if len(resources) != len({item.reference for item in resources}):
            raise ApiContractError("response resources must be unique")
        if len(resources) > 1_000:
            raise ApiContractError("response resources exceed the schema limit")
        object.__setattr__(self, "resources", resources)
        if status is ResponseStatus.REJECTED:
            if self.error is None or resources or self.page is not None:
                raise ApiContractError("rejected response requires only an error")
        else:
            if self.error is not None:
                raise ApiContractError("successful response cannot carry an error")
            if operation not in PAGINATED_OPERATIONS and not resources:
                raise ApiContractError("non-list success requires a resource")
            expected = RESOURCE_KIND_BY_OPERATION[operation]
            if any(item.kind is not expected for item in resources):
                raise ApiContractError("response resource kind does not match operation")
            if operation in PAGINATED_OPERATIONS:
                if not isinstance(self.page, PageResult):
                    raise ApiContractError("list response requires pagination")
                if self.page.returned_count != len(resources):
                    raise ApiContractError("page returned_count does not match resources")
            elif self.page is not None:
                raise ApiContractError("non-list response must not carry pagination")
        response_id, digest = _identity("ASP", self.KIND, self._body())
        object.__setattr__(self, "response_contract_id", response_id)
        object.__setattr__(self, "response_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "error": None if self.error is None else self.error.to_dict(),
            "operation": self.operation.value,
            "page": None if self.page is None else self.page.to_dict(),
            "request_contract_id": self.request_contract_id,
            "request_sha256": self.request_sha256,
            "resources": [item.to_dict() for item in self.resources],
            "responded_at": self.responded_at,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "response_contract_id": self.response_contract_id,
            "response_sha256": self.response_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> ApiResponseEnvelope:
        fields = {
            "binding",
            "effects",
            "error",
            "kind",
            "operation",
            "page",
            "request_contract_id",
            "request_sha256",
            "resources",
            "responded_at",
            "response_contract_id",
            "response_sha256",
            "schema_version",
            "status",
        }
        _exact(raw, fields, "API response")
        _no_effects(raw["effects"])
        if (
            raw["kind"] != cls.KIND
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != SCHEMA_VERSION
        ):
            raise ApiContractError("API response kind or version is invalid")
        candidate = cls(
            operation=raw["operation"],
            request_contract_id=raw["request_contract_id"],
            request_sha256=raw["request_sha256"],
            binding=TenantPrincipalBinding.from_dict(raw["binding"]),
            responded_at=raw["responded_at"],
            status=raw["status"],
            resources=tuple(
                ResourceReference.from_dict(item)
                for item in _list(raw["resources"], "response resources")
            ),
            page=None if raw["page"] is None else PageResult.from_dict(raw["page"]),
            error=None if raw["error"] is None else ApiError.from_dict(raw["error"]),
        )
        if candidate.to_dict() != dict(raw):
            raise ApiContractError("API response identity or contents are invalid")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> ApiResponseEnvelope:
        return cls.from_dict(_canonical_document(document, "API response"))


@dataclass(frozen=True)
class DetachedSignature:
    """Detached signature material without signing key contents."""

    key_ref: str
    algorithm: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.key_ref, str) or SECRET_REF_RE.fullmatch(self.key_ref) is None:
            raise ApiContractError("signature key_ref must be an opaque secret reference")
        if self.algorithm not in {"ed25519", "ecdsa_p256_sha256"}:
            raise ApiContractError("signature algorithm is invalid")
        if not isinstance(self.signature, str) or SIGNATURE_RE.fullmatch(self.signature) is None:
            raise ApiContractError("detached signature is invalid")
        try:
            base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
        except (ValueError, binascii.Error) as exc:
            raise ApiContractError("detached signature is not base64url") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_ref": self.key_ref,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DetachedSignature:
        _exact(raw, {"algorithm", "key_ref", "signature"}, "detached signature")
        return cls(**raw)


@dataclass(frozen=True)
class RetryPlan:
    """Bounded retry schedule metadata with no timer or delivery effect."""

    delays_seconds: tuple[int, ...]
    dead_letter_after_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.delays_seconds, tuple) or not self.delays_seconds:
            raise ApiContractError("retry plan requires delays")
        if len(self.delays_seconds) > 10:
            raise ApiContractError("retry plan exceeds attempt limit")
        previous = 0
        for delay in self.delays_seconds:
            _positive(delay, "retry delay", 86_400)
            if delay <= previous:
                raise ApiContractError("retry delays must strictly increase")
            previous = delay
        if self.dead_letter_after_attempts != len(self.delays_seconds) + 1:
            raise ApiContractError("dead-letter count must include the initial attempt")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dead_letter_after_attempts": self.dead_letter_after_attempts,
            "delays_seconds": list(self.delays_seconds),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetryPlan:
        _exact(raw, {"dead_letter_after_attempts", "delays_seconds"}, "retry plan")
        return cls(
            tuple(_list(raw["delays_seconds"], "retry delays")),
            raw["dead_letter_after_attempts"],
        )


def _events(values: Sequence[WebhookEventType | str]) -> tuple[WebhookEventType, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise ApiContractError("event filters must be a non-empty sequence")
    try:
        result = tuple(
            sorted((WebhookEventType(item) for item in values), key=lambda item: item.value)
        )
    except (TypeError, ValueError) as exc:
        raise ApiContractError("event filter is invalid") from exc
    if len(result) != len(set(result)):
        raise ApiContractError("event filters must be unique")
    return result


@dataclass(frozen=True)
class WebhookSubscription:
    """Signed subscription declaration using endpoint and key references only."""

    subscription_id: str
    binding: TenantPrincipalBinding
    endpoint_ref: str
    signing_key_ref: str
    event_filters: tuple[WebhookEventType | str, ...]
    max_in_flight: int
    created_at: str
    signature: DetachedSignature
    subscription_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.webhook-subscription.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "subscription_id", _identifier(self.subscription_id, "subscription_id")
        )
        if not isinstance(self.binding, TenantPrincipalBinding):
            raise ApiContractError("subscription binding is invalid")
        if (
            not isinstance(self.endpoint_ref, str)
            or ENDPOINT_REF_RE.fullmatch(self.endpoint_ref) is None
        ):
            raise ApiContractError("endpoint_ref is invalid")
        if (
            not isinstance(self.signing_key_ref, str)
            or SECRET_REF_RE.fullmatch(self.signing_key_ref) is None
        ):
            raise ApiContractError("signing_key_ref must be an opaque secret reference")
        object.__setattr__(self, "event_filters", _events(self.event_filters))
        _positive(self.max_in_flight, "max_in_flight", 1_000)
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        if not isinstance(self.signature, DetachedSignature):
            raise ApiContractError("subscription signature is invalid")
        if self.signature.key_ref != self.signing_key_ref:
            raise ApiContractError("subscription signature key does not match signing_key_ref")
        object.__setattr__(self, "subscription_sha256", canonical_sha256(self._unsigned_body()))

    def _unsigned_body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "created_at": self.created_at,
            "endpoint_ref": self.endpoint_ref,
            "event_filters": [item.value for item in self.event_filters],
            "max_in_flight": self.max_in_flight,
            "signing_key_ref": self.signing_key_ref,
            "subscription_id": self.subscription_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_body(),
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "signature": self.signature.to_dict(),
            "subscription_sha256": self.subscription_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> WebhookSubscription:
        fields = {
            "binding",
            "created_at",
            "effects",
            "endpoint_ref",
            "event_filters",
            "kind",
            "max_in_flight",
            "schema_version",
            "signature",
            "signing_key_ref",
            "subscription_id",
            "subscription_sha256",
        }
        _exact(raw, fields, "webhook subscription")
        _no_effects(raw["effects"])
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise ApiContractError("subscription kind or version is invalid")
        candidate = cls(
            subscription_id=raw["subscription_id"],
            binding=TenantPrincipalBinding.from_dict(raw["binding"]),
            endpoint_ref=raw["endpoint_ref"],
            signing_key_ref=raw["signing_key_ref"],
            event_filters=tuple(_list(raw["event_filters"], "event_filters")),
            max_in_flight=raw["max_in_flight"],
            created_at=raw["created_at"],
            signature=DetachedSignature.from_dict(raw["signature"]),
        )
        if candidate.to_dict() != dict(raw):
            raise ApiContractError("subscription hash or contents are invalid")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> WebhookSubscription:
        return cls.from_dict(_canonical_document(document, "webhook subscription"))


@dataclass(frozen=True)
class WebhookDelivery:
    """Signed event delivery record with sequence and replay bindings."""

    delivery_id: str
    subscription_id: str
    subscription_sha256: str
    sequence: int
    nonce: str
    event_type: WebhookEventType | str
    resource: ResourceReference
    occurred_at: str
    expires_at: str
    attempt: int
    state: DeliveryState | str
    retry_plan: RetryPlan
    signature: DetachedSignature
    delivery_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.webhook-delivery.v1"

    def __post_init__(self) -> None:
        for name in ("delivery_id", "subscription_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(
            self, "subscription_sha256", _digest(self.subscription_sha256, "subscription_sha256")
        )
        _positive(self.sequence, "delivery sequence", 9_223_372_036_854_775_807)
        if not isinstance(self.nonce, str) or NONCE_RE.fullmatch(self.nonce) is None:
            raise ApiContractError("delivery nonce is invalid")
        try:
            event_type = WebhookEventType(self.event_type)
            state = DeliveryState(self.state)
        except (TypeError, ValueError) as exc:
            raise ApiContractError("delivery event type or state is invalid") from exc
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "state", state)
        if not isinstance(self.resource, ResourceReference):
            raise ApiContractError("delivery resource is invalid")
        if self.resource.kind is not RESOURCE_KIND_BY_EVENT[event_type]:
            raise ApiContractError("delivery resource kind does not match its event type")
        object.__setattr__(self, "occurred_at", _timestamp(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.occurred_at):
            raise ApiContractError("delivery expiry must follow occurrence")
        _positive(self.attempt, "delivery attempt", 11)
        if not isinstance(self.retry_plan, RetryPlan):
            raise ApiContractError("retry_plan is invalid")
        if self.attempt > self.retry_plan.dead_letter_after_attempts:
            raise ApiContractError("attempt exceeds retry plan")
        if state is DeliveryState.DEAD_LETTERED and (
            self.attempt != self.retry_plan.dead_letter_after_attempts
        ):
            raise ApiContractError("dead-letter state requires the terminal attempt")
        if state is DeliveryState.ACKNOWLEDGED:
            raise ApiContractError("delivery cannot self-assert acknowledgement")
        if not isinstance(self.signature, DetachedSignature):
            raise ApiContractError("delivery signature is invalid")
        object.__setattr__(self, "delivery_sha256", canonical_sha256(self._unsigned_body()))

    def _unsigned_body(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "delivery_id": self.delivery_id,
            "event_type": self.event_type.value,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "occurred_at": self.occurred_at,
            "resource": self.resource.to_dict(),
            "retry_plan": self.retry_plan.to_dict(),
            "sequence": self.sequence,
            "state": self.state.value,
            "subscription_id": self.subscription_id,
            "subscription_sha256": self.subscription_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_body(),
            "delivery_sha256": self.delivery_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "signature": self.signature.to_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> WebhookDelivery:
        fields = {
            "attempt",
            "delivery_id",
            "delivery_sha256",
            "effects",
            "event_type",
            "expires_at",
            "kind",
            "nonce",
            "occurred_at",
            "resource",
            "retry_plan",
            "schema_version",
            "sequence",
            "signature",
            "state",
            "subscription_id",
            "subscription_sha256",
        }
        _exact(raw, fields, "webhook delivery")
        _no_effects(raw["effects"])
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise ApiContractError("delivery kind or version is invalid")
        candidate = cls(
            delivery_id=raw["delivery_id"],
            subscription_id=raw["subscription_id"],
            subscription_sha256=raw["subscription_sha256"],
            sequence=raw["sequence"],
            nonce=raw["nonce"],
            event_type=raw["event_type"],
            resource=ResourceReference.from_dict(raw["resource"]),
            occurred_at=raw["occurred_at"],
            expires_at=raw["expires_at"],
            attempt=raw["attempt"],
            state=raw["state"],
            retry_plan=RetryPlan.from_dict(raw["retry_plan"]),
            signature=DetachedSignature.from_dict(raw["signature"]),
        )
        if candidate.to_dict() != dict(raw):
            raise ApiContractError("delivery hash or contents are invalid")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> WebhookDelivery:
        return cls.from_dict(_canonical_document(document, "webhook delivery"))


@dataclass(frozen=True)
class WebhookAcknowledgement:
    """Signed acknowledgement bound to one exact delivery."""

    acknowledgement_id: str
    subscription_id: str
    delivery_id: str
    delivery_sha256: str
    sequence: int
    acknowledged_at: str
    signature: DetachedSignature
    acknowledgement_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.webhook-acknowledgement.v1"

    def __post_init__(self) -> None:
        for name in ("acknowledgement_id", "subscription_id", "delivery_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(
            self, "delivery_sha256", _digest(self.delivery_sha256, "delivery_sha256")
        )
        _positive(self.sequence, "acknowledgement sequence", 9_223_372_036_854_775_807)
        object.__setattr__(
            self, "acknowledged_at", _timestamp(self.acknowledged_at, "acknowledged_at")
        )
        if not isinstance(self.signature, DetachedSignature):
            raise ApiContractError("acknowledgement signature is invalid")
        object.__setattr__(self, "acknowledgement_sha256", canonical_sha256(self._unsigned_body()))

    def _unsigned_body(self) -> dict[str, Any]:
        return {
            "acknowledged_at": self.acknowledged_at,
            "acknowledgement_id": self.acknowledgement_id,
            "delivery_id": self.delivery_id,
            "delivery_sha256": self.delivery_sha256,
            "sequence": self.sequence,
            "subscription_id": self.subscription_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_body(),
            "acknowledgement_sha256": self.acknowledgement_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "signature": self.signature.to_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> WebhookAcknowledgement:
        fields = {
            "acknowledged_at",
            "acknowledgement_id",
            "acknowledgement_sha256",
            "delivery_id",
            "delivery_sha256",
            "effects",
            "kind",
            "schema_version",
            "sequence",
            "signature",
            "subscription_id",
        }
        _exact(raw, fields, "webhook acknowledgement")
        _no_effects(raw["effects"])
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise ApiContractError("acknowledgement kind or version is invalid")
        candidate = cls(
            acknowledgement_id=raw["acknowledgement_id"],
            subscription_id=raw["subscription_id"],
            delivery_id=raw["delivery_id"],
            delivery_sha256=raw["delivery_sha256"],
            sequence=raw["sequence"],
            acknowledged_at=raw["acknowledged_at"],
            signature=DetachedSignature.from_dict(raw["signature"]),
        )
        if candidate.to_dict() != dict(raw):
            raise ApiContractError("acknowledgement hash or contents are invalid")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> WebhookAcknowledgement:
        return cls.from_dict(_canonical_document(document, "webhook acknowledgement"))


@dataclass(frozen=True)
class ReplayWindow:
    """Immutable receiver state for contiguous delivery replay rejection."""

    subscription_id: str
    last_sequence: int
    delivery_ids: tuple[str, ...] = ()
    nonces: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "subscription_id", _identifier(self.subscription_id, "subscription_id")
        )
        _non_negative(self.last_sequence, "last_sequence", 9_223_372_036_854_775_807)
        for name in ("delivery_ids", "nonces"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > 10_000:
                raise ApiContractError(f"{name} is invalid")
            if len(values) != len(set(values)):
                raise ApiContractError(f"{name} contains duplicates")
        for delivery_id in self.delivery_ids:
            _identifier(delivery_id, "replay delivery_id")
        for nonce in self.nonces:
            if NONCE_RE.fullmatch(nonce) is None:
                raise ApiContractError("replay nonce is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_ids": list(self.delivery_ids),
            "last_sequence": self.last_sequence,
            "nonces": list(self.nonces),
            "subscription_id": self.subscription_id,
        }


def accept_webhook_delivery(
    subscription: WebhookSubscription,
    delivery: WebhookDelivery,
    window: ReplayWindow,
    *,
    received_at: str,
) -> ReplayWindow:
    """Validate a delivery against immutable replay state and return new state."""

    if not isinstance(subscription, WebhookSubscription):
        raise ApiContractError("subscription is invalid")
    if not isinstance(delivery, WebhookDelivery):
        raise ApiContractError("delivery is invalid")
    if not isinstance(window, ReplayWindow):
        raise ApiContractError("replay window is invalid")
    received = _timestamp(received_at, "received_at")
    if delivery.subscription_id != subscription.subscription_id:
        raise ApiContractError("delivery subscription_id does not match")
    if delivery.subscription_sha256 != subscription.subscription_sha256:
        raise ApiContractError("delivery subscription hash does not match")
    if window.subscription_id != subscription.subscription_id:
        raise ApiContractError("replay window subscription does not match")
    if delivery.event_type not in subscription.event_filters:
        raise ApiContractError("delivery event is not allowed by the subscription")
    if delivery.signature.key_ref != subscription.signing_key_ref:
        raise ApiContractError("delivery signature key does not match the subscription")
    if delivery.sequence != window.last_sequence + 1:
        raise ApiContractError("delivery sequence is not contiguous")
    if delivery.delivery_id in window.delivery_ids or delivery.nonce in window.nonces:
        raise ApiContractError("delivery is a replay")
    if _instant(received) < _instant(delivery.occurred_at):
        raise ApiContractError("delivery was received before its occurrence")
    if _instant(received) > _instant(delivery.expires_at):
        raise ApiContractError("delivery has expired")
    return ReplayWindow(
        subscription_id=window.subscription_id,
        last_sequence=delivery.sequence,
        delivery_ids=(*window.delivery_ids, delivery.delivery_id)[-10_000:],
        nonces=(*window.nonces, delivery.nonce)[-10_000:],
    )


def verify_api_exchange(request: ApiRequestEnvelope, response: ApiResponseEnvelope) -> None:
    """Verify that one response is bound to an exact request and its budgets."""

    if not isinstance(request, ApiRequestEnvelope) or not isinstance(response, ApiResponseEnvelope):
        raise ApiContractError("API exchange inputs are invalid")
    try:
        request = ApiRequestEnvelope.from_dict(request.to_dict())
        response = ApiResponseEnvelope.from_dict(response.to_dict())
    except (ApiContractError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ApiContractError("API exchange source integrity is invalid") from exc
    if (
        response.operation is not request.operation
        or response.request_contract_id != request.request_contract_id
        or response.request_sha256 != request.request_sha256
        or response.binding != request.binding
    ):
        raise ApiContractError("API response does not match its request")
    if _instant(response.responded_at) < _instant(request.issued_at):
        raise ApiContractError("API response precedes its request")
    if len(response.resources) > request.budget.max_reference_count:
        raise ApiContractError("API response reference count exceeds request budget")
    if response.page is not None:
        if request.page is None:
            raise ApiContractError("API response page was not requested")
        if response.page.returned_count > request.page.size:
            raise ApiContractError("API response page exceeds requested size")


def verify_webhook_acknowledgement(
    subscription: WebhookSubscription,
    delivery: WebhookDelivery,
    acknowledgement: WebhookAcknowledgement,
) -> None:
    """Verify acknowledgement bindings without changing delivery state."""

    if not all(
        isinstance(item, expected)
        for item, expected in (
            (subscription, WebhookSubscription),
            (delivery, WebhookDelivery),
            (acknowledgement, WebhookAcknowledgement),
        )
    ):
        raise ApiContractError("webhook acknowledgement inputs are invalid")
    if (
        acknowledgement.subscription_id != subscription.subscription_id
        or delivery.subscription_id != subscription.subscription_id
        or delivery.subscription_sha256 != subscription.subscription_sha256
        or acknowledgement.delivery_id != delivery.delivery_id
        or acknowledgement.delivery_sha256 != delivery.delivery_sha256
        or acknowledgement.sequence != delivery.sequence
    ):
        raise ApiContractError("acknowledgement binding does not match delivery")
    if acknowledgement.signature.key_ref != subscription.signing_key_ref:
        raise ApiContractError("acknowledgement signature key does not match subscription")
    if _instant(acknowledgement.acknowledged_at) < _instant(delivery.occurred_at):
        raise ApiContractError("acknowledgement precedes delivery occurrence")


def parse_contract(raw: Any) -> Any:
    """Parse one strict published contract by its closed kind value."""

    if not isinstance(raw, Mapping):
        raise ApiContractError("contract must be an object")
    parser = {
        ApiRequestEnvelope.KIND: ApiRequestEnvelope.from_dict,
        ApiResponseEnvelope.KIND: ApiResponseEnvelope.from_dict,
        WebhookSubscription.KIND: WebhookSubscription.from_dict,
        WebhookDelivery.KIND: WebhookDelivery.from_dict,
        WebhookAcknowledgement.KIND: WebhookAcknowledgement.from_dict,
    }.get(raw.get("kind"))
    if parser is None:
        raise ApiContractError("contract kind is unsupported")
    return parser(raw)


__all__ = [
    "NO_EFFECTS",
    "ApiContractError",
    "ApiError",
    "ApiOperation",
    "ApiRequestEnvelope",
    "ApiResponseEnvelope",
    "DeliveryState",
    "DetachedSignature",
    "ErrorCode",
    "PageRequest",
    "PageResult",
    "ReplayWindow",
    "RequestBudget",
    "ResourceKind",
    "ResourceReference",
    "ResponseStatus",
    "RetryPlan",
    "TenantPrincipalBinding",
    "WebhookAcknowledgement",
    "WebhookDelivery",
    "WebhookEventType",
    "WebhookSubscription",
    "accept_webhook_delivery",
    "canonical_json",
    "canonical_sha256",
    "parse_contract",
    "verify_api_exchange",
    "verify_webhook_acknowledgement",
]
