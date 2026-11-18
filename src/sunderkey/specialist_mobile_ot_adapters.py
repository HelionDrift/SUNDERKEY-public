"""Fail-closed contracts for mobile, desktop, wireless, IoT, and OT adapters.

The module contains declarations, deterministic requests, injected adapter
observations, and receipts. It contains no exploit payload, radio transmitter,
device command, process runner, network client, or autonomous action loop.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Protocol

SCHEMA_VERSION = 1
MAX_WINDOW_SECONDS = 86_400

BOUNDARY_EFFECTS = MappingProxyType(
    {
        "autonomous_execution": "none",
        "builtin_device_commands": "none",
        "builtin_exploit_payloads": "none",
        "builtin_network": "none",
        "builtin_process_execution": "none",
        "builtin_radio_transmission": "none",
        "injected_adapter_invocation": "caller_supplied_only",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|scoperef|targetref|protocolref|deviceref|"
    r"sessionref|evidenceref|budgetref|restorationref|approvalref|actorref|"
    r"capabilityref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}|"
    r"\b(?:password|passwd|secret|access_token|refresh_token|id_token|otp)"
    r"\s*[:=]\s*[^,}\s]+|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)


class SpecialistBoundaryError(ValueError):
    """Raised when the specialist boundary rejects a contract."""


class SpecialistDomain(StrEnum):
    MOBILE = "mobile"
    DESKTOP_CLIENT = "desktop_client"
    WIRELESS = "wireless"
    EMBEDDED_IOT = "embedded_iot"
    OT_ICS = "ot_ics"


class EnvironmentClass(StrEnum):
    SIMULATION = "simulation"
    LAB = "lab"
    STAGING = "staging"
    PRODUCTION = "production"


class SystemCriticality(StrEnum):
    STANDARD = "standard"
    BUSINESS_CRITICAL = "business_critical"
    SAFETY_CRITICAL = "safety_critical"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"


class ActionClass(StrEnum):
    PASSIVE = "passive"
    AUTHENTICATED_READ = "authenticated_read"
    VALIDATION = "validation"
    CONTROLLED_CHANGE = "controlled_change"
    DISRUPTIVE = "disruptive"


class ActionTier(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3


class AdapterDisposition(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


class ReceiptStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"
    HALTED_RESTORATION_REQUIRED = "halted_restoration_required"


REQUIRED_TIER = MappingProxyType(
    {
        ActionClass.PASSIVE: ActionTier.R0,
        ActionClass.AUTHENTICATED_READ: ActionTier.R1,
        ActionClass.VALIDATION: ActionTier.R2,
        ActionClass.CONTROLLED_CHANGE: ActionTier.R3,
        ActionClass.DISRUPTIVE: ActionTier.R3,
    }
)

CAPABILITIES = MappingProxyType(
    {
        SpecialistDomain.MOBILE: (
            "mobile_application_analysis",
            "mobile_platform_configuration_validation",
            "mobile_session_boundary_assessment",
        ),
        SpecialistDomain.DESKTOP_CLIENT: (
            "desktop_client_analysis",
            "local_trust_boundary_validation",
            "update_channel_assessment",
        ),
        SpecialistDomain.WIRELESS: (
            "wireless_configuration_analysis",
            "wireless_identity_boundary_validation",
            "spectrum_evidence_assessment",
        ),
        SpecialistDomain.EMBEDDED_IOT: (
            "firmware_evidence_analysis",
            "embedded_interface_validation",
            "device_lifecycle_assessment",
        ),
        SpecialistDomain.OT_ICS: (
            "industrial_protocol_evidence_analysis",
            "control_boundary_validation",
            "safety_interlock_assessment",
        ),
    }
)


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_RE.search(encoded):
        raise SpecialistBoundaryError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise SpecialistBoundaryError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SpecialistBoundaryError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise SpecialistBoundaryError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise SpecialistBoundaryError(f"{label} must be an opaque reference")
    if not value.startswith(namespace + ":"):
        raise SpecialistBoundaryError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SpecialistBoundaryError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise SpecialistBoundaryError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SpecialistBoundaryError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise SpecialistBoundaryError(f"{label} is invalid") from exc


def _tier(value: Any, label: str) -> ActionTier:
    if not isinstance(value, str):
        raise SpecialistBoundaryError(f"{label} is invalid")
    try:
        return ActionTier[value]
    except KeyError as exc:
        raise SpecialistBoundaryError(f"{label} is invalid") from exc


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecialistBoundaryError(f"{label} is invalid")
    if not minimum <= value <= maximum:
        raise SpecialistBoundaryError(f"{label} is invalid")
    return value


def _metadata(body: Mapping[str, Any], kind: str) -> None:
    if body.get("kind") != kind or body.get("schema_version") != SCHEMA_VERSION:
        raise SpecialistBoundaryError("contract metadata is invalid")
    if body.get("boundary_effects") != dict(BOUNDARY_EFFECTS):
        raise SpecialistBoundaryError("contract attempts boundary escalation")
    if body.get("qualification_effect") != "none":
        raise SpecialistBoundaryError("qualification effect must remain none")


def _exact_keys(body: Mapping[str, Any], expected: set[str]) -> None:
    if set(body) != expected:
        raise SpecialistBoundaryError("contract fields are invalid")


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    domain: SpecialistDomain
    capability_ref: str
    capability_names: tuple[str, ...]
    maximum_tier: ActionTier = ActionTier.R3
    declaration_id: str = ""
    declaration_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", SpecialistDomain(self.domain))
        object.__setattr__(self, "maximum_tier", ActionTier(self.maximum_tier))
        _reference(self.capability_ref, "capability_ref", "capabilityref")
        names = tuple(self.capability_names)
        if names != CAPABILITIES[self.domain]:
            raise SpecialistBoundaryError("capability names are not the fixed profile")
        body = self._body()
        expected_id, expected_sha = _identity("MOD", "capability-declaration-v1", body)
        if self.declaration_id and self.declaration_id != expected_id:
            raise SpecialistBoundaryError("declaration identity is invalid")
        if self.declaration_sha256 and self.declaration_sha256 != expected_sha:
            raise SpecialistBoundaryError("declaration digest is invalid")
        object.__setattr__(self, "declaration_id", expected_id)
        object.__setattr__(self, "declaration_sha256", expected_sha)

    def _body(self) -> dict[str, Any]:
        return {
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "capability_names": list(self.capability_names),
            "capability_ref": self.capability_ref,
            "domain": self.domain.value,
            "kind": "mobile_ot_capability_declaration",
            "maximum_tier": self.maximum_tier.name,
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class BudgetBinding:
    budget_ref: str
    maximum_operations: int
    maximum_bytes: int
    maximum_changes: int
    maximum_duration_seconds: int
    budget_sha256: str = ""

    def __post_init__(self) -> None:
        _reference(self.budget_ref, "budget_ref", "budgetref")
        _integer(self.maximum_operations, "maximum_operations", 1, 1_000_000)
        _integer(self.maximum_bytes, "maximum_bytes", 1, 1_000_000_000_000)
        _integer(self.maximum_changes, "maximum_changes", 0, 1_000_000)
        _integer(self.maximum_duration_seconds, "maximum_duration_seconds", 1, 86_400)
        expected = canonical_sha256(self._body())
        if self.budget_sha256 and self.budget_sha256 != expected:
            raise SpecialistBoundaryError("budget digest is invalid")
        object.__setattr__(self, "budget_sha256", expected)

    def _body(self) -> dict[str, Any]:
        return {
            "budget_ref": self.budget_ref,
            "maximum_bytes": self.maximum_bytes,
            "maximum_changes": self.maximum_changes,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "maximum_operations": self.maximum_operations,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "budget_sha256": self.budget_sha256}


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    tenant_ref: str
    mission_ref: str
    environment: EnvironmentClass
    criticality: SystemCriticality
    scope_ref: str
    scope_sha256: str
    target_ref: str
    target_sha256: str
    protocol_ref: str
    protocol_sha256: str
    device_ref: str
    device_sha256: str
    session_ref: str
    session_sha256: str
    evidence_plan_ref: str
    evidence_plan_sha256: str
    restoration_plan_ref: str
    restoration_plan_sha256: str
    approval_ref: str
    approval_sha256: str
    approving_actor_ref: str
    independent_approval_ref: str
    independent_approval_sha256: str
    independent_actor_ref: str
    budget: BudgetBinding
    context_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "environment", EnvironmentClass(self.environment))
        object.__setattr__(self, "criticality", SystemCriticality(self.criticality))
        namespaces = {
            "tenant_ref": "tenantref",
            "mission_ref": "missionref",
            "scope_ref": "scoperef",
            "target_ref": "targetref",
            "protocol_ref": "protocolref",
            "device_ref": "deviceref",
            "session_ref": "sessionref",
            "evidence_plan_ref": "evidenceref",
            "restoration_plan_ref": "restorationref",
            "approval_ref": "approvalref",
            "approving_actor_ref": "actorref",
            "independent_approval_ref": "approvalref",
            "independent_actor_ref": "actorref",
        }
        for field, namespace in namespaces.items():
            _reference(getattr(self, field), field, namespace)
        for field in (
            "scope_sha256",
            "target_sha256",
            "protocol_sha256",
            "device_sha256",
            "session_sha256",
            "evidence_plan_sha256",
            "restoration_plan_sha256",
            "approval_sha256",
            "independent_approval_sha256",
        ):
            _digest(getattr(self, field), field)
        if not isinstance(self.budget, BudgetBinding):
            raise SpecialistBoundaryError("budget must be a BudgetBinding")
        if self.criticality is not SystemCriticality.STANDARD:
            if self.approving_actor_ref == self.independent_actor_ref:
                raise SpecialistBoundaryError("critical systems require independent approvers")
            if self.independent_approval_ref.endswith(":none"):
                raise SpecialistBoundaryError("critical systems require independent approval")
        expected = canonical_sha256(self._body())
        if self.context_sha256 and self.context_sha256 != expected:
            raise SpecialistBoundaryError("context digest is invalid")
        object.__setattr__(self, "context_sha256", expected)

    def _body(self) -> dict[str, Any]:
        return {
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "approving_actor_ref": self.approving_actor_ref,
            "budget": self.budget.to_dict(),
            "criticality": self.criticality.value,
            "device_ref": self.device_ref,
            "device_sha256": self.device_sha256,
            "environment": self.environment.value,
            "evidence_plan_ref": self.evidence_plan_ref,
            "evidence_plan_sha256": self.evidence_plan_sha256,
            "independent_actor_ref": self.independent_actor_ref,
            "independent_approval_ref": self.independent_approval_ref,
            "independent_approval_sha256": self.independent_approval_sha256,
            "mission_ref": self.mission_ref,
            "protocol_ref": self.protocol_ref,
            "protocol_sha256": self.protocol_sha256,
            "restoration_plan_ref": self.restoration_plan_ref,
            "restoration_plan_sha256": self.restoration_plan_sha256,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "session_ref": self.session_ref,
            "session_sha256": self.session_sha256,
            "target_ref": self.target_ref,
            "target_sha256": self.target_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "context_sha256": self.context_sha256}


@dataclass(frozen=True, slots=True)
class SpecialistActionRequest:
    declaration_id: str
    declaration_sha256: str
    domain: SpecialistDomain
    capability_ref: str
    action_class: ActionClass
    action_tier: ActionTier
    context: ExecutionContext
    intent_sha256: str
    estimated_operations: int
    estimated_bytes: int
    estimated_changes: int
    estimated_duration_seconds: int
    idempotency_sha256: str
    issued_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", SpecialistDomain(self.domain))
        object.__setattr__(self, "action_class", ActionClass(self.action_class))
        object.__setattr__(self, "action_tier", ActionTier(self.action_tier))
        _reference(self.capability_ref, "capability_ref", "capabilityref")
        _digest(self.declaration_sha256, "declaration_sha256")
        _digest(self.intent_sha256, "intent_sha256")
        _digest(self.idempotency_sha256, "idempotency_sha256")
        if not isinstance(self.context, ExecutionContext):
            raise SpecialistBoundaryError("context must be an ExecutionContext")
        _integer(self.estimated_operations, "estimated_operations", 1, 1_000_000)
        _integer(self.estimated_bytes, "estimated_bytes", 0, 1_000_000_000_000)
        _integer(self.estimated_changes, "estimated_changes", 0, 1_000_000)
        _integer(self.estimated_duration_seconds, "estimated_duration_seconds", 1, 86_400)
        issued = _instant(_timestamp(self.issued_at, "issued_at"))
        expires = _instant(_timestamp(self.expires_at, "expires_at"))
        if not 0 < (expires - issued).total_seconds() <= MAX_WINDOW_SECONDS:
            raise SpecialistBoundaryError("request window is invalid")
        expected_id, expected_sha = _identity("MOR", "mobile-ot-action-request-v1", self._body())
        if self.request_id and self.request_id != expected_id:
            raise SpecialistBoundaryError("request identity is invalid")
        if self.request_sha256 and self.request_sha256 != expected_sha:
            raise SpecialistBoundaryError("request digest is invalid")
        object.__setattr__(self, "request_id", expected_id)
        object.__setattr__(self, "request_sha256", expected_sha)

    def _body(self) -> dict[str, Any]:
        return {
            "action_class": self.action_class.value,
            "action_tier": self.action_tier.name,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "capability_ref": self.capability_ref,
            "context": self.context.to_dict(),
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "domain": self.domain.value,
            "estimated_bytes": self.estimated_bytes,
            "estimated_changes": self.estimated_changes,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "estimated_operations": self.estimated_operations,
            "expires_at": self.expires_at,
            "idempotency_sha256": self.idempotency_sha256,
            "intent_sha256": self.intent_sha256,
            "issued_at": self.issued_at,
            "kind": "mobile_ot_action_request",
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class AdapterObservation:
    request_id: str
    request_sha256: str
    context_sha256: str
    target_sha256: str
    protocol_sha256: str
    device_sha256: str
    session_sha256: str
    disposition: AdapterDisposition
    evidence_sha256: str
    actual_operations: int
    actual_bytes: int
    actual_changes: int
    actual_duration_seconds: int
    restoration_complete: bool
    restoration_evidence_sha256: str | None
    started_at: str
    completed_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "disposition", AdapterDisposition(self.disposition))
        for field in (
            "request_sha256",
            "context_sha256",
            "target_sha256",
            "protocol_sha256",
            "device_sha256",
            "session_sha256",
            "evidence_sha256",
        ):
            _digest(getattr(self, field), field)
        _integer(self.actual_operations, "actual_operations", 0, 1_000_000)
        _integer(self.actual_bytes, "actual_bytes", 0, 1_000_000_000_000)
        _integer(self.actual_changes, "actual_changes", 0, 1_000_000)
        _integer(self.actual_duration_seconds, "actual_duration_seconds", 0, 86_400)
        if not isinstance(self.restoration_complete, bool):
            raise SpecialistBoundaryError("restoration_complete must be boolean")
        if self.restoration_evidence_sha256 is not None:
            _digest(self.restoration_evidence_sha256, "restoration_evidence_sha256")
        if self.restoration_complete != (self.restoration_evidence_sha256 is not None):
            raise SpecialistBoundaryError("restoration evidence is inconsistent")
        started = _instant(_timestamp(self.started_at, "started_at"))
        completed = _instant(_timestamp(self.completed_at, "completed_at"))
        if completed < started:
            raise SpecialistBoundaryError("observation timing is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actual_bytes": self.actual_bytes,
            "actual_changes": self.actual_changes,
            "actual_duration_seconds": self.actual_duration_seconds,
            "actual_operations": self.actual_operations,
            "completed_at": self.completed_at,
            "context_sha256": self.context_sha256,
            "device_sha256": self.device_sha256,
            "disposition": self.disposition.value,
            "evidence_sha256": self.evidence_sha256,
            "protocol_sha256": self.protocol_sha256,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "restoration_complete": self.restoration_complete,
            "restoration_evidence_sha256": self.restoration_evidence_sha256,
            "session_sha256": self.session_sha256,
            "started_at": self.started_at,
            "target_sha256": self.target_sha256,
        }


@dataclass(frozen=True, slots=True)
class SpecialistActionReceipt:
    request_id: str
    request_sha256: str
    declaration_id: str
    declaration_sha256: str
    domain: SpecialistDomain
    capability_ref: str
    action_class: ActionClass
    action_tier: ActionTier
    context_sha256: str
    idempotency_sha256: str
    observation: AdapterObservation
    status: ReceiptStatus
    receipt_id: str = ""
    receipt_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", SpecialistDomain(self.domain))
        object.__setattr__(self, "action_class", ActionClass(self.action_class))
        object.__setattr__(self, "action_tier", ActionTier(self.action_tier))
        object.__setattr__(self, "status", ReceiptStatus(self.status))
        for field in (
            "request_sha256",
            "declaration_sha256",
            "context_sha256",
            "idempotency_sha256",
        ):
            _digest(getattr(self, field), field)
        _reference(self.capability_ref, "capability_ref", "capabilityref")
        if not isinstance(self.observation, AdapterObservation):
            raise SpecialistBoundaryError("observation must be an AdapterObservation")
        expected_id, expected_sha = _identity("MOC", "mobile-ot-action-receipt-v1", self._body())
        if self.receipt_id and self.receipt_id != expected_id:
            raise SpecialistBoundaryError("receipt identity is invalid")
        if self.receipt_sha256 and self.receipt_sha256 != expected_sha:
            raise SpecialistBoundaryError("receipt digest is invalid")
        object.__setattr__(self, "receipt_id", expected_id)
        object.__setattr__(self, "receipt_sha256", expected_sha)

    def _body(self) -> dict[str, Any]:
        return {
            "action_class": self.action_class.value,
            "action_tier": self.action_tier.name,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "capability_ref": self.capability_ref,
            "context_sha256": self.context_sha256,
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "domain": self.domain.value,
            "idempotency_sha256": self.idempotency_sha256,
            "kind": "mobile_ot_action_receipt",
            "observation": self.observation.to_dict(),
            "qualification_effect": "none",
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


class SpecialistExecutionAdapter(Protocol):
    """Caller-supplied implementation outside this repository-only boundary."""

    def execute(self, request: SpecialistActionRequest) -> AdapterObservation: ...


def recommended_capability_declarations() -> tuple[CapabilityDeclaration, ...]:
    return tuple(
        CapabilityDeclaration(
            domain=domain,
            capability_ref=f"capabilityref:specialist-{domain.value}",
            capability_names=CAPABILITIES[domain],
        )
        for domain in SpecialistDomain
    )


def dispatch_specialist_action(
    request: SpecialistActionRequest,
    declaration: CapabilityDeclaration,
    expected_context: ExecutionContext,
    adapter: SpecialistExecutionAdapter,
    *,
    evaluated_at: datetime,
    seen_request_ids: Iterable[str] = (),
    seen_idempotency_sha256: Iterable[str] = (),
) -> SpecialistActionReceipt:
    """Validate and invoke exactly one injected adapter without retry."""

    if not all(
        (
            isinstance(request, SpecialistActionRequest),
            isinstance(declaration, CapabilityDeclaration),
            isinstance(expected_context, ExecutionContext),
        )
    ):
        raise SpecialistBoundaryError("dispatch inputs are invalid")
    if request.domain is not declaration.domain:
        raise SpecialistBoundaryError("declaration domain does not match")
    if request.capability_ref != declaration.capability_ref:
        raise SpecialistBoundaryError("declaration capability does not match")
    if (
        request.declaration_id != declaration.declaration_id
        or request.declaration_sha256 != declaration.declaration_sha256
    ):
        raise SpecialistBoundaryError("declaration binding does not match")
    if request.context != expected_context:
        raise SpecialistBoundaryError("execution context does not match")
    if request.action_tier is not REQUIRED_TIER[request.action_class]:
        raise SpecialistBoundaryError("action tier does not match the action class")
    if request.action_tier > declaration.maximum_tier:
        raise SpecialistBoundaryError("action tier exceeds declaration")
    if request.action_class is ActionClass.DISRUPTIVE:
        if request.context.environment not in (EnvironmentClass.SIMULATION, EnvironmentClass.LAB):
            raise SpecialistBoundaryError("disruptive actions require simulation or lab")
        if (
            request.domain
            in (
                SpecialistDomain.WIRELESS,
                SpecialistDomain.OT_ICS,
            )
            and request.context.environment is EnvironmentClass.PRODUCTION
        ):
            raise SpecialistBoundaryError("production disruptive action is prohibited")
    if not isinstance(evaluated_at, datetime) or evaluated_at.tzinfo is None:
        raise SpecialistBoundaryError("evaluated_at must be timezone aware")
    now = evaluated_at.astimezone(UTC).replace(microsecond=0)
    if not _instant(request.issued_at) <= now < _instant(request.expires_at):
        raise SpecialistBoundaryError("request is not active")
    if request.request_id in set(seen_request_ids):
        raise SpecialistBoundaryError("request replay is forbidden")
    if request.idempotency_sha256 in set(seen_idempotency_sha256):
        raise SpecialistBoundaryError("idempotency replay is forbidden")
    budget = request.context.budget
    if (
        request.estimated_operations > budget.maximum_operations
        or request.estimated_bytes > budget.maximum_bytes
        or request.estimated_changes > budget.maximum_changes
        or request.estimated_duration_seconds > budget.maximum_duration_seconds
    ):
        raise SpecialistBoundaryError("request estimate exceeds budget")
    if (
        request.action_class
        not in (
            ActionClass.CONTROLLED_CHANGE,
            ActionClass.DISRUPTIVE,
        )
        and request.estimated_changes != 0
    ):
        raise SpecialistBoundaryError("non-changing action estimates changes")
    if request.action_class in (
        ActionClass.CONTROLLED_CHANGE,
        ActionClass.DISRUPTIVE,
    ) and request.context.restoration_plan_ref.endswith(":none"):
        raise SpecialistBoundaryError("changing actions require restoration planning")

    observation = adapter.execute(request)
    if not isinstance(observation, AdapterObservation):
        raise SpecialistBoundaryError("adapter returned an invalid observation")
    exact_bindings = (
        observation.request_id == request.request_id,
        observation.request_sha256 == request.request_sha256,
        observation.context_sha256 == request.context.context_sha256,
        observation.target_sha256 == request.context.target_sha256,
        observation.protocol_sha256 == request.context.protocol_sha256,
        observation.device_sha256 == request.context.device_sha256,
        observation.session_sha256 == request.context.session_sha256,
    )
    if not all(exact_bindings):
        raise SpecialistBoundaryError("adapter observation binding does not match")
    if (
        observation.actual_operations > budget.maximum_operations
        or observation.actual_bytes > budget.maximum_bytes
        or observation.actual_changes > budget.maximum_changes
        or observation.actual_duration_seconds > budget.maximum_duration_seconds
    ):
        raise SpecialistBoundaryError("adapter observation exceeds budget")
    if (
        request.action_class
        not in (
            ActionClass.CONTROLLED_CHANGE,
            ActionClass.DISRUPTIVE,
        )
        and observation.actual_changes != 0
    ):
        raise SpecialistBoundaryError("non-changing action reported changes")

    status = ReceiptStatus(observation.disposition.value)
    if observation.actual_changes and not observation.restoration_complete:
        status = ReceiptStatus.HALTED_RESTORATION_REQUIRED
    return SpecialistActionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        domain=request.domain,
        capability_ref=request.capability_ref,
        action_class=request.action_class,
        action_tier=request.action_tier,
        context_sha256=request.context.context_sha256,
        idempotency_sha256=request.idempotency_sha256,
        observation=observation,
        status=status,
    )


def parse_contract(
    body: Mapping[str, Any],
) -> CapabilityDeclaration | SpecialistActionRequest | SpecialistActionReceipt:
    """Parse one strict declaration, request, or receipt mapping."""

    if not isinstance(body, Mapping):
        raise SpecialistBoundaryError("contract must be an object")
    kind = body.get("kind")
    if kind == "mobile_ot_capability_declaration":
        _metadata(body, kind)
        _exact_keys(
            body,
            set(
                CapabilityDeclaration(
                    SpecialistDomain.MOBILE,
                    "capabilityref:probe",
                    CAPABILITIES[SpecialistDomain.MOBILE],
                ).to_dict()
            ),
        )
        return CapabilityDeclaration(
            domain=_enum(SpecialistDomain, body["domain"], "domain"),
            capability_ref=body["capability_ref"],
            capability_names=tuple(body["capability_names"]),
            maximum_tier=_tier(body["maximum_tier"], "maximum_tier"),
            declaration_id=body["declaration_id"],
            declaration_sha256=body["declaration_sha256"],
        )
    if kind == "mobile_ot_action_request":
        _metadata(body, kind)
        _exact_keys(body, _REQUEST_KEYS)
        context = _parse_context(body["context"])
        return SpecialistActionRequest(
            declaration_id=body["declaration_id"],
            declaration_sha256=body["declaration_sha256"],
            domain=_enum(SpecialistDomain, body["domain"], "domain"),
            capability_ref=body["capability_ref"],
            action_class=_enum(ActionClass, body["action_class"], "action_class"),
            action_tier=_tier(body["action_tier"], "action_tier"),
            context=context,
            intent_sha256=body["intent_sha256"],
            estimated_operations=body["estimated_operations"],
            estimated_bytes=body["estimated_bytes"],
            estimated_changes=body["estimated_changes"],
            estimated_duration_seconds=body["estimated_duration_seconds"],
            idempotency_sha256=body["idempotency_sha256"],
            issued_at=body["issued_at"],
            expires_at=body["expires_at"],
            request_id=body["request_id"],
            request_sha256=body["request_sha256"],
        )
    if kind == "mobile_ot_action_receipt":
        _metadata(body, kind)
        _exact_keys(body, _RECEIPT_KEYS)
        observation = _parse_observation(body["observation"])
        return SpecialistActionReceipt(
            request_id=body["request_id"],
            request_sha256=body["request_sha256"],
            declaration_id=body["declaration_id"],
            declaration_sha256=body["declaration_sha256"],
            domain=_enum(SpecialistDomain, body["domain"], "domain"),
            capability_ref=body["capability_ref"],
            action_class=_enum(ActionClass, body["action_class"], "action_class"),
            action_tier=_tier(body["action_tier"], "action_tier"),
            context_sha256=body["context_sha256"],
            idempotency_sha256=body["idempotency_sha256"],
            observation=observation,
            status=_enum(ReceiptStatus, body["status"], "status"),
            receipt_id=body["receipt_id"],
            receipt_sha256=body["receipt_sha256"],
        )
    raise SpecialistBoundaryError("contract kind is invalid")


def _parse_budget(body: Any) -> BudgetBinding:
    if not isinstance(body, Mapping):
        raise SpecialistBoundaryError("budget must be an object")
    _exact_keys(body, set(BudgetBinding("budgetref:probe", 1, 1, 0, 1).to_dict()))
    return BudgetBinding(**body)


def _parse_context(body: Any) -> ExecutionContext:
    if not isinstance(body, Mapping):
        raise SpecialistBoundaryError("context must be an object")
    _exact_keys(body, _CONTEXT_KEYS)
    values = dict(body)
    values["budget"] = _parse_budget(values["budget"])
    values["environment"] = _enum(EnvironmentClass, values["environment"], "environment")
    values["criticality"] = _enum(SystemCriticality, values["criticality"], "criticality")
    return ExecutionContext(**values)


def _parse_observation(body: Any) -> AdapterObservation:
    if not isinstance(body, Mapping):
        raise SpecialistBoundaryError("observation must be an object")
    _exact_keys(body, _OBSERVATION_KEYS)
    values = dict(body)
    values["disposition"] = _enum(AdapterDisposition, values["disposition"], "disposition")
    return AdapterObservation(**values)


_REQUEST_KEYS = set(
    SpecialistActionRequest(
        declaration_id="MOD-" + "0" * 32,
        declaration_sha256="sha256:" + "0" * 64,
        domain=SpecialistDomain.MOBILE,
        capability_ref="capabilityref:probe",
        action_class=ActionClass.PASSIVE,
        action_tier=ActionTier.R0,
        context=ExecutionContext(
            tenant_ref="tenantref:probe",
            mission_ref="missionref:probe",
            environment=EnvironmentClass.LAB,
            criticality=SystemCriticality.STANDARD,
            scope_ref="scoperef:probe",
            scope_sha256="sha256:" + "0" * 64,
            target_ref="targetref:probe",
            target_sha256="sha256:" + "0" * 64,
            protocol_ref="protocolref:probe",
            protocol_sha256="sha256:" + "0" * 64,
            device_ref="deviceref:probe",
            device_sha256="sha256:" + "0" * 64,
            session_ref="sessionref:probe",
            session_sha256="sha256:" + "0" * 64,
            evidence_plan_ref="evidenceref:probe",
            evidence_plan_sha256="sha256:" + "0" * 64,
            restoration_plan_ref="restorationref:none",
            restoration_plan_sha256="sha256:" + "0" * 64,
            approval_ref="approvalref:probe",
            approval_sha256="sha256:" + "0" * 64,
            approving_actor_ref="actorref:one",
            independent_approval_ref="approvalref:none",
            independent_approval_sha256="sha256:" + "0" * 64,
            independent_actor_ref="actorref:none",
            budget=BudgetBinding("budgetref:probe", 1, 1, 0, 1),
        ),
        intent_sha256="sha256:" + "0" * 64,
        estimated_operations=1,
        estimated_bytes=0,
        estimated_changes=0,
        estimated_duration_seconds=1,
        idempotency_sha256="sha256:" + "0" * 64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T00:00:01Z",
    ).to_dict()
)
_CONTEXT_KEYS = set(
    ExecutionContext(
        tenant_ref="tenantref:probe",
        mission_ref="missionref:probe",
        environment=EnvironmentClass.LAB,
        criticality=SystemCriticality.STANDARD,
        scope_ref="scoperef:probe",
        scope_sha256="sha256:" + "0" * 64,
        target_ref="targetref:probe",
        target_sha256="sha256:" + "0" * 64,
        protocol_ref="protocolref:probe",
        protocol_sha256="sha256:" + "0" * 64,
        device_ref="deviceref:probe",
        device_sha256="sha256:" + "0" * 64,
        session_ref="sessionref:probe",
        session_sha256="sha256:" + "0" * 64,
        evidence_plan_ref="evidenceref:probe",
        evidence_plan_sha256="sha256:" + "0" * 64,
        restoration_plan_ref="restorationref:none",
        restoration_plan_sha256="sha256:" + "0" * 64,
        approval_ref="approvalref:probe",
        approval_sha256="sha256:" + "0" * 64,
        approving_actor_ref="actorref:one",
        independent_approval_ref="approvalref:none",
        independent_approval_sha256="sha256:" + "0" * 64,
        independent_actor_ref="actorref:none",
        budget=BudgetBinding("budgetref:probe", 1, 1, 0, 1),
    ).to_dict()
)
_OBSERVATION_KEYS = set(
    AdapterObservation(
        request_id="MOR-" + "0" * 32,
        request_sha256="sha256:" + "0" * 64,
        context_sha256="sha256:" + "0" * 64,
        target_sha256="sha256:" + "0" * 64,
        protocol_sha256="sha256:" + "0" * 64,
        device_sha256="sha256:" + "0" * 64,
        session_sha256="sha256:" + "0" * 64,
        disposition=AdapterDisposition.COMPLETED,
        evidence_sha256="sha256:" + "0" * 64,
        actual_operations=0,
        actual_bytes=0,
        actual_changes=0,
        actual_duration_seconds=0,
        restoration_complete=False,
        restoration_evidence_sha256=None,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:00Z",
    ).to_dict()
)
_RECEIPT_KEYS = {
    "action_class",
    "action_tier",
    "boundary_effects",
    "capability_ref",
    "context_sha256",
    "declaration_id",
    "declaration_sha256",
    "domain",
    "idempotency_sha256",
    "kind",
    "observation",
    "qualification_effect",
    "receipt_id",
    "receipt_sha256",
    "request_id",
    "request_sha256",
    "schema_version",
    "status",
}
