"""Fail-closed contracts for injected specialist assessment adapters.

This module defines capability declarations, deterministic action requests, and
normalized receipts for network, host, container, database, messaging, and
lateral-movement assessment specialists. It contains no network client,
credential resolver, exploit payload, target implementation, or autonomous
execution loop. Any target interaction is delegated to a caller-supplied
adapter after exact context, tier, freshness, replay, and budget checks.
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
MAX_CAPABILITIES = 32

BOUNDARY_EFFECTS = MappingProxyType(
    {
        "autonomous_execution": "none",
        "builtin_network": "none",
        "builtin_target_action": "none",
        "credential_resolution": "none",
        "injected_adapter_invocation": "caller_supplied_only",
        "persistence": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|scoperef|targetref|routeref|workerref|sessionref|"
    r"fenceref|admissionref|approvalref|leaseref|evidenceref|cleanupref|"
    r"restorationref|capabilityref|budgetref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}|"
    r"\b(?:password|passwd|secret|access_token|refresh_token|id_token|otp)"
    r"\s*[:=]\s*[^,}\s]+|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)


class SpecialistAdapterContractError(ValueError):
    """Raised when a specialist adapter contract fails closed."""


class SpecialistFamily(StrEnum):
    NETWORK = "network"
    HOST = "host"
    CONTAINER = "container"
    DATABASE = "database"
    MESSAGING = "messaging"
    LATERAL_MOVEMENT = "lateral_movement"


class ActionClass(StrEnum):
    PASSIVE = "passive"
    AUTHENTICATED_READ = "authenticated_read"
    VALIDATION = "validation"
    CONTROLLED_CHANGE = "controlled_change"


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
    HALTED_CLEANUP_REQUIRED = "halted_cleanup_required"


REQUIRED_TIER = MappingProxyType(
    {
        ActionClass.PASSIVE: ActionTier.R0,
        ActionClass.AUTHENTICATED_READ: ActionTier.R1,
        ActionClass.VALIDATION: ActionTier.R2,
        ActionClass.CONTROLLED_CHANGE: ActionTier.R3,
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret scanning."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_MATERIAL_RE.search(encoded):
        raise SpecialistAdapterContractError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise SpecialistAdapterContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SpecialistAdapterContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise SpecialistAdapterContractError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise SpecialistAdapterContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise SpecialistAdapterContractError(f"{label} must use the {namespace} namespace")
    if SECRET_MATERIAL_RE.search(value):
        raise SpecialistAdapterContractError(f"{label} contains secret material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SpecialistAdapterContractError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise SpecialistAdapterContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SpecialistAdapterContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _evaluated_at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SpecialistAdapterContractError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _instant(_timestamp(issued_at, f"{label} issued_at"))
    expires = _instant(_timestamp(expires_at, f"{label} expires_at"))
    seconds = (expires - issued).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS:
        raise SpecialistAdapterContractError(f"{label} window is invalid")


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise SpecialistAdapterContractError(f"{label} is invalid") from exc


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise SpecialistAdapterContractError(f"{label} is invalid")
    return value


def _nonnegative(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise SpecialistAdapterContractError(f"{label} is invalid")
    return value


def _metadata(body: Mapping[str, Any], kind: str) -> None:
    if body.get("kind") != kind or body.get("schema_version") != SCHEMA_VERSION:
        raise SpecialistAdapterContractError("contract metadata is invalid")
    if body.get("boundary_effects") != dict(BOUNDARY_EFFECTS):
        raise SpecialistAdapterContractError("contract attempts boundary escalation")


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityDeclaration:
    family: SpecialistFamily
    capability_ref: str
    capability_names: tuple[str, ...]
    supported_action_classes: tuple[ActionClass, ...]
    maximum_tier: ActionTier

    def __post_init__(self) -> None:
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        names = tuple(self.capability_names)
        if not 1 <= len(names) <= MAX_CAPABILITIES or len(names) != len(set(names)):
            raise SpecialistAdapterContractError("capability_names count is invalid")
        if any(not isinstance(item, str) or not item or len(item) > 96 for item in names):
            raise SpecialistAdapterContractError("capability_names contains an invalid item")
        object.__setattr__(self, "capability_names", tuple(sorted(names)))
        actions = tuple(ActionClass(item) for item in self.supported_action_classes)
        if not actions or len(actions) != len(set(actions)):
            raise SpecialistAdapterContractError("supported_action_classes is invalid")
        object.__setattr__(
            self,
            "supported_action_classes",
            tuple(sorted(actions, key=lambda item: REQUIRED_TIER[item])),
        )
        object.__setattr__(self, "maximum_tier", ActionTier(self.maximum_tier))
        if ActionClass.PASSIVE not in actions:
            raise SpecialistAdapterContractError("passive capability is required")
        if any(REQUIRED_TIER[item] > self.maximum_tier for item in actions):
            raise SpecialistAdapterContractError("action exceeds the declared maximum tier")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "specialist_capability_declaration",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "capability_names": list(self.capability_names),
            "supported_action_classes": [item.value for item in self.supported_action_classes],
            "maximum_tier": self.maximum_tier.name,
            "qualification_effect": "none",
        }

    @property
    def declaration_id(self) -> str:
        return _identity("SCD", "specialist-capability-declaration-v1", self._body())[0]

    @property
    def declaration_sha256(self) -> str:
        return _identity("SCD", "specialist-capability-declaration-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class BudgetEnvelope:
    budget_ref: str
    maximum_requests: int
    maximum_bytes: int
    maximum_changes: int
    maximum_duration_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "budget_ref", _reference(self.budget_ref, "budget_ref", "budgetref")
        )
        object.__setattr__(
            self,
            "maximum_requests",
            _positive(self.maximum_requests, "maximum_requests", 1_000_000),
        )
        object.__setattr__(
            self,
            "maximum_bytes",
            _positive(self.maximum_bytes, "maximum_bytes", 2**63 - 1),
        )
        object.__setattr__(
            self,
            "maximum_changes",
            _nonnegative(self.maximum_changes, "maximum_changes", 1_000_000),
        )
        object.__setattr__(
            self,
            "maximum_duration_seconds",
            _positive(
                self.maximum_duration_seconds,
                "maximum_duration_seconds",
                MAX_WINDOW_SECONDS,
            ),
        )

    @property
    def budget_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_ref": self.budget_ref,
            "maximum_requests": self.maximum_requests,
            "maximum_bytes": self.maximum_bytes,
            "maximum_changes": self.maximum_changes,
            "maximum_duration_seconds": self.maximum_duration_seconds,
        }


@dataclass(frozen=True, slots=True)
class SpecialistExecutionContext:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    scope_sha256: str
    target_ref: str
    target_sha256: str
    route_ref: str
    route_sha256: str
    worker_ref: str
    session_ref: str
    fence_ref: str
    fence_epoch: int
    fencing_token_sha256: str
    action_admission_ref: str
    action_admission_sha256: str
    approval_ref: str
    approval_sha256: str
    credential_lease_ref: str
    credential_lease_sha256: str
    evidence_plan_ref: str
    evidence_plan_sha256: str
    cleanup_plan_ref: str
    cleanup_plan_sha256: str
    restoration_plan_ref: str
    restoration_plan_sha256: str
    budget: BudgetEnvelope

    def __post_init__(self) -> None:
        references = (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
            ("route_ref", "routeref"),
            ("worker_ref", "workerref"),
            ("session_ref", "sessionref"),
            ("fence_ref", "fenceref"),
            ("action_admission_ref", "admissionref"),
            ("approval_ref", "approvalref"),
            ("credential_lease_ref", "leaseref"),
            ("evidence_plan_ref", "evidenceref"),
            ("cleanup_plan_ref", "cleanupref"),
            ("restoration_plan_ref", "restorationref"),
        )
        for field_name, namespace in references:
            object.__setattr__(
                self,
                field_name,
                _reference(getattr(self, field_name), field_name, namespace),
            )
        for field_name in (
            "scope_sha256",
            "target_sha256",
            "route_sha256",
            "fencing_token_sha256",
            "action_admission_sha256",
            "approval_sha256",
            "credential_lease_sha256",
            "evidence_plan_sha256",
            "cleanup_plan_sha256",
            "restoration_plan_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        if isinstance(self.fence_epoch, bool) or not 1 <= self.fence_epoch <= 2**63 - 1:
            raise SpecialistAdapterContractError("fence_epoch is invalid")
        if not isinstance(self.budget, BudgetEnvelope):
            raise SpecialistAdapterContractError("budget is invalid")

    @property
    def context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_ref": self.tenant_ref,
            "mission_ref": self.mission_ref,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "target_ref": self.target_ref,
            "target_sha256": self.target_sha256,
            "route_ref": self.route_ref,
            "route_sha256": self.route_sha256,
            "worker_ref": self.worker_ref,
            "session_ref": self.session_ref,
            "fence_ref": self.fence_ref,
            "fence_epoch": self.fence_epoch,
            "fencing_token_sha256": self.fencing_token_sha256,
            "action_admission_ref": self.action_admission_ref,
            "action_admission_sha256": self.action_admission_sha256,
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "credential_lease_ref": self.credential_lease_ref,
            "credential_lease_sha256": self.credential_lease_sha256,
            "evidence_plan_ref": self.evidence_plan_ref,
            "evidence_plan_sha256": self.evidence_plan_sha256,
            "cleanup_plan_ref": self.cleanup_plan_ref,
            "cleanup_plan_sha256": self.cleanup_plan_sha256,
            "restoration_plan_ref": self.restoration_plan_ref,
            "restoration_plan_sha256": self.restoration_plan_sha256,
            "budget": self.budget.to_dict(),
            "budget_sha256": self.budget.budget_sha256,
        }


@dataclass(frozen=True, slots=True)
class SpecialistActionRequest:
    declaration_id: str
    declaration_sha256: str
    family: SpecialistFamily
    capability_ref: str
    action_class: ActionClass
    action_tier: ActionTier
    context: SpecialistExecutionContext
    intent_sha256: str
    estimated_requests: int
    estimated_bytes: int
    estimated_changes: int
    estimated_duration_seconds: int
    idempotency_sha256: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.declaration_id, str)
            or re.fullmatch(r"SCD-[0-9A-F]{32}", self.declaration_id) is None
        ):
            raise SpecialistAdapterContractError("declaration_id is invalid")
        object.__setattr__(
            self,
            "declaration_sha256",
            _digest(self.declaration_sha256, "declaration_sha256"),
        )
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        object.__setattr__(self, "action_class", ActionClass(self.action_class))
        object.__setattr__(self, "action_tier", ActionTier(self.action_tier))
        if self.action_tier != REQUIRED_TIER[self.action_class]:
            raise SpecialistAdapterContractError("action tier does not match action class")
        if not isinstance(self.context, SpecialistExecutionContext):
            raise SpecialistAdapterContractError("context is invalid")
        object.__setattr__(self, "intent_sha256", _digest(self.intent_sha256, "intent_sha256"))
        object.__setattr__(
            self,
            "idempotency_sha256",
            _digest(self.idempotency_sha256, "idempotency_sha256"),
        )
        estimates = (
            ("estimated_requests", self.context.budget.maximum_requests, True),
            ("estimated_bytes", self.context.budget.maximum_bytes, False),
            ("estimated_changes", self.context.budget.maximum_changes, False),
            (
                "estimated_duration_seconds",
                self.context.budget.maximum_duration_seconds,
                True,
            ),
        )
        for field_name, maximum, must_be_positive in estimates:
            value = getattr(self, field_name)
            normalized = (
                _positive(value, field_name, maximum)
                if must_be_positive
                else _nonnegative(value, field_name, maximum)
            )
            object.__setattr__(self, field_name, normalized)
        _window(self.issued_at, self.expires_at, "request")
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "issued_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        self._validate_tier_bindings()

    def _validate_tier_bindings(self) -> None:
        no_credential = self.context.credential_lease_ref == "leaseref:none"
        no_cleanup = self.context.cleanup_plan_ref == "cleanupref:none"
        no_restoration = self.context.restoration_plan_ref == "restorationref:none"
        if self.action_class is ActionClass.PASSIVE and not no_credential:
            raise SpecialistAdapterContractError("passive action cannot bind a credential lease")
        if self.action_class is not ActionClass.PASSIVE and no_credential:
            raise SpecialistAdapterContractError("this action class requires a credential lease")
        if self.action_class is ActionClass.CONTROLLED_CHANGE:
            if no_cleanup or no_restoration or self.estimated_changes < 1:
                raise SpecialistAdapterContractError(
                    "controlled change requires cleanup, restoration, and a change budget"
                )
        elif not no_cleanup or not no_restoration or self.estimated_changes != 0:
            raise SpecialistAdapterContractError(
                "non-changing action must use no-change cleanup and restoration bindings"
            )

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "specialist_action_request",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "action_class": self.action_class.value,
            "action_tier": self.action_tier.name,
            "context": self.context.to_dict(),
            "context_sha256": self.context.context_sha256,
            "intent_sha256": self.intent_sha256,
            "estimated_requests": self.estimated_requests,
            "estimated_bytes": self.estimated_bytes,
            "estimated_changes": self.estimated_changes,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "idempotency_sha256": self.idempotency_sha256,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "qualification_effect": "none",
        }

    @property
    def request_id(self) -> str:
        return _identity("SAR", "specialist-action-request-v1", self._body())[0]

    @property
    def request_sha256(self) -> str:
        return _identity("SAR", "specialist-action-request-v1", self._body())[1]

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
    disposition: AdapterDisposition
    evidence_sha256: str
    actual_requests: int
    actual_bytes: int
    actual_changes: int
    actual_duration_seconds: int
    cleanup_complete: bool
    restoration_complete: bool
    cleanup_evidence_sha256: str | None
    restoration_evidence_sha256: str | None
    started_at: str
    completed_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"SAR-[0-9A-F]{32}", self.request_id) is None
        ):
            raise SpecialistAdapterContractError("observation request_id is invalid")
        for field_name in ("request_sha256", "context_sha256", "evidence_sha256"):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        object.__setattr__(self, "disposition", AdapterDisposition(self.disposition))
        for field_name, maximum in (
            ("actual_requests", 1_000_000),
            ("actual_bytes", 2**63 - 1),
            ("actual_changes", 1_000_000),
            ("actual_duration_seconds", MAX_WINDOW_SECONDS),
        ):
            object.__setattr__(
                self,
                field_name,
                _nonnegative(getattr(self, field_name), field_name, maximum),
            )
        if not isinstance(self.cleanup_complete, bool) or not isinstance(
            self.restoration_complete, bool
        ):
            raise SpecialistAdapterContractError("cleanup flags must be boolean")
        for field_name in ("cleanup_evidence_sha256", "restoration_evidence_sha256"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _digest(value, field_name))
        if self.cleanup_complete != (self.cleanup_evidence_sha256 is not None):
            raise SpecialistAdapterContractError("cleanup evidence does not match status")
        if self.restoration_complete != (self.restoration_evidence_sha256 is not None):
            raise SpecialistAdapterContractError("restoration evidence does not match status")
        object.__setattr__(self, "started_at", _timestamp(self.started_at, "started_at"))
        object.__setattr__(self, "completed_at", _timestamp(self.completed_at, "completed_at"))
        if _instant(self.completed_at) < _instant(self.started_at):
            raise SpecialistAdapterContractError("observation time order is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "context_sha256": self.context_sha256,
            "disposition": self.disposition.value,
            "evidence_sha256": self.evidence_sha256,
            "actual_requests": self.actual_requests,
            "actual_bytes": self.actual_bytes,
            "actual_changes": self.actual_changes,
            "actual_duration_seconds": self.actual_duration_seconds,
            "cleanup_complete": self.cleanup_complete,
            "restoration_complete": self.restoration_complete,
            "cleanup_evidence_sha256": self.cleanup_evidence_sha256,
            "restoration_evidence_sha256": self.restoration_evidence_sha256,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True, slots=True)
class SpecialistActionReceipt:
    request_id: str
    request_sha256: str
    declaration_id: str
    declaration_sha256: str
    family: SpecialistFamily
    capability_ref: str
    action_class: ActionClass
    action_tier: ActionTier
    context_sha256: str
    idempotency_sha256: str
    observation: AdapterObservation
    status: ReceiptStatus

    def __post_init__(self) -> None:
        for value, pattern, label in (
            (self.request_id, r"SAR-[0-9A-F]{32}", "request_id"),
            (self.declaration_id, r"SCD-[0-9A-F]{32}", "declaration_id"),
        ):
            if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
                raise SpecialistAdapterContractError(f"{label} is invalid")
        for field_name in (
            "request_sha256",
            "declaration_sha256",
            "context_sha256",
            "idempotency_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        object.__setattr__(self, "action_class", ActionClass(self.action_class))
        object.__setattr__(self, "action_tier", ActionTier(self.action_tier))
        object.__setattr__(self, "status", ReceiptStatus(self.status))
        if not isinstance(self.observation, AdapterObservation):
            raise SpecialistAdapterContractError("observation is invalid")
        if (
            self.observation.request_id != self.request_id
            or self.observation.request_sha256 != self.request_sha256
            or self.observation.context_sha256 != self.context_sha256
        ):
            raise SpecialistAdapterContractError("receipt observation binding does not match")
        if self.action_tier != REQUIRED_TIER[self.action_class]:
            raise SpecialistAdapterContractError("receipt tier does not match action class")
        expected_status = {
            AdapterDisposition.DENIED: ReceiptStatus.DENIED,
            AdapterDisposition.FAILED: ReceiptStatus.FAILED,
        }.get(self.observation.disposition)
        if expected_status is None:
            if self.action_class is ActionClass.CONTROLLED_CHANGE and not (
                self.observation.cleanup_complete and self.observation.restoration_complete
            ):
                expected_status = ReceiptStatus.HALTED_CLEANUP_REQUIRED
            else:
                expected_status = ReceiptStatus.COMPLETED
        if self.status is not expected_status:
            raise SpecialistAdapterContractError("receipt status does not match observation")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "specialist_action_receipt",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "action_class": self.action_class.value,
            "action_tier": self.action_tier.name,
            "context_sha256": self.context_sha256,
            "idempotency_sha256": self.idempotency_sha256,
            "observation": self.observation.to_dict(),
            "status": self.status.value,
            "qualification_effect": "none",
        }

    @property
    def receipt_id(self) -> str:
        return _identity("SAC", "specialist-action-receipt-v1", self._body())[0]

    @property
    def receipt_sha256(self) -> str:
        return _identity("SAC", "specialist-action-receipt-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


class SpecialistAdapter(Protocol):
    """Caller-supplied adapter boundary. Implementations must enforce the request."""

    def execute(self, request: SpecialistActionRequest) -> AdapterObservation:
        """Return a digest-only observation for one exactly bound request."""


def dispatch_specialist_action(
    request: SpecialistActionRequest,
    declaration: SpecialistCapabilityDeclaration,
    expected_context: SpecialistExecutionContext,
    adapter: SpecialistAdapter,
    *,
    evaluated_at: datetime,
    seen_request_ids: Iterable[str] = (),
    seen_idempotency_sha256: Iterable[str] = (),
) -> SpecialistActionReceipt:
    """Validate and invoke one injected adapter, then normalize its observation."""

    if not isinstance(request, SpecialistActionRequest):
        raise SpecialistAdapterContractError("request is invalid")
    if not isinstance(declaration, SpecialistCapabilityDeclaration):
        raise SpecialistAdapterContractError("declaration is invalid")
    if not isinstance(expected_context, SpecialistExecutionContext):
        raise SpecialistAdapterContractError("expected_context is invalid")
    if request.declaration_id != declaration.declaration_id or (
        request.declaration_sha256 != declaration.declaration_sha256
    ):
        raise SpecialistAdapterContractError("declaration binding does not match")
    if request.family != declaration.family or request.capability_ref != declaration.capability_ref:
        raise SpecialistAdapterContractError("capability binding does not match")
    if request.action_class not in declaration.supported_action_classes:
        raise SpecialistAdapterContractError("action class is not declared")
    if request.action_tier > declaration.maximum_tier:
        raise SpecialistAdapterContractError("action tier exceeds declaration")
    if request.context != expected_context:
        raise SpecialistAdapterContractError("execution context does not match")
    at = _evaluated_at(evaluated_at)
    if not _instant(request.issued_at) <= at < _instant(request.expires_at):
        raise SpecialistAdapterContractError("request is stale or not yet active")
    if request.request_id in set(seen_request_ids):
        raise SpecialistAdapterContractError("request replay was detected")
    if request.idempotency_sha256 in set(seen_idempotency_sha256):
        raise SpecialistAdapterContractError("idempotency replay was detected")

    observation = adapter.execute(request)
    if not isinstance(observation, AdapterObservation):
        raise SpecialistAdapterContractError("adapter returned an invalid observation")
    if (
        observation.request_id != request.request_id
        or observation.request_sha256 != request.request_sha256
        or observation.context_sha256 != request.context.context_sha256
    ):
        raise SpecialistAdapterContractError("adapter observation binding does not match")
    if not _instant(request.issued_at) <= _instant(observation.started_at):
        raise SpecialistAdapterContractError("adapter observation predates request")
    if _instant(observation.completed_at) > _instant(request.expires_at):
        raise SpecialistAdapterContractError("adapter observation exceeds request window")

    budget = request.context.budget
    usage = (
        (observation.actual_requests, budget.maximum_requests),
        (observation.actual_bytes, budget.maximum_bytes),
        (observation.actual_changes, budget.maximum_changes),
        (observation.actual_duration_seconds, budget.maximum_duration_seconds),
    )
    if any(actual > maximum for actual, maximum in usage):
        raise SpecialistAdapterContractError("adapter observation exceeds the bound budget")
    if request.action_class is not ActionClass.CONTROLLED_CHANGE and observation.actual_changes:
        raise SpecialistAdapterContractError("non-changing action reported target changes")

    if observation.disposition is AdapterDisposition.DENIED:
        status = ReceiptStatus.DENIED
    elif observation.disposition is AdapterDisposition.FAILED:
        status = ReceiptStatus.FAILED
    elif request.action_class is ActionClass.CONTROLLED_CHANGE and not (
        observation.cleanup_complete and observation.restoration_complete
    ):
        status = ReceiptStatus.HALTED_CLEANUP_REQUIRED
    else:
        status = ReceiptStatus.COMPLETED

    return SpecialistActionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        family=request.family,
        capability_ref=request.capability_ref,
        action_class=request.action_class,
        action_tier=request.action_tier,
        context_sha256=request.context.context_sha256,
        idempotency_sha256=request.idempotency_sha256,
        observation=observation,
        status=status,
    )


def recommended_capability_declarations() -> tuple[SpecialistCapabilityDeclaration, ...]:
    """Return deterministic repository-only declarations for six specialist families."""

    records = {
        SpecialistFamily.NETWORK: (
            "route inventory",
            "service exposure verification",
            "segmentation control validation",
            "approved path change validation",
        ),
        SpecialistFamily.HOST: (
            "host posture inventory",
            "authenticated configuration review",
            "local control validation",
            "reversible host setting validation",
        ),
        SpecialistFamily.CONTAINER: (
            "workload metadata inventory",
            "authenticated runtime review",
            "isolation control validation",
            "reversible workload policy validation",
        ),
        SpecialistFamily.DATABASE: (
            "service metadata inventory",
            "authenticated privilege review",
            "authorization control validation",
            "reversible database policy validation",
        ),
        SpecialistFamily.MESSAGING: (
            "broker metadata inventory",
            "authenticated queue and topic review",
            "routing authorization validation",
            "reversible messaging policy validation",
        ),
        SpecialistFamily.LATERAL_MOVEMENT: (
            "trust path inventory",
            "authenticated remote management review",
            "segmentation path validation",
            "reversible path control validation",
        ),
    }
    actions = tuple(ActionClass)
    return tuple(
        SpecialistCapabilityDeclaration(
            family=family,
            capability_ref=f"capabilityref:specialist/{family.value}",
            capability_names=names,
            supported_action_classes=actions,
            maximum_tier=ActionTier.R3,
        )
        for family, names in records.items()
    )


def _require_keys(body: Mapping[str, Any], expected: set[str]) -> None:
    if set(body) != expected:
        raise SpecialistAdapterContractError("contract fields are invalid")


def _parse_budget(body: Mapping[str, Any]) -> BudgetEnvelope:
    _require_keys(
        body,
        {
            "budget_ref",
            "maximum_requests",
            "maximum_bytes",
            "maximum_changes",
            "maximum_duration_seconds",
        },
    )
    return BudgetEnvelope(**body)


def _parse_context(body: Mapping[str, Any]) -> SpecialistExecutionContext:
    values = dict(body)
    _require_keys(
        values,
        {
            "tenant_ref",
            "mission_ref",
            "scope_ref",
            "scope_sha256",
            "target_ref",
            "target_sha256",
            "route_ref",
            "route_sha256",
            "worker_ref",
            "session_ref",
            "fence_ref",
            "fence_epoch",
            "fencing_token_sha256",
            "action_admission_ref",
            "action_admission_sha256",
            "approval_ref",
            "approval_sha256",
            "credential_lease_ref",
            "credential_lease_sha256",
            "evidence_plan_ref",
            "evidence_plan_sha256",
            "cleanup_plan_ref",
            "cleanup_plan_sha256",
            "restoration_plan_ref",
            "restoration_plan_sha256",
            "budget",
            "budget_sha256",
        },
    )
    budget_sha256 = values.pop("budget_sha256")
    budget_value = values.pop("budget")
    if not isinstance(budget_value, Mapping):
        raise SpecialistAdapterContractError("budget is invalid")
    budget = _parse_budget(budget_value)
    if budget.budget_sha256 != budget_sha256:
        raise SpecialistAdapterContractError("budget digest does not match")
    return SpecialistExecutionContext(budget=budget, **values)


def _parse_observation(body: Mapping[str, Any]) -> AdapterObservation:
    _require_keys(body, set(AdapterObservation.__dataclass_fields__))
    return AdapterObservation(**body)


def parse_contract(
    value: Mapping[str, Any],
) -> SpecialistCapabilityDeclaration | SpecialistActionRequest | SpecialistActionReceipt:
    """Parse and verify one strict declaration, request, or receipt wire record."""

    if not isinstance(value, Mapping):
        raise SpecialistAdapterContractError("contract must be a mapping")
    body = dict(value)
    kind = body.get("kind")
    if kind == "specialist_capability_declaration":
        _metadata(body, kind)
        _require_keys(
            body,
            {
                "declaration_id",
                "declaration_sha256",
                "kind",
                "schema_version",
                "boundary_effects",
                "family",
                "capability_ref",
                "capability_names",
                "supported_action_classes",
                "maximum_tier",
                "qualification_effect",
            },
        )
        record = SpecialistCapabilityDeclaration(
            family=body["family"],
            capability_ref=body["capability_ref"],
            capability_names=tuple(body["capability_names"]),
            supported_action_classes=tuple(body["supported_action_classes"]),
            maximum_tier=ActionTier[body["maximum_tier"]],
        )
        if record.to_dict() != body:
            raise SpecialistAdapterContractError("declaration identity does not match")
        return record
    if kind == "specialist_action_request":
        _metadata(body, kind)
        expected = {
            "request_id",
            "request_sha256",
            "kind",
            "schema_version",
            "boundary_effects",
            "declaration_id",
            "declaration_sha256",
            "family",
            "capability_ref",
            "action_class",
            "action_tier",
            "context",
            "context_sha256",
            "intent_sha256",
            "estimated_requests",
            "estimated_bytes",
            "estimated_changes",
            "estimated_duration_seconds",
            "idempotency_sha256",
            "issued_at",
            "expires_at",
            "qualification_effect",
        }
        _require_keys(body, expected)
        context_value = body["context"]
        if not isinstance(context_value, Mapping):
            raise SpecialistAdapterContractError("context is invalid")
        context = _parse_context(context_value)
        if context.context_sha256 != body["context_sha256"]:
            raise SpecialistAdapterContractError("context digest does not match")
        record = SpecialistActionRequest(
            declaration_id=body["declaration_id"],
            declaration_sha256=body["declaration_sha256"],
            family=body["family"],
            capability_ref=body["capability_ref"],
            action_class=body["action_class"],
            action_tier=ActionTier[body["action_tier"]],
            context=context,
            intent_sha256=body["intent_sha256"],
            estimated_requests=body["estimated_requests"],
            estimated_bytes=body["estimated_bytes"],
            estimated_changes=body["estimated_changes"],
            estimated_duration_seconds=body["estimated_duration_seconds"],
            idempotency_sha256=body["idempotency_sha256"],
            issued_at=body["issued_at"],
            expires_at=body["expires_at"],
        )
        if record.to_dict() != body:
            raise SpecialistAdapterContractError("request identity does not match")
        return record
    if kind == "specialist_action_receipt":
        _metadata(body, kind)
        expected = {
            "receipt_id",
            "receipt_sha256",
            "kind",
            "schema_version",
            "boundary_effects",
            "request_id",
            "request_sha256",
            "declaration_id",
            "declaration_sha256",
            "family",
            "capability_ref",
            "action_class",
            "action_tier",
            "context_sha256",
            "idempotency_sha256",
            "observation",
            "status",
            "qualification_effect",
        }
        _require_keys(body, expected)
        observation_value = body["observation"]
        if not isinstance(observation_value, Mapping):
            raise SpecialistAdapterContractError("observation is invalid")
        record = SpecialistActionReceipt(
            request_id=body["request_id"],
            request_sha256=body["request_sha256"],
            declaration_id=body["declaration_id"],
            declaration_sha256=body["declaration_sha256"],
            family=body["family"],
            capability_ref=body["capability_ref"],
            action_class=body["action_class"],
            action_tier=ActionTier[body["action_tier"]],
            context_sha256=body["context_sha256"],
            idempotency_sha256=body["idempotency_sha256"],
            observation=_parse_observation(observation_value),
            status=body["status"],
        )
        if record.to_dict() != body:
            raise SpecialistAdapterContractError("receipt identity does not match")
        return record
    raise SpecialistAdapterContractError("contract kind is invalid")
