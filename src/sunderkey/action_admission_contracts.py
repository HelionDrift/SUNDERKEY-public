"""Deterministic, fail-closed atomic action-admission contracts.

This module evaluates caller-supplied records and emits an inert decision. It
does not authorize, dispatch, execute, stop, restore, or contact anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_EVIDENCE_OBLIGATIONS = 32

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_use": "none",
        "dispatch": "none",
        "network": "none",
        "restoration": "none",
        "stop": "none",
        "target_action": "none",
    }
)


class ActionAdmissionContractError(ValueError):
    """Raised when an action-admission contract fails structural validation."""


class ActionTier(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class AdmissionStatus(StrEnum):
    ADMITTED_CONTRACT_ONLY = "admitted_contract_only"
    DENIED = "denied"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class TargetEnvironment(StrEnum):
    SANDBOX = "sandbox"
    REPLICA = "replica"
    LIVE = "live"


class EvidenceKind(StrEnum):
    SCOPE_AUTHORITY = "scope_authority"
    TARGET_AUTHORITY = "target_authority"
    SAFETY_REVIEW = "safety_review"
    OBSERVABILITY = "observability"
    STOP_READINESS = "stop_readiness"
    RESTORATION_READINESS = "restoration_readiness"
    CUSTODY = "custody"


class DenialReason(StrEnum):
    CONTEXT_MISMATCH = "context_mismatch"
    WORKER_SESSION_MISMATCH = "worker_session_mismatch"
    STALE_WORKER_SESSION = "stale_worker_session"
    APPROVAL_MISMATCH = "approval_mismatch"
    APPROVAL_TIER_EXCEEDED = "approval_tier_exceeded"
    STALE_APPROVAL = "stale_approval"
    CREDENTIAL_MISMATCH = "credential_mismatch"
    STALE_CREDENTIAL = "stale_credential"
    HEALTH_MISMATCH = "health_mismatch"
    WORKER_UNHEALTHY = "worker_unhealthy"
    STALE_HEALTH = "stale_health"
    BUDGET_MISMATCH = "budget_mismatch"
    BUDGET_EXCEEDED = "budget_exceeded"
    TARGET_MISMATCH = "target_mismatch"
    MISSING_EVIDENCE = "missing_evidence"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    STALE_EVIDENCE = "stale_evidence"
    STOP_CONDITION_MISMATCH = "stop_condition_mismatch"
    STALE_STOP_CONDITION = "stale_stop_condition"
    RESTORATION_DUTY_MISMATCH = "restoration_duty_mismatch"
    STALE_REQUEST = "stale_request"


_TIER_ORDER = {tier: index for index, tier in enumerate(ActionTier)}
REQUIRED_EVIDENCE = frozenset(EvidenceKind)


def canonical_json(value: Any) -> str:
    """Return canonical printable ASCII JSON."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ActionAdmissionContractError("value cannot be canonicalized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ActionAdmissionContractError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ActionAdmissionContractError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ActionAdmissionContractError(f"{label} must be an exact version")
    if value.lower() in {"auto", "current", "default", "latest", "stable"}:
        raise ActionAdmissionContractError(f"{label} must not be a moving alias")
    if not any(character.isdigit() for character in value):
        raise ActionAdmissionContractError(f"{label} must contain a version number")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ActionAdmissionContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ActionAdmissionContractError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    if _instant(_timestamp(expires_at, f"{label} expires_at")) <= _instant(
        _timestamp(issued_at, f"{label} issued_at")
    ):
        raise ActionAdmissionContractError(f"{label} expiry must follow issuance")


def _current(issued_at: str, expires_at: str, evaluated_at: datetime) -> bool:
    return _instant(issued_at) <= evaluated_at < _instant(expires_at)


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ActionAdmissionContractError(f"{label} fields are invalid")
    return raw


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ActionAdmissionContractError(f"{label} is invalid") from exc


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if raw.get("kind") != kind or raw.get("schema_version") != SCHEMA_VERSION:
        raise ActionAdmissionContractError("contract metadata is invalid")
    if raw.get("effects") != dict(NO_EFFECTS):
        raise ActionAdmissionContractError("contract attempts effect escalation")


def _canonical_document(document: str) -> Mapping[str, Any]:
    try:
        raw = json.loads(document)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ActionAdmissionContractError("document is not valid JSON") from exc
    if not isinstance(raw, Mapping) or canonical_json(raw) != document:
        raise ActionAdmissionContractError("document is not canonical JSON")
    return raw


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    artifact_ref: str
    artifact_sha256: str
    exact_version: str

    def __post_init__(self) -> None:
        _identifier(self.artifact_ref, "artifact_ref")
        _digest(self.artifact_sha256, "artifact_sha256")
        _version(self.exact_version, "exact_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "exact_version": self.exact_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ArtifactBinding:
        return cls(**_exact(raw, {"artifact_ref", "artifact_sha256", "exact_version"}, "artifact"))


@dataclass(frozen=True, slots=True)
class ContextBinding:
    tenant_id: str
    mission_id: str
    scope_id: str
    scope_sha256: str
    policy: ArtifactBinding

    def __post_init__(self) -> None:
        for label in ("tenant_id", "mission_id", "scope_id"):
            _identifier(getattr(self, label), label)
        _digest(self.scope_sha256, "scope_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "policy": self.policy.to_dict(),
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ContextBinding:
        value = dict(
            _exact(
                raw, {"mission_id", "policy", "scope_id", "scope_sha256", "tenant_id"}, "context"
            )
        )
        value["policy"] = ArtifactBinding.from_dict(value["policy"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class WorkerSession:
    worker_id: str
    worker_profile_id: str
    session_id: str
    tenant_id: str
    mission_id: str
    fence_token_sha256: str
    leader_epoch: int
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for label in ("worker_id", "worker_profile_id", "session_id", "tenant_id", "mission_id"):
            _identifier(getattr(self, label), label)
        _digest(self.fence_token_sha256, "fence_token_sha256")
        if (
            isinstance(self.leader_epoch, bool)
            or not isinstance(self.leader_epoch, int)
            or self.leader_epoch < 1
        ):
            raise ActionAdmissionContractError("leader_epoch must be a positive integer")
        _window(self.issued_at, self.expires_at, "worker session")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> WorkerSession:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "worker session"))


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    approval_id: str
    approval_sha256: str
    tenant_id: str
    mission_id: str
    scope_sha256: str
    target_sha256: str
    action_sha256: str
    worker_id: str
    session_id: str
    fence_token_sha256: str
    leader_epoch: int
    authorized_tier: ActionTier
    approver_id: str
    decision: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for label in (
            "approval_id",
            "tenant_id",
            "mission_id",
            "worker_id",
            "session_id",
            "approver_id",
        ):
            _identifier(getattr(self, label), label)
        for label in (
            "approval_sha256",
            "scope_sha256",
            "target_sha256",
            "action_sha256",
            "fence_token_sha256",
        ):
            _digest(getattr(self, label), label)
        if (
            isinstance(self.leader_epoch, bool)
            or not isinstance(self.leader_epoch, int)
            or self.leader_epoch < 1
        ):
            raise ActionAdmissionContractError("approval leader_epoch must be positive")
        object.__setattr__(
            self, "authorized_tier", _enum(ActionTier, self.authorized_tier, "authorized_tier")
        )
        if self.decision != "approved":
            raise ActionAdmissionContractError("approval decision must be approved")
        _window(self.issued_at, self.expires_at, "approval")

    def to_dict(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        value["authorized_tier"] = self.authorized_tier.value
        return value

    @classmethod
    def from_dict(cls, raw: Any) -> ApprovalBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "approval"))


@dataclass(frozen=True, slots=True)
class CredentialLease:
    lease_id: str
    credential_ref_sha256: str
    tenant_id: str
    mission_id: str
    scope_sha256: str
    worker_id: str
    session_id: str
    fence_token_sha256: str
    leader_epoch: int
    permitted_action_sha256: str
    revoked: bool
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for label in ("lease_id", "tenant_id", "mission_id", "worker_id", "session_id"):
            _identifier(getattr(self, label), label)
        for label in (
            "credential_ref_sha256",
            "scope_sha256",
            "fence_token_sha256",
            "permitted_action_sha256",
        ):
            _digest(getattr(self, label), label)
        if (
            isinstance(self.leader_epoch, bool)
            or not isinstance(self.leader_epoch, int)
            or self.leader_epoch < 1
        ):
            raise ActionAdmissionContractError("credential leader_epoch must be positive")
        if not isinstance(self.revoked, bool):
            raise ActionAdmissionContractError("revoked must be boolean")
        _window(self.issued_at, self.expires_at, "credential lease")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> CredentialLease:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "credential lease"))


@dataclass(frozen=True, slots=True)
class HealthEvidence:
    worker_id: str
    session_id: str
    fence_token_sha256: str
    leader_epoch: int
    status: HealthStatus
    evidence_sha256: str
    observed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _identifier(self.worker_id, "health worker_id")
        _identifier(self.session_id, "health session_id")
        _digest(self.fence_token_sha256, "health fence_token_sha256")
        if (
            isinstance(self.leader_epoch, bool)
            or not isinstance(self.leader_epoch, int)
            or self.leader_epoch < 1
        ):
            raise ActionAdmissionContractError("health leader_epoch must be positive")
        object.__setattr__(self, "status", _enum(HealthStatus, self.status, "health status"))
        _digest(self.evidence_sha256, "health evidence_sha256")
        _window(self.observed_at, self.expires_at, "health evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_sha256": self.evidence_sha256,
            "expires_at": self.expires_at,
            "fence_token_sha256": self.fence_token_sha256,
            "leader_epoch": self.leader_epoch,
            "observed_at": self.observed_at,
            "session_id": self.session_id,
            "status": self.status.value,
            "worker_id": self.worker_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> HealthEvidence:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "health evidence"))


@dataclass(frozen=True, slots=True)
class BudgetBinding:
    tenant_id: str
    mission_id: str
    budget_sha256: str
    request_limit: int
    requests_used: int
    token_limit: int
    tokens_used: int
    cost_limit_microunits: int
    cost_used_microunits: int
    action_request_cost: int
    action_token_cost: int
    action_cost_microunits: int

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "budget tenant_id")
        _identifier(self.mission_id, "budget mission_id")
        _digest(self.budget_sha256, "budget_sha256")
        for label in tuple(self.__dataclass_fields__)[3:]:
            value = getattr(self, label)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ActionAdmissionContractError(f"{label} must be a nonnegative integer")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> BudgetBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "budget"))


@dataclass(frozen=True, slots=True)
class TargetBinding:
    target_id: str
    target_sha256: str
    authority_sha256: str
    tenant_id: str
    mission_id: str
    scope_sha256: str
    environment: TargetEnvironment

    def __post_init__(self) -> None:
        for label in ("target_id", "tenant_id", "mission_id"):
            _identifier(getattr(self, label), label)
        for label in ("target_sha256", "authority_sha256", "scope_sha256"):
            _digest(getattr(self, label), label)
        object.__setattr__(
            self, "environment", _enum(TargetEnvironment, self.environment, "target environment")
        )

    def to_dict(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        value["environment"] = self.environment.value
        return value

    @classmethod
    def from_dict(cls, raw: Any) -> TargetBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "target"))


@dataclass(frozen=True, slots=True)
class RequestedAction:
    action_id: str
    action_type: str
    action_tier: ActionTier
    action_sha256: str
    target_sha256: str
    parameters_sha256: str
    tool: ArtifactBinding
    idempotency_key_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.action_id, "action_id")
        _identifier(self.action_type, "action_type")
        object.__setattr__(self, "action_tier", _enum(ActionTier, self.action_tier, "action_tier"))
        for label in (
            "action_sha256",
            "target_sha256",
            "parameters_sha256",
            "idempotency_key_sha256",
        ):
            _digest(getattr(self, label), label)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_sha256": self.action_sha256,
            "action_tier": self.action_tier.value,
            "action_type": self.action_type,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "parameters_sha256": self.parameters_sha256,
            "target_sha256": self.target_sha256,
            "tool": self.tool.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RequestedAction:
        value = dict(_exact(raw, set(cls.__dataclass_fields__), "requested action"))
        value["tool"] = ArtifactBinding.from_dict(value["tool"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class EvidenceObligation:
    evidence_kind: EvidenceKind
    evidence_sha256: str
    tenant_id: str
    mission_id: str
    scope_sha256: str
    target_sha256: str
    action_sha256: str
    producer_id: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_kind", _enum(EvidenceKind, self.evidence_kind, "evidence_kind")
        )
        for label in ("evidence_sha256", "scope_sha256", "target_sha256", "action_sha256"):
            _digest(getattr(self, label), label)
        for label in ("tenant_id", "mission_id", "producer_id"):
            _identifier(getattr(self, label), label)
        _window(self.issued_at, self.expires_at, "evidence obligation")

    def to_dict(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        value["evidence_kind"] = self.evidence_kind.value
        return value

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceObligation:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "evidence obligation"))


@dataclass(frozen=True, slots=True)
class StopConditions:
    stop_contract_sha256: str
    monitor_session_id: str
    monitor_worker_id: str
    scope_sha256: str
    target_sha256: str
    action_sha256: str
    maximum_impact_events: int
    stop_deadline_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for label in ("stop_contract_sha256", "scope_sha256", "target_sha256", "action_sha256"):
            _digest(getattr(self, label), label)
        _identifier(self.monitor_session_id, "monitor_session_id")
        _identifier(self.monitor_worker_id, "monitor_worker_id")
        if (
            isinstance(self.maximum_impact_events, bool)
            or not isinstance(self.maximum_impact_events, int)
            or self.maximum_impact_events < 1
        ):
            raise ActionAdmissionContractError("maximum_impact_events must be positive")
        _timestamp(self.stop_deadline_at, "stop_deadline_at")
        _timestamp(self.expires_at, "stop expires_at")
        if _instant(self.expires_at) > _instant(self.stop_deadline_at):
            raise ActionAdmissionContractError("stop expiry must not exceed stop deadline")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> StopConditions:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "stop conditions"))


@dataclass(frozen=True, slots=True)
class RestorationDuties:
    required: bool
    restoration_plan_sha256: str
    owner_profile_id: str
    verifier_profile_id: str
    scope_sha256: str
    target_sha256: str
    action_sha256: str
    completion_evidence_required: bool

    def __post_init__(self) -> None:
        if not isinstance(self.required, bool) or not isinstance(
            self.completion_evidence_required, bool
        ):
            raise ActionAdmissionContractError("restoration flags must be boolean")
        if not self.required or not self.completion_evidence_required:
            raise ActionAdmissionContractError(
                "restoration and completion evidence must be required"
            )
        for label in ("restoration_plan_sha256", "scope_sha256", "target_sha256", "action_sha256"):
            _digest(getattr(self, label), label)
        _identifier(self.owner_profile_id, "restoration owner_profile_id")
        _identifier(self.verifier_profile_id, "restoration verifier_profile_id")
        if self.owner_profile_id == self.verifier_profile_id:
            raise ActionAdmissionContractError("restoration owner and verifier must differ")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> RestorationDuties:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "restoration duties"))


@dataclass(frozen=True, slots=True)
class ActionAdmissionRequest:
    context: ContextBinding
    worker_session: WorkerSession
    approval: ApprovalBinding
    credential_lease: CredentialLease
    health: HealthEvidence
    budget: BudgetBinding
    target: TargetBinding
    action: RequestedAction
    evidence_obligations: tuple[EvidenceObligation, ...]
    stop_conditions: StopConditions
    restoration_duties: RestorationDuties
    requested_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    KIND: ClassVar[str] = "action_admission_request"

    def __post_init__(self) -> None:
        _window(self.requested_at, self.expires_at, "admission request")
        if not isinstance(self.evidence_obligations, tuple):
            raise ActionAdmissionContractError("evidence_obligations must be a tuple")
        if not 1 <= len(self.evidence_obligations) <= MAX_EVIDENCE_OBLIGATIONS:
            raise ActionAdmissionContractError("evidence_obligations count is invalid")
        kinds = tuple(item.evidence_kind.value for item in self.evidence_obligations)
        if kinds != tuple(sorted(kinds)) or len(set(kinds)) != len(kinds):
            raise ActionAdmissionContractError("evidence_obligations must be unique and canonical")
        body = self._body()
        record_id, digest = _identity("AAR", self.KIND, body)
        if self.request_id and self.request_id != record_id:
            raise ActionAdmissionContractError("request_id does not match content")
        if self.request_sha256 and self.request_sha256 != digest:
            raise ActionAdmissionContractError("request_sha256 does not match content")
        object.__setattr__(self, "request_id", record_id)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "approval": self.approval.to_dict(),
            "budget": self.budget.to_dict(),
            "context": self.context.to_dict(),
            "credential_lease": self.credential_lease.to_dict(),
            "effects": dict(NO_EFFECTS),
            "evidence_obligations": [item.to_dict() for item in self.evidence_obligations],
            "expires_at": self.expires_at,
            "health": self.health.to_dict(),
            "kind": self.KIND,
            "requested_at": self.requested_at,
            "restoration_duties": self.restoration_duties.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "stop_conditions": self.stop_conditions.to_dict(),
            "target": self.target.to_dict(),
            "worker_session": self.worker_session.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> ActionAdmissionRequest:
        fields = {
            "action",
            "approval",
            "budget",
            "context",
            "credential_lease",
            "effects",
            "evidence_obligations",
            "expires_at",
            "health",
            "kind",
            "request_id",
            "request_sha256",
            "requested_at",
            "restoration_duties",
            "schema_version",
            "stop_conditions",
            "target",
            "worker_session",
        }
        value = dict(_exact(raw, fields, "admission request"))
        _metadata(value, cls.KIND)
        raw_evidence = value.pop("evidence_obligations")
        if not isinstance(raw_evidence, list):
            raise ActionAdmissionContractError("evidence_obligations must be an array")
        value.pop("effects")
        value.pop("kind")
        value.pop("schema_version")
        value["context"] = ContextBinding.from_dict(value["context"])
        value["worker_session"] = WorkerSession.from_dict(value["worker_session"])
        value["approval"] = ApprovalBinding.from_dict(value["approval"])
        value["credential_lease"] = CredentialLease.from_dict(value["credential_lease"])
        value["health"] = HealthEvidence.from_dict(value["health"])
        value["budget"] = BudgetBinding.from_dict(value["budget"])
        value["target"] = TargetBinding.from_dict(value["target"])
        value["action"] = RequestedAction.from_dict(value["action"])
        value["evidence_obligations"] = tuple(
            EvidenceObligation.from_dict(item) for item in raw_evidence
        )
        value["stop_conditions"] = StopConditions.from_dict(value["stop_conditions"])
        value["restoration_duties"] = RestorationDuties.from_dict(value["restoration_duties"])
        candidate = cls(**value)
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise ActionAdmissionContractError("admission request is not canonical")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> ActionAdmissionRequest:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class ActionAdmissionDecision:
    request_id: str
    request_sha256: str
    evaluated_at: str
    status: AdmissionStatus
    denial_reasons: tuple[DenialReason, ...]
    tenant_id: str
    mission_id: str
    scope_sha256: str
    worker_id: str
    session_id: str
    fence_token_sha256: str
    approval_sha256: str
    credential_lease_id: str
    target_sha256: str
    action_sha256: str
    decision_id: str = ""
    decision_sha256: str = ""

    KIND: ClassVar[str] = "action_admission_decision"

    def __post_init__(self) -> None:
        for label in (
            "request_id",
            "tenant_id",
            "mission_id",
            "worker_id",
            "session_id",
            "credential_lease_id",
        ):
            _identifier(getattr(self, label), label)
        for label in (
            "request_sha256",
            "scope_sha256",
            "fence_token_sha256",
            "approval_sha256",
            "target_sha256",
            "action_sha256",
        ):
            _digest(getattr(self, label), label)
        _timestamp(self.evaluated_at, "evaluated_at")
        object.__setattr__(self, "status", _enum(AdmissionStatus, self.status, "admission status"))
        reasons = tuple(_enum(DenialReason, item, "denial reason") for item in self.denial_reasons)
        if reasons != tuple(sorted(set(reasons), key=lambda item: item.value)):
            raise ActionAdmissionContractError("denial_reasons must be unique and canonical")
        if (self.status is AdmissionStatus.DENIED) != bool(reasons):
            raise ActionAdmissionContractError("status and denial_reasons disagree")
        object.__setattr__(self, "denial_reasons", reasons)
        record_id, digest = _identity("AAD", self.KIND, self._body())
        if self.decision_id and self.decision_id != record_id:
            raise ActionAdmissionContractError("decision_id does not match content")
        if self.decision_sha256 and self.decision_sha256 != digest:
            raise ActionAdmissionContractError("decision_sha256 does not match content")
        object.__setattr__(self, "decision_id", record_id)
        object.__setattr__(self, "decision_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "approval_sha256": self.approval_sha256,
            "credential_lease_id": self.credential_lease_id,
            "denial_reasons": [item.value for item in self.denial_reasons],
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "fence_token_sha256": self.fence_token_sha256,
            "kind": self.KIND,
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "session_id": self.session_id,
            "status": self.status.value,
            "target_sha256": self.target_sha256,
            "tenant_id": self.tenant_id,
            "worker_id": self.worker_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> ActionAdmissionDecision:
        fields = {
            "action_sha256",
            "approval_sha256",
            "credential_lease_id",
            "decision_id",
            "decision_sha256",
            "denial_reasons",
            "effects",
            "evaluated_at",
            "fence_token_sha256",
            "kind",
            "mission_id",
            "request_id",
            "request_sha256",
            "schema_version",
            "scope_sha256",
            "session_id",
            "status",
            "target_sha256",
            "tenant_id",
            "worker_id",
        }
        value = dict(_exact(raw, fields, "admission decision"))
        _metadata(value, cls.KIND)
        raw_reasons = value.pop("denial_reasons")
        if not isinstance(raw_reasons, list):
            raise ActionAdmissionContractError("denial_reasons must be an array")
        value["denial_reasons"] = tuple(raw_reasons)
        value.pop("effects")
        value.pop("kind")
        value.pop("schema_version")
        candidate = cls(**value)
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise ActionAdmissionContractError("admission decision is not canonical")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> ActionAdmissionDecision:
        return cls.from_dict(_canonical_document(document))


def evaluate_action_admission(
    request: ActionAdmissionRequest,
    *,
    evaluated_at: str,
) -> ActionAdmissionDecision:
    """Evaluate every admission prerequisite atomically with no side effects."""

    evaluated = _instant(_timestamp(evaluated_at, "evaluated_at"))
    context = request.context
    worker = request.worker_session
    approval = request.approval
    credential = request.credential_lease
    health = request.health
    budget = request.budget
    target = request.target
    action = request.action
    stop = request.stop_conditions
    restoration = request.restoration_duties
    reasons: set[DenialReason] = set()

    if not (
        worker.tenant_id
        == approval.tenant_id
        == credential.tenant_id
        == budget.tenant_id
        == target.tenant_id
        == context.tenant_id
        and worker.mission_id
        == approval.mission_id
        == credential.mission_id
        == budget.mission_id
        == target.mission_id
        == context.mission_id
    ):
        reasons.add(DenialReason.CONTEXT_MISMATCH)
    if not (worker.worker_id == approval.worker_id == credential.worker_id):
        reasons.add(DenialReason.WORKER_SESSION_MISMATCH)
    if not (
        worker.session_id == approval.session_id == credential.session_id
        and worker.fence_token_sha256
        == approval.fence_token_sha256
        == credential.fence_token_sha256
        and worker.leader_epoch == approval.leader_epoch == credential.leader_epoch
    ):
        reasons.add(DenialReason.WORKER_SESSION_MISMATCH)
    if not _current(worker.issued_at, worker.expires_at, evaluated):
        reasons.add(DenialReason.STALE_WORKER_SESSION)

    if not (
        approval.scope_sha256 == context.scope_sha256
        and approval.target_sha256 == target.target_sha256
        and approval.action_sha256 == action.action_sha256
    ):
        reasons.add(DenialReason.APPROVAL_MISMATCH)
    if _TIER_ORDER[action.action_tier] > _TIER_ORDER[approval.authorized_tier]:
        reasons.add(DenialReason.APPROVAL_TIER_EXCEEDED)
    if not _current(approval.issued_at, approval.expires_at, evaluated):
        reasons.add(DenialReason.STALE_APPROVAL)

    if not (
        credential.scope_sha256 == context.scope_sha256
        and credential.permitted_action_sha256 == action.action_sha256
        and not credential.revoked
    ):
        reasons.add(DenialReason.CREDENTIAL_MISMATCH)
    if not _current(credential.issued_at, credential.expires_at, evaluated):
        reasons.add(DenialReason.STALE_CREDENTIAL)

    if not (
        health.worker_id == worker.worker_id
        and health.session_id == worker.session_id
        and health.fence_token_sha256 == worker.fence_token_sha256
        and health.leader_epoch == worker.leader_epoch
    ):
        reasons.add(DenialReason.HEALTH_MISMATCH)
    if health.status is not HealthStatus.HEALTHY:
        reasons.add(DenialReason.WORKER_UNHEALTHY)
    if not _current(health.observed_at, health.expires_at, evaluated):
        reasons.add(DenialReason.STALE_HEALTH)

    if budget.tenant_id != context.tenant_id or budget.mission_id != context.mission_id:
        reasons.add(DenialReason.BUDGET_MISMATCH)
    if (
        budget.requests_used + budget.action_request_cost > budget.request_limit
        or budget.tokens_used + budget.action_token_cost > budget.token_limit
        or budget.cost_used_microunits + budget.action_cost_microunits
        > budget.cost_limit_microunits
    ):
        reasons.add(DenialReason.BUDGET_EXCEEDED)
    if action.target_sha256 != target.target_sha256 or target.scope_sha256 != context.scope_sha256:
        reasons.add(DenialReason.TARGET_MISMATCH)

    evidence_kinds = {item.evidence_kind for item in request.evidence_obligations}
    if evidence_kinds != REQUIRED_EVIDENCE:
        reasons.add(DenialReason.MISSING_EVIDENCE)
    for evidence in request.evidence_obligations:
        if not (
            evidence.tenant_id == context.tenant_id
            and evidence.mission_id == context.mission_id
            and evidence.scope_sha256 == context.scope_sha256
            and evidence.target_sha256 == target.target_sha256
            and evidence.action_sha256 == action.action_sha256
        ):
            reasons.add(DenialReason.EVIDENCE_MISMATCH)
        if not _current(evidence.issued_at, evidence.expires_at, evaluated):
            reasons.add(DenialReason.STALE_EVIDENCE)

    if not (
        stop.scope_sha256 == context.scope_sha256
        and stop.target_sha256 == target.target_sha256
        and stop.action_sha256 == action.action_sha256
        and stop.monitor_session_id != worker.session_id
        and stop.monitor_worker_id != worker.worker_id
    ):
        reasons.add(DenialReason.STOP_CONDITION_MISMATCH)
    if evaluated >= _instant(stop.expires_at) or evaluated >= _instant(stop.stop_deadline_at):
        reasons.add(DenialReason.STALE_STOP_CONDITION)

    if not (
        restoration.scope_sha256 == context.scope_sha256
        and restoration.target_sha256 == target.target_sha256
        and restoration.action_sha256 == action.action_sha256
    ):
        reasons.add(DenialReason.RESTORATION_DUTY_MISMATCH)
    if not _current(request.requested_at, request.expires_at, evaluated):
        reasons.add(DenialReason.STALE_REQUEST)

    ordered = tuple(sorted(reasons, key=lambda item: item.value))
    return ActionAdmissionDecision(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        evaluated_at=evaluated_at,
        status=AdmissionStatus.DENIED if ordered else AdmissionStatus.ADMITTED_CONTRACT_ONLY,
        denial_reasons=ordered,
        tenant_id=context.tenant_id,
        mission_id=context.mission_id,
        scope_sha256=context.scope_sha256,
        worker_id=worker.worker_id,
        session_id=worker.session_id,
        fence_token_sha256=worker.fence_token_sha256,
        approval_sha256=approval.approval_sha256,
        credential_lease_id=credential.lease_id,
        target_sha256=target.target_sha256,
        action_sha256=action.action_sha256,
    )


def parse_contract(document: str) -> ActionAdmissionRequest | ActionAdmissionDecision:
    """Parse canonical JSON into the declared action-admission contract."""

    raw = _canonical_document(document)
    if raw.get("kind") == ActionAdmissionRequest.KIND:
        return ActionAdmissionRequest.from_dict(raw)
    if raw.get("kind") == ActionAdmissionDecision.KIND:
        return ActionAdmissionDecision.from_dict(raw)
    raise ActionAdmissionContractError("contract kind is invalid")
