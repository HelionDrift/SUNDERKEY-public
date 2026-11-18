"""Critical-role redundancy and advanced-domain activation contracts.

The contracts in this module evaluate caller-supplied, content-addressed
records. They do not route work, activate a domain, authorize an action,
contact a target, deploy a worker, or change qualification state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 64

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = MappingProxyType(
    {
        "activation": "none",
        "authorization": "none",
        "deployment": "none",
        "network": "none",
        "qualification": "none",
        "routing": "none",
        "target_action": "none",
    }
)


class AdvancedDomainGateError(ValueError):
    """Raised when an advanced-domain contract fails closed."""


class CriticalRole(StrEnum):
    DOMAIN_COMMAND = "domain_command"
    SAFETY = "safety"
    VALIDATION = "validation"
    HIGH_VALUE_SPECIALTY = "high_value_specialty"


class RuntimeKind(StrEnum):
    HUMAN = "human"
    MODEL = "model"
    HYBRID = "hybrid"


class AdvancedDomain(StrEnum):
    OT_CYBER_PHYSICAL = "ot_cyber_physical"
    HEALTHCARE = "healthcare"
    TRANSPORT = "transport"
    SPECIALIZED_PROTOCOLS = "specialized_protocols"
    MODEL_INFRASTRUCTURE = "model_infrastructure"
    OTHER_HIGH_RISK = "other_high_risk"


class EnvironmentClass(StrEnum):
    SIMULATOR = "simulator"
    REPLICA = "replica"
    LIVE = "live"


class ActionTier(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class EvidenceKind(StrEnum):
    HAZARD_ANALYSIS = "hazard_analysis"
    SIMULATOR_OR_REPLICA = "simulator_or_replica"
    TARGET_AUTHORITY = "target_authority"
    MONITORING = "monitoring"
    STOP = "stop"
    CLEANUP = "cleanup"
    RESTORATION = "restoration"
    CUSTODY = "custody"


class ReviewerRole(StrEnum):
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


class GateStatus(StrEnum):
    DENIED = "denied"
    CONTRACT_READY_UNVERIFIED = "contract_ready_unverified"


EXPECTED_COMMANDERS = MappingProxyType(
    {
        AdvancedDomain.OT_CYBER_PHYSICAL: "AOE-GD-D19-CMD",
        AdvancedDomain.HEALTHCARE: "AOE-GD-D25-CMD",
        AdvancedDomain.TRANSPORT: "AOE-GD-D25-CMD",
        AdvancedDomain.SPECIALIZED_PROTOCOLS: "AOE-GE-D22-CMD",
        AdvancedDomain.MODEL_INFRASTRUCTURE: "AOE-GD-D20-CMD",
    }
)

MAXIMUM_DOMAIN_TIERS = MappingProxyType(
    {
        AdvancedDomain.OT_CYBER_PHYSICAL: ActionTier.R0,
        AdvancedDomain.HEALTHCARE: ActionTier.R0,
        AdvancedDomain.TRANSPORT: ActionTier.R0,
        AdvancedDomain.SPECIALIZED_PROTOCOLS: ActionTier.R1,
        AdvancedDomain.MODEL_INFRASTRUCTURE: ActionTier.R1,
        AdvancedDomain.OTHER_HIGH_RISK: ActionTier.R0,
    }
)

REQUIRED_EVIDENCE_KINDS = frozenset(EvidenceKind)
_TIER_ORDER = {tier: index for index, tier in enumerate(ActionTier)}


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AdvancedDomainGateError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise AdvancedDomainGateError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AdvancedDomainGateError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise AdvancedDomainGateError(f"{label} must be an exact version")
    if value.lower() in {"auto", "current", "default", "latest", "stable"}:
        raise AdvancedDomainGateError(f"{label} must not be a moving alias")
    if not any(character.isdigit() for character in value):
        raise AdvancedDomainGateError(f"{label} must contain a version number")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AdvancedDomainGateError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AdvancedDomainGateError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise AdvancedDomainGateError(f"{label} is invalid") from exc


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise AdvancedDomainGateError(f"{label} fields are invalid")
    return raw


def _window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _instant(_timestamp(issued_at, f"{label} issued_at"))
    expires = _instant(_timestamp(expires_at, f"{label} expires_at"))
    if expires <= issued:
        raise AdvancedDomainGateError(f"{label} expiry must follow issuance")


def _current(issued_at: str, expires_at: str, evaluated_at: datetime) -> bool:
    return _instant(issued_at) <= evaluated_at < _instant(expires_at)


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if raw.get("kind") != kind or raw.get("schema_version") != SCHEMA_VERSION:
        raise AdvancedDomainGateError("contract metadata is invalid")
    if raw.get("effects") != dict(NO_EFFECTS):
        raise AdvancedDomainGateError("contract attempts effect escalation")


def _verify(raw: Mapping[str, Any], candidate: Any) -> Any:
    if dict(raw) != candidate.to_dict():
        raise AdvancedDomainGateError("record identity or contents are invalid")
    return candidate


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
        value = _exact(raw, {"artifact_ref", "artifact_sha256", "exact_version"}, "artifact")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class QualificationEvidence:
    artifact: ArtifactBinding
    decision: str
    qualified_at: str
    expires_at: str
    reviewer_profile_id: str

    def __post_init__(self) -> None:
        if self.decision != "qualified":
            raise AdvancedDomainGateError("qualification decision must be qualified")
        _identifier(self.reviewer_profile_id, "qualification reviewer_profile_id")
        _window(self.qualified_at, self.expires_at, "qualification evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "decision": self.decision,
            "expires_at": self.expires_at,
            "qualified_at": self.qualified_at,
            "reviewer_profile_id": self.reviewer_profile_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationEvidence:
        value = dict(
            _exact(
                raw,
                {"artifact", "decision", "expires_at", "qualified_at", "reviewer_profile_id"},
                "qualification evidence",
            )
        )
        value["artifact"] = ArtifactBinding.from_dict(value["artifact"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class RoleCandidate:
    candidate_id: str
    profile_id: str
    runtime_kind: RuntimeKind | str
    maintainer_id: str
    failure_domain_id: str
    qualification: QualificationEvidence
    provider_id: str | None = None
    model_id: str | None = None
    model_version: str | None = None

    def __post_init__(self) -> None:
        for name in ("candidate_id", "profile_id", "maintainer_id", "failure_domain_id"):
            _identifier(getattr(self, name), name)
        runtime_kind = _enum(RuntimeKind, self.runtime_kind, "runtime_kind")
        object.__setattr__(self, "runtime_kind", runtime_kind)
        if self.qualification.reviewer_profile_id in {
            self.candidate_id,
            self.profile_id,
            self.maintainer_id,
        }:
            raise AdvancedDomainGateError("candidate cannot review its own qualification")
        if runtime_kind is RuntimeKind.HUMAN:
            if any(
                value is not None for value in (self.provider_id, self.model_id, self.model_version)
            ):
                raise AdvancedDomainGateError("human candidate cannot carry model bindings")
        else:
            if None in (self.provider_id, self.model_id, self.model_version):
                raise AdvancedDomainGateError("model-backed candidate requires provider and model")
            _identifier(self.provider_id, "provider_id")
            _identifier(self.model_id, "model_id")
            _version(self.model_version, "model_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "failure_domain_id": self.failure_domain_id,
            "maintainer_id": self.maintainer_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "profile_id": self.profile_id,
            "provider_id": self.provider_id,
            "qualification": self.qualification.to_dict(),
            "runtime_kind": self.runtime_kind.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RoleCandidate:
        value = dict(
            _exact(
                raw,
                {
                    "candidate_id",
                    "failure_domain_id",
                    "maintainer_id",
                    "model_id",
                    "model_version",
                    "profile_id",
                    "provider_id",
                    "qualification",
                    "runtime_kind",
                },
                "role candidate",
            )
        )
        value["qualification"] = QualificationEvidence.from_dict(value["qualification"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class CriticalRolePair:
    role: CriticalRole | str
    primary: RoleCandidate
    alternate: RoleCandidate

    def __post_init__(self) -> None:
        role = _enum(CriticalRole, self.role, "critical role")
        object.__setattr__(self, "role", role)
        if self.primary.candidate_id == self.alternate.candidate_id:
            raise AdvancedDomainGateError("critical role primary and alternate must be distinct")
        if self.primary.failure_domain_id == self.alternate.failure_domain_id:
            raise AdvancedDomainGateError("critical role candidates share a failure domain")
        if self.primary.maintainer_id == self.alternate.maintainer_id:
            raise AdvancedDomainGateError("critical role candidates share a maintainer")
        if self.primary.qualification.reviewer_profile_id == self.alternate.candidate_id:
            raise AdvancedDomainGateError("alternate cannot qualify the primary candidate")
        if self.alternate.qualification.reviewer_profile_id == self.primary.candidate_id:
            raise AdvancedDomainGateError("primary cannot qualify the alternate candidate")
        if (
            self.primary.runtime_kind is not RuntimeKind.HUMAN
            and self.alternate.runtime_kind is not RuntimeKind.HUMAN
            and self.primary.provider_id == self.alternate.provider_id
        ):
            raise AdvancedDomainGateError("model-backed alternatives must use distinct providers")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alternate": self.alternate.to_dict(),
            "primary": self.primary.to_dict(),
            "role": self.role.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CriticalRolePair:
        value = dict(_exact(raw, {"alternate", "primary", "role"}, "critical role pair"))
        value["primary"] = RoleCandidate.from_dict(value["primary"])
        value["alternate"] = RoleCandidate.from_dict(value["alternate"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class CriticalRoleRoster:
    army_registry: ArtifactBinding
    qualification_standard: ArtifactBinding
    role_pairs: tuple[CriticalRolePair, ...]
    issued_at: str
    expires_at: str
    roster_id: str = field(init=False)
    roster_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.critical-role-roster.v1"

    def __post_init__(self) -> None:
        _window(self.issued_at, self.expires_at, "critical role roster")
        pairs = tuple(sorted(self.role_pairs, key=lambda item: item.role.value))
        if len(pairs) != len(CriticalRole) or {item.role for item in pairs} != set(CriticalRole):
            raise AdvancedDomainGateError("roster must contain every critical role exactly once")
        candidate_ids = [
            candidate.candidate_id for pair in pairs for candidate in (pair.primary, pair.alternate)
        ]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise AdvancedDomainGateError("critical candidates cannot be aliased across roles")
        object.__setattr__(self, "role_pairs", pairs)
        record_id, digest = _identity("ACR", self.KIND, self._body())
        object.__setattr__(self, "roster_id", record_id)
        object.__setattr__(self, "roster_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "army_registry": self.army_registry.to_dict(),
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "qualification_standard": self.qualification_standard.to_dict(),
            "role_pairs": [item.to_dict() for item in self.role_pairs],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "roster_id": self.roster_id,
            "roster_sha256": self.roster_sha256,
            **self._body(),
            "effects": dict(NO_EFFECTS),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> CriticalRoleRoster:
        fields = {
            "army_registry",
            "effects",
            "expires_at",
            "issued_at",
            "kind",
            "qualification_standard",
            "role_pairs",
            "roster_id",
            "roster_sha256",
            "schema_version",
        }
        value = _exact(raw, fields, "critical role roster")
        _metadata(value, cls.KIND)
        candidate = cls(
            army_registry=ArtifactBinding.from_dict(value["army_registry"]),
            qualification_standard=ArtifactBinding.from_dict(value["qualification_standard"]),
            role_pairs=tuple(CriticalRolePair.from_dict(item) for item in value["role_pairs"]),
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
        )
        return _verify(value, candidate)

    @classmethod
    def from_json(cls, raw: str) -> CriticalRoleRoster:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class DomainSafetyPolicy:
    domain: AdvancedDomain | str
    domain_commander_profile_id: str
    maximum_action_tier: ActionTier | str
    roster_id: str
    roster_sha256: str
    hazard_method: ArtifactBinding
    simulator_requirements: ArtifactBinding
    monitoring_contract: ArtifactBinding
    stop_contract: ArtifactBinding
    cleanup_contract: ArtifactBinding
    restoration_contract: ArtifactBinding
    custody_contract: ArtifactBinding
    issued_at: str
    expires_at: str
    policy_id: str = field(init=False)
    policy_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.advanced-domain-safety-policy.v1"

    def __post_init__(self) -> None:
        domain = _enum(AdvancedDomain, self.domain, "advanced domain")
        tier = _enum(ActionTier, self.maximum_action_tier, "maximum_action_tier")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "maximum_action_tier", tier)
        _identifier(self.domain_commander_profile_id, "domain_commander_profile_id")
        expected = EXPECTED_COMMANDERS.get(domain)
        if expected is not None and self.domain_commander_profile_id != expected:
            raise AdvancedDomainGateError("domain commander does not match Army v2")
        if expected is None and not self.domain_commander_profile_id.endswith("-CMD"):
            raise AdvancedDomainGateError("other high-risk domain requires a domain commander")
        if tier is not MAXIMUM_DOMAIN_TIERS[domain]:
            raise AdvancedDomainGateError("domain action-tier ceiling is unsafe")
        _identifier(self.roster_id, "roster_id")
        _digest(self.roster_sha256, "roster_sha256")
        _window(self.issued_at, self.expires_at, "domain safety policy")
        record_id, digest = _identity("ADP", self.KIND, self._body())
        object.__setattr__(self, "policy_id", record_id)
        object.__setattr__(self, "policy_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cleanup_contract": self.cleanup_contract.to_dict(),
            "custody_contract": self.custody_contract.to_dict(),
            "domain": self.domain.value,
            "domain_commander_profile_id": self.domain_commander_profile_id,
            "expires_at": self.expires_at,
            "hazard_method": self.hazard_method.to_dict(),
            "issued_at": self.issued_at,
            "maximum_action_tier": self.maximum_action_tier.value,
            "monitoring_contract": self.monitoring_contract.to_dict(),
            "restoration_contract": self.restoration_contract.to_dict(),
            "roster_id": self.roster_id,
            "roster_sha256": self.roster_sha256,
            "simulator_requirements": self.simulator_requirements.to_dict(),
            "stop_contract": self.stop_contract.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            **self._body(),
            "effects": dict(NO_EFFECTS),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DomainSafetyPolicy:
        fields = {
            "cleanup_contract",
            "custody_contract",
            "domain",
            "domain_commander_profile_id",
            "effects",
            "expires_at",
            "hazard_method",
            "issued_at",
            "kind",
            "maximum_action_tier",
            "monitoring_contract",
            "policy_id",
            "policy_sha256",
            "restoration_contract",
            "roster_id",
            "roster_sha256",
            "schema_version",
            "simulator_requirements",
            "stop_contract",
        }
        value = _exact(raw, fields, "domain safety policy")
        _metadata(value, cls.KIND)
        kwargs = {
            name: ArtifactBinding.from_dict(value[name])
            for name in (
                "cleanup_contract",
                "custody_contract",
                "hazard_method",
                "monitoring_contract",
                "restoration_contract",
                "simulator_requirements",
                "stop_contract",
            )
        }
        candidate = cls(
            domain=value["domain"],
            domain_commander_profile_id=value["domain_commander_profile_id"],
            maximum_action_tier=value["maximum_action_tier"],
            roster_id=value["roster_id"],
            roster_sha256=value["roster_sha256"],
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
            **kwargs,
        )
        return _verify(value, candidate)

    @classmethod
    def from_json(cls, raw: str) -> DomainSafetyPolicy:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class SafetyEvidence:
    evidence_kind: EvidenceKind | str
    artifact: ArtifactBinding
    producer_profile_id: str
    reviewer_profile_id: str
    policy_sha256: str
    scope_sha256: str
    action_tier: ActionTier | str
    environment: EnvironmentClass | str
    disposition: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        kind = _enum(EvidenceKind, self.evidence_kind, "evidence_kind")
        tier = _enum(ActionTier, self.action_tier, "evidence action_tier")
        environment = _enum(EnvironmentClass, self.environment, "evidence environment")
        object.__setattr__(self, "evidence_kind", kind)
        object.__setattr__(self, "action_tier", tier)
        object.__setattr__(self, "environment", environment)
        _identifier(self.producer_profile_id, "evidence producer_profile_id")
        _identifier(self.reviewer_profile_id, "evidence reviewer_profile_id")
        if self.producer_profile_id == self.reviewer_profile_id:
            raise AdvancedDomainGateError("safety evidence cannot be self-reviewed")
        _digest(self.policy_sha256, "evidence policy_sha256")
        _digest(self.scope_sha256, "evidence scope_sha256")
        if self.disposition != "accepted":
            raise AdvancedDomainGateError("safety evidence disposition must be accepted")
        _window(self.issued_at, self.expires_at, "safety evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier.value,
            "artifact": self.artifact.to_dict(),
            "disposition": self.disposition,
            "environment": self.environment.value,
            "evidence_kind": self.evidence_kind.value,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "policy_sha256": self.policy_sha256,
            "producer_profile_id": self.producer_profile_id,
            "reviewer_profile_id": self.reviewer_profile_id,
            "scope_sha256": self.scope_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SafetyEvidence:
        fields = {
            "action_tier",
            "artifact",
            "disposition",
            "environment",
            "evidence_kind",
            "expires_at",
            "issued_at",
            "policy_sha256",
            "producer_profile_id",
            "reviewer_profile_id",
            "scope_sha256",
        }
        value = dict(_exact(raw, fields, "safety evidence"))
        value["artifact"] = ArtifactBinding.from_dict(value["artifact"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class IndependentReview:
    reviewer_role: ReviewerRole | str
    reviewer_profile_id: str
    activation_basis_sha256: str
    artifact: ArtifactBinding
    decision: str
    reviewed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        role = _enum(ReviewerRole, self.reviewer_role, "reviewer_role")
        object.__setattr__(self, "reviewer_role", role)
        _identifier(self.reviewer_profile_id, "reviewer_profile_id")
        _digest(self.activation_basis_sha256, "activation_basis_sha256")
        if self.decision != "accepted":
            raise AdvancedDomainGateError("independent review decision must be accepted")
        _window(self.reviewed_at, self.expires_at, "independent review")

    def to_dict(self) -> dict[str, Any]:
        return {
            "activation_basis_sha256": self.activation_basis_sha256,
            "artifact": self.artifact.to_dict(),
            "decision": self.decision,
            "expires_at": self.expires_at,
            "reviewed_at": self.reviewed_at,
            "reviewer_profile_id": self.reviewer_profile_id,
            "reviewer_role": self.reviewer_role.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentReview:
        fields = {
            "activation_basis_sha256",
            "artifact",
            "decision",
            "expires_at",
            "reviewed_at",
            "reviewer_profile_id",
            "reviewer_role",
        }
        value = dict(_exact(raw, fields, "independent review"))
        value["artifact"] = ArtifactBinding.from_dict(value["artifact"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class CanaryAdmission:
    admission_ref: str
    admission_sha256: str
    canary_evidence: ArtifactBinding
    policy_sha256: str
    scope_sha256: str
    action_tier: ActionTier | str
    decision: str
    decision_maker_profile_id: str
    independent_reviewer_profile_id: str
    admitted_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _identifier(self.admission_ref, "admission_ref")
        _digest(self.admission_sha256, "admission_sha256")
        _digest(self.policy_sha256, "canary policy_sha256")
        _digest(self.scope_sha256, "canary scope_sha256")
        object.__setattr__(
            self, "action_tier", _enum(ActionTier, self.action_tier, "canary action_tier")
        )
        if self.decision != "admitted":
            raise AdvancedDomainGateError("canary decision must be admitted")
        _identifier(self.decision_maker_profile_id, "canary decision_maker_profile_id")
        _identifier(self.independent_reviewer_profile_id, "canary reviewer_profile_id")
        if self.decision_maker_profile_id == self.independent_reviewer_profile_id:
            raise AdvancedDomainGateError("canary admission requires separate review")
        _window(self.admitted_at, self.expires_at, "canary admission")
        body = self._body()
        expected = canonical_sha256(
            {"content": body, "domain": "sunderkey.advanced-domain-canary-admission.v1"}
        )
        if self.admission_sha256 != expected:
            raise AdvancedDomainGateError("canary admission hash does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier.value,
            "admission_ref": self.admission_ref,
            "admitted_at": self.admitted_at,
            "canary_evidence": self.canary_evidence.to_dict(),
            "decision": self.decision,
            "decision_maker_profile_id": self.decision_maker_profile_id,
            "expires_at": self.expires_at,
            "independent_reviewer_profile_id": self.independent_reviewer_profile_id,
            "policy_sha256": self.policy_sha256,
            "scope_sha256": self.scope_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"admission_sha256": self.admission_sha256, **self._body()}

    @classmethod
    def build(
        cls,
        *,
        admission_ref: str,
        canary_evidence: ArtifactBinding,
        policy_sha256: str,
        scope_sha256: str,
        action_tier: ActionTier | str,
        decision_maker_profile_id: str,
        independent_reviewer_profile_id: str,
        admitted_at: str,
        expires_at: str,
    ) -> CanaryAdmission:
        tier = _enum(ActionTier, action_tier, "canary action_tier")
        body = {
            "action_tier": tier.value,
            "admission_ref": admission_ref,
            "admitted_at": admitted_at,
            "canary_evidence": canary_evidence.to_dict(),
            "decision": "admitted",
            "decision_maker_profile_id": decision_maker_profile_id,
            "expires_at": expires_at,
            "independent_reviewer_profile_id": independent_reviewer_profile_id,
            "policy_sha256": policy_sha256,
            "scope_sha256": scope_sha256,
        }
        digest = canonical_sha256(
            {"content": body, "domain": "sunderkey.advanced-domain-canary-admission.v1"}
        )
        return cls(
            admission_ref=admission_ref,
            admission_sha256=digest,
            canary_evidence=canary_evidence,
            policy_sha256=policy_sha256,
            scope_sha256=scope_sha256,
            action_tier=tier,
            decision="admitted",
            decision_maker_profile_id=decision_maker_profile_id,
            independent_reviewer_profile_id=independent_reviewer_profile_id,
            admitted_at=admitted_at,
            expires_at=expires_at,
        )

    @classmethod
    def from_dict(cls, raw: Any) -> CanaryAdmission:
        fields = {
            "action_tier",
            "admission_ref",
            "admission_sha256",
            "admitted_at",
            "canary_evidence",
            "decision",
            "decision_maker_profile_id",
            "expires_at",
            "independent_reviewer_profile_id",
            "policy_sha256",
            "scope_sha256",
        }
        value = dict(_exact(raw, fields, "canary admission"))
        value["canary_evidence"] = ArtifactBinding.from_dict(value["canary_evidence"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class DomainActivationRequest:
    requester_profile_id: str
    domain: AdvancedDomain | str
    domain_commander_profile_id: str
    environment: EnvironmentClass | str
    requested_action_tier: ActionTier | str
    policy_id: str
    policy_sha256: str
    roster_id: str
    roster_sha256: str
    scope: ArtifactBinding
    target_authority: ArtifactBinding
    deployment_profile: ArtifactBinding
    evidence: tuple[SafetyEvidence, ...]
    independent_reviews: tuple[IndependentReview, ...]
    canary_admission: CanaryAdmission | None
    requested_at: str
    expires_at: str
    activation_basis_sha256: str = field(init=False)
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.advanced-domain-activation-request.v1"

    def __post_init__(self) -> None:
        _identifier(self.requester_profile_id, "requester_profile_id")
        _identifier(self.domain_commander_profile_id, "domain_commander_profile_id")
        object.__setattr__(self, "domain", _enum(AdvancedDomain, self.domain, "domain"))
        object.__setattr__(
            self, "environment", _enum(EnvironmentClass, self.environment, "environment")
        )
        object.__setattr__(
            self,
            "requested_action_tier",
            _enum(ActionTier, self.requested_action_tier, "requested_action_tier"),
        )
        _identifier(self.policy_id, "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _identifier(self.roster_id, "roster_id")
        _digest(self.roster_sha256, "roster_sha256")
        _window(self.requested_at, self.expires_at, "activation request")
        evidence = tuple(sorted(self.evidence, key=lambda item: item.evidence_kind.value))
        if len(evidence) > MAX_ITEMS:
            raise AdvancedDomainGateError("activation evidence exceeds the item limit")
        if len({item.evidence_kind for item in evidence}) != len(evidence):
            raise AdvancedDomainGateError("activation evidence kinds must be unique")
        object.__setattr__(self, "evidence", evidence)
        reviews = tuple(sorted(self.independent_reviews, key=lambda item: item.reviewer_role.value))
        if len({item.reviewer_role for item in reviews}) != len(reviews):
            raise AdvancedDomainGateError("independent reviewer roles must be unique")
        object.__setattr__(self, "independent_reviews", reviews)
        basis = canonical_sha256(
            {"content": self._basis_body(), "domain": "sunderkey.advanced-domain-basis.v1"}
        )
        object.__setattr__(self, "activation_basis_sha256", basis)
        record_id, digest = _identity("ADR", self.KIND, self._body())
        object.__setattr__(self, "request_id", record_id)
        object.__setattr__(self, "request_sha256", digest)

    def _basis_body(self) -> dict[str, Any]:
        return {
            "deployment_profile": self.deployment_profile.to_dict(),
            "domain": self.domain.value,
            "domain_commander_profile_id": self.domain_commander_profile_id,
            "environment": self.environment.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "expires_at": self.expires_at,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "requested_action_tier": self.requested_action_tier.value,
            "requested_at": self.requested_at,
            "requester_profile_id": self.requester_profile_id,
            "roster_id": self.roster_id,
            "roster_sha256": self.roster_sha256,
            "scope": self.scope.to_dict(),
            "target_authority": self.target_authority.to_dict(),
        }

    def _body(self) -> dict[str, Any]:
        return {
            "activation_basis_sha256": self.activation_basis_sha256,
            **self._basis_body(),
            "canary_admission": (
                None if self.canary_admission is None else self.canary_admission.to_dict()
            ),
            "independent_reviews": [item.to_dict() for item in self.independent_reviews],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
            "effects": dict(NO_EFFECTS),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DomainActivationRequest:
        fields = {
            "activation_basis_sha256",
            "canary_admission",
            "deployment_profile",
            "domain",
            "domain_commander_profile_id",
            "effects",
            "environment",
            "evidence",
            "expires_at",
            "independent_reviews",
            "kind",
            "policy_id",
            "policy_sha256",
            "request_id",
            "request_sha256",
            "requested_action_tier",
            "requested_at",
            "requester_profile_id",
            "roster_id",
            "roster_sha256",
            "schema_version",
            "scope",
            "target_authority",
        }
        value = _exact(raw, fields, "domain activation request")
        _metadata(value, cls.KIND)
        candidate = cls(
            requester_profile_id=value["requester_profile_id"],
            domain=value["domain"],
            domain_commander_profile_id=value["domain_commander_profile_id"],
            environment=value["environment"],
            requested_action_tier=value["requested_action_tier"],
            policy_id=value["policy_id"],
            policy_sha256=value["policy_sha256"],
            roster_id=value["roster_id"],
            roster_sha256=value["roster_sha256"],
            scope=ArtifactBinding.from_dict(value["scope"]),
            target_authority=ArtifactBinding.from_dict(value["target_authority"]),
            deployment_profile=ArtifactBinding.from_dict(value["deployment_profile"]),
            evidence=tuple(SafetyEvidence.from_dict(item) for item in value["evidence"]),
            independent_reviews=tuple(
                IndependentReview.from_dict(item) for item in value["independent_reviews"]
            ),
            canary_admission=(
                None
                if value["canary_admission"] is None
                else CanaryAdmission.from_dict(value["canary_admission"])
            ),
            requested_at=value["requested_at"],
            expires_at=value["expires_at"],
        )
        return _verify(value, candidate)

    @classmethod
    def from_json(cls, raw: str) -> DomainActivationRequest:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class DomainGateDecision:
    request_id: str
    request_sha256: str
    policy_id: str
    policy_sha256: str
    roster_id: str
    roster_sha256: str
    evaluated_at: str
    status: GateStatus | str
    blocker_codes: tuple[str, ...]
    decision_id: str = field(init=False)
    decision_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.advanced-domain-gate-decision.v1"

    def __post_init__(self) -> None:
        for name in ("request_id", "policy_id", "roster_id"):
            _identifier(getattr(self, name), name)
        for name in ("request_sha256", "policy_sha256", "roster_sha256"):
            _digest(getattr(self, name), name)
        _timestamp(self.evaluated_at, "evaluated_at")
        status = _enum(GateStatus, self.status, "gate status")
        object.__setattr__(self, "status", status)
        blockers = tuple(sorted(self.blocker_codes))
        if len(blockers) != len(set(blockers)) or any(
            not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item)
            for item in blockers
        ):
            raise AdvancedDomainGateError("blocker_codes are invalid")
        if (status is GateStatus.DENIED) != bool(blockers):
            raise AdvancedDomainGateError("gate status and blockers disagree")
        object.__setattr__(self, "blocker_codes", blockers)
        record_id, digest = _identity("AGD", self.KIND, self._body())
        object.__setattr__(self, "decision_id", record_id)
        object.__setattr__(self, "decision_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "blocker_codes": list(self.blocker_codes),
            "evaluated_at": self.evaluated_at,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "roster_id": self.roster_id,
            "roster_sha256": self.roster_sha256,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
            **self._body(),
            "effects": dict(NO_EFFECTS),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DomainGateDecision:
        fields = {
            "blocker_codes",
            "decision_id",
            "decision_sha256",
            "effects",
            "evaluated_at",
            "kind",
            "policy_id",
            "policy_sha256",
            "request_id",
            "request_sha256",
            "roster_id",
            "roster_sha256",
            "schema_version",
            "status",
        }
        value = _exact(raw, fields, "domain gate decision")
        _metadata(value, cls.KIND)
        candidate = cls(
            request_id=value["request_id"],
            request_sha256=value["request_sha256"],
            policy_id=value["policy_id"],
            policy_sha256=value["policy_sha256"],
            roster_id=value["roster_id"],
            roster_sha256=value["roster_sha256"],
            evaluated_at=value["evaluated_at"],
            status=value["status"],
            blocker_codes=tuple(value["blocker_codes"]),
        )
        return _verify(value, candidate)

    @classmethod
    def from_json(cls, raw: str) -> DomainGateDecision:
        return cls.from_dict(_load(raw))


def _load(raw: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AdvancedDomainGateError("contract JSON is invalid") from exc
    if not isinstance(value, Mapping) or canonical_json(value) != raw:
        raise AdvancedDomainGateError("contract JSON must be canonical")
    return value


def _roster_participants(roster: CriticalRoleRoster) -> set[str]:
    return {
        value
        for pair in roster.role_pairs
        for candidate in (pair.primary, pair.alternate)
        for value in (
            candidate.candidate_id,
            candidate.profile_id,
            candidate.maintainer_id,
        )
    }


def evaluate_domain_activation(
    policy: DomainSafetyPolicy,
    roster: CriticalRoleRoster,
    request: DomainActivationRequest,
    *,
    evaluated_at: str,
) -> DomainGateDecision:
    """Evaluate contract compatibility without granting any runtime effect."""

    now_text = _timestamp(evaluated_at, "evaluated_at")
    now = _instant(now_text)
    blockers: set[str] = set()

    if policy.roster_id != roster.roster_id or policy.roster_sha256 != roster.roster_sha256:
        blockers.add("policy_roster_binding_mismatch")
    if request.policy_id != policy.policy_id or request.policy_sha256 != policy.policy_sha256:
        blockers.add("request_policy_binding_mismatch")
    if request.roster_id != roster.roster_id or request.roster_sha256 != roster.roster_sha256:
        blockers.add("request_roster_binding_mismatch")
    if request.domain is not policy.domain:
        blockers.add("domain_mismatch")
    if request.domain_commander_profile_id != policy.domain_commander_profile_id:
        blockers.add("domain_commander_mismatch")
    if _TIER_ORDER[request.requested_action_tier] > _TIER_ORDER[policy.maximum_action_tier]:
        blockers.add("unsafe_action_tier")

    if not _current(roster.issued_at, roster.expires_at, now):
        blockers.add("roster_not_current")
    if not _current(policy.issued_at, policy.expires_at, now):
        blockers.add("policy_not_current")
    if not _current(request.requested_at, request.expires_at, now):
        blockers.add("request_not_current")
    for pair in roster.role_pairs:
        for candidate in (pair.primary, pair.alternate):
            evidence = candidate.qualification
            if not _current(evidence.qualified_at, evidence.expires_at, now):
                blockers.add("qualification_evidence_not_current")

    evidence_by_kind = {item.evidence_kind: item for item in request.evidence}
    missing = REQUIRED_EVIDENCE_KINDS - set(evidence_by_kind)
    if missing:
        blockers.add("required_safety_evidence_missing")
    for item in request.evidence:
        if item.policy_sha256 != policy.policy_sha256:
            blockers.add("evidence_policy_binding_mismatch")
        if item.scope_sha256 != request.scope.artifact_sha256:
            blockers.add("evidence_scope_binding_mismatch")
        if item.action_tier is not request.requested_action_tier:
            blockers.add("evidence_action_tier_mismatch")
        if not _current(item.issued_at, item.expires_at, now):
            blockers.add("safety_evidence_not_current")
        if item.evidence_kind is EvidenceKind.SIMULATOR_OR_REPLICA and item.environment not in {
            EnvironmentClass.SIMULATOR,
            EnvironmentClass.REPLICA,
        }:
            blockers.add("simulator_or_replica_proof_invalid")
        elif (
            item.evidence_kind is not EvidenceKind.SIMULATOR_OR_REPLICA
            and item.environment is not request.environment
        ):
            blockers.add("evidence_environment_mismatch")

    expected_artifacts = {
        EvidenceKind.HAZARD_ANALYSIS: policy.hazard_method,
        EvidenceKind.MONITORING: policy.monitoring_contract,
        EvidenceKind.STOP: policy.stop_contract,
        EvidenceKind.CLEANUP: policy.cleanup_contract,
        EvidenceKind.RESTORATION: policy.restoration_contract,
        EvidenceKind.CUSTODY: policy.custody_contract,
        EvidenceKind.SIMULATOR_OR_REPLICA: policy.simulator_requirements,
        EvidenceKind.TARGET_AUTHORITY: request.target_authority,
    }
    for kind, expected in expected_artifacts.items():
        item = evidence_by_kind.get(kind)
        if item is not None and item.artifact != expected:
            blockers.add(f"{kind.value}_binding_mismatch")

    reviews = {item.reviewer_role: item for item in request.independent_reviews}
    if set(reviews) != set(ReviewerRole):
        blockers.add("independent_reviews_missing")
    reviewer_ids = [item.reviewer_profile_id for item in request.independent_reviews]
    if len(reviewer_ids) != len(set(reviewer_ids)):
        blockers.add("independent_reviewer_aliasing")
    forbidden_reviewers = _roster_participants(roster) | {
        request.requester_profile_id,
        request.domain_commander_profile_id,
    }
    for review in request.independent_reviews:
        if review.reviewer_profile_id in forbidden_reviewers:
            blockers.add("self_review_forbidden")
        if review.activation_basis_sha256 != request.activation_basis_sha256:
            blockers.add("review_basis_binding_mismatch")
        if not _current(review.reviewed_at, review.expires_at, now):
            blockers.add("independent_review_not_current")

    if request.environment is EnvironmentClass.LIVE:
        canary = request.canary_admission
        if canary is None:
            blockers.add("separate_canary_admission_missing")
        else:
            if (
                canary.policy_sha256 != policy.policy_sha256
                or canary.scope_sha256 != request.scope.artifact_sha256
                or canary.action_tier is not request.requested_action_tier
            ):
                blockers.add("canary_admission_binding_mismatch")
            if not _current(canary.admitted_at, canary.expires_at, now):
                blockers.add("canary_admission_not_current")
            if (
                canary.decision_maker_profile_id in forbidden_reviewers
                or canary.independent_reviewer_profile_id in forbidden_reviewers
                or canary.decision_maker_profile_id in reviewer_ids
                or canary.independent_reviewer_profile_id in reviewer_ids
            ):
                blockers.add("canary_admission_not_independent")
    elif request.canary_admission is not None:
        blockers.add("canary_admission_for_non_live_request")

    status = GateStatus.DENIED if blockers else GateStatus.CONTRACT_READY_UNVERIFIED
    return DomainGateDecision(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        policy_id=policy.policy_id,
        policy_sha256=policy.policy_sha256,
        roster_id=roster.roster_id,
        roster_sha256=roster.roster_sha256,
        evaluated_at=now_text,
        status=status,
        blocker_codes=tuple(blockers),
    )


def parse_contract(raw: Mapping[str, Any] | str) -> Any:
    """Parse one supported contract and verify its content identity."""

    value = _load(raw) if isinstance(raw, str) else raw
    if not isinstance(value, Mapping):
        raise AdvancedDomainGateError("contract must be an object")
    kind = value.get("kind")
    parsers = {
        CriticalRoleRoster.KIND: CriticalRoleRoster.from_dict,
        DomainSafetyPolicy.KIND: DomainSafetyPolicy.from_dict,
        DomainActivationRequest.KIND: DomainActivationRequest.from_dict,
        DomainGateDecision.KIND: DomainGateDecision.from_dict,
    }
    parser = parsers.get(kind)
    if parser is None:
        raise AdvancedDomainGateError("contract kind is unsupported")
    return parser(value)


__all__ = [
    "EXPECTED_COMMANDERS",
    "MAXIMUM_DOMAIN_TIERS",
    "NO_EFFECTS",
    "ActionTier",
    "AdvancedDomain",
    "AdvancedDomainGateError",
    "ArtifactBinding",
    "CanaryAdmission",
    "CriticalRole",
    "CriticalRolePair",
    "CriticalRoleRoster",
    "DomainActivationRequest",
    "DomainGateDecision",
    "DomainSafetyPolicy",
    "EnvironmentClass",
    "EvidenceKind",
    "GateStatus",
    "IndependentReview",
    "QualificationEvidence",
    "ReviewerRole",
    "RoleCandidate",
    "RuntimeKind",
    "SafetyEvidence",
    "canonical_json",
    "canonical_sha256",
    "evaluate_domain_activation",
    "parse_contract",
]
