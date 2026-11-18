"""Deterministic, effect-free assessment guidance cards.

This module converts caller-supplied, already-governed references into
content-addressed coverage objectives and scheduler hints. It does not discover
files, access credentials, contact targets, authorize work, schedule work, or
execute an assessment.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 2048
MAX_TEXT = 2000

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REF_RE = re.compile(r"[a-z][a-z0-9_-]{1,31}:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
VERSION_RE = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9][a-z0-9.-]{0,31})?\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = {
    "authorization": "none",
    "credential_access": "none",
    "deployment": "none",
    "discovery": "none",
    "execution": "none",
    "network": "none",
    "routing": "none",
    "scheduling": "none",
    "target_contact": "none",
}

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:api[_-]?key|password|passwd|secret|token)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
)
_HOSTILE_PATTERNS = (
    re.compile(r"\bignore (?:all |the )?(?:previous|prior) instructions\b", re.IGNORECASE),
    re.compile(
        r"\b(?:bypass|disable|evade) (?:authorization|guardrails?|safety|scope)\b", re.IGNORECASE
    ),
    re.compile(r"\b(?:reverse shell|exfiltrat(?:e|ion)|credential theft)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:run|execute|launch) (?:this |the )?(?:command|payload|shell)\b", re.IGNORECASE
    ),
    re.compile(r"(?:https?://|file://|\\\\|`|\$\(|&&|\|\||[<>])", re.IGNORECASE),
)


class AssessmentGuidanceError(ValueError):
    """Raised when guidance input or a serialized card fails closed."""


class PriorityKind(StrEnum):
    GOAL = "goal"
    ENDPOINT = "endpoint"
    ROLE = "role"
    ATTACK_TYPE = "attack_type"
    ATTACK_SURFACE_GAP = "attack_surface_gap"
    WORLD_MODEL_FRONTIER = "world_model_frontier"


class RiskTier(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class ObjectiveKind(StrEnum):
    GOAL = "goal"
    ENDPOINT = "endpoint"
    ROLE = "role"
    ATTACK_TYPE = "attack_type"
    GAP = "gap"
    FRONTIER = "frontier"


RISK_ORDER = {RiskTier.LOW: 1, RiskTier.MODERATE: 2, RiskTier.HIGH: 3}


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
        raise AssessmentGuidanceError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise AssessmentGuidanceError(f"{label} fields are invalid")
    return raw


def _field_names(record_type: type[Any]) -> set[str]:
    return {item.name for item in fields(record_type)}


def _ref(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REF_RE.fullmatch(value) is None:
        raise AssessmentGuidanceError(f"{label} must be an opaque reference")
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise AssessmentGuidanceError(f"{label} contains credential or secret material")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise AssessmentGuidanceError(f"{label} must use {namespace}")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise AssessmentGuidanceError(f"{label} must be a code")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AssessmentGuidanceError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AssessmentGuidanceError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AssessmentGuidanceError(f"{label} must be valid") from exc


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AssessmentGuidanceError(f"{label} must be between {minimum} and {maximum}")
    return value


def _tuple(values: Sequence[Any], label: str, maximum: int = MAX_ITEMS) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise AssessmentGuidanceError(f"{label} must be a sequence")
    result = tuple(values)
    if len(result) > maximum:
        raise AssessmentGuidanceError(f"{label} exceeds its limit")
    return result


def _safe_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise AssessmentGuidanceError(f"{label} must be bounded text")
    if not allow_empty and not value.strip():
        raise AssessmentGuidanceError(f"{label} must not be empty")
    if value != value.strip() or any(ord(char) < 32 or ord(char) > 126 for char in value):
        raise AssessmentGuidanceError(f"{label} must use canonical printable ASCII")
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise AssessmentGuidanceError(f"{label} contains credential or secret material")
    if any(pattern.search(value) for pattern in _HOSTILE_PATTERNS):
        raise AssessmentGuidanceError(f"{label} contains hostile instructions")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise AssessmentGuidanceError(f"{label} must be an immutable exact version")
    if any(token in value.lower() for token in ("latest", "main", "head", "snapshot")):
        raise AssessmentGuidanceError(f"{label} cannot be a moving version")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise AssessmentGuidanceError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class GuidanceBinding:
    """Tenant, context, scope, and immutable source-artifact binding."""

    tenant_ref: str
    context_ref: str
    scope_ref: str
    scope_sha256: str
    target_context_sha256: str
    service_contract_sha256: str
    attack_surface_sha256: str
    world_model_sha256: str

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.context_ref, "context_ref", "contextref")
        _ref(self.scope_ref, "scope_ref", "scoperef")
        for name in (
            "scope_sha256",
            "target_context_sha256",
            "service_contract_sha256",
            "attack_surface_sha256",
            "world_model_sha256",
        ):
            _digest(getattr(self, name), name)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> GuidanceBinding:
        _exact(raw, _field_names(cls), "guidance binding")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class AssessmentGoal:
    goal_ref: str
    objective_code: str
    coverage_weight: int
    acceptance_sha256: str

    def __post_init__(self) -> None:
        _ref(self.goal_ref, "goal_ref", "goalref")
        _code(self.objective_code, "objective_code")
        _bounded_int(self.coverage_weight, "coverage_weight", 1, 1000)
        _digest(self.acceptance_sha256, "acceptance_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentGoal:
        _exact(raw, _field_names(cls), "assessment goal")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class PriorityRule:
    subject_ref: str
    subject_kind: PriorityKind | str
    rank: int
    reason_code: str

    def __post_init__(self) -> None:
        _ref(self.subject_ref, "subject_ref")
        object.__setattr__(
            self, "subject_kind", _enum(PriorityKind, self.subject_kind, "subject_kind")
        )
        _bounded_int(self.rank, "rank", 1, MAX_ITEMS)
        _code(self.reason_code, "reason_code")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "reason_code": self.reason_code,
            "subject_kind": self.subject_kind.value,
            "subject_ref": self.subject_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> PriorityRule:
        _exact(raw, _field_names(cls), "priority rule")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class EndpointReference:
    endpoint_ref: str
    endpoint_sha256: str
    tenant_ref: str
    context_ref: str
    scope_ref: str
    service_contract_sha256: str
    protected: bool
    in_scope: bool

    def __post_init__(self) -> None:
        _ref(self.endpoint_ref, "endpoint_ref", "endpointref")
        _digest(self.endpoint_sha256, "endpoint_sha256")
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.context_ref, "context_ref", "contextref")
        _ref(self.scope_ref, "scope_ref", "scoperef")
        _digest(self.service_contract_sha256, "service_contract_sha256")
        if not isinstance(self.protected, bool) or not isinstance(self.in_scope, bool):
            raise AssessmentGuidanceError("endpoint flags must be booleans")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> EndpointReference:
        _exact(raw, _field_names(cls), "endpoint reference")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class RoleReference:
    role_ref: str
    role_sha256: str
    tenant_ref: str
    context_ref: str
    scope_ref: str
    in_scope: bool

    def __post_init__(self) -> None:
        _ref(self.role_ref, "role_ref", "roleref")
        _digest(self.role_sha256, "role_sha256")
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.context_ref, "context_ref", "contextref")
        _ref(self.scope_ref, "scope_ref", "scoperef")
        if not isinstance(self.in_scope, bool):
            raise AssessmentGuidanceError("role in_scope must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> RoleReference:
        _exact(raw, _field_names(cls), "role reference")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class AttackTypeSelection:
    attack_type_ref: str
    attack_type_code: str
    catalog_version: str
    catalog_sha256: str
    risk_tier: RiskTier | str
    estimated_risk_points: int

    def __post_init__(self) -> None:
        _ref(self.attack_type_ref, "attack_type_ref", "attackref")
        _code(self.attack_type_code, "attack_type_code")
        _version(self.catalog_version, "catalog_version")
        _digest(self.catalog_sha256, "catalog_sha256")
        object.__setattr__(self, "risk_tier", _enum(RiskTier, self.risk_tier, "risk_tier"))
        _bounded_int(self.estimated_risk_points, "estimated_risk_points", 0, 1_000_000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_type_code": self.attack_type_code,
            "attack_type_ref": self.attack_type_ref,
            "catalog_sha256": self.catalog_sha256,
            "catalog_version": self.catalog_version,
            "estimated_risk_points": self.estimated_risk_points,
            "risk_tier": self.risk_tier.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AttackTypeSelection:
        _exact(raw, _field_names(cls), "attack type selection")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class PayloadFixtureReference:
    fixture_ref: str
    artifact_version: str
    artifact_sha256: str
    content_type: str
    executable: bool = False
    contains_credentials: bool = False

    def __post_init__(self) -> None:
        _ref(self.fixture_ref, "fixture_ref", "fixtureref")
        _version(self.artifact_version, "artifact_version")
        _digest(self.artifact_sha256, "artifact_sha256")
        if self.content_type not in {"application/json", "application/octet-stream", "text/plain"}:
            raise AssessmentGuidanceError("content_type is not allowed")
        if self.executable is not False:
            raise AssessmentGuidanceError("executable payload fixtures are prohibited")
        if self.contains_credentials is not False:
            raise AssessmentGuidanceError("credential-bearing fixtures are prohibited")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> PayloadFixtureReference:
        _exact(raw, _field_names(cls), "payload fixture reference")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class GapReference:
    gap_ref: str
    gap_sha256: str
    context_ref: str
    reason_code: str
    severity: RiskTier | str

    def __post_init__(self) -> None:
        _ref(self.gap_ref, "gap_ref", "gapref")
        _digest(self.gap_sha256, "gap_sha256")
        _ref(self.context_ref, "context_ref", "contextref")
        _code(self.reason_code, "reason_code")
        object.__setattr__(self, "severity", _enum(RiskTier, self.severity, "severity"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_ref": self.context_ref,
            "gap_ref": self.gap_ref,
            "gap_sha256": self.gap_sha256,
            "reason_code": self.reason_code,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GapReference:
        _exact(raw, _field_names(cls), "gap reference")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class FrontierReference:
    frontier_ref: str
    frontier_sha256: str
    context_ref: str
    reason_code: str
    confidence: int

    def __post_init__(self) -> None:
        _ref(self.frontier_ref, "frontier_ref", "frontierref")
        _digest(self.frontier_sha256, "frontier_sha256")
        _ref(self.context_ref, "context_ref", "contextref")
        _code(self.reason_code, "reason_code")
        _bounded_int(self.confidence, "confidence", 0, 100)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> FrontierReference:
        _exact(raw, _field_names(cls), "frontier reference")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class GuidanceConstraints:
    risk_budget_points: int
    request_budget: int
    token_budget: int
    max_parallelism: int
    impact_ceiling: RiskTier | str

    def __post_init__(self) -> None:
        _bounded_int(self.risk_budget_points, "risk_budget_points", 0, 1_000_000)
        _bounded_int(self.request_budget, "request_budget", 0, 1_000_000)
        _bounded_int(self.token_budget, "token_budget", 0, 100_000_000)
        _bounded_int(self.max_parallelism, "max_parallelism", 1, 10_000)
        object.__setattr__(
            self, "impact_ceiling", _enum(RiskTier, self.impact_ceiling, "impact_ceiling")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "impact_ceiling": self.impact_ceiling.value,
            "max_parallelism": self.max_parallelism,
            "request_budget": self.request_budget,
            "risk_budget_points": self.risk_budget_points,
            "token_budget": self.token_budget,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GuidanceConstraints:
        _exact(raw, _field_names(cls), "guidance constraints")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class GuidanceRequest:
    """Complete caller-supplied planning input with no implicit discovery."""

    binding: GuidanceBinding
    goals: tuple[AssessmentGoal, ...]
    focus_priorities: tuple[PriorityRule, ...]
    exclusion_priorities: tuple[PriorityRule, ...]
    endpoints: tuple[EndpointReference, ...]
    roles: tuple[RoleReference, ...]
    attack_types: tuple[AttackTypeSelection, ...]
    custom_strategy: str
    payload_fixtures: tuple[PayloadFixtureReference, ...]
    gaps: tuple[GapReference, ...]
    frontiers: tuple[FrontierReference, ...]
    constraints: GuidanceConstraints
    created_at: str
    expires_at: str

    COLLECTIONS: ClassVar[dict[str, type[Any]]] = {
        "goals": AssessmentGoal,
        "focus_priorities": PriorityRule,
        "exclusion_priorities": PriorityRule,
        "endpoints": EndpointReference,
        "roles": RoleReference,
        "attack_types": AttackTypeSelection,
        "payload_fixtures": PayloadFixtureReference,
        "gaps": GapReference,
        "frontiers": FrontierReference,
    }

    def __post_init__(self) -> None:
        if not isinstance(self.binding, GuidanceBinding):
            raise AssessmentGuidanceError("binding is invalid")
        if not isinstance(self.constraints, GuidanceConstraints):
            raise AssessmentGuidanceError("constraints are invalid")
        _safe_text(self.custom_strategy, "custom_strategy", allow_empty=True)
        created = _timestamp(self.created_at, "created_at")
        if _timestamp(self.expires_at, "expires_at") <= created:
            raise AssessmentGuidanceError("expires_at must follow created_at")
        for name, item_type in self.COLLECTIONS.items():
            values = _tuple(getattr(self, name), name)
            if any(not isinstance(item, item_type) for item in values):
                raise AssessmentGuidanceError(f"{name} contains an invalid item")
            key = _sort_key_for(item_type)
            canonical = tuple(sorted(values, key=key))
            if len({key(item) for item in canonical}) != len(canonical):
                raise AssessmentGuidanceError(f"{name} contains duplicate identities")
            object.__setattr__(self, name, canonical)
        if not self.goals:
            raise AssessmentGuidanceError("at least one assessment goal is required")
        self._validate_bindings()
        self._validate_priorities()
        self._validate_risk()

    def _validate_bindings(self) -> None:
        for item in (*self.endpoints, *self.roles):
            if (
                item.tenant_ref != self.binding.tenant_ref
                or item.context_ref != self.binding.context_ref
                or item.scope_ref != self.binding.scope_ref
            ):
                raise AssessmentGuidanceError("cross-context or scope input is prohibited")
            if not item.in_scope:
                raise AssessmentGuidanceError("scope escape input is prohibited")
        for endpoint in self.endpoints:
            if endpoint.service_contract_sha256 != self.binding.service_contract_sha256:
                raise AssessmentGuidanceError("endpoint service contract binding mismatch")
        for item in (*self.gaps, *self.frontiers):
            if item.context_ref != self.binding.context_ref:
                raise AssessmentGuidanceError("cross-context gap or frontier is prohibited")

    def _validate_priorities(self) -> None:
        available = {
            PriorityKind.GOAL: {item.goal_ref for item in self.goals},
            PriorityKind.ENDPOINT: {item.endpoint_ref for item in self.endpoints},
            PriorityKind.ROLE: {item.role_ref for item in self.roles},
            PriorityKind.ATTACK_TYPE: {item.attack_type_ref for item in self.attack_types},
            PriorityKind.ATTACK_SURFACE_GAP: {item.gap_ref for item in self.gaps},
            PriorityKind.WORLD_MODEL_FRONTIER: {item.frontier_ref for item in self.frontiers},
        }
        for label, values in (
            ("focus_priorities", self.focus_priorities),
            ("exclusion_priorities", self.exclusion_priorities),
        ):
            ranks = sorted(item.rank for item in values)
            if ranks != list(range(1, len(values) + 1)):
                raise AssessmentGuidanceError(f"{label} ranks are ambiguous")
            for item in values:
                if item.subject_ref not in available[item.subject_kind]:
                    raise AssessmentGuidanceError(f"{label} references an unknown subject")
        focus_refs = {item.subject_ref for item in self.focus_priorities}
        excluded_refs = {item.subject_ref for item in self.exclusion_priorities}
        if focus_refs & excluded_refs:
            raise AssessmentGuidanceError("focus and exclusion priorities conflict")
        protected = {item.endpoint_ref for item in self.endpoints if item.protected}
        if protected & focus_refs:
            raise AssessmentGuidanceError("protected endpoint conflicts with focus priority")
        if not protected.issubset(excluded_refs):
            raise AssessmentGuidanceError("protected endpoints require explicit exclusion")

    def _validate_risk(self) -> None:
        selected_risk = sum(item.estimated_risk_points for item in self.attack_types)
        if selected_risk > self.constraints.risk_budget_points:
            raise AssessmentGuidanceError("selected attack types exceed the risk budget")
        ceiling = RISK_ORDER[self.constraints.impact_ceiling]
        if any(RISK_ORDER[item.risk_tier] > ceiling for item in self.attack_types):
            raise AssessmentGuidanceError("selected attack type exceeds the impact ceiling")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_types": [item.to_dict() for item in self.attack_types],
            "binding": self.binding.to_dict(),
            "constraints": self.constraints.to_dict(),
            "created_at": self.created_at,
            "custom_strategy": self.custom_strategy,
            "endpoints": [item.to_dict() for item in self.endpoints],
            "exclusion_priorities": [item.to_dict() for item in self.exclusion_priorities],
            "expires_at": self.expires_at,
            "focus_priorities": [item.to_dict() for item in self.focus_priorities],
            "frontiers": [item.to_dict() for item in self.frontiers],
            "gaps": [item.to_dict() for item in self.gaps],
            "goals": [item.to_dict() for item in self.goals],
            "payload_fixtures": [item.to_dict() for item in self.payload_fixtures],
            "roles": [item.to_dict() for item in self.roles],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GuidanceRequest:
        _exact(raw, _field_names(cls), "guidance request")
        values = dict(raw)
        values["binding"] = GuidanceBinding.from_dict(raw["binding"])
        values["constraints"] = GuidanceConstraints.from_dict(raw["constraints"])
        for name, item_type in cls.COLLECTIONS.items():
            values[name] = tuple(item_type.from_dict(item) for item in _tuple(raw[name], name))
        return cls(**values)


def _sort_key_for(item_type: type[Any]):
    if item_type is PriorityRule:
        return lambda item: (item.rank, item.subject_kind.value, item.subject_ref)
    field = {
        AssessmentGoal: "goal_ref",
        EndpointReference: "endpoint_ref",
        RoleReference: "role_ref",
        AttackTypeSelection: "attack_type_ref",
        PayloadFixtureReference: "fixture_ref",
        GapReference: "gap_ref",
        FrontierReference: "frontier_ref",
    }[item_type]
    return lambda item: getattr(item, field)


@dataclass(frozen=True, slots=True)
class CoverageObjective:
    objective_ref: str
    objective_kind: ObjectiveKind | str
    subject_ref: str
    order: int
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _ref(self.objective_ref, "objective_ref", "objectiveref")
        object.__setattr__(
            self, "objective_kind", _enum(ObjectiveKind, self.objective_kind, "objective_kind")
        )
        _ref(self.subject_ref, "subject_ref")
        _bounded_int(self.order, "order", 1, MAX_ITEMS * 8)
        reasons = tuple(sorted({_code(value, "reason_code") for value in self.reason_codes}))
        if not reasons:
            raise AssessmentGuidanceError("coverage objective requires reason codes")
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_kind": self.objective_kind.value,
            "objective_ref": self.objective_ref,
            "order": self.order,
            "reason_codes": list(self.reason_codes),
            "subject_ref": self.subject_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageObjective:
        _exact(raw, _field_names(cls), "coverage objective")
        values = dict(raw)
        values["reason_codes"] = tuple(raw["reason_codes"])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class SchedulerHint:
    hint_ref: str
    order: int
    subject_ref: str
    objective_refs: tuple[str, ...]
    attack_type_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    status: str = "proposal_only"

    def __post_init__(self) -> None:
        _ref(self.hint_ref, "hint_ref", "hintref")
        _bounded_int(self.order, "order", 1, MAX_ITEMS * 8)
        _ref(self.subject_ref, "subject_ref")
        for name, namespace in (
            ("objective_refs", "objectiveref"),
            ("attack_type_refs", "attackref"),
        ):
            values = tuple(sorted({_ref(value, name, namespace) for value in getattr(self, name)}))
            object.__setattr__(self, name, values)
        reasons = tuple(sorted({_code(value, "reason_code") for value in self.reason_codes}))
        blockers = tuple(sorted({_code(value, "blocker_code") for value in self.blocker_codes}))
        if not reasons:
            raise AssessmentGuidanceError("scheduler hint requires a reason code")
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "blocker_codes", blockers)
        if self.status != "proposal_only":
            raise AssessmentGuidanceError("scheduler hints must remain proposal_only")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_type_refs": list(self.attack_type_refs),
            "blocker_codes": list(self.blocker_codes),
            "hint_ref": self.hint_ref,
            "objective_refs": list(self.objective_refs),
            "order": self.order,
            "reason_codes": list(self.reason_codes),
            "status": self.status,
            "subject_ref": self.subject_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SchedulerHint:
        _exact(raw, _field_names(cls), "scheduler hint")
        values = dict(raw)
        for name in ("objective_refs", "attack_type_refs", "reason_codes", "blocker_codes"):
            values[name] = tuple(raw[name])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class AssessmentGuidanceCard:
    """Content-addressed guidance output without authority or effects."""

    schema_version: int
    card_id: str
    card_sha256: str
    request_sha256: str
    request: GuidanceRequest
    coverage_objectives: tuple[CoverageObjective, ...]
    scheduler_hints: tuple[SchedulerHint, ...]
    conflict_reasons: tuple[str, ...]
    gap_reasons: tuple[str, ...]
    independent_review_required: bool
    expires_at: str
    effects: Mapping[str, str]
    qualification_effect: str = "none"

    DOMAIN: ClassVar[str] = "sunderkey.assessment-guidance-card.v1"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise AssessmentGuidanceError("schema_version is unsupported")
        _digest(self.request_sha256, "request_sha256")
        if not isinstance(self.request, GuidanceRequest):
            raise AssessmentGuidanceError("request is invalid")
        if self.request_sha256 != canonical_sha256(self.request.to_dict()):
            raise AssessmentGuidanceError("request digest does not match content")
        objectives = tuple(self.coverage_objectives)
        hints = tuple(self.scheduler_hints)
        if any(not isinstance(item, CoverageObjective) for item in objectives):
            raise AssessmentGuidanceError("coverage_objectives contains an invalid item")
        if any(not isinstance(item, SchedulerHint) for item in hints):
            raise AssessmentGuidanceError("scheduler_hints contains an invalid item")
        if [item.order for item in objectives] != list(range(1, len(objectives) + 1)):
            raise AssessmentGuidanceError("coverage objective ordering is invalid")
        if [item.order for item in hints] != list(range(1, len(hints) + 1)):
            raise AssessmentGuidanceError("scheduler hint ordering is invalid")
        object.__setattr__(self, "coverage_objectives", objectives)
        object.__setattr__(self, "scheduler_hints", hints)
        for name in ("conflict_reasons", "gap_reasons"):
            values = tuple(sorted({_code(value, name) for value in getattr(self, name)}))
            object.__setattr__(self, name, values)
        if not isinstance(self.independent_review_required, bool):
            raise AssessmentGuidanceError("independent_review_required must be boolean")
        if self.expires_at != self.request.expires_at:
            raise AssessmentGuidanceError("card expiration must match request expiration")
        if not isinstance(self.effects, Mapping):
            raise AssessmentGuidanceError("effects must preserve the no-effect boundary")
        effects = dict(self.effects)
        if effects != NO_EFFECTS or set(effects) != set(NO_EFFECTS):
            raise AssessmentGuidanceError("effects must preserve the no-effect boundary")
        object.__setattr__(self, "effects", MappingProxyType(effects))
        if self.qualification_effect != "none":
            raise AssessmentGuidanceError("card cannot create a qualification effect")
        expected_id, expected_sha = _identity("AGC", self.DOMAIN, self._body())
        if self.card_id != expected_id or self.card_sha256 != expected_sha:
            raise AssessmentGuidanceError("card content address does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "conflict_reasons": list(self.conflict_reasons),
            "coverage_objectives": [item.to_dict() for item in self.coverage_objectives],
            "effects": dict(self.effects),
            "expires_at": self.expires_at,
            "gap_reasons": list(self.gap_reasons),
            "independent_review_required": self.independent_review_required,
            "kind": self.DOMAIN,
            "qualification_effect": self.qualification_effect,
            "request": self.request.to_dict(),
            "request_sha256": self.request_sha256,
            "scheduler_hints": [item.to_dict() for item in self.scheduler_hints],
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "card_id": self.card_id, "card_sha256": self.card_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentGuidanceCard:
        expected = {
            "card_id",
            "card_sha256",
            "conflict_reasons",
            "coverage_objectives",
            "effects",
            "expires_at",
            "gap_reasons",
            "independent_review_required",
            "kind",
            "qualification_effect",
            "request",
            "request_sha256",
            "scheduler_hints",
            "schema_version",
        }
        _exact(raw, expected, "assessment guidance card")
        if raw["kind"] != cls.DOMAIN:
            raise AssessmentGuidanceError("card kind is invalid")
        return cls(
            schema_version=raw["schema_version"],
            card_id=raw["card_id"],
            card_sha256=raw["card_sha256"],
            request_sha256=raw["request_sha256"],
            request=GuidanceRequest.from_dict(raw["request"]),
            coverage_objectives=tuple(
                CoverageObjective.from_dict(item)
                for item in _tuple(raw["coverage_objectives"], "coverage_objectives")
            ),
            scheduler_hints=tuple(
                SchedulerHint.from_dict(item)
                for item in _tuple(raw["scheduler_hints"], "scheduler_hints")
            ),
            conflict_reasons=tuple(raw["conflict_reasons"]),
            gap_reasons=tuple(raw["gap_reasons"]),
            independent_review_required=raw["independent_review_required"],
            expires_at=raw["expires_at"],
            effects=raw["effects"],
            qualification_effect=raw["qualification_effect"],
        )


def build_assessment_guidance(request: GuidanceRequest) -> AssessmentGuidanceCard:
    """Build a deterministic, proposal-only guidance card."""

    if not isinstance(request, GuidanceRequest):
        raise AssessmentGuidanceError("request is invalid")
    excluded = {item.subject_ref for item in request.exclusion_priorities}
    focus = {item.subject_ref: item for item in request.focus_priorities}
    candidates: list[tuple[int, int, str, ObjectiveKind, tuple[str, ...]]] = []
    kind_order = {
        ObjectiveKind.ENDPOINT: 1,
        ObjectiveKind.ROLE: 2,
        ObjectiveKind.ATTACK_TYPE: 3,
        ObjectiveKind.GAP: 4,
        ObjectiveKind.FRONTIER: 5,
        ObjectiveKind.GOAL: 6,
    }

    def add(kind: ObjectiveKind, subject_ref: str, default_order: int, reasons: tuple[str, ...]):
        if subject_ref in excluded:
            return
        priority = focus.get(subject_ref)
        rank = priority.rank if priority else MAX_ITEMS + default_order
        reason_set = set(reasons)
        if priority:
            reason_set.update(("explicit_focus", priority.reason_code))
        candidates.append((rank, kind_order[kind], subject_ref, kind, tuple(sorted(reason_set))))

    for index, item in enumerate(request.endpoints, 1):
        if not item.protected:
            add(ObjectiveKind.ENDPOINT, item.endpoint_ref, index, ("endpoint_coverage",))
    for index, item in enumerate(request.roles, 1):
        add(ObjectiveKind.ROLE, item.role_ref, index, ("role_coverage",))
    for index, item in enumerate(request.attack_types, 1):
        add(ObjectiveKind.ATTACK_TYPE, item.attack_type_ref, index, ("attack_type_selected",))
    for index, item in enumerate(request.gaps, 1):
        add(ObjectiveKind.GAP, item.gap_ref, index, ("attack_surface_gap", item.reason_code))
    for index, item in enumerate(request.frontiers, 1):
        add(
            ObjectiveKind.FRONTIER,
            item.frontier_ref,
            index,
            ("world_model_frontier", item.reason_code),
        )
    for index, item in enumerate(request.goals, 1):
        add(ObjectiveKind.GOAL, item.goal_ref, index, ("assessment_goal", item.objective_code))

    candidates.sort(key=lambda value: (value[0], value[1], value[2]))
    objectives = tuple(
        CoverageObjective(
            objective_ref=f"objectiveref:guidance-{index:04d}",
            objective_kind=kind,
            subject_ref=subject_ref,
            order=index,
            reason_codes=reasons,
        )
        for index, (_, _, subject_ref, kind, reasons) in enumerate(candidates, 1)
    )
    attack_refs = tuple(
        item.attack_type_ref
        for item in request.attack_types
        if item.attack_type_ref not in excluded
    )
    fixture_block = ("independent_fixture_review_required",) if request.payload_fixtures else ()
    hints = tuple(
        SchedulerHint(
            hint_ref=f"hintref:guidance-{index:04d}",
            order=index,
            subject_ref=objective.subject_ref,
            objective_refs=(objective.objective_ref,),
            attack_type_refs=(
                (objective.subject_ref,)
                if objective.objective_kind is ObjectiveKind.ATTACK_TYPE
                else attack_refs
            ),
            reason_codes=objective.reason_codes,
            blocker_codes=fixture_block,
        )
        for index, objective in enumerate(objectives, 1)
    )
    conflict_reasons = tuple(
        sorted(
            {"protected_endpoint_excluded" for endpoint in request.endpoints if endpoint.protected}
            | {"explicit_exclusion_applied" for _item in request.exclusion_priorities}
        )
    )
    gap_reasons = tuple(sorted({item.reason_code for item in request.gaps}))
    independent_review_required = bool(
        request.custom_strategy
        or request.payload_fixtures
        or any(item.risk_tier is RiskTier.HIGH for item in request.attack_types)
    )
    request_sha256 = canonical_sha256(request.to_dict())
    body = {
        "conflict_reasons": list(conflict_reasons),
        "coverage_objectives": [item.to_dict() for item in objectives],
        "effects": dict(NO_EFFECTS),
        "expires_at": request.expires_at,
        "gap_reasons": list(gap_reasons),
        "independent_review_required": independent_review_required,
        "kind": AssessmentGuidanceCard.DOMAIN,
        "qualification_effect": "none",
        "request": request.to_dict(),
        "request_sha256": request_sha256,
        "scheduler_hints": [item.to_dict() for item in hints],
        "schema_version": SCHEMA_VERSION,
    }
    card_id, card_sha256 = _identity("AGC", AssessmentGuidanceCard.DOMAIN, body)
    return AssessmentGuidanceCard(
        schema_version=SCHEMA_VERSION,
        card_id=card_id,
        card_sha256=card_sha256,
        request_sha256=request_sha256,
        request=request,
        coverage_objectives=objectives,
        scheduler_hints=hints,
        conflict_reasons=conflict_reasons,
        gap_reasons=gap_reasons,
        independent_review_required=independent_review_required,
        expires_at=request.expires_at,
        effects=dict(NO_EFFECTS),
    )


def parse_assessment_guidance(raw: str | bytes | Mapping[str, Any]) -> AssessmentGuidanceCard:
    """Strictly parse and verify a serialized guidance card."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AssessmentGuidanceError("card bytes must be UTF-8 JSON") from exc
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AssessmentGuidanceError("card must be valid JSON") from exc
    else:
        decoded = raw
    card = AssessmentGuidanceCard.from_dict(decoded)
    if card.to_dict() != decoded:
        raise AssessmentGuidanceError("card encoding is not canonical")
    return card


__all__ = [
    "NO_EFFECTS",
    "AssessmentGoal",
    "AssessmentGuidanceCard",
    "AssessmentGuidanceError",
    "AttackTypeSelection",
    "CoverageObjective",
    "EndpointReference",
    "FrontierReference",
    "GapReference",
    "GuidanceBinding",
    "GuidanceConstraints",
    "GuidanceRequest",
    "ObjectiveKind",
    "PayloadFixtureReference",
    "PriorityKind",
    "PriorityRule",
    "RiskTier",
    "RoleReference",
    "SchedulerHint",
    "build_assessment_guidance",
    "canonical_json",
    "canonical_sha256",
    "parse_assessment_guidance",
]
