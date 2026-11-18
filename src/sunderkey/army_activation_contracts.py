"""Fail-closed Army activation and route-retirement evidence contracts.

These immutable, content-addressed records describe observations and review
decisions for roadmap phases 159 through 161. They do not route traffic,
activate candidates, retire routes, restore routes, call providers, or perform
network operations.
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
from typing import Any, ClassVar

__all__ = [
    "NO_EFFECTS",
    "SCHEMA_VERSION",
    "ActivationContext",
    "ActivationReadiness",
    "ArmyActivationContractError",
    "ArtifactBinding",
    "BudgetLimits",
    "CanaryActivationPacket",
    "CanaryDisposition",
    "CanaryObservation",
    "CanaryStatus",
    "CollaborationScorecard",
    "EquivalenceStatus",
    "EvidenceReference",
    "EvidenceSafety",
    "ExactSystemBinding",
    "IndependentReview",
    "ReadinessStatus",
    "RetirementDecision",
    "RetirementDisposition",
    "ReviewDecision",
    "ReviewerRole",
    "RollbackContract",
    "RollbackWindow",
    "RouteEquivalenceAssessment",
    "RouteRestorationObservation",
    "ShadowRoutingObservation",
    "ShadowRoutingReport",
    "StageStatus",
    "StopCriterion",
    "assess_activation_readiness",
    "assess_route_equivalence",
    "authorize_bounded_canary",
    "build_rollback_contract",
    "build_shadow_routing_report",
    "canonical_json",
    "canonical_sha256",
    "decide_route_retirement",
    "observe_bounded_canary",
    "observe_route_restoration",
    "parse_contract",
    "verify_contract",
]

SCHEMA_VERSION = 1
MAX_EVIDENCE = 256
MAX_OBSERVATIONS = 10_000
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@)",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType(
    {
        "activation": "none",
        "authorization": "none",
        "deployment": "none",
        "model_calls": "none",
        "network": "none",
        "provider_clients": "none",
        "route_retirement": "none",
        "route_restoration": "none",
        "routing": "none",
        "traffic_duplication": "none",
    }
)


class ArmyActivationContractError(ValueError):
    """Raised when activation evidence fails closed."""


class ReviewerRole(StrEnum):
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


class ReviewDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class EvidenceSafety(StrEnum):
    SAFE = "safe"
    UNSAFE = "unsafe"


class StageStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    BLOCKED = "blocked"


class EquivalenceStatus(StrEnum):
    EQUIVALENT = "equivalent"
    NOT_EQUIVALENT = "not_equivalent"
    BLOCKED = "blocked"


class CanaryStatus(StrEnum):
    READY_FOR_SEPARATE_EXECUTION = "ready_for_separate_execution"
    BLOCKED = "blocked"


class CanaryDisposition(StrEnum):
    PASS = "pass"
    STOPPED = "stopped"
    UNSAFE = "unsafe"


class RetirementDisposition(StrEnum):
    RETIRE = "retire"
    RETAIN = "retain"
    BLOCKED = "blocked"


class ReadinessStatus(StrEnum):
    READY_FOR_SEPARATE_ACTIVATION = "ready_for_separate_activation"
    NOT_READY = "not_ready"
    ROLLBACK_VERIFIED = "rollback_verified"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

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
        raise ArmyActivationContractError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 16:
        raise ArmyActivationContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ArmyActivationContractError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise ArmyActivationContractError(f"{label} contains an unsupported value")


def _safe_text(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ArmyActivationContractError(
            f"{label} must be non-empty text within {maximum} characters"
        )
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise ArmyActivationContractError(f"{label} must contain printable ASCII only")
    if SECRET_RE.search(value):
        raise ArmyActivationContractError(f"{label} appears to contain secret material")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ArmyActivationContractError(f"{label} must be a safe identifier")
    return _safe_text(value, label, 256)


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ArmyActivationContractError(f"{label} must be a safe version")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ArmyActivationContractError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ArmyActivationContractError(f"{label} must be a UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ArmyActivationContractError(f"{label} must be between {minimum} and {maximum}")
    return value


def _exact_fields(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ArmyActivationContractError(f"{label} fields do not match the contract")
    return raw


def _sorted_unique(
    values: Sequence[str], label: str, maximum: int = MAX_EVIDENCE
) -> tuple[str, ...]:
    result = tuple(values)
    if not result or len(result) > maximum or len(set(result)) != len(result):
        raise ArmyActivationContractError(f"{label} must be a non-empty unique bounded sequence")
    for value in result:
        _identifier(value, label)
    if result != tuple(sorted(result)):
        raise ArmyActivationContractError(f"{label} must be sorted")
    return result


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "record_kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _verify_identity(
    prefix: str,
    kind: str,
    record_id: str,
    record_sha256: str,
    body: Mapping[str, Any],
) -> None:
    expected_id, expected_sha = _identity(prefix, kind, body)
    if record_id != expected_id or record_sha256 != expected_sha:
        raise ArmyActivationContractError(f"{kind} identity does not match its content")


def _effects() -> dict[str, str]:
    return dict(NO_EFFECTS)


def _verify_effects(value: Any) -> None:
    if value != dict(NO_EFFECTS):
        raise ArmyActivationContractError("effects must declare NO_EFFECTS")


@dataclass(frozen=True)
class ArtifactBinding:
    artifact_id: str
    version: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.artifact_id, "artifact_id")
        _version(self.version, "version")
        _sha256(self.artifact_sha256, "artifact_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ArtifactBinding:
        raw = _exact_fields(raw, {"artifact_id", "artifact_sha256", "version"}, "artifact binding")
        return cls(raw["artifact_id"], raw["version"], raw["artifact_sha256"])


@dataclass(frozen=True)
class ExactSystemBinding:
    candidate: ArtifactBinding
    profile: ArtifactBinding
    model: ArtifactBinding
    provider: ArtifactBinding
    tool: ArtifactBinding
    prompt: ArtifactBinding
    policy: ArtifactBinding
    roadmap: ArtifactBinding
    qualification: ArtifactBinding

    COMPONENTS: ClassVar[tuple[str, ...]] = (
        "candidate",
        "profile",
        "model",
        "provider",
        "tool",
        "prompt",
        "policy",
        "roadmap",
        "qualification",
    )

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name).to_dict() for name in self.COMPONENTS}

    @classmethod
    def from_dict(cls, raw: Any) -> ExactSystemBinding:
        raw = _exact_fields(raw, set(cls.COMPONENTS), "system binding")
        return cls(**{name: ArtifactBinding.from_dict(raw[name]) for name in cls.COMPONENTS})


@dataclass(frozen=True)
class ActivationContext:
    tenant: ArtifactBinding
    mission: ArtifactBinding
    route: ArtifactBinding
    cohort: ArtifactBinding

    @property
    def context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort.to_dict(),
            "mission": self.mission.to_dict(),
            "route": self.route.to_dict(),
            "tenant": self.tenant.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActivationContext:
        raw = _exact_fields(raw, {"cohort", "mission", "route", "tenant"}, "activation context")
        return cls(
            tenant=ArtifactBinding.from_dict(raw["tenant"]),
            mission=ArtifactBinding.from_dict(raw["mission"]),
            route=ArtifactBinding.from_dict(raw["route"]),
            cohort=ArtifactBinding.from_dict(raw["cohort"]),
        )


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    evidence_sha256: str
    binding_sha256: str
    context_sha256: str
    observed_at: str
    expires_at: str
    contaminated: bool
    safety: EvidenceSafety

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        _identifier(self.evidence_type, "evidence_type")
        _sha256(self.evidence_sha256, "evidence_sha256")
        _sha256(self.binding_sha256, "binding_sha256")
        _sha256(self.context_sha256, "context_sha256")
        observed = _timestamp(self.observed_at, "observed_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= observed:
            raise ArmyActivationContractError("evidence must expire after it was observed")
        if not isinstance(self.contaminated, bool):
            raise ArmyActivationContractError("contaminated must be a boolean")

    def assert_usable(
        self,
        binding: ExactSystemBinding,
        context: ActivationContext,
        at: str,
        label: str,
    ) -> None:
        instant = _timestamp(at, "evaluation time")
        if self.binding_sha256 != binding.binding_sha256:
            raise ArmyActivationContractError(f"{label} has a mismatched system binding")
        if self.context_sha256 != context.context_sha256:
            raise ArmyActivationContractError(f"{label} has a mismatched activation context")
        if self.contaminated:
            raise ArmyActivationContractError(f"{label} is contaminated")
        if self.safety is not EvidenceSafety.SAFE:
            raise ArmyActivationContractError(f"{label} is unsafe")
        if instant < _timestamp(self.observed_at, "observed_at"):
            raise ArmyActivationContractError(f"{label} is from the future")
        if instant >= _timestamp(self.expires_at, "expires_at"):
            raise ArmyActivationContractError(f"{label} is stale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "contaminated": self.contaminated,
            "context_sha256": self.context_sha256,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "evidence_type": self.evidence_type,
            "expires_at": self.expires_at,
            "observed_at": self.observed_at,
            "safety": self.safety.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceReference:
        raw = _exact_fields(
            raw,
            {
                "binding_sha256",
                "contaminated",
                "context_sha256",
                "evidence_id",
                "evidence_sha256",
                "evidence_type",
                "expires_at",
                "observed_at",
                "safety",
            },
            "evidence reference",
        )
        return cls(
            evidence_id=raw["evidence_id"],
            evidence_type=raw["evidence_type"],
            evidence_sha256=raw["evidence_sha256"],
            binding_sha256=raw["binding_sha256"],
            context_sha256=raw["context_sha256"],
            observed_at=raw["observed_at"],
            expires_at=raw["expires_at"],
            contaminated=raw["contaminated"],
            safety=EvidenceSafety(raw["safety"]),
        )


@dataclass(frozen=True)
class IndependentReview:
    role: ReviewerRole
    reviewer_id: str
    reviewer_version: str
    decision: ReviewDecision
    reviewed_at: str
    expires_at: str
    review_sha256: str
    binding_sha256: str
    context_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.reviewer_id, "reviewer_id")
        _version(self.reviewer_version, "reviewer_version")
        reviewed = _timestamp(self.reviewed_at, "reviewed_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= reviewed:
            raise ArmyActivationContractError("review must expire after review time")
        _sha256(self.review_sha256, "review_sha256")
        _sha256(self.binding_sha256, "binding_sha256")
        _sha256(self.context_sha256, "context_sha256")

    def assert_usable(
        self,
        binding: ExactSystemBinding,
        context: ActivationContext,
        at: str,
        excluded_reviewers: set[str],
    ) -> None:
        instant = _timestamp(at, "evaluation time")
        if self.binding_sha256 != binding.binding_sha256:
            raise ArmyActivationContractError("review has a mismatched system binding")
        if self.context_sha256 != context.context_sha256:
            raise ArmyActivationContractError("review has a mismatched activation context")
        if self.reviewer_id in excluded_reviewers:
            raise ArmyActivationContractError("reviewer is not independent")
        if self.decision is not ReviewDecision.APPROVED:
            raise ArmyActivationContractError("review was not approved")
        if instant < _timestamp(self.reviewed_at, "reviewed_at"):
            raise ArmyActivationContractError("review is from the future")
        if instant >= _timestamp(self.expires_at, "expires_at"):
            raise ArmyActivationContractError("review is stale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "context_sha256": self.context_sha256,
            "decision": self.decision.value,
            "expires_at": self.expires_at,
            "review_sha256": self.review_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_id": self.reviewer_id,
            "reviewer_version": self.reviewer_version,
            "role": self.role.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentReview:
        raw = _exact_fields(
            raw,
            {
                "binding_sha256",
                "context_sha256",
                "decision",
                "expires_at",
                "review_sha256",
                "reviewed_at",
                "reviewer_id",
                "reviewer_version",
                "role",
            },
            "independent review",
        )
        return cls(
            role=ReviewerRole(raw["role"]),
            reviewer_id=raw["reviewer_id"],
            reviewer_version=raw["reviewer_version"],
            decision=ReviewDecision(raw["decision"]),
            reviewed_at=raw["reviewed_at"],
            expires_at=raw["expires_at"],
            review_sha256=raw["review_sha256"],
            binding_sha256=raw["binding_sha256"],
            context_sha256=raw["context_sha256"],
        )


def _validate_reviews(
    reviews: Sequence[IndependentReview],
    binding: ExactSystemBinding,
    context: ActivationContext,
    at: str,
    excluded_reviewers: Sequence[str],
) -> tuple[IndependentReview, ...]:
    result = tuple(reviews)
    if len(result) != 2 or {item.role for item in result} != set(ReviewerRole):
        raise ArmyActivationContractError(
            "both independent Control and Assurance reviews are required"
        )
    if len({item.reviewer_id for item in result}) != 2:
        raise ArmyActivationContractError("Control and Assurance reviewers must be independent")
    excluded = set(excluded_reviewers)
    for item in result:
        item.assert_usable(binding, context, at, excluded)
    if result != tuple(sorted(result, key=lambda item: item.role.value)):
        raise ArmyActivationContractError("reviews must be sorted by role")
    return result


@dataclass(frozen=True)
class BudgetLimits:
    maximum_requests: int
    maximum_tokens: int
    maximum_cost_microunits: int
    maximum_duration_seconds: int
    maximum_errors: int

    def __post_init__(self) -> None:
        _bounded_int(self.maximum_requests, "maximum_requests", 1, 10_000_000)
        _bounded_int(self.maximum_tokens, "maximum_tokens", 1, 10_000_000_000)
        _bounded_int(self.maximum_cost_microunits, "maximum_cost_microunits", 1, 10**15)
        _bounded_int(self.maximum_duration_seconds, "maximum_duration_seconds", 1, 2_592_000)
        _bounded_int(self.maximum_errors, "maximum_errors", 0, self.maximum_requests)

    def to_dict(self) -> dict[str, int]:
        return {
            "maximum_cost_microunits": self.maximum_cost_microunits,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "maximum_errors": self.maximum_errors,
            "maximum_requests": self.maximum_requests,
            "maximum_tokens": self.maximum_tokens,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BudgetLimits:
        raw = _exact_fields(
            raw,
            {
                "maximum_cost_microunits",
                "maximum_duration_seconds",
                "maximum_errors",
                "maximum_requests",
                "maximum_tokens",
            },
            "budget limits",
        )
        return cls(**raw)


@dataclass(frozen=True)
class StopCriterion:
    criterion_id: str
    metric: str
    operator: str
    threshold_microunits: int
    critical: bool

    def __post_init__(self) -> None:
        _identifier(self.criterion_id, "criterion_id")
        _identifier(self.metric, "metric")
        if self.operator not in {
            "greater_than",
            "greater_than_or_equal",
            "less_than",
            "less_than_or_equal",
        }:
            raise ArmyActivationContractError("operator is not supported")
        _bounded_int(self.threshold_microunits, "threshold_microunits", 0, 1_000_000)
        if not isinstance(self.critical, bool):
            raise ArmyActivationContractError("critical must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "critical": self.critical,
            "criterion_id": self.criterion_id,
            "metric": self.metric,
            "operator": self.operator,
            "threshold_microunits": self.threshold_microunits,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StopCriterion:
        raw = _exact_fields(
            raw,
            {"critical", "criterion_id", "metric", "operator", "threshold_microunits"},
            "stop criterion",
        )
        return cls(**raw)


@dataclass(frozen=True)
class RollbackWindow:
    opens_at: str
    closes_at: str
    restore_within_seconds: int

    def __post_init__(self) -> None:
        opens = _timestamp(self.opens_at, "opens_at")
        closes = _timestamp(self.closes_at, "closes_at")
        if closes <= opens:
            raise ArmyActivationContractError("rollback window must close after it opens")
        _bounded_int(self.restore_within_seconds, "restore_within_seconds", 1, 604_800)
        if self.restore_within_seconds > int((closes - opens).total_seconds()):
            raise ArmyActivationContractError("restore deadline exceeds rollback window")

    def to_dict(self) -> dict[str, Any]:
        return {
            "closes_at": self.closes_at,
            "opens_at": self.opens_at,
            "restore_within_seconds": self.restore_within_seconds,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RollbackWindow:
        raw = _exact_fields(
            raw,
            {"closes_at", "opens_at", "restore_within_seconds"},
            "rollback window",
        )
        return cls(**raw)


def _base_body(
    binding: ExactSystemBinding,
    context: ActivationContext,
    created_at: str,
) -> dict[str, Any]:
    _timestamp(created_at, "created_at")
    return {
        "binding": binding.to_dict(),
        "context": context.to_dict(),
        "created_at": created_at,
        "effects": _effects(),
        "schema_version": SCHEMA_VERSION,
    }


def _common_from_dict(
    raw: Mapping[str, Any], kind: str
) -> tuple[ExactSystemBinding, ActivationContext, str]:
    if raw["record_kind"] != kind or raw["schema_version"] != SCHEMA_VERSION:
        raise ArmyActivationContractError("record kind or schema version is unsupported")
    _verify_effects(raw["effects"])
    return (
        ExactSystemBinding.from_dict(raw["binding"]),
        ActivationContext.from_dict(raw["context"]),
        raw["created_at"],
    )


@dataclass(frozen=True)
class ShadowRoutingObservation:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    request_fingerprint_sha256: str
    control_result_sha256: str
    candidate_result_sha256: str
    collaboration_trace_sha256: str
    matched: bool
    safe: bool
    evidence: EvidenceReference

    KIND: ClassVar[str] = "shadow_routing_observation"
    PREFIX: ClassVar[str] = "ASO"

    def __post_init__(self) -> None:
        for name in (
            "request_fingerprint_sha256",
            "control_result_sha256",
            "candidate_result_sha256",
            "collaboration_trace_sha256",
        ):
            _sha256(getattr(self, name), name)
        if not isinstance(self.matched, bool) or not isinstance(self.safe, bool):
            raise ArmyActivationContractError("matched and safe must be booleans")
        self.evidence.assert_usable(self.binding, self.context, self.created_at, "shadow evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "candidate_result_sha256": self.candidate_result_sha256,
            "collaboration_trace_sha256": self.collaboration_trace_sha256,
            "control_result_sha256": self.control_result_sha256,
            "evidence": self.evidence.to_dict(),
            "matched": self.matched,
            "request_fingerprint_sha256": self.request_fingerprint_sha256,
            "safe": self.safe,
        }

    @classmethod
    def create(
        cls,
        *,
        binding: ExactSystemBinding,
        context: ActivationContext,
        created_at: str,
        request_fingerprint_sha256: str,
        control_result_sha256: str,
        candidate_result_sha256: str,
        collaboration_trace_sha256: str,
        matched: bool,
        safe: bool,
        evidence: EvidenceReference,
    ) -> ShadowRoutingObservation:
        body = {
            **_base_body(binding, context, created_at),
            "candidate_result_sha256": candidate_result_sha256,
            "collaboration_trace_sha256": collaboration_trace_sha256,
            "control_result_sha256": control_result_sha256,
            "evidence": evidence.to_dict(),
            "matched": matched,
            "request_fingerprint_sha256": request_fingerprint_sha256,
            "safe": safe,
        }
        record_id, digest = _identity(cls.PREFIX, cls.KIND, body)
        return cls(
            record_id,
            digest,
            binding,
            context,
            created_at,
            request_fingerprint_sha256,
            control_result_sha256,
            candidate_result_sha256,
            collaboration_trace_sha256,
            matched,
            safe,
            evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ShadowRoutingObservation:
        expected = {
            "binding",
            "candidate_result_sha256",
            "collaboration_trace_sha256",
            "context",
            "control_result_sha256",
            "created_at",
            "effects",
            "evidence",
            "matched",
            "record_id",
            "record_kind",
            "record_sha256",
            "request_fingerprint_sha256",
            "safe",
            "schema_version",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["request_fingerprint_sha256"],
            raw["control_result_sha256"],
            raw["candidate_result_sha256"],
            raw["collaboration_trace_sha256"],
            raw["matched"],
            raw["safe"],
            EvidenceReference.from_dict(raw["evidence"]),
        )


@dataclass(frozen=True)
class ShadowRoutingReport:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    observation_ids: tuple[str, ...]
    observation_sha256s: tuple[str, ...]
    matched_count: int
    unsafe_count: int
    status: StageStatus
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "shadow_routing_report"
    PREFIX: ClassVar[str] = "ASR"

    def __post_init__(self) -> None:
        ids = _sorted_unique(self.observation_ids, "observation_ids", MAX_OBSERVATIONS)
        object.__setattr__(self, "observation_ids", ids)
        shas = tuple(self.observation_sha256s)
        if len(shas) != len(ids) or len(set(shas)) != len(shas) or shas != tuple(sorted(shas)):
            raise ArmyActivationContractError(
                "observation hashes must be sorted, unique, and aligned"
            )
        for digest in shas:
            _sha256(digest, "observation_sha256")
        _bounded_int(self.matched_count, "matched_count", 0, len(ids))
        _bounded_int(self.unsafe_count, "unsafe_count", 0, len(ids))
        if self.status is StageStatus.PASS and (
            self.matched_count != len(ids) or self.unsafe_count
        ):
            raise ArmyActivationContractError("passing shadow report must match safely")
        for evidence in self.failure_evidence:
            evidence.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if self.status is not StageStatus.PASS and not self.failure_evidence:
            raise ArmyActivationContractError("non-passing shadow report requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "matched_count": self.matched_count,
            "observation_ids": list(self.observation_ids),
            "observation_sha256s": list(self.observation_sha256s),
            "status": self.status.value,
            "unsafe_count": self.unsafe_count,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ShadowRoutingReport:
        expected = {
            "binding",
            "context",
            "created_at",
            "effects",
            "failure_evidence",
            "matched_count",
            "observation_ids",
            "observation_sha256s",
            "record_id",
            "record_kind",
            "record_sha256",
            "schema_version",
            "status",
            "unsafe_count",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            tuple(raw["observation_ids"]),
            tuple(raw["observation_sha256s"]),
            raw["matched_count"],
            raw["unsafe_count"],
            StageStatus(raw["status"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


def build_shadow_routing_report(
    *,
    observations: Sequence[ShadowRoutingObservation],
    created_at: str,
    failure_evidence: Sequence[EvidenceReference] = (),
) -> ShadowRoutingReport:
    items = tuple(observations)
    if not items or len(items) > MAX_OBSERVATIONS:
        raise ArmyActivationContractError("a bounded non-empty observation set is required")
    binding, context = items[0].binding, items[0].context
    if any(item.binding != binding or item.context != context for item in items):
        raise ArmyActivationContractError("shadow observations cross a binding or context boundary")
    ordered = tuple(sorted(items, key=lambda item: item.record_id))
    ids = tuple(item.record_id for item in ordered)
    shas = tuple(sorted(item.record_sha256 for item in ordered))
    matched_count = sum(item.matched for item in items)
    unsafe_count = sum(not item.safe for item in items)
    status = (
        StageStatus.PASS if matched_count == len(items) and unsafe_count == 0 else StageStatus.FAIL
    )
    body = {
        **_base_body(binding, context, created_at),
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "matched_count": matched_count,
        "observation_ids": list(ids),
        "observation_sha256s": list(shas),
        "status": status.value,
        "unsafe_count": unsafe_count,
    }
    record_id, digest = _identity(ShadowRoutingReport.PREFIX, ShadowRoutingReport.KIND, body)
    return ShadowRoutingReport(
        record_id,
        digest,
        binding,
        context,
        created_at,
        ids,
        shas,
        matched_count,
        unsafe_count,
        status,
        tuple(failure_evidence),
    )


@dataclass(frozen=True)
class CollaborationScorecard:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    shadow_report_sha256: str
    evaluated_handoffs: int
    successful_handoffs: int
    ownership_conflicts: int
    evidence_losses: int
    score_microunits: int
    minimum_score_microunits: int
    status: StageStatus
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "collaboration_scorecard"
    PREFIX: ClassVar[str] = "ACS"

    def __post_init__(self) -> None:
        _sha256(self.shadow_report_sha256, "shadow_report_sha256")
        _bounded_int(self.evaluated_handoffs, "evaluated_handoffs", 1, 10_000_000)
        _bounded_int(self.successful_handoffs, "successful_handoffs", 0, self.evaluated_handoffs)
        _bounded_int(self.ownership_conflicts, "ownership_conflicts", 0, self.evaluated_handoffs)
        _bounded_int(self.evidence_losses, "evidence_losses", 0, self.evaluated_handoffs)
        _bounded_int(self.score_microunits, "score_microunits", 0, 1_000_000)
        _bounded_int(self.minimum_score_microunits, "minimum_score_microunits", 1, 1_000_000)
        expected = (self.successful_handoffs * 1_000_000) // self.evaluated_handoffs
        if self.score_microunits != expected:
            raise ArmyActivationContractError(
                "collaboration score is not derived from the handoffs"
            )
        passing = (
            expected >= self.minimum_score_microunits
            and not self.ownership_conflicts
            and not self.evidence_losses
        )
        if (self.status is StageStatus.PASS) != passing:
            raise ArmyActivationContractError(
                "collaboration status does not match the measurements"
            )
        for evidence in self.failure_evidence:
            evidence.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if not passing and not self.failure_evidence:
            raise ArmyActivationContractError("failed collaboration requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "evaluated_handoffs": self.evaluated_handoffs,
            "evidence_losses": self.evidence_losses,
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "minimum_score_microunits": self.minimum_score_microunits,
            "ownership_conflicts": self.ownership_conflicts,
            "score_microunits": self.score_microunits,
            "shadow_report_sha256": self.shadow_report_sha256,
            "status": self.status.value,
            "successful_handoffs": self.successful_handoffs,
        }

    @classmethod
    def create(
        cls,
        *,
        report: ShadowRoutingReport,
        created_at: str,
        evaluated_handoffs: int,
        successful_handoffs: int,
        ownership_conflicts: int,
        evidence_losses: int,
        minimum_score_microunits: int,
        failure_evidence: Sequence[EvidenceReference] = (),
    ) -> CollaborationScorecard:
        _bounded_int(evaluated_handoffs, "evaluated_handoffs", 1, 10_000_000)
        score = (successful_handoffs * 1_000_000) // evaluated_handoffs
        passing = (
            score >= minimum_score_microunits and not ownership_conflicts and not evidence_losses
        )
        status = StageStatus.PASS if passing else StageStatus.FAIL
        body = {
            **_base_body(report.binding, report.context, created_at),
            "evaluated_handoffs": evaluated_handoffs,
            "evidence_losses": evidence_losses,
            "failure_evidence": [item.to_dict() for item in failure_evidence],
            "minimum_score_microunits": minimum_score_microunits,
            "ownership_conflicts": ownership_conflicts,
            "score_microunits": score,
            "shadow_report_sha256": report.record_sha256,
            "status": status.value,
            "successful_handoffs": successful_handoffs,
        }
        record_id, digest = _identity(cls.PREFIX, cls.KIND, body)
        return cls(
            record_id,
            digest,
            report.binding,
            report.context,
            created_at,
            report.record_sha256,
            evaluated_handoffs,
            successful_handoffs,
            ownership_conflicts,
            evidence_losses,
            score,
            minimum_score_microunits,
            status,
            tuple(failure_evidence),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationScorecard:
        expected = {
            "binding",
            "context",
            "created_at",
            "effects",
            "evaluated_handoffs",
            "evidence_losses",
            "failure_evidence",
            "minimum_score_microunits",
            "ownership_conflicts",
            "record_id",
            "record_kind",
            "record_sha256",
            "schema_version",
            "score_microunits",
            "shadow_report_sha256",
            "status",
            "successful_handoffs",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["shadow_report_sha256"],
            raw["evaluated_handoffs"],
            raw["successful_handoffs"],
            raw["ownership_conflicts"],
            raw["evidence_losses"],
            raw["score_microunits"],
            raw["minimum_score_microunits"],
            StageStatus(raw["status"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


@dataclass(frozen=True)
class RouteEquivalenceAssessment:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    shadow_report_sha256: str
    scorecard_sha256: str
    reviews: tuple[IndependentReview, ...]
    excluded_principals: tuple[str, ...]
    status: EquivalenceStatus
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "route_equivalence_assessment"
    PREFIX: ClassVar[str] = "AEA"

    def __post_init__(self) -> None:
        _sha256(self.shadow_report_sha256, "shadow_report_sha256")
        _sha256(self.scorecard_sha256, "scorecard_sha256")
        object.__setattr__(
            self,
            "excluded_principals",
            _sorted_unique(self.excluded_principals, "excluded_principals"),
        )
        _validate_reviews(
            self.reviews, self.binding, self.context, self.created_at, self.excluded_principals
        )
        for evidence in self.failure_evidence:
            evidence.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if self.status is not EquivalenceStatus.EQUIVALENT and not self.failure_evidence:
            raise ArmyActivationContractError("non-equivalence requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "excluded_principals": list(self.excluded_principals),
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "reviews": [item.to_dict() for item in self.reviews],
            "scorecard_sha256": self.scorecard_sha256,
            "shadow_report_sha256": self.shadow_report_sha256,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RouteEquivalenceAssessment:
        expected = {
            "binding",
            "context",
            "created_at",
            "effects",
            "excluded_principals",
            "failure_evidence",
            "record_id",
            "record_kind",
            "record_sha256",
            "reviews",
            "schema_version",
            "scorecard_sha256",
            "shadow_report_sha256",
            "status",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["shadow_report_sha256"],
            raw["scorecard_sha256"],
            tuple(IndependentReview.from_dict(item) for item in raw["reviews"]),
            tuple(raw["excluded_principals"]),
            EquivalenceStatus(raw["status"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


def assess_route_equivalence(
    *,
    report: ShadowRoutingReport,
    scorecard: CollaborationScorecard,
    reviews: Sequence[IndependentReview],
    excluded_principals: Sequence[str],
    created_at: str,
    failure_evidence: Sequence[EvidenceReference] = (),
) -> RouteEquivalenceAssessment:
    if (
        report.binding != scorecard.binding
        or report.context != scorecard.context
        or scorecard.shadow_report_sha256 != report.record_sha256
    ):
        raise ArmyActivationContractError("report and scorecard bindings do not match")
    _validate_reviews(reviews, report.binding, report.context, created_at, excluded_principals)
    status = (
        EquivalenceStatus.EQUIVALENT
        if report.status is StageStatus.PASS and scorecard.status is StageStatus.PASS
        else EquivalenceStatus.NOT_EQUIVALENT
    )
    body = {
        **_base_body(report.binding, report.context, created_at),
        "excluded_principals": list(excluded_principals),
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "reviews": [item.to_dict() for item in reviews],
        "scorecard_sha256": scorecard.record_sha256,
        "shadow_report_sha256": report.record_sha256,
        "status": status.value,
    }
    record_id, digest = _identity(
        RouteEquivalenceAssessment.PREFIX, RouteEquivalenceAssessment.KIND, body
    )
    return RouteEquivalenceAssessment(
        record_id,
        digest,
        report.binding,
        report.context,
        created_at,
        report.record_sha256,
        scorecard.record_sha256,
        tuple(reviews),
        tuple(excluded_principals),
        status,
        tuple(failure_evidence),
    )


@dataclass(frozen=True)
class CanaryActivationPacket:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    equivalence_assessment_sha256: str
    activation_authorization: EvidenceReference
    traffic_basis_points: int
    budgets: BudgetLimits
    stop_criteria: tuple[StopCriterion, ...]
    rollback_window: RollbackWindow
    reviews: tuple[IndependentReview, ...]
    excluded_principals: tuple[str, ...]
    status: CanaryStatus

    KIND: ClassVar[str] = "canary_activation_packet"
    PREFIX: ClassVar[str] = "ACP"

    def __post_init__(self) -> None:
        _sha256(self.equivalence_assessment_sha256, "equivalence_assessment_sha256")
        if self.activation_authorization.evidence_type != "bounded_canary_activation_authorization":
            raise ArmyActivationContractError("a separate bounded canary authorization is required")
        self.activation_authorization.assert_usable(
            self.binding, self.context, self.created_at, "canary authorization"
        )
        _bounded_int(self.traffic_basis_points, "traffic_basis_points", 1, 1_000)
        if (
            not self.stop_criteria
            or len(self.stop_criteria) > 64
            or len({item.criterion_id for item in self.stop_criteria}) != len(self.stop_criteria)
        ):
            raise ArmyActivationContractError(
                "canary stop criteria must be non-empty, unique, and bounded"
            )
        if not any(item.critical for item in self.stop_criteria):
            raise ArmyActivationContractError("canary requires a critical stop criterion")
        if tuple(self.stop_criteria) != tuple(
            sorted(self.stop_criteria, key=lambda item: item.criterion_id)
        ):
            raise ArmyActivationContractError("stop criteria must be sorted")
        object.__setattr__(
            self,
            "excluded_principals",
            _sorted_unique(self.excluded_principals, "excluded_principals"),
        )
        _validate_reviews(
            self.reviews, self.binding, self.context, self.created_at, self.excluded_principals
        )
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "activation_authorization": self.activation_authorization.to_dict(),
            "budgets": self.budgets.to_dict(),
            "equivalence_assessment_sha256": self.equivalence_assessment_sha256,
            "excluded_principals": list(self.excluded_principals),
            "reviews": [item.to_dict() for item in self.reviews],
            "rollback_window": self.rollback_window.to_dict(),
            "status": self.status.value,
            "stop_criteria": [item.to_dict() for item in self.stop_criteria],
            "traffic_basis_points": self.traffic_basis_points,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CanaryActivationPacket:
        expected = {
            "activation_authorization",
            "binding",
            "budgets",
            "context",
            "created_at",
            "effects",
            "equivalence_assessment_sha256",
            "excluded_principals",
            "record_id",
            "record_kind",
            "record_sha256",
            "reviews",
            "rollback_window",
            "schema_version",
            "status",
            "stop_criteria",
            "traffic_basis_points",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["equivalence_assessment_sha256"],
            EvidenceReference.from_dict(raw["activation_authorization"]),
            raw["traffic_basis_points"],
            BudgetLimits.from_dict(raw["budgets"]),
            tuple(StopCriterion.from_dict(item) for item in raw["stop_criteria"]),
            RollbackWindow.from_dict(raw["rollback_window"]),
            tuple(IndependentReview.from_dict(item) for item in raw["reviews"]),
            tuple(raw["excluded_principals"]),
            CanaryStatus(raw["status"]),
        )


def authorize_bounded_canary(
    *,
    assessment: RouteEquivalenceAssessment,
    activation_authorization: EvidenceReference,
    traffic_basis_points: int,
    budgets: BudgetLimits,
    stop_criteria: Sequence[StopCriterion],
    rollback_window: RollbackWindow,
    reviews: Sequence[IndependentReview],
    excluded_principals: Sequence[str],
    created_at: str,
) -> CanaryActivationPacket:
    if assessment.status is not EquivalenceStatus.EQUIVALENT:
        raise ArmyActivationContractError("canary requires an equivalent route assessment")
    _validate_reviews(
        reviews, assessment.binding, assessment.context, created_at, excluded_principals
    )
    status = CanaryStatus.READY_FOR_SEPARATE_EXECUTION
    body = {
        **_base_body(assessment.binding, assessment.context, created_at),
        "activation_authorization": activation_authorization.to_dict(),
        "budgets": budgets.to_dict(),
        "equivalence_assessment_sha256": assessment.record_sha256,
        "excluded_principals": list(excluded_principals),
        "reviews": [item.to_dict() for item in reviews],
        "rollback_window": rollback_window.to_dict(),
        "status": status.value,
        "stop_criteria": [item.to_dict() for item in stop_criteria],
        "traffic_basis_points": traffic_basis_points,
    }
    record_id, digest = _identity(CanaryActivationPacket.PREFIX, CanaryActivationPacket.KIND, body)
    return CanaryActivationPacket(
        record_id,
        digest,
        assessment.binding,
        assessment.context,
        created_at,
        assessment.record_sha256,
        activation_authorization,
        traffic_basis_points,
        budgets,
        tuple(stop_criteria),
        rollback_window,
        tuple(reviews),
        tuple(excluded_principals),
        status,
    )


@dataclass(frozen=True)
class CanaryObservation:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    canary_packet_sha256: str
    requests_used: int
    tokens_used: int
    cost_microunits_used: int
    duration_seconds: int
    errors: int
    triggered_criteria: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]
    failure_evidence: tuple[EvidenceReference, ...]
    disposition: CanaryDisposition

    KIND: ClassVar[str] = "canary_observation"
    PREFIX: ClassVar[str] = "ACO"

    def __post_init__(self) -> None:
        _sha256(self.canary_packet_sha256, "canary_packet_sha256")
        for name in (
            "requests_used",
            "tokens_used",
            "cost_microunits_used",
            "duration_seconds",
            "errors",
        ):
            _bounded_int(getattr(self, name), name, 0, 10**15)
        object.__setattr__(self, "triggered_criteria", tuple(sorted(set(self.triggered_criteria))))
        if not self.evidence:
            raise ArmyActivationContractError("canary observation requires evidence")
        for item in (*self.evidence, *self.failure_evidence):
            item.assert_usable(self.binding, self.context, self.created_at, "canary evidence")
        if self.disposition is not CanaryDisposition.PASS and not self.failure_evidence:
            raise ArmyActivationContractError("non-passing canary requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "canary_packet_sha256": self.canary_packet_sha256,
            "cost_microunits_used": self.cost_microunits_used,
            "disposition": self.disposition.value,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
            "evidence": [item.to_dict() for item in self.evidence],
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "requests_used": self.requests_used,
            "tokens_used": self.tokens_used,
            "triggered_criteria": list(self.triggered_criteria),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CanaryObservation:
        expected = {
            "binding",
            "canary_packet_sha256",
            "context",
            "cost_microunits_used",
            "created_at",
            "disposition",
            "duration_seconds",
            "effects",
            "errors",
            "evidence",
            "failure_evidence",
            "record_id",
            "record_kind",
            "record_sha256",
            "requests_used",
            "schema_version",
            "tokens_used",
            "triggered_criteria",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["canary_packet_sha256"],
            raw["requests_used"],
            raw["tokens_used"],
            raw["cost_microunits_used"],
            raw["duration_seconds"],
            raw["errors"],
            tuple(raw["triggered_criteria"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["evidence"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
            CanaryDisposition(raw["disposition"]),
        )


def observe_bounded_canary(
    *,
    packet: CanaryActivationPacket,
    created_at: str,
    requests_used: int,
    tokens_used: int,
    cost_microunits_used: int,
    duration_seconds: int,
    errors: int,
    triggered_criteria: Sequence[str],
    evidence: Sequence[EvidenceReference],
    failure_evidence: Sequence[EvidenceReference] = (),
) -> CanaryObservation:
    if packet.status is not CanaryStatus.READY_FOR_SEPARATE_EXECUTION:
        raise ArmyActivationContractError("canary packet is not ready")
    triggered = tuple(sorted(set(triggered_criteria)))
    known = {item.criterion_id for item in packet.stop_criteria}
    if not set(triggered) <= known:
        raise ArmyActivationContractError("unknown stop criterion was reported")
    exceeded = (
        requests_used > packet.budgets.maximum_requests
        or tokens_used > packet.budgets.maximum_tokens
        or cost_microunits_used > packet.budgets.maximum_cost_microunits
        or duration_seconds > packet.budgets.maximum_duration_seconds
        or errors > packet.budgets.maximum_errors
    )
    disposition = CanaryDisposition.STOPPED if triggered or exceeded else CanaryDisposition.PASS
    body = {
        **_base_body(packet.binding, packet.context, created_at),
        "canary_packet_sha256": packet.record_sha256,
        "cost_microunits_used": cost_microunits_used,
        "disposition": disposition.value,
        "duration_seconds": duration_seconds,
        "errors": errors,
        "evidence": [item.to_dict() for item in evidence],
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "requests_used": requests_used,
        "tokens_used": tokens_used,
        "triggered_criteria": list(triggered),
    }
    record_id, digest = _identity(CanaryObservation.PREFIX, CanaryObservation.KIND, body)
    return CanaryObservation(
        record_id,
        digest,
        packet.binding,
        packet.context,
        created_at,
        packet.record_sha256,
        requests_used,
        tokens_used,
        cost_microunits_used,
        duration_seconds,
        errors,
        triggered,
        tuple(evidence),
        tuple(failure_evidence),
        disposition,
    )


@dataclass(frozen=True)
class RetirementDecision:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    canary_observation_sha256s: tuple[str, ...]
    reviews: tuple[IndependentReview, ...]
    excluded_principals: tuple[str, ...]
    disposition: RetirementDisposition
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "retirement_decision"
    PREFIX: ClassVar[str] = "ARD"

    def __post_init__(self) -> None:
        shas = tuple(self.canary_observation_sha256s)
        if not shas or len(set(shas)) != len(shas) or shas != tuple(sorted(shas)):
            raise ArmyActivationContractError("canary observation hashes must be sorted and unique")
        for digest in shas:
            _sha256(digest, "canary_observation_sha256")
        object.__setattr__(
            self,
            "excluded_principals",
            _sorted_unique(self.excluded_principals, "excluded_principals"),
        )
        _validate_reviews(
            self.reviews, self.binding, self.context, self.created_at, self.excluded_principals
        )
        for item in self.failure_evidence:
            item.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if self.disposition is not RetirementDisposition.RETIRE and not self.failure_evidence:
            raise ArmyActivationContractError("non-retirement requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "canary_observation_sha256s": list(self.canary_observation_sha256s),
            "disposition": self.disposition.value,
            "excluded_principals": list(self.excluded_principals),
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "reviews": [item.to_dict() for item in self.reviews],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetirementDecision:
        expected = {
            "binding",
            "canary_observation_sha256s",
            "context",
            "created_at",
            "disposition",
            "effects",
            "excluded_principals",
            "failure_evidence",
            "record_id",
            "record_kind",
            "record_sha256",
            "reviews",
            "schema_version",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            tuple(raw["canary_observation_sha256s"]),
            tuple(IndependentReview.from_dict(item) for item in raw["reviews"]),
            tuple(raw["excluded_principals"]),
            RetirementDisposition(raw["disposition"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


def decide_route_retirement(
    *,
    observations: Sequence[CanaryObservation],
    reviews: Sequence[IndependentReview],
    excluded_principals: Sequence[str],
    created_at: str,
    failure_evidence: Sequence[EvidenceReference] = (),
) -> RetirementDecision:
    items = tuple(observations)
    if not items:
        raise ArmyActivationContractError("retirement requires canary observations")
    binding, context = items[0].binding, items[0].context
    if any(item.binding != binding or item.context != context for item in items):
        raise ArmyActivationContractError("canary observations cross a binding or context boundary")
    _validate_reviews(reviews, binding, context, created_at, excluded_principals)
    disposition = (
        RetirementDisposition.RETIRE
        if all(item.disposition is CanaryDisposition.PASS for item in items)
        else RetirementDisposition.RETAIN
    )
    shas = tuple(sorted(item.record_sha256 for item in items))
    body = {
        **_base_body(binding, context, created_at),
        "canary_observation_sha256s": list(shas),
        "disposition": disposition.value,
        "excluded_principals": list(excluded_principals),
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "reviews": [item.to_dict() for item in reviews],
    }
    record_id, digest = _identity(RetirementDecision.PREFIX, RetirementDecision.KIND, body)
    return RetirementDecision(
        record_id,
        digest,
        binding,
        context,
        created_at,
        shas,
        tuple(reviews),
        tuple(excluded_principals),
        disposition,
        tuple(failure_evidence),
    )


@dataclass(frozen=True)
class RollbackContract:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    retirement_decision_sha256: str
    prior_route: ArtifactBinding
    rollback_authorization: EvidenceReference
    rollback_window: RollbackWindow
    budgets: BudgetLimits
    stop_criteria: tuple[StopCriterion, ...]
    reviews: tuple[IndependentReview, ...]
    excluded_principals: tuple[str, ...]

    KIND: ClassVar[str] = "rollback_contract"
    PREFIX: ClassVar[str] = "ARB"

    def __post_init__(self) -> None:
        _sha256(self.retirement_decision_sha256, "retirement_decision_sha256")
        if self.prior_route == self.context.route:
            raise ArmyActivationContractError(
                "prior route must be distinct from the candidate route"
            )
        if self.rollback_authorization.evidence_type != "route_rollback_authorization":
            raise ArmyActivationContractError("route rollback authorization is required")
        self.rollback_authorization.assert_usable(
            self.binding, self.context, self.created_at, "rollback authorization"
        )
        if not self.stop_criteria:
            raise ArmyActivationContractError("rollback contract requires stop criteria")
        object.__setattr__(
            self,
            "excluded_principals",
            _sorted_unique(self.excluded_principals, "excluded_principals"),
        )
        _validate_reviews(
            self.reviews, self.binding, self.context, self.created_at, self.excluded_principals
        )
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "budgets": self.budgets.to_dict(),
            "excluded_principals": list(self.excluded_principals),
            "prior_route": self.prior_route.to_dict(),
            "retirement_decision_sha256": self.retirement_decision_sha256,
            "reviews": [item.to_dict() for item in self.reviews],
            "rollback_authorization": self.rollback_authorization.to_dict(),
            "rollback_window": self.rollback_window.to_dict(),
            "stop_criteria": [item.to_dict() for item in self.stop_criteria],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RollbackContract:
        expected = {
            "binding",
            "budgets",
            "context",
            "created_at",
            "effects",
            "excluded_principals",
            "prior_route",
            "record_id",
            "record_kind",
            "record_sha256",
            "retirement_decision_sha256",
            "reviews",
            "rollback_authorization",
            "rollback_window",
            "schema_version",
            "stop_criteria",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["retirement_decision_sha256"],
            ArtifactBinding.from_dict(raw["prior_route"]),
            EvidenceReference.from_dict(raw["rollback_authorization"]),
            RollbackWindow.from_dict(raw["rollback_window"]),
            BudgetLimits.from_dict(raw["budgets"]),
            tuple(StopCriterion.from_dict(item) for item in raw["stop_criteria"]),
            tuple(IndependentReview.from_dict(item) for item in raw["reviews"]),
            tuple(raw["excluded_principals"]),
        )


def build_rollback_contract(
    *,
    decision: RetirementDecision,
    prior_route: ArtifactBinding,
    rollback_authorization: EvidenceReference,
    rollback_window: RollbackWindow,
    budgets: BudgetLimits,
    stop_criteria: Sequence[StopCriterion],
    reviews: Sequence[IndependentReview],
    excluded_principals: Sequence[str],
    created_at: str,
) -> RollbackContract:
    if decision.disposition is not RetirementDisposition.RETIRE:
        raise ArmyActivationContractError("rollback contract requires a retirement decision")
    body = {
        **_base_body(decision.binding, decision.context, created_at),
        "budgets": budgets.to_dict(),
        "excluded_principals": list(excluded_principals),
        "prior_route": prior_route.to_dict(),
        "retirement_decision_sha256": decision.record_sha256,
        "reviews": [item.to_dict() for item in reviews],
        "rollback_authorization": rollback_authorization.to_dict(),
        "rollback_window": rollback_window.to_dict(),
        "stop_criteria": [item.to_dict() for item in stop_criteria],
    }
    record_id, digest = _identity(RollbackContract.PREFIX, RollbackContract.KIND, body)
    return RollbackContract(
        record_id,
        digest,
        decision.binding,
        decision.context,
        created_at,
        decision.record_sha256,
        prior_route,
        rollback_authorization,
        rollback_window,
        budgets,
        tuple(stop_criteria),
        tuple(reviews),
        tuple(excluded_principals),
    )


@dataclass(frozen=True)
class RouteRestorationObservation:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    rollback_contract_sha256: str
    restored_route_sha256: str
    restored_at: str
    evidence: EvidenceReference
    verified: bool
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "route_restoration_observation"
    PREFIX: ClassVar[str] = "ARO"

    def __post_init__(self) -> None:
        _sha256(self.rollback_contract_sha256, "rollback_contract_sha256")
        _sha256(self.restored_route_sha256, "restored_route_sha256")
        if _timestamp(self.restored_at, "restored_at") > _timestamp(self.created_at, "created_at"):
            raise ArmyActivationContractError("restoration cannot be observed before it occurs")
        self.evidence.assert_usable(
            self.binding, self.context, self.created_at, "restoration evidence"
        )
        for item in self.failure_evidence:
            item.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if not self.verified and not self.failure_evidence:
            raise ArmyActivationContractError("failed restoration requires failure evidence")
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "evidence": self.evidence.to_dict(),
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "restored_at": self.restored_at,
            "restored_route_sha256": self.restored_route_sha256,
            "rollback_contract_sha256": self.rollback_contract_sha256,
            "verified": self.verified,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RouteRestorationObservation:
        expected = {
            "binding",
            "context",
            "created_at",
            "effects",
            "evidence",
            "failure_evidence",
            "record_id",
            "record_kind",
            "record_sha256",
            "restored_at",
            "restored_route_sha256",
            "rollback_contract_sha256",
            "schema_version",
            "verified",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["rollback_contract_sha256"],
            raw["restored_route_sha256"],
            raw["restored_at"],
            EvidenceReference.from_dict(raw["evidence"]),
            raw["verified"],
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


def observe_route_restoration(
    *,
    contract: RollbackContract,
    restored_route: ArtifactBinding,
    restored_at: str,
    created_at: str,
    evidence: EvidenceReference,
    failure_evidence: Sequence[EvidenceReference] = (),
) -> RouteRestorationObservation:
    instant = _timestamp(restored_at, "restored_at")
    window_ok = (
        _timestamp(contract.rollback_window.opens_at, "opens_at")
        <= instant
        < _timestamp(contract.rollback_window.closes_at, "closes_at")
    )
    verified = window_ok and restored_route == contract.prior_route
    body = {
        **_base_body(contract.binding, contract.context, created_at),
        "evidence": evidence.to_dict(),
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "restored_at": restored_at,
        "restored_route_sha256": restored_route.artifact_sha256,
        "rollback_contract_sha256": contract.record_sha256,
        "verified": verified,
    }
    record_id, digest = _identity(
        RouteRestorationObservation.PREFIX, RouteRestorationObservation.KIND, body
    )
    return RouteRestorationObservation(
        record_id,
        digest,
        contract.binding,
        contract.context,
        created_at,
        contract.record_sha256,
        restored_route.artifact_sha256,
        restored_at,
        evidence,
        verified,
        tuple(failure_evidence),
    )


@dataclass(frozen=True)
class ActivationReadiness:
    record_id: str
    record_sha256: str
    binding: ExactSystemBinding
    context: ActivationContext
    created_at: str
    equivalence_assessment_sha256: str
    canary_packet_sha256: str
    retirement_decision_sha256: str
    rollback_contract_sha256: str
    restoration_observation_sha256: str | None
    reviews: tuple[IndependentReview, ...]
    excluded_principals: tuple[str, ...]
    status: ReadinessStatus
    failure_evidence: tuple[EvidenceReference, ...]

    KIND: ClassVar[str] = "activation_readiness"
    PREFIX: ClassVar[str] = "AAR"

    def __post_init__(self) -> None:
        for name in (
            "equivalence_assessment_sha256",
            "canary_packet_sha256",
            "retirement_decision_sha256",
            "rollback_contract_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.restoration_observation_sha256 is not None:
            _sha256(self.restoration_observation_sha256, "restoration_observation_sha256")
        object.__setattr__(
            self,
            "excluded_principals",
            _sorted_unique(self.excluded_principals, "excluded_principals"),
        )
        _validate_reviews(
            self.reviews, self.binding, self.context, self.created_at, self.excluded_principals
        )
        for item in self.failure_evidence:
            item.assert_usable(self.binding, self.context, self.created_at, "failure evidence")
        if self.status is ReadinessStatus.NOT_READY and not self.failure_evidence:
            raise ArmyActivationContractError("not-ready status requires failure evidence")
        if (
            self.status is ReadinessStatus.ROLLBACK_VERIFIED
            and self.restoration_observation_sha256 is None
        ):
            raise ArmyActivationContractError(
                "rollback readiness requires a restoration observation"
            )
        _verify_identity(self.PREFIX, self.KIND, self.record_id, self.record_sha256, self._body())

    def _body(self) -> dict[str, Any]:
        return {
            **_base_body(self.binding, self.context, self.created_at),
            "canary_packet_sha256": self.canary_packet_sha256,
            "equivalence_assessment_sha256": self.equivalence_assessment_sha256,
            "excluded_principals": list(self.excluded_principals),
            "failure_evidence": [item.to_dict() for item in self.failure_evidence],
            "restoration_observation_sha256": self.restoration_observation_sha256,
            "retirement_decision_sha256": self.retirement_decision_sha256,
            "reviews": [item.to_dict() for item in self.reviews],
            "rollback_contract_sha256": self.rollback_contract_sha256,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "record_id": self.record_id,
            "record_kind": self.KIND,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActivationReadiness:
        expected = {
            "binding",
            "canary_packet_sha256",
            "context",
            "created_at",
            "effects",
            "equivalence_assessment_sha256",
            "excluded_principals",
            "failure_evidence",
            "record_id",
            "record_kind",
            "record_sha256",
            "restoration_observation_sha256",
            "retirement_decision_sha256",
            "reviews",
            "rollback_contract_sha256",
            "schema_version",
            "status",
        }
        raw = _exact_fields(raw, expected, cls.KIND)
        binding, context, created_at = _common_from_dict(raw, cls.KIND)
        return cls(
            raw["record_id"],
            raw["record_sha256"],
            binding,
            context,
            created_at,
            raw["equivalence_assessment_sha256"],
            raw["canary_packet_sha256"],
            raw["retirement_decision_sha256"],
            raw["rollback_contract_sha256"],
            raw["restoration_observation_sha256"],
            tuple(IndependentReview.from_dict(item) for item in raw["reviews"]),
            tuple(raw["excluded_principals"]),
            ReadinessStatus(raw["status"]),
            tuple(EvidenceReference.from_dict(item) for item in raw["failure_evidence"]),
        )


def assess_activation_readiness(
    *,
    assessment: RouteEquivalenceAssessment,
    packet: CanaryActivationPacket,
    decision: RetirementDecision,
    rollback: RollbackContract,
    restoration: RouteRestorationObservation | None,
    reviews: Sequence[IndependentReview],
    excluded_principals: Sequence[str],
    created_at: str,
    failure_evidence: Sequence[EvidenceReference] = (),
) -> ActivationReadiness:
    records = (packet, decision, rollback)
    if any(
        item.binding != assessment.binding or item.context != assessment.context for item in records
    ):
        raise ArmyActivationContractError("activation records cross a binding or context boundary")
    if (
        packet.equivalence_assessment_sha256 != assessment.record_sha256
        or rollback.retirement_decision_sha256 != decision.record_sha256
    ):
        raise ArmyActivationContractError("activation record chain is not intact")
    if restoration is not None and (
        restoration.binding != assessment.binding
        or restoration.context != assessment.context
        or restoration.rollback_contract_sha256 != rollback.record_sha256
    ):
        raise ArmyActivationContractError("restoration record does not match the activation chain")
    _validate_reviews(
        reviews, assessment.binding, assessment.context, created_at, excluded_principals
    )
    if restoration is not None and restoration.verified:
        status = ReadinessStatus.ROLLBACK_VERIFIED
    elif (
        assessment.status is EquivalenceStatus.EQUIVALENT
        and packet.status is CanaryStatus.READY_FOR_SEPARATE_EXECUTION
        and decision.disposition is RetirementDisposition.RETIRE
    ):
        status = ReadinessStatus.READY_FOR_SEPARATE_ACTIVATION
    else:
        status = ReadinessStatus.NOT_READY
    body = {
        **_base_body(assessment.binding, assessment.context, created_at),
        "canary_packet_sha256": packet.record_sha256,
        "equivalence_assessment_sha256": assessment.record_sha256,
        "excluded_principals": list(excluded_principals),
        "failure_evidence": [item.to_dict() for item in failure_evidence],
        "restoration_observation_sha256": restoration.record_sha256 if restoration else None,
        "retirement_decision_sha256": decision.record_sha256,
        "reviews": [item.to_dict() for item in reviews],
        "rollback_contract_sha256": rollback.record_sha256,
        "status": status.value,
    }
    record_id, digest = _identity(ActivationReadiness.PREFIX, ActivationReadiness.KIND, body)
    return ActivationReadiness(
        record_id,
        digest,
        assessment.binding,
        assessment.context,
        created_at,
        assessment.record_sha256,
        packet.record_sha256,
        decision.record_sha256,
        rollback.record_sha256,
        restoration.record_sha256 if restoration else None,
        tuple(reviews),
        tuple(excluded_principals),
        status,
        tuple(failure_evidence),
    )


RECORD_TYPES: Mapping[str, type[Any]] = MappingProxyType(
    {
        item.KIND: item
        for item in (
            ShadowRoutingObservation,
            ShadowRoutingReport,
            CollaborationScorecard,
            RouteEquivalenceAssessment,
            CanaryActivationPacket,
            CanaryObservation,
            RetirementDecision,
            RollbackContract,
            RouteRestorationObservation,
            ActivationReadiness,
        )
    }
)


def parse_contract(raw: Any) -> Any:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("record_kind"), str):
        raise ArmyActivationContractError("record_kind is required")
    record_type = RECORD_TYPES.get(raw["record_kind"])
    if record_type is None:
        raise ArmyActivationContractError("record_kind is unsupported")
    return record_type.from_dict(raw)


def verify_contract(record: Any) -> None:
    """Rebuild a supported record and verify its strict fields and identity."""

    if not hasattr(record, "to_dict"):
        raise ArmyActivationContractError("record does not support contract serialization")
    rebuilt = parse_contract(record.to_dict())
    if rebuilt != record:
        raise ArmyActivationContractError("record does not round trip exactly")
