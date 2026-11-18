"""Deterministic evidence-aware asset risk scoring contracts.

The module scores only caller-supplied, content-addressed evidence. It has no
network, provider, credential, discovery, target, deployment, remediation, or
authorization capability.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
CONTRACT_DOMAIN = "sunderkey.asset-risk-scorecard.v1"
MAX_ASSETS = 10_000
MAX_FINDINGS = 100_000
MAX_AGE_SECONDS = 31_536_000
MAX_BPS = 10_000

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credentials": "none",
        "deployment": "none",
        "discovery": "none",
        "filesystem_discovery": "none",
        "live_target_state": "not_observed",
        "network": "none",
        "prediction": "none",
        "provider_calls": "none",
        "remediation": "none",
        "target_actions": "none",
    }
)

BASELINE_SEVERITY_BPS = MappingProxyType(
    {"critical": 10_000, "high": 6_000, "info": 250, "low": 1_000, "medium": 3_000}
)
COMPOSITE_SEVERITY_BPS = MappingProxyType(
    {"critical": 10_000, "high": 7_500, "info": 500, "low": 2_000, "medium": 4_500}
)
VALIDATION_BONUS_BPS = MappingProxyType(
    {"candidate": 0, "invalid": 0, "reproduced": 1_000, "verified": 500}
)
REMEDIATION_BONUS_BPS = MappingProxyType(
    {
        "in_progress": 250,
        "open_unaddressed": 750,
        "planned": 500,
        "reported_remediated": 0,
    }
)
EXCEPTION_BONUS_BPS = MappingProxyType({"approved": 750, "none": 0, "temporary": 500})

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_CONTENT_ID_RE = re.compile(r"[A-Z]{3}-[0-9A-F]{32}\Z")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)


class AssetRiskScoringError(ValueError):
    """Raised when score inputs or serialized scorecards fail closed."""


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingValidationState(StrEnum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    REPRODUCED = "reproduced"
    INVALID = "invalid"


class FindingRecordState(StrEnum):
    ACTIVE = "active"
    MERGED_AWAY = "merged_away"


class RemediationState(StrEnum):
    OPEN_UNADDRESSED = "open_unaddressed"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    REPORTED_REMEDIATED = "reported_remediated"


class ExceptionState(StrEnum):
    NONE = "none"
    TEMPORARY = "temporary"
    APPROVED = "approved"


class ReachabilityState(StrEnum):
    CONFIRMED = "confirmed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


class EvidenceState(StrEnum):
    COMPLETE = "complete"
    STALE = "stale"
    INSUFFICIENT = "insufficient"
    INVALID = "invalid"


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 18:
        raise AssetRiskScoringError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssetRiskScoringError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AssetRiskScoringError(f"{label} contains an unsupported value")


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON without secret-like material."""

    _validate_json(value, "value")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AssetRiskScoringError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise AssetRiskScoringError("secret-like material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise AssetRiskScoringError(f"{label} fields do not match the contract")
    return raw


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise AssetRiskScoringError(f"{label} must be a sequence")
    return value


def _identifier(value: Any, label: str, *, namespace: str | None = None) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_RE.fullmatch(value) is None
        or _SECRET_RE.search(value)
    ):
        raise AssetRiskScoringError(f"{label} must be a safe identifier")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise AssetRiskScoringError(f"{label} must use the {namespace} namespace")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AssetRiskScoringError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise AssetRiskScoringError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AssetRiskScoringError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AssetRiskScoringError(f"{label} is outside the supported range")
    return value


def _bps(value: Any, label: str) -> int:
    return _bounded_int(value, label, 0, MAX_BPS)


def _version(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _VERSION_RE.fullmatch(value) is None
        or value.lower() in {"current", "head", "latest", "main", "master", "tip"}
    ):
        raise AssetRiskScoringError(f"{label} must be an exact version")
    return value


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _content_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise AssetRiskScoringError(f"{label} is invalid")
    return value


def _ceil_ratio(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


@dataclass(frozen=True, slots=True)
class RiskScoringPolicy:
    policy_version: str
    maximum_evidence_age_seconds: int
    minimum_evidence_coverage_bps: int
    policy_id: str = field(init=False)
    policy_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.asset-risk-scoring-policy.v1"

    def __post_init__(self) -> None:
        _version(self.policy_version, "policy_version")
        _bounded_int(
            self.maximum_evidence_age_seconds,
            "maximum_evidence_age_seconds",
            1,
            MAX_AGE_SECONDS,
        )
        _bps(self.minimum_evidence_coverage_bps, "minimum_evidence_coverage_bps")
        identity, digest = _identity("RSP", self.KIND, self.body())
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "maximum_evidence_age_seconds": self.maximum_evidence_age_seconds,
            "minimum_evidence_coverage_bps": self.minimum_evidence_coverage_bps,
            "policy_version": self.policy_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "policy_id": self.policy_id, "policy_sha256": self.policy_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> RiskScoringPolicy:
        item = dict(
            _exact(
                raw,
                {
                    "maximum_evidence_age_seconds",
                    "minimum_evidence_coverage_bps",
                    "policy_id",
                    "policy_sha256",
                    "policy_version",
                },
                "risk scoring policy",
            )
        )
        identity = item.pop("policy_id")
        digest = item.pop("policy_sha256")
        result = cls(**item)
        if result.policy_id != identity or result.policy_sha256 != digest:
            raise AssetRiskScoringError("risk scoring policy content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class AssetCriticalityExposureBinding:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    asset_ref: str
    asset_sha256: str
    criticality_bps: int
    exposure_bps: int
    evidence_coverage_bps: int
    uncertainty_bps: int
    evidence_sha256: str
    observed_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.asset-criticality-exposure-binding.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.asset_ref, "asset_ref", namespace="assetref")
        _sha256(self.asset_sha256, "asset_sha256")
        _bps(self.criticality_bps, "criticality_bps")
        _bps(self.exposure_bps, "exposure_bps")
        _bps(self.evidence_coverage_bps, "evidence_coverage_bps")
        _bps(self.uncertainty_bps, "uncertainty_bps")
        _sha256(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.observed_at, "observed_at")
        identity, digest = _identity("ACB", self.KIND, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_ref": self.asset_ref,
            "asset_sha256": self.asset_sha256,
            "context_ref": self.context_ref,
            "criticality_bps": self.criticality_bps,
            "evidence_coverage_bps": self.evidence_coverage_bps,
            "evidence_sha256": self.evidence_sha256,
            "exposure_bps": self.exposure_bps,
            "observed_at": self.observed_at,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
            "uncertainty_bps": self.uncertainty_bps,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "binding_id": self.binding_id, "binding_sha256": self.binding_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> AssetCriticalityExposureBinding:
        fields = {
            "asset_ref",
            "asset_sha256",
            "binding_id",
            "binding_sha256",
            "context_ref",
            "criticality_bps",
            "evidence_coverage_bps",
            "evidence_sha256",
            "exposure_bps",
            "observed_at",
            "scope_sha256",
            "tenant_ref",
            "uncertainty_bps",
        }
        item = dict(_exact(raw, fields, "asset binding"))
        identity = item.pop("binding_id")
        digest = item.pop("binding_sha256")
        result = cls(**item)
        if result.binding_id != identity or result.binding_sha256 != digest:
            raise AssetRiskScoringError("asset binding content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class OpenFindingRecord:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    asset_ref: str
    asset_sha256: str
    finding_ref: str
    finding_sha256: str
    severity: Severity
    confidence_bps: int
    validation_state: FindingValidationState
    record_state: FindingRecordState
    remediation_state: RemediationState
    exception_state: ExceptionState
    evidence_coverage_bps: int
    evidence_sha256: str
    observed_at: str
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.open-finding-record.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.asset_ref, "asset_ref", namespace="assetref")
        _sha256(self.asset_sha256, "asset_sha256")
        _identifier(self.finding_ref, "finding_ref", namespace="findingref")
        _sha256(self.finding_sha256, "finding_sha256")
        _bps(self.confidence_bps, "confidence_bps")
        _bps(self.evidence_coverage_bps, "evidence_coverage_bps")
        _sha256(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.observed_at, "observed_at")
        identity, digest = _identity("OFR", self.KIND, self.body())
        object.__setattr__(self, "record_id", identity)
        object.__setattr__(self, "record_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_ref": self.asset_ref,
            "asset_sha256": self.asset_sha256,
            "confidence_bps": self.confidence_bps,
            "context_ref": self.context_ref,
            "evidence_coverage_bps": self.evidence_coverage_bps,
            "evidence_sha256": self.evidence_sha256,
            "exception_state": self.exception_state.value,
            "finding_ref": self.finding_ref,
            "finding_sha256": self.finding_sha256,
            "observed_at": self.observed_at,
            "record_state": self.record_state.value,
            "remediation_state": self.remediation_state.value,
            "scope_sha256": self.scope_sha256,
            "severity": self.severity.value,
            "tenant_ref": self.tenant_ref,
            "validation_state": self.validation_state.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "record_id": self.record_id, "record_sha256": self.record_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> OpenFindingRecord:
        fields = {
            "asset_ref",
            "asset_sha256",
            "confidence_bps",
            "context_ref",
            "evidence_coverage_bps",
            "evidence_sha256",
            "exception_state",
            "finding_ref",
            "finding_sha256",
            "observed_at",
            "record_id",
            "record_sha256",
            "record_state",
            "remediation_state",
            "scope_sha256",
            "severity",
            "tenant_ref",
            "validation_state",
        }
        item = dict(_exact(raw, fields, "open finding record"))
        identity = item.pop("record_id")
        digest = item.pop("record_sha256")
        try:
            item["severity"] = Severity(item["severity"])
            item["validation_state"] = FindingValidationState(item["validation_state"])
            item["record_state"] = FindingRecordState(item["record_state"])
            item["remediation_state"] = RemediationState(item["remediation_state"])
            item["exception_state"] = ExceptionState(item["exception_state"])
        except ValueError as exc:
            raise AssetRiskScoringError("open finding record enum is invalid") from exc
        result = cls(**item)
        if result.record_id != identity or result.record_sha256 != digest:
            raise AssetRiskScoringError("open finding record content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class AttackPathEvidence:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    asset_ref: str
    asset_sha256: str
    reachability_state: ReachabilityState
    depth: int
    evidence_coverage_bps: int
    uncertainty_bps: int
    evidence_sha256: str
    observed_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.attack-path-evidence.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.asset_ref, "asset_ref", namespace="assetref")
        _sha256(self.asset_sha256, "asset_sha256")
        _bounded_int(self.depth, "depth", 0, 64)
        _bps(self.evidence_coverage_bps, "evidence_coverage_bps")
        _bps(self.uncertainty_bps, "uncertainty_bps")
        _sha256(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.observed_at, "observed_at")
        if self.reachability_state is ReachabilityState.CONFIRMED and self.depth == 0:
            raise AssetRiskScoringError("confirmed reachability requires a positive depth")
        if self.reachability_state is not ReachabilityState.CONFIRMED and self.depth != 0:
            raise AssetRiskScoringError("unconfirmed reachability cannot claim a path depth")
        identity, digest = _identity("APE", self.KIND, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_ref": self.asset_ref,
            "asset_sha256": self.asset_sha256,
            "context_ref": self.context_ref,
            "depth": self.depth,
            "evidence_coverage_bps": self.evidence_coverage_bps,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "reachability_state": self.reachability_state.value,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
            "uncertainty_bps": self.uncertainty_bps,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "binding_id": self.binding_id, "binding_sha256": self.binding_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> AttackPathEvidence:
        fields = {
            "asset_ref",
            "asset_sha256",
            "binding_id",
            "binding_sha256",
            "context_ref",
            "depth",
            "evidence_coverage_bps",
            "evidence_sha256",
            "observed_at",
            "reachability_state",
            "scope_sha256",
            "tenant_ref",
            "uncertainty_bps",
        }
        item = dict(_exact(raw, fields, "attack path evidence"))
        identity = item.pop("binding_id")
        digest = item.pop("binding_sha256")
        try:
            item["reachability_state"] = ReachabilityState(item["reachability_state"])
        except ValueError as exc:
            raise AssetRiskScoringError("reachability state is invalid") from exc
        result = cls(**item)
        if result.binding_id != identity or result.binding_sha256 != digest:
            raise AssetRiskScoringError("attack path content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class DefenderDetectionCoverage:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    asset_ref: str
    asset_sha256: str
    detection_coverage_bps: int
    evidence_coverage_bps: int
    uncertainty_bps: int
    evidence_sha256: str
    observed_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-detection-coverage.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.asset_ref, "asset_ref", namespace="assetref")
        _sha256(self.asset_sha256, "asset_sha256")
        _bps(self.detection_coverage_bps, "detection_coverage_bps")
        _bps(self.evidence_coverage_bps, "evidence_coverage_bps")
        _bps(self.uncertainty_bps, "uncertainty_bps")
        _sha256(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.observed_at, "observed_at")
        identity, digest = _identity("DDC", self.KIND, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_ref": self.asset_ref,
            "asset_sha256": self.asset_sha256,
            "context_ref": self.context_ref,
            "detection_coverage_bps": self.detection_coverage_bps,
            "evidence_coverage_bps": self.evidence_coverage_bps,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
            "uncertainty_bps": self.uncertainty_bps,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "binding_id": self.binding_id, "binding_sha256": self.binding_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> DefenderDetectionCoverage:
        fields = {
            "asset_ref",
            "asset_sha256",
            "binding_id",
            "binding_sha256",
            "context_ref",
            "detection_coverage_bps",
            "evidence_coverage_bps",
            "evidence_sha256",
            "observed_at",
            "scope_sha256",
            "tenant_ref",
            "uncertainty_bps",
        }
        item = dict(_exact(raw, fields, "defender detection coverage"))
        identity = item.pop("binding_id")
        digest = item.pop("binding_sha256")
        result = cls(**item)
        if result.binding_id != identity or result.binding_sha256 != digest:
            raise AssetRiskScoringError("defender coverage content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class FindingContribution:
    finding_ref: str
    finding_sha256: str
    severity: str
    validation_state: str
    remediation_state: str
    exception_state: str
    evidence_age_seconds: int
    baseline_contribution_bps: int
    severity_component_bps: int
    validation_bonus_bps: int
    confidence_uncertainty_bonus_bps: int
    remediation_bonus_bps: int
    exception_bonus_bps: int
    composite_contribution_bps: int

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class CompositeBreakdown:
    finding_aggregate_bps: int
    baseline_floor_bps: int
    asset_context_floor_bps: int
    inherent_floor_bps: int
    attack_path_bonus_bps: int
    attack_path_uncertainty_bonus_bps: int
    asset_uncertainty_bonus_bps: int
    defender_uncertainty_bonus_bps: int
    pre_control_score_bps: int
    defender_detection_reduction_bps: int
    calculated_score_bps: int

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class AssetRiskScorecard:
    rank: int
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    asset_ref: str
    asset_sha256: str
    asset_binding_id: str
    asset_binding_sha256: str
    attack_path_binding_id: str | None
    attack_path_binding_sha256: str | None
    defender_binding_id: str | None
    defender_binding_sha256: str | None
    evidence_state: EvidenceState
    disposition: str
    baseline_score_bps: int
    calculated_composite_score_bps: int
    composite_score_bps: int
    fail_closed_floor_applied: bool
    confidence_bps: int
    coverage_bps: int
    finding_count: int
    maximum_evidence_age_seconds: int
    reason_codes: tuple[str, ...]
    finding_contributions: tuple[FindingContribution, ...]
    composite_breakdown: CompositeBreakdown
    scorecard_id: str = field(init=False)
    scorecard_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.asset-risk-scorecard.v1"

    def __post_init__(self) -> None:
        _bounded_int(self.rank, "rank", 1, MAX_ASSETS)
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.asset_ref, "asset_ref", namespace="assetref")
        _sha256(self.asset_sha256, "asset_sha256")
        _content_id(self.asset_binding_id, "asset_binding_id", "ACB")
        _sha256(self.asset_binding_sha256, "asset_binding_sha256")
        for identity, digest, prefix, label in (
            (
                self.attack_path_binding_id,
                self.attack_path_binding_sha256,
                "APE",
                "attack path",
            ),
            (self.defender_binding_id, self.defender_binding_sha256, "DDC", "defender"),
        ):
            if (identity is None) != (digest is None):
                raise AssetRiskScoringError(f"{label} binding identity is incomplete")
            if identity is not None:
                _content_id(identity, f"{label}_binding_id", prefix)
                _sha256(digest, f"{label}_binding_sha256")
        for name in (
            "baseline_score_bps",
            "calculated_composite_score_bps",
            "composite_score_bps",
            "confidence_bps",
            "coverage_bps",
        ):
            _bps(getattr(self, name), name)
        _bounded_int(self.finding_count, "finding_count", 0, MAX_FINDINGS)
        _bounded_int(
            self.maximum_evidence_age_seconds,
            "maximum_evidence_age_seconds",
            0,
            MAX_AGE_SECONDS * 100,
        )
        if self.reason_codes != tuple(sorted(set(self.reason_codes))) or not self.reason_codes:
            raise AssetRiskScoringError("reason_codes must be non-empty, sorted, and unique")
        for reason in self.reason_codes:
            _identifier(reason, "reason_code")
        if len(self.finding_contributions) != self.finding_count:
            raise AssetRiskScoringError("finding contribution count does not match")
        identity, digest = _identity("ARS", self.KIND, self.body())
        object.__setattr__(self, "scorecard_id", identity)
        object.__setattr__(self, "scorecard_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_binding_id": self.asset_binding_id,
            "asset_binding_sha256": self.asset_binding_sha256,
            "asset_ref": self.asset_ref,
            "asset_sha256": self.asset_sha256,
            "attack_path_binding_id": self.attack_path_binding_id,
            "attack_path_binding_sha256": self.attack_path_binding_sha256,
            "baseline": {
                "formula_id": "open_finding_severity_weighted_v1",
                "score_bps": self.baseline_score_bps,
            },
            "composite": {
                "breakdown": self.composite_breakdown.to_dict(),
                "calculated_score_bps": self.calculated_composite_score_bps,
                "fail_closed_floor_applied": self.fail_closed_floor_applied,
                "formula_id": "evidence_aware_asset_risk_v1",
                "score_bps": self.composite_score_bps,
            },
            "confidence_bps": self.confidence_bps,
            "context_ref": self.context_ref,
            "coverage_bps": self.coverage_bps,
            "defender_binding_id": self.defender_binding_id,
            "defender_binding_sha256": self.defender_binding_sha256,
            "disposition": self.disposition,
            "evidence_state": self.evidence_state.value,
            "finding_contributions": [item.to_dict() for item in self.finding_contributions],
            "finding_count": self.finding_count,
            "maximum_evidence_age_seconds": self.maximum_evidence_age_seconds,
            "rank": self.rank,
            "reason_codes": list(self.reason_codes),
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "scorecard_id": self.scorecard_id,
            "scorecard_sha256": self.scorecard_sha256,
        }


@dataclass(frozen=True, slots=True)
class AssetRiskPortfolio:
    calculated_at: str
    policy: RiskScoringPolicy
    asset_bindings: tuple[AssetCriticalityExposureBinding, ...]
    finding_records: tuple[OpenFindingRecord, ...]
    attack_path_bindings: tuple[AttackPathEvidence, ...]
    defender_bindings: tuple[DefenderDetectionCoverage, ...]
    scorecards: tuple[AssetRiskScorecard, ...]
    portfolio_id: str = field(init=False)
    portfolio_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.asset-risk-portfolio.v1"

    def __post_init__(self) -> None:
        _timestamp(self.calculated_at, "calculated_at")
        if not self.asset_bindings or len(self.asset_bindings) > MAX_ASSETS:
            raise AssetRiskScoringError("asset binding count is outside the supported range")
        if len(self.finding_records) > MAX_FINDINGS:
            raise AssetRiskScoringError("finding record count is outside the supported range")
        if len(self.scorecards) != len(self.asset_bindings):
            raise AssetRiskScoringError("scorecard count does not match asset count")
        identity, digest = _identity("ARP", self.KIND, self.body())
        object.__setattr__(self, "portfolio_id", identity)
        object.__setattr__(self, "portfolio_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_bindings": [item.to_dict() for item in self.asset_bindings],
            "attack_path_bindings": [item.to_dict() for item in self.attack_path_bindings],
            "calculated_at": self.calculated_at,
            "contract_type": "asset_risk_portfolio",
            "defender_bindings": [item.to_dict() for item in self.defender_bindings],
            "effects": dict(NO_EFFECTS),
            "finding_records": [item.to_dict() for item in self.finding_records],
            "policy": self.policy.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "scorecards": [item.to_dict() for item in self.scorecards],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "portfolio_id": self.portfolio_id,
            "portfolio_sha256": self.portfolio_sha256,
        }

    @property
    def document_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> AssetRiskPortfolio:
        fields = {
            "asset_bindings",
            "attack_path_bindings",
            "calculated_at",
            "contract_type",
            "defender_bindings",
            "effects",
            "finding_records",
            "policy",
            "portfolio_id",
            "portfolio_sha256",
            "schema_version",
            "scorecards",
        }
        item = dict(_exact(raw, fields, "asset risk portfolio"))
        if item["schema_version"] != SCHEMA_VERSION:
            raise AssetRiskScoringError("schema_version is not supported")
        if item["contract_type"] != "asset_risk_portfolio":
            raise AssetRiskScoringError("contract_type is invalid")
        if item["effects"] != dict(NO_EFFECTS):
            raise AssetRiskScoringError("effects boundary is invalid")
        assets = tuple(
            AssetCriticalityExposureBinding.from_dict(value)
            for value in _sequence(item["asset_bindings"], "asset_bindings")
        )
        findings = tuple(
            OpenFindingRecord.from_dict(value)
            for value in _sequence(item["finding_records"], "finding_records")
        )
        paths = tuple(
            AttackPathEvidence.from_dict(value)
            for value in _sequence(item["attack_path_bindings"], "attack_path_bindings")
        )
        defenders = tuple(
            DefenderDetectionCoverage.from_dict(value)
            for value in _sequence(item["defender_bindings"], "defender_bindings")
        )
        rebuilt = build_asset_risk_portfolio(
            calculated_at=item["calculated_at"],
            policy=RiskScoringPolicy.from_dict(item["policy"]),
            asset_bindings=assets,
            finding_records=findings,
            attack_path_bindings=paths,
            defender_bindings=defenders,
        )
        if rebuilt.to_dict() != raw:
            raise AssetRiskScoringError("portfolio content address or derived score is invalid")
        return rebuilt

    @classmethod
    def from_json(cls, value: str) -> AssetRiskPortfolio:
        if not isinstance(value, str):
            raise AssetRiskScoringError("portfolio JSON must be text")
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AssetRiskScoringError("portfolio JSON is invalid") from exc
        return cls.from_dict(raw)


def _age_seconds(observed_at: str, calculated_at: str) -> int:
    age = int((_instant(calculated_at) - _instant(observed_at)).total_seconds())
    if age < 0:
        raise AssetRiskScoringError("evidence timestamp is in the future")
    return age


def _same_binding(
    asset: AssetCriticalityExposureBinding,
    candidate: OpenFindingRecord | AttackPathEvidence | DefenderDetectionCoverage,
) -> bool:
    return (
        asset.tenant_ref == candidate.tenant_ref
        and asset.context_ref == candidate.context_ref
        and asset.scope_sha256 == candidate.scope_sha256
        and asset.asset_ref == candidate.asset_ref
        and asset.asset_sha256 == candidate.asset_sha256
    )


def _finding_contribution(
    finding: OpenFindingRecord,
    *,
    calculated_at: str,
) -> FindingContribution:
    baseline = BASELINE_SEVERITY_BPS[finding.severity.value]
    severity = COMPOSITE_SEVERITY_BPS[finding.severity.value]
    validation = VALIDATION_BONUS_BPS[finding.validation_state.value]
    uncertainty = _ceil_ratio((MAX_BPS - finding.confidence_bps) * 2_000, MAX_BPS)
    remediation = REMEDIATION_BONUS_BPS[finding.remediation_state.value]
    exception = EXCEPTION_BONUS_BPS[finding.exception_state.value]
    composite = min(MAX_BPS, severity + validation + uncertainty + remediation + exception)
    return FindingContribution(
        finding_ref=finding.finding_ref,
        finding_sha256=finding.finding_sha256,
        severity=finding.severity.value,
        validation_state=finding.validation_state.value,
        remediation_state=finding.remediation_state.value,
        exception_state=finding.exception_state.value,
        evidence_age_seconds=_age_seconds(finding.observed_at, calculated_at),
        baseline_contribution_bps=baseline,
        severity_component_bps=severity,
        validation_bonus_bps=validation,
        confidence_uncertainty_bonus_bps=uncertainty,
        remediation_bonus_bps=remediation,
        exception_bonus_bps=exception,
        composite_contribution_bps=composite,
    )


def _score_asset(
    *,
    rank: int,
    calculated_at: str,
    policy: RiskScoringPolicy,
    asset: AssetCriticalityExposureBinding,
    findings: tuple[OpenFindingRecord, ...],
    attack_path: AttackPathEvidence | None,
    defender: DefenderDetectionCoverage | None,
) -> AssetRiskScorecard:
    contributions = tuple(
        _finding_contribution(item, calculated_at=calculated_at) for item in findings
    )
    baseline_score = min(
        MAX_BPS,
        sum(item.baseline_contribution_bps for item in contributions),
    )
    finding_aggregate = 0
    if contributions:
        finding_aggregate = min(
            MAX_BPS,
            max(item.composite_contribution_bps for item in contributions)
            + min(2_500, (len(contributions) - 1) * 250),
        )
    asset_context_floor = (asset.criticality_bps * 3 + asset.exposure_bps * 2) // 5
    inherent_floor = max(baseline_score, finding_aggregate, asset_context_floor)

    if attack_path is None:
        attack_bonus = 1_500
        attack_uncertainty = 2_000
    else:
        if attack_path.reachability_state is ReachabilityState.CONFIRMED:
            attack_bonus = max(500, 2_500 - min(attack_path.depth, 20) * 100)
        elif attack_path.reachability_state is ReachabilityState.UNKNOWN:
            attack_bonus = 1_500
        else:
            attack_bonus = 0
        attack_uncertainty = _ceil_ratio(
            (MAX_BPS - attack_path.evidence_coverage_bps) * 1_000,
            MAX_BPS,
        ) + _ceil_ratio(attack_path.uncertainty_bps * 1_000, MAX_BPS)

    asset_uncertainty = _ceil_ratio(asset.uncertainty_bps * 1_000, MAX_BPS)
    if defender is None:
        defender_uncertainty = 2_000
        defender_reduction = 0
    else:
        defender_uncertainty = _ceil_ratio(
            (MAX_BPS - defender.evidence_coverage_bps) * 1_000,
            MAX_BPS,
        ) + _ceil_ratio(defender.uncertainty_bps * 1_000, MAX_BPS)
        defender_reduction = defender.detection_coverage_bps * 2_000 // MAX_BPS

    pre_control = min(
        MAX_BPS,
        inherent_floor
        + attack_bonus
        + attack_uncertainty
        + asset_uncertainty
        + defender_uncertainty,
    )
    calculated_score = max(inherent_floor, pre_control - defender_reduction)

    ages = [_age_seconds(asset.observed_at, calculated_at)]
    ages.extend(item.evidence_age_seconds for item in contributions)
    if attack_path is not None:
        ages.append(_age_seconds(attack_path.observed_at, calculated_at))
    if defender is not None:
        ages.append(_age_seconds(defender.observed_at, calculated_at))
    maximum_age = max(ages)

    coverages = [asset.evidence_coverage_bps]
    coverages.extend(item.evidence_coverage_bps for item in findings)
    coverages.append(attack_path.evidence_coverage_bps if attack_path is not None else 0)
    coverages.append(defender.evidence_coverage_bps if defender is not None else 0)
    coverage = min(coverages)
    confidence = min((item.confidence_bps for item in findings), default=0)

    reasons: set[str] = set()
    if not findings:
        reasons.add("evidence.missing_open_findings")
    if attack_path is None:
        reasons.add("evidence.missing_attack_path")
    elif attack_path.reachability_state is ReachabilityState.UNKNOWN:
        reasons.add("risk.attack_reachability_unknown")
    if defender is None:
        reasons.add("evidence.missing_defender_coverage")
    if coverage < policy.minimum_evidence_coverage_bps:
        reasons.add("evidence.coverage_below_minimum")
    if maximum_age > policy.maximum_evidence_age_seconds:
        reasons.add("evidence.stale")
    if any(item.validation_state is FindingValidationState.INVALID for item in findings):
        reasons.add("evidence.invalid_finding")
    if any(item.exception_state is not ExceptionState.NONE for item in findings):
        reasons.add("risk.exception_retained")
    if any(item.remediation_state is RemediationState.REPORTED_REMEDIATED for item in findings):
        reasons.add("risk.reported_remediation_unverified")

    if "evidence.invalid_finding" in reasons:
        evidence_state = EvidenceState.INVALID
        disposition = "blocked_invalid"
    elif "evidence.stale" in reasons:
        evidence_state = EvidenceState.STALE
        disposition = "blocked_stale"
    elif any(item.startswith("evidence.missing_") for item in reasons) or (
        "evidence.coverage_below_minimum" in reasons
    ):
        evidence_state = EvidenceState.INSUFFICIENT
        disposition = "blocked_insufficient"
    else:
        evidence_state = EvidenceState.COMPLETE
        disposition = "manual_review_required"
        reasons.add("risk.score_calculated")

    fail_closed = evidence_state is not EvidenceState.COMPLETE
    score = MAX_BPS if fail_closed else calculated_score
    breakdown = CompositeBreakdown(
        finding_aggregate_bps=finding_aggregate,
        baseline_floor_bps=baseline_score,
        asset_context_floor_bps=asset_context_floor,
        inherent_floor_bps=inherent_floor,
        attack_path_bonus_bps=attack_bonus,
        attack_path_uncertainty_bonus_bps=attack_uncertainty,
        asset_uncertainty_bonus_bps=asset_uncertainty,
        defender_uncertainty_bonus_bps=defender_uncertainty,
        pre_control_score_bps=pre_control,
        defender_detection_reduction_bps=defender_reduction,
        calculated_score_bps=calculated_score,
    )
    return AssetRiskScorecard(
        rank=rank,
        tenant_ref=asset.tenant_ref,
        context_ref=asset.context_ref,
        scope_sha256=asset.scope_sha256,
        asset_ref=asset.asset_ref,
        asset_sha256=asset.asset_sha256,
        asset_binding_id=asset.binding_id,
        asset_binding_sha256=asset.binding_sha256,
        attack_path_binding_id=None if attack_path is None else attack_path.binding_id,
        attack_path_binding_sha256=None if attack_path is None else attack_path.binding_sha256,
        defender_binding_id=None if defender is None else defender.binding_id,
        defender_binding_sha256=None if defender is None else defender.binding_sha256,
        evidence_state=evidence_state,
        disposition=disposition,
        baseline_score_bps=baseline_score,
        calculated_composite_score_bps=calculated_score,
        composite_score_bps=score,
        fail_closed_floor_applied=fail_closed,
        confidence_bps=confidence,
        coverage_bps=coverage,
        finding_count=len(findings),
        maximum_evidence_age_seconds=maximum_age,
        reason_codes=tuple(sorted(reasons)),
        finding_contributions=contributions,
        composite_breakdown=breakdown,
    )


def _unique(values: Sequence[Any], field_name: str, label: str) -> None:
    seen: set[str] = set()
    for value in values:
        member = getattr(value, field_name)
        if member in seen:
            raise AssetRiskScoringError(f"duplicate {label} is forbidden")
        seen.add(member)


def build_asset_risk_portfolio(
    *,
    calculated_at: str,
    policy: RiskScoringPolicy,
    asset_bindings: Sequence[AssetCriticalityExposureBinding],
    finding_records: Sequence[OpenFindingRecord],
    attack_path_bindings: Sequence[AttackPathEvidence],
    defender_bindings: Sequence[DefenderDetectionCoverage],
) -> AssetRiskPortfolio:
    """Build a deterministic, content-addressed asset risk portfolio."""

    _timestamp(calculated_at, "calculated_at")
    assets = tuple(asset_bindings)
    findings = tuple(finding_records)
    paths = tuple(attack_path_bindings)
    defenders = tuple(defender_bindings)
    if not assets or len(assets) > MAX_ASSETS:
        raise AssetRiskScoringError("asset binding count is outside the supported range")
    if len(findings) > MAX_FINDINGS:
        raise AssetRiskScoringError("finding record count is outside the supported range")
    if len(paths) > len(assets) or len(defenders) > len(assets):
        raise AssetRiskScoringError("per-asset evidence count exceeds asset count")
    if any(not isinstance(item, AssetCriticalityExposureBinding) for item in assets):
        raise AssetRiskScoringError("asset_bindings contain an invalid item")
    if any(not isinstance(item, OpenFindingRecord) for item in findings):
        raise AssetRiskScoringError("finding_records contain an invalid item")
    if any(not isinstance(item, AttackPathEvidence) for item in paths):
        raise AssetRiskScoringError("attack_path_bindings contain an invalid item")
    if any(not isinstance(item, DefenderDetectionCoverage) for item in defenders):
        raise AssetRiskScoringError("defender_bindings contain an invalid item")

    for field_name, label in (
        ("asset_ref", "asset reference"),
        ("asset_sha256", "asset digest"),
        ("binding_id", "asset binding identity"),
        ("binding_sha256", "asset binding digest"),
    ):
        _unique(assets, field_name, label)
    for field_name, label in (
        ("finding_ref", "finding reference"),
        ("finding_sha256", "finding digest"),
        ("record_id", "finding record identity"),
        ("record_sha256", "finding record digest"),
    ):
        _unique(findings, field_name, label)
    _unique(paths, "asset_ref", "attack path asset reference")
    _unique(paths, "binding_sha256", "attack path digest")
    _unique(defenders, "asset_ref", "defender asset reference")
    _unique(defenders, "binding_sha256", "defender binding digest")

    asset_by_ref = {item.asset_ref: item for item in assets}
    findings_by_asset: dict[str, list[OpenFindingRecord]] = {item.asset_ref: [] for item in assets}
    for finding in findings:
        asset = asset_by_ref.get(finding.asset_ref)
        if asset is None:
            raise AssetRiskScoringError("finding references an unknown asset")
        if finding.record_state is FindingRecordState.MERGED_AWAY:
            raise AssetRiskScoringError("merged-away finding cannot be scored")
        if not _same_binding(asset, finding):
            raise AssetRiskScoringError(
                "finding crosses its tenant, context, scope, or asset binding"
            )
        findings_by_asset[asset.asset_ref].append(finding)

    path_by_asset: dict[str, AttackPathEvidence] = {}
    for path in paths:
        asset = asset_by_ref.get(path.asset_ref)
        if asset is None:
            raise AssetRiskScoringError("attack path references an unknown asset")
        if not _same_binding(asset, path):
            raise AssetRiskScoringError(
                "attack path crosses its tenant, context, scope, or asset binding"
            )
        path_by_asset[path.asset_ref] = path

    defender_by_asset: dict[str, DefenderDetectionCoverage] = {}
    for defender in defenders:
        asset = asset_by_ref.get(defender.asset_ref)
        if asset is None:
            raise AssetRiskScoringError("defender coverage references an unknown asset")
        if not _same_binding(asset, defender):
            raise AssetRiskScoringError(
                "defender coverage crosses its tenant, context, scope, or asset binding"
            )
        defender_by_asset[defender.asset_ref] = defender

    provisional: list[AssetRiskScorecard] = []
    for asset in sorted(assets, key=lambda item: item.asset_ref):
        asset_findings = tuple(
            sorted(findings_by_asset[asset.asset_ref], key=lambda item: item.finding_ref)
        )
        provisional.append(
            _score_asset(
                rank=1,
                calculated_at=calculated_at,
                policy=policy,
                asset=asset,
                findings=asset_findings,
                attack_path=path_by_asset.get(asset.asset_ref),
                defender=defender_by_asset.get(asset.asset_ref),
            )
        )

    state_priority = {
        EvidenceState.COMPLETE: 0,
        EvidenceState.INSUFFICIENT: 1,
        EvidenceState.STALE: 2,
        EvidenceState.INVALID: 3,
    }
    provisional.sort(
        key=lambda item: (
            -item.composite_score_bps,
            -state_priority[item.evidence_state],
            -item.baseline_score_bps,
            item.asset_ref,
        )
    )
    ranked: list[AssetRiskScorecard] = []
    for rank, item in enumerate(provisional, start=1):
        asset = asset_by_ref[item.asset_ref]
        ranked.append(
            _score_asset(
                rank=rank,
                calculated_at=calculated_at,
                policy=policy,
                asset=asset,
                findings=tuple(
                    sorted(findings_by_asset[asset.asset_ref], key=lambda value: value.finding_ref)
                ),
                attack_path=path_by_asset.get(asset.asset_ref),
                defender=defender_by_asset.get(asset.asset_ref),
            )
        )

    return AssetRiskPortfolio(
        calculated_at=calculated_at,
        policy=policy,
        asset_bindings=tuple(sorted(assets, key=lambda item: item.asset_ref)),
        finding_records=tuple(sorted(findings, key=lambda item: item.finding_ref)),
        attack_path_bindings=tuple(sorted(paths, key=lambda item: item.asset_ref)),
        defender_bindings=tuple(sorted(defenders, key=lambda item: item.asset_ref)),
        scorecards=tuple(ranked),
    )


def verify_asset_risk_portfolio(value: AssetRiskPortfolio | Mapping[str, Any] | str) -> None:
    """Rebuild a portfolio and reject any changed input, score, rank, or identity."""

    if isinstance(value, AssetRiskPortfolio):
        AssetRiskPortfolio.from_dict(value.to_dict())
    elif isinstance(value, str):
        AssetRiskPortfolio.from_json(value)
    else:
        AssetRiskPortfolio.from_dict(value)


__all__ = [
    "NO_EFFECTS",
    "AssetCriticalityExposureBinding",
    "AssetRiskPortfolio",
    "AssetRiskScorecard",
    "AssetRiskScoringError",
    "AttackPathEvidence",
    "CompositeBreakdown",
    "DefenderDetectionCoverage",
    "EvidenceState",
    "ExceptionState",
    "FindingContribution",
    "FindingRecordState",
    "FindingValidationState",
    "OpenFindingRecord",
    "ReachabilityState",
    "RemediationState",
    "RiskScoringPolicy",
    "Severity",
    "build_asset_risk_portfolio",
    "canonical_json",
    "canonical_sha256",
    "verify_asset_risk_portfolio",
]
