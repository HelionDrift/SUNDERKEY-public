"""Deterministic drift, shadow, canary, and regression evaluation contracts.

The contracts in this module are immutable and content addressed. They compare
already collected measurements. They do not call models, duplicate traffic,
route requests, authorize actions, or change deployments.
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
from typing import Any

SCHEMA_VERSION = 1
MILLION = 1_000_000
MAX_STRATA = 128
MAX_OBSERVATIONS = 64

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "deployment": "none",
        "model_calls": "none",
        "network": "none",
        "operational_decisions": "none",
        "provider_clients": "none",
        "routing": "none",
        "traffic_duplication": "none",
    }
)


class EvaluationDriftError(ValueError):
    """Raised when an evaluation contract fails closed."""


class EvaluationMode(StrEnum):
    OFFLINE = "offline"
    SHADOW = "shadow"
    CANARY_PLAN = "canary_plan"


class SubjectRole(StrEnum):
    CONTROL = "control"
    CANDIDATE = "candidate"


class MetricName(StrEnum):
    SAFETY = "safety"
    CORRECTNESS = "correctness"
    ABSTENTION = "abstention"
    FINDING_QUALITY = "finding_quality"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    LATENCY = "latency"
    COST = "cost"


class Direction(StrEnum):
    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


class MetricDisposition(StrEnum):
    PASS = "pass"
    REGRESSION = "regression"
    CRITICAL_REGRESSION = "critical_regression"


class AssessmentOutcome(StrEnum):
    PASS = "pass"
    REGRESSION = "regression"
    STOPPED = "stopped"


class ConfidenceBand(StrEnum):
    MINIMUM = "minimum"
    MODERATE = "moderate"
    STRONG = "strong"


class GateRole(StrEnum):
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


class CanaryPlanStatus(StrEnum):
    BLOCKED = "blocked"
    READY_FOR_SEPARATE_AUTHORIZATION = "ready_for_separate_authorization"


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
        raise EvaluationDriftError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise EvaluationDriftError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvaluationDriftError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise EvaluationDriftError(f"{label} contains an unsupported value")


def _safe_text(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvaluationDriftError(f"{label} must be non-empty text within {maximum} characters")
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise EvaluationDriftError(f"{label} must contain printable ASCII only")
    if SECRET_RE.search(value):
        raise EvaluationDriftError(f"{label} appears to contain secret material")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise EvaluationDriftError(f"{label} must be a safe identifier")
    _safe_text(value, label, 256)
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise EvaluationDriftError(f"{label} must be a safe version")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvaluationDriftError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EvaluationDriftError(f"{label} must be a UTC timestamp")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return parsed


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvaluationDriftError(f"{label} must be between {minimum} and {maximum}")
    return value


def _exact_fields(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise EvaluationDriftError(f"{label} fields do not match the contract")
    return raw


def _sorted_unique(values: Sequence[str], label: str, maximum: int = MAX_STRATA) -> tuple[str, ...]:
    result = tuple(values)
    if not result or len(result) > maximum or len(set(result)) != len(result):
        raise EvaluationDriftError(f"{label} must be a non-empty unique bounded sequence")
    for value in result:
        _identifier(value, label)
    if result != tuple(sorted(result)):
        raise EvaluationDriftError(f"{label} must be sorted")
    return result


@dataclass(frozen=True)
class DistributionBinding:
    distribution_id: str
    distribution_version: str
    artifact_sha256: str
    strata: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.distribution_id, "distribution_id")
        _version(self.distribution_version, "distribution_version")
        _sha256(self.artifact_sha256, "artifact_sha256")
        object.__setattr__(self, "strata", _sorted_unique(self.strata, "distribution strata"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "distribution_id": self.distribution_id,
            "distribution_version": self.distribution_version,
            "strata": list(self.strata),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DistributionBinding:
        raw = _exact_fields(
            raw,
            {"artifact_sha256", "distribution_id", "distribution_version", "strata"},
            "distribution binding",
        )
        return cls(
            distribution_id=raw["distribution_id"],
            distribution_version=raw["distribution_version"],
            artifact_sha256=raw["artifact_sha256"],
            strata=tuple(raw["strata"]),
        )


@dataclass(frozen=True)
class StratumSample:
    stratum: str
    sample_count: int

    def __post_init__(self) -> None:
        _identifier(self.stratum, "stratum")
        _bounded_int(self.sample_count, "sample_count", 1, 10_000_000)

    def to_dict(self) -> dict[str, Any]:
        return {"sample_count": self.sample_count, "stratum": self.stratum}

    @classmethod
    def from_dict(cls, raw: Any) -> StratumSample:
        raw = _exact_fields(raw, {"sample_count", "stratum"}, "stratum sample")
        return cls(**raw)


@dataclass(frozen=True)
class EvaluationCohort:
    cohort_id: str
    cohort_sha256: str
    distribution: DistributionBinding
    samples: tuple[StratumSample, ...]
    collected_at: str
    expires_at: str

    def __post_init__(self) -> None:
        collected = _timestamp(self.collected_at, "collected_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= collected:
            raise EvaluationDriftError("cohort expires_at must be after collected_at")
        if not self.samples or len(self.samples) > MAX_STRATA:
            raise EvaluationDriftError("cohort samples are empty or exceed the limit")
        names = tuple(sample.stratum for sample in self.samples)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise EvaluationDriftError("cohort samples must be unique and sorted")
        if not set(names).issubset(self.distribution.strata):
            raise EvaluationDriftError("cohort samples include an unbound stratum")
        expected_id, expected_sha = _identity("ECO", "sunderkey.evaluation-cohort.v1", self.body())
        if self.cohort_id != expected_id or self.cohort_sha256 != expected_sha:
            raise EvaluationDriftError("cohort identity does not match its content")

    @property
    def total_samples(self) -> int:
        return sum(sample.sample_count for sample in self.samples)

    def body(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at,
            "distribution": self.distribution.to_dict(),
            "expires_at": self.expires_at,
            "samples": [sample.to_dict() for sample in self.samples],
        }

    def to_dict(self) -> dict[str, Any]:
        return {"cohort_id": self.cohort_id, "cohort_sha256": self.cohort_sha256, **self.body()}

    @classmethod
    def create(
        cls,
        *,
        distribution: DistributionBinding,
        samples: Sequence[StratumSample],
        collected_at: str,
        expires_at: str,
    ) -> EvaluationCohort:
        body = {
            "collected_at": collected_at,
            "distribution": distribution.to_dict(),
            "expires_at": expires_at,
            "samples": [sample.to_dict() for sample in samples],
        }
        cohort_id, cohort_sha256 = _identity("ECO", "sunderkey.evaluation-cohort.v1", body)
        return cls(cohort_id, cohort_sha256, distribution, tuple(samples), collected_at, expires_at)

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationCohort:
        raw = _exact_fields(
            raw,
            {"cohort_id", "cohort_sha256", "collected_at", "distribution", "expires_at", "samples"},
            "cohort",
        )
        return cls(
            raw["cohort_id"],
            raw["cohort_sha256"],
            DistributionBinding.from_dict(raw["distribution"]),
            tuple(StratumSample.from_dict(item) for item in raw["samples"]),
            raw["collected_at"],
            raw["expires_at"],
        )


@dataclass(frozen=True)
class MetricObservation:
    observation_id: str
    observation_sha256: str
    cohort_sha256: str
    role: SubjectRole | str
    subject_id: str
    subject_version: str
    metric: MetricName | str
    value_microunits: int
    sample_count: int
    strata: tuple[str, ...]
    observed_at: str
    source_sha256: str

    def __post_init__(self) -> None:
        _sha256(self.cohort_sha256, "cohort_sha256")
        try:
            object.__setattr__(self, "role", SubjectRole(self.role))
            object.__setattr__(self, "metric", MetricName(self.metric))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("observation role or metric is invalid") from exc
        _identifier(self.subject_id, "subject_id")
        _version(self.subject_version, "subject_version")
        _bounded_int(self.value_microunits, "value_microunits", 0, 10**15)
        _bounded_int(self.sample_count, "sample_count", 1, 10_000_000)
        object.__setattr__(self, "strata", _sorted_unique(self.strata, "observation strata"))
        _timestamp(self.observed_at, "observed_at")
        _sha256(self.source_sha256, "source_sha256")
        expected_id, expected_sha = _identity("EOB", "sunderkey.metric-observation.v1", self.body())
        if self.observation_id != expected_id or self.observation_sha256 != expected_sha:
            raise EvaluationDriftError("observation identity does not match its content")

    def body(self) -> dict[str, Any]:
        return {
            "cohort_sha256": self.cohort_sha256,
            "metric": self.metric.value,
            "observed_at": self.observed_at,
            "role": self.role.value,
            "sample_count": self.sample_count,
            "source_sha256": self.source_sha256,
            "strata": list(self.strata),
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "value_microunits": self.value_microunits,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            **self.body(),
        }

    @classmethod
    def create(cls, **values: Any) -> MetricObservation:
        body = dict(values)
        body["role"] = SubjectRole(body["role"]).value
        body["metric"] = MetricName(body["metric"]).value
        body["strata"] = list(body["strata"])
        observation_id, observation_sha256 = _identity(
            "EOB", "sunderkey.metric-observation.v1", body
        )
        return cls(observation_id, observation_sha256, **values)

    @classmethod
    def from_dict(cls, raw: Any) -> MetricObservation:
        fields = {
            "cohort_sha256",
            "metric",
            "observation_id",
            "observation_sha256",
            "observed_at",
            "role",
            "sample_count",
            "source_sha256",
            "strata",
            "subject_id",
            "subject_version",
            "value_microunits",
        }
        raw = _exact_fields(raw, fields, "observation")
        return cls(
            observation_id=raw["observation_id"],
            observation_sha256=raw["observation_sha256"],
            cohort_sha256=raw["cohort_sha256"],
            role=raw["role"],
            subject_id=raw["subject_id"],
            subject_version=raw["subject_version"],
            metric=raw["metric"],
            value_microunits=raw["value_microunits"],
            sample_count=raw["sample_count"],
            strata=tuple(raw["strata"]),
            observed_at=raw["observed_at"],
            source_sha256=raw["source_sha256"],
        )


@dataclass(frozen=True)
class EvaluationBaseline:
    baseline_id: str
    baseline_sha256: str
    cohort_sha256: str
    control_id: str
    control_version: str
    distribution_artifact_sha256: str
    observations: tuple[MetricObservation, ...]
    pinned_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _sha256(self.cohort_sha256, "cohort_sha256")
        _identifier(self.control_id, "control_id")
        _version(self.control_version, "control_version")
        _sha256(self.distribution_artifact_sha256, "distribution_artifact_sha256")
        pinned = _timestamp(self.pinned_at, "pinned_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= pinned:
            raise EvaluationDriftError("baseline expires_at must be after pinned_at")
        _validate_observation_set(
            self.observations,
            role=SubjectRole.CONTROL,
            subject_id=self.control_id,
            subject_version=self.control_version,
            cohort_sha256=self.cohort_sha256,
        )
        expected_id, expected_sha = _identity(
            "EBL", "sunderkey.evaluation-baseline.v1", self.body()
        )
        if self.baseline_id != expected_id or self.baseline_sha256 != expected_sha:
            raise EvaluationDriftError("baseline identity does not match its content")

    def body(self) -> dict[str, Any]:
        return {
            "cohort_sha256": self.cohort_sha256,
            "control_id": self.control_id,
            "control_version": self.control_version,
            "distribution_artifact_sha256": self.distribution_artifact_sha256,
            "expires_at": self.expires_at,
            "observations": [item.to_dict() for item in self.observations],
            "pinned_at": self.pinned_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "baseline_sha256": self.baseline_sha256,
            **self.body(),
        }

    @classmethod
    def create(cls, **values: Any) -> EvaluationBaseline:
        body = {
            **values,
            "observations": [item.to_dict() for item in values["observations"]],
        }
        baseline_id, baseline_sha256 = _identity("EBL", "sunderkey.evaluation-baseline.v1", body)
        return cls(baseline_id, baseline_sha256, **values)

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationBaseline:
        fields = {
            "baseline_id",
            "baseline_sha256",
            "cohort_sha256",
            "control_id",
            "control_version",
            "distribution_artifact_sha256",
            "expires_at",
            "observations",
            "pinned_at",
        }
        raw = _exact_fields(raw, fields, "baseline")
        return cls(
            baseline_id=raw["baseline_id"],
            baseline_sha256=raw["baseline_sha256"],
            cohort_sha256=raw["cohort_sha256"],
            control_id=raw["control_id"],
            control_version=raw["control_version"],
            distribution_artifact_sha256=raw["distribution_artifact_sha256"],
            observations=tuple(MetricObservation.from_dict(item) for item in raw["observations"]),
            pinned_at=raw["pinned_at"],
            expires_at=raw["expires_at"],
        )


def _validate_observation_set(
    observations: Sequence[MetricObservation],
    *,
    role: SubjectRole,
    subject_id: str,
    subject_version: str,
    cohort_sha256: str,
) -> None:
    if not observations or len(observations) > MAX_OBSERVATIONS:
        raise EvaluationDriftError("observation set is empty or exceeds the limit")
    metrics = tuple(item.metric.value for item in observations)
    if metrics != tuple(sorted(metrics)) or len(metrics) != len(set(metrics)):
        raise EvaluationDriftError("observations must have unique sorted metrics")
    for item in observations:
        if (
            item.role is not role
            or item.subject_id != subject_id
            or item.subject_version != subject_version
            or item.cohort_sha256 != cohort_sha256
        ):
            raise EvaluationDriftError("observation binding does not match its container")


@dataclass(frozen=True)
class MetricThreshold:
    metric: MetricName | str
    direction: Direction | str
    max_regression_microunits: int
    minimum_samples: int
    hard_candidate_limit_microunits: int | None
    critical: bool

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "metric", MetricName(self.metric))
            object.__setattr__(self, "direction", Direction(self.direction))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("threshold metric or direction is invalid") from exc
        _bounded_int(self.max_regression_microunits, "max_regression_microunits", 0, 10**15)
        _bounded_int(self.minimum_samples, "minimum_samples", 1, 10_000_000)
        if self.hard_candidate_limit_microunits is not None:
            _bounded_int(
                self.hard_candidate_limit_microunits,
                "hard_candidate_limit_microunits",
                0,
                10**15,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "critical": self.critical,
            "direction": self.direction.value,
            "hard_candidate_limit_microunits": self.hard_candidate_limit_microunits,
            "max_regression_microunits": self.max_regression_microunits,
            "metric": self.metric.value,
            "minimum_samples": self.minimum_samples,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> MetricThreshold:
        raw = _exact_fields(
            raw,
            {
                "critical",
                "direction",
                "hard_candidate_limit_microunits",
                "max_regression_microunits",
                "metric",
                "minimum_samples",
            },
            "metric threshold",
        )
        return cls(**raw)


@dataclass(frozen=True)
class EvaluationPolicy:
    policy_id: str
    policy_version: str
    thresholds: tuple[MetricThreshold, ...]
    required_strata: tuple[str, ...]
    max_evidence_age_seconds: int
    min_total_samples: int
    max_total_samples: int

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "policy_id")
        _version(self.policy_version, "policy_version")
        metrics = tuple(item.metric.value for item in self.thresholds)
        if metrics != tuple(sorted(metrics)) or set(metrics) != {item.value for item in MetricName}:
            raise EvaluationDriftError("policy must contain one sorted threshold for every metric")
        object.__setattr__(
            self, "required_strata", _sorted_unique(self.required_strata, "required strata")
        )
        _bounded_int(self.max_evidence_age_seconds, "max_evidence_age_seconds", 1, 31_536_000)
        _bounded_int(self.min_total_samples, "min_total_samples", 1, 10_000_000)
        _bounded_int(self.max_total_samples, "max_total_samples", 1, 10_000_000)
        if self.max_total_samples < self.min_total_samples:
            raise EvaluationDriftError("max_total_samples must not be below min_total_samples")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_evidence_age_seconds": self.max_evidence_age_seconds,
            "max_total_samples": self.max_total_samples,
            "min_total_samples": self.min_total_samples,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "required_strata": list(self.required_strata),
            "thresholds": [item.to_dict() for item in self.thresholds],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationPolicy:
        raw = _exact_fields(
            raw,
            {
                "max_evidence_age_seconds",
                "max_total_samples",
                "min_total_samples",
                "policy_id",
                "policy_version",
                "required_strata",
                "thresholds",
            },
            "evaluation policy",
        )
        return cls(
            policy_id=raw["policy_id"],
            policy_version=raw["policy_version"],
            thresholds=tuple(MetricThreshold.from_dict(item) for item in raw["thresholds"]),
            required_strata=tuple(raw["required_strata"]),
            max_evidence_age_seconds=raw["max_evidence_age_seconds"],
            min_total_samples=raw["min_total_samples"],
            max_total_samples=raw["max_total_samples"],
        )


@dataclass(frozen=True)
class MetricResult:
    metric: MetricName | str
    control_value_microunits: int
    candidate_value_microunits: int
    regression_microunits: int
    allowed_regression_microunits: int
    confidence: ConfidenceBand | str
    disposition: MetricDisposition | str
    reason: str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "metric", MetricName(self.metric))
            object.__setattr__(self, "confidence", ConfidenceBand(self.confidence))
            object.__setattr__(self, "disposition", MetricDisposition(self.disposition))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("metric result enum value is invalid") from exc
        for name in (
            "control_value_microunits",
            "candidate_value_microunits",
            "allowed_regression_microunits",
        ):
            _bounded_int(getattr(self, name), name, 0, 10**15)
        _bounded_int(self.regression_microunits, "regression_microunits", -(10**15), 10**15)
        _safe_text(self.reason, "metric result reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_regression_microunits": self.allowed_regression_microunits,
            "candidate_value_microunits": self.candidate_value_microunits,
            "confidence": self.confidence.value,
            "control_value_microunits": self.control_value_microunits,
            "disposition": self.disposition.value,
            "metric": self.metric.value,
            "reason": self.reason,
            "regression_microunits": self.regression_microunits,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> MetricResult:
        raw = _exact_fields(
            raw,
            {
                "allowed_regression_microunits",
                "candidate_value_microunits",
                "confidence",
                "control_value_microunits",
                "disposition",
                "metric",
                "reason",
                "regression_microunits",
            },
            "metric result",
        )
        return cls(**raw)


@dataclass(frozen=True)
class DriftAssessment:
    assessment_id: str
    assessment_sha256: str
    baseline_sha256: str
    cohort_sha256: str
    candidate_id: str
    candidate_version: str
    distribution_artifact_sha256: str
    mode: EvaluationMode | str
    policy_id: str
    policy_version: str
    assessed_at: str
    candidate_observations: tuple[MetricObservation, ...]
    metric_results: tuple[MetricResult, ...]
    stop_reasons: tuple[str, ...]
    outcome: AssessmentOutcome | str
    effects: Mapping[str, str]

    def __post_init__(self) -> None:
        _sha256(self.baseline_sha256, "baseline_sha256")
        _sha256(self.cohort_sha256, "cohort_sha256")
        _identifier(self.candidate_id, "candidate_id")
        _version(self.candidate_version, "candidate_version")
        _sha256(self.distribution_artifact_sha256, "distribution_artifact_sha256")
        try:
            object.__setattr__(self, "mode", EvaluationMode(self.mode))
            object.__setattr__(self, "outcome", AssessmentOutcome(self.outcome))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("assessment mode or outcome is invalid") from exc
        _identifier(self.policy_id, "policy_id")
        _version(self.policy_version, "policy_version")
        _timestamp(self.assessed_at, "assessed_at")
        _validate_observation_set(
            self.candidate_observations,
            role=SubjectRole.CANDIDATE,
            subject_id=self.candidate_id,
            subject_version=self.candidate_version,
            cohort_sha256=self.cohort_sha256,
        )
        metrics = tuple(item.metric.value for item in self.metric_results)
        if metrics != tuple(sorted(metrics)) or len(metrics) != len(set(metrics)):
            raise EvaluationDriftError("metric results must be unique and sorted")
        if tuple(self.stop_reasons) != tuple(sorted(set(self.stop_reasons))):
            raise EvaluationDriftError("stop reasons must be unique and sorted")
        for reason in self.stop_reasons:
            _identifier(reason, "stop reason")
        if dict(self.effects) != NO_EFFECTS:
            raise EvaluationDriftError("assessment effects must remain empty")
        object.__setattr__(self, "effects", MappingProxyType(dict(self.effects)))
        if self.outcome is AssessmentOutcome.STOPPED and not self.stop_reasons:
            raise EvaluationDriftError("stopped assessment requires a stop reason")
        if self.outcome is not AssessmentOutcome.STOPPED and self.stop_reasons:
            raise EvaluationDriftError("non-stopped assessment cannot contain stop reasons")
        expected_id, expected_sha = _identity("EDA", "sunderkey.drift-assessment.v1", self.body())
        if self.assessment_id != expected_id or self.assessment_sha256 != expected_sha:
            raise EvaluationDriftError("assessment identity does not match its content")

    @property
    def operational_decision(self) -> bool:
        return False

    def body(self) -> dict[str, Any]:
        return {
            "assessed_at": self.assessed_at,
            "baseline_sha256": self.baseline_sha256,
            "candidate_id": self.candidate_id,
            "candidate_observations": [item.to_dict() for item in self.candidate_observations],
            "candidate_version": self.candidate_version,
            "cohort_sha256": self.cohort_sha256,
            "distribution_artifact_sha256": self.distribution_artifact_sha256,
            "effects": dict(self.effects),
            "metric_results": [item.to_dict() for item in self.metric_results],
            "mode": self.mode.value,
            "operational_decision": False,
            "outcome": self.outcome.value,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "stop_reasons": list(self.stop_reasons),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DriftAssessment:
        fields = {
            "assessed_at",
            "assessment_id",
            "assessment_sha256",
            "baseline_sha256",
            "candidate_id",
            "candidate_observations",
            "candidate_version",
            "cohort_sha256",
            "distribution_artifact_sha256",
            "effects",
            "metric_results",
            "mode",
            "operational_decision",
            "outcome",
            "policy_id",
            "policy_version",
            "schema_version",
            "stop_reasons",
        }
        raw = _exact_fields(raw, fields, "drift assessment")
        if raw["schema_version"] != SCHEMA_VERSION or raw["operational_decision"] is not False:
            raise EvaluationDriftError("assessment schema or decision boundary is invalid")
        return cls(
            assessment_id=raw["assessment_id"],
            assessment_sha256=raw["assessment_sha256"],
            baseline_sha256=raw["baseline_sha256"],
            cohort_sha256=raw["cohort_sha256"],
            candidate_id=raw["candidate_id"],
            candidate_version=raw["candidate_version"],
            distribution_artifact_sha256=raw["distribution_artifact_sha256"],
            mode=raw["mode"],
            policy_id=raw["policy_id"],
            policy_version=raw["policy_version"],
            assessed_at=raw["assessed_at"],
            candidate_observations=tuple(
                MetricObservation.from_dict(item) for item in raw["candidate_observations"]
            ),
            metric_results=tuple(MetricResult.from_dict(item) for item in raw["metric_results"]),
            stop_reasons=tuple(raw["stop_reasons"]),
            outcome=raw["outcome"],
            effects=raw["effects"],
        )


def assess_drift(
    *,
    baseline: EvaluationBaseline,
    cohort: EvaluationCohort,
    candidate_id: str,
    candidate_version: str,
    candidate_observations: Sequence[MetricObservation],
    policy: EvaluationPolicy,
    mode: EvaluationMode | str,
    assessed_at: str,
) -> DriftAssessment:
    """Compare a candidate with a pinned control using integer-only rules."""

    mode = EvaluationMode(mode)
    now = _timestamp(assessed_at, "assessed_at")
    _identifier(candidate_id, "candidate_id")
    _version(candidate_version, "candidate_version")
    if baseline.cohort_sha256 != cohort.cohort_sha256:
        raise EvaluationDriftError("baseline and cohort bindings differ")
    if baseline.distribution_artifact_sha256 != cohort.distribution.artifact_sha256:
        raise EvaluationDriftError("baseline and distribution bindings differ")
    candidate_observations = tuple(candidate_observations)
    _validate_observation_set(
        candidate_observations,
        role=SubjectRole.CANDIDATE,
        subject_id=candidate_id,
        subject_version=candidate_version,
        cohort_sha256=cohort.cohort_sha256,
    )

    stop_reasons: set[str] = set()
    present_strata = {sample.stratum for sample in cohort.samples}
    if not set(policy.required_strata).issubset(present_strata):
        stop_reasons.add("missing_required_strata")
    if cohort.total_samples < policy.min_total_samples:
        stop_reasons.add("insufficient_total_samples")
    if cohort.total_samples > policy.max_total_samples:
        stop_reasons.add("sample_limit_exceeded")
    freshness_floor = now.timestamp() - policy.max_evidence_age_seconds
    if (
        now >= _timestamp(cohort.expires_at, "cohort expires_at")
        or now >= _timestamp(baseline.expires_at, "baseline expires_at")
        or _timestamp(cohort.collected_at, "cohort collected_at").timestamp() < freshness_floor
    ):
        stop_reasons.add("stale_evidence")

    control_by_metric = {item.metric: item for item in baseline.observations}
    candidate_by_metric = {item.metric: item for item in candidate_observations}
    threshold_by_metric = {item.metric: item for item in policy.thresholds}
    if set(control_by_metric) != set(MetricName) or set(candidate_by_metric) != set(MetricName):
        raise EvaluationDriftError("control and candidate require observations for every metric")

    results: list[MetricResult] = []
    for metric in sorted(MetricName, key=lambda item: item.value):
        control = control_by_metric[metric]
        candidate = candidate_by_metric[metric]
        threshold = threshold_by_metric[metric]
        if set(control.strata) != set(cohort.distribution.strata) or set(candidate.strata) != set(
            cohort.distribution.strata
        ):
            stop_reasons.add("missing_observation_strata")
        if (
            control.sample_count < threshold.minimum_samples
            or candidate.sample_count < threshold.minimum_samples
        ):
            stop_reasons.add("insufficient_metric_samples")
        if (
            now.timestamp() - _timestamp(control.observed_at, "control observed_at").timestamp()
            > policy.max_evidence_age_seconds
            or now.timestamp()
            - _timestamp(candidate.observed_at, "candidate observed_at").timestamp()
            > policy.max_evidence_age_seconds
        ):
            stop_reasons.add("stale_evidence")
        if threshold.direction is Direction.HIGHER_IS_BETTER:
            regression = control.value_microunits - candidate.value_microunits
            hard_failure = (
                threshold.hard_candidate_limit_microunits is not None
                and candidate.value_microunits < threshold.hard_candidate_limit_microunits
            )
        else:
            regression = candidate.value_microunits - control.value_microunits
            hard_failure = (
                threshold.hard_candidate_limit_microunits is not None
                and candidate.value_microunits > threshold.hard_candidate_limit_microunits
            )
        sample_floor = min(control.sample_count, candidate.sample_count)
        if sample_floor >= threshold.minimum_samples * 4:
            confidence = ConfidenceBand.STRONG
        elif sample_floor >= threshold.minimum_samples * 2:
            confidence = ConfidenceBand.MODERATE
        else:
            confidence = ConfidenceBand.MINIMUM
        failed = regression > threshold.max_regression_microunits or hard_failure
        if failed and threshold.critical:
            disposition = MetricDisposition.CRITICAL_REGRESSION
            reason = "critical threshold exceeded"
            if metric is MetricName.SAFETY:
                stop_reasons.add("critical_safety_regression")
        elif failed:
            disposition = MetricDisposition.REGRESSION
            reason = "threshold exceeded"
        else:
            disposition = MetricDisposition.PASS
            reason = "threshold satisfied"
        if metric is MetricName.COST and hard_failure:
            stop_reasons.add("over_budget")
        results.append(
            MetricResult(
                metric=metric,
                control_value_microunits=control.value_microunits,
                candidate_value_microunits=candidate.value_microunits,
                regression_microunits=regression,
                allowed_regression_microunits=threshold.max_regression_microunits,
                confidence=confidence,
                disposition=disposition,
                reason=reason,
            )
        )

    if stop_reasons:
        outcome = AssessmentOutcome.STOPPED
    elif any(item.disposition is not MetricDisposition.PASS for item in results):
        outcome = AssessmentOutcome.REGRESSION
    else:
        outcome = AssessmentOutcome.PASS
    values = {
        "baseline_sha256": baseline.baseline_sha256,
        "cohort_sha256": cohort.cohort_sha256,
        "candidate_id": candidate_id,
        "candidate_version": candidate_version,
        "distribution_artifact_sha256": cohort.distribution.artifact_sha256,
        "mode": mode,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "assessed_at": assessed_at,
        "candidate_observations": candidate_observations,
        "metric_results": tuple(results),
        "stop_reasons": tuple(sorted(stop_reasons)),
        "outcome": outcome,
        "effects": dict(NO_EFFECTS),
    }
    body = {
        "assessed_at": assessed_at,
        "baseline_sha256": baseline.baseline_sha256,
        "candidate_id": candidate_id,
        "candidate_observations": [item.to_dict() for item in candidate_observations],
        "candidate_version": candidate_version,
        "cohort_sha256": cohort.cohort_sha256,
        "distribution_artifact_sha256": cohort.distribution.artifact_sha256,
        "effects": dict(NO_EFFECTS),
        "metric_results": [item.to_dict() for item in results],
        "mode": mode.value,
        "operational_decision": False,
        "outcome": outcome.value,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "stop_reasons": sorted(stop_reasons),
    }
    assessment_id, assessment_sha256 = _identity("EDA", "sunderkey.drift-assessment.v1", body)
    return DriftAssessment(assessment_id, assessment_sha256, **values)


@dataclass(frozen=True)
class IndependentGate:
    role: GateRole | str
    reviewer_id: str
    reviewer_version: str
    approved: bool
    reviewed_at: str
    attestation_sha256: str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "role", GateRole(self.role))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("gate role is invalid") from exc
        _identifier(self.reviewer_id, "reviewer_id")
        _version(self.reviewer_version, "reviewer_version")
        _timestamp(self.reviewed_at, "reviewed_at")
        _sha256(self.attestation_sha256, "attestation_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "attestation_sha256": self.attestation_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_id": self.reviewer_id,
            "reviewer_version": self.reviewer_version,
            "role": self.role.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentGate:
        raw = _exact_fields(
            raw,
            {
                "approved",
                "attestation_sha256",
                "reviewed_at",
                "reviewer_id",
                "reviewer_version",
                "role",
            },
            "independent gate",
        )
        return cls(**raw)


@dataclass(frozen=True)
class CanaryStage:
    stage: int
    exposure_basis_points: int
    minimum_observations: int

    def __post_init__(self) -> None:
        _bounded_int(self.stage, "stage", 1, 32)
        _bounded_int(self.exposure_basis_points, "exposure_basis_points", 1, 10_000)
        _bounded_int(self.minimum_observations, "minimum_observations", 1, 10_000_000)

    def to_dict(self) -> dict[str, int]:
        return {
            "exposure_basis_points": self.exposure_basis_points,
            "minimum_observations": self.minimum_observations,
            "stage": self.stage,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CanaryStage:
        raw = _exact_fields(
            raw, {"exposure_basis_points", "minimum_observations", "stage"}, "canary stage"
        )
        return cls(**raw)


@dataclass(frozen=True)
class CanaryProgressionPlan:
    plan_id: str
    plan_sha256: str
    assessment_sha256: str
    stages: tuple[CanaryStage, ...]
    gates: tuple[IndependentGate, ...]
    rollback_criteria: tuple[str, ...]
    status: CanaryPlanStatus | str
    blocked_reasons: tuple[str, ...]
    effects: Mapping[str, str]

    def __post_init__(self) -> None:
        _sha256(self.assessment_sha256, "assessment_sha256")
        if not self.stages or len(self.stages) > 32:
            raise EvaluationDriftError("canary stages are empty or exceed the limit")
        stage_numbers = tuple(item.stage for item in self.stages)
        exposure = tuple(item.exposure_basis_points for item in self.stages)
        if stage_numbers != tuple(range(1, len(self.stages) + 1)) or exposure != tuple(
            sorted(exposure)
        ):
            raise EvaluationDriftError("canary stages must be contiguous with ascending exposure")
        if len(self.gates) > 2:
            raise EvaluationDriftError("canary plan accepts at most two gates")
        gate_roles = tuple(item.role.value for item in self.gates)
        if gate_roles != tuple(sorted(set(gate_roles))):
            raise EvaluationDriftError("canary gates must be unique and sorted")
        separation_failed = len({item.reviewer_id for item in self.gates}) != len(self.gates)
        if tuple(self.rollback_criteria) != tuple(sorted(set(self.rollback_criteria))):
            raise EvaluationDriftError("rollback criteria must be unique and sorted")
        for criterion in self.rollback_criteria:
            _safe_text(criterion, "rollback criterion")
        try:
            object.__setattr__(self, "status", CanaryPlanStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise EvaluationDriftError("canary plan status is invalid") from exc
        if tuple(self.blocked_reasons) != tuple(sorted(set(self.blocked_reasons))):
            raise EvaluationDriftError("blocked reasons must be unique and sorted")
        for reason in self.blocked_reasons:
            _identifier(reason, "blocked reason")
        if self.status is CanaryPlanStatus.BLOCKED and not self.blocked_reasons:
            raise EvaluationDriftError("blocked canary plan requires a reason")
        if (
            self.status is CanaryPlanStatus.READY_FOR_SEPARATE_AUTHORIZATION
            and self.blocked_reasons
        ):
            raise EvaluationDriftError("ready canary plan cannot include blocked reasons")
        if separation_failed and "reviewer_separation_failed" not in self.blocked_reasons:
            raise EvaluationDriftError("reviewer separation failure must remain recorded")
        if separation_failed and self.status is not CanaryPlanStatus.BLOCKED:
            raise EvaluationDriftError("reviewer separation failure must block the canary plan")
        if not self.rollback_criteria and "missing_rollback_criteria" not in self.blocked_reasons:
            raise EvaluationDriftError("missing rollback criteria must remain recorded")
        if not self.rollback_criteria and self.status is not CanaryPlanStatus.BLOCKED:
            raise EvaluationDriftError("missing rollback criteria must block the canary plan")
        if dict(self.effects) != NO_EFFECTS:
            raise EvaluationDriftError("canary plan effects must remain empty")
        object.__setattr__(self, "effects", MappingProxyType(dict(self.effects)))
        expected_id, expected_sha = _identity(
            "ECP", "sunderkey.canary-progression-plan.v1", self.body()
        )
        if self.plan_id != expected_id or self.plan_sha256 != expected_sha:
            raise EvaluationDriftError("canary plan identity does not match its content")

    def body(self) -> dict[str, Any]:
        return {
            "assessment_sha256": self.assessment_sha256,
            "blocked_reasons": list(self.blocked_reasons),
            "effects": dict(self.effects),
            "gates": [item.to_dict() for item in self.gates],
            "planning_only": True,
            "rollback_criteria": list(self.rollback_criteria),
            "stages": [item.to_dict() for item in self.stages],
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "plan_sha256": self.plan_sha256, **self.body()}

    @classmethod
    def from_dict(cls, raw: Any) -> CanaryProgressionPlan:
        fields = {
            "assessment_sha256",
            "blocked_reasons",
            "effects",
            "gates",
            "plan_id",
            "plan_sha256",
            "planning_only",
            "rollback_criteria",
            "stages",
            "status",
        }
        raw = _exact_fields(raw, fields, "canary progression plan")
        if raw["planning_only"] is not True:
            raise EvaluationDriftError("canary progression must remain planning-only")
        return cls(
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            assessment_sha256=raw["assessment_sha256"],
            stages=tuple(CanaryStage.from_dict(item) for item in raw["stages"]),
            gates=tuple(IndependentGate.from_dict(item) for item in raw["gates"]),
            rollback_criteria=tuple(raw["rollback_criteria"]),
            status=raw["status"],
            blocked_reasons=tuple(raw["blocked_reasons"]),
            effects=raw["effects"],
        )


def build_canary_progression_plan(
    *,
    assessment: DriftAssessment,
    stages: Sequence[CanaryStage],
    gates: Sequence[IndependentGate],
    rollback_criteria: Sequence[str],
) -> CanaryProgressionPlan:
    """Build a plan only. Readiness is not authorization to progress."""

    blocked: set[str] = set()
    if assessment.mode is not EvaluationMode.CANARY_PLAN:
        blocked.add("assessment_mode_not_canary_plan")
    if assessment.outcome is not AssessmentOutcome.PASS:
        blocked.add("assessment_not_passed")
    gate_by_role = {item.role: item for item in gates}
    for role in GateRole:
        gate = gate_by_role.get(role)
        if gate is None:
            blocked.add(f"missing_{role.value}_gate")
        elif not gate.approved:
            blocked.add(f"{role.value}_gate_rejected")
    if len({item.reviewer_id for item in gates}) != len(gates):
        blocked.add("reviewer_separation_failed")
    if not rollback_criteria:
        blocked.add("missing_rollback_criteria")
    status = (
        CanaryPlanStatus.BLOCKED if blocked else CanaryPlanStatus.READY_FOR_SEPARATE_AUTHORIZATION
    )
    sorted_gates = tuple(sorted(gates, key=lambda item: item.role.value))
    sorted_criteria = tuple(sorted(set(rollback_criteria)))
    values = {
        "assessment_sha256": assessment.assessment_sha256,
        "stages": tuple(stages),
        "gates": sorted_gates,
        "rollback_criteria": sorted_criteria,
        "status": status,
        "blocked_reasons": tuple(sorted(blocked)),
        "effects": dict(NO_EFFECTS),
    }
    body = {
        "assessment_sha256": assessment.assessment_sha256,
        "blocked_reasons": sorted(blocked),
        "effects": dict(NO_EFFECTS),
        "gates": [item.to_dict() for item in sorted_gates],
        "planning_only": True,
        "rollback_criteria": list(sorted_criteria),
        "stages": [item.to_dict() for item in stages],
        "status": status.value,
    }
    plan_id, plan_sha256 = _identity("ECP", "sunderkey.canary-progression-plan.v1", body)
    return CanaryProgressionPlan(plan_id, plan_sha256, **values)


def verify_assessment(assessment: DriftAssessment) -> None:
    """Reconstruct an assessment to verify identity and strict fields."""

    DriftAssessment.from_dict(assessment.to_dict())


def verify_canary_plan(plan: CanaryProgressionPlan) -> None:
    """Reconstruct a canary plan to verify identity and strict fields."""

    CanaryProgressionPlan.from_dict(plan.to_dict())
