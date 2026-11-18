"""Offline detection, telemetry correlation, control, and replay contracts.

The module validates caller-supplied references only. It never collects
telemetry, connects to a target, writes to a detection system, authorizes an
action, or changes qualification state.
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
CONTRACT_DOMAIN = "sunderkey.detection-validation-contract.v1"
PLAN_DOMAIN = "sunderkey.detection-validation-replay-plan.v1"
MAX_ITEMS = 512
MAX_WINDOW_SECONDS = 86_400

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "collection": "none",
        "detection_system_write": "none",
        "network": "none",
        "qualification": "none",
        "target_action": "none",
    }
)


class DetectionValidationError(ValueError):
    """Raised when a validation contract fails closed."""


class TelemetryDomain(StrEnum):
    NETWORK = "network"
    IDENTITY = "identity"
    CLOUD = "cloud"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    DATA = "data"


class ObservationKind(StrEnum):
    EVENT = "event"
    ALERT = "alert"
    INVESTIGATION = "investigation"
    PREVENTION = "prevention"


class ExpectedEffect(StrEnum):
    DETECT = "detect"
    INVESTIGATE = "investigate"
    PREVENT = "prevent"


class SignalDisposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    INCONCLUSIVE = "inconclusive"


class OutcomeState(StrEnum):
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    INCONCLUSIVE = "inconclusive"


class GapKind(StrEnum):
    MISSING_TELEMETRY = "missing_telemetry"
    MISSING_DETECTION = "missing_detection"
    MISSING_INVESTIGATION = "missing_investigation"
    MISSING_PREVENTION = "missing_prevention"
    DETECTOR_UNMAPPED = "detector_unmapped"
    CONTROL_UNVERIFIED = "control_unverified"


class GapSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewerRole(StrEnum):
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


class ReplayMode(StrEnum):
    OFFLINE_EVIDENCE = "offline_evidence"
    CUSTOMER_MANAGED_LAB = "customer_managed_lab"
    SEPARATELY_AUTHORIZED_RUNTIME = "separately_authorized_runtime"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as exc:
        raise DetectionValidationError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(
    raw: Any, fields: set[str], label: str, *, optional: set[str] = frozenset()
) -> Mapping[str, Any]:
    if (
        not isinstance(raw, Mapping)
        or not set(raw).issubset(fields | optional)
        or set(raw) - optional != fields
    ):
        raise DetectionValidationError(f"{label} fields do not match the contract")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise DetectionValidationError(f"{label} must be a safe identifier")
    if SECRET_RE.search(value):
        raise DetectionValidationError(f"{label} appears to contain secret material")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise DetectionValidationError(f"{label} must be a reason code")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DetectionValidationError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DetectionValidationError(f"{label} must be a UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DetectionValidationError(f"{label} must be between {minimum} and {maximum}")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise DetectionValidationError(f"{label} is invalid") from exc


def _bounded_unique(
    values: Sequence[Any], label: str, *, allow_empty: bool = False
) -> tuple[Any, ...]:
    result = tuple(values)
    if (
        (not result and not allow_empty)
        or len(result) > MAX_ITEMS
        or len(set(result)) != len(result)
    ):
        raise DetectionValidationError(f"{label} must be a bounded unique sequence")
    return result


def _effects(raw: Any, label: str) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != dict(NO_EFFECTS):
        raise DetectionValidationError(f"{label} effects are invalid")


@dataclass(frozen=True)
class ExecutionEvidenceBinding:
    assessment_id: str
    execution_id: str
    executor_profile_id: str
    action_tier: str
    scope_sha256: str
    action_sha256: str
    evidence_sha256: str
    execution_started_at: str
    execution_completed_at: str

    def __post_init__(self) -> None:
        for name in ("assessment_id", "execution_id", "executor_profile_id"):
            _identifier(getattr(self, name), name)
        if self.action_tier not in {"R0", "R1", "R2", "R3", "R4"}:
            raise DetectionValidationError("action_tier is invalid")
        for name in ("scope_sha256", "action_sha256", "evidence_sha256"):
            _sha256(getattr(self, name), name)
        started = _timestamp(self.execution_started_at, "execution_started_at")
        completed = _timestamp(self.execution_completed_at, "execution_completed_at")
        if completed < started:
            raise DetectionValidationError("execution_completed_at precedes execution_started_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "action_tier": self.action_tier,
            "assessment_id": self.assessment_id,
            "evidence_sha256": self.evidence_sha256,
            "execution_completed_at": self.execution_completed_at,
            "execution_id": self.execution_id,
            "execution_started_at": self.execution_started_at,
            "executor_profile_id": self.executor_profile_id,
            "scope_sha256": self.scope_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutionEvidenceBinding:
        fields = {
            "action_sha256",
            "action_tier",
            "assessment_id",
            "evidence_sha256",
            "execution_completed_at",
            "execution_id",
            "execution_started_at",
            "executor_profile_id",
            "scope_sha256",
        }
        value = _exact(raw, fields, "execution evidence binding")
        return cls(**value)


@dataclass(frozen=True)
class CorrelationWindow:
    opens_at: str
    closes_at: str
    maximum_lag_seconds: int

    def __post_init__(self) -> None:
        opens = _timestamp(self.opens_at, "correlation opens_at")
        closes = _timestamp(self.closes_at, "correlation closes_at")
        if closes <= opens:
            raise DetectionValidationError("correlation window must have positive duration")
        duration = int((closes - opens).total_seconds())
        _bounded_int(duration, "correlation window duration", 1, MAX_WINDOW_SECONDS)
        _bounded_int(self.maximum_lag_seconds, "maximum_lag_seconds", 0, MAX_WINDOW_SECONDS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "closes_at": self.closes_at,
            "maximum_lag_seconds": self.maximum_lag_seconds,
            "opens_at": self.opens_at,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CorrelationWindow:
        value = _exact(raw, {"closes_at", "maximum_lag_seconds", "opens_at"}, "correlation window")
        return cls(**value)


@dataclass(frozen=True)
class IndependentValidationBinding:
    reviewer_profile_id: str
    reviewer_role: ReviewerRole | str
    decision: str
    scope_sha256: str
    action_sha256: str
    evidence_sha256: str
    review_sha256: str
    reviewed_at: str

    def __post_init__(self) -> None:
        _identifier(self.reviewer_profile_id, "reviewer_profile_id")
        object.__setattr__(
            self, "reviewer_role", _enum(ReviewerRole, self.reviewer_role, "reviewer_role")
        )
        if self.decision != "accepted":
            raise DetectionValidationError("independent validation decision must be accepted")
        for name in ("scope_sha256", "action_sha256", "evidence_sha256", "review_sha256"):
            _sha256(getattr(self, name), name)
        _timestamp(self.reviewed_at, "reviewed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "decision": self.decision,
            "evidence_sha256": self.evidence_sha256,
            "review_sha256": self.review_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_profile_id": self.reviewer_profile_id,
            "reviewer_role": self.reviewer_role.value,
            "scope_sha256": self.scope_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentValidationBinding:
        fields = {
            "action_sha256",
            "decision",
            "evidence_sha256",
            "review_sha256",
            "reviewed_at",
            "reviewer_profile_id",
            "reviewer_role",
            "scope_sha256",
        }
        return cls(**_exact(raw, fields, "independent validation binding"))


@dataclass(frozen=True)
class ControlObjective:
    objective_id: str
    material_path_id: str
    control_id: str
    control_family: TelemetryDomain | str
    expected_effect: ExpectedEffect | str
    control_config_sha256: str
    required_domains: tuple[TelemetryDomain | str, ...]
    expectation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("objective_id", "material_path_id", "control_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(
            self, "control_family", _enum(TelemetryDomain, self.control_family, "control_family")
        )
        object.__setattr__(
            self, "expected_effect", _enum(ExpectedEffect, self.expected_effect, "expected_effect")
        )
        _sha256(self.control_config_sha256, "control_config_sha256")
        domains = tuple(
            _enum(TelemetryDomain, value, "required domain") for value in self.required_domains
        )
        _bounded_unique(domains, "required_domains")
        object.__setattr__(self, "required_domains", tuple(sorted(domains, key=str)))
        expectations = _bounded_unique(self.expectation_ids, "expectation_ids")
        for value in expectations:
            _identifier(value, "expectation_id")
        object.__setattr__(self, "expectation_ids", tuple(sorted(expectations)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_config_sha256": self.control_config_sha256,
            "control_family": self.control_family.value,
            "control_id": self.control_id,
            "expectation_ids": list(self.expectation_ids),
            "expected_effect": self.expected_effect.value,
            "material_path_id": self.material_path_id,
            "objective_id": self.objective_id,
            "required_domains": [value.value for value in self.required_domains],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ControlObjective:
        fields = {
            "control_config_sha256",
            "control_family",
            "control_id",
            "expectation_ids",
            "expected_effect",
            "material_path_id",
            "objective_id",
            "required_domains",
        }
        value = _exact(raw, fields, "control objective")
        return cls(
            **{
                **value,
                "expectation_ids": tuple(value["expectation_ids"]),
                "required_domains": tuple(value["required_domains"]),
            }
        )


@dataclass(frozen=True)
class ExpectedDetection:
    expectation_id: str
    objective_id: str
    detector_id: str
    telemetry_domain: TelemetryDomain | str
    accepted_observation_kinds: tuple[ObservationKind | str, ...]
    maximum_latency_seconds: int
    detector_config_sha256: str
    required: bool = True

    def __post_init__(self) -> None:
        for name in ("expectation_id", "objective_id", "detector_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(
            self,
            "telemetry_domain",
            _enum(TelemetryDomain, self.telemetry_domain, "telemetry_domain"),
        )
        kinds = tuple(
            _enum(ObservationKind, value, "accepted observation kind")
            for value in self.accepted_observation_kinds
        )
        _bounded_unique(kinds, "accepted_observation_kinds")
        object.__setattr__(self, "accepted_observation_kinds", tuple(sorted(kinds, key=str)))
        _bounded_int(self.maximum_latency_seconds, "maximum_latency_seconds", 0, MAX_WINDOW_SECONDS)
        _sha256(self.detector_config_sha256, "detector_config_sha256")
        if not isinstance(self.required, bool):
            raise DetectionValidationError("required must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_observation_kinds": [
                value.value for value in self.accepted_observation_kinds
            ],
            "detector_config_sha256": self.detector_config_sha256,
            "detector_id": self.detector_id,
            "expectation_id": self.expectation_id,
            "maximum_latency_seconds": self.maximum_latency_seconds,
            "objective_id": self.objective_id,
            "required": self.required,
            "telemetry_domain": self.telemetry_domain.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpectedDetection:
        fields = {
            "accepted_observation_kinds",
            "detector_config_sha256",
            "detector_id",
            "expectation_id",
            "maximum_latency_seconds",
            "objective_id",
            "required",
            "telemetry_domain",
        }
        value = _exact(raw, fields, "expected detection")
        return cls(
            **{**value, "accepted_observation_kinds": tuple(value["accepted_observation_kinds"])}
        )


@dataclass(frozen=True)
class TelemetryObservationReference:
    observation_id: str
    source_system_id: str
    detector_id: str
    telemetry_domain: TelemetryDomain | str
    observation_kind: ObservationKind | str
    observed_at: str
    retained_until: str
    artifact_sha256: str
    custody_sha256: str
    custody_status: str
    scope_sha256: str
    action_sha256: str
    evidence_sha256: str
    redacted: bool = True

    def __post_init__(self) -> None:
        for name in ("observation_id", "source_system_id", "detector_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(
            self,
            "telemetry_domain",
            _enum(TelemetryDomain, self.telemetry_domain, "telemetry_domain"),
        )
        object.__setattr__(
            self,
            "observation_kind",
            _enum(ObservationKind, self.observation_kind, "observation_kind"),
        )
        observed = _timestamp(self.observed_at, "observed_at")
        retained = _timestamp(self.retained_until, "retained_until")
        if retained <= observed:
            raise DetectionValidationError("retained_until must follow observed_at")
        for name in (
            "artifact_sha256",
            "custody_sha256",
            "scope_sha256",
            "action_sha256",
            "evidence_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.custody_status != "durable_verified":
            raise DetectionValidationError("telemetry custody must be durable_verified")
        if self.redacted is not True:
            raise DetectionValidationError("telemetry references must be redacted")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "artifact_sha256": self.artifact_sha256,
            "custody_sha256": self.custody_sha256,
            "custody_status": self.custody_status,
            "detector_id": self.detector_id,
            "evidence_sha256": self.evidence_sha256,
            "observation_id": self.observation_id,
            "observation_kind": self.observation_kind.value,
            "observed_at": self.observed_at,
            "redacted": self.redacted,
            "retained_until": self.retained_until,
            "scope_sha256": self.scope_sha256,
            "source_system_id": self.source_system_id,
            "telemetry_domain": self.telemetry_domain.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TelemetryObservationReference:
        fields = {
            "action_sha256",
            "artifact_sha256",
            "custody_sha256",
            "custody_status",
            "detector_id",
            "evidence_sha256",
            "observation_id",
            "observation_kind",
            "observed_at",
            "redacted",
            "retained_until",
            "scope_sha256",
            "source_system_id",
            "telemetry_domain",
        }
        return cls(**_exact(raw, fields, "telemetry observation reference"))


@dataclass(frozen=True)
class DetectorObservation:
    detector_observation_id: str
    expectation_id: str
    detector_id: str
    observation_ids: tuple[str, ...]
    disposition: SignalDisposition | str
    rationale_code: str
    evidence_sha256: str
    evaluated_at: str

    def __post_init__(self) -> None:
        for name in ("detector_observation_id", "expectation_id", "detector_id"):
            _identifier(getattr(self, name), name)
        observations = _bounded_unique(self.observation_ids, "observation_ids", allow_empty=True)
        for value in observations:
            _identifier(value, "observation_id")
        object.__setattr__(self, "observation_ids", tuple(sorted(observations)))
        disposition = _enum(SignalDisposition, self.disposition, "signal disposition")
        object.__setattr__(self, "disposition", disposition)
        if (
            disposition in {SignalDisposition.TRUE_POSITIVE, SignalDisposition.FALSE_POSITIVE}
            and not observations
        ):
            raise DetectionValidationError("positive signal dispositions require observations")
        if disposition is SignalDisposition.FALSE_NEGATIVE and observations:
            raise DetectionValidationError("false_negative cannot cite a telemetry observation")
        _code(self.rationale_code, "rationale_code")
        _sha256(self.evidence_sha256, "detector observation evidence_sha256")
        _timestamp(self.evaluated_at, "evaluated_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_observation_id": self.detector_observation_id,
            "disposition": self.disposition.value,
            "evaluated_at": self.evaluated_at,
            "evidence_sha256": self.evidence_sha256,
            "expectation_id": self.expectation_id,
            "observation_ids": list(self.observation_ids),
            "rationale_code": self.rationale_code,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DetectorObservation:
        fields = {
            "detector_id",
            "detector_observation_id",
            "disposition",
            "evaluated_at",
            "evidence_sha256",
            "expectation_id",
            "observation_ids",
            "rationale_code",
        }
        value = _exact(raw, fields, "detector observation")
        return cls(**{**value, "observation_ids": tuple(value["observation_ids"])})


@dataclass(frozen=True)
class ControlValidationOutcome:
    outcome_id: str
    objective_id: str
    detector_observation_ids: tuple[str, ...]
    outcome_state: OutcomeState | str
    false_positive_count: int
    false_negative_count: int
    evidence_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.outcome_id, "outcome_id")
        _identifier(self.objective_id, "objective_id")
        values = _bounded_unique(self.detector_observation_ids, "detector_observation_ids")
        for value in values:
            _identifier(value, "detector_observation_id")
        object.__setattr__(self, "detector_observation_ids", tuple(sorted(values)))
        object.__setattr__(
            self, "outcome_state", _enum(OutcomeState, self.outcome_state, "outcome_state")
        )
        _bounded_int(self.false_positive_count, "false_positive_count", 0, MAX_ITEMS)
        _bounded_int(self.false_negative_count, "false_negative_count", 0, MAX_ITEMS)
        _sha256(self.evidence_sha256, "outcome evidence_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_observation_ids": list(self.detector_observation_ids),
            "evidence_sha256": self.evidence_sha256,
            "false_negative_count": self.false_negative_count,
            "false_positive_count": self.false_positive_count,
            "objective_id": self.objective_id,
            "outcome_id": self.outcome_id,
            "outcome_state": self.outcome_state.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ControlValidationOutcome:
        fields = {
            "detector_observation_ids",
            "evidence_sha256",
            "false_negative_count",
            "false_positive_count",
            "objective_id",
            "outcome_id",
            "outcome_state",
        }
        value = _exact(raw, fields, "control validation outcome")
        return cls(
            **{**value, "detector_observation_ids": tuple(value["detector_observation_ids"])}
        )


@dataclass(frozen=True)
class CoverageGap:
    gap_id: str
    objective_id: str
    expectation_id: str
    gap_kind: GapKind | str
    severity: GapSeverity | str
    reason_code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        for name in ("gap_id", "objective_id", "expectation_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(self, "gap_kind", _enum(GapKind, self.gap_kind, "gap_kind"))
        object.__setattr__(self, "severity", _enum(GapSeverity, self.severity, "gap severity"))
        _code(self.reason_code, "reason_code")
        _sha256(self.evidence_sha256, "gap evidence_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_sha256": self.evidence_sha256,
            "expectation_id": self.expectation_id,
            "gap_id": self.gap_id,
            "gap_kind": self.gap_kind.value,
            "objective_id": self.objective_id,
            "reason_code": self.reason_code,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageGap:
        fields = {
            "evidence_sha256",
            "expectation_id",
            "gap_id",
            "gap_kind",
            "objective_id",
            "reason_code",
            "severity",
        }
        return cls(**_exact(raw, fields, "coverage gap"))


@dataclass(frozen=True)
class DetectionValidationContract:
    binding: ExecutionEvidenceBinding
    correlation_window: CorrelationWindow
    objectives: tuple[ControlObjective, ...]
    expected_detections: tuple[ExpectedDetection, ...]
    telemetry_observations: tuple[TelemetryObservationReference, ...]
    detector_observations: tuple[DetectorObservation, ...]
    control_outcomes: tuple[ControlValidationOutcome, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    independent_validations: tuple[IndependentValidationBinding, ...]
    evaluated_at: str
    live_action_claimed: bool = False
    live_action_authorization_sha256: str | None = None
    contract_id: str = field(init=False)
    contract_sha256: str = field(init=False)

    KIND: ClassVar[str] = CONTRACT_DOMAIN

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionEvidenceBinding) or not isinstance(
            self.correlation_window, CorrelationWindow
        ):
            raise DetectionValidationError("binding and correlation_window are required")
        evaluated = _timestamp(self.evaluated_at, "evaluated_at")
        objectives = self._objects(self.objectives, ControlObjective, "objectives", "objective_id")
        expected = self._objects(
            self.expected_detections, ExpectedDetection, "expected_detections", "expectation_id"
        )
        telemetry = self._objects(
            self.telemetry_observations,
            TelemetryObservationReference,
            "telemetry_observations",
            "observation_id",
            allow_empty=True,
        )
        detector = self._objects(
            self.detector_observations,
            DetectorObservation,
            "detector_observations",
            "detector_observation_id",
        )
        outcomes = self._objects(
            self.control_outcomes, ControlValidationOutcome, "control_outcomes", "outcome_id"
        )
        gaps = self._objects(
            self.coverage_gaps, CoverageGap, "coverage_gaps", "gap_id", allow_empty=True
        )
        validations = self._objects(
            self.independent_validations,
            IndependentValidationBinding,
            "independent_validations",
            "reviewer_role",
        )
        for name, value in (
            ("objectives", objectives),
            ("expected_detections", expected),
            ("telemetry_observations", telemetry),
            ("detector_observations", detector),
            ("control_outcomes", outcomes),
            ("coverage_gaps", gaps),
            ("independent_validations", validations),
        ):
            object.__setattr__(self, name, value)
        self._validate_window(evaluated, telemetry)
        self._validate_bindings(validations, telemetry, detector, outcomes, gaps)
        self._validate_graph(objectives, expected, telemetry, detector, outcomes, gaps)
        if not isinstance(self.live_action_claimed, bool):
            raise DetectionValidationError("live_action_claimed must be boolean")
        if self.live_action_claimed:
            if self.live_action_authorization_sha256 is None:
                raise DetectionValidationError("live action claim lacks separate authorization")
            _sha256(self.live_action_authorization_sha256, "live_action_authorization_sha256")
            if self.binding.action_tier == "R0":
                raise DetectionValidationError("R0 evidence cannot claim a live action")
        elif self.live_action_authorization_sha256 is not None:
            raise DetectionValidationError("unused live action authorization is forbidden")
        body = self._body()
        identity, digest = _identity("DVC", self.KIND, body)
        object.__setattr__(self, "contract_id", identity)
        object.__setattr__(self, "contract_sha256", digest)

    @staticmethod
    def _objects(
        values: Sequence[Any],
        expected_type: type,
        label: str,
        key: str,
        *,
        allow_empty: bool = False,
    ) -> tuple[Any, ...]:
        result = tuple(values)
        if (
            (not result and not allow_empty)
            or len(result) > MAX_ITEMS
            or not all(isinstance(item, expected_type) for item in result)
        ):
            raise DetectionValidationError(f"{label} must be a bounded sequence of valid records")
        keys = [getattr(item, key) for item in result]
        if len(set(keys)) != len(keys):
            raise DetectionValidationError(f"{label} contains duplicate identities")
        return tuple(sorted(result, key=lambda item: str(getattr(item, key))))

    def _validate_window(
        self, evaluated: datetime, telemetry: tuple[TelemetryObservationReference, ...]
    ) -> None:
        opens = _timestamp(self.correlation_window.opens_at, "correlation opens_at")
        closes = _timestamp(self.correlation_window.closes_at, "correlation closes_at")
        started = _timestamp(self.binding.execution_started_at, "execution_started_at")
        completed = _timestamp(self.binding.execution_completed_at, "execution_completed_at")
        if opens > started or closes < completed:
            raise DetectionValidationError("correlation window does not contain execution")
        if int((closes - completed).total_seconds()) > self.correlation_window.maximum_lag_seconds:
            raise DetectionValidationError("correlation window exceeds maximum lag")
        if evaluated < closes:
            raise DetectionValidationError("evaluation precedes correlation window close")
        for item in telemetry:
            observed = _timestamp(item.observed_at, "observed_at")
            retained = _timestamp(item.retained_until, "retained_until")
            if observed < opens or observed > closes:
                raise DetectionValidationError(
                    "telemetry observation is outside the correlation window"
                )
            if retained <= evaluated:
                raise DetectionValidationError("telemetry observation custody is stale")

    def _validate_bindings(
        self,
        validations: tuple[IndependentValidationBinding, ...],
        telemetry: tuple[TelemetryObservationReference, ...],
        detector: tuple[DetectorObservation, ...],
        outcomes: tuple[ControlValidationOutcome, ...],
        gaps: tuple[CoverageGap, ...],
    ) -> None:
        roles = {item.reviewer_role for item in validations}
        if roles != set(ReviewerRole) or len(validations) != 2:
            raise DetectionValidationError(
                "both independent validation roles are required exactly once"
            )
        reviewers = {item.reviewer_profile_id for item in validations}
        if len(reviewers) != 2 or self.binding.executor_profile_id in reviewers:
            raise DetectionValidationError(
                "independent validators must be distinct from the executor and each other"
            )
        expected_hashes = (
            self.binding.scope_sha256,
            self.binding.action_sha256,
            self.binding.evidence_sha256,
        )
        for item in validations:
            if (item.scope_sha256, item.action_sha256, item.evidence_sha256) != expected_hashes:
                raise DetectionValidationError(
                    "independent validation hashes do not match execution evidence"
                )
            reviewed = _timestamp(item.reviewed_at, "reviewed_at")
            if reviewed < _timestamp(self.correlation_window.closes_at, "correlation closes_at"):
                raise DetectionValidationError("independent validation precedes correlation close")
            if reviewed > _timestamp(self.evaluated_at, "evaluated_at"):
                raise DetectionValidationError("independent validation follows contract evaluation")
        for item in telemetry:
            if (item.scope_sha256, item.action_sha256, item.evidence_sha256) != expected_hashes:
                raise DetectionValidationError("telemetry hashes do not match execution evidence")
        if any(
            item.evidence_sha256 != self.binding.evidence_sha256
            for item in (*detector, *outcomes, *gaps)
        ):
            raise DetectionValidationError(
                "validation evidence hash does not match execution evidence"
            )

    @staticmethod
    def _derive_state(dispositions: tuple[SignalDisposition, ...]) -> OutcomeState:
        false_negatives = sum(value is SignalDisposition.FALSE_NEGATIVE for value in dispositions)
        false_positives = sum(value is SignalDisposition.FALSE_POSITIVE for value in dispositions)
        inconclusive = sum(value is SignalDisposition.INCONCLUSIVE for value in dispositions)
        true_positives = sum(value is SignalDisposition.TRUE_POSITIVE for value in dispositions)
        if false_negatives and true_positives:
            return OutcomeState.PARTIALLY_EFFECTIVE
        if false_negatives:
            return OutcomeState.INEFFECTIVE
        if false_positives and true_positives:
            return OutcomeState.PARTIALLY_EFFECTIVE
        if false_positives:
            return OutcomeState.INEFFECTIVE
        if inconclusive:
            return OutcomeState.INCONCLUSIVE
        return OutcomeState.EFFECTIVE

    def _validate_graph(
        self,
        objectives: tuple[ControlObjective, ...],
        expected: tuple[ExpectedDetection, ...],
        telemetry: tuple[TelemetryObservationReference, ...],
        detector: tuple[DetectorObservation, ...],
        outcomes: tuple[ControlValidationOutcome, ...],
        gaps: tuple[CoverageGap, ...],
    ) -> None:
        objective_by_id = {item.objective_id: item for item in objectives}
        expected_by_id = {item.expectation_id: item for item in expected}
        telemetry_by_id = {item.observation_id: item for item in telemetry}
        detector_by_id = {item.detector_observation_id: item for item in detector}
        if set(item.objective_id for item in expected) != set(objective_by_id):
            raise DetectionValidationError("every objective must have expected detections")
        if {item.objective_id for item in outcomes} != set(objective_by_id) or len(outcomes) != len(
            objectives
        ):
            raise DetectionValidationError("every objective must have exactly one control outcome")
        for objective in objectives:
            actual = {
                item.expectation_id
                for item in expected
                if item.objective_id == objective.objective_id
            }
            if set(objective.expectation_ids) != actual:
                raise DetectionValidationError("objective expectation bindings are incomplete")
            expected_domains = {
                item.telemetry_domain
                for item in expected
                if item.objective_id == objective.objective_id
            }
            if set(objective.required_domains) != expected_domains:
                raise DetectionValidationError(
                    "objective required domains are not exactly mapped to expectations"
                )
            expected_effect_kind = {
                ExpectedEffect.DETECT: ObservationKind.ALERT,
                ExpectedEffect.INVESTIGATE: ObservationKind.INVESTIGATION,
                ExpectedEffect.PREVENT: ObservationKind.PREVENTION,
            }[objective.expected_effect]
            if not any(
                expected_effect_kind in item.accepted_observation_kinds
                for item in expected
                if item.objective_id == objective.objective_id
            ):
                raise DetectionValidationError(
                    "objective expected effect is not represented by its detections"
                )
        by_expectation: dict[str, list[DetectorObservation]] = {key: [] for key in expected_by_id}
        for item in detector:
            expectation = expected_by_id.get(item.expectation_id)
            if expectation is None or item.detector_id != expectation.detector_id:
                raise DetectionValidationError(
                    "detector observation does not match its expectation"
                )
            by_expectation[item.expectation_id].append(item)
            assessment_time = _timestamp(item.evaluated_at, "detector evaluated_at")
            if assessment_time < _timestamp(
                self.correlation_window.closes_at, "correlation closes_at"
            ) or assessment_time > _timestamp(self.evaluated_at, "evaluated_at"):
                raise DetectionValidationError(
                    "detector observation evaluation is outside the review interval"
                )
            for observation_id in item.observation_ids:
                observation = telemetry_by_id.get(observation_id)
                if observation is None:
                    raise DetectionValidationError("detector observation cites missing telemetry")
                if (
                    observation.detector_id != item.detector_id
                    or observation.telemetry_domain is not expectation.telemetry_domain
                ):
                    raise DetectionValidationError("telemetry does not match detector expectation")
                if observation.observation_kind not in expectation.accepted_observation_kinds:
                    raise DetectionValidationError(
                        "telemetry kind is not accepted by the expectation"
                    )
                completed = _timestamp(
                    self.binding.execution_completed_at, "execution_completed_at"
                )
                observed = _timestamp(observation.observed_at, "observed_at")
                if (
                    observed > completed
                    and int((observed - completed).total_seconds())
                    > expectation.maximum_latency_seconds
                ):
                    raise DetectionValidationError("telemetry exceeds expected detection latency")
        for expectation_id, records in by_expectation.items():
            if len(records) != 1:
                raise DetectionValidationError(
                    "every expectation must have exactly one detector observation"
                )
            if (
                expected_by_id[expectation_id].required
                and records[0].disposition is SignalDisposition.INCONCLUSIVE
            ):
                matching = [gap for gap in gaps if gap.expectation_id == expectation_id]
                if not matching:
                    raise DetectionValidationError(
                        "inconclusive required detection needs a coverage gap"
                    )
        for outcome in outcomes:
            objective = objective_by_id[outcome.objective_id]
            expected_ids = set(objective.expectation_ids)
            records = [detector_by_id.get(value) for value in outcome.detector_observation_ids]
            if (
                any(item is None for item in records)
                or {item.expectation_id for item in records if item is not None} != expected_ids
            ):
                raise DetectionValidationError("control outcome detector bindings are incomplete")
            typed_records = tuple(item for item in records if item is not None)
            dispositions = tuple(item.disposition for item in typed_records)
            if outcome.false_positive_count != sum(
                value is SignalDisposition.FALSE_POSITIVE for value in dispositions
            ):
                raise DetectionValidationError(
                    "control outcome false-positive count is contradictory"
                )
            if outcome.false_negative_count != sum(
                value is SignalDisposition.FALSE_NEGATIVE for value in dispositions
            ):
                raise DetectionValidationError(
                    "control outcome false-negative count is contradictory"
                )
            if outcome.outcome_state is not self._derive_state(dispositions):
                raise DetectionValidationError("control outcome state is contradictory")
        for gap in gaps:
            expectation = expected_by_id.get(gap.expectation_id)
            if expectation is None or expectation.objective_id != gap.objective_id:
                raise DetectionValidationError("coverage gap does not match its expectation")
            objective = objective_by_id[gap.objective_id]
            compatible_gap_kinds = {
                ExpectedEffect.DETECT: {GapKind.MISSING_TELEMETRY, GapKind.MISSING_DETECTION},
                ExpectedEffect.INVESTIGATE: {
                    GapKind.MISSING_TELEMETRY,
                    GapKind.MISSING_INVESTIGATION,
                },
                ExpectedEffect.PREVENT: {
                    GapKind.MISSING_TELEMETRY,
                    GapKind.MISSING_PREVENTION,
                },
            }[objective.expected_effect]
            if (
                gap.gap_kind
                in {
                    GapKind.MISSING_TELEMETRY,
                    GapKind.MISSING_DETECTION,
                    GapKind.MISSING_INVESTIGATION,
                    GapKind.MISSING_PREVENTION,
                }
                and gap.gap_kind not in compatible_gap_kinds
            ):
                raise DetectionValidationError(
                    "coverage gap kind contradicts the objective expected effect"
                )
        gaps_by_objective = {item.objective_id for item in gaps}
        if any(
            item.outcome_state is OutcomeState.EFFECTIVE and item.objective_id in gaps_by_objective
            for item in outcomes
        ):
            raise DetectionValidationError(
                "effective control outcome cannot declare a coverage gap"
            )
        false_negative_ids = {
            item.expectation_id
            for item in detector
            if item.disposition is SignalDisposition.FALSE_NEGATIVE
        }
        gap_ids = {
            item.expectation_id
            for item in gaps
            if item.gap_kind
            in {
                GapKind.MISSING_TELEMETRY,
                GapKind.MISSING_DETECTION,
                GapKind.MISSING_INVESTIGATION,
                GapKind.MISSING_PREVENTION,
            }
        }
        if not false_negative_ids.issubset(gap_ids):
            raise DetectionValidationError("false negatives require explicit coverage gaps")

    def _body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "control_outcomes": [item.to_dict() for item in self.control_outcomes],
            "correlation_window": self.correlation_window.to_dict(),
            "coverage_gaps": [item.to_dict() for item in self.coverage_gaps],
            "detector_observations": [item.to_dict() for item in self.detector_observations],
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "expected_detections": [item.to_dict() for item in self.expected_detections],
            "independent_validations": [item.to_dict() for item in self.independent_validations],
            "live_action_authorization_sha256": self.live_action_authorization_sha256,
            "live_action_claimed": self.live_action_claimed,
            "objectives": [item.to_dict() for item in self.objectives],
            "schema_version": SCHEMA_VERSION,
            "telemetry_observations": [item.to_dict() for item in self.telemetry_observations],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "kind": self.KIND,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DetectionValidationContract:
        fields = {
            "binding",
            "contract_id",
            "contract_sha256",
            "control_outcomes",
            "correlation_window",
            "coverage_gaps",
            "detector_observations",
            "effects",
            "evaluated_at",
            "expected_detections",
            "independent_validations",
            "kind",
            "live_action_authorization_sha256",
            "live_action_claimed",
            "objectives",
            "schema_version",
            "telemetry_observations",
        }
        value = _exact(raw, fields, "detection validation contract")
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise DetectionValidationError("contract kind or schema version is invalid")
        _effects(value["effects"], "contract")
        candidate = cls(
            binding=ExecutionEvidenceBinding.from_dict(value["binding"]),
            correlation_window=CorrelationWindow.from_dict(value["correlation_window"]),
            objectives=tuple(ControlObjective.from_dict(item) for item in value["objectives"]),
            expected_detections=tuple(
                ExpectedDetection.from_dict(item) for item in value["expected_detections"]
            ),
            telemetry_observations=tuple(
                TelemetryObservationReference.from_dict(item)
                for item in value["telemetry_observations"]
            ),
            detector_observations=tuple(
                DetectorObservation.from_dict(item) for item in value["detector_observations"]
            ),
            control_outcomes=tuple(
                ControlValidationOutcome.from_dict(item) for item in value["control_outcomes"]
            ),
            coverage_gaps=tuple(CoverageGap.from_dict(item) for item in value["coverage_gaps"]),
            independent_validations=tuple(
                IndependentValidationBinding.from_dict(item)
                for item in value["independent_validations"]
            ),
            evaluated_at=value["evaluated_at"],
            live_action_claimed=value["live_action_claimed"],
            live_action_authorization_sha256=value["live_action_authorization_sha256"],
        )
        if (
            candidate.contract_id != value["contract_id"]
            or candidate.contract_sha256 != value["contract_sha256"]
        ):
            raise DetectionValidationError("contract content address is invalid")
        return candidate


@dataclass(frozen=True)
class ReplaySafeValidationPlan:
    source_contract_id: str
    source_contract_sha256: str
    scope_sha256: str
    action_sha256: str
    evidence_sha256: str
    control_change_sha256: str
    replay_mode: ReplayMode | str
    maximum_attempts: int
    requested_action_tier: str
    independent_validations: tuple[IndependentValidationBinding, ...]
    live_action_requested: bool = False
    live_action_authorization_sha256: str | None = None
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)
    idempotency_key: str = field(init=False)

    KIND: ClassVar[str] = PLAN_DOMAIN

    def __post_init__(self) -> None:
        _identifier(self.source_contract_id, "source_contract_id")
        for name in (
            "source_contract_sha256",
            "scope_sha256",
            "action_sha256",
            "evidence_sha256",
            "control_change_sha256",
        ):
            _sha256(getattr(self, name), name)
        object.__setattr__(self, "replay_mode", _enum(ReplayMode, self.replay_mode, "replay_mode"))
        _bounded_int(self.maximum_attempts, "maximum_attempts", 1, 5)
        if self.requested_action_tier not in {"R0", "R1", "R2", "R3", "R4"}:
            raise DetectionValidationError("requested_action_tier is invalid")
        validations = tuple(
            sorted(self.independent_validations, key=lambda item: item.reviewer_role.value)
        )
        if len(validations) != 2 or {item.reviewer_role for item in validations} != set(
            ReviewerRole
        ):
            raise DetectionValidationError("replay plan requires both independent validation roles")
        if len({item.reviewer_profile_id for item in validations}) != 2:
            raise DetectionValidationError("replay validators must be distinct")
        hashes = (self.scope_sha256, self.action_sha256, self.evidence_sha256)
        if any(
            (item.scope_sha256, item.action_sha256, item.evidence_sha256) != hashes
            for item in validations
        ):
            raise DetectionValidationError("replay validation hashes do not match")
        object.__setattr__(self, "independent_validations", validations)
        if not isinstance(self.live_action_requested, bool):
            raise DetectionValidationError("live_action_requested must be boolean")
        if self.live_action_requested:
            if (
                self.replay_mode is not ReplayMode.SEPARATELY_AUTHORIZED_RUNTIME
                or self.live_action_authorization_sha256 is None
            ):
                raise DetectionValidationError("live replay requires separate authorization")
            _sha256(self.live_action_authorization_sha256, "live_action_authorization_sha256")
        elif self.live_action_authorization_sha256 is not None:
            raise DetectionValidationError("unused live action authorization is forbidden")
        if self.replay_mode is ReplayMode.OFFLINE_EVIDENCE and self.requested_action_tier != "R0":
            raise DetectionValidationError("offline replay must remain R0")
        body = self._body()
        identity, digest = _identity("DVRP", self.KIND, body)
        object.__setattr__(self, "plan_id", identity)
        object.__setattr__(self, "plan_sha256", digest)
        object.__setattr__(
            self,
            "idempotency_key",
            canonical_sha256(
                {
                    "domain": self.KIND,
                    "source": self.source_contract_sha256,
                    "control_change": self.control_change_sha256,
                }
            ),
        )

    def _body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "control_change_sha256": self.control_change_sha256,
            "effects": dict(NO_EFFECTS),
            "evidence_sha256": self.evidence_sha256,
            "independent_validations": [item.to_dict() for item in self.independent_validations],
            "live_action_authorization_sha256": self.live_action_authorization_sha256,
            "live_action_requested": self.live_action_requested,
            "maximum_attempts": self.maximum_attempts,
            "replay_mode": self.replay_mode.value,
            "requested_action_tier": self.requested_action_tier,
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "source_contract_id": self.source_contract_id,
            "source_contract_sha256": self.source_contract_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "idempotency_key": self.idempotency_key,
            "kind": self.KIND,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ReplaySafeValidationPlan:
        fields = {
            "action_sha256",
            "control_change_sha256",
            "effects",
            "evidence_sha256",
            "idempotency_key",
            "independent_validations",
            "kind",
            "live_action_authorization_sha256",
            "live_action_requested",
            "maximum_attempts",
            "plan_id",
            "plan_sha256",
            "replay_mode",
            "requested_action_tier",
            "schema_version",
            "scope_sha256",
            "source_contract_id",
            "source_contract_sha256",
        }
        value = _exact(raw, fields, "replay validation plan")
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise DetectionValidationError("replay plan kind or schema version is invalid")
        _effects(value["effects"], "replay plan")
        candidate = cls(
            source_contract_id=value["source_contract_id"],
            source_contract_sha256=value["source_contract_sha256"],
            scope_sha256=value["scope_sha256"],
            action_sha256=value["action_sha256"],
            evidence_sha256=value["evidence_sha256"],
            control_change_sha256=value["control_change_sha256"],
            replay_mode=value["replay_mode"],
            maximum_attempts=value["maximum_attempts"],
            requested_action_tier=value["requested_action_tier"],
            independent_validations=tuple(
                IndependentValidationBinding.from_dict(item)
                for item in value["independent_validations"]
            ),
            live_action_requested=value["live_action_requested"],
            live_action_authorization_sha256=value["live_action_authorization_sha256"],
        )
        if (
            candidate.plan_id != value["plan_id"]
            or candidate.plan_sha256 != value["plan_sha256"]
            or candidate.idempotency_key != value["idempotency_key"]
        ):
            raise DetectionValidationError("replay plan content address is invalid")
        return candidate


def build_replay_plan(
    contract: DetectionValidationContract,
    *,
    control_change_sha256: str,
    replay_mode: ReplayMode | str = ReplayMode.OFFLINE_EVIDENCE,
    maximum_attempts: int = 1,
    requested_action_tier: str = "R0",
    live_action_requested: bool = False,
    live_action_authorization_sha256: str | None = None,
) -> ReplaySafeValidationPlan:
    """Build an inert replay plan from a verified validation contract."""

    verified = DetectionValidationContract.from_dict(contract.to_dict())
    return ReplaySafeValidationPlan(
        source_contract_id=verified.contract_id,
        source_contract_sha256=verified.contract_sha256,
        scope_sha256=verified.binding.scope_sha256,
        action_sha256=verified.binding.action_sha256,
        evidence_sha256=verified.binding.evidence_sha256,
        control_change_sha256=control_change_sha256,
        replay_mode=replay_mode,
        maximum_attempts=maximum_attempts,
        requested_action_tier=requested_action_tier,
        independent_validations=verified.independent_validations,
        live_action_requested=live_action_requested,
        live_action_authorization_sha256=live_action_authorization_sha256,
    )


__all__ = [
    "CONTRACT_DOMAIN",
    "NO_EFFECTS",
    "PLAN_DOMAIN",
    "SCHEMA_VERSION",
    "ControlObjective",
    "ControlValidationOutcome",
    "CorrelationWindow",
    "CoverageGap",
    "DetectionValidationContract",
    "DetectionValidationError",
    "DetectorObservation",
    "ExecutionEvidenceBinding",
    "ExpectedDetection",
    "ExpectedEffect",
    "GapKind",
    "GapSeverity",
    "IndependentValidationBinding",
    "ObservationKind",
    "OutcomeState",
    "ReplayMode",
    "ReplaySafeValidationPlan",
    "ReviewerRole",
    "SignalDisposition",
    "TelemetryDomain",
    "TelemetryObservationReference",
    "build_replay_plan",
    "canonical_json",
    "canonical_sha256",
]
