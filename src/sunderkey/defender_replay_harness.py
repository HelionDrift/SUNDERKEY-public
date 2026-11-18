"""Deterministic offline defender replay and promotion contracts.

The harness consumes caller-supplied, sanitized references. It does not read
the filesystem, contact a provider, query a defensive system, perform target
actions, or claim operational effectiveness.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 512
MAX_SECONDS = 31_536_000
NO_BUILTIN_NETWORK = True
NO_BUILTIN_PROVIDER_CALLS = True
NO_FILESYSTEM_DISCOVERY = True
NO_TARGET_ACTIONS = True
QUALIFICATION_EFFECT = "none"
RUNTIME_STATUS = "repository_only_nonqualified"
REQUIRED_REVIEWER_ROLES = ("independent_assurance", "independent_control")
NO_EFFECTS = MappingProxyType(
    {
        "credential_access": "none",
        "filesystem_discovery": "none",
        "network": "none",
        "provider_calls": "none",
        "qualification": "none",
        "source_write": "none",
        "target_action": "none",
    }
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,255}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_CONTENT_ID_RE = re.compile(r"^[A-Z]{3}-[0-9A-F]{32}$")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b[\"']?\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)


class DefenderReplayError(ValueError):
    """Raised when replay input or output fails closed."""


class AvailabilityState(StrEnum):
    AVAILABLE = "available"
    ABSENT = "absent"


class ObservationState(StrEnum):
    DETECTED_WITHIN_OBJECTIVE = "detected_within_objective"
    DETECTED_LATE = "detected_late"
    FAILED_DETECTION = "failed_detection"
    ABSENT_SOURCE_DATA = "absent_source_data"


class ReviewDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON without secret-like material."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DefenderReplayError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise DefenderReplayError("secret-like material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DefenderReplayError(f"{label} fields are invalid")
    return raw


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DefenderReplayError(f"{label} must be a sha256 digest")
    return value


def _ref(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None or _SECRET_RE.search(value):
        raise DefenderReplayError(f"{label} must be a safe opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise DefenderReplayError(f"{label} must use the {namespace} namespace")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise DefenderReplayError(f"{label} must be a canonical code")
    return value


def _content_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise DefenderReplayError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DefenderReplayError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DefenderReplayError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise DefenderReplayError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DefenderReplayError(f"{label} is outside the supported range")
    return value


def _objects(values: Sequence[Any], item_type: type[Any], label: str) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)):
        raise DefenderReplayError(f"{label} must be a sequence")
    result = tuple(values)
    if len(result) > MAX_ITEMS or any(not isinstance(item, item_type) for item in result):
        raise DefenderReplayError(f"{label} is invalid")
    return result


def _codes(values: Sequence[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise DefenderReplayError(f"{label} must be a sequence")
    result = tuple(values)
    if not result or len(result) > MAX_ITEMS:
        raise DefenderReplayError(f"{label} is outside the supported range")
    for value in result:
        _code(value, label)
    if result != tuple(sorted(set(result))):
        raise DefenderReplayError(f"{label} must be sorted and unique")
    return result


@dataclass(frozen=True, slots=True)
class ReplayContext:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    corpus_sha256: str
    provenance_policy_sha256: str

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _ref(self.context_ref, "context_ref", "contextref")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.corpus_sha256, "corpus_sha256")
        _digest(self.provenance_policy_sha256, "provenance_policy_sha256")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> ReplayContext:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "replay context"))


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceBinding:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    assessment_ref: str
    assessment_sha256: str
    evidence_manifest_sha256: str
    custody_sha256: str
    completed_at: str
    sanitized: bool = True
    custody_status: str = "durable_verified"
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.replay-assessment-evidence-binding.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _ref(self.context_ref, "context_ref", "contextref")
        _digest(self.scope_sha256, "scope_sha256")
        _ref(self.assessment_ref, "assessment_ref", "assessmentref")
        _digest(self.assessment_sha256, "assessment_sha256")
        _digest(self.evidence_manifest_sha256, "evidence_manifest_sha256")
        _digest(self.custody_sha256, "custody_sha256")
        _time(self.completed_at, "completed_at")
        if self.sanitized is not True or self.custody_status != "durable_verified":
            raise DefenderReplayError("assessment evidence must be sanitized and durable_verified")
        identity, digest = _identity("AEB", self.KIND, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "assessment_sha256": self.assessment_sha256,
            "completed_at": self.completed_at,
            "context_ref": self.context_ref,
            "custody_sha256": self.custody_sha256,
            "custody_status": self.custody_status,
            "engagement_ref": self.engagement_ref,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
            "sanitized": self.sanitized,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class EvaluationContractBinding:
    program_id: str
    program_sha256: str
    run_plan_id: str
    run_plan_sha256: str
    scoring_policy_sha256: str
    corpus_assembly_sha256: str
    evaluator_ref: str
    producer_ref: str

    def __post_init__(self) -> None:
        _content_id(self.program_id, "program_id", "EVP")
        _digest(self.program_sha256, "program_sha256")
        _content_id(self.run_plan_id, "run_plan_id", "ERP")
        _digest(self.run_plan_sha256, "run_plan_sha256")
        _digest(self.scoring_policy_sha256, "scoring_policy_sha256")
        _digest(self.corpus_assembly_sha256, "corpus_assembly_sha256")
        _ref(self.evaluator_ref, "evaluator_ref", "principalref")
        _ref(self.producer_ref, "producer_ref", "principalref")
        if self.evaluator_ref == self.producer_ref:
            raise DefenderReplayError("evaluator and producer identities must be separated")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationContractBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "evaluation binding"))


@dataclass(frozen=True, slots=True)
class DetectionCorrelationBinding:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    correlation_bundle_id: str
    correlation_bundle_sha256: str
    correlation_assessment_id: str
    correlation_assessment_sha256: str
    correlation_review_plan_id: str
    correlation_review_plan_sha256: str
    consumed_events_manifest_sha256: str
    evaluated_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-correlation-binding.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _ref(self.context_ref, "context_ref", "contextref")
        _digest(self.scope_sha256, "scope_sha256")
        _content_id(self.correlation_bundle_id, "correlation_bundle_id", "DCB")
        _digest(self.correlation_bundle_sha256, "correlation_bundle_sha256")
        _content_id(self.correlation_assessment_id, "correlation_assessment_id", "DCA")
        _digest(self.correlation_assessment_sha256, "correlation_assessment_sha256")
        _content_id(self.correlation_review_plan_id, "correlation_review_plan_id", "DRP")
        _digest(self.correlation_review_plan_sha256, "correlation_review_plan_sha256")
        _digest(self.consumed_events_manifest_sha256, "consumed_events_manifest_sha256")
        _time(self.evaluated_at, "evaluated_at")
        identity, digest = _identity("DRC", self.KIND, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "consumed_events_manifest_sha256": self.consumed_events_manifest_sha256,
            "context_ref": self.context_ref,
            "correlation_assessment_id": self.correlation_assessment_id,
            "correlation_assessment_sha256": self.correlation_assessment_sha256,
            "correlation_bundle_id": self.correlation_bundle_id,
            "correlation_bundle_sha256": self.correlation_bundle_sha256,
            "correlation_review_plan_id": self.correlation_review_plan_id,
            "correlation_review_plan_sha256": self.correlation_review_plan_sha256,
            "engagement_ref": self.engagement_ref,
            "evaluated_at": self.evaluated_at,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class TelemetryFixture:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    corpus_sha256: str
    source_event_ref: str
    normalized_event_id: str
    normalized_event_sha256: str
    source_artifact_sha256: str
    provenance_sha256: str
    finding_fixture_id: str
    finding_fixture_sha256: str
    telemetry_domain: str
    operation_code: str
    occurred_at: str
    observed_at: str
    sanitized: bool = True
    fixture_id: str = field(init=False)
    fixture_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-telemetry-fixture.v1"
    DOMAINS: ClassVar[frozenset[str]] = frozenset(
        {"application_api", "cloud", "endpoint", "identity", "network", "siem"}
    )

    def __post_init__(self) -> None:
        _context_fields(self)
        _ref(self.source_event_ref, "source_event_ref", "eventref")
        _content_id(self.normalized_event_id, "normalized_event_id", "NTE")
        _digest(self.normalized_event_sha256, "normalized_event_sha256")
        _digest(self.source_artifact_sha256, "source_artifact_sha256")
        _digest(self.provenance_sha256, "provenance_sha256")
        _content_id(self.finding_fixture_id, "finding_fixture_id", "DFF")
        _digest(self.finding_fixture_sha256, "finding_fixture_sha256")
        if self.telemetry_domain not in self.DOMAINS:
            raise DefenderReplayError("telemetry_domain is invalid")
        _code(self.operation_code, "operation_code")
        _time(self.occurred_at, "occurred_at")
        _time(self.observed_at, "observed_at")
        if _instant(self.observed_at) < _instant(self.occurred_at):
            raise DefenderReplayError("telemetry observation precedes occurrence")
        if self.sanitized is not True:
            raise DefenderReplayError("telemetry fixture must be sanitized")
        identity, digest = _identity("DTF", self.KIND, self.body())
        object.__setattr__(self, "fixture_id", identity)
        object.__setattr__(self, "fixture_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "context_ref": self.context_ref,
            "corpus_sha256": self.corpus_sha256,
            "engagement_ref": self.engagement_ref,
            "finding_fixture_id": self.finding_fixture_id,
            "finding_fixture_sha256": self.finding_fixture_sha256,
            "normalized_event_id": self.normalized_event_id,
            "normalized_event_sha256": self.normalized_event_sha256,
            "observed_at": self.observed_at,
            "occurred_at": self.occurred_at,
            "operation_code": self.operation_code,
            "provenance_sha256": self.provenance_sha256,
            "sanitized": self.sanitized,
            "scope_sha256": self.scope_sha256,
            "source_artifact_sha256": self.source_artifact_sha256,
            "source_event_ref": self.source_event_ref,
            "telemetry_domain": self.telemetry_domain,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class FindingFixture:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    corpus_sha256: str
    assessment_binding_id: str
    assessment_binding_sha256: str
    finding_ref: str
    finding_sha256: str
    evidence_sha256: str
    provenance_sha256: str
    occurred_at: str
    sanitized: bool = True
    fixture_id: str = field(init=False)
    fixture_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-finding-fixture.v1"

    def __post_init__(self) -> None:
        _context_fields(self)
        _content_id(self.assessment_binding_id, "assessment_binding_id", "AEB")
        _digest(self.assessment_binding_sha256, "assessment_binding_sha256")
        _ref(self.finding_ref, "finding_ref", "findingref")
        _digest(self.finding_sha256, "finding_sha256")
        _digest(self.evidence_sha256, "evidence_sha256")
        _digest(self.provenance_sha256, "provenance_sha256")
        _time(self.occurred_at, "occurred_at")
        if self.sanitized is not True:
            raise DefenderReplayError("finding fixture must be sanitized")
        identity, digest = _identity("DFF", self.KIND, self.body())
        object.__setattr__(self, "fixture_id", identity)
        object.__setattr__(self, "fixture_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_binding_id": self.assessment_binding_id,
            "assessment_binding_sha256": self.assessment_binding_sha256,
            "context_ref": self.context_ref,
            "corpus_sha256": self.corpus_sha256,
            "engagement_ref": self.engagement_ref,
            "evidence_sha256": self.evidence_sha256,
            "finding_ref": self.finding_ref,
            "finding_sha256": self.finding_sha256,
            "occurred_at": self.occurred_at,
            "provenance_sha256": self.provenance_sha256,
            "sanitized": self.sanitized,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


def _context_fields(value: Any) -> None:
    _ref(value.tenant_ref, "tenant_ref", "tenantref")
    _ref(value.engagement_ref, "engagement_ref", "engagementref")
    _ref(value.context_ref, "context_ref", "contextref")
    _digest(value.scope_sha256, "scope_sha256")
    _digest(value.corpus_sha256, "corpus_sha256")


@dataclass(frozen=True, slots=True)
class SourceAvailability:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    corpus_sha256: str
    telemetry_domain: str
    window_opens_at: str
    window_closes_at: str
    state: AvailabilityState | str
    evidence_sha256: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        _context_fields(self)
        if self.telemetry_domain not in TelemetryFixture.DOMAINS:
            raise DefenderReplayError("telemetry_domain is invalid")
        _time(self.window_opens_at, "window_opens_at")
        _time(self.window_closes_at, "window_closes_at")
        if _instant(self.window_closes_at) <= _instant(self.window_opens_at):
            raise DefenderReplayError("availability window is invalid")
        try:
            object.__setattr__(self, "state", AvailabilityState(self.state))
        except (TypeError, ValueError) as exc:
            raise DefenderReplayError("availability state is invalid") from exc
        _digest(self.evidence_sha256, "evidence_sha256")
        _digest(self.provenance_sha256, "provenance_sha256")

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["state"] = self.state.value
        return result


@dataclass(frozen=True, slots=True)
class DetectionExpectation:
    control_ref: str
    finding_fixture_id: str
    finding_fixture_sha256: str
    operation_code: str
    telemetry_domains: tuple[str, ...]
    maximum_latency_seconds: int

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        _content_id(self.finding_fixture_id, "finding_fixture_id", "DFF")
        _digest(self.finding_fixture_sha256, "finding_fixture_sha256")
        _code(self.operation_code, "operation_code")
        domains = _codes(self.telemetry_domains, "telemetry_domains")
        if any(domain not in TelemetryFixture.DOMAINS for domain in domains):
            raise DefenderReplayError("telemetry domain is unsupported")
        object.__setattr__(self, "telemetry_domains", domains)
        _bounded_int(self.maximum_latency_seconds, "maximum_latency_seconds", 0, MAX_SECONDS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_ref": self.control_ref,
            "finding_fixture_id": self.finding_fixture_id,
            "finding_fixture_sha256": self.finding_fixture_sha256,
            "maximum_latency_seconds": self.maximum_latency_seconds,
            "operation_code": self.operation_code,
            "telemetry_domains": list(self.telemetry_domains),
        }


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    context: ReplayContext
    assessment_evidence: AssessmentEvidenceBinding
    detection_correlation: DetectionCorrelationBinding
    evaluation: EvaluationContractBinding
    telemetry_fixtures: tuple[TelemetryFixture, ...]
    finding_fixtures: tuple[FindingFixture, ...]
    source_availability: tuple[SourceAvailability, ...]
    expectations: tuple[DetectionExpectation, ...]
    replayed_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-request.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.context, ReplayContext):
            raise DefenderReplayError("context is invalid")
        if not isinstance(self.assessment_evidence, AssessmentEvidenceBinding):
            raise DefenderReplayError("assessment_evidence is invalid")
        if not isinstance(self.detection_correlation, DetectionCorrelationBinding):
            raise DefenderReplayError("detection_correlation is invalid")
        if not isinstance(self.evaluation, EvaluationContractBinding):
            raise DefenderReplayError("evaluation is invalid")
        telemetry = _objects(self.telemetry_fixtures, TelemetryFixture, "telemetry fixtures")
        findings = _objects(self.finding_fixtures, FindingFixture, "finding fixtures")
        availability = _objects(self.source_availability, SourceAvailability, "source availability")
        expectations = _objects(self.expectations, DetectionExpectation, "expectations")
        if not findings or not availability or not expectations:
            raise DefenderReplayError("replay requires findings, availability, and expectations")
        _unique_content(telemetry, "telemetry fixtures")
        _unique_content(findings, "finding fixtures")
        if len({item.control_ref for item in expectations}) != len(expectations):
            raise DefenderReplayError("expectation control references must be unique")
        availability_keys = [
            (item.telemetry_domain, item.window_opens_at, item.window_closes_at)
            for item in availability
        ]
        if len(set(availability_keys)) != len(availability_keys):
            raise DefenderReplayError("source availability entries must be unique")
        object.__setattr__(
            self, "telemetry_fixtures", tuple(sorted(telemetry, key=lambda x: x.fixture_id))
        )
        object.__setattr__(
            self, "finding_fixtures", tuple(sorted(findings, key=lambda x: x.fixture_id))
        )
        object.__setattr__(
            self,
            "source_availability",
            tuple(sorted(availability, key=lambda x: (x.telemetry_domain, x.window_opens_at))),
        )
        object.__setattr__(
            self, "expectations", tuple(sorted(expectations, key=lambda x: x.control_ref))
        )
        _time(self.replayed_at, "replayed_at")
        self._validate_bindings()
        cutoff = _instant(self.replayed_at)
        if any(_instant(item.occurred_at) > cutoff for item in self.finding_fixtures):
            raise DefenderReplayError("finding occurs after replay cutoff")
        if any(_instant(item.observed_at) > cutoff for item in self.telemetry_fixtures):
            raise DefenderReplayError("telemetry observation follows replay cutoff")
        findings_by_id = {item.fixture_id: item for item in self.finding_fixtures}
        if any(
            _instant(findings_by_id[item.finding_fixture_id].occurred_at)
            + timedelta(seconds=item.maximum_latency_seconds)
            > cutoff
            for item in self.expectations
        ):
            raise DefenderReplayError("replay cutoff precedes detection objective")
        identity, digest = _identity("DRQ", self.KIND, self.body())
        object.__setattr__(self, "request_id", identity)
        object.__setattr__(self, "request_sha256", digest)

    def _validate_bindings(self) -> None:
        expected = (
            self.context.tenant_ref,
            self.context.engagement_ref,
            self.context.context_ref,
            self.context.scope_sha256,
        )
        assessment_actual = (
            self.assessment_evidence.tenant_ref,
            self.assessment_evidence.engagement_ref,
            self.assessment_evidence.context_ref,
            self.assessment_evidence.scope_sha256,
        )
        if assessment_actual != expected:
            raise DefenderReplayError("assessment evidence crosses the bound context")
        correlation_actual = (
            self.detection_correlation.tenant_ref,
            self.detection_correlation.engagement_ref,
            self.detection_correlation.context_ref,
            self.detection_correlation.scope_sha256,
        )
        if correlation_actual != expected:
            raise DefenderReplayError("detection correlation crosses the bound context")
        for item in (*self.telemetry_fixtures, *self.finding_fixtures, *self.source_availability):
            actual = (item.tenant_ref, item.engagement_ref, item.context_ref, item.scope_sha256)
            if actual != expected or item.corpus_sha256 != self.context.corpus_sha256:
                raise DefenderReplayError("replay input crosses the bound context")
        for finding in self.finding_fixtures:
            if (
                finding.assessment_binding_id != self.assessment_evidence.binding_id
                or finding.assessment_binding_sha256 != self.assessment_evidence.binding_sha256
            ):
                raise DefenderReplayError("finding fixture assessment provenance is invalid")
        findings = {item.fixture_id: item.fixture_sha256 for item in self.finding_fixtures}
        for telemetry_item in self.telemetry_fixtures:
            if (
                findings.get(telemetry_item.finding_fixture_id)
                != telemetry_item.finding_fixture_sha256
            ):
                raise DefenderReplayError("telemetry finding content address is invalid")
        for expectation in self.expectations:
            if findings.get(expectation.finding_fixture_id) != expectation.finding_fixture_sha256:
                raise DefenderReplayError("expectation finding content address is invalid")

    def body(self) -> dict[str, Any]:
        return {
            "assessment_evidence": self.assessment_evidence.to_dict(),
            "context": self.context.to_dict(),
            "detection_correlation": self.detection_correlation.to_dict(),
            "evaluation": self.evaluation.to_dict(),
            "expectations": [item.to_dict() for item in self.expectations],
            "finding_fixtures": [item.to_dict() for item in self.finding_fixtures],
            "replayed_at": self.replayed_at,
            "source_availability": [item.to_dict() for item in self.source_availability],
            "telemetry_fixtures": [item.to_dict() for item in self.telemetry_fixtures],
        }

    def input_manifest_sha256(self) -> str:
        return canonical_sha256(self.body())


def _unique_content(values: Sequence[Any], label: str) -> None:
    ids = [item.fixture_id for item in values]
    digests = [item.fixture_sha256 for item in values]
    if len(set(ids)) != len(ids) or len(set(digests)) != len(digests):
        raise DefenderReplayError(f"{label} must have unique identities and digests")


@dataclass(frozen=True, slots=True)
class ReplayObservation:
    control_ref: str
    finding_fixture_id: str
    finding_fixture_sha256: str
    state: ObservationState | str
    matched_telemetry_fixture_id: str | None
    matched_telemetry_fixture_sha256: str | None
    latency_seconds: int | None
    maximum_latency_seconds: int
    available_domains: tuple[str, ...]
    absent_domains: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        _content_id(self.finding_fixture_id, "finding_fixture_id", "DFF")
        _digest(self.finding_fixture_sha256, "finding_fixture_sha256")
        try:
            object.__setattr__(self, "state", ObservationState(self.state))
        except (TypeError, ValueError) as exc:
            raise DefenderReplayError("observation state is invalid") from exc
        available = tuple(self.available_domains)
        absent = tuple(self.absent_domains)
        if available != tuple(sorted(set(available))) or absent != tuple(sorted(set(absent))):
            raise DefenderReplayError("observation domains must be sorted and unique")
        if set(available) & set(absent):
            raise DefenderReplayError("observation domain states overlap")
        object.__setattr__(self, "available_domains", available)
        object.__setattr__(self, "absent_domains", absent)
        _bounded_int(self.maximum_latency_seconds, "maximum_latency_seconds", 0, MAX_SECONDS)
        _code(self.reason_code, "reason_code")
        detected = self.state in {
            ObservationState.DETECTED_WITHIN_OBJECTIVE,
            ObservationState.DETECTED_LATE,
        }
        if detected:
            _content_id(self.matched_telemetry_fixture_id, "matched telemetry fixture", "DTF")
            _digest(self.matched_telemetry_fixture_sha256, "matched telemetry fixture digest")
            _bounded_int(self.latency_seconds, "latency_seconds", 0, MAX_SECONDS)
        elif any(
            value is not None
            for value in (
                self.matched_telemetry_fixture_id,
                self.matched_telemetry_fixture_sha256,
                self.latency_seconds,
            )
        ):
            raise DefenderReplayError("unmatched observation contains telemetry evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "absent_domains": list(self.absent_domains),
            "available_domains": list(self.available_domains),
            "control_ref": self.control_ref,
            "finding_fixture_id": self.finding_fixture_id,
            "finding_fixture_sha256": self.finding_fixture_sha256,
            "latency_seconds": self.latency_seconds,
            "matched_telemetry_fixture_id": self.matched_telemetry_fixture_id,
            "matched_telemetry_fixture_sha256": self.matched_telemetry_fixture_sha256,
            "maximum_latency_seconds": self.maximum_latency_seconds,
            "reason_code": self.reason_code,
            "state": self.state.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ReplayObservation:
        fields = set(cls.__dataclass_fields__)
        item = dict(_exact(raw, fields, "replay observation"))
        item["available_domains"] = tuple(item["available_domains"])
        item["absent_domains"] = tuple(item["absent_domains"])
        return cls(**item)


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    total_expectations: int
    evaluable_expectations: int
    detected_count: int
    within_objective_count: int
    late_count: int
    failed_detection_count: int
    absent_source_data_count: int
    detection_coverage_basis_points: int | None
    objective_coverage_basis_points: int | None
    mean_detection_latency_seconds: int | None
    maximum_detection_latency_seconds: int | None

    def __post_init__(self) -> None:
        for name in (
            "total_expectations",
            "evaluable_expectations",
            "detected_count",
            "within_objective_count",
            "late_count",
            "failed_detection_count",
            "absent_source_data_count",
        ):
            _bounded_int(getattr(self, name), name, 0, MAX_ITEMS)
        for name in ("detection_coverage_basis_points", "objective_coverage_basis_points"):
            value = getattr(self, name)
            if value is not None:
                _bounded_int(value, name, 0, 10_000)
        for name in ("mean_detection_latency_seconds", "maximum_detection_latency_seconds"):
            value = getattr(self, name)
            if value is not None:
                _bounded_int(value, name, 0, MAX_SECONDS)
        if self.evaluable_expectations + self.absent_source_data_count != self.total_expectations:
            raise DefenderReplayError("coverage counts are inconsistent")
        if self.detected_count + self.failed_detection_count != self.evaluable_expectations:
            raise DefenderReplayError("evaluable coverage counts are inconsistent")
        if self.within_objective_count + self.late_count != self.detected_count:
            raise DefenderReplayError("latency coverage counts are inconsistent")
        if self.evaluable_expectations == 0:
            if (
                self.detection_coverage_basis_points is not None
                or self.objective_coverage_basis_points is not None
            ):
                raise DefenderReplayError("coverage must be unknown without evaluable data")
        elif (
            self.detection_coverage_basis_points is None
            or self.objective_coverage_basis_points is None
        ):
            raise DefenderReplayError("coverage is required for evaluable data")
        if self.detected_count == 0 and (
            self.mean_detection_latency_seconds is not None
            or self.maximum_detection_latency_seconds is not None
        ):
            raise DefenderReplayError("latency must be unknown without detections")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageSummary:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "coverage summary"))


@dataclass(frozen=True, slots=True)
class DefenderReplayReceipt:
    tenant_ref: str
    engagement_ref: str
    context_ref: str
    scope_sha256: str
    corpus_sha256: str
    provenance_policy_sha256: str
    request_id: str
    request_sha256: str
    input_manifest_sha256: str
    evaluation_program_id: str
    evaluation_program_sha256: str
    evaluation_run_plan_id: str
    evaluation_run_plan_sha256: str
    assessment_binding_id: str
    assessment_binding_sha256: str
    correlation_binding_id: str
    correlation_binding_sha256: str
    correlation_bundle_id: str
    correlation_bundle_sha256: str
    producer_ref: str
    replayed_at: str
    observations: tuple[ReplayObservation, ...]
    summary: CoverageSummary
    review_status: str = "pending_independent_review"
    promotion_status: str = "blocked_pending_independent_review"
    external_effectiveness_claim: str = "not_asserted"
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-receipt.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _ref(self.context_ref, "context_ref", "contextref")
        for name in (
            "scope_sha256",
            "corpus_sha256",
            "provenance_policy_sha256",
            "request_sha256",
            "input_manifest_sha256",
            "evaluation_program_sha256",
            "evaluation_run_plan_sha256",
            "assessment_binding_sha256",
            "correlation_binding_sha256",
            "correlation_bundle_sha256",
        ):
            _digest(getattr(self, name), name)
        _content_id(self.request_id, "request_id", "DRQ")
        _content_id(self.evaluation_program_id, "evaluation_program_id", "EVP")
        _content_id(self.evaluation_run_plan_id, "evaluation_run_plan_id", "ERP")
        _content_id(self.assessment_binding_id, "assessment_binding_id", "AEB")
        _content_id(self.correlation_binding_id, "correlation_binding_id", "DRC")
        _content_id(self.correlation_bundle_id, "correlation_bundle_id", "DCB")
        _ref(self.producer_ref, "producer_ref", "principalref")
        _time(self.replayed_at, "replayed_at")
        observations = _objects(self.observations, ReplayObservation, "observations")
        if (
            not observations
            or tuple(sorted(observations, key=lambda x: x.control_ref)) != observations
        ):
            raise DefenderReplayError("observations must be nonempty and sorted")
        if len({item.control_ref for item in observations}) != len(observations):
            raise DefenderReplayError("observation control references must be unique")
        if not isinstance(self.summary, CoverageSummary):
            raise DefenderReplayError("summary is invalid")
        if self.review_status != "pending_independent_review":
            raise DefenderReplayError("receipt must await independent review")
        if self.promotion_status != "blocked_pending_independent_review":
            raise DefenderReplayError("receipt cannot self-authorize promotion")
        if self.external_effectiveness_claim != "not_asserted":
            raise DefenderReplayError("external effectiveness claims are forbidden")
        identity, digest = _identity("DRR", self.KIND, self.body())
        object.__setattr__(self, "receipt_id", identity)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_binding_id": self.assessment_binding_id,
            "assessment_binding_sha256": self.assessment_binding_sha256,
            "context_ref": self.context_ref,
            "correlation_binding_id": self.correlation_binding_id,
            "correlation_binding_sha256": self.correlation_binding_sha256,
            "correlation_bundle_id": self.correlation_bundle_id,
            "correlation_bundle_sha256": self.correlation_bundle_sha256,
            "corpus_sha256": self.corpus_sha256,
            "engagement_ref": self.engagement_ref,
            "evaluation_program_id": self.evaluation_program_id,
            "evaluation_program_sha256": self.evaluation_program_sha256,
            "evaluation_run_plan_id": self.evaluation_run_plan_id,
            "evaluation_run_plan_sha256": self.evaluation_run_plan_sha256,
            "external_effectiveness_claim": self.external_effectiveness_claim,
            "input_manifest_sha256": self.input_manifest_sha256,
            "observations": [item.to_dict() for item in self.observations],
            "producer_ref": self.producer_ref,
            "promotion_status": self.promotion_status,
            "provenance_policy_sha256": self.provenance_policy_sha256,
            "replayed_at": self.replayed_at,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "review_status": self.review_status,
            "scope_sha256": self.scope_sha256,
            "summary": self.summary.to_dict(),
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "qualification_effect": QUALIFICATION_EFFECT,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "required_reviewer_roles": list(REQUIRED_REVIEWER_ROLES),
            "runtime_status": RUNTIME_STATUS,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DefenderReplayReceipt:
        metadata = {
            "effects",
            "kind",
            "qualification_effect",
            "receipt_id",
            "receipt_sha256",
            "required_reviewer_roles",
            "runtime_status",
            "schema_version",
        }
        body_fields = set(cls.__dataclass_fields__) - {"KIND", "receipt_id", "receipt_sha256"}
        item = dict(_exact(raw, metadata | body_fields, "defender replay receipt"))
        expected_id = item.pop("receipt_id")
        expected_sha = item.pop("receipt_sha256")
        if (
            item.pop("kind") != cls.KIND
            or item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("effects") != dict(NO_EFFECTS)
            or item.pop("qualification_effect") != QUALIFICATION_EFFECT
            or item.pop("runtime_status") != RUNTIME_STATUS
            or tuple(item.pop("required_reviewer_roles")) != REQUIRED_REVIEWER_ROLES
        ):
            raise DefenderReplayError("receipt metadata is invalid")
        item["observations"] = tuple(
            ReplayObservation.from_dict(value) for value in item["observations"]
        )
        item["summary"] = CoverageSummary.from_dict(item["summary"])
        candidate = cls(**item)
        if candidate.receipt_id != expected_id or candidate.receipt_sha256 != expected_sha:
            raise DefenderReplayError("receipt content address does not match")
        return candidate


@dataclass(frozen=True, slots=True)
class IndependentReplayReview:
    receipt_id: str
    receipt_sha256: str
    reviewer_ref: str
    reviewer_role: str
    producer_ref: str
    decision: ReviewDecision | str
    reviewed_at: str
    evidence_sha256: str
    rationale_code: str
    review_id: str = field(init=False)
    review_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.defender-replay-independent-review.v1"

    def __post_init__(self) -> None:
        _content_id(self.receipt_id, "receipt_id", "DRR")
        _digest(self.receipt_sha256, "receipt_sha256")
        _ref(self.reviewer_ref, "reviewer_ref", "principalref")
        _ref(self.producer_ref, "producer_ref", "principalref")
        if self.reviewer_role not in REQUIRED_REVIEWER_ROLES:
            raise DefenderReplayError("reviewer role is not independent")
        if self.reviewer_ref == self.producer_ref:
            raise DefenderReplayError("producer cannot independently review replay")
        try:
            object.__setattr__(self, "decision", ReviewDecision(self.decision))
        except (TypeError, ValueError) as exc:
            raise DefenderReplayError("review decision is invalid") from exc
        _time(self.reviewed_at, "reviewed_at")
        _digest(self.evidence_sha256, "evidence_sha256")
        _code(self.rationale_code, "rationale_code")
        identity, digest = _identity("DRI", self.KIND, self.body())
        object.__setattr__(self, "review_id", identity)
        object.__setattr__(self, "review_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "evidence_sha256": self.evidence_sha256,
            "producer_ref": self.producer_ref,
            "rationale_code": self.rationale_code,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_ref": self.reviewer_ref,
            "reviewer_role": self.reviewer_role,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "review_id": self.review_id,
            "review_sha256": self.review_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentReplayReview:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {"kind", "schema_version"}
        item = dict(_exact(raw, fields, "independent replay review"))
        expected_id = item.pop("review_id")
        expected_sha = item.pop("review_sha256")
        if item.pop("kind") != cls.KIND or item.pop("schema_version") != SCHEMA_VERSION:
            raise DefenderReplayError("review metadata is invalid")
        candidate = cls(**item)
        if candidate.review_id != expected_id or candidate.review_sha256 != expected_sha:
            raise DefenderReplayError("review content address does not match")
        return candidate


@dataclass(frozen=True, slots=True)
class PromotionAssessment:
    receipt_id: str
    receipt_sha256: str
    review_ids: tuple[str, ...]
    review_sha256s: tuple[str, ...]
    eligible: bool
    status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _content_id(self.receipt_id, "receipt_id", "DRR")
        _digest(self.receipt_sha256, "receipt_sha256")
        if self.status not in {"eligible_for_promotion", "blocked"}:
            raise DefenderReplayError("promotion status is invalid")
        if self.eligible != (self.status == "eligible_for_promotion"):
            raise DefenderReplayError("promotion status is inconsistent")
        if len(self.review_ids) != len(self.review_sha256s):
            raise DefenderReplayError("promotion review evidence is inconsistent")
        for identity in self.review_ids:
            _content_id(identity, "review_id", "DRI")
        for digest in self.review_sha256s:
            _digest(digest, "review_sha256")
        reasons = tuple(self.reason_codes)
        if not reasons or reasons != tuple(sorted(set(reasons))):
            raise DefenderReplayError("promotion reasons must be sorted and unique")
        for reason in reasons:
            _code(reason, "promotion reason")
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reason_codes": list(self.reason_codes),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "review_ids": list(self.review_ids),
            "review_sha256s": list(self.review_sha256s),
            "status": self.status,
        }


def _availability_for(
    expectation: DetectionExpectation, request: ReplayRequest, through_at: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    finding = next(
        item
        for item in request.finding_fixtures
        if item.fixture_id == expectation.finding_fixture_id
    )
    available: list[str] = []
    absent: list[str] = []
    start = _instant(finding.occurred_at)
    end = _instant(through_at)
    for domain in expectation.telemetry_domains:
        windows = sorted(
            (
                item
                for item in request.source_availability
                if item.telemetry_domain == domain
                and _instant(item.window_closes_at) > start
                and _instant(item.window_opens_at) <= end
            ),
            key=lambda item: item.window_opens_at,
        )
        if not windows or _instant(windows[0].window_opens_at) > start:
            raise DefenderReplayError("expectation lacks unambiguous source availability")
        cursor = start
        covered = True
        for window in windows:
            opens = _instant(window.window_opens_at)
            closes = _instant(window.window_closes_at)
            if opens > cursor:
                covered = False
            elif opens < cursor and cursor != start:
                raise DefenderReplayError("expectation has overlapping source availability")
            if window.state is AvailabilityState.ABSENT:
                covered = False
            cursor = max(cursor, closes)
        if cursor <= end:
            covered = False
        (available if covered else absent).append(domain)
    return tuple(available), tuple(absent)


def _observe(expectation: DetectionExpectation, request: ReplayRequest) -> ReplayObservation:
    finding = next(
        item
        for item in request.finding_fixtures
        if item.fixture_id == expectation.finding_fixture_id
    )
    matches = [
        item
        for item in request.telemetry_fixtures
        if item.finding_fixture_id == finding.fixture_id
        and item.finding_fixture_sha256 == finding.fixture_sha256
        and item.telemetry_domain in expectation.telemetry_domains
        and item.operation_code == expectation.operation_code
        and _instant(item.occurred_at) >= _instant(finding.occurred_at)
    ]
    first = min(matches, key=lambda item: (item.observed_at, item.fixture_id)) if matches else None
    available, absent = _availability_for(
        expectation, request, first.observed_at if first else request.replayed_at
    )
    if absent:
        return ReplayObservation(
            control_ref=expectation.control_ref,
            finding_fixture_id=finding.fixture_id,
            finding_fixture_sha256=finding.fixture_sha256,
            state=ObservationState.ABSENT_SOURCE_DATA,
            matched_telemetry_fixture_id=None,
            matched_telemetry_fixture_sha256=None,
            latency_seconds=None,
            maximum_latency_seconds=expectation.maximum_latency_seconds,
            available_domains=available,
            absent_domains=absent,
            reason_code="source_data_absent",
        )
    if not matches:
        return ReplayObservation(
            control_ref=expectation.control_ref,
            finding_fixture_id=finding.fixture_id,
            finding_fixture_sha256=finding.fixture_sha256,
            state=ObservationState.FAILED_DETECTION,
            matched_telemetry_fixture_id=None,
            matched_telemetry_fixture_sha256=None,
            latency_seconds=None,
            maximum_latency_seconds=expectation.maximum_latency_seconds,
            available_domains=available,
            absent_domains=(),
            reason_code="expected_signal_not_observed",
        )
    assert first is not None
    latency = int((_instant(first.observed_at) - _instant(finding.occurred_at)).total_seconds())
    _bounded_int(latency, "latency_seconds", 0, MAX_SECONDS)
    within = latency <= expectation.maximum_latency_seconds
    return ReplayObservation(
        control_ref=expectation.control_ref,
        finding_fixture_id=finding.fixture_id,
        finding_fixture_sha256=finding.fixture_sha256,
        state=(
            ObservationState.DETECTED_WITHIN_OBJECTIVE if within else ObservationState.DETECTED_LATE
        ),
        matched_telemetry_fixture_id=first.fixture_id,
        matched_telemetry_fixture_sha256=first.fixture_sha256,
        latency_seconds=latency,
        maximum_latency_seconds=expectation.maximum_latency_seconds,
        available_domains=available,
        absent_domains=(),
        reason_code="latency_objective_met" if within else "latency_objective_missed",
    )


def _basis_points(numerator: int, denominator: int) -> int:
    return (numerator * 10_000 + denominator // 2) // denominator


def _summary(observations: Sequence[ReplayObservation]) -> CoverageSummary:
    absent = sum(item.state is ObservationState.ABSENT_SOURCE_DATA for item in observations)
    failed = sum(item.state is ObservationState.FAILED_DETECTION for item in observations)
    within = sum(item.state is ObservationState.DETECTED_WITHIN_OBJECTIVE for item in observations)
    late = sum(item.state is ObservationState.DETECTED_LATE for item in observations)
    detected = within + late
    evaluable = detected + failed
    latencies = [item.latency_seconds for item in observations if item.latency_seconds is not None]
    return CoverageSummary(
        total_expectations=len(observations),
        evaluable_expectations=evaluable,
        detected_count=detected,
        within_objective_count=within,
        late_count=late,
        failed_detection_count=failed,
        absent_source_data_count=absent,
        detection_coverage_basis_points=(_basis_points(detected, evaluable) if evaluable else None),
        objective_coverage_basis_points=(_basis_points(within, evaluable) if evaluable else None),
        mean_detection_latency_seconds=(sum(latencies) // len(latencies) if latencies else None),
        maximum_detection_latency_seconds=(max(latencies) if latencies else None),
    )


def run_defender_replay(request: ReplayRequest) -> DefenderReplayReceipt:
    """Replay supplied fixtures offline and return a nonqualifying receipt."""

    if not isinstance(request, ReplayRequest):
        raise DefenderReplayError("request is invalid")
    observations = tuple(_observe(item, request) for item in request.expectations)
    return DefenderReplayReceipt(
        tenant_ref=request.context.tenant_ref,
        engagement_ref=request.context.engagement_ref,
        context_ref=request.context.context_ref,
        scope_sha256=request.context.scope_sha256,
        corpus_sha256=request.context.corpus_sha256,
        provenance_policy_sha256=request.context.provenance_policy_sha256,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        input_manifest_sha256=request.input_manifest_sha256(),
        evaluation_program_id=request.evaluation.program_id,
        evaluation_program_sha256=request.evaluation.program_sha256,
        evaluation_run_plan_id=request.evaluation.run_plan_id,
        evaluation_run_plan_sha256=request.evaluation.run_plan_sha256,
        assessment_binding_id=request.assessment_evidence.binding_id,
        assessment_binding_sha256=request.assessment_evidence.binding_sha256,
        correlation_binding_id=request.detection_correlation.binding_id,
        correlation_binding_sha256=request.detection_correlation.binding_sha256,
        correlation_bundle_id=request.detection_correlation.correlation_bundle_id,
        correlation_bundle_sha256=request.detection_correlation.correlation_bundle_sha256,
        producer_ref=request.evaluation.producer_ref,
        replayed_at=request.replayed_at,
        observations=observations,
        summary=_summary(observations),
    )


def assess_replay_promotion(
    receipt: DefenderReplayReceipt,
    reviews: Sequence[IndependentReplayReview],
) -> PromotionAssessment:
    """Assess promotion eligibility without mutating or promoting any artifact."""

    if not isinstance(receipt, DefenderReplayReceipt):
        raise DefenderReplayError("receipt is invalid")
    items = _objects(reviews, IndependentReplayReview, "reviews")
    if len({item.review_id for item in items}) != len(items):
        raise DefenderReplayError("review identities must be unique")
    if len({item.reviewer_ref for item in items}) != len(items):
        raise DefenderReplayError("reviewers must be independent identities")
    for item in items:
        if (
            item.receipt_id != receipt.receipt_id
            or item.receipt_sha256 != receipt.receipt_sha256
            or item.producer_ref != receipt.producer_ref
        ):
            raise DefenderReplayError("review does not bind the replay receipt")
    accepted_roles = {
        item.reviewer_role for item in items if item.decision is ReviewDecision.ACCEPTED
    }
    rejected = any(item.decision is ReviewDecision.REJECTED for item in items)
    missing = sorted(set(REQUIRED_REVIEWER_ROLES) - accepted_roles)
    reasons: list[str] = []
    if rejected:
        reasons.append("independent_review_rejected")
    if missing:
        reasons.extend(f"missing_{role}" for role in missing)
    eligible = not reasons
    if eligible:
        reasons.append("independent_reviews_accepted")
    ordered = tuple(sorted(items, key=lambda item: item.review_id))
    return PromotionAssessment(
        receipt_id=receipt.receipt_id,
        receipt_sha256=receipt.receipt_sha256,
        review_ids=tuple(item.review_id for item in ordered),
        review_sha256s=tuple(item.review_sha256 for item in ordered),
        eligible=eligible,
        status="eligible_for_promotion" if eligible else "blocked",
        reason_codes=tuple(sorted(reasons)),
    )


def parse_defender_replay_receipt(raw: str | Mapping[str, Any]) -> DefenderReplayReceipt:
    """Parse and verify an exact defender replay receipt."""

    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DefenderReplayError("receipt is not valid JSON") from exc
    else:
        value = raw
    return DefenderReplayReceipt.from_dict(value)


def verify_defender_replay_receipt(receipt: DefenderReplayReceipt) -> None:
    """Verify receipt metadata, invariants, and content address."""

    parsed = parse_defender_replay_receipt(receipt.to_dict())
    if parsed != receipt:
        raise DefenderReplayError("receipt verification failed")
