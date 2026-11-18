"""Deterministic repository-only detection correlation and review contracts.

The module correlates caller-supplied references. It has no SIEM query,
network transport, provider client, source write, target action, or
qualification effect.
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
MAX_ITEMS = 512
MAX_SECONDS = 31_536_000
NO_BUILTIN_NETWORK = True
NO_BUILTIN_SIEM_QUERY = True
QUALIFICATION_EFFECT = "none"
RUNTIME_STATUS = "repository_only_nonqualified"
NO_EFFECTS = MappingProxyType(
    {
        "correlation": "reference_only",
        "network": "none",
        "provider_calls": "none",
        "qualification": "none",
        "siem_query": "none",
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
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)


class DetectionCorrelationError(ValueError):
    """Raised when correlation input or derived output fails closed."""


class ValidationState(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class ControlKind(StrEnum):
    EXPECTED_DETECTION = "expected_detection"
    NEGATIVE_CONTROL = "negative_control"
    FALSE_POSITIVE_CONTROL = "false_positive_control"


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
        raise DetectionCorrelationError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise DetectionCorrelationError("secret-like material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DetectionCorrelationError(f"{label} fields are invalid")
    return raw


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DetectionCorrelationError(f"{label} must be a sha256 digest")
    return value


def _ref(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None or _SECRET_RE.search(value):
        raise DetectionCorrelationError(f"{label} must be a safe opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise DetectionCorrelationError(f"{label} must use the {namespace} namespace")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise DetectionCorrelationError(f"{label} must be a canonical code")
    return value


def _content_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise DetectionCorrelationError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DetectionCorrelationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DetectionCorrelationError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise DetectionCorrelationError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DetectionCorrelationError(f"{label} is outside the supported range")
    return value


def _codes(values: Sequence[str], label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise DetectionCorrelationError(f"{label} must be a sequence")
    result = tuple(values)
    if (not result and not allow_empty) or len(result) > MAX_ITEMS:
        raise DetectionCorrelationError(f"{label} is outside the supported range")
    for value in result:
        _code(value, label)
    if result != tuple(sorted(set(result))):
        raise DetectionCorrelationError(f"{label} must be sorted and unique")
    return result


def _objects(values: Sequence[Any], item_type: type[Any], label: str) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)):
        raise DetectionCorrelationError(f"{label} must be a sequence")
    result = tuple(values)
    if len(result) > MAX_ITEMS or any(not isinstance(item, item_type) for item in result):
        raise DetectionCorrelationError(f"{label} is invalid")
    return result


def _window(opens_at: str, closes_at: str, maximum_seconds: int) -> None:
    _time(opens_at, "opens_at")
    _time(closes_at, "closes_at")
    seconds = int((_instant(closes_at) - _instant(opens_at)).total_seconds())
    if not 1 <= seconds <= maximum_seconds:
        raise DetectionCorrelationError("control window is outside the strict budget")


@dataclass(frozen=True, slots=True)
class CorrelationBudget:
    maximum_expected_detections: int
    maximum_observed_signals: int
    maximum_negative_controls: int
    maximum_false_positive_controls: int
    maximum_control_results: int
    maximum_derived_findings: int
    maximum_window_seconds: int
    maximum_signal_age_seconds: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            maximum = MAX_SECONDS if name.endswith("_seconds") else MAX_ITEMS
            _bounded_int(getattr(self, name), name, 1, maximum)
        total = (
            self.maximum_expected_detections
            + self.maximum_negative_controls
            + self.maximum_false_positive_controls
        )
        if self.maximum_control_results < total:
            raise DetectionCorrelationError("control result budget must cover configured controls")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> CorrelationBudget:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "correlation budget"))


@dataclass(frozen=True, slots=True)
class ExecutionEvidenceReference:
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    execution_result_id: str
    execution_result_sha256: str
    action_sha256: str
    evidence_manifest_sha256: str
    custody_policy_sha256: str
    artifact_ref: str
    artifact_sha256: str
    custody_sha256: str
    started_at: str
    completed_at: str
    custody_status: str = "durable_verified"
    reference_id: str = field(init=False)
    reference_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.execution-evidence-reference.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        for name in (
            "scope_sha256",
            "execution_result_sha256",
            "action_sha256",
            "evidence_manifest_sha256",
            "custody_policy_sha256",
            "artifact_sha256",
            "custody_sha256",
        ):
            _digest(getattr(self, name), name)
        _content_id(self.execution_result_id, "execution_result_id", "ERE")
        _ref(self.artifact_ref, "artifact_ref", "artifactref")
        _time(self.started_at, "started_at")
        _time(self.completed_at, "completed_at")
        if _instant(self.completed_at) < _instant(self.started_at):
            raise DetectionCorrelationError("execution completion precedes start")
        if self.custody_status != "durable_verified":
            raise DetectionCorrelationError("execution custody must be durable_verified")
        identity, digest = _identity("EER", self.KIND, self.body())
        object.__setattr__(self, "reference_id", identity)
        object.__setattr__(self, "reference_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "completed_at": self.completed_at,
            "custody_policy_sha256": self.custody_policy_sha256,
            "custody_sha256": self.custody_sha256,
            "custody_status": self.custody_status,
            "engagement_ref": self.engagement_ref,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
            "execution_result_id": self.execution_result_id,
            "execution_result_sha256": self.execution_result_sha256,
            "scope_sha256": self.scope_sha256,
            "started_at": self.started_at,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "reference_id": self.reference_id,
            "reference_sha256": self.reference_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutionEvidenceReference:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {"kind", "schema_version"}
        item = dict(_exact(raw, fields, "execution evidence reference"))
        expected_id = item.pop("reference_id")
        expected_sha = item.pop("reference_sha256")
        if item.pop("kind") != cls.KIND or item.pop("schema_version") != SCHEMA_VERSION:
            raise DetectionCorrelationError("execution evidence metadata is invalid")
        candidate = cls(**item)
        if candidate.reference_id != expected_id or candidate.reference_sha256 != expected_sha:
            raise DetectionCorrelationError("execution evidence content address does not match")
        return candidate


@dataclass(frozen=True, slots=True)
class NormalizedSignalReference:
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    custody_policy_sha256: str
    source_binding_id: str
    source_binding_sha256: str
    normalized_event_id: str
    normalized_event_sha256: str
    source_event_ref: str
    raw_event_sha256: str
    artifact_ref: str
    custody_sha256: str
    telemetry_domain: str
    operation_code: str
    outcome: str
    severity: str
    occurred_at: str
    normalized_at: str
    custody_status: str = "durable_verified"
    redacted: bool = True
    signal_id: str = field(init=False)
    signal_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.normalized-signal-reference.v1"
    DOMAINS: ClassVar[frozenset[str]] = frozenset(
        {"application_api", "cloud", "endpoint", "identity", "network", "siem"}
    )
    OUTCOMES: ClassVar[frozenset[str]] = frozenset(
        {"allowed", "blocked", "failure", "success", "unknown"}
    )
    SEVERITIES: ClassVar[frozenset[str]] = frozenset(
        {"critical", "high", "informational", "low", "medium", "unknown"}
    )

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        for name in (
            "scope_sha256",
            "custody_policy_sha256",
            "source_binding_sha256",
            "normalized_event_sha256",
            "raw_event_sha256",
            "custody_sha256",
        ):
            _digest(getattr(self, name), name)
        _content_id(self.source_binding_id, "source_binding_id", "TSB")
        _content_id(self.normalized_event_id, "normalized_event_id", "NTE")
        _ref(self.source_event_ref, "source_event_ref", "eventref")
        _ref(self.artifact_ref, "artifact_ref", "artifactref")
        if self.telemetry_domain not in self.DOMAINS:
            raise DetectionCorrelationError("telemetry_domain is invalid")
        _code(self.operation_code, "operation_code")
        if self.outcome not in self.OUTCOMES or self.severity not in self.SEVERITIES:
            raise DetectionCorrelationError("normalized signal classification is invalid")
        _time(self.occurred_at, "occurred_at")
        _time(self.normalized_at, "normalized_at")
        if _instant(self.normalized_at) < _instant(self.occurred_at):
            raise DetectionCorrelationError("signal normalization precedes occurrence")
        if self.custody_status != "durable_verified":
            raise DetectionCorrelationError("signal custody must be durable_verified")
        if self.redacted is not True:
            raise DetectionCorrelationError("normalized signal reference must be redacted")
        identity, digest = _identity("NSR", self.KIND, self.body())
        object.__setattr__(self, "signal_id", identity)
        object.__setattr__(self, "signal_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "custody_policy_sha256": self.custody_policy_sha256,
            "custody_sha256": self.custody_sha256,
            "custody_status": self.custody_status,
            "engagement_ref": self.engagement_ref,
            "normalized_at": self.normalized_at,
            "normalized_event_id": self.normalized_event_id,
            "normalized_event_sha256": self.normalized_event_sha256,
            "occurred_at": self.occurred_at,
            "operation_code": self.operation_code,
            "outcome": self.outcome,
            "raw_event_sha256": self.raw_event_sha256,
            "redacted": self.redacted,
            "scope_sha256": self.scope_sha256,
            "severity": self.severity,
            "source_binding_id": self.source_binding_id,
            "source_binding_sha256": self.source_binding_sha256,
            "source_event_ref": self.source_event_ref,
            "telemetry_domain": self.telemetry_domain,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "signal_id": self.signal_id,
            "signal_sha256": self.signal_sha256,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> NormalizedSignalReference:
        fields = (set(cls.__dataclass_fields__) - {"DOMAINS", "KIND", "OUTCOMES", "SEVERITIES"}) | {
            "kind",
            "schema_version",
        }
        item = dict(_exact(raw, fields, "normalized signal reference"))
        expected_id = item.pop("signal_id")
        expected_sha = item.pop("signal_sha256")
        if item.pop("kind") != cls.KIND or item.pop("schema_version") != SCHEMA_VERSION:
            raise DetectionCorrelationError("normalized signal metadata is invalid")
        candidate = cls(**item)
        if candidate.signal_id != expected_id or candidate.signal_sha256 != expected_sha:
            raise DetectionCorrelationError("normalized signal content address does not match")
        return candidate


@dataclass(frozen=True, slots=True)
class ExpectedDetection:
    control_ref: str
    expectation_ref: str
    operation_code: str
    telemetry_domains: tuple[str, ...]
    accepted_outcomes: tuple[str, ...]
    opens_at: str
    closes_at: str
    minimum_signal_count: int = 1

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        _ref(self.expectation_ref, "expectation_ref", "expectationref")
        _code(self.operation_code, "operation_code")
        domains = _codes(self.telemetry_domains, "telemetry_domains")
        outcomes = _codes(self.accepted_outcomes, "accepted_outcomes")
        if not set(domains).issubset(NormalizedSignalReference.DOMAINS):
            raise DetectionCorrelationError("expected detection domain is invalid")
        if not set(outcomes).issubset(NormalizedSignalReference.OUTCOMES):
            raise DetectionCorrelationError("expected detection outcome is invalid")
        object.__setattr__(self, "telemetry_domains", domains)
        object.__setattr__(self, "accepted_outcomes", outcomes)
        _time(self.opens_at, "opens_at")
        _time(self.closes_at, "closes_at")
        _bounded_int(self.minimum_signal_count, "minimum_signal_count", 1, MAX_ITEMS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_outcomes": list(self.accepted_outcomes),
            "closes_at": self.closes_at,
            "control_ref": self.control_ref,
            "expectation_ref": self.expectation_ref,
            "minimum_signal_count": self.minimum_signal_count,
            "opens_at": self.opens_at,
            "operation_code": self.operation_code,
            "telemetry_domains": list(self.telemetry_domains),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpectedDetection:
        item = dict(_exact(raw, set(cls.__dataclass_fields__), "expected detection"))
        item["telemetry_domains"] = tuple(item["telemetry_domains"])
        item["accepted_outcomes"] = tuple(item["accepted_outcomes"])
        return cls(**item)


@dataclass(frozen=True, slots=True)
class NegativeControl:
    control_ref: str
    operation_code: str
    telemetry_domains: tuple[str, ...]
    opens_at: str
    closes_at: str
    maximum_signal_count: int = 0

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        _code(self.operation_code, "operation_code")
        domains = _codes(self.telemetry_domains, "telemetry_domains")
        if not set(domains).issubset(NormalizedSignalReference.DOMAINS):
            raise DetectionCorrelationError("negative control domain is invalid")
        object.__setattr__(self, "telemetry_domains", domains)
        _time(self.opens_at, "opens_at")
        _time(self.closes_at, "closes_at")
        _bounded_int(self.maximum_signal_count, "maximum_signal_count", 0, MAX_ITEMS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "closes_at": self.closes_at,
            "control_ref": self.control_ref,
            "maximum_signal_count": self.maximum_signal_count,
            "opens_at": self.opens_at,
            "operation_code": self.operation_code,
            "telemetry_domains": list(self.telemetry_domains),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> NegativeControl:
        item = dict(_exact(raw, set(cls.__dataclass_fields__), "negative control"))
        item["telemetry_domains"] = tuple(item["telemetry_domains"])
        return cls(**item)


@dataclass(frozen=True, slots=True)
class FalsePositiveControl:
    control_ref: str
    operation_code: str
    telemetry_domains: tuple[str, ...]
    opens_at: str
    closes_at: str
    maximum_signal_count: int
    baseline_evidence_sha256: str

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        _code(self.operation_code, "operation_code")
        domains = _codes(self.telemetry_domains, "telemetry_domains")
        if not set(domains).issubset(NormalizedSignalReference.DOMAINS):
            raise DetectionCorrelationError("false-positive control domain is invalid")
        object.__setattr__(self, "telemetry_domains", domains)
        _time(self.opens_at, "opens_at")
        _time(self.closes_at, "closes_at")
        _bounded_int(self.maximum_signal_count, "maximum_signal_count", 0, MAX_ITEMS)
        _digest(self.baseline_evidence_sha256, "baseline_evidence_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_evidence_sha256": self.baseline_evidence_sha256,
            "closes_at": self.closes_at,
            "control_ref": self.control_ref,
            "maximum_signal_count": self.maximum_signal_count,
            "opens_at": self.opens_at,
            "operation_code": self.operation_code,
            "telemetry_domains": list(self.telemetry_domains),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FalsePositiveControl:
        item = dict(_exact(raw, set(cls.__dataclass_fields__), "false-positive control"))
        item["telemetry_domains"] = tuple(item["telemetry_domains"])
        return cls(**item)


@dataclass(frozen=True, slots=True)
class CorrelationRequest:
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    custody_policy_sha256: str
    execution: ExecutionEvidenceReference
    signals: tuple[NormalizedSignalReference, ...]
    expected_detections: tuple[ExpectedDetection, ...]
    negative_controls: tuple[NegativeControl, ...]
    false_positive_controls: tuple[FalsePositiveControl, ...]
    prior_consumed_event_sha256s: tuple[str, ...]
    budget: CorrelationBudget
    evaluated_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.detection-correlation-request.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.custody_policy_sha256, "custody_policy_sha256")
        if not isinstance(self.execution, ExecutionEvidenceReference):
            raise DetectionCorrelationError("execution reference is invalid")
        if not isinstance(self.budget, CorrelationBudget):
            raise DetectionCorrelationError("correlation budget is invalid")
        _time(self.evaluated_at, "evaluated_at")
        signals = _objects(self.signals, NormalizedSignalReference, "signals")
        expected = _objects(self.expected_detections, ExpectedDetection, "expected_detections")
        negative = _objects(self.negative_controls, NegativeControl, "negative_controls")
        false_positive = _objects(
            self.false_positive_controls,
            FalsePositiveControl,
            "false_positive_controls",
        )
        prior = tuple(self.prior_consumed_event_sha256s)
        if len(prior) > MAX_ITEMS or prior != tuple(sorted(set(prior))):
            raise DetectionCorrelationError(
                "prior replay state must be bounded, sorted, and unique"
            )
        for digest in prior:
            _digest(digest, "prior_consumed_event_sha256")
        object.__setattr__(self, "signals", tuple(sorted(signals, key=lambda item: item.signal_id)))
        object.__setattr__(
            self,
            "expected_detections",
            tuple(sorted(expected, key=lambda item: item.control_ref)),
        )
        object.__setattr__(
            self,
            "negative_controls",
            tuple(sorted(negative, key=lambda item: item.control_ref)),
        )
        object.__setattr__(
            self,
            "false_positive_controls",
            tuple(sorted(false_positive, key=lambda item: item.control_ref)),
        )
        object.__setattr__(self, "prior_consumed_event_sha256s", prior)
        self._validate_context_freshness_replay_and_budgets()
        identity, digest = _identity("DCR", self.KIND, self.body())
        object.__setattr__(self, "request_id", identity)
        object.__setattr__(self, "request_sha256", digest)

    def _validate_context_freshness_replay_and_budgets(self) -> None:
        context = (
            self.tenant_ref,
            self.engagement_ref,
            self.scope_sha256,
            self.custody_policy_sha256,
        )
        execution_context = (
            self.execution.tenant_ref,
            self.execution.engagement_ref,
            self.execution.scope_sha256,
            self.execution.custody_policy_sha256,
        )
        if execution_context != context:
            raise DetectionCorrelationError("execution evidence crosses the bound context")
        if _instant(self.evaluated_at) < _instant(self.execution.completed_at):
            raise DetectionCorrelationError("evaluation precedes execution completion")
        if len(self.signals) > self.budget.maximum_observed_signals:
            raise DetectionCorrelationError("observed signal budget exceeded")
        if len(self.expected_detections) > self.budget.maximum_expected_detections:
            raise DetectionCorrelationError("expected detection budget exceeded")
        if len(self.negative_controls) > self.budget.maximum_negative_controls:
            raise DetectionCorrelationError("negative control budget exceeded")
        if len(self.false_positive_controls) > self.budget.maximum_false_positive_controls:
            raise DetectionCorrelationError("false-positive control budget exceeded")
        total = (
            len(self.expected_detections)
            + len(self.negative_controls)
            + len(self.false_positive_controls)
        )
        if not total or total > self.budget.maximum_control_results:
            raise DetectionCorrelationError("control result budget exceeded")
        control_refs = [
            item.control_ref
            for item in (
                *self.expected_detections,
                *self.negative_controls,
                *self.false_positive_controls,
            )
        ]
        if len(set(control_refs)) != len(control_refs):
            raise DetectionCorrelationError("control reference is duplicated")
        identities: set[str] = set()
        event_digests: set[str] = set()
        source_refs: set[str] = set()
        raw_digests: set[str] = set()
        replay_state = set(self.prior_consumed_event_sha256s)
        evaluated = _instant(self.evaluated_at)
        for signal in self.signals:
            signal_context = (
                signal.tenant_ref,
                signal.engagement_ref,
                signal.scope_sha256,
                signal.custody_policy_sha256,
            )
            if signal_context != context:
                raise DetectionCorrelationError("normalized signal crosses the bound context")
            age = int((evaluated - _instant(signal.normalized_at)).total_seconds())
            if age < 0 or age > self.budget.maximum_signal_age_seconds:
                raise DetectionCorrelationError("normalized signal is stale or future-dated")
            if signal.normalized_event_sha256 in replay_state:
                raise DetectionCorrelationError("normalized signal replay is forbidden")
            for value, seen, label in (
                (signal.normalized_event_id, identities, "normalized event identity"),
                (signal.normalized_event_sha256, event_digests, "normalized event digest"),
                (signal.source_event_ref, source_refs, "source event reference"),
                (signal.raw_event_sha256, raw_digests, "raw event digest"),
            ):
                if value in seen:
                    raise DetectionCorrelationError(f"duplicate {label} is forbidden")
                seen.add(value)
        for control in (
            *self.expected_detections,
            *self.negative_controls,
            *self.false_positive_controls,
        ):
            _window(control.opens_at, control.closes_at, self.budget.maximum_window_seconds)

    def body(self) -> dict[str, Any]:
        return {
            "budget": self.budget.to_dict(),
            "custody_policy_sha256": self.custody_policy_sha256,
            "engagement_ref": self.engagement_ref,
            "evaluated_at": self.evaluated_at,
            "execution": self.execution.to_dict(),
            "expected_detections": [item.to_dict() for item in self.expected_detections],
            "false_positive_controls": [item.to_dict() for item in self.false_positive_controls],
            "negative_controls": [item.to_dict() for item in self.negative_controls],
            "prior_consumed_event_sha256s": list(self.prior_consumed_event_sha256s),
            "scope_sha256": self.scope_sha256,
            "signals": [item.to_dict() for item in self.signals],
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "qualification_effect": QUALIFICATION_EFFECT,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "runtime_status": RUNTIME_STATUS,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CorrelationRequest:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "qualification_effect",
            "runtime_status",
            "schema_version",
        }
        item = dict(_exact(raw, fields, "correlation request"))
        expected_id = item.pop("request_id")
        expected_sha = item.pop("request_sha256")
        if (
            item.pop("kind") != cls.KIND
            or item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("effects") != dict(NO_EFFECTS)
            or item.pop("qualification_effect") != QUALIFICATION_EFFECT
            or item.pop("runtime_status") != RUNTIME_STATUS
        ):
            raise DetectionCorrelationError("correlation request metadata is invalid")
        item["execution"] = ExecutionEvidenceReference.from_dict(item["execution"])
        item["signals"] = tuple(
            NormalizedSignalReference.from_dict(value) for value in item["signals"]
        )
        item["expected_detections"] = tuple(
            ExpectedDetection.from_dict(value) for value in item["expected_detections"]
        )
        item["negative_controls"] = tuple(
            NegativeControl.from_dict(value) for value in item["negative_controls"]
        )
        item["false_positive_controls"] = tuple(
            FalsePositiveControl.from_dict(value) for value in item["false_positive_controls"]
        )
        item["prior_consumed_event_sha256s"] = tuple(item["prior_consumed_event_sha256s"])
        item["budget"] = CorrelationBudget.from_dict(item["budget"])
        candidate = cls(**item)
        if candidate.request_id != expected_id or candidate.request_sha256 != expected_sha:
            raise DetectionCorrelationError("correlation request content address does not match")
        return candidate


@dataclass(frozen=True, slots=True)
class ControlValidationResult:
    control_ref: str
    control_kind: ControlKind | str
    state: ValidationState | str
    matched_signal_ids: tuple[str, ...]
    observed_count: int
    threshold_count: int
    reason_code: str
    result_id: str = field(init=False)
    result_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.control-validation-result.v1"

    def __post_init__(self) -> None:
        _ref(self.control_ref, "control_ref", "controlref")
        try:
            object.__setattr__(self, "control_kind", ControlKind(self.control_kind))
            object.__setattr__(self, "state", ValidationState(self.state))
        except ValueError as exc:
            raise DetectionCorrelationError("control validation classification is invalid") from exc
        matched = tuple(self.matched_signal_ids)
        for value in matched:
            _content_id(value, "matched signal id", "NSR")
        if matched != tuple(sorted(set(matched))):
            raise DetectionCorrelationError("matched signal ids must be sorted and unique")
        object.__setattr__(self, "matched_signal_ids", matched)
        _bounded_int(self.observed_count, "observed_count", 0, MAX_ITEMS)
        _bounded_int(self.threshold_count, "threshold_count", 0, MAX_ITEMS)
        if self.observed_count != len(matched):
            raise DetectionCorrelationError("observed count does not match signal membership")
        _code(self.reason_code, "reason_code")
        identity, digest = _identity("CVR", self.KIND, self.body())
        object.__setattr__(self, "result_id", identity)
        object.__setattr__(self, "result_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "control_kind": self.control_kind.value,
            "control_ref": self.control_ref,
            "matched_signal_ids": list(self.matched_signal_ids),
            "observed_count": self.observed_count,
            "reason_code": self.reason_code,
            "state": self.state.value,
            "threshold_count": self.threshold_count,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "result_id": self.result_id,
            "result_sha256": self.result_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class DerivedFinding:
    finding_type: str
    control_ref: str
    code: str
    evidence_signal_ids: tuple[str, ...]
    priority: str
    finding_id: str = field(init=False)
    finding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.detection-correlation-derived-finding.v1"
    FINDING_TYPES: ClassVar[frozenset[str]] = frozenset(
        {"coverage_gap", "root_cause_hypothesis", "tuning_recommendation"}
    )
    PRIORITIES: ClassVar[frozenset[str]] = frozenset({"low", "medium", "high", "critical"})

    def __post_init__(self) -> None:
        if self.finding_type not in self.FINDING_TYPES:
            raise DetectionCorrelationError("finding_type is invalid")
        _ref(self.control_ref, "control_ref", "controlref")
        _code(self.code, "code")
        evidence = tuple(self.evidence_signal_ids)
        for value in evidence:
            _content_id(value, "evidence signal id", "NSR")
        if evidence != tuple(sorted(set(evidence))):
            raise DetectionCorrelationError("evidence signal ids must be sorted and unique")
        object.__setattr__(self, "evidence_signal_ids", evidence)
        if self.priority not in self.PRIORITIES:
            raise DetectionCorrelationError("finding priority is invalid")
        identity, digest = _identity("DCF", self.KIND, self.body())
        object.__setattr__(self, "finding_id", identity)
        object.__setattr__(self, "finding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "control_ref": self.control_ref,
            "evidence_signal_ids": list(self.evidence_signal_ids),
            "finding_type": self.finding_type,
            "priority": self.priority,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_sha256": self.finding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class CorrelationAssessment:
    request_id: str
    request_sha256: str
    validation_results: tuple[ControlValidationResult, ...]
    coverage_gaps: tuple[DerivedFinding, ...]
    root_cause_hypotheses: tuple[DerivedFinding, ...]
    tuning_recommendations: tuple[DerivedFinding, ...]
    consumed_event_sha256s: tuple[str, ...]
    overall_state: str
    assessment_id: str = field(init=False)
    assessment_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.detection-correlation-assessment.v1"

    def __post_init__(self) -> None:
        _content_id(self.request_id, "request_id", "DCR")
        _digest(self.request_sha256, "request_sha256")
        results = _objects(
            self.validation_results,
            ControlValidationResult,
            "validation_results",
        )
        if not results:
            raise DetectionCorrelationError("validation results cannot be empty")
        results = tuple(sorted(results, key=lambda item: item.control_ref))
        if len({item.control_ref for item in results}) != len(results):
            raise DetectionCorrelationError("validation result control is duplicated")
        object.__setattr__(self, "validation_results", results)
        for name, expected_type in (
            ("coverage_gaps", "coverage_gap"),
            ("root_cause_hypotheses", "root_cause_hypothesis"),
            ("tuning_recommendations", "tuning_recommendation"),
        ):
            findings = _objects(getattr(self, name), DerivedFinding, name)
            if any(item.finding_type != expected_type for item in findings):
                raise DetectionCorrelationError(f"{name} contains a mismatched finding type")
            object.__setattr__(
                self, name, tuple(sorted(findings, key=lambda item: item.finding_id))
            )
        consumed = tuple(self.consumed_event_sha256s)
        for value in consumed:
            _digest(value, "consumed_event_sha256")
        if consumed != tuple(sorted(set(consumed))):
            raise DetectionCorrelationError("consumed event digests must be sorted and unique")
        object.__setattr__(self, "consumed_event_sha256s", consumed)
        derived = (
            "passed" if all(item.state is ValidationState.PASSED for item in results) else "failed"
        )
        if self.overall_state != derived:
            raise DetectionCorrelationError("overall state does not match control results")
        identity, digest = _identity("DCA", self.KIND, self.body())
        object.__setattr__(self, "assessment_id", identity)
        object.__setattr__(self, "assessment_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "consumed_event_sha256s": list(self.consumed_event_sha256s),
            "coverage_gaps": [item.to_dict() for item in self.coverage_gaps],
            "overall_state": self.overall_state,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "root_cause_hypotheses": [item.to_dict() for item in self.root_cause_hypotheses],
            "tuning_recommendations": [item.to_dict() for item in self.tuning_recommendations],
            "validation_results": [item.to_dict() for item in self.validation_results],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "qualification_effect": QUALIFICATION_EFFECT,
            "runtime_status": RUNTIME_STATUS,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class IndependentReviewPlan:
    request_id: str
    request_sha256: str
    assessment_id: str
    assessment_sha256: str
    execution_reference_sha256: str
    required_reviewer_roles: tuple[str, ...]
    review_status: str = "pending_independent_review"
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.detection-correlation-review-plan.v1"

    def __post_init__(self) -> None:
        _content_id(self.request_id, "request_id", "DCR")
        _digest(self.request_sha256, "request_sha256")
        _content_id(self.assessment_id, "assessment_id", "DCA")
        _digest(self.assessment_sha256, "assessment_sha256")
        _digest(self.execution_reference_sha256, "execution_reference_sha256")
        roles = _codes(self.required_reviewer_roles, "required_reviewer_roles")
        required = ("independent_assurance", "independent_control")
        if roles != required:
            raise DetectionCorrelationError("both independent reviewer roles are required")
        object.__setattr__(self, "required_reviewer_roles", roles)
        if self.review_status != "pending_independent_review":
            raise DetectionCorrelationError("review plan cannot claim a completed review")
        identity, digest = _identity("DRP", self.KIND, self.body())
        object.__setattr__(self, "plan_id", identity)
        object.__setattr__(self, "plan_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "execution_reference_sha256": self.execution_reference_sha256,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "required_reviewer_roles": list(self.required_reviewer_roles),
            "review_status": self.review_status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "qualification_effect": QUALIFICATION_EFFECT,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


@dataclass(frozen=True, slots=True)
class CorrelationBundle:
    request: CorrelationRequest
    assessment: CorrelationAssessment
    review_plan: IndependentReviewPlan
    bundle_id: str = field(init=False)
    bundle_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.detection-correlation-bundle.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request, CorrelationRequest)
            or not isinstance(self.assessment, CorrelationAssessment)
            or not isinstance(self.review_plan, IndependentReviewPlan)
        ):
            raise DetectionCorrelationError("correlation bundle component is invalid")
        if (
            self.assessment.request_id != self.request.request_id
            or self.assessment.request_sha256 != self.request.request_sha256
            or self.review_plan.request_id != self.request.request_id
            or self.review_plan.request_sha256 != self.request.request_sha256
            or self.review_plan.assessment_id != self.assessment.assessment_id
            or self.review_plan.assessment_sha256 != self.assessment.assessment_sha256
            or self.review_plan.execution_reference_sha256
            != self.request.execution.reference_sha256
        ):
            raise DetectionCorrelationError("correlation bundle binding is inconsistent")
        identity, digest = _identity("DCB", self.KIND, self.body())
        object.__setattr__(self, "bundle_id", identity)
        object.__setattr__(self, "bundle_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment.to_dict(),
            "request": self.request.to_dict(),
            "review_plan": self.review_plan.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "bundle_sha256": self.bundle_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "qualification_effect": QUALIFICATION_EFFECT,
            "runtime_status": RUNTIME_STATUS,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }


def _matches(
    signals: Sequence[NormalizedSignalReference],
    *,
    operation_code: str,
    domains: Sequence[str],
    opens_at: str,
    closes_at: str,
    outcomes: Sequence[str] | None = None,
) -> tuple[NormalizedSignalReference, ...]:
    allowed_domains = set(domains)
    allowed_outcomes = set(outcomes) if outcomes is not None else None
    opens = _instant(opens_at)
    closes = _instant(closes_at)
    return tuple(
        signal
        for signal in signals
        if signal.operation_code == operation_code
        and signal.telemetry_domain in allowed_domains
        and opens <= _instant(signal.occurred_at) <= closes
        and (allowed_outcomes is None or signal.outcome in allowed_outcomes)
    )


def _derived_for_failed_control(
    *,
    control_ref: str,
    control_kind: ControlKind,
    signals: Sequence[NormalizedSignalReference],
    matched: Sequence[NormalizedSignalReference],
    operation_code: str,
    domains: Sequence[str],
    opens_at: str,
    closes_at: str,
) -> tuple[DerivedFinding, DerivedFinding, DerivedFinding]:
    evidence = tuple(sorted(item.signal_id for item in matched))
    if control_kind is not ControlKind.EXPECTED_DETECTION:
        codes = ("unexpected_signal", "detector_overmatching", "narrow_detection_logic")
        priority = "high"
    else:
        in_domain = [item for item in signals if item.telemetry_domain in set(domains)]
        matching_outside = [item for item in signals if item.operation_code == operation_code]
        if not in_domain:
            codes = ("missing_telemetry", "source_telemetry_absent", "enable_source_mapping")
            priority = "critical"
        elif matching_outside:
            codes = (
                "detection_window_gap",
                "correlation_window_mismatch",
                "review_detection_window",
            )
            evidence = tuple(sorted(item.signal_id for item in matching_outside))
            priority = "high"
        else:
            codes = (
                "missing_detection",
                "detector_mapping_mismatch",
                "tune_detector_mapping",
            )
            priority = "high"
    return (
        DerivedFinding("coverage_gap", control_ref, codes[0], evidence, priority),
        DerivedFinding("root_cause_hypothesis", control_ref, codes[1], evidence, priority),
        DerivedFinding("tuning_recommendation", control_ref, codes[2], evidence, priority),
    )


def correlate_detection_controls(request: CorrelationRequest) -> CorrelationBundle:
    """Correlate bounded references without querying a source or changing state."""

    if not isinstance(request, CorrelationRequest):
        raise DetectionCorrelationError("correlation request is invalid")
    results: list[ControlValidationResult] = []
    gaps: list[DerivedFinding] = []
    hypotheses: list[DerivedFinding] = []
    recommendations: list[DerivedFinding] = []
    for control in request.expected_detections:
        matched = _matches(
            request.signals,
            operation_code=control.operation_code,
            domains=control.telemetry_domains,
            opens_at=control.opens_at,
            closes_at=control.closes_at,
            outcomes=control.accepted_outcomes,
        )
        passed = len(matched) >= control.minimum_signal_count
        results.append(
            ControlValidationResult(
                control_ref=control.control_ref,
                control_kind=ControlKind.EXPECTED_DETECTION,
                state=ValidationState.PASSED if passed else ValidationState.FAILED,
                matched_signal_ids=tuple(sorted(item.signal_id for item in matched)),
                observed_count=len(matched),
                threshold_count=control.minimum_signal_count,
                reason_code="expected_signal_observed" if passed else "expected_signal_missing",
            )
        )
        if not passed:
            gap, hypothesis, recommendation = _derived_for_failed_control(
                control_ref=control.control_ref,
                control_kind=ControlKind.EXPECTED_DETECTION,
                signals=request.signals,
                matched=matched,
                operation_code=control.operation_code,
                domains=control.telemetry_domains,
                opens_at=control.opens_at,
                closes_at=control.closes_at,
            )
            gaps.append(gap)
            hypotheses.append(hypothesis)
            recommendations.append(recommendation)
    for control_kind, controls in (
        (ControlKind.NEGATIVE_CONTROL, request.negative_controls),
        (ControlKind.FALSE_POSITIVE_CONTROL, request.false_positive_controls),
    ):
        for control in controls:
            matched = _matches(
                request.signals,
                operation_code=control.operation_code,
                domains=control.telemetry_domains,
                opens_at=control.opens_at,
                closes_at=control.closes_at,
            )
            passed = len(matched) <= control.maximum_signal_count
            results.append(
                ControlValidationResult(
                    control_ref=control.control_ref,
                    control_kind=control_kind,
                    state=ValidationState.PASSED if passed else ValidationState.FAILED,
                    matched_signal_ids=tuple(sorted(item.signal_id for item in matched)),
                    observed_count=len(matched),
                    threshold_count=control.maximum_signal_count,
                    reason_code=(
                        "absence_control_satisfied" if passed else "unexpected_signal_observed"
                    ),
                )
            )
            if not passed:
                gap, hypothesis, recommendation = _derived_for_failed_control(
                    control_ref=control.control_ref,
                    control_kind=control_kind,
                    signals=request.signals,
                    matched=matched,
                    operation_code=control.operation_code,
                    domains=control.telemetry_domains,
                    opens_at=control.opens_at,
                    closes_at=control.closes_at,
                )
                gaps.append(gap)
                hypotheses.append(hypothesis)
                recommendations.append(recommendation)
    derived_count = len(gaps) + len(hypotheses) + len(recommendations)
    if derived_count > request.budget.maximum_derived_findings:
        raise DetectionCorrelationError("derived finding budget exceeded")
    results_tuple = tuple(results)
    assessment = CorrelationAssessment(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        validation_results=results_tuple,
        coverage_gaps=tuple(gaps),
        root_cause_hypotheses=tuple(hypotheses),
        tuning_recommendations=tuple(recommendations),
        consumed_event_sha256s=tuple(
            sorted(signal.normalized_event_sha256 for signal in request.signals)
        ),
        overall_state=(
            "passed"
            if all(item.state is ValidationState.PASSED for item in results_tuple)
            else "failed"
        ),
    )
    review_plan = IndependentReviewPlan(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        assessment_id=assessment.assessment_id,
        assessment_sha256=assessment.assessment_sha256,
        execution_reference_sha256=request.execution.reference_sha256,
        required_reviewer_roles=("independent_assurance", "independent_control"),
    )
    return CorrelationBundle(request=request, assessment=assessment, review_plan=review_plan)


def parse_contract(raw: str | Mapping[str, Any]) -> CorrelationRequest:
    """Parse and verify the only caller-authored top-level contract."""

    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DetectionCorrelationError("contract is not valid JSON") from exc
    else:
        value = raw
    if not isinstance(value, Mapping) or value.get("kind") != CorrelationRequest.KIND:
        raise DetectionCorrelationError("contract kind is not supported")
    return CorrelationRequest.from_dict(value)


__all__ = [
    "NO_BUILTIN_NETWORK",
    "NO_BUILTIN_SIEM_QUERY",
    "NO_EFFECTS",
    "QUALIFICATION_EFFECT",
    "RUNTIME_STATUS",
    "ControlKind",
    "ControlValidationResult",
    "CorrelationAssessment",
    "CorrelationBudget",
    "CorrelationBundle",
    "CorrelationRequest",
    "DerivedFinding",
    "DetectionCorrelationError",
    "ExecutionEvidenceReference",
    "ExpectedDetection",
    "FalsePositiveControl",
    "IndependentReviewPlan",
    "NegativeControl",
    "NormalizedSignalReference",
    "ValidationState",
    "canonical_json",
    "canonical_sha256",
    "correlate_detection_controls",
    "parse_contract",
]
