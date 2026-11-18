"""Fail-closed target-health assessment over injected boundary evidence.

This module performs no target interaction. It accepts content-addressed
receipts and health attestations supplied by authorized HTTP, browser, and
target-session boundaries, then emits one deterministic observation receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, TypeAlias
from urllib.parse import urlsplit

from .authorized_browser_runtime import (
    BrowserActionReceipt,
    BrowserActionStatus,
    verify_browser_action_receipt,
)
from .authorized_http_runtime import (
    ExchangeStatus,
    HttpExchangeReceipt,
    verify_exchange_receipt,
)
from .authorized_target_session_runtime import (
    SessionAcquisitionStatus,
    TargetSessionReceipt,
    verify_target_session_receipt,
)
from .execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
    canonical_json,
)
from .signed_scope_compiler import ScopeBudgetState, VerifiedAssessmentScope, evaluate_request

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
ENFORCEMENT_BOUNDARY = "repository_attested_health_evidence_only"
CLAIM_SCOPE = "point_in_time_bounded_health_observation"
MAX_EVIDENCE_BYTES = 100_000_000

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")


class AuthorizedTargetHealthRuntimeError(ValueError):
    """Raised when a target-health contract value is malformed."""


class HealthDimension(StrEnum):
    """Closed health dimension vocabulary."""

    REACHABILITY = "reachability"
    LATENCY = "latency"
    AUTHENTICATION_CONTINUITY = "authentication_continuity"
    WAF = "waf"
    SERVICE_HEALTH = "service_health"


class HealthSignalState(StrEnum):
    """Closed point-in-time health state vocabulary."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class BoundarySourceKind(StrEnum):
    """Authorized boundary receipt types accepted as source evidence."""

    HTTP = "authorized_http"
    BROWSER = "authorized_browser"
    TARGET_SESSION = "authorized_target_session"


class TargetHealthStatus(StrEnum):
    """Terminal target-health receipt states."""

    REJECTED = "rejected"
    COMPLETED = "completed"


_DIMENSION_ORDER = tuple(HealthDimension)
_SOURCE_ORDER = tuple(BoundarySourceKind)
_DETAIL_STATE = {
    HealthDimension.REACHABILITY: {
        "reachable": HealthSignalState.HEALTHY,
        "intermittent_reachability": HealthSignalState.DEGRADED,
        "unreachable": HealthSignalState.UNHEALTHY,
    },
    HealthDimension.LATENCY: {
        "within_latency_threshold": HealthSignalState.HEALTHY,
        "above_healthy_latency_threshold": HealthSignalState.DEGRADED,
        "above_degraded_latency_threshold": HealthSignalState.UNHEALTHY,
    },
    HealthDimension.AUTHENTICATION_CONTINUITY: {
        "session_continuous": HealthSignalState.HEALTHY,
        "session_continuity_degraded": HealthSignalState.DEGRADED,
        "session_continuity_lost": HealthSignalState.UNHEALTHY,
    },
    HealthDimension.WAF: {
        "expected_control_observed": HealthSignalState.HEALTHY,
        "control_state_changed": HealthSignalState.DEGRADED,
        "expected_control_absent": HealthSignalState.UNHEALTHY,
    },
    HealthDimension.SERVICE_HEALTH: {
        "service_healthy": HealthSignalState.HEALTHY,
        "service_degraded": HealthSignalState.DEGRADED,
        "service_unhealthy": HealthSignalState.UNHEALTHY,
    },
}
_ALLOWED_SOURCES = {
    HealthDimension.REACHABILITY: {
        BoundarySourceKind.HTTP,
        BoundarySourceKind.BROWSER,
    },
    HealthDimension.LATENCY: {
        BoundarySourceKind.HTTP,
        BoundarySourceKind.BROWSER,
    },
    HealthDimension.AUTHENTICATION_CONTINUITY: {
        BoundarySourceKind.BROWSER,
        BoundarySourceKind.TARGET_SESSION,
    },
    HealthDimension.WAF: {
        BoundarySourceKind.HTTP,
        BoundarySourceKind.BROWSER,
    },
    HealthDimension.SERVICE_HEALTH: {
        BoundarySourceKind.HTTP,
        BoundarySourceKind.BROWSER,
    },
}
_STATE_RANK = {
    HealthSignalState.HEALTHY: 0,
    HealthSignalState.DEGRADED: 1,
    HealthSignalState.UNHEALTHY: 2,
}


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(canonical_json(value).encode("ascii"))


def _identity(prefix: str, kind: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = _canonical_sha({"body": body, "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthorizedTargetHealthRuntimeError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AuthorizedTargetHealthRuntimeError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise AuthorizedTargetHealthRuntimeError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AuthorizedTargetHealthRuntimeError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise AuthorizedTargetHealthRuntimeError(f"{label} must be canonical UTC")
    if not value.isascii():
        raise AuthorizedTargetHealthRuntimeError(f"{label} must be ASCII")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorizedTargetHealthRuntimeError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise AuthorizedTargetHealthRuntimeError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _binding_sha(binding: ExecutionBinding) -> str:
    return _canonical_sha(binding.to_dict())


def _https_url(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 2048:
        raise AuthorizedTargetHealthRuntimeError("target_url is invalid")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise AuthorizedTargetHealthRuntimeError("target_url must be credential-free HTTPS")
    try:
        port = parts.port
    except ValueError as exc:
        raise AuthorizedTargetHealthRuntimeError("target_url port is invalid") from exc
    if port not in {None, 443}:
        raise AuthorizedTargetHealthRuntimeError("target_url must use HTTPS port 443")
    return value


@dataclass(frozen=True, slots=True)
class AuthorizedTargetHealthPolicy:
    """Exact execution, scope request, freshness, and budget policy."""

    binding: ExecutionBinding
    execution_policy_id: str
    execution_policy_sha256: str
    target_url: str
    method: str
    technique_id: str
    impact_tier: str
    max_admission_age_seconds: int
    max_signal_age_seconds: int
    max_signal_ttl_seconds: int
    healthy_latency_milliseconds: int
    degraded_latency_milliseconds: int
    request_ceiling: int
    evidence_byte_ceiling: int
    observation_ceiling: int
    max_source_receipts: int
    policy_id: str = ""
    policy_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_health_policy"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedTargetHealthRuntimeError("policy binding is invalid")
        _identifier(self.execution_policy_id, "execution_policy_id")
        _digest(self.execution_policy_sha256, "execution_policy_sha256")
        _https_url(self.target_url)
        method = _code(self.method.lower(), "method").upper()
        if method not in {"GET", "HEAD"}:
            raise AuthorizedTargetHealthRuntimeError("health method must be GET or HEAD")
        object.__setattr__(self, "method", method)
        _identifier(self.technique_id, "technique_id")
        if self.impact_tier not in {"R0", "R1"}:
            raise AuthorizedTargetHealthRuntimeError("health impact_tier must be R0 or R1")
        for value, label, maximum in (
            (self.max_admission_age_seconds, "max_admission_age_seconds", 3600),
            (self.max_signal_age_seconds, "max_signal_age_seconds", 3600),
            (self.max_signal_ttl_seconds, "max_signal_ttl_seconds", 3600),
            (self.healthy_latency_milliseconds, "healthy_latency_milliseconds", 600_000),
            (self.degraded_latency_milliseconds, "degraded_latency_milliseconds", 600_000),
            (self.request_ceiling, "request_ceiling", 1_000_000),
            (self.evidence_byte_ceiling, "evidence_byte_ceiling", MAX_EVIDENCE_BYTES),
            (self.observation_ceiling, "observation_ceiling", 1_000_000),
            (self.max_source_receipts, "max_source_receipts", 64),
        ):
            _integer(value, label, 1, maximum)
        if self.degraded_latency_milliseconds < self.healthy_latency_milliseconds:
            raise AuthorizedTargetHealthRuntimeError("latency thresholds are inverted")
        if self.observation_ceiling < len(_DIMENSION_ORDER):
            raise AuthorizedTargetHealthRuntimeError("observation ceiling is too small")
        if self.max_source_receipts < len(_SOURCE_ORDER):
            raise AuthorizedTargetHealthRuntimeError("source receipt ceiling is too small")
        identity, digest = _identity("THP", self.KIND, self.body())
        if self.policy_id and self.policy_id != identity:
            raise AuthorizedTargetHealthRuntimeError("policy_id does not match content")
        if self.policy_sha256 and not hmac.compare_digest(self.policy_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "claim_scope": CLAIM_SCOPE,
            "degraded_latency_milliseconds": self.degraded_latency_milliseconds,
            "evidence_byte_ceiling": self.evidence_byte_ceiling,
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "healthy_latency_milliseconds": self.healthy_latency_milliseconds,
            "impact_tier": self.impact_tier,
            "max_admission_age_seconds": self.max_admission_age_seconds,
            "max_signal_age_seconds": self.max_signal_age_seconds,
            "max_signal_ttl_seconds": self.max_signal_ttl_seconds,
            "max_source_receipts": self.max_source_receipts,
            "method": self.method,
            "observation_ceiling": self.observation_ceiling,
            "request_ceiling": self.request_ceiling,
            "required_dimensions": [item.value for item in _DIMENSION_ORDER],
            "required_source_kinds": [item.value for item in _SOURCE_ORDER],
            "target_url": self.target_url,
            "technique_id": self.technique_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class TargetHealthBudgetState:
    """Fresh caller-supplied counters for one health aggregation."""

    binding_sha256: str
    execution_request_sha256: str
    requests_used: int
    evidence_bytes_used: int
    observations_used: int
    observed_at: str
    expires_at: str
    state_id: str = ""
    state_sha256: str = ""

    KIND: ClassVar[str] = "target_health_budget_state"

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "budget binding_sha256")
        _digest(self.execution_request_sha256, "budget execution_request_sha256")
        _integer(self.requests_used, "requests_used", 0, 1_000_000)
        _integer(self.evidence_bytes_used, "evidence_bytes_used", 0, MAX_EVIDENCE_BYTES)
        _integer(self.observations_used, "observations_used", 0, 1_000_000)
        _utc(self.observed_at, "budget observed_at")
        _utc(self.expires_at, "budget expires_at")
        if _instant(self.expires_at) <= _instant(self.observed_at):
            raise AuthorizedTargetHealthRuntimeError("budget attestation expiry is invalid")
        identity, digest = _identity("THB", self.KIND, self.body())
        if self.state_id and self.state_id != identity:
            raise AuthorizedTargetHealthRuntimeError("budget state_id does not match content")
        if self.state_sha256 and not hmac.compare_digest(self.state_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError("budget state_sha256 does not match content")
        object.__setattr__(self, "state_id", identity)
        object.__setattr__(self, "state_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "evidence_bytes_used": self.evidence_bytes_used,
            "execution_request_sha256": self.execution_request_sha256,
            "expires_at": self.expires_at,
            "observations_used": self.observations_used,
            "observed_at": self.observed_at,
            "requests_used": self.requests_used,
        }


@dataclass(frozen=True, slots=True)
class TargetHealthSafetySnapshot:
    """Fresh cancellation, emergency-stop, and runtime-health attestation."""

    binding_sha256: str
    execution_request_sha256: str
    health: HealthState
    canceled: bool
    emergency_stop: bool
    observed_at: str
    expires_at: str
    attestation_sha256: str = ""

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "safety binding_sha256")
        _digest(self.execution_request_sha256, "safety execution_request_sha256")
        if not isinstance(self.health, HealthState):
            raise AuthorizedTargetHealthRuntimeError("safety health is invalid")
        if not isinstance(self.canceled, bool) or not isinstance(self.emergency_stop, bool):
            raise AuthorizedTargetHealthRuntimeError("safety stop flags are invalid")
        _utc(self.observed_at, "safety observed_at")
        _utc(self.expires_at, "safety expires_at")
        if _instant(self.expires_at) <= _instant(self.observed_at):
            raise AuthorizedTargetHealthRuntimeError("safety attestation expiry is invalid")
        digest = _canonical_sha(self.body())
        if self.attestation_sha256 and not hmac.compare_digest(self.attestation_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError(
                "safety attestation_sha256 does not match content"
            )
        object.__setattr__(self, "attestation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "canceled": self.canceled,
            "emergency_stop": self.emergency_stop,
            "execution_request_sha256": self.execution_request_sha256,
            "expires_at": self.expires_at,
            "health": self.health.value,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class BoundaryReceiptReference:
    """Minimal content-addressed reference to a verified boundary receipt."""

    source_kind: BoundarySourceKind
    receipt_id: str
    receipt_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    binding_sha256: str
    source_status: str
    observed_at: str
    boundary_performed: bool
    reference_sha256: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, BoundarySourceKind):
            raise AuthorizedTargetHealthRuntimeError("source_kind is invalid")
        for value, label in (
            (self.receipt_id, "source receipt_id"),
            (self.execution_request_id, "source execution_request_id"),
            (self.admission_receipt_id, "source admission_receipt_id"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.receipt_sha256, "source receipt_sha256"),
            (self.execution_request_sha256, "source execution_request_sha256"),
            (self.admission_receipt_sha256, "source admission_receipt_sha256"),
            (self.binding_sha256, "source binding_sha256"),
        ):
            _digest(value, label)
        _code(self.source_status, "source_status")
        _utc(self.observed_at, "source observed_at")
        if self.boundary_performed is not True:
            raise AuthorizedTargetHealthRuntimeError("source boundary was not performed")
        digest = _canonical_sha(self.body())
        if self.reference_sha256 and not hmac.compare_digest(self.reference_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError(
                "source reference_sha256 does not match content"
            )
        object.__setattr__(self, "reference_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "binding_sha256": self.binding_sha256,
            "boundary_performed": self.boundary_performed,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "observed_at": self.observed_at,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "source_kind": self.source_kind.value,
            "source_status": self.source_status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "reference_sha256": self.reference_sha256}


@dataclass(frozen=True, slots=True)
class TargetHealthObservation:
    """One content-addressed point-in-time health attestation."""

    dimension: HealthDimension
    state: HealthSignalState
    detail_code: str
    source_kind: BoundarySourceKind
    source_receipt_id: str
    source_receipt_sha256: str
    evidence_sha256: str
    observed_at: str
    expires_at: str
    latency_milliseconds: int | None = None
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_health_observation"

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, HealthDimension):
            raise AuthorizedTargetHealthRuntimeError("observation dimension is invalid")
        if not isinstance(self.state, HealthSignalState):
            raise AuthorizedTargetHealthRuntimeError("observation state is invalid")
        if not isinstance(self.source_kind, BoundarySourceKind):
            raise AuthorizedTargetHealthRuntimeError("observation source_kind is invalid")
        _code(self.detail_code, "detail_code")
        if _DETAIL_STATE[self.dimension].get(self.detail_code) is not self.state:
            raise AuthorizedTargetHealthRuntimeError("observation state overclaims its detail code")
        _identifier(self.source_receipt_id, "source_receipt_id")
        _digest(self.source_receipt_sha256, "source_receipt_sha256")
        _digest(self.evidence_sha256, "evidence_sha256")
        _utc(self.observed_at, "observation observed_at")
        _utc(self.expires_at, "observation expires_at")
        if _instant(self.expires_at) <= _instant(self.observed_at):
            raise AuthorizedTargetHealthRuntimeError("observation expiry is invalid")
        if self.dimension is HealthDimension.LATENCY:
            _integer(
                self.latency_milliseconds,
                "latency_milliseconds",
                0,
                600_000,
            )
        elif self.latency_milliseconds is not None:
            raise AuthorizedTargetHealthRuntimeError(
                "latency value is only valid for the latency dimension"
            )
        identity, digest = _identity("THO", self.KIND, self.body())
        if self.observation_id and self.observation_id != identity:
            raise AuthorizedTargetHealthRuntimeError("observation_id does not match content")
        if self.observation_sha256 and not hmac.compare_digest(self.observation_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", identity)
        object.__setattr__(self, "observation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "detail_code": self.detail_code,
            "dimension": self.dimension.value,
            "evidence_sha256": self.evidence_sha256,
            "expires_at": self.expires_at,
            "latency_milliseconds": self.latency_milliseconds,
            "observed_at": self.observed_at,
            "source_kind": self.source_kind.value,
            "source_receipt_id": self.source_receipt_id,
            "source_receipt_sha256": self.source_receipt_sha256,
            "state": self.state.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class TargetHealthReceipt:
    """Deterministic aggregate over exact boundary and signal evidence."""

    status: TargetHealthStatus
    reason: str
    overall_health: HealthSignalState | None
    scope_id: str
    scope_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    execution_policy_id: str
    execution_policy_sha256: str
    runtime_policy_id: str
    runtime_policy_sha256: str
    binding: ExecutionBinding
    binding_sha256: str
    target_url: str
    observed_at: str
    monotonic_tick: int
    safety_attestation: TargetHealthSafetySnapshot | None
    safety_attestation_sha256: str | None
    budget_state: TargetHealthBudgetState | None
    budget_state_sha256: str | None
    source_receipts: tuple[BoundaryReceiptReference, ...]
    observations: tuple[TargetHealthObservation, ...]
    source_validation_performed: bool
    external_call_performed: bool = False
    network_call_performed: bool = False
    browser_action_performed: bool = False
    authentication_performed: bool = False
    authority_effect: str = "none"
    qualification_effect: str = "none"
    claim_scope: str = CLAIM_SCOPE
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_health_receipt"

    def __post_init__(self) -> None:
        if not isinstance(self.status, TargetHealthStatus):
            raise AuthorizedTargetHealthRuntimeError("receipt status is invalid")
        _code(self.reason, "receipt reason")
        _identifier(self.scope_id, "scope_id")
        _digest(self.scope_sha256, "scope_sha256")
        for value, label in (
            (self.execution_request_id, "execution_request_id"),
            (self.admission_receipt_id, "admission_receipt_id"),
            (self.execution_policy_id, "execution_policy_id"),
            (self.runtime_policy_id, "runtime_policy_id"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.execution_request_sha256, "execution_request_sha256"),
            (self.admission_receipt_sha256, "admission_receipt_sha256"),
            (self.execution_policy_sha256, "execution_policy_sha256"),
            (self.runtime_policy_sha256, "runtime_policy_sha256"),
            (self.binding_sha256, "binding_sha256"),
        ):
            _digest(value, label)
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedTargetHealthRuntimeError("receipt binding is invalid")
        if not hmac.compare_digest(self.binding_sha256, _binding_sha(self.binding)):
            raise AuthorizedTargetHealthRuntimeError("receipt binding_sha256 is invalid")
        _https_url(self.target_url)
        _utc(self.observed_at, "receipt observed_at")
        _integer(self.monotonic_tick, "receipt monotonic_tick", 1, 2**63 - 1)
        if (self.safety_attestation is None) != (self.safety_attestation_sha256 is None):
            raise AuthorizedTargetHealthRuntimeError("safety attestation evidence is incomplete")
        if (self.budget_state is None) != (self.budget_state_sha256 is None):
            raise AuthorizedTargetHealthRuntimeError("budget attestation evidence is incomplete")
        if self.safety_attestation is not None:
            if not isinstance(self.safety_attestation, TargetHealthSafetySnapshot):
                raise AuthorizedTargetHealthRuntimeError("safety attestation is invalid")
            _digest(self.safety_attestation_sha256, "safety_attestation_sha256")
            if not hmac.compare_digest(
                self.safety_attestation_sha256 or "",
                self.safety_attestation.attestation_sha256,
            ):
                raise AuthorizedTargetHealthRuntimeError("safety attestation digest mismatch")
            if (
                self.safety_attestation.binding_sha256 != self.binding_sha256
                or self.safety_attestation.execution_request_sha256 != self.execution_request_sha256
            ):
                raise AuthorizedTargetHealthRuntimeError("safety attestation binding mismatch")
        if self.budget_state is not None:
            if not isinstance(self.budget_state, TargetHealthBudgetState):
                raise AuthorizedTargetHealthRuntimeError("budget attestation is invalid")
            _digest(self.budget_state_sha256, "budget_state_sha256")
            if not hmac.compare_digest(
                self.budget_state_sha256 or "", self.budget_state.state_sha256
            ):
                raise AuthorizedTargetHealthRuntimeError("budget attestation digest mismatch")
            if (
                self.budget_state.binding_sha256 != self.binding_sha256
                or self.budget_state.execution_request_sha256 != self.execution_request_sha256
            ):
                raise AuthorizedTargetHealthRuntimeError("budget attestation binding mismatch")
        if any(
            (
                self.external_call_performed,
                self.network_call_performed,
                self.browser_action_performed,
                self.authentication_performed,
            )
        ):
            raise AuthorizedTargetHealthRuntimeError(
                "target-health aggregation cannot claim external effects"
            )
        if self.authority_effect != "none" or self.qualification_effect != "none":
            raise AuthorizedTargetHealthRuntimeError(
                "target-health receipt cannot grant authority or qualification"
            )
        if self.claim_scope != CLAIM_SCOPE or self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise AuthorizedTargetHealthRuntimeError("receipt boundary claim is invalid")
        if not isinstance(self.source_receipts, tuple) or not all(
            isinstance(item, BoundaryReceiptReference) for item in self.source_receipts
        ):
            raise AuthorizedTargetHealthRuntimeError("source receipts are invalid")
        if not isinstance(self.observations, tuple) or not all(
            isinstance(item, TargetHealthObservation) for item in self.observations
        ):
            raise AuthorizedTargetHealthRuntimeError("observations are invalid")
        expected_sources = tuple(
            sorted(
                self.source_receipts,
                key=lambda item: (_SOURCE_ORDER.index(item.source_kind), item.receipt_id),
            )
        )
        expected_observations = tuple(
            sorted(self.observations, key=lambda item: _DIMENSION_ORDER.index(item.dimension))
        )
        if self.source_receipts != expected_sources or self.observations != expected_observations:
            raise AuthorizedTargetHealthRuntimeError("receipt evidence must be canonical")
        if self.status is TargetHealthStatus.REJECTED:
            if (
                self.overall_health is not None
                or self.source_receipts
                or self.observations
                or self.source_validation_performed
            ):
                raise AuthorizedTargetHealthRuntimeError(
                    "rejected receipt cannot claim validated health evidence"
                )
        else:
            if self.safety_attestation is None or self.budget_state is None:
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt requires exact safety and budget attestations"
                )
            if (
                self.safety_attestation.health is not HealthState.HEALTHY
                or self.safety_attestation.canceled
                or self.safety_attestation.emergency_stop
            ):
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt safety attestation is not healthy"
                )
            receipt_time = _instant(self.observed_at)
            for observed_at, expires_at, label in (
                (
                    self.safety_attestation.observed_at,
                    self.safety_attestation.expires_at,
                    "safety",
                ),
                (self.budget_state.observed_at, self.budget_state.expires_at, "budget"),
            ):
                if not (_instant(observed_at) <= receipt_time < _instant(expires_at)):
                    raise AuthorizedTargetHealthRuntimeError(
                        f"completed receipt {label} attestation is not current"
                    )
            if not isinstance(self.overall_health, HealthSignalState):
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt requires overall health"
                )
            if self.reason != f"observed_{self.overall_health.value}":
                raise AuthorizedTargetHealthRuntimeError("completed reason is inconsistent")
            if not self.source_validation_performed:
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt requires source validation"
                )
            dimensions = tuple(item.dimension for item in self.observations)
            if dimensions != _DIMENSION_ORDER:
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt requires all health dimensions"
                )
            source_kinds = {item.source_kind for item in self.source_receipts}
            if source_kinds != set(_SOURCE_ORDER):
                raise AuthorizedTargetHealthRuntimeError(
                    "completed receipt requires all boundary source kinds"
                )
            references = {
                (item.source_kind, item.receipt_id, item.receipt_sha256)
                for item in self.source_receipts
            }
            if any(
                (item.source_kind, item.source_receipt_id, item.source_receipt_sha256)
                not in references
                for item in self.observations
            ):
                raise AuthorizedTargetHealthRuntimeError("observation source receipt is missing")
            derived = max(self.observations, key=lambda item: _STATE_RANK[item.state]).state
            if self.overall_health is not derived:
                raise AuthorizedTargetHealthRuntimeError("overall health is overclaimed")
            values = {item.dimension: item.state for item in self.observations}
            if (
                values[HealthDimension.REACHABILITY] is HealthSignalState.UNHEALTHY
                and values[HealthDimension.SERVICE_HEALTH] is HealthSignalState.HEALTHY
            ):
                raise AuthorizedTargetHealthRuntimeError("service health contradicts reachability")
        identity, digest = _identity("THR", self.KIND, self.body())
        if self.receipt_id and self.receipt_id != identity:
            raise AuthorizedTargetHealthRuntimeError("receipt_id does not match content")
        if self.receipt_sha256 and not hmac.compare_digest(self.receipt_sha256, digest):
            raise AuthorizedTargetHealthRuntimeError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", identity)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "authentication_performed": self.authentication_performed,
            "authority_effect": self.authority_effect,
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "browser_action_performed": self.browser_action_performed,
            "budget_state": None if self.budget_state is None else self.budget_state.body(),
            "budget_state_sha256": self.budget_state_sha256,
            "claim_scope": self.claim_scope,
            "enforcement_boundary": self.enforcement_boundary,
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "external_call_performed": self.external_call_performed,
            "monotonic_tick": self.monotonic_tick,
            "network_call_performed": self.network_call_performed,
            "observations": [item.to_dict() for item in self.observations],
            "observed_at": self.observed_at,
            "overall_health": (None if self.overall_health is None else self.overall_health.value),
            "qualification_effect": self.qualification_effect,
            "reason": self.reason,
            "runtime_policy_id": self.runtime_policy_id,
            "runtime_policy_sha256": self.runtime_policy_sha256,
            "safety_attestation": (
                None if self.safety_attestation is None else self.safety_attestation.body()
            ),
            "safety_attestation_sha256": self.safety_attestation_sha256,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "source_receipts": [item.to_dict() for item in self.source_receipts],
            "source_validation_performed": self.source_validation_performed,
            "status": self.status.value,
            "target_url": self.target_url,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


BoundaryReceipt: TypeAlias = HttpExchangeReceipt | BrowserActionReceipt | TargetSessionReceipt


def _source_reference(
    receipt: BoundaryReceipt,
    scope: VerifiedAssessmentScope,
    binding: ExecutionBinding,
) -> BoundaryReceiptReference:
    if isinstance(receipt, HttpExchangeReceipt):
        verify_exchange_receipt(receipt.to_dict())
        if (
            receipt.status is ExchangeStatus.REJECTED_BEFORE_SEND
            or not receipt.transport_called
            or not receipt.network_call_performed
        ):
            raise AuthorizedTargetHealthRuntimeError("source receipt has no HTTP observation")
        source_kind = BoundarySourceKind.HTTP
        performed = receipt.network_call_performed
    elif isinstance(receipt, BrowserActionReceipt):
        verify_browser_action_receipt(receipt.to_dict())
        if (
            receipt.status is BrowserActionStatus.REJECTED_BEFORE_DRIVER
            or not receipt.driver_called
        ):
            raise AuthorizedTargetHealthRuntimeError("source receipt has no browser observation")
        source_kind = BoundarySourceKind.BROWSER
        performed = receipt.driver_called
    elif isinstance(receipt, TargetSessionReceipt):
        verify_target_session_receipt(receipt.to_dict())
        if (
            receipt.status is SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION
            or not receipt.provider_called
        ):
            raise AuthorizedTargetHealthRuntimeError("source receipt has no session observation")
        source_kind = BoundarySourceKind.TARGET_SESSION
        performed = receipt.provider_called
    else:
        raise AuthorizedTargetHealthRuntimeError("source receipt type is invalid")
    if (
        receipt.scope_id != scope.scope_id
        or receipt.scope_sha256 != scope.content_sha256
        or receipt.binding != binding
        or receipt.authority_effect != "none"
        or receipt.qualification_effect != "none"
    ):
        raise AuthorizedTargetHealthRuntimeError("source receipt binding mismatch")
    if (
        isinstance(receipt, TargetSessionReceipt)
        and receipt.session_id is not None
        and receipt.session_id != binding.session_id
    ):
        raise AuthorizedTargetHealthRuntimeError("source session binding mismatch")
    observed_at = receipt.transcript[-1].observed_at
    return BoundaryReceiptReference(
        source_kind=source_kind,
        receipt_id=receipt.receipt_id,
        receipt_sha256=receipt.receipt_sha256,
        execution_request_id=receipt.execution_request_id,
        execution_request_sha256=receipt.execution_request_sha256,
        admission_receipt_id=receipt.admission_receipt_id,
        admission_receipt_sha256=receipt.admission_receipt_sha256,
        binding_sha256=_binding_sha(receipt.binding),
        source_status=receipt.status.value,
        observed_at=observed_at,
        boundary_performed=performed,
    )


def _reason(exc: Exception) -> str:
    message = str(exc).lower()
    if "missing" in message or "requires all" in message:
        return "missing_attestation"
    if "stale" in message or "expired" in message or "future" in message:
        return "stale_attestation"
    if "safety" in message or message in {
        "canceled",
        "emergency_stop",
        "health_not_healthy",
    }:
        return "safety_rejected"
    if "budget" in message or "ceiling" in message:
        return "budget_rejected"
    if "scope" in message or "outside" in message or "protected" in message:
        return "scope_rejected"
    if "admission" in message:
        return "admission_rejected"
    if "policy" in message or "binding" in message:
        return "binding_rejected"
    if "overclaim" in message or "contradict" in message:
        return "overclaim_rejected"
    if "source" in message:
        return "source_rejected"
    return "invalid_state"


def _reject(
    reason: str,
    scope: VerifiedAssessmentScope,
    request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedTargetHealthPolicy,
    clock: ClockObservation,
    safety: TargetHealthSafetySnapshot | None,
    budget: TargetHealthBudgetState | None,
) -> TargetHealthReceipt:
    binding_sha256 = _binding_sha(request.binding)
    if safety is not None and (
        safety.binding_sha256 != binding_sha256
        or safety.execution_request_sha256 != request.request_sha256
    ):
        safety = None
    if budget is not None and (
        budget.binding_sha256 != binding_sha256
        or budget.execution_request_sha256 != request.request_sha256
    ):
        budget = None
    return TargetHealthReceipt(
        status=TargetHealthStatus.REJECTED,
        reason=reason,
        overall_health=None,
        scope_id=scope.scope_id,
        scope_sha256=scope.content_sha256,
        execution_request_id=request.request_id,
        execution_request_sha256=request.request_sha256,
        admission_receipt_id=admission.receipt_id,
        admission_receipt_sha256=admission.receipt_sha256,
        execution_policy_id=request.policy_id,
        execution_policy_sha256=request.policy_sha256,
        runtime_policy_id=policy.policy_id,
        runtime_policy_sha256=policy.policy_sha256,
        binding=request.binding,
        binding_sha256=binding_sha256,
        target_url=policy.target_url,
        observed_at=clock.observed_at,
        monotonic_tick=clock.monotonic_tick,
        safety_attestation=safety,
        safety_attestation_sha256=(None if safety is None else safety.attestation_sha256),
        budget_state=budget,
        budget_state_sha256=None if budget is None else budget.state_sha256,
        source_receipts=(),
        observations=(),
        source_validation_performed=False,
    )


def observe_authorized_target_health(
    *,
    scope: VerifiedAssessmentScope,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedTargetHealthPolicy,
    scope_budget_state: ScopeBudgetState,
    runtime_budget_state: TargetHealthBudgetState | None,
    safety_snapshot: TargetHealthSafetySnapshot | None,
    clock_observation: ClockObservation,
    observations: tuple[TargetHealthObservation, ...],
    boundary_receipts: tuple[BoundaryReceipt, ...],
) -> TargetHealthReceipt:
    """Validate injected evidence and publish one bounded health receipt."""

    for value, expected, label in (
        (scope, VerifiedAssessmentScope, "scope"),
        (execution_request, ExecutionRequest, "execution_request"),
        (admission, AdmissionReceipt, "admission"),
        (policy, AuthorizedTargetHealthPolicy, "policy"),
        (clock_observation, ClockObservation, "clock_observation"),
    ):
        if not isinstance(value, expected):
            raise AuthorizedTargetHealthRuntimeError(f"{label} is invalid")
    try:
        now = _instant(clock_observation.observed_at)
        if execution_request.binding != policy.binding:
            raise AuthorizedTargetHealthRuntimeError("execution binding mismatch")
        if (
            execution_request.binding.scope_id != scope.scope_id
            or execution_request.binding.scope_sha256 != scope.content_sha256
        ):
            raise AuthorizedTargetHealthRuntimeError("execution scope binding mismatch")
        if execution_request.policy_id != policy.execution_policy_id or not hmac.compare_digest(
            execution_request.policy_sha256, policy.execution_policy_sha256
        ):
            raise AuthorizedTargetHealthRuntimeError("execution policy binding mismatch")
        if admission.status is not AdmissionStatus.ADMITTED:
            raise AuthorizedTargetHealthRuntimeError("execution admission is not allowed")
        if (
            admission.request_id != execution_request.request_id
            or not hmac.compare_digest(admission.request_sha256, execution_request.request_sha256)
            or admission.policy_id != execution_request.policy_id
            or not hmac.compare_digest(admission.policy_sha256, execution_request.policy_sha256)
        ):
            raise AuthorizedTargetHealthRuntimeError("admission receipt binding mismatch")
        admission_time = _instant(admission.observed_at)
        if (
            admission_time > now
            or (now - admission_time).total_seconds() > policy.max_admission_age_seconds
        ):
            raise AuthorizedTargetHealthRuntimeError("admission attestation is stale")
        if clock_observation.monotonic_tick < admission.monotonic_tick:
            raise AuthorizedTargetHealthRuntimeError("clock state is invalid")
        if execution_request.operation_code != "authorized_target_health":
            raise AuthorizedTargetHealthRuntimeError("execution operation is invalid")
        if (
            execution_request.attempt_number != 1
            or execution_request.prior_execution_sha256 is not None
        ):
            raise AuthorizedTargetHealthRuntimeError("automatic retries are forbidden")
        expected_size = len(canonical_json(policy.to_dict()).encode("ascii"))
        if (
            execution_request.payload_sha256 != policy.policy_sha256
            or execution_request.payload_size_bytes != expected_size
        ):
            raise AuthorizedTargetHealthRuntimeError("execution policy payload mismatch")
        if not isinstance(scope_budget_state, ScopeBudgetState):
            raise AuthorizedTargetHealthRuntimeError("scope budget state is missing")
        decision = evaluate_request(
            scope,
            url=policy.target_url,
            method=policy.method,
            technique_id=policy.technique_id,
            impact_tier=policy.impact_tier,
            budget_state=scope_budget_state,
            at=now,
        )
        if not decision.allowed:
            raise AuthorizedTargetHealthRuntimeError(f"scope rejected: {decision.reason}")
        if safety_snapshot is None or runtime_budget_state is None:
            raise AuthorizedTargetHealthRuntimeError("missing control attestation")
        if (
            safety_snapshot.binding_sha256 != _binding_sha(execution_request.binding)
            or safety_snapshot.execution_request_sha256 != execution_request.request_sha256
        ):
            raise AuthorizedTargetHealthRuntimeError("safety binding mismatch")
        safety_time = _instant(safety_snapshot.observed_at)
        if (
            safety_time > now
            or now >= _instant(safety_snapshot.expires_at)
            or (now - safety_time).total_seconds() > policy.max_signal_age_seconds
        ):
            raise AuthorizedTargetHealthRuntimeError("safety attestation is stale")
        if safety_snapshot.canceled:
            raise AuthorizedTargetHealthRuntimeError("canceled")
        if safety_snapshot.emergency_stop:
            raise AuthorizedTargetHealthRuntimeError("emergency_stop")
        if safety_snapshot.health is not HealthState.HEALTHY:
            raise AuthorizedTargetHealthRuntimeError("health_not_healthy")
        if (
            runtime_budget_state.binding_sha256 != _binding_sha(execution_request.binding)
            or runtime_budget_state.execution_request_sha256 != execution_request.request_sha256
        ):
            raise AuthorizedTargetHealthRuntimeError("budget binding mismatch")
        budget_time = _instant(runtime_budget_state.observed_at)
        if (
            budget_time > now
            or now >= _instant(runtime_budget_state.expires_at)
            or (now - budget_time).total_seconds() > policy.max_signal_age_seconds
        ):
            raise AuthorizedTargetHealthRuntimeError("budget attestation is stale")
        if not isinstance(observations, tuple) or not observations:
            raise AuthorizedTargetHealthRuntimeError("missing health observations")
        if not isinstance(boundary_receipts, tuple) or not boundary_receipts:
            raise AuthorizedTargetHealthRuntimeError("missing source receipts")
        if len(boundary_receipts) > policy.max_source_receipts:
            raise AuthorizedTargetHealthRuntimeError("source receipt ceiling exceeded")
        evidence_bytes = len(
            canonical_json([item.to_dict() for item in observations]).encode("ascii")
        )
        if runtime_budget_state.requests_used + 1 > policy.request_ceiling:
            raise AuthorizedTargetHealthRuntimeError("request budget exhausted")
        if runtime_budget_state.evidence_bytes_used + evidence_bytes > policy.evidence_byte_ceiling:
            raise AuthorizedTargetHealthRuntimeError("evidence byte budget exhausted")
        if runtime_budget_state.observations_used + len(observations) > policy.observation_ceiling:
            raise AuthorizedTargetHealthRuntimeError("observation budget exhausted")

        references = tuple(
            sorted(
                (
                    _source_reference(item, scope, execution_request.binding)
                    for item in boundary_receipts
                ),
                key=lambda item: (_SOURCE_ORDER.index(item.source_kind), item.receipt_id),
            )
        )
        reference_keys = {
            (item.source_kind, item.receipt_id, item.receipt_sha256): item for item in references
        }
        if len(reference_keys) != len(references):
            raise AuthorizedTargetHealthRuntimeError("source receipt is duplicated")
        if {item.source_kind for item in references} != set(_SOURCE_ORDER):
            raise AuthorizedTargetHealthRuntimeError("missing required boundary source kind")
        for reference in references:
            source_time = _instant(reference.observed_at)
            if (
                source_time > now
                or (now - source_time).total_seconds() > policy.max_signal_age_seconds
            ):
                raise AuthorizedTargetHealthRuntimeError("source receipt is stale")

        normalized = tuple(
            sorted(observations, key=lambda item: _DIMENSION_ORDER.index(item.dimension))
        )
        if tuple(item.dimension for item in normalized) != _DIMENSION_ORDER:
            raise AuthorizedTargetHealthRuntimeError("missing or duplicate health dimension")
        used_keys: set[tuple[BoundarySourceKind, str, str]] = set()
        for item in normalized:
            key = (item.source_kind, item.source_receipt_id, item.source_receipt_sha256)
            reference = reference_keys.get(key)
            if reference is None:
                raise AuthorizedTargetHealthRuntimeError("observation source receipt is missing")
            used_keys.add(key)
            if item.source_kind not in _ALLOWED_SOURCES[item.dimension]:
                raise AuthorizedTargetHealthRuntimeError(
                    "observation source kind is invalid for dimension"
                )
            observed = _instant(item.observed_at)
            expires = _instant(item.expires_at)
            if observed < _instant(reference.observed_at):
                raise AuthorizedTargetHealthRuntimeError("observation predates source attestation")
            if observed > now or now >= expires:
                raise AuthorizedTargetHealthRuntimeError("observation is stale or future")
            if (now - observed).total_seconds() > policy.max_signal_age_seconds:
                raise AuthorizedTargetHealthRuntimeError("observation is stale")
            if (expires - observed).total_seconds() > policy.max_signal_ttl_seconds:
                raise AuthorizedTargetHealthRuntimeError(
                    "observation attestation TTL exceeds policy"
                )
            if item.state is HealthSignalState.HEALTHY and reference.source_status != "completed":
                raise AuthorizedTargetHealthRuntimeError(
                    "healthy observation overclaims a failed source"
                )
            if item.dimension is HealthDimension.LATENCY:
                latency = item.latency_milliseconds
                if latency is None:
                    raise AuthorizedTargetHealthRuntimeError("latency attestation is missing")
                expected = (
                    HealthSignalState.HEALTHY
                    if latency <= policy.healthy_latency_milliseconds
                    else HealthSignalState.DEGRADED
                    if latency <= policy.degraded_latency_milliseconds
                    else HealthSignalState.UNHEALTHY
                )
                if item.state is not expected:
                    raise AuthorizedTargetHealthRuntimeError(
                        "latency state overclaims measured latency"
                    )
        if used_keys != set(reference_keys):
            raise AuthorizedTargetHealthRuntimeError("unreferenced source receipt is forbidden")
        states = {item.dimension: item.state for item in normalized}
        if (
            states[HealthDimension.REACHABILITY] is HealthSignalState.UNHEALTHY
            and states[HealthDimension.SERVICE_HEALTH] is HealthSignalState.HEALTHY
        ):
            raise AuthorizedTargetHealthRuntimeError("service health contradicts reachability")
        overall = max(normalized, key=lambda item: _STATE_RANK[item.state]).state
    except Exception as exc:
        return _reject(
            _reason(exc),
            scope,
            execution_request,
            admission,
            policy,
            clock_observation,
            safety_snapshot,
            runtime_budget_state,
        )

    return TargetHealthReceipt(
        status=TargetHealthStatus.COMPLETED,
        reason=f"observed_{overall.value}",
        overall_health=overall,
        scope_id=scope.scope_id,
        scope_sha256=scope.content_sha256,
        execution_request_id=execution_request.request_id,
        execution_request_sha256=execution_request.request_sha256,
        admission_receipt_id=admission.receipt_id,
        admission_receipt_sha256=admission.receipt_sha256,
        execution_policy_id=execution_request.policy_id,
        execution_policy_sha256=execution_request.policy_sha256,
        runtime_policy_id=policy.policy_id,
        runtime_policy_sha256=policy.policy_sha256,
        binding=execution_request.binding,
        binding_sha256=_binding_sha(execution_request.binding),
        target_url=policy.target_url,
        observed_at=clock_observation.observed_at,
        monotonic_tick=clock_observation.monotonic_tick,
        safety_attestation=safety_snapshot,
        safety_attestation_sha256=safety_snapshot.attestation_sha256,
        budget_state=runtime_budget_state,
        budget_state_sha256=runtime_budget_state.state_sha256,
        source_receipts=references,
        observations=normalized,
        source_validation_performed=True,
    )


_BINDING_FIELDS = {
    "context_id",
    "context_sha256",
    "fence_epoch",
    "lease_id",
    "scope_id",
    "scope_sha256",
    "session_id",
    "target_id",
    "target_sha256",
    "tenant_id",
}
_SOURCE_FIELDS = {
    "admission_receipt_id",
    "admission_receipt_sha256",
    "binding_sha256",
    "boundary_performed",
    "execution_request_id",
    "execution_request_sha256",
    "observed_at",
    "receipt_id",
    "receipt_sha256",
    "reference_sha256",
    "source_kind",
    "source_status",
}
_OBSERVATION_FIELDS = {
    "detail_code",
    "dimension",
    "evidence_sha256",
    "expires_at",
    "kind",
    "latency_milliseconds",
    "observation_id",
    "observation_sha256",
    "observed_at",
    "schema_version",
    "source_kind",
    "source_receipt_id",
    "source_receipt_sha256",
    "state",
}
_SAFETY_ATTESTATION_FIELDS = {
    "binding_sha256",
    "canceled",
    "emergency_stop",
    "execution_request_sha256",
    "expires_at",
    "health",
    "observed_at",
}
_BUDGET_STATE_FIELDS = {
    "binding_sha256",
    "evidence_bytes_used",
    "execution_request_sha256",
    "expires_at",
    "observations_used",
    "observed_at",
    "requests_used",
}
_RECEIPT_FIELDS = {
    "admission_receipt_id",
    "admission_receipt_sha256",
    "authentication_performed",
    "authority_effect",
    "binding",
    "binding_sha256",
    "browser_action_performed",
    "budget_state",
    "budget_state_sha256",
    "claim_scope",
    "enforcement_boundary",
    "execution_policy_id",
    "execution_policy_sha256",
    "execution_request_id",
    "execution_request_sha256",
    "external_call_performed",
    "kind",
    "monotonic_tick",
    "network_call_performed",
    "observations",
    "observed_at",
    "overall_health",
    "qualification_effect",
    "reason",
    "receipt_id",
    "receipt_sha256",
    "runtime_policy_id",
    "runtime_policy_sha256",
    "safety_attestation",
    "safety_attestation_sha256",
    "schema_version",
    "scope_id",
    "scope_sha256",
    "source_receipts",
    "source_validation_performed",
    "status",
    "target_url",
}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizedTargetHealthRuntimeError(f"{label} fields are invalid")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthorizedTargetHealthRuntimeError("receipt JSON contains a duplicate key")
        value[key] = item
    return value


def parse_target_health_receipt(raw: bytes | str | dict[str, Any]) -> TargetHealthReceipt:
    """Parse canonical target-health receipt JSON into its exact immutable record."""

    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthorizedTargetHealthRuntimeError("receipt must be ASCII") from exc
        return parse_target_health_receipt(text)
    if isinstance(raw, str):
        try:
            raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise AuthorizedTargetHealthRuntimeError("receipt must be ASCII") from exc
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_pairs,
                parse_float=lambda _: (_ for _ in ()).throw(
                    AuthorizedTargetHealthRuntimeError("floating-point values are forbidden")
                ),
                parse_constant=lambda _: (_ for _ in ()).throw(
                    AuthorizedTargetHealthRuntimeError("non-finite values are forbidden")
                ),
            )
        except AuthorizedTargetHealthRuntimeError:
            raise
        except json.JSONDecodeError as exc:
            raise AuthorizedTargetHealthRuntimeError("receipt JSON is invalid") from exc
        if raw != canonical_json(value):
            raise AuthorizedTargetHealthRuntimeError("receipt JSON is not canonical")
    elif isinstance(raw, dict):
        value = raw
    else:
        raise AuthorizedTargetHealthRuntimeError("receipt input is invalid")
    data = _exact(value, _RECEIPT_FIELDS, "receipt")
    if data["schema_version"] != SCHEMA_VERSION or data["kind"] != TargetHealthReceipt.KIND:
        raise AuthorizedTargetHealthRuntimeError("receipt type or version is invalid")
    binding = ExecutionBinding(**_exact(data["binding"], _BINDING_FIELDS, "binding"))
    if not isinstance(data["source_receipts"], list):
        raise AuthorizedTargetHealthRuntimeError("source_receipts is invalid")
    source_receipts = tuple(
        BoundaryReceiptReference(
            source_kind=BoundarySourceKind(item["source_kind"]),
            receipt_id=item["receipt_id"],
            receipt_sha256=item["receipt_sha256"],
            execution_request_id=item["execution_request_id"],
            execution_request_sha256=item["execution_request_sha256"],
            admission_receipt_id=item["admission_receipt_id"],
            admission_receipt_sha256=item["admission_receipt_sha256"],
            binding_sha256=item["binding_sha256"],
            source_status=item["source_status"],
            observed_at=item["observed_at"],
            boundary_performed=item["boundary_performed"],
            reference_sha256=item["reference_sha256"],
        )
        for item in (
            _exact(candidate, _SOURCE_FIELDS, "source receipt")
            for candidate in data["source_receipts"]
        )
    )
    if not isinstance(data["observations"], list):
        raise AuthorizedTargetHealthRuntimeError("observations is invalid")
    observations = []
    for candidate in data["observations"]:
        item = _exact(candidate, _OBSERVATION_FIELDS, "observation")
        if item["schema_version"] != SCHEMA_VERSION or item["kind"] != TargetHealthObservation.KIND:
            raise AuthorizedTargetHealthRuntimeError("observation type or version is invalid")
        observations.append(
            TargetHealthObservation(
                dimension=HealthDimension(item["dimension"]),
                state=HealthSignalState(item["state"]),
                detail_code=item["detail_code"],
                source_kind=BoundarySourceKind(item["source_kind"]),
                source_receipt_id=item["source_receipt_id"],
                source_receipt_sha256=item["source_receipt_sha256"],
                evidence_sha256=item["evidence_sha256"],
                observed_at=item["observed_at"],
                expires_at=item["expires_at"],
                latency_milliseconds=item["latency_milliseconds"],
                observation_id=item["observation_id"],
                observation_sha256=item["observation_sha256"],
            )
        )
    safety_data = data["safety_attestation"]
    safety_attestation = (
        None
        if safety_data is None
        else TargetHealthSafetySnapshot(
            binding_sha256=_exact(safety_data, _SAFETY_ATTESTATION_FIELDS, "safety attestation")[
                "binding_sha256"
            ],
            execution_request_sha256=safety_data["execution_request_sha256"],
            health=HealthState(safety_data["health"]),
            canceled=safety_data["canceled"],
            emergency_stop=safety_data["emergency_stop"],
            observed_at=safety_data["observed_at"],
            expires_at=safety_data["expires_at"],
            attestation_sha256=data["safety_attestation_sha256"] or "",
        )
    )
    budget_data = data["budget_state"]
    budget_state = (
        None
        if budget_data is None
        else TargetHealthBudgetState(
            binding_sha256=_exact(budget_data, _BUDGET_STATE_FIELDS, "budget state")[
                "binding_sha256"
            ],
            execution_request_sha256=budget_data["execution_request_sha256"],
            requests_used=budget_data["requests_used"],
            evidence_bytes_used=budget_data["evidence_bytes_used"],
            observations_used=budget_data["observations_used"],
            observed_at=budget_data["observed_at"],
            expires_at=budget_data["expires_at"],
            state_sha256=data["budget_state_sha256"] or "",
        )
    )
    receipt = TargetHealthReceipt(
        status=TargetHealthStatus(data["status"]),
        reason=data["reason"],
        overall_health=(
            None if data["overall_health"] is None else HealthSignalState(data["overall_health"])
        ),
        scope_id=data["scope_id"],
        scope_sha256=data["scope_sha256"],
        execution_request_id=data["execution_request_id"],
        execution_request_sha256=data["execution_request_sha256"],
        admission_receipt_id=data["admission_receipt_id"],
        admission_receipt_sha256=data["admission_receipt_sha256"],
        execution_policy_id=data["execution_policy_id"],
        execution_policy_sha256=data["execution_policy_sha256"],
        runtime_policy_id=data["runtime_policy_id"],
        runtime_policy_sha256=data["runtime_policy_sha256"],
        binding=binding,
        binding_sha256=data["binding_sha256"],
        target_url=data["target_url"],
        observed_at=data["observed_at"],
        monotonic_tick=data["monotonic_tick"],
        safety_attestation=safety_attestation,
        safety_attestation_sha256=data["safety_attestation_sha256"],
        budget_state=budget_state,
        budget_state_sha256=data["budget_state_sha256"],
        source_receipts=source_receipts,
        observations=tuple(observations),
        source_validation_performed=data["source_validation_performed"],
        external_call_performed=data["external_call_performed"],
        network_call_performed=data["network_call_performed"],
        browser_action_performed=data["browser_action_performed"],
        authentication_performed=data["authentication_performed"],
        authority_effect=data["authority_effect"],
        qualification_effect=data["qualification_effect"],
        claim_scope=data["claim_scope"],
        enforcement_boundary=data["enforcement_boundary"],
        receipt_id=data["receipt_id"],
        receipt_sha256=data["receipt_sha256"],
    )
    if receipt.to_dict() != data:
        raise AuthorizedTargetHealthRuntimeError("receipt content address is invalid")
    return receipt


def verify_target_health_receipt(raw: bytes | str | dict[str, Any]) -> MappingProxyType:
    """Strictly verify a receipt while preserving the established mapping result."""

    return MappingProxyType(parse_target_health_receipt(raw).to_dict())


__all__ = [
    "AuthorizedTargetHealthPolicy",
    "AuthorizedTargetHealthRuntimeError",
    "BoundaryReceiptReference",
    "BoundarySourceKind",
    "HealthDimension",
    "HealthSignalState",
    "TargetHealthBudgetState",
    "TargetHealthObservation",
    "TargetHealthReceipt",
    "TargetHealthSafetySnapshot",
    "TargetHealthStatus",
    "observe_authorized_target_health",
    "parse_target_health_receipt",
    "verify_target_health_receipt",
]
