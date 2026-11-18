"""Repository-only conformance evidence for target-facing adapters.

The suite records deterministic observations collected by an external runner.
It performs no target interaction and grants no authority or qualification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"
EXECUTION_SCOPE = "repository_only_offline_adapter_conformance"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")


class TargetAdapterConformanceError(ValueError):
    """Raised when conformance evidence is incomplete or malformed."""


class AdapterStopRequested(RuntimeError):
    """Raised when a shared cancellation or emergency-stop signal is active."""

    def __init__(self, code: str) -> None:
        _code(code, "stop code")
        self.code = code
        super().__init__(code)


class AdapterStopState:
    """Thread-safe local stop signal shared with injected reference adapters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._code: str | None = None

    def cancel(self) -> None:
        with self._lock:
            self._code = "canceled"

    def emergency_stop(self) -> None:
        with self._lock:
            self._code = "emergency_stop"

    def check(self) -> None:
        with self._lock:
            code = self._code
        if code is not None:
            raise AdapterStopRequested(code)

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._code is not None

    @property
    def code(self) -> str | None:
        with self._lock:
            return self._code


class TargetAdapterRequirement(StrEnum):
    """Closed requirements for repository reference target adapters."""

    DNS_REBINDING_REJECTED = "dns_rebinding_rejected"
    TLS_ORIGIN_EXACT = "tls_origin_exact"
    REDIRECT_REAUTHORIZATION_REQUIRED = "redirect_reauthorization_required"
    REQUEST_RESPONSE_LIMITS = "request_response_limits"
    STOP_PROPAGATION = "stop_propagation"
    OPAQUE_SESSION_SECRET_BOUNDARY = "opaque_session_secret_boundary"
    MFA_CHALLENGE_SUSPENDS = "mfa_challenge_suspends"
    LEASE_REVOCATION_REJECTED = "lease_revocation_rejected"
    SIGNED_HEALTH_CHAIN = "signed_health_chain"
    UNHEALTHY_TARGET_PAUSE_PROPOSED = "unhealthy_target_pause_proposed"
    EXISTING_AUTHORITY_CONTRACTS_REUSED = "existing_authority_contracts_reused"
    ADAPTER_CANNOT_SELF_AUTHORIZE = "adapter_cannot_self_authorize"
    DETERMINISTIC_TRANSPORT_ONLY = "deterministic_transport_only"
    LIVE_QUALIFICATION_EXTERNAL = "live_qualification_external"


REQUIRED_REQUIREMENTS = tuple(TargetAdapterRequirement)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise TargetAdapterConformanceError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": body, "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise TargetAdapterConformanceError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TargetAdapterConformanceError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise TargetAdapterConformanceError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class TargetAdapterConformanceObservation:
    """One externally collected deterministic requirement observation."""

    requirement: TargetAdapterRequirement
    passed: bool
    evidence_sha256: str
    outcome_code: str
    network_call_performed: bool = False
    authority_effect: str = AUTHORITY_EFFECT
    qualification_effect: str = QUALIFICATION_EFFECT
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "target_adapter_conformance_observation"

    def __post_init__(self) -> None:
        try:
            requirement = TargetAdapterRequirement(self.requirement)
        except (TypeError, ValueError) as exc:
            raise TargetAdapterConformanceError("requirement is invalid") from exc
        object.__setattr__(self, "requirement", requirement)
        if not isinstance(self.passed, bool):
            raise TargetAdapterConformanceError("passed must be a boolean")
        _digest(self.evidence_sha256, "evidence_sha256")
        _code(self.outcome_code, "outcome_code")
        expected_outcome = "passed" if self.passed else "failed"
        if self.outcome_code != expected_outcome:
            raise TargetAdapterConformanceError("outcome_code is inconsistent")
        if self.network_call_performed is not False:
            raise TargetAdapterConformanceError("repository conformance cannot claim network use")
        if self.authority_effect != AUTHORITY_EFFECT:
            raise TargetAdapterConformanceError("observation cannot grant authority")
        if self.qualification_effect != QUALIFICATION_EFFECT:
            raise TargetAdapterConformanceError("observation cannot grant qualification")
        identity, digest = _identity("TAO", self.KIND, self.body())
        if self.observation_id and self.observation_id != identity:
            raise TargetAdapterConformanceError("observation_id does not match content")
        if self.observation_sha256 and not hmac.compare_digest(
            self.observation_sha256, digest
        ):
            raise TargetAdapterConformanceError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", identity)
        object.__setattr__(self, "observation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "authority_effect": self.authority_effect,
            "evidence_sha256": self.evidence_sha256,
            "network_call_performed": self.network_call_performed,
            "outcome_code": self.outcome_code,
            "passed": self.passed,
            "qualification_effect": self.qualification_effect,
            "requirement": self.requirement.value,
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
class TargetAdapterConformanceReport:
    """Complete nonqualifying report over the closed requirement set."""

    adapter_id: str
    adapter_release_sha256: str
    observations: tuple[TargetAdapterConformanceObservation, ...]
    status: str
    execution_scope: str = EXECUTION_SCOPE
    network_call_performed: bool = False
    authority_effect: str = AUTHORITY_EFFECT
    qualification_effect: str = QUALIFICATION_EFFECT
    live_deployment_qualified: bool = False
    report_id: str = ""
    report_sha256: str = ""

    KIND: ClassVar[str] = "target_adapter_conformance_report"

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "adapter_id")
        _digest(self.adapter_release_sha256, "adapter_release_sha256")
        if not isinstance(self.observations, tuple) or not all(
            isinstance(item, TargetAdapterConformanceObservation) for item in self.observations
        ):
            raise TargetAdapterConformanceError("observations are invalid")
        ordered = tuple(sorted(self.observations, key=lambda item: item.requirement.value))
        if self.observations != ordered:
            raise TargetAdapterConformanceError("observations must be canonical")
        requirements = tuple(item.requirement for item in ordered)
        if len(set(requirements)) != len(requirements):
            raise TargetAdapterConformanceError("requirements must be unique")
        if set(requirements) != set(REQUIRED_REQUIREMENTS):
            raise TargetAdapterConformanceError("report must cover every requirement")
        expected_status = (
            "passed_repository_conformance"
            if all(item.passed for item in ordered)
            else "failed_repository_conformance"
        )
        if self.status != expected_status:
            raise TargetAdapterConformanceError("report status is inconsistent")
        if self.execution_scope != EXECUTION_SCOPE:
            raise TargetAdapterConformanceError("execution_scope is invalid")
        if self.network_call_performed is not False:
            raise TargetAdapterConformanceError("repository report cannot claim network use")
        if self.authority_effect != AUTHORITY_EFFECT:
            raise TargetAdapterConformanceError("report cannot grant authority")
        if self.qualification_effect != QUALIFICATION_EFFECT:
            raise TargetAdapterConformanceError("report cannot grant qualification")
        if self.live_deployment_qualified is not False:
            raise TargetAdapterConformanceError("repository report cannot qualify deployment")
        identity, digest = _identity("TAR", self.KIND, self.body())
        if self.report_id and self.report_id != identity:
            raise TargetAdapterConformanceError("report_id does not match content")
        if self.report_sha256 and not hmac.compare_digest(self.report_sha256, digest):
            raise TargetAdapterConformanceError("report_sha256 does not match content")
        object.__setattr__(self, "report_id", identity)
        object.__setattr__(self, "report_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_release_sha256": self.adapter_release_sha256,
            "authority_effect": self.authority_effect,
            "execution_scope": self.execution_scope,
            "live_deployment_qualified": self.live_deployment_qualified,
            "network_call_performed": self.network_call_performed,
            "observations": [item.to_dict() for item in self.observations],
            "qualification_effect": self.qualification_effect,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "schema_version": SCHEMA_VERSION,
        }


def build_target_adapter_conformance_report(
    *,
    adapter_id: str,
    adapter_release_sha256: str,
    observations: Iterable[TargetAdapterConformanceObservation],
) -> TargetAdapterConformanceReport:
    """Build a canonical complete report without executing an adapter."""

    values = tuple(sorted(tuple(observations), key=lambda item: item.requirement.value))
    status = (
        "passed_repository_conformance"
        if values and all(item.passed for item in values)
        else "failed_repository_conformance"
    )
    return TargetAdapterConformanceReport(
        adapter_id=adapter_id,
        adapter_release_sha256=adapter_release_sha256,
        observations=values,
        status=status,
    )


_OBSERVATION_FIELDS = {
    "authority_effect",
    "evidence_sha256",
    "kind",
    "network_call_performed",
    "observation_id",
    "observation_sha256",
    "outcome_code",
    "passed",
    "qualification_effect",
    "requirement",
    "schema_version",
}
_REPORT_FIELDS = {
    "adapter_id",
    "adapter_release_sha256",
    "authority_effect",
    "execution_scope",
    "kind",
    "live_deployment_qualified",
    "network_call_performed",
    "observations",
    "qualification_effect",
    "report_id",
    "report_sha256",
    "schema_version",
    "status",
}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TargetAdapterConformanceError("report JSON contains a duplicate key")
        result[key] = value
    return result


def verify_target_adapter_conformance_report(
    raw: bytes | str | dict[str, Any],
) -> MappingProxyType:
    """Strictly verify one report and return its canonical mapping."""

    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise TargetAdapterConformanceError("report must be ASCII") from exc
        try:
            value = json.loads(text, object_pairs_hook=_pairs)
        except json.JSONDecodeError as exc:
            raise TargetAdapterConformanceError("report JSON is invalid") from exc
        if canonical_json(value) != text:
            raise TargetAdapterConformanceError("report JSON is not canonical")
    elif isinstance(raw, str):
        if not raw.isascii():
            raise TargetAdapterConformanceError("report must be ASCII")
        try:
            value = json.loads(raw, object_pairs_hook=_pairs)
        except json.JSONDecodeError as exc:
            raise TargetAdapterConformanceError("report JSON is invalid") from exc
        if canonical_json(value) != raw:
            raise TargetAdapterConformanceError("report JSON is not canonical")
    else:
        value = raw
    if not isinstance(value, dict) or set(value) != _REPORT_FIELDS:
        raise TargetAdapterConformanceError("report fields are invalid")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["kind"] != TargetAdapterConformanceReport.KIND
    ):
        raise TargetAdapterConformanceError("report version or kind is invalid")
    raw_observations = value["observations"]
    if not isinstance(raw_observations, list):
        raise TargetAdapterConformanceError("observations must be a list")
    observations: list[TargetAdapterConformanceObservation] = []
    for raw_observation in raw_observations:
        if not isinstance(raw_observation, dict) or set(raw_observation) != _OBSERVATION_FIELDS:
            raise TargetAdapterConformanceError("observation fields are invalid")
        if (
            raw_observation["schema_version"] != SCHEMA_VERSION
            or raw_observation["kind"] != TargetAdapterConformanceObservation.KIND
        ):
            raise TargetAdapterConformanceError("observation version or kind is invalid")
        observations.append(
            TargetAdapterConformanceObservation(
                requirement=raw_observation["requirement"],
                passed=raw_observation["passed"],
                evidence_sha256=raw_observation["evidence_sha256"],
                outcome_code=raw_observation["outcome_code"],
                network_call_performed=raw_observation["network_call_performed"],
                authority_effect=raw_observation["authority_effect"],
                qualification_effect=raw_observation["qualification_effect"],
                observation_id=raw_observation["observation_id"],
                observation_sha256=raw_observation["observation_sha256"],
            )
        )
    report = TargetAdapterConformanceReport(
        adapter_id=value["adapter_id"],
        adapter_release_sha256=value["adapter_release_sha256"],
        observations=tuple(observations),
        status=value["status"],
        execution_scope=value["execution_scope"],
        network_call_performed=value["network_call_performed"],
        authority_effect=value["authority_effect"],
        qualification_effect=value["qualification_effect"],
        live_deployment_qualified=value["live_deployment_qualified"],
        report_id=value["report_id"],
        report_sha256=value["report_sha256"],
    )
    if report.to_dict() != value:
        raise TargetAdapterConformanceError("report content address is invalid")
    return MappingProxyType(report.to_dict())


__all__ = [
    "AdapterStopRequested",
    "AdapterStopState",
    "AUTHORITY_EFFECT",
    "EXECUTION_SCOPE",
    "NO_BUILTIN_IO",
    "QUALIFICATION_EFFECT",
    "REQUIRED_REQUIREMENTS",
    "TargetAdapterConformanceError",
    "TargetAdapterConformanceObservation",
    "TargetAdapterConformanceReport",
    "TargetAdapterRequirement",
    "build_target_adapter_conformance_report",
    "canonical_json",
    "canonical_sha256",
    "verify_target_adapter_conformance_report",
]
