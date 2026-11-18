"""Fail-closed authorized target-session acquisition boundary.

The runtime joins verified assessment scope, execution-control admission, and
opaque credential lease evidence before calling an injected session provider
once. It never resolves, receives, stores, serializes, or hashes credential
material. No concrete identity, browser, network, or credential adapter is
included.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol
from urllib.parse import urlsplit

from .assessment_transport_contracts import TargetSessionIntent, canonical_json
from .credential_broker_contracts import CredentialLease, LeaseMode
from .execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
)
from .signed_scope_compiler import ScopeBudgetState, VerifiedAssessmentScope, evaluate_request

SCHEMA_VERSION = 1
ENFORCEMENT_BOUNDARY = "injected_credential_session_provider_only"
MAX_SESSION_TTL_SECONDS = 900
MAX_TRANSCRIPT_EVENTS = 32

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
CODE_RE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|taskref|principalref|targetref|techniqueref|"
    r"purposeref|scoperef|sessionref|obligationref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|cookie|otp|magic[_-]?link)\s*[:=])",
    re.IGNORECASE,
)


class AuthorizedTargetSessionRuntimeError(ValueError):
    """Raised when target-session evidence is malformed or ambiguous."""


class SessionAcquisitionStatus(StrEnum):
    """Closed terminal state vocabulary."""

    REJECTED_BEFORE_AUTHENTICATION = "rejected_before_authentication"
    PROVIDER_FAILED = "provider_failed"
    POSTCONDITION_REJECTED = "postcondition_rejected"
    COMPLETED = "completed"


class CleanupStatus(StrEnum):
    """Truthful cleanup state at receipt publication time."""

    NOT_REQUIRED_BEFORE_PROVIDER = "not_required_before_provider"
    PENDING_EXTERNAL_VERIFICATION = "pending_external_verification"


class RevocationStatus(StrEnum):
    """Truthful lease revocation state at receipt publication time."""

    NOT_CHECKED = "not_checked"
    CHECKED_NOT_REVOKED = "checked_not_revoked"
    CHECKED_NOT_REVOKED_AFTER_AUTHENTICATION = "checked_not_revoked_after_authentication"
    REVOKED = "revoked"
    CHECK_FAILED = "check_failed"


class LeaseUseReservationStatus(StrEnum):
    """Truthful atomic lease-use state at receipt publication time."""

    NOT_RESERVED = "not_reserved"
    COMPLETED = "completed"
    COMPLETION_FAILED = "completion_failed"


class CredentialSessionProviderFailure(RuntimeError):
    """Known provider failure carrying only a stable non-secret code."""

    def __init__(self, code: str) -> None:
        self.code = _code(code, "provider failure code")
        super().__init__(self.code)


class LeaseUseStoreFailure(RuntimeError):
    """Known atomic lease-use store failure with a stable non-secret code."""

    def __init__(self, code: str) -> None:
        self.code = _code(code, "lease-use store failure code")
        super().__init__(self.code)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(canonical_json(value).encode("ascii"))


def _identity(prefix: str, kind: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = _canonical_sha({"body": body, "kind": kind, "schema_version": SCHEMA_VERSION})
    return f"{prefix}-{digest.split(':', 1)[1][:32].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    return value


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise AuthorizedTargetSessionRuntimeError(f"{label} has an invalid namespace")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is not canonical")
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _ascii(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AuthorizedTargetSessionRuntimeError(f"{label} is invalid")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise AuthorizedTargetSessionRuntimeError(f"{label} must be visible ASCII")
    if SECRET_RE.search(value):
        raise AuthorizedTargetSessionRuntimeError(f"{label} resembles secret material")
    return value


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizedTargetSessionRuntimeError(f"{label} fields are invalid")
    return value


def _binding_sha(binding: ExecutionBinding) -> str:
    return _canonical_sha(binding.to_dict())


def _https_origin(value: str, label: str) -> str:
    _ascii(value, label, 2048)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AuthorizedTargetSessionRuntimeError(f"{label} must be an absolute HTTPS URL")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise AuthorizedTargetSessionRuntimeError(f"{label} has an invalid port") from exc
    host = parsed.hostname.lower()
    if parsed.hostname != host or parsed.path == "":
        raise AuthorizedTargetSessionRuntimeError(f"{label} is not canonical")
    origin = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    if value != origin and not value.startswith(origin + "/"):
        raise AuthorizedTargetSessionRuntimeError(f"{label} origin is ambiguous")
    return origin


@dataclass(frozen=True, slots=True)
class OpaqueLeaseBinding:
    """Exact deployment-supplied lease binding without credential material."""

    lease_id: str
    lease_sha256: str
    tenant_ref: str
    assessment_ref: str
    task_ref: str
    subject_principal_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    scope_refs: tuple[str, ...]
    lease_mode: LeaseMode
    session_ref: str | None
    issued_at: str
    expires_at: str
    max_uses: int
    binding_id: str = ""
    binding_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_session_opaque_lease_binding"

    def __post_init__(self) -> None:
        _identifier(self.lease_id, "lease_id")
        _digest(self.lease_sha256, "lease_sha256")
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("task_ref", "taskref"),
            ("subject_principal_ref", "principalref"),
            ("target_ref", "targetref"),
            ("technique_ref", "techniqueref"),
            ("purpose_ref", "purposeref"),
        ):
            _reference(getattr(self, name), name, namespace)
        if not isinstance(self.scope_refs, tuple) or not self.scope_refs:
            raise AuthorizedTargetSessionRuntimeError("scope_refs must be a non-empty tuple")
        scopes = tuple(
            sorted(_reference(item, "scope_ref", "scoperef") for item in self.scope_refs)
        )
        if len(set(scopes)) != len(scopes):
            raise AuthorizedTargetSessionRuntimeError("scope_refs must be unique")
        object.__setattr__(self, "scope_refs", scopes)
        try:
            mode = LeaseMode(self.lease_mode)
        except (TypeError, ValueError) as exc:
            raise AuthorizedTargetSessionRuntimeError("lease_mode is invalid") from exc
        object.__setattr__(self, "lease_mode", mode)
        if self.session_ref is not None:
            _reference(self.session_ref, "session_ref", "sessionref")
        if mode is LeaseMode.ONE_TIME and (self.session_ref is not None or self.max_uses != 1):
            raise AuthorizedTargetSessionRuntimeError("one_time lease binding is invalid")
        if mode is LeaseMode.SESSION_BOUND and self.session_ref is None:
            raise AuthorizedTargetSessionRuntimeError("session_bound lease requires session_ref")
        _integer(self.max_uses, "max_uses", 1, 100)
        _utc(self.issued_at, "issued_at")
        _utc(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.issued_at):
            raise AuthorizedTargetSessionRuntimeError("lease binding must expire after issuance")
        binding_id, digest = _identity("OLB", self.KIND, self.body())
        if self.binding_id and self.binding_id != binding_id:
            raise AuthorizedTargetSessionRuntimeError("binding_id does not match content")
        if self.binding_sha256 and self.binding_sha256 != digest:
            raise AuthorizedTargetSessionRuntimeError("binding_sha256 does not match content")
        object.__setattr__(self, "binding_id", binding_id)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "lease_id": self.lease_id,
            "lease_mode": self.lease_mode.value,
            "lease_sha256": self.lease_sha256,
            "max_uses": self.max_uses,
            "purpose_ref": self.purpose_ref,
            "scope_refs": list(self.scope_refs),
            "session_ref": self.session_ref,
            "subject_principal_ref": self.subject_principal_ref,
            "target_ref": self.target_ref,
            "task_ref": self.task_ref,
            "technique_ref": self.technique_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class AuthorizedTargetSessionPolicy:
    """Exact session runtime binding and obligation policy."""

    execution_binding: ExecutionBinding
    execution_policy_id: str
    execution_policy_sha256: str
    assessment_ref: str
    task_ref: str
    scope_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    login_origin: str
    cleanup_obligation_ref: str
    revocation_obligation_ref: str
    max_session_ttl_seconds: int
    policy_id: str = ""
    policy_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_session_policy"

    def __post_init__(self) -> None:
        if not isinstance(self.execution_binding, ExecutionBinding):
            raise AuthorizedTargetSessionRuntimeError("execution_binding is invalid")
        _identifier(self.execution_policy_id, "execution_policy_id")
        _digest(self.execution_policy_sha256, "execution_policy_sha256")
        for name, namespace in (
            ("assessment_ref", "assessmentref"),
            ("task_ref", "taskref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
            ("technique_ref", "techniqueref"),
            ("purpose_ref", "purposeref"),
            ("cleanup_obligation_ref", "obligationref"),
            ("revocation_obligation_ref", "obligationref"),
        ):
            _reference(getattr(self, name), name, namespace)
        origin = _https_origin(self.login_origin + "/", "login_origin")
        if self.login_origin != origin:
            raise AuthorizedTargetSessionRuntimeError("login_origin must contain only an origin")
        object.__setattr__(self, "login_origin", origin)
        _integer(
            self.max_session_ttl_seconds,
            "max_session_ttl_seconds",
            1,
            MAX_SESSION_TTL_SECONDS,
        )
        policy_id, digest = _identity("ATSP", self.KIND, self.body())
        if self.policy_id and self.policy_id != policy_id:
            raise AuthorizedTargetSessionRuntimeError("policy_id does not match content")
        if self.policy_sha256 and self.policy_sha256 != digest:
            raise AuthorizedTargetSessionRuntimeError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_id", policy_id)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "cleanup_obligation_ref": self.cleanup_obligation_ref,
            "execution_binding": self.execution_binding.to_dict(),
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "login_origin": self.login_origin,
            "max_session_ttl_seconds": self.max_session_ttl_seconds,
            "purpose_ref": self.purpose_ref,
            "revocation_obligation_ref": self.revocation_obligation_ref,
            "scope_ref": self.scope_ref,
            "target_ref": self.target_ref,
            "task_ref": self.task_ref,
            "technique_ref": self.technique_ref,
        }


@dataclass(frozen=True, slots=True)
class TargetSessionSafetySnapshot:
    """Request-bound health and stop state from injected infrastructure."""

    binding_sha256: str
    request_sha256: str
    health: HealthState
    canceled: bool
    emergency_stop: bool

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "safety binding_sha256")
        _digest(self.request_sha256, "safety request_sha256")
        if not isinstance(self.health, HealthState):
            raise AuthorizedTargetSessionRuntimeError("safety health is invalid")
        if not isinstance(self.canceled, bool) or not isinstance(self.emergency_stop, bool):
            raise AuthorizedTargetSessionRuntimeError("safety flags are invalid")


class TargetSessionRuntimeClock(Protocol):
    def observe(self) -> ClockObservation: ...


class TargetSessionSafetyMonitor(Protocol):
    def observe(self) -> TargetSessionSafetySnapshot: ...


@dataclass(frozen=True, slots=True)
class RevocationObservation:
    """Exact lease revocation observation without provider data."""

    lease_id: str
    lease_sha256: str
    revoked: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.lease_id, "revocation lease_id")
        _digest(self.lease_sha256, "revocation lease_sha256")
        if not isinstance(self.revoked, bool):
            raise AuthorizedTargetSessionRuntimeError("revocation flag is invalid")
        _digest(self.evidence_sha256, "revocation evidence_sha256")


class LeaseRevocationChecker(Protocol):
    def observe(self, lease_id: str, lease_sha256: str) -> RevocationObservation: ...


@dataclass(frozen=True, slots=True)
class LeaseUseReservationRequest:
    """Exact lease, request, and session tuple that must be reserved atomically."""

    lease_id: str
    lease_sha256: str
    lease_binding_sha256: str
    lease_use_number: int
    lease_mode: LeaseMode
    execution_request_id: str
    execution_request_sha256: str
    execution_binding_sha256: str
    requested_session_id: str
    reservation_key_sha256: str = ""

    def __post_init__(self) -> None:
        _identifier(self.lease_id, "reservation lease_id")
        for name in (
            "lease_sha256",
            "lease_binding_sha256",
            "execution_request_sha256",
            "execution_binding_sha256",
        ):
            _digest(getattr(self, name), name)
        _integer(self.lease_use_number, "reservation lease_use_number", 1, 100)
        try:
            mode = LeaseMode(self.lease_mode)
        except (TypeError, ValueError) as exc:
            raise AuthorizedTargetSessionRuntimeError("reservation lease_mode is invalid") from exc
        object.__setattr__(self, "lease_mode", mode)
        _identifier(self.execution_request_id, "reservation execution_request_id")
        _identifier(self.requested_session_id, "reservation requested_session_id")
        expected = _canonical_sha(self.body())
        if self.reservation_key_sha256 and self.reservation_key_sha256 != expected:
            raise AuthorizedTargetSessionRuntimeError(
                "reservation_key_sha256 does not match content"
            )
        object.__setattr__(self, "reservation_key_sha256", expected)

    def body(self) -> dict[str, Any]:
        return {
            "execution_binding_sha256": self.execution_binding_sha256,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "lease_binding_sha256": self.lease_binding_sha256,
            "lease_id": self.lease_id,
            "lease_mode": self.lease_mode.value,
            "lease_sha256": self.lease_sha256,
            "lease_use_number": self.lease_use_number,
            "requested_session_id": self.requested_session_id,
        }


@dataclass(frozen=True, slots=True)
class LeaseUseReservationEvidence:
    """Store evidence that one exact lease-use tuple was reserved."""

    reservation_key_sha256: str
    reservation_id: str = ""
    reservation_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_session_lease_use_reservation"

    def __post_init__(self) -> None:
        _digest(self.reservation_key_sha256, "reservation_key_sha256")
        reservation_id, reservation_sha256 = _identity(
            "LUR",
            self.KIND,
            {"reservation_key_sha256": self.reservation_key_sha256},
        )
        if self.reservation_id and self.reservation_id != reservation_id:
            raise AuthorizedTargetSessionRuntimeError("reservation_id does not match content")
        if self.reservation_sha256 and self.reservation_sha256 != reservation_sha256:
            raise AuthorizedTargetSessionRuntimeError("reservation_sha256 does not match content")
        object.__setattr__(self, "reservation_id", reservation_id)
        object.__setattr__(self, "reservation_sha256", reservation_sha256)


@dataclass(frozen=True, slots=True)
class LeaseUseCompletionEvidence:
    """Store evidence that a reserved use reached one terminal outcome."""

    reservation_id: str
    reservation_sha256: str
    reservation_key_sha256: str
    outcome: str
    provider_called: bool
    completion_sha256: str = ""

    def __post_init__(self) -> None:
        _identifier(self.reservation_id, "completion reservation_id")
        _digest(self.reservation_sha256, "completion reservation_sha256")
        _digest(self.reservation_key_sha256, "completion reservation_key_sha256")
        _code(self.outcome, "lease-use completion outcome")
        if self.provider_called is not True and not (
            self.provider_called is False and self.outcome == "rejected_before_authentication"
        ):
            raise AuthorizedTargetSessionRuntimeError(
                "zero-call completion requires rejection before authentication"
            )
        expected = _canonical_sha(self.body())
        if self.completion_sha256 and self.completion_sha256 != expected:
            raise AuthorizedTargetSessionRuntimeError("completion_sha256 does not match content")
        object.__setattr__(self, "completion_sha256", expected)

    def body(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "provider_called": self.provider_called,
            "reservation_id": self.reservation_id,
            "reservation_key_sha256": self.reservation_key_sha256,
            "reservation_sha256": self.reservation_sha256,
        }


class AtomicLeaseUseStore(Protocol):
    """Injected compare-and-set boundary for lease use and completion."""

    def reserve(self, request: LeaseUseReservationRequest) -> LeaseUseReservationEvidence: ...

    def complete(
        self,
        reservation: LeaseUseReservationEvidence,
        outcome: str,
        provider_called: bool,
    ) -> LeaseUseCompletionEvidence: ...


@dataclass(frozen=True, slots=True)
class CredentialSessionCommand:
    """One internal-authentication command carrying only an opaque reference."""

    intent_sha256: str
    execution_request_sha256: str
    runtime_policy_sha256: str
    lease_id: str
    lease_sha256: str
    lease_use_number: int
    credential_reference: str = field(repr=False)
    login_url: str
    method: str
    authentication_mode: str
    requested_session_id: str
    principal_label: str
    maximum_attempts: int = 1
    retries_allowed: bool = False

    def __post_init__(self) -> None:
        for name in ("intent_sha256", "execution_request_sha256", "runtime_policy_sha256"):
            _digest(getattr(self, name), name)
        _identifier(self.lease_id, "lease_id")
        _digest(self.lease_sha256, "lease_sha256")
        _integer(self.lease_use_number, "lease_use_number", 1, 100)
        if not isinstance(
            self.credential_reference, str
        ) or not self.credential_reference.startswith("credref:"):
            raise AuthorizedTargetSessionRuntimeError("credential_reference is not opaque")
        _ascii(self.credential_reference, "credential_reference", 256)
        _https_origin(self.login_url, "login_url")
        if self.method not in {"GET", "POST"}:
            raise AuthorizedTargetSessionRuntimeError("authentication method is invalid")
        _code(self.authentication_mode, "authentication_mode")
        _identifier(self.requested_session_id, "requested_session_id")
        _reference(self.principal_label, "principal_label", "principalref")
        if self.maximum_attempts != 1 or self.retries_allowed is not False:
            raise AuthorizedTargetSessionRuntimeError("authentication must allow one attempt")

    def to_provider_dict(self) -> dict[str, Any]:
        """Return provider input metadata with the opaque reference included."""

        return {
            **self.to_audit_dict(),
            "credential_reference": self.credential_reference,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Return safe evidence without serializing the opaque reference."""

        return {
            "authentication_mode": self.authentication_mode,
            "credential_reference_sha256": _sha(self.credential_reference.encode("ascii")),
            "execution_request_sha256": self.execution_request_sha256,
            "intent_sha256": self.intent_sha256,
            "lease_id": self.lease_id,
            "lease_sha256": self.lease_sha256,
            "lease_use_number": self.lease_use_number,
            "login_url_sha256": _sha(self.login_url.encode("ascii")),
            "maximum_attempts": self.maximum_attempts,
            "method": self.method,
            "principal_label": self.principal_label,
            "requested_session_id": self.requested_session_id,
            "retries_allowed": self.retries_allowed,
            "runtime_policy_sha256": self.runtime_policy_sha256,
        }


@dataclass(frozen=True, slots=True)
class CredentialSessionResult:
    """Provider result containing attestations and no credential material."""

    succeeded: bool
    failure_code: str | None
    session_id: str | None
    principal_label: str | None
    isolated: bool
    expires_at: str | None
    authentication_attempts: int
    session_attestation_sha256: str | None
    principal_attestation_sha256: str | None
    cleanup_obligation_ref: str | None
    revocation_obligation_ref: str | None
    credential_material_returned: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.succeeded, bool):
            raise AuthorizedTargetSessionRuntimeError("provider success flag is invalid")
        _integer(self.authentication_attempts, "authentication_attempts", 1, 1)
        if not isinstance(self.isolated, bool) or self.credential_material_returned is not False:
            raise AuthorizedTargetSessionRuntimeError("provider result contains unsafe flags")
        if self.succeeded:
            if self.failure_code is not None:
                raise AuthorizedTargetSessionRuntimeError("successful result has failure_code")
            _identifier(self.session_id, "result session_id")
            _reference(self.principal_label, "result principal_label", "principalref")
            _utc(self.expires_at, "result expires_at")
            _digest(self.session_attestation_sha256, "session_attestation_sha256")
            _digest(self.principal_attestation_sha256, "principal_attestation_sha256")
            _reference(self.cleanup_obligation_ref, "cleanup_obligation_ref", "obligationref")
            _reference(
                self.revocation_obligation_ref,
                "revocation_obligation_ref",
                "obligationref",
            )
        else:
            _code(self.failure_code, "failure_code")
            if any(
                item is not None
                for item in (
                    self.session_id,
                    self.principal_label,
                    self.expires_at,
                    self.session_attestation_sha256,
                    self.principal_attestation_sha256,
                    self.cleanup_obligation_ref,
                    self.revocation_obligation_ref,
                )
            ):
                raise AuthorizedTargetSessionRuntimeError(
                    "failed provider result must not claim a session"
                )


class CredentialSessionProvider(Protocol):
    def acquire(self, command: CredentialSessionCommand) -> CredentialSessionResult: ...


def session_attestation_sha256(command: CredentialSessionCommand, expires_at: str) -> str:
    """Compute the exact expected isolated-session attestation digest."""

    _utc(expires_at, "expires_at")
    return _canonical_sha(
        {
            "intent_sha256": command.intent_sha256,
            "isolated": True,
            "lease_sha256": command.lease_sha256,
            "principal_label": command.principal_label,
            "requested_session_id": command.requested_session_id,
            "expires_at": expires_at,
        }
    )


def principal_attestation_sha256(command: CredentialSessionCommand) -> str:
    """Compute the expected principal-to-lease attestation digest."""

    return _canonical_sha(
        {
            "intent_sha256": command.intent_sha256,
            "lease_sha256": command.lease_sha256,
            "lease_use_number": command.lease_use_number,
            "principal_label": command.principal_label,
        }
    )


@dataclass(frozen=True, slots=True)
class SessionTranscriptEvent:
    """One hash-chained session acquisition checkpoint."""

    sequence: int
    stage: str
    detail_sha256: str
    observed_at: str
    monotonic_tick: int
    previous_event_sha256: str | None
    event_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_session_transcript_event"

    def __post_init__(self) -> None:
        _integer(self.sequence, "event sequence", 1, MAX_TRANSCRIPT_EVENTS)
        _code(self.stage, "event stage")
        _digest(self.detail_sha256, "event detail_sha256")
        _utc(self.observed_at, "event observed_at")
        _integer(self.monotonic_tick, "event monotonic_tick", 1, 2**63 - 1)
        if self.previous_event_sha256 is not None:
            _digest(self.previous_event_sha256, "event previous_event_sha256")
        digest = _canonical_sha(self.body())
        if self.event_sha256 and self.event_sha256 != digest:
            raise AuthorizedTargetSessionRuntimeError("event_sha256 does not match content")
        object.__setattr__(self, "event_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "detail_sha256": self.detail_sha256,
            "monotonic_tick": self.monotonic_tick,
            "observed_at": self.observed_at,
            "previous_event_sha256": self.previous_event_sha256,
            "sequence": self.sequence,
            "stage": self.stage,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "event_sha256": self.event_sha256}


@dataclass(frozen=True, slots=True)
class TargetSessionReceipt:
    """Content-addressed terminal evidence for one acquisition attempt."""

    status: SessionAcquisitionStatus
    reason: str
    scope_id: str
    scope_sha256: str
    intent_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    execution_policy_id: str
    execution_policy_sha256: str
    runtime_policy_id: str
    runtime_policy_sha256: str
    binding: ExecutionBinding
    lease_source_kind: str
    lease_id: str
    lease_sha256: str
    lease_binding_sha256: str
    lease_use_number: int
    lease_use_reservation_key_sha256: str
    lease_use_reservation_status: LeaseUseReservationStatus
    lease_use_reservation_id: str | None
    lease_use_reservation_sha256: str | None
    lease_use_completion_sha256: str | None
    provider_called: bool
    authentication_attempts: int
    session_id: str | None
    principal_label: str | None
    session_expires_at: str | None
    session_attestation_sha256: str | None
    principal_attestation_sha256: str | None
    cleanup_obligation_ref: str
    cleanup_status: CleanupStatus
    revocation_obligation_ref: str
    revocation_status: RevocationStatus
    revocation_evidence_sha256: tuple[str, ...]
    credential_material_observed: bool
    transcript: tuple[SessionTranscriptEvent, ...]
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    authority_effect: str = "none"
    qualification_effect: str = "none"
    transcript_id: str = ""
    transcript_sha256: str = ""
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "authorized_target_session_receipt"

    def __post_init__(self) -> None:
        if not isinstance(self.status, SessionAcquisitionStatus):
            raise AuthorizedTargetSessionRuntimeError("receipt status is invalid")
        _code(self.reason, "receipt reason")
        if self.status is SessionAcquisitionStatus.COMPLETED and self.reason != "completed":
            raise AuthorizedTargetSessionRuntimeError("completed receipt reason must be completed")
        _identifier(self.scope_id, "scope_id")
        for name in (
            "scope_sha256",
            "intent_sha256",
            "execution_request_sha256",
            "admission_receipt_sha256",
            "execution_policy_sha256",
            "runtime_policy_sha256",
            "lease_sha256",
            "lease_binding_sha256",
            "lease_use_reservation_key_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "execution_request_id",
            "admission_receipt_id",
            "execution_policy_id",
            "runtime_policy_id",
            "lease_id",
        ):
            _identifier(getattr(self, name), name)
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedTargetSessionRuntimeError("receipt binding is invalid")
        if self.lease_source_kind not in {"credential_lease", "opaque_exact_binding"}:
            raise AuthorizedTargetSessionRuntimeError("lease_source_kind is invalid")
        _integer(self.lease_use_number, "lease_use_number", 1, 100)
        if not isinstance(self.lease_use_reservation_status, LeaseUseReservationStatus):
            raise AuthorizedTargetSessionRuntimeError("lease_use_reservation_status is invalid")
        reservation_values = (
            self.lease_use_reservation_id,
            self.lease_use_reservation_sha256,
        )
        if self.lease_use_reservation_status is LeaseUseReservationStatus.NOT_RESERVED:
            if any(value is not None for value in reservation_values) or (
                self.lease_use_completion_sha256 is not None
            ):
                raise AuthorizedTargetSessionRuntimeError(
                    "unreserved receipt cannot claim lease-use evidence"
                )
        else:
            if any(value is None for value in reservation_values):
                raise AuthorizedTargetSessionRuntimeError(
                    "reserved receipt requires lease-use evidence"
                )
            _identifier(self.lease_use_reservation_id, "lease_use_reservation_id")
            _digest(
                self.lease_use_reservation_sha256,
                "lease_use_reservation_sha256",
            )
            expected_reservation = LeaseUseReservationEvidence(
                self.lease_use_reservation_key_sha256
            )
            if (
                self.lease_use_reservation_id != expected_reservation.reservation_id
                or self.lease_use_reservation_sha256 != expected_reservation.reservation_sha256
            ):
                raise AuthorizedTargetSessionRuntimeError(
                    "lease-use reservation evidence does not match key"
                )
            if self.lease_use_reservation_status is LeaseUseReservationStatus.COMPLETED:
                _digest(self.lease_use_completion_sha256, "lease_use_completion_sha256")
                completion_outcome = {
                    SessionAcquisitionStatus.COMPLETED: "completed",
                    SessionAcquisitionStatus.POSTCONDITION_REJECTED: ("postcondition_rejected"),
                    SessionAcquisitionStatus.PROVIDER_FAILED: "provider_failed",
                    SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION: (
                        "rejected_before_authentication"
                    ),
                }.get(self.status)
                if completion_outcome is None:
                    raise AuthorizedTargetSessionRuntimeError(
                        "lease-use completion has an invalid terminal status"
                    )
                expected_completion = LeaseUseCompletionEvidence(
                    reservation_id=expected_reservation.reservation_id,
                    reservation_sha256=expected_reservation.reservation_sha256,
                    reservation_key_sha256=self.lease_use_reservation_key_sha256,
                    outcome=completion_outcome,
                    provider_called=self.provider_called,
                )
                if self.lease_use_completion_sha256 != expected_completion.completion_sha256:
                    raise AuthorizedTargetSessionRuntimeError(
                        "lease-use completion evidence does not match outcome"
                    )
            elif self.lease_use_completion_sha256 is not None:
                raise AuthorizedTargetSessionRuntimeError(
                    "failed completion cannot claim completion evidence"
                )
        if not isinstance(self.provider_called, bool):
            raise AuthorizedTargetSessionRuntimeError("provider_called is invalid")
        if (self.status is SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION) != (
            self.provider_called is False
        ):
            raise AuthorizedTargetSessionRuntimeError(
                "pre-authentication rejection and provider call are inconsistent"
            )
        _integer(self.authentication_attempts, "authentication_attempts", 0, 1)
        if self.provider_called != (self.authentication_attempts == 1):
            raise AuthorizedTargetSessionRuntimeError("provider call evidence is inconsistent")
        reserved = self.lease_use_reservation_status in {
            LeaseUseReservationStatus.COMPLETED,
            LeaseUseReservationStatus.COMPLETION_FAILED,
        }
        zero_call_rejection = (
            self.provider_called is False
            and self.status is SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION
            and self.cleanup_status is CleanupStatus.NOT_REQUIRED_BEFORE_PROVIDER
        )
        if (not self.provider_called and not zero_call_rejection) or (
            self.provider_called != reserved and not (reserved and zero_call_rejection)
        ):
            raise AuthorizedTargetSessionRuntimeError(
                "provider call and lease-use evidence are inconsistent"
            )
        nullable_digests = (
            (self.session_attestation_sha256, "session_attestation_sha256"),
            (self.principal_attestation_sha256, "principal_attestation_sha256"),
        )
        for value, label in nullable_digests:
            if value is not None:
                _digest(value, label)
        if self.session_id is not None:
            _identifier(self.session_id, "session_id")
        if self.principal_label is not None:
            _reference(self.principal_label, "principal_label", "principalref")
        if self.session_expires_at is not None:
            _utc(self.session_expires_at, "session_expires_at")
        _reference(self.cleanup_obligation_ref, "cleanup_obligation_ref", "obligationref")
        _reference(self.revocation_obligation_ref, "revocation_obligation_ref", "obligationref")
        if not isinstance(self.cleanup_status, CleanupStatus) or not isinstance(
            self.revocation_status, RevocationStatus
        ):
            raise AuthorizedTargetSessionRuntimeError("obligation status is invalid")
        if (
            not isinstance(self.revocation_evidence_sha256, tuple)
            or len(self.revocation_evidence_sha256) > 2
        ):
            raise AuthorizedTargetSessionRuntimeError("revocation evidence is invalid")
        for digest in self.revocation_evidence_sha256:
            _digest(digest, "revocation evidence digest")
        if self.credential_material_observed is not False:
            raise AuthorizedTargetSessionRuntimeError("receipt cannot claim credential material")
        if self.status is SessionAcquisitionStatus.COMPLETED:
            if self.lease_use_reservation_status is not LeaseUseReservationStatus.COMPLETED:
                raise AuthorizedTargetSessionRuntimeError(
                    "completed session requires lease-use completion evidence"
                )
            if any(
                item is None
                for item in (
                    self.session_id,
                    self.principal_label,
                    self.session_expires_at,
                    self.session_attestation_sha256,
                    self.principal_attestation_sha256,
                )
            ):
                raise AuthorizedTargetSessionRuntimeError(
                    "completed receipt requires session proof"
                )
            if self.cleanup_status is not CleanupStatus.PENDING_EXTERNAL_VERIFICATION:
                raise AuthorizedTargetSessionRuntimeError("completed session requires cleanup")
            if (
                self.revocation_status
                is not RevocationStatus.CHECKED_NOT_REVOKED_AFTER_AUTHENTICATION
            ):
                raise AuthorizedTargetSessionRuntimeError(
                    "completed session requires revocation proof"
                )
            if len(self.revocation_evidence_sha256) != 2:
                raise AuthorizedTargetSessionRuntimeError(
                    "completed session requires two revocation observations"
                )
        elif any(
            item is not None
            for item in (
                self.session_id,
                self.principal_label,
                self.session_expires_at,
                self.session_attestation_sha256,
                self.principal_attestation_sha256,
            )
        ):
            raise AuthorizedTargetSessionRuntimeError(
                "non-completed receipt cannot claim a session"
            )
        if self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise AuthorizedTargetSessionRuntimeError("enforcement_boundary is invalid")
        if self.authority_effect != "none" or self.qualification_effect != "none":
            raise AuthorizedTargetSessionRuntimeError("receipt effects must remain none")
        _validate_transcript(self.transcript)
        transcript_body = [item.to_dict() for item in self.transcript]
        transcript_id, transcript_digest = _identity(
            "AST", "authorized_target_session_transcript", {"events": transcript_body}
        )
        if self.transcript_id and self.transcript_id != transcript_id:
            raise AuthorizedTargetSessionRuntimeError("transcript_id does not match content")
        if self.transcript_sha256 and self.transcript_sha256 != transcript_digest:
            raise AuthorizedTargetSessionRuntimeError("transcript_sha256 does not match content")
        object.__setattr__(self, "transcript_id", transcript_id)
        object.__setattr__(self, "transcript_sha256", transcript_digest)
        receipt_id, receipt_digest = _identity("ASR", self.KIND, self.body())
        if self.receipt_id and self.receipt_id != receipt_id:
            raise AuthorizedTargetSessionRuntimeError("receipt_id does not match content")
        if self.receipt_sha256 and self.receipt_sha256 != receipt_digest:
            raise AuthorizedTargetSessionRuntimeError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", receipt_digest)

    def body(self) -> dict[str, Any]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "authentication_attempts": self.authentication_attempts,
            "authority_effect": self.authority_effect,
            "binding": self.binding.to_dict(),
            "cleanup_obligation_ref": self.cleanup_obligation_ref,
            "cleanup_status": self.cleanup_status.value,
            "credential_material_observed": self.credential_material_observed,
            "enforcement_boundary": self.enforcement_boundary,
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "intent_sha256": self.intent_sha256,
            "lease_id": self.lease_id,
            "lease_binding_sha256": self.lease_binding_sha256,
            "lease_sha256": self.lease_sha256,
            "lease_source_kind": self.lease_source_kind,
            "lease_use_number": self.lease_use_number,
            "lease_use_completion_sha256": self.lease_use_completion_sha256,
            "lease_use_reservation_id": self.lease_use_reservation_id,
            "lease_use_reservation_key_sha256": self.lease_use_reservation_key_sha256,
            "lease_use_reservation_sha256": self.lease_use_reservation_sha256,
            "lease_use_reservation_status": self.lease_use_reservation_status.value,
            "principal_attestation_sha256": self.principal_attestation_sha256,
            "principal_label": self.principal_label,
            "provider_called": self.provider_called,
            "qualification_effect": self.qualification_effect,
            "reason": self.reason,
            "revocation_evidence_sha256": list(self.revocation_evidence_sha256),
            "revocation_obligation_ref": self.revocation_obligation_ref,
            "revocation_status": self.revocation_status.value,
            "runtime_policy_id": self.runtime_policy_id,
            "runtime_policy_sha256": self.runtime_policy_sha256,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "session_attestation_sha256": self.session_attestation_sha256,
            "session_expires_at": self.session_expires_at,
            "session_id": self.session_id,
            "status": self.status.value,
            "transcript": [item.to_dict() for item in self.transcript],
            "transcript_id": self.transcript_id,
            "transcript_sha256": self.transcript_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


def _validate_transcript(events: tuple[SessionTranscriptEvent, ...]) -> None:
    if not isinstance(events, tuple) or not events or len(events) > MAX_TRANSCRIPT_EVENTS:
        raise AuthorizedTargetSessionRuntimeError("transcript is invalid")
    previous: str | None = None
    prior_tick = 0
    prior_time: datetime | None = None
    for index, event in enumerate(events, start=1):
        if not isinstance(event, SessionTranscriptEvent):
            raise AuthorizedTargetSessionRuntimeError("transcript event is invalid")
        if event.sequence != index or event.previous_event_sha256 != previous:
            raise AuthorizedTargetSessionRuntimeError("transcript chain is invalid")
        observed = _instant(event.observed_at)
        if event.monotonic_tick <= prior_tick or (prior_time is not None and observed < prior_time):
            raise AuthorizedTargetSessionRuntimeError("transcript time is not monotonic")
        previous = event.event_sha256
        prior_tick = event.monotonic_tick
        prior_time = observed


class _Evidence:
    def __init__(self) -> None:
        self.events: list[SessionTranscriptEvent] = []

    def add(self, stage: str, detail: dict[str, Any], observed: ClockObservation) -> None:
        self.events.append(
            SessionTranscriptEvent(
                sequence=len(self.events) + 1,
                stage=stage,
                detail_sha256=_canonical_sha(detail),
                observed_at=observed.observed_at,
                monotonic_tick=observed.monotonic_tick,
                previous_event_sha256=(self.events[-1].event_sha256 if self.events else None),
            )
        )


@dataclass(frozen=True, slots=True)
class _LeaseView:
    source_kind: str
    lease_id: str
    lease_sha256: str
    binding_sha256: str
    tenant_ref: str
    assessment_ref: str
    task_ref: str
    subject_principal_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    scope_refs: tuple[str, ...]
    lease_mode: LeaseMode
    session_ref: str | None
    issued_at: str
    expires_at: str
    max_uses: int


def _lease_view(value: CredentialLease | OpaqueLeaseBinding) -> _LeaseView:
    if isinstance(value, CredentialLease):
        return _LeaseView(
            "credential_lease",
            value.lease_id,
            value.lease_sha256,
            value.lease_sha256,
            value.tenant_ref,
            value.assessment_ref,
            value.task_ref,
            value.subject_principal_ref,
            value.target_ref,
            value.technique_ref,
            value.purpose_ref,
            value.scope_refs,
            value.lease_mode,
            value.session_ref,
            value.issued_at,
            value.expires_at,
            value.max_uses,
        )
    if isinstance(value, OpaqueLeaseBinding):
        return _LeaseView(
            "opaque_exact_binding",
            value.lease_id,
            value.lease_sha256,
            value.binding_sha256,
            value.tenant_ref,
            value.assessment_ref,
            value.task_ref,
            value.subject_principal_ref,
            value.target_ref,
            value.technique_ref,
            value.purpose_ref,
            value.scope_refs,
            value.lease_mode,
            value.session_ref,
            value.issued_at,
            value.expires_at,
            value.max_uses,
        )
    raise AuthorizedTargetSessionRuntimeError("lease must be exact broker or opaque evidence")


def _observation(
    clock: TargetSessionRuntimeClock, previous: ClockObservation | None
) -> ClockObservation:
    try:
        current = clock.observe()
    except Exception as exc:
        raise AuthorizedTargetSessionRuntimeError("clock_failure") from exc
    if not isinstance(current, ClockObservation):
        raise AuthorizedTargetSessionRuntimeError("clock_failure")
    if previous is not None and (
        current.monotonic_tick <= previous.monotonic_tick
        or _instant(current.observed_at) < _instant(previous.observed_at)
    ):
        raise AuthorizedTargetSessionRuntimeError("clock_rollback")
    return current


def _check_safety(
    monitor: TargetSessionSafetyMonitor,
    request: ExecutionRequest,
) -> TargetSessionSafetySnapshot:
    try:
        snapshot = monitor.observe()
    except Exception as exc:
        raise AuthorizedTargetSessionRuntimeError("safety_monitor_failure") from exc
    if not isinstance(snapshot, TargetSessionSafetySnapshot):
        raise AuthorizedTargetSessionRuntimeError("safety_monitor_failure")
    if snapshot.binding_sha256 != _binding_sha(request.binding):
        raise AuthorizedTargetSessionRuntimeError("safety_binding_mismatch")
    if snapshot.request_sha256 != request.request_sha256:
        raise AuthorizedTargetSessionRuntimeError("safety_request_mismatch")
    if snapshot.canceled:
        raise AuthorizedTargetSessionRuntimeError("canceled")
    if snapshot.emergency_stop:
        raise AuthorizedTargetSessionRuntimeError("emergency_stop")
    if snapshot.health is not HealthState.HEALTHY:
        raise AuthorizedTargetSessionRuntimeError("health_not_healthy")
    return snapshot


def _observe_revocation(
    checker: LeaseRevocationChecker,
    lease: _LeaseView,
) -> RevocationObservation:
    try:
        observation = checker.observe(lease.lease_id, lease.lease_sha256)
    except Exception as exc:
        raise AuthorizedTargetSessionRuntimeError("revocation_check_failure") from exc
    if not isinstance(observation, RevocationObservation):
        raise AuthorizedTargetSessionRuntimeError("revocation_check_failure")
    if observation.lease_id != lease.lease_id or observation.lease_sha256 != lease.lease_sha256:
        raise AuthorizedTargetSessionRuntimeError("revocation_binding_mismatch")
    return observation


def _reserve_lease_use(
    store: AtomicLeaseUseStore,
    request: LeaseUseReservationRequest,
) -> LeaseUseReservationEvidence:
    try:
        evidence = store.reserve(request)
    except LeaseUseStoreFailure:
        raise
    except Exception as exc:
        raise AuthorizedTargetSessionRuntimeError("lease_use_reservation_failure") from exc
    if (
        not isinstance(evidence, LeaseUseReservationEvidence)
        or evidence.reservation_key_sha256 != request.reservation_key_sha256
    ):
        raise AuthorizedTargetSessionRuntimeError("lease_use_reservation_mismatch")
    return evidence


def _complete_lease_use(
    store: AtomicLeaseUseStore,
    reservation: LeaseUseReservationEvidence,
    outcome: str,
    provider_called: bool = True,
) -> LeaseUseCompletionEvidence:
    try:
        evidence = store.complete(reservation, outcome, provider_called)
    except Exception as exc:
        raise AuthorizedTargetSessionRuntimeError("lease_use_completion_failure") from exc
    if (
        not isinstance(evidence, LeaseUseCompletionEvidence)
        or evidence.reservation_id != reservation.reservation_id
        or evidence.reservation_sha256 != reservation.reservation_sha256
        or evidence.reservation_key_sha256 != reservation.reservation_key_sha256
        or evidence.outcome != outcome
        or evidence.provider_called is not provider_called
    ):
        raise AuthorizedTargetSessionRuntimeError("lease_use_completion_mismatch")
    return evidence


def _reason(exc: Exception) -> str:
    text = str(exc)
    known = {
        "admission_not_allowed",
        "binding_mismatch",
        "canceled",
        "clock_failure",
        "clock_rollback",
        "credential_binding_mismatch",
        "emergency_stop",
        "health_not_healthy",
        "lease_expired",
        "lease_revoked",
        "lease_use_completion_failure",
        "lease_use_completion_mismatch",
        "lease_use_replayed",
        "lease_use_reservation_failure",
        "lease_use_reservation_mismatch",
        "lease_usage_exhausted",
        "multi_principal_isolation_failure",
        "principal_mismatch",
        "provider_exception",
        "revocation_binding_mismatch",
        "revocation_check_failure",
        "safety_binding_mismatch",
        "safety_monitor_failure",
        "safety_request_mismatch",
        "scope_rejected",
        "session_postcondition_rejected",
    }
    return text if text in known else "validation_rejected"


def _check_preconditions(
    scope: VerifiedAssessmentScope,
    intent: TargetSessionIntent,
    request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedTargetSessionPolicy,
    lease: _LeaseView,
    lease_use_number: int,
    observed: ClockObservation,
) -> str:
    if not isinstance(scope, VerifiedAssessmentScope):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if not isinstance(intent, TargetSessionIntent):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if not isinstance(request, ExecutionRequest) or not isinstance(admission, AdmissionReceipt):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if not isinstance(policy, AuthorizedTargetSessionPolicy):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if request.binding != policy.execution_binding:
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if request.binding.lease_id != lease.lease_id:
        raise AuthorizedTargetSessionRuntimeError("credential_binding_mismatch")
    if (
        request.binding.scope_id != scope.scope_id
        or request.binding.scope_sha256 != scope.content_sha256
    ):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if (
        intent.binding.scope_id != scope.scope_id
        or intent.binding.scope_sha256 != scope.content_sha256
    ):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if intent.binding.task_id != request.binding.context_id:
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if intent.requested_session_id != request.binding.session_id:
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if (
        request.payload_sha256 != intent.intent_sha256
        or request.operation_code != "authorized_target_session"
    ):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if request.payload_size_bytes != len(canonical_json(intent.to_dict()).encode("ascii")):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if request.cleanup_obligation_sha256 != _canonical_sha(
        {"cleanup_obligation_ref": policy.cleanup_obligation_ref}
    ):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if request.attempt_number != 1 or request.prior_execution_sha256 is not None:
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if (
        request.policy_id != policy.execution_policy_id
        or request.policy_sha256 != policy.execution_policy_sha256
    ):
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    if (
        admission.status is not AdmissionStatus.ADMITTED
        or admission.request_id != request.request_id
        or admission.request_sha256 != request.request_sha256
        or admission.policy_id != request.policy_id
        or admission.policy_sha256 != request.policy_sha256
    ):
        raise AuthorizedTargetSessionRuntimeError("admission_not_allowed")
    if _https_origin(intent.login_url, "login_url") != policy.login_origin:
        raise AuthorizedTargetSessionRuntimeError("binding_mismatch")
    decision = evaluate_request(
        scope,
        url=intent.login_url,
        method=intent.method.value,
        technique_id=intent.binding.technique_id,
        impact_tier=intent.binding.impact_tier,
        budget_state=ScopeBudgetState(
            requests_completed=intent.binding.budget.requests_completed,
            requests_active=intent.binding.budget.requests_active,
            requests_in_current_minute=intent.binding.budget.requests_in_current_minute,
        ),
        at=_instant(observed.observed_at),
    )
    if not decision.allowed:
        raise AuthorizedTargetSessionRuntimeError("scope_rejected")
    selected = [
        item
        for item in intent.credential_references
        if item.principal_label == intent.principal_label
    ]
    if len(selected) != 1:
        raise AuthorizedTargetSessionRuntimeError("principal_mismatch")
    if len({item.credential_ref for item in intent.credential_references}) != len(
        intent.credential_references
    ):
        raise AuthorizedTargetSessionRuntimeError("multi_principal_isolation_failure")
    if intent.principal_label != lease.subject_principal_ref:
        raise AuthorizedTargetSessionRuntimeError("principal_mismatch")
    expected = (
        (lease.tenant_ref, request.binding.tenant_id),
        (lease.assessment_ref, policy.assessment_ref),
        (lease.task_ref, policy.task_ref),
        (lease.target_ref, policy.target_ref),
        (lease.target_ref, request.binding.target_id),
        (lease.technique_ref, policy.technique_ref),
        (lease.purpose_ref, policy.purpose_ref),
    )
    if any(left != right for left, right in expected):
        raise AuthorizedTargetSessionRuntimeError("credential_binding_mismatch")
    if policy.scope_ref not in lease.scope_refs or policy.scope_ref != f"scoperef:{scope.scope_id}":
        raise AuthorizedTargetSessionRuntimeError("credential_binding_mismatch")
    if intent.binding.technique_id != policy.technique_ref.split(":", 1)[1]:
        raise AuthorizedTargetSessionRuntimeError("credential_binding_mismatch")
    if lease.session_ref is not None and lease.session_ref != intent.requested_session_id:
        raise AuthorizedTargetSessionRuntimeError("credential_binding_mismatch")
    _integer(lease_use_number, "lease_use_number", 1, 100)
    if lease_use_number > lease.max_uses:
        raise AuthorizedTargetSessionRuntimeError("lease_usage_exhausted")
    now = _instant(observed.observed_at)
    if not (_instant(lease.issued_at) <= now < _instant(lease.expires_at)):
        raise AuthorizedTargetSessionRuntimeError("lease_expired")
    return selected[0].credential_ref


def _receipt(
    *,
    status: SessionAcquisitionStatus,
    reason: str,
    scope: VerifiedAssessmentScope,
    intent: TargetSessionIntent,
    request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedTargetSessionPolicy,
    lease: _LeaseView,
    lease_use_number: int,
    reservation_request: LeaseUseReservationRequest,
    reservation: LeaseUseReservationEvidence | None,
    completion: LeaseUseCompletionEvidence | None,
    reservation_status: LeaseUseReservationStatus,
    provider_called: bool,
    result: CredentialSessionResult | None,
    cleanup_status: CleanupStatus,
    revocation_status: RevocationStatus,
    revocation_evidence: tuple[str, ...],
    evidence: _Evidence,
) -> TargetSessionReceipt:
    completed = status is SessionAcquisitionStatus.COMPLETED
    return TargetSessionReceipt(
        status=status,
        reason=reason,
        scope_id=scope.scope_id,
        scope_sha256=scope.content_sha256,
        intent_sha256=intent.intent_sha256,
        execution_request_id=request.request_id,
        execution_request_sha256=request.request_sha256,
        admission_receipt_id=admission.receipt_id,
        admission_receipt_sha256=admission.receipt_sha256,
        execution_policy_id=request.policy_id,
        execution_policy_sha256=request.policy_sha256,
        runtime_policy_id=policy.policy_id,
        runtime_policy_sha256=policy.policy_sha256,
        binding=request.binding,
        lease_source_kind=lease.source_kind,
        lease_id=lease.lease_id,
        lease_sha256=lease.lease_sha256,
        lease_binding_sha256=lease.binding_sha256,
        lease_use_number=lease_use_number,
        lease_use_reservation_key_sha256=reservation_request.reservation_key_sha256,
        lease_use_reservation_status=reservation_status,
        lease_use_reservation_id=(None if reservation is None else reservation.reservation_id),
        lease_use_reservation_sha256=(
            None if reservation is None else reservation.reservation_sha256
        ),
        lease_use_completion_sha256=(None if completion is None else completion.completion_sha256),
        provider_called=provider_called,
        authentication_attempts=1 if provider_called else 0,
        session_id=result.session_id if completed and result else None,
        principal_label=result.principal_label if completed and result else None,
        session_expires_at=result.expires_at if completed and result else None,
        session_attestation_sha256=(
            result.session_attestation_sha256 if completed and result else None
        ),
        principal_attestation_sha256=(
            result.principal_attestation_sha256 if completed and result else None
        ),
        cleanup_obligation_ref=policy.cleanup_obligation_ref,
        cleanup_status=cleanup_status,
        revocation_obligation_ref=policy.revocation_obligation_ref,
        revocation_status=revocation_status,
        revocation_evidence_sha256=revocation_evidence,
        credential_material_observed=False,
        transcript=tuple(evidence.events),
    )


def execute_authorized_target_session(
    *,
    scope: VerifiedAssessmentScope,
    intent: TargetSessionIntent,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedTargetSessionPolicy,
    lease: CredentialLease | OpaqueLeaseBinding,
    lease_use_number: int,
    clock: TargetSessionRuntimeClock,
    safety_monitor: TargetSessionSafetyMonitor,
    revocation_checker: LeaseRevocationChecker,
    lease_use_store: AtomicLeaseUseStore,
    provider: CredentialSessionProvider,
) -> TargetSessionReceipt:
    """Validate all bindings and call the injected provider at most once."""

    lease_view = _lease_view(lease)
    reservation_request = LeaseUseReservationRequest(
        lease_id=lease_view.lease_id,
        lease_sha256=lease_view.lease_sha256,
        lease_binding_sha256=lease_view.binding_sha256,
        lease_use_number=lease_use_number,
        lease_mode=lease_view.lease_mode,
        execution_request_id=execution_request.request_id,
        execution_request_sha256=execution_request.request_sha256,
        execution_binding_sha256=_binding_sha(execution_request.binding),
        requested_session_id=intent.requested_session_id,
    )
    evidence = _Evidence()
    first: ClockObservation | None = None
    latest_observation: ClockObservation | None = None
    reservation: LeaseUseReservationEvidence | None = None
    revocation_status = RevocationStatus.NOT_CHECKED
    revocation_evidence: tuple[str, ...] = ()
    try:
        first = _observation(clock, None)
        latest_observation = first
        credential_reference = _check_preconditions(
            scope,
            intent,
            execution_request,
            admission,
            policy,
            lease_view,
            lease_use_number,
            first,
        )
        _check_safety(safety_monitor, execution_request)
        revocation = _observe_revocation(revocation_checker, lease_view)
        revocation_evidence = (revocation.evidence_sha256,)
        if revocation.revoked:
            raise AuthorizedTargetSessionRuntimeError("lease_revoked")
        revocation_status = RevocationStatus.CHECKED_NOT_REVOKED
        second = _observation(clock, first)
        latest_observation = second
        _check_preconditions(
            scope,
            intent,
            execution_request,
            admission,
            policy,
            lease_view,
            lease_use_number,
            second,
        )
        _check_safety(safety_monitor, execution_request)
        evidence.add(
            "pre_authentication",
            {
                "revocation_evidence_sha256": revocation.evidence_sha256,
                "safety_binding_sha256": _binding_sha(execution_request.binding),
            },
            second,
        )
        command = CredentialSessionCommand(
            intent_sha256=intent.intent_sha256,
            execution_request_sha256=execution_request.request_sha256,
            runtime_policy_sha256=policy.policy_sha256,
            lease_id=lease_view.lease_id,
            lease_sha256=lease_view.lease_sha256,
            lease_use_number=lease_use_number,
            credential_reference=credential_reference,
            login_url=intent.login_url,
            method=intent.method.value,
            authentication_mode=intent.mode.value,
            requested_session_id=intent.requested_session_id,
            principal_label=intent.principal_label,
        )
        reservation = _reserve_lease_use(lease_use_store, reservation_request)
        try:
            _check_safety(safety_monitor, execution_request)
            try:
                fresh_revocation = _observe_revocation(revocation_checker, lease_view)
            except Exception:
                revocation_status = RevocationStatus.CHECK_FAILED
                raise
            revocation_evidence = (fresh_revocation.evidence_sha256,)
            revocation_status = (
                RevocationStatus.REVOKED
                if fresh_revocation.revoked
                else RevocationStatus.CHECKED_NOT_REVOKED
            )
            if fresh_revocation.revoked:
                raise AuthorizedTargetSessionRuntimeError("lease_revoked")
        finally:
            reserved_observation = _observation(clock, second)
            latest_observation = reserved_observation
        _check_preconditions(
            scope,
            intent,
            execution_request,
            admission,
            policy,
            lease_view,
            lease_use_number,
            reserved_observation,
        )
        evidence.add(
            "lease_use_reserved",
            {
                "reservation_sha256": reservation.reservation_sha256,
                "revocation_evidence_sha256": fresh_revocation.evidence_sha256,
            },
            reserved_observation,
        )
    except Exception as exc:
        reason = _reason(exc)
        completion = None
        reservation_status = LeaseUseReservationStatus.NOT_RESERVED
        if reservation is not None:
            try:
                completion = _complete_lease_use(
                    lease_use_store,
                    reservation,
                    "rejected_before_authentication",
                    provider_called=False,
                )
                reservation_status = LeaseUseReservationStatus.COMPLETED
            except Exception as completion_exc:
                reason = _reason(completion_exc)
                reservation_status = LeaseUseReservationStatus.COMPLETION_FAILED
        rejection_observation = latest_observation or ClockObservation(
            admission.observed_at,
            admission.monotonic_tick,
        )
        if not evidence.events or (
            evidence.events[-1].monotonic_tick < rejection_observation.monotonic_tick
        ):
            evidence.add(
                "validation_rejected",
                {
                    "completion_sha256": (
                        None if completion is None else completion.completion_sha256
                    ),
                    "reason": reason,
                    "reservation_sha256": (
                        None if reservation is None else reservation.reservation_sha256
                    ),
                    "revocation_evidence_sha256": list(revocation_evidence),
                },
                rejection_observation,
            )
        if _reason(exc) == "lease_revoked":
            revocation_status = RevocationStatus.REVOKED
        elif _reason(exc) in {"revocation_check_failure", "revocation_binding_mismatch"}:
            revocation_status = RevocationStatus.CHECK_FAILED
        return _receipt(
            status=SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
            reason=reason,
            scope=scope,
            intent=intent,
            request=execution_request,
            admission=admission,
            policy=policy,
            lease=lease_view,
            lease_use_number=lease_use_number,
            reservation_request=reservation_request,
            reservation=reservation,
            completion=completion,
            reservation_status=reservation_status,
            provider_called=False,
            result=None,
            cleanup_status=CleanupStatus.NOT_REQUIRED_BEFORE_PROVIDER,
            revocation_status=revocation_status,
            revocation_evidence=revocation_evidence,
            evidence=evidence,
        )

    assert reservation is not None

    def finish_lease_use(
        outcome: str,
    ) -> tuple[
        LeaseUseCompletionEvidence | None,
        LeaseUseReservationStatus,
        str | None,
    ]:
        try:
            completion = _complete_lease_use(lease_use_store, reservation, outcome)
        except Exception as exc:
            return None, LeaseUseReservationStatus.COMPLETION_FAILED, _reason(exc)
        return completion, LeaseUseReservationStatus.COMPLETED, None

    def provider_failure_receipt(reason: str) -> TargetSessionReceipt:
        completion, reservation_status, completion_reason = finish_lease_use("provider_failed")
        final_reason = completion_reason or reason
        try:
            failure_observation = _observation(clock, reserved_observation)
            evidence.add(
                (
                    "lease_use_completion_failed"
                    if completion_reason is not None
                    else "provider_failed"
                ),
                {
                    "completion_sha256": (
                        None if completion is None else completion.completion_sha256
                    ),
                    "reason": final_reason,
                },
                failure_observation,
            )
        except AuthorizedTargetSessionRuntimeError:
            pass
        return _receipt(
            status=SessionAcquisitionStatus.PROVIDER_FAILED,
            reason=final_reason,
            scope=scope,
            intent=intent,
            request=execution_request,
            admission=admission,
            policy=policy,
            lease=lease_view,
            lease_use_number=lease_use_number,
            reservation_request=reservation_request,
            reservation=reservation,
            completion=completion,
            reservation_status=reservation_status,
            provider_called=True,
            result=None,
            cleanup_status=CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
            revocation_status=revocation_status,
            revocation_evidence=revocation_evidence,
            evidence=evidence,
        )

    try:
        result = provider.acquire(command)
        if not isinstance(result, CredentialSessionResult):
            raise AuthorizedTargetSessionRuntimeError("provider_exception")
    except CredentialSessionProviderFailure as exc:
        return provider_failure_receipt(exc.code)
    except Exception:
        return provider_failure_receipt("provider_exception")

    if not result.succeeded:
        return provider_failure_receipt(result.failure_code or "provider_exception")

    try:
        third = _observation(clock, reserved_observation)
        _check_safety(safety_monitor, execution_request)
        final_revocation = _observe_revocation(revocation_checker, lease_view)
        revocation_evidence = (
            revocation_evidence[0],
            final_revocation.evidence_sha256,
        )
        if final_revocation.revoked:
            raise AuthorizedTargetSessionRuntimeError("lease_revoked")
        revocation_status = RevocationStatus.CHECKED_NOT_REVOKED_AFTER_AUTHENTICATION
        if (
            result.session_id != intent.requested_session_id
            or result.principal_label != intent.principal_label
            or result.isolated is not True
            or result.cleanup_obligation_ref != policy.cleanup_obligation_ref
            or result.revocation_obligation_ref != policy.revocation_obligation_ref
        ):
            raise AuthorizedTargetSessionRuntimeError("session_postcondition_rejected")
        expected_session = session_attestation_sha256(command, result.expires_at or "")
        expected_principal = principal_attestation_sha256(command)
        if (
            result.session_attestation_sha256 != expected_session
            or result.principal_attestation_sha256 != expected_principal
        ):
            raise AuthorizedTargetSessionRuntimeError("session_postcondition_rejected")
        expires = _instant(result.expires_at or "")
        maximum = min(
            _instant(second.observed_at) + timedelta(seconds=policy.max_session_ttl_seconds),
            _instant(lease_view.expires_at),
            _instant(scope.to_dict()["expires_at"]),
        )
        if expires <= _instant(third.observed_at) or expires > maximum:
            raise AuthorizedTargetSessionRuntimeError("session_postcondition_rejected")
    except Exception as exc:
        reason = _reason(exc)
        completion, reservation_status, completion_reason = finish_lease_use(
            "postcondition_rejected"
        )
        reason = completion_reason or reason
        if "third" in locals():
            evidence.add(
                (
                    "lease_use_completion_failed"
                    if completion_reason is not None
                    else "postcondition_rejected"
                ),
                {
                    "completion_sha256": (
                        None if completion is None else completion.completion_sha256
                    ),
                    "reason": reason,
                },
                third,
            )
        if _reason(exc) == "lease_revoked":
            revocation_status = RevocationStatus.REVOKED
        elif _reason(exc) in {"revocation_check_failure", "revocation_binding_mismatch"}:
            revocation_status = RevocationStatus.CHECK_FAILED
        return _receipt(
            status=SessionAcquisitionStatus.POSTCONDITION_REJECTED,
            reason=reason,
            scope=scope,
            intent=intent,
            request=execution_request,
            admission=admission,
            policy=policy,
            lease=lease_view,
            lease_use_number=lease_use_number,
            reservation_request=reservation_request,
            reservation=reservation,
            completion=completion,
            reservation_status=reservation_status,
            provider_called=True,
            result=None,
            cleanup_status=CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
            revocation_status=revocation_status,
            revocation_evidence=revocation_evidence,
            evidence=evidence,
        )

    completion, reservation_status, completion_reason = finish_lease_use("completed")
    if completion_reason is not None:
        evidence.add(
            "lease_use_completion_failed",
            {"reason": completion_reason},
            third,
        )
        return _receipt(
            status=SessionAcquisitionStatus.POSTCONDITION_REJECTED,
            reason=completion_reason,
            scope=scope,
            intent=intent,
            request=execution_request,
            admission=admission,
            policy=policy,
            lease=lease_view,
            lease_use_number=lease_use_number,
            reservation_request=reservation_request,
            reservation=reservation,
            completion=None,
            reservation_status=reservation_status,
            provider_called=True,
            result=None,
            cleanup_status=CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
            revocation_status=revocation_status,
            revocation_evidence=revocation_evidence,
            evidence=evidence,
        )
    assert completion is not None
    evidence.add(
        "completed",
        {
            "lease_use_completion_sha256": completion.completion_sha256,
            "principal_attestation_sha256": result.principal_attestation_sha256,
            "revocation_evidence_sha256": final_revocation.evidence_sha256,
            "session_attestation_sha256": result.session_attestation_sha256,
        },
        third,
    )
    return _receipt(
        status=SessionAcquisitionStatus.COMPLETED,
        reason="completed",
        scope=scope,
        intent=intent,
        request=execution_request,
        admission=admission,
        policy=policy,
        lease=lease_view,
        lease_use_number=lease_use_number,
        reservation_request=reservation_request,
        reservation=reservation,
        completion=completion,
        reservation_status=reservation_status,
        provider_called=True,
        result=result,
        cleanup_status=CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
        revocation_status=revocation_status,
        revocation_evidence=revocation_evidence,
        evidence=evidence,
    )


RECEIPT_FIELDS = {
    "admission_receipt_id",
    "admission_receipt_sha256",
    "authentication_attempts",
    "authority_effect",
    "binding",
    "cleanup_obligation_ref",
    "cleanup_status",
    "credential_material_observed",
    "enforcement_boundary",
    "execution_policy_id",
    "execution_policy_sha256",
    "execution_request_id",
    "execution_request_sha256",
    "intent_sha256",
    "kind",
    "lease_id",
    "lease_binding_sha256",
    "lease_sha256",
    "lease_source_kind",
    "lease_use_completion_sha256",
    "lease_use_number",
    "lease_use_reservation_id",
    "lease_use_reservation_key_sha256",
    "lease_use_reservation_sha256",
    "lease_use_reservation_status",
    "principal_attestation_sha256",
    "principal_label",
    "provider_called",
    "qualification_effect",
    "reason",
    "receipt_id",
    "receipt_sha256",
    "revocation_evidence_sha256",
    "revocation_obligation_ref",
    "revocation_status",
    "runtime_policy_id",
    "runtime_policy_sha256",
    "schema_version",
    "scope_id",
    "scope_sha256",
    "session_attestation_sha256",
    "session_expires_at",
    "session_id",
    "status",
    "transcript",
    "transcript_id",
    "transcript_sha256",
}
EVENT_FIELDS = {
    "detail_sha256",
    "event_sha256",
    "monotonic_tick",
    "observed_at",
    "previous_event_sha256",
    "sequence",
    "stage",
}
BINDING_FIELDS = {
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


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizedTargetSessionRuntimeError("receipt JSON contains a duplicate key")
        result[key] = value
    return result


def verify_target_session_receipt(raw: bytes | str | dict[str, Any]) -> MappingProxyType:
    """Strictly parse and verify a canonical target-session receipt."""

    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthorizedTargetSessionRuntimeError("receipt must be ASCII") from exc
        return verify_target_session_receipt(text)
    if isinstance(raw, str):
        try:
            raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise AuthorizedTargetSessionRuntimeError("receipt must be ASCII") from exc
        try:
            value = json.loads(raw, object_pairs_hook=_no_duplicates)
        except AuthorizedTargetSessionRuntimeError:
            raise
        except json.JSONDecodeError as exc:
            raise AuthorizedTargetSessionRuntimeError("receipt JSON is invalid") from exc
        if raw != canonical_json(value):
            raise AuthorizedTargetSessionRuntimeError("receipt JSON is not canonical")
    elif isinstance(raw, dict):
        value = raw
    else:
        raise AuthorizedTargetSessionRuntimeError("receipt input is invalid")
    data = _exact_fields(value, RECEIPT_FIELDS, "receipt")
    if data["schema_version"] != SCHEMA_VERSION or data["kind"] != TargetSessionReceipt.KIND:
        raise AuthorizedTargetSessionRuntimeError("receipt type or version is invalid")
    binding_data = _exact_fields(data["binding"], BINDING_FIELDS, "binding")
    binding = ExecutionBinding(**binding_data)
    if not isinstance(data["transcript"], list):
        raise AuthorizedTargetSessionRuntimeError("transcript is invalid")
    events = tuple(
        SessionTranscriptEvent(**_exact_fields(item, EVENT_FIELDS, "event"))
        for item in data["transcript"]
    )
    candidate = TargetSessionReceipt(
        status=SessionAcquisitionStatus(data["status"]),
        reason=data["reason"],
        scope_id=data["scope_id"],
        scope_sha256=data["scope_sha256"],
        intent_sha256=data["intent_sha256"],
        execution_request_id=data["execution_request_id"],
        execution_request_sha256=data["execution_request_sha256"],
        admission_receipt_id=data["admission_receipt_id"],
        admission_receipt_sha256=data["admission_receipt_sha256"],
        execution_policy_id=data["execution_policy_id"],
        execution_policy_sha256=data["execution_policy_sha256"],
        runtime_policy_id=data["runtime_policy_id"],
        runtime_policy_sha256=data["runtime_policy_sha256"],
        binding=binding,
        lease_source_kind=data["lease_source_kind"],
        lease_id=data["lease_id"],
        lease_sha256=data["lease_sha256"],
        lease_binding_sha256=data["lease_binding_sha256"],
        lease_use_number=data["lease_use_number"],
        lease_use_reservation_key_sha256=data["lease_use_reservation_key_sha256"],
        lease_use_reservation_status=LeaseUseReservationStatus(
            data["lease_use_reservation_status"]
        ),
        lease_use_reservation_id=data["lease_use_reservation_id"],
        lease_use_reservation_sha256=data["lease_use_reservation_sha256"],
        lease_use_completion_sha256=data["lease_use_completion_sha256"],
        provider_called=data["provider_called"],
        authentication_attempts=data["authentication_attempts"],
        session_id=data["session_id"],
        principal_label=data["principal_label"],
        session_expires_at=data["session_expires_at"],
        session_attestation_sha256=data["session_attestation_sha256"],
        principal_attestation_sha256=data["principal_attestation_sha256"],
        cleanup_obligation_ref=data["cleanup_obligation_ref"],
        cleanup_status=CleanupStatus(data["cleanup_status"]),
        revocation_obligation_ref=data["revocation_obligation_ref"],
        revocation_status=RevocationStatus(data["revocation_status"]),
        revocation_evidence_sha256=tuple(data["revocation_evidence_sha256"]),
        credential_material_observed=data["credential_material_observed"],
        transcript=events,
        enforcement_boundary=data["enforcement_boundary"],
        authority_effect=data["authority_effect"],
        qualification_effect=data["qualification_effect"],
        transcript_id=data["transcript_id"],
        transcript_sha256=data["transcript_sha256"],
        receipt_id=data["receipt_id"],
        receipt_sha256=data["receipt_sha256"],
    )
    if candidate.to_dict() != data:
        raise AuthorizedTargetSessionRuntimeError("receipt content address is invalid")
    return MappingProxyType(candidate.to_dict())


__all__ = [
    "AtomicLeaseUseStore",
    "AuthorizedTargetSessionPolicy",
    "AuthorizedTargetSessionRuntimeError",
    "CleanupStatus",
    "CredentialSessionCommand",
    "CredentialSessionProvider",
    "CredentialSessionProviderFailure",
    "CredentialSessionResult",
    "LeaseRevocationChecker",
    "LeaseUseCompletionEvidence",
    "LeaseUseReservationEvidence",
    "LeaseUseReservationRequest",
    "LeaseUseReservationStatus",
    "LeaseUseStoreFailure",
    "OpaqueLeaseBinding",
    "RevocationObservation",
    "RevocationStatus",
    "SessionAcquisitionStatus",
    "TargetSessionReceipt",
    "TargetSessionRuntimeClock",
    "TargetSessionSafetyMonitor",
    "TargetSessionSafetySnapshot",
    "execute_authorized_target_session",
    "principal_attestation_sha256",
    "session_attestation_sha256",
    "verify_target_session_receipt",
]
