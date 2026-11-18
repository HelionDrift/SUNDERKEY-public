"""Authenticated-target session contracts with no networking or secret material.

The records in this module bind authenticated assessment activity to an exact
tenant, mission, scope, target, worker, session, and fencing context. They
describe evidence and transport-ready digests only. They never resolve a
credential, create a network client, perform login, answer MFA, follow a
redirect, refresh a token, send a request, or terminate a remote session.
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
MAX_WINDOW_SECONDS = 86_400
MAX_AUTHORIZATION_CASES = 64

NO_EFFECTS = MappingProxyType(
    {
        "authentication": "none",
        "credential_resolution": "none",
        "logout": "none",
        "mfa_response": "none",
        "network": "none",
        "redirect_following": "none",
        "refresh": "none",
        "remote_revocation": "none",
        "request_dispatch": "none",
        "session_creation": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|scoperef|targetref|workerref|sessionref|fenceref|"
    r"principalref|leaseref|evidenceref|checkpointref|operatorref|cookieref|"
    r"caseref|reasonref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
HEADER_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}\Z")
SECRET_MATERIAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}|"
    r"\b(?:cookie|set-cookie)\s*:\s*[^\s]+|"
    r"\b(?:password|passwd|secret|access_token|refresh_token|id_token|otp|"
    r"authorization_code|session_cookie)\s*[:=]\s*[^,}\s]+|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)


class AuthenticatedTargetContractError(ValueError):
    """Raised when an authenticated-target contract fails closed."""


class AuthenticationMethod(StrEnum):
    BASIC = "basic"
    BEARER = "bearer"
    COOKIE_SESSION = "cookie_session"
    OAUTH2_PKCE = "oauth2_pkce"
    OIDC_PKCE = "oidc_pkce"


class MFAStatus(StrEnum):
    OPERATOR_CONFIRMED = "operator_confirmed"
    OPERATOR_DECLINED = "operator_declined"


class AdmissionStatus(StrEnum):
    ADMITTED = "admitted"
    DENIED = "denied"


class TerminationReason(StrEnum):
    LOGOUT = "logout"
    REVOKED = "revoked"
    EXPIRED = "expired"
    OPERATOR_STOP = "operator_stop"
    FENCE_REPLACED = "fence_replaced"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret scanning."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_MATERIAL_RE.search(encoded):
        raise AuthenticatedTargetContractError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise AuthenticatedTargetContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthenticatedTargetContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AuthenticatedTargetContractError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise AuthenticatedTargetContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise AuthenticatedTargetContractError(f"{label} must use the {namespace} namespace")
    if SECRET_MATERIAL_RE.search(value):
        raise AuthenticatedTargetContractError(f"{label} contains secret material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AuthenticatedTargetContractError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AuthenticatedTargetContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AuthenticatedTargetContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _evaluated_at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AuthenticatedTargetContractError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _instant(_timestamp(issued_at, f"{label} issued_at"))
    expires = _instant(_timestamp(expires_at, f"{label} expires_at"))
    seconds = (expires - issued).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS:
        raise AuthenticatedTargetContractError(f"{label} window is invalid")


def _current(issued_at: str, expires_at: str, at: datetime) -> bool:
    return _instant(issued_at) <= at < _instant(expires_at)


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise AuthenticatedTargetContractError(f"{label} is invalid") from exc


def _references(
    values: Sequence[str], label: str, namespace: str, *, minimum: int = 1
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AuthenticatedTargetContractError(f"{label} must be a sequence")
    normalized = tuple(_reference(item, f"{label} item", namespace) for item in values)
    if len(normalized) < minimum or len(normalized) != len(set(normalized)):
        raise AuthenticatedTargetContractError(f"{label} count or uniqueness is invalid")
    return tuple(sorted(normalized))


def _header_digests(value: Mapping[str, str], label: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise AuthenticatedTargetContractError(f"{label} must be a bounded mapping")
    normalized: dict[str, str] = {}
    for name, digest in value.items():
        if not isinstance(name, str) or HEADER_NAME_RE.fullmatch(name) is None:
            raise AuthenticatedTargetContractError(f"{label} contains an invalid header name")
        lowered = name.lower()
        if lowered in normalized:
            raise AuthenticatedTargetContractError(f"{label} contains duplicate header names")
        normalized[lowered] = _digest(digest, f"{label}.{lowered}")
    return MappingProxyType(dict(sorted(normalized.items())))


def _metadata(body: Mapping[str, Any], kind: str) -> None:
    if body.get("kind") != kind or body.get("schema_version") != SCHEMA_VERSION:
        raise AuthenticatedTargetContractError("contract metadata is invalid")
    if body.get("effects") != dict(NO_EFFECTS):
        raise AuthenticatedTargetContractError("contract attempts effect escalation")


@dataclass(frozen=True, slots=True)
class SessionContextBinding:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    target_ref: str
    worker_ref: str
    session_ref: str
    fence_ref: str
    fencing_token_sha256: str
    fence_epoch: int

    def __post_init__(self) -> None:
        namespaces = (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
            ("worker_ref", "workerref"),
            ("session_ref", "sessionref"),
            ("fence_ref", "fenceref"),
        )
        for field_name, namespace in namespaces:
            object.__setattr__(
                self,
                field_name,
                _reference(getattr(self, field_name), field_name, namespace),
            )
        object.__setattr__(
            self,
            "fencing_token_sha256",
            _digest(self.fencing_token_sha256, "fencing_token_sha256"),
        )
        if isinstance(self.fence_epoch, bool) or not 1 <= self.fence_epoch <= 2**63 - 1:
            raise AuthenticatedTargetContractError("fence_epoch is invalid")

    @property
    def context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "fence_epoch": self.fence_epoch,
            "fence_ref": self.fence_ref,
            "fencing_token_sha256": self.fencing_token_sha256,
            "mission_ref": self.mission_ref,
            "scope_ref": self.scope_ref,
            "session_ref": self.session_ref,
            "target_ref": self.target_ref,
            "tenant_ref": self.tenant_ref,
            "worker_ref": self.worker_ref,
        }


@dataclass(frozen=True, slots=True)
class OpaqueCredentialLease:
    lease_ref: str
    authentication_method: AuthenticationMethod
    descriptor_sha256: str
    principal_ref: str
    context_sha256: str
    issued_at: str
    expires_at: str
    revoked_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "lease_ref", _reference(self.lease_ref, "lease_ref", "leaseref"))
        object.__setattr__(
            self,
            "authentication_method",
            _enum(AuthenticationMethod, self.authentication_method, "authentication_method"),
        )
        object.__setattr__(
            self, "descriptor_sha256", _digest(self.descriptor_sha256, "descriptor_sha256")
        )
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        _window(self.issued_at, self.expires_at, "lease")
        if self.revoked_at is not None:
            revoked = _instant(_timestamp(self.revoked_at, "revoked_at"))
            if not _instant(self.issued_at) <= revoked <= _instant(self.expires_at):
                raise AuthenticatedTargetContractError("revoked_at is outside the lease window")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authentication_method": self.authentication_method.value,
            "context_sha256": self.context_sha256,
            "descriptor_sha256": self.descriptor_sha256,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "lease_ref": self.lease_ref,
            "principal_ref": self.principal_ref,
            "revoked_at": self.revoked_at,
        }


@dataclass(frozen=True, slots=True)
class RedirectPKCEEvidence:
    protocol: AuthenticationMethod
    evidence_ref: str
    context_sha256: str
    state_sha256: str
    pkce_challenge_sha256: str
    redirect_uri_sha256: str
    authorization_response_sha256: str
    nonce_sha256: str | None
    observed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "protocol", _enum(AuthenticationMethod, self.protocol, "protocol"))
        if self.protocol not in {AuthenticationMethod.OAUTH2_PKCE, AuthenticationMethod.OIDC_PKCE}:
            raise AuthenticatedTargetContractError("redirect evidence requires OAuth or OIDC PKCE")
        object.__setattr__(
            self, "evidence_ref", _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        )
        for name in (
            "context_sha256",
            "state_sha256",
            "pkce_challenge_sha256",
            "redirect_uri_sha256",
            "authorization_response_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        if self.nonce_sha256 is not None:
            object.__setattr__(self, "nonce_sha256", _digest(self.nonce_sha256, "nonce_sha256"))
        if self.protocol is AuthenticationMethod.OIDC_PKCE and self.nonce_sha256 is None:
            raise AuthenticatedTargetContractError("OIDC evidence requires a nonce digest")
        if self.protocol is AuthenticationMethod.OAUTH2_PKCE and self.nonce_sha256 is not None:
            raise AuthenticatedTargetContractError(
                "OAuth evidence must not claim OIDC nonce evidence"
            )
        _window(self.observed_at, self.expires_at, "redirect evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_response_sha256": self.authorization_response_sha256,
            "context_sha256": self.context_sha256,
            "evidence_ref": self.evidence_ref,
            "expires_at": self.expires_at,
            "nonce_sha256": self.nonce_sha256,
            "observed_at": self.observed_at,
            "pkce_challenge_sha256": self.pkce_challenge_sha256,
            "protocol": self.protocol.value,
            "redirect_uri_sha256": self.redirect_uri_sha256,
            "state_sha256": self.state_sha256,
        }


@dataclass(frozen=True, slots=True)
class MFACheckpointEvidence:
    checkpoint_ref: str
    operator_ref: str
    context_sha256: str
    challenge_sha256: str
    status: MFAStatus
    observed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "checkpoint_ref",
            _reference(self.checkpoint_ref, "checkpoint_ref", "checkpointref"),
        )
        object.__setattr__(
            self, "operator_ref", _reference(self.operator_ref, "operator_ref", "operatorref")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        object.__setattr__(
            self, "challenge_sha256", _digest(self.challenge_sha256, "challenge_sha256")
        )
        object.__setattr__(self, "status", _enum(MFAStatus, self.status, "status"))
        _window(self.observed_at, self.expires_at, "MFA checkpoint")

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_sha256": self.challenge_sha256,
            "checkpoint_ref": self.checkpoint_ref,
            "context_sha256": self.context_sha256,
            "expires_at": self.expires_at,
            "observed_at": self.observed_at,
            "operator_ref": self.operator_ref,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class RefreshEvidence:
    evidence_ref: str
    context_sha256: str
    predecessor_lease_ref: str
    successor_lease_ref: str
    exchange_sha256: str
    observed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_ref", _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        for name in ("predecessor_lease_ref", "successor_lease_ref"):
            object.__setattr__(self, name, _reference(getattr(self, name), name, "leaseref"))
        if self.predecessor_lease_ref == self.successor_lease_ref:
            raise AuthenticatedTargetContractError("refresh must rotate the lease reference")
        object.__setattr__(
            self, "exchange_sha256", _digest(self.exchange_sha256, "exchange_sha256")
        )
        _window(self.observed_at, self.expires_at, "refresh evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_sha256": self.context_sha256,
            "evidence_ref": self.evidence_ref,
            "exchange_sha256": self.exchange_sha256,
            "expires_at": self.expires_at,
            "observed_at": self.observed_at,
            "predecessor_lease_ref": self.predecessor_lease_ref,
            "successor_lease_ref": self.successor_lease_ref,
        }


@dataclass(frozen=True, slots=True)
class AuthenticatedSessionContract:
    context: SessionContextBinding
    authentication_method: AuthenticationMethod
    principal_ref: str
    lease: OpaqueCredentialLease
    cookie_jar_ref: str | None
    isolation_nonce_sha256: str
    redirect_evidence: RedirectPKCEEvidence | None
    mfa_checkpoint: MFACheckpointEvidence | None
    refresh_evidence: tuple[RefreshEvidence, ...]
    issued_at: str
    expires_at: str
    contract_id: str = field(init=False)
    contract_sha256: str = field(init=False)

    KIND: ClassVar[str] = "authenticated_session_contract"
    PREFIX: ClassVar[str] = "ASC"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.session.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.context, SessionContextBinding) or not isinstance(
            self.lease, OpaqueCredentialLease
        ):
            raise AuthenticatedTargetContractError("session context or lease is invalid")
        object.__setattr__(
            self,
            "authentication_method",
            _enum(AuthenticationMethod, self.authentication_method, "authentication_method"),
        )
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        if self.cookie_jar_ref is not None:
            object.__setattr__(
                self,
                "cookie_jar_ref",
                _reference(self.cookie_jar_ref, "cookie_jar_ref", "cookieref"),
            )
        object.__setattr__(
            self,
            "isolation_nonce_sha256",
            _digest(self.isolation_nonce_sha256, "isolation_nonce_sha256"),
        )
        refresh = tuple(self.refresh_evidence)
        if len(refresh) != len({item.evidence_ref for item in refresh}) or len(refresh) > 16:
            raise AuthenticatedTargetContractError("refresh evidence is duplicated or excessive")
        object.__setattr__(self, "refresh_evidence", refresh)
        _window(self.issued_at, self.expires_at, "session contract")
        self._validate_bindings()
        body = self._body()
        identity, digest = _identity(self.PREFIX, self.DOMAIN, body)
        object.__setattr__(self, "contract_id", identity)
        object.__setattr__(self, "contract_sha256", digest)

    def _validate_bindings(self) -> None:
        context_digest = self.context.context_sha256
        if (
            self.lease.context_sha256 != context_digest
            or self.lease.principal_ref != self.principal_ref
            or self.lease.authentication_method is not self.authentication_method
        ):
            raise AuthenticatedTargetContractError("lease is not bound to the session context")
        if self.authentication_method is AuthenticationMethod.COOKIE_SESSION:
            if self.cookie_jar_ref is None:
                raise AuthenticatedTargetContractError(
                    "cookie sessions require an isolated cookie jar"
                )
        elif self.cookie_jar_ref is not None:
            raise AuthenticatedTargetContractError("cookie jar is valid only for cookie sessions")
        redirect_required = self.authentication_method in {
            AuthenticationMethod.OAUTH2_PKCE,
            AuthenticationMethod.OIDC_PKCE,
        }
        if redirect_required != (self.redirect_evidence is not None):
            raise AuthenticatedTargetContractError("redirect evidence requirement is not satisfied")
        if self.redirect_evidence is not None and (
            self.redirect_evidence.context_sha256 != context_digest
            or self.redirect_evidence.protocol is not self.authentication_method
        ):
            raise AuthenticatedTargetContractError("redirect evidence is cross-context")
        if self.mfa_checkpoint is not None and self.mfa_checkpoint.context_sha256 != context_digest:
            raise AuthenticatedTargetContractError("MFA evidence is cross-context")
        predecessor = self.lease.lease_ref
        for item in self.refresh_evidence:
            if item.context_sha256 != context_digest or item.predecessor_lease_ref != predecessor:
                raise AuthenticatedTargetContractError("refresh evidence chain is invalid")
            predecessor = item.successor_lease_ref
        if _instant(self.issued_at) < _instant(self.lease.issued_at):
            raise AuthenticatedTargetContractError("session predates its credential lease")
        if (
            _instant(self.expires_at) > _instant(self.lease.expires_at)
            and not self.refresh_evidence
        ):
            raise AuthenticatedTargetContractError(
                "session exceeds its lease without refresh evidence"
            )

    @property
    def active_lease_ref(self) -> str:
        return (
            self.refresh_evidence[-1].successor_lease_ref
            if self.refresh_evidence
            else self.lease.lease_ref
        )

    def _body(self) -> dict[str, Any]:
        return {
            "authentication_method": self.authentication_method.value,
            "context": self.context.to_dict(),
            "cookie_jar_ref": self.cookie_jar_ref,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "isolation_nonce_sha256": self.isolation_nonce_sha256,
            "issued_at": self.issued_at,
            "kind": self.KIND,
            "lease": self.lease.to_dict(),
            "mfa_checkpoint": self.mfa_checkpoint.to_dict() if self.mfa_checkpoint else None,
            "principal_ref": self.principal_ref,
            "redirect_evidence": (
                self.redirect_evidence.to_dict() if self.redirect_evidence else None
            ),
            "refresh_evidence": [item.to_dict() for item in self.refresh_evidence],
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class PrincipalAuthorizationCase:
    case_ref: str
    principal_ref: str
    session_ref: str
    role_sha256: str
    resource_sha256: str
    action_sha256: str
    expected_allowed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_ref", _reference(self.case_ref, "case_ref", "caseref"))
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(
            self, "session_ref", _reference(self.session_ref, "session_ref", "sessionref")
        )
        for name in ("role_sha256", "resource_sha256", "action_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        if not isinstance(self.expected_allowed, bool):
            raise AuthenticatedTargetContractError("expected_allowed must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "case_ref": self.case_ref,
            "expected_allowed": self.expected_allowed,
            "principal_ref": self.principal_ref,
            "resource_sha256": self.resource_sha256,
            "role_sha256": self.role_sha256,
            "session_ref": self.session_ref,
        }


@dataclass(frozen=True, slots=True)
class MultiPrincipalAuthorizationPlan:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    target_ref: str
    cases: tuple[PrincipalAuthorizationCase, ...]
    issued_at: str
    expires_at: str
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "multi_principal_authorization_plan"
    PREFIX: ClassVar[str] = "MAP"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.multi-principal.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        cases = tuple(self.cases)
        if not 2 <= len(cases) <= MAX_AUTHORIZATION_CASES:
            raise AuthenticatedTargetContractError("multi-principal plan requires 2 to 64 cases")
        if not all(isinstance(item, PrincipalAuthorizationCase) for item in cases):
            raise AuthenticatedTargetContractError("authorization case is invalid")
        if len({item.case_ref for item in cases}) != len(cases):
            raise AuthenticatedTargetContractError("authorization case references must be unique")
        if len({item.session_ref for item in cases}) != len(cases):
            raise AuthenticatedTargetContractError(
                "each principal case requires an isolated session"
            )
        if len({item.principal_ref for item in cases}) < 2:
            raise AuthenticatedTargetContractError(
                "multi-principal plan requires distinct principals"
            )
        if not any(not item.expected_allowed for item in cases):
            raise AuthenticatedTargetContractError("plan requires a negative authorization case")
        object.__setattr__(self, "cases", tuple(sorted(cases, key=lambda item: item.case_ref)))
        _window(self.issued_at, self.expires_at, "authorization plan")
        identity, digest = _identity(self.PREFIX, self.DOMAIN, self._body())
        object.__setattr__(self, "plan_id", identity)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cases": [item.to_dict() for item in self.cases],
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "kind": self.KIND,
            "mission_ref": self.mission_ref,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "target_ref": self.target_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "plan_sha256": self.plan_sha256, **self._body()}


@dataclass(frozen=True, slots=True)
class SessionAdmission:
    contract_id: str
    contract_sha256: str
    context_sha256: str
    active_lease_ref: str
    status: AdmissionStatus
    reason_refs: tuple[str, ...]
    evaluated_at: str
    admission_id: str = field(init=False)
    admission_sha256: str = field(init=False)

    KIND: ClassVar[str] = "session_admission"
    PREFIX: ClassVar[str] = "ASA"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.admission.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.contract_id, str) or not re.fullmatch(
            r"ASC-[0-9A-F]{32}", self.contract_id
        ):
            raise AuthenticatedTargetContractError("contract_id is invalid")
        object.__setattr__(
            self, "contract_sha256", _digest(self.contract_sha256, "contract_sha256")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        object.__setattr__(
            self,
            "active_lease_ref",
            _reference(self.active_lease_ref, "active_lease_ref", "leaseref"),
        )
        object.__setattr__(self, "status", _enum(AdmissionStatus, self.status, "status"))
        object.__setattr__(
            self,
            "reason_refs",
            _references(self.reason_refs, "reason_refs", "reasonref", minimum=0),
        )
        object.__setattr__(self, "evaluated_at", _timestamp(self.evaluated_at, "evaluated_at"))
        if (self.status is AdmissionStatus.ADMITTED) == bool(self.reason_refs):
            raise AuthenticatedTargetContractError("admission reasons do not match status")
        identity, digest = _identity(self.PREFIX, self.DOMAIN, self._body())
        object.__setattr__(self, "admission_id", identity)
        object.__setattr__(self, "admission_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "active_lease_ref": self.active_lease_ref,
            "context_sha256": self.context_sha256,
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": self.KIND,
            "reason_refs": list(self.reason_refs),
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
            **self._body(),
        }


def evaluate_session_admission(
    contract: AuthenticatedSessionContract,
    expected_context: SessionContextBinding,
    *,
    evaluated_at: datetime,
    observed_fencing_token_sha256: str,
    revoked_lease_refs: Sequence[str] = (),
) -> SessionAdmission:
    """Evaluate a session locally without resolving secrets or contacting a target."""

    if not isinstance(contract, AuthenticatedSessionContract) or not isinstance(
        expected_context, SessionContextBinding
    ):
        raise AuthenticatedTargetContractError("contract and expected context are required")
    at = _evaluated_at(evaluated_at)
    observed_fence = _digest(observed_fencing_token_sha256, "observed_fencing_token_sha256")
    revoked = set(_references(revoked_lease_refs, "revoked_lease_refs", "leaseref", minimum=0))
    reasons: set[str] = set()
    if contract.context != expected_context:
        reasons.add("reasonref:context-mismatch")
    if observed_fence != expected_context.fencing_token_sha256:
        reasons.add("reasonref:fence-mismatch")
    if not _current(contract.issued_at, contract.expires_at, at):
        reasons.add("reasonref:session-stale")
    if contract.lease.revoked_at is not None or contract.active_lease_ref in revoked:
        reasons.add("reasonref:lease-revoked")
    if (
        not _current(contract.lease.issued_at, contract.lease.expires_at, at)
        and not contract.refresh_evidence
    ):
        reasons.add("reasonref:lease-stale")
    if contract.redirect_evidence is not None and not _current(
        contract.redirect_evidence.observed_at, contract.redirect_evidence.expires_at, at
    ):
        reasons.add("reasonref:redirect-evidence-stale")
    if contract.mfa_checkpoint is not None:
        if contract.mfa_checkpoint.status is not MFAStatus.OPERATOR_CONFIRMED:
            reasons.add("reasonref:mfa-not-confirmed")
        if not _current(
            contract.mfa_checkpoint.observed_at, contract.mfa_checkpoint.expires_at, at
        ):
            reasons.add("reasonref:mfa-evidence-stale")
    if contract.refresh_evidence and not _current(
        contract.refresh_evidence[-1].observed_at,
        contract.refresh_evidence[-1].expires_at,
        at,
    ):
        reasons.add("reasonref:refresh-evidence-stale")
    return SessionAdmission(
        contract_id=contract.contract_id,
        contract_sha256=contract.contract_sha256,
        context_sha256=contract.context.context_sha256,
        active_lease_ref=contract.active_lease_ref,
        status=AdmissionStatus.DENIED if reasons else AdmissionStatus.ADMITTED,
        reason_refs=tuple(sorted(reasons)),
        evaluated_at=at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


@dataclass(frozen=True, slots=True)
class PreparedAuthenticatedRequest:
    admission_id: str
    admission_sha256: str
    context_sha256: str
    method_sha256: str
    request_target_sha256: str
    header_value_sha256: Mapping[str, str]
    body_sha256: str | None
    prepared_at: str
    expires_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "prepared_authenticated_request"
    PREFIX: ClassVar[str] = "AQR"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.request.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.admission_id, str)
            or re.fullmatch(r"ASA-[0-9A-F]{32}", self.admission_id) is None
        ):
            raise AuthenticatedTargetContractError("admission_id is invalid")
        for name in (
            "admission_sha256",
            "context_sha256",
            "method_sha256",
            "request_target_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(
            self,
            "header_value_sha256",
            _header_digests(self.header_value_sha256, "header_value_sha256"),
        )
        if self.body_sha256 is not None:
            object.__setattr__(self, "body_sha256", _digest(self.body_sha256, "body_sha256"))
        _window(self.prepared_at, self.expires_at, "prepared request")
        identity, digest = _identity(self.PREFIX, self.DOMAIN, self._body())
        object.__setattr__(self, "request_id", identity)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
            "body_sha256": self.body_sha256,
            "context_sha256": self.context_sha256,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "header_value_sha256": dict(self.header_value_sha256),
            "kind": self.KIND,
            "method_sha256": self.method_sha256,
            "prepared_at": self.prepared_at,
            "request_target_sha256": self.request_target_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


def prepare_authenticated_request(
    admission: SessionAdmission,
    *,
    method_sha256: str,
    request_target_sha256: str,
    header_value_sha256: Mapping[str, str],
    body_sha256: str | None,
    prepared_at: str,
    expires_at: str,
) -> PreparedAuthenticatedRequest:
    """Prepare digest-only transport data after successful local admission."""

    if (
        not isinstance(admission, SessionAdmission)
        or admission.status is not AdmissionStatus.ADMITTED
    ):
        raise AuthenticatedTargetContractError("only an admitted session may prepare a request")
    if not _current(admission.evaluated_at, expires_at, _instant(prepared_at)):
        raise AuthenticatedTargetContractError(
            "request preparation is outside the admission window"
        )
    return PreparedAuthenticatedRequest(
        admission_id=admission.admission_id,
        admission_sha256=admission.admission_sha256,
        context_sha256=admission.context_sha256,
        method_sha256=method_sha256,
        request_target_sha256=request_target_sha256,
        header_value_sha256=header_value_sha256,
        body_sha256=body_sha256,
        prepared_at=prepared_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True, slots=True)
class NormalizedAuthenticatedResponse:
    request_id: str
    request_sha256: str
    context_sha256: str
    status_code: int
    header_value_sha256: Mapping[str, str]
    body_sha256: str
    body_size_bytes: int
    received_at: str
    response_id: str = field(init=False)
    response_sha256: str = field(init=False)

    KIND: ClassVar[str] = "normalized_authenticated_response"
    PREFIX: ClassVar[str] = "ANR"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.response.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"AQR-[0-9A-F]{32}", self.request_id) is None
        ):
            raise AuthenticatedTargetContractError("request_id is invalid")
        object.__setattr__(self, "request_sha256", _digest(self.request_sha256, "request_sha256"))
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        if isinstance(self.status_code, bool) or not 100 <= self.status_code <= 599:
            raise AuthenticatedTargetContractError("status_code is invalid")
        object.__setattr__(
            self,
            "header_value_sha256",
            _header_digests(self.header_value_sha256, "header_value_sha256"),
        )
        object.__setattr__(self, "body_sha256", _digest(self.body_sha256, "body_sha256"))
        if (
            isinstance(self.body_size_bytes, bool)
            or not 0 <= self.body_size_bytes <= 64 * 1024 * 1024
        ):
            raise AuthenticatedTargetContractError("body_size_bytes is invalid")
        object.__setattr__(self, "received_at", _timestamp(self.received_at, "received_at"))
        identity, digest = _identity(self.PREFIX, self.DOMAIN, self._body())
        object.__setattr__(self, "response_id", identity)
        object.__setattr__(self, "response_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "body_sha256": self.body_sha256,
            "body_size_bytes": self.body_size_bytes,
            "context_sha256": self.context_sha256,
            "effects": dict(NO_EFFECTS),
            "header_value_sha256": dict(self.header_value_sha256),
            "kind": self.KIND,
            "received_at": self.received_at,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
            "status_code": self.status_code,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "response_id": self.response_id,
            "response_sha256": self.response_sha256,
            **self._body(),
        }


def normalize_authenticated_response(
    request: PreparedAuthenticatedRequest,
    *,
    status_code: int,
    header_value_sha256: Mapping[str, str],
    body_sha256: str,
    body_size_bytes: int,
    received_at: str,
) -> NormalizedAuthenticatedResponse:
    """Normalize a caller-supplied response without receiving network bytes."""

    if not isinstance(request, PreparedAuthenticatedRequest):
        raise AuthenticatedTargetContractError("prepared request is required")
    if not _instant(request.prepared_at) <= _instant(_timestamp(received_at, "received_at")):
        raise AuthenticatedTargetContractError("response predates the request")
    return NormalizedAuthenticatedResponse(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        context_sha256=request.context_sha256,
        status_code=status_code,
        header_value_sha256=header_value_sha256,
        body_sha256=body_sha256,
        body_size_bytes=body_size_bytes,
        received_at=received_at,
    )


@dataclass(frozen=True, slots=True)
class SessionTerminationEvidence:
    contract_id: str
    contract_sha256: str
    context_sha256: str
    reason: TerminationReason
    evidence_refs: tuple[str, ...]
    logout_observed: bool
    revocation_observed: bool
    terminated_at: str
    termination_id: str = field(init=False)
    termination_sha256: str = field(init=False)

    KIND: ClassVar[str] = "session_termination_evidence"
    PREFIX: ClassVar[str] = "ATE"
    DOMAIN: ClassVar[str] = "sunderkey.authenticated-target.termination.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.contract_id, str)
            or re.fullmatch(r"ASC-[0-9A-F]{32}", self.contract_id) is None
        ):
            raise AuthenticatedTargetContractError("contract_id is invalid")
        object.__setattr__(
            self, "contract_sha256", _digest(self.contract_sha256, "contract_sha256")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        object.__setattr__(self, "reason", _enum(TerminationReason, self.reason, "reason"))
        object.__setattr__(
            self,
            "evidence_refs",
            _references(self.evidence_refs, "evidence_refs", "evidenceref"),
        )
        if not isinstance(self.logout_observed, bool) or not isinstance(
            self.revocation_observed, bool
        ):
            raise AuthenticatedTargetContractError("termination observations must be boolean")
        if self.reason is TerminationReason.LOGOUT and not self.logout_observed:
            raise AuthenticatedTargetContractError("logout termination requires logout evidence")
        if self.reason is TerminationReason.REVOKED and not self.revocation_observed:
            raise AuthenticatedTargetContractError(
                "revocation termination requires revocation evidence"
            )
        object.__setattr__(self, "terminated_at", _timestamp(self.terminated_at, "terminated_at"))
        identity, digest = _identity(self.PREFIX, self.DOMAIN, self._body())
        object.__setattr__(self, "termination_id", identity)
        object.__setattr__(self, "termination_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "context_sha256": self.context_sha256,
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "effects": dict(NO_EFFECTS),
            "evidence_refs": list(self.evidence_refs),
            "kind": self.KIND,
            "logout_observed": self.logout_observed,
            "reason": self.reason.value,
            "revocation_observed": self.revocation_observed,
            "schema_version": SCHEMA_VERSION,
            "terminated_at": self.terminated_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "termination_id": self.termination_id,
            "termination_sha256": self.termination_sha256,
            **self._body(),
        }


def record_session_termination(
    contract: AuthenticatedSessionContract,
    *,
    reason: TerminationReason,
    evidence_refs: Sequence[str],
    logout_observed: bool,
    revocation_observed: bool,
    terminated_at: str,
) -> SessionTerminationEvidence:
    """Record caller-supplied termination evidence without remote effects."""

    if not isinstance(contract, AuthenticatedSessionContract):
        raise AuthenticatedTargetContractError("session contract is required")
    at = _instant(_timestamp(terminated_at, "terminated_at"))
    if at < _instant(contract.issued_at):
        raise AuthenticatedTargetContractError("termination predates the session")
    return SessionTerminationEvidence(
        contract_id=contract.contract_id,
        contract_sha256=contract.contract_sha256,
        context_sha256=contract.context.context_sha256,
        reason=reason,
        evidence_refs=tuple(evidence_refs),
        logout_observed=logout_observed,
        revocation_observed=revocation_observed,
        terminated_at=terminated_at,
    )


def parse_contract(raw: Mapping[str, Any]) -> object:
    """Parse and verify any top-level authenticated-target record."""

    if not isinstance(raw, Mapping):
        raise AuthenticatedTargetContractError("record must be a mapping")
    kind = raw.get("kind")
    parsers = {
        AuthenticatedSessionContract.KIND: _parse_session,
        MultiPrincipalAuthorizationPlan.KIND: _parse_plan,
        SessionAdmission.KIND: _parse_admission,
        PreparedAuthenticatedRequest.KIND: _parse_request,
        NormalizedAuthenticatedResponse.KIND: _parse_response,
        SessionTerminationEvidence.KIND: _parse_termination,
    }
    parser = parsers.get(kind)
    if parser is None:
        raise AuthenticatedTargetContractError("record kind is unsupported")
    candidate = parser(raw)
    if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
        raise AuthenticatedTargetContractError("record identity or contents are invalid")
    return candidate


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise AuthenticatedTargetContractError(f"{label} fields are invalid")
    return raw


def _context(raw: Any) -> SessionContextBinding:
    value = _exact(
        raw,
        {
            "fence_epoch",
            "fence_ref",
            "fencing_token_sha256",
            "mission_ref",
            "scope_ref",
            "session_ref",
            "target_ref",
            "tenant_ref",
            "worker_ref",
        },
        "context",
    )
    return SessionContextBinding(**value)


def _lease(raw: Any) -> OpaqueCredentialLease:
    value = _exact(
        raw,
        {
            "authentication_method",
            "context_sha256",
            "descriptor_sha256",
            "expires_at",
            "issued_at",
            "lease_ref",
            "principal_ref",
            "revoked_at",
        },
        "lease",
    )
    return OpaqueCredentialLease(**value)


def _redirect(raw: Any) -> RedirectPKCEEvidence | None:
    if raw is None:
        return None
    value = _exact(
        raw,
        {
            "authorization_response_sha256",
            "context_sha256",
            "evidence_ref",
            "expires_at",
            "nonce_sha256",
            "observed_at",
            "pkce_challenge_sha256",
            "protocol",
            "redirect_uri_sha256",
            "state_sha256",
        },
        "redirect_evidence",
    )
    return RedirectPKCEEvidence(**value)


def _mfa(raw: Any) -> MFACheckpointEvidence | None:
    if raw is None:
        return None
    value = _exact(
        raw,
        {
            "challenge_sha256",
            "checkpoint_ref",
            "context_sha256",
            "expires_at",
            "observed_at",
            "operator_ref",
            "status",
        },
        "mfa_checkpoint",
    )
    return MFACheckpointEvidence(**value)


def _refresh(raw: Any) -> RefreshEvidence:
    value = _exact(
        raw,
        {
            "context_sha256",
            "evidence_ref",
            "exchange_sha256",
            "expires_at",
            "observed_at",
            "predecessor_lease_ref",
            "successor_lease_ref",
        },
        "refresh_evidence",
    )
    return RefreshEvidence(**value)


def _parse_session(raw: Mapping[str, Any]) -> AuthenticatedSessionContract:
    fields = {
        "authentication_method",
        "context",
        "contract_id",
        "contract_sha256",
        "cookie_jar_ref",
        "effects",
        "expires_at",
        "isolation_nonce_sha256",
        "issued_at",
        "kind",
        "lease",
        "mfa_checkpoint",
        "principal_ref",
        "redirect_evidence",
        "refresh_evidence",
        "schema_version",
    }
    value = _exact(raw, fields, "session contract")
    _metadata(value, AuthenticatedSessionContract.KIND)
    candidate = AuthenticatedSessionContract(
        context=_context(value["context"]),
        authentication_method=value["authentication_method"],
        principal_ref=value["principal_ref"],
        lease=_lease(value["lease"]),
        cookie_jar_ref=value["cookie_jar_ref"],
        isolation_nonce_sha256=value["isolation_nonce_sha256"],
        redirect_evidence=_redirect(value["redirect_evidence"]),
        mfa_checkpoint=_mfa(value["mfa_checkpoint"]),
        refresh_evidence=tuple(_refresh(item) for item in value["refresh_evidence"]),
        issued_at=value["issued_at"],
        expires_at=value["expires_at"],
    )
    return candidate


def _case(raw: Any) -> PrincipalAuthorizationCase:
    value = _exact(
        raw,
        {
            "action_sha256",
            "case_ref",
            "expected_allowed",
            "principal_ref",
            "resource_sha256",
            "role_sha256",
            "session_ref",
        },
        "authorization case",
    )
    return PrincipalAuthorizationCase(**value)


def _parse_plan(raw: Mapping[str, Any]) -> MultiPrincipalAuthorizationPlan:
    fields = {
        "cases",
        "effects",
        "expires_at",
        "issued_at",
        "kind",
        "mission_ref",
        "plan_id",
        "plan_sha256",
        "schema_version",
        "scope_ref",
        "target_ref",
        "tenant_ref",
    }
    value = _exact(raw, fields, "authorization plan")
    _metadata(value, MultiPrincipalAuthorizationPlan.KIND)
    return MultiPrincipalAuthorizationPlan(
        tenant_ref=value["tenant_ref"],
        mission_ref=value["mission_ref"],
        scope_ref=value["scope_ref"],
        target_ref=value["target_ref"],
        cases=tuple(_case(item) for item in value["cases"]),
        issued_at=value["issued_at"],
        expires_at=value["expires_at"],
    )


def _parse_admission(raw: Mapping[str, Any]) -> SessionAdmission:
    fields = {
        "active_lease_ref",
        "admission_id",
        "admission_sha256",
        "context_sha256",
        "contract_id",
        "contract_sha256",
        "effects",
        "evaluated_at",
        "kind",
        "reason_refs",
        "schema_version",
        "status",
    }
    value = _exact(raw, fields, "session admission")
    _metadata(value, SessionAdmission.KIND)
    return SessionAdmission(
        contract_id=value["contract_id"],
        contract_sha256=value["contract_sha256"],
        context_sha256=value["context_sha256"],
        active_lease_ref=value["active_lease_ref"],
        status=value["status"],
        reason_refs=tuple(value["reason_refs"]),
        evaluated_at=value["evaluated_at"],
    )


def _parse_request(raw: Mapping[str, Any]) -> PreparedAuthenticatedRequest:
    fields = {
        "admission_id",
        "admission_sha256",
        "body_sha256",
        "context_sha256",
        "effects",
        "expires_at",
        "header_value_sha256",
        "kind",
        "method_sha256",
        "prepared_at",
        "request_id",
        "request_sha256",
        "request_target_sha256",
        "schema_version",
    }
    value = _exact(raw, fields, "prepared request")
    _metadata(value, PreparedAuthenticatedRequest.KIND)
    return PreparedAuthenticatedRequest(
        admission_id=value["admission_id"],
        admission_sha256=value["admission_sha256"],
        context_sha256=value["context_sha256"],
        method_sha256=value["method_sha256"],
        request_target_sha256=value["request_target_sha256"],
        header_value_sha256=value["header_value_sha256"],
        body_sha256=value["body_sha256"],
        prepared_at=value["prepared_at"],
        expires_at=value["expires_at"],
    )


def _parse_response(raw: Mapping[str, Any]) -> NormalizedAuthenticatedResponse:
    fields = {
        "body_sha256",
        "body_size_bytes",
        "context_sha256",
        "effects",
        "header_value_sha256",
        "kind",
        "received_at",
        "request_id",
        "request_sha256",
        "response_id",
        "response_sha256",
        "schema_version",
        "status_code",
    }
    value = _exact(raw, fields, "normalized response")
    _metadata(value, NormalizedAuthenticatedResponse.KIND)
    return NormalizedAuthenticatedResponse(
        request_id=value["request_id"],
        request_sha256=value["request_sha256"],
        context_sha256=value["context_sha256"],
        status_code=value["status_code"],
        header_value_sha256=value["header_value_sha256"],
        body_sha256=value["body_sha256"],
        body_size_bytes=value["body_size_bytes"],
        received_at=value["received_at"],
    )


def _parse_termination(raw: Mapping[str, Any]) -> SessionTerminationEvidence:
    fields = {
        "context_sha256",
        "contract_id",
        "contract_sha256",
        "effects",
        "evidence_refs",
        "kind",
        "logout_observed",
        "reason",
        "revocation_observed",
        "schema_version",
        "terminated_at",
        "termination_id",
        "termination_sha256",
    }
    value = _exact(raw, fields, "termination evidence")
    _metadata(value, SessionTerminationEvidence.KIND)
    return SessionTerminationEvidence(
        contract_id=value["contract_id"],
        contract_sha256=value["contract_sha256"],
        context_sha256=value["context_sha256"],
        reason=value["reason"],
        evidence_refs=tuple(value["evidence_refs"]),
        logout_observed=value["logout_observed"],
        revocation_observed=value["revocation_observed"],
        terminated_at=value["terminated_at"],
    )
