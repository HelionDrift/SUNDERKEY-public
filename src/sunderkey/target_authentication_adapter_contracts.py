"""Fail-closed target authentication adapter contracts.

This additive version 2 contract surface binds credential-reference provenance,
provider identity, authentication policy, commands, flow observations, results,
and receipts. It contains no credential resolver, network client, browser,
provider implementation, secret material, or live effect.
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

SCHEMA_VERSION = 2
MAX_WINDOW_SECONDS = 86_400
MAX_FLOW_EVIDENCE = 128

NO_EFFECTS = MappingProxyType(
    {
        "browser_automation": "none",
        "credential_resolution": "none",
        "lifecycle_action": "none",
        "mfa_response": "none",
        "network": "none",
        "provider_invocation": "none",
        "remote_authentication": "none",
        "session_mutation": "none",
    }
)
NO_CLAIMS = MappingProxyType(
    {
        "authorization": "none",
        "deployment": "none",
        "live_readiness": "none",
        "parity": "none",
        "qualification": "none",
        "successful_authentication": "none",
        "superiority": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|scoperef|targetref|principalref|sessionref|"
    r"providerref|instanceref|fixtureref):[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}\Z"
)
CREDENTIAL_SOURCE_RE = re.compile(r"credentialref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
CREDENTIAL_TRANSPORT_RE = re.compile(r"credref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
RECORD_ID_RE = re.compile(r"(?:TAPB|TACP|TAPE|TAAP|TAAC|TAFE|TAAR|TAAT)-[0-9A-F]{32}\Z")
CREDENTIAL_DESCRIPTOR_ID_RE = re.compile(r"CBD-[0-9A-F]{32}\Z")
CREDENTIAL_LEASE_ID_RE = re.compile(r"CLZ-[0-9A-F]{32}\Z")
UPSTREAM_RECORD_ID_PATTERNS = MappingProxyType(
    {
        "execution_policy_id": re.compile(r"ECP-[0-9A-F]{32}\Z"),
        "execution_request_id": re.compile(r"ECRQ-[0-9A-F]{32}\Z"),
        "admission_receipt_id": re.compile(r"ECAR-[0-9A-F]{32}\Z"),
        "runtime_policy_id": re.compile(r"ATSP-[0-9A-F]{32}\Z"),
        "runtime_receipt_id": re.compile(r"ASR-[0-9A-F]{32}\Z"),
    }
)
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|cookie)\s*[:=]\s*[^,}\s]+|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)


class TargetAuthenticationContractError(ValueError):
    """Raised when a version 2 target authentication contract fails closed."""


class ExecutionEnvironment(StrEnum):
    DETERMINISTIC_FIXTURE = "deterministic_fixture"
    EXTERNAL_RUNTIME_OBSERVATION = "external_runtime_observation"


class AuthenticationMode(StrEnum):
    BASIC_REFERENCE = "basic_reference"
    BEARER_REFERENCE = "bearer_reference"
    FORM_LOGIN_PASSWORD = "form_login_password"
    FORM_LOGIN_TOTP = "form_login_totp"
    FORM_LOGIN_EMAIL_OTP = "form_login_email_otp"
    MAGIC_LINK_REFERENCE = "magic_link_reference"
    OAUTH2_PKCE = "oauth2_pkce"
    OIDC_PKCE = "oidc_pkce"


class AuthenticationProtocol(StrEnum):
    HTTP_BASIC = "http_basic"
    HTTP_BEARER = "http_bearer"
    HTML_FORM = "html_form"
    MAGIC_LINK = "magic_link"
    OAUTH2 = "oauth2"
    OIDC = "oidc"


class AuthenticationFactor(StrEnum):
    PASSWORD_REFERENCE = "password_reference"
    BEARER_REFERENCE = "bearer_reference"
    TOTP_REFERENCE = "totp_reference"
    EMAIL_OTP_REFERENCE = "email_otp_reference"
    MAGIC_LINK_REFERENCE = "magic_link_reference"
    FEDERATED_IDENTITY_SESSION_REFERENCE = "federated_identity_session_reference"
    PKCE_VERIFIER_REFERENCE = "pkce_verifier_reference"


class PrincipalTopology(StrEnum):
    SINGLE_PRINCIPAL = "single_principal"
    MULTI_PRINCIPAL = "multi_principal"
    FEDERATED_PRINCIPAL = "federated_principal"


class SessionCarrier(StrEnum):
    AUTHORIZATION_HEADER_REFERENCE = "authorization_header_reference"
    BROWSER_COOKIE_JAR_REFERENCE = "browser_cookie_jar_reference"
    BROWSER_REDIRECT_CALLBACK_REFERENCE = "browser_redirect_callback_reference"
    MAGIC_LINK_CALLBACK_REFERENCE = "magic_link_callback_reference"


class CredentialLeaseMode(StrEnum):
    ONE_TIME = "one_time"
    SESSION_BOUND = "session_bound"


class AuthenticationOperation(StrEnum):
    ACQUIRE_SESSION = "acquire_session"
    REFRESH_SESSION = "refresh_session"
    TERMINATE_SESSION = "terminate_session"


class FlowStage(StrEnum):
    CREDENTIAL_REFERENCE_BOUND = "credential_reference_bound"
    REDIRECT_OBSERVED = "redirect_observed"
    CHALLENGE_OBSERVED = "challenge_observed"
    CALLBACK_OBSERVED = "callback_observed"
    SESSION_OBSERVED = "session_observed"
    TERMINATION_OBSERVED = "termination_observed"
    FAILURE_OBSERVED = "failure_observed"


class AuthenticationOutcome(StrEnum):
    AUTHENTICATED = "authenticated"
    TERMINATED = "terminated"
    FAILED = "failed"
    STOPPED = "stopped"


class AuthenticationFailureCode(StrEnum):
    COMMAND_EXPIRED = "command_expired"
    CREDENTIAL_REFERENCE_UNAVAILABLE = "credential_reference_unavailable"
    CREDENTIAL_PROVENANCE_MISMATCH = "credential_provenance_mismatch"
    PROVIDER_IDENTITY_MISMATCH = "provider_identity_mismatch"
    POLICY_BINDING_MISMATCH = "policy_binding_mismatch"
    UNSUPPORTED_MODE = "unsupported_mode"
    CHALLENGE_NOT_SATISFIED = "challenge_not_satisfied"
    CALLBACK_INVALID = "callback_invalid"
    SESSION_NOT_ESTABLISHED = "session_not_established"
    SESSION_REFRESH_FAILED = "session_refresh_failed"
    SESSION_TERMINATION_FAILED = "session_termination_failed"
    FIXTURE_SCENARIO_INVALID = "fixture_scenario_invalid"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMEOUT = "timeout"
    OPERATOR_STOP = "operator_stop"
    MISSION_STOP = "mission_stop"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"


class LifecycleObligation(StrEnum):
    SECRET_NON_PERSISTENCE = "secret_non_persistence"
    SESSION_ISOLATION = "session_isolation"
    REFRESH_PREDECESSOR_BOUND = "refresh_predecessor_bound"
    LOGOUT_REQUIRED = "logout_required"
    REVOCATION_OBSERVATION_REQUIRED = "revocation_observation_required"
    MFA_OPERATOR_BOUND = "mfa_operator_bound"


@dataclass(frozen=True, slots=True)
class AuthenticationModeProfile:
    mode: AuthenticationMode
    protocol: AuthenticationProtocol
    factors: tuple[AuthenticationFactor, ...]
    carrier: SessionCarrier
    topology: PrincipalTopology
    successful_flow_stages: tuple[FlowStage, ...]
    lifecycle_obligations: tuple[LifecycleObligation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "factors": [item.value for item in sorted(self.factors, key=str)],
            "carrier": self.carrier.value,
            "lifecycle_obligations": [
                item.value for item in sorted(self.lifecycle_obligations, key=str)
            ],
            "mode": self.mode.value,
            "protocol": self.protocol.value,
            "successful_flow_stages": [item.value for item in self.successful_flow_stages],
            "topology": self.topology.value,
        }


def _profile(
    mode: AuthenticationMode,
    protocol: AuthenticationProtocol,
    factors: tuple[AuthenticationFactor, ...],
    carrier: SessionCarrier,
    topology: PrincipalTopology,
    stages: tuple[FlowStage, ...],
    obligations: tuple[LifecycleObligation, ...],
) -> AuthenticationModeProfile:
    return AuthenticationModeProfile(
        mode, protocol, factors, carrier, topology, stages, obligations
    )


_BASE_OBLIGATIONS = (
    LifecycleObligation.SECRET_NON_PERSISTENCE,
    LifecycleObligation.SESSION_ISOLATION,
    LifecycleObligation.LOGOUT_REQUIRED,
    LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
)
AUTHENTICATION_MODE_PROFILES = MappingProxyType(
    {
        (AuthenticationMode.BASIC_REFERENCE, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.BASIC_REFERENCE,
            AuthenticationProtocol.HTTP_BASIC,
            (AuthenticationFactor.PASSWORD_REFERENCE,),
            SessionCarrier.AUTHORIZATION_HEADER_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.BASIC_REFERENCE, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.BASIC_REFERENCE,
            AuthenticationProtocol.HTTP_BASIC,
            (AuthenticationFactor.PASSWORD_REFERENCE,),
            SessionCarrier.AUTHORIZATION_HEADER_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.BEARER_REFERENCE, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.BEARER_REFERENCE,
            AuthenticationProtocol.HTTP_BEARER,
            (AuthenticationFactor.BEARER_REFERENCE,),
            SessionCarrier.AUTHORIZATION_HEADER_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.BEARER_REFERENCE, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.BEARER_REFERENCE,
            AuthenticationProtocol.HTTP_BEARER,
            (AuthenticationFactor.BEARER_REFERENCE,),
            SessionCarrier.AUTHORIZATION_HEADER_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.FORM_LOGIN_PASSWORD, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_PASSWORD,
            AuthenticationProtocol.HTML_FORM,
            (AuthenticationFactor.PASSWORD_REFERENCE,),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.FORM_LOGIN_PASSWORD, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_PASSWORD,
            AuthenticationProtocol.HTML_FORM,
            (AuthenticationFactor.PASSWORD_REFERENCE,),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (FlowStage.CREDENTIAL_REFERENCE_BOUND, FlowStage.SESSION_OBSERVED),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.FORM_LOGIN_TOTP, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_TOTP,
            AuthenticationProtocol.HTML_FORM,
            (AuthenticationFactor.PASSWORD_REFERENCE, AuthenticationFactor.TOTP_REFERENCE),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CHALLENGE_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS + (LifecycleObligation.MFA_OPERATOR_BOUND,),
        ),
        (AuthenticationMode.FORM_LOGIN_TOTP, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_TOTP,
            AuthenticationProtocol.HTML_FORM,
            (AuthenticationFactor.PASSWORD_REFERENCE, AuthenticationFactor.TOTP_REFERENCE),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CHALLENGE_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS + (LifecycleObligation.MFA_OPERATOR_BOUND,),
        ),
        (AuthenticationMode.FORM_LOGIN_EMAIL_OTP, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_EMAIL_OTP,
            AuthenticationProtocol.HTML_FORM,
            (
                AuthenticationFactor.PASSWORD_REFERENCE,
                AuthenticationFactor.EMAIL_OTP_REFERENCE,
            ),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CHALLENGE_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS + (LifecycleObligation.MFA_OPERATOR_BOUND,),
        ),
        (AuthenticationMode.FORM_LOGIN_EMAIL_OTP, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.FORM_LOGIN_EMAIL_OTP,
            AuthenticationProtocol.HTML_FORM,
            (
                AuthenticationFactor.PASSWORD_REFERENCE,
                AuthenticationFactor.EMAIL_OTP_REFERENCE,
            ),
            SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CHALLENGE_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS + (LifecycleObligation.MFA_OPERATOR_BOUND,),
        ),
        (AuthenticationMode.MAGIC_LINK_REFERENCE, PrincipalTopology.SINGLE_PRINCIPAL): _profile(
            AuthenticationMode.MAGIC_LINK_REFERENCE,
            AuthenticationProtocol.MAGIC_LINK,
            (AuthenticationFactor.MAGIC_LINK_REFERENCE,),
            SessionCarrier.MAGIC_LINK_CALLBACK_REFERENCE,
            PrincipalTopology.SINGLE_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.MAGIC_LINK_REFERENCE, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.MAGIC_LINK_REFERENCE,
            AuthenticationProtocol.MAGIC_LINK,
            (AuthenticationFactor.MAGIC_LINK_REFERENCE,),
            SessionCarrier.MAGIC_LINK_CALLBACK_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.OAUTH2_PKCE, PrincipalTopology.FEDERATED_PRINCIPAL): _profile(
            AuthenticationMode.OAUTH2_PKCE,
            AuthenticationProtocol.OAUTH2,
            (
                AuthenticationFactor.FEDERATED_IDENTITY_SESSION_REFERENCE,
                AuthenticationFactor.PKCE_VERIFIER_REFERENCE,
            ),
            SessionCarrier.BROWSER_REDIRECT_CALLBACK_REFERENCE,
            PrincipalTopology.FEDERATED_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.REDIRECT_OBSERVED,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.OAUTH2_PKCE, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.OAUTH2_PKCE,
            AuthenticationProtocol.OAUTH2,
            (
                AuthenticationFactor.FEDERATED_IDENTITY_SESSION_REFERENCE,
                AuthenticationFactor.PKCE_VERIFIER_REFERENCE,
            ),
            SessionCarrier.BROWSER_REDIRECT_CALLBACK_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.REDIRECT_OBSERVED,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.OIDC_PKCE, PrincipalTopology.FEDERATED_PRINCIPAL): _profile(
            AuthenticationMode.OIDC_PKCE,
            AuthenticationProtocol.OIDC,
            (
                AuthenticationFactor.FEDERATED_IDENTITY_SESSION_REFERENCE,
                AuthenticationFactor.PKCE_VERIFIER_REFERENCE,
            ),
            SessionCarrier.BROWSER_REDIRECT_CALLBACK_REFERENCE,
            PrincipalTopology.FEDERATED_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.REDIRECT_OBSERVED,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
        (AuthenticationMode.OIDC_PKCE, PrincipalTopology.MULTI_PRINCIPAL): _profile(
            AuthenticationMode.OIDC_PKCE,
            AuthenticationProtocol.OIDC,
            (
                AuthenticationFactor.FEDERATED_IDENTITY_SESSION_REFERENCE,
                AuthenticationFactor.PKCE_VERIFIER_REFERENCE,
            ),
            SessionCarrier.BROWSER_REDIRECT_CALLBACK_REFERENCE,
            PrincipalTopology.MULTI_PRINCIPAL,
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.REDIRECT_OBSERVED,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
            _BASE_OBLIGATIONS,
        ),
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after fail-closed validation."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_RE.search(encoded):
        raise TargetAuthenticationContractError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def transport_credential_reference_sha256(credential_ref: str) -> str:
    """Hash an exact ``credref:`` value without normalizing or serializing it."""

    exact = _credential_reference(credential_ref, "credential_ref", source=False)
    return "sha256:" + hashlib.sha256(exact.encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise TargetAuthenticationContractError(f"{label} exceeds the nesting limit")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        _ascii(value, label)
        return
    if type(value) in {list, tuple}:
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is not str:
                raise TargetAuthenticationContractError(f"{label} has a non-string key")
            _ascii(key, f"{label} key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise TargetAuthenticationContractError(f"{label} has an unsupported value")


def _ascii(value: Any, label: str, *, minimum: int = 1, maximum: int = 512) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise TargetAuthenticationContractError(f"{label} must be bounded ASCII text")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise TargetAuthenticationContractError(f"{label} must contain printable ASCII only")
    if SECRET_RE.search(value):
        raise TargetAuthenticationContractError(f"{label} contains secret material")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    if not isinstance(value, (str, enum_type)):
        raise TargetAuthenticationContractError(f"{label} is invalid")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise TargetAuthenticationContractError(f"{label} is invalid") from exc


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise TargetAuthenticationContractError(f"{label} must be a SHA-256 digest")
    return value


def _reference(value: Any, label: str, namespace: str) -> str:
    if type(value) is not str or REFERENCE_RE.fullmatch(value) is None:
        raise TargetAuthenticationContractError(f"{label} must be an opaque reference")
    if not value.startswith(namespace + ":"):
        raise TargetAuthenticationContractError(f"{label} must use the {namespace} namespace")
    return _ascii(value, label, maximum=200)


def _credential_reference(value: Any, label: str, *, source: bool) -> str:
    pattern = CREDENTIAL_SOURCE_RE if source else CREDENTIAL_TRANSPORT_RE
    namespace = "credentialref" if source else "credref"
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise TargetAuthenticationContractError(f"{label} must use the {namespace} namespace")
    return _ascii(value, label, maximum=256)


def _identifier(value: Any, label: str, *, version: bool = False) -> str:
    pattern = VERSION_RE if version else IDENTIFIER_RE
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise TargetAuthenticationContractError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise TargetAuthenticationContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TargetAuthenticationContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _instant(_timestamp(issued_at, f"{label} issued_at"))
    expires = _instant(_timestamp(expires_at, f"{label} expires_at"))
    seconds = (expires - issued).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS:
        raise TargetAuthenticationContractError(f"{label} window is invalid")


def _positive_int(value: Any, label: str, ceiling: int) -> int:
    if type(value) is not int or not 1 <= value <= ceiling:
        raise TargetAuthenticationContractError(f"{label} is invalid")
    return value


def _unique_enum_tuple(
    values: Sequence[Any], enum_type: type[StrEnum], label: str, *, minimum: int = 1
) -> tuple[Any, ...]:
    if type(values) not in {list, tuple}:
        raise TargetAuthenticationContractError(f"{label} must be a sequence")
    normalized = tuple(_enum(enum_type, item, f"{label} item") for item in values)
    if len(normalized) < minimum or len(normalized) != len(set(normalized)):
        raise TargetAuthenticationContractError(f"{label} count or uniqueness is invalid")
    return tuple(sorted(normalized, key=str))


def _ordered_enum_tuple(
    values: Sequence[Any], enum_type: type[StrEnum], label: str, *, minimum: int = 1
) -> tuple[Any, ...]:
    if type(values) not in {list, tuple}:
        raise TargetAuthenticationContractError(f"{label} must be a sequence")
    normalized = tuple(_enum(enum_type, item, f"{label} item") for item in values)
    if len(normalized) < minimum or len(normalized) != len(set(normalized)):
        raise TargetAuthenticationContractError(f"{label} count or uniqueness is invalid")
    return normalized


def _array(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        raise TargetAuthenticationContractError(f"{label} must be an array")
    return value


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _metadata(body: Mapping[str, Any], record_kind: str) -> None:
    if (
        body.get("record_kind") != record_kind
        or type(body.get("schema_version")) is not int
        or body.get("schema_version") != SCHEMA_VERSION
    ):
        raise TargetAuthenticationContractError("record metadata is invalid")
    if body.get("effects") != dict(NO_EFFECTS) or body.get("claims") != dict(NO_CLAIMS):
        raise TargetAuthenticationContractError("record attempts a claim or effect escalation")


def _record_body(record_kind: str, content: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(content),
        "claims": dict(NO_CLAIMS),
        "effects": dict(NO_EFFECTS),
        "record_kind": record_kind,
        "schema_version": SCHEMA_VERSION,
    }


@dataclass(frozen=True, slots=True)
class ContentAddressBinding:
    record_id: str
    record_sha256: str

    def __post_init__(self) -> None:
        if type(self.record_id) is not str or RECORD_ID_RE.fullmatch(self.record_id) is None:
            raise TargetAuthenticationContractError("record_id is invalid")
        _digest(self.record_sha256, "record_sha256")

    def to_dict(self) -> dict[str, str]:
        return {"record_id": self.record_id, "record_sha256": self.record_sha256}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ContentAddressBinding:
        values = _exact(raw, {"record_id", "record_sha256"}, "content address binding")
        return cls(**values)


def _require_binding_prefix(
    value: ContentAddressBinding, label: str, prefix: str
) -> ContentAddressBinding:
    if not isinstance(value, ContentAddressBinding) or not value.record_id.startswith(prefix + "-"):
        raise TargetAuthenticationContractError(f"{label} has the wrong record type")
    return value


@dataclass(frozen=True, slots=True)
class AuthenticationProfileEvidence:
    mode: AuthenticationMode
    protocol: AuthenticationProtocol
    factors: tuple[AuthenticationFactor, ...]
    carrier: SessionCarrier
    topology: PrincipalTopology
    successful_flow_stages: tuple[FlowStage, ...]
    lifecycle_obligations: tuple[LifecycleObligation, ...]
    profile_id: str = field(init=False)
    profile_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _enum(AuthenticationMode, self.mode, "profile mode"))
        object.__setattr__(
            self, "protocol", _enum(AuthenticationProtocol, self.protocol, "profile protocol")
        )
        object.__setattr__(
            self,
            "factors",
            _unique_enum_tuple(self.factors, AuthenticationFactor, "profile factors"),
        )
        object.__setattr__(self, "carrier", _enum(SessionCarrier, self.carrier, "profile carrier"))
        object.__setattr__(
            self, "topology", _enum(PrincipalTopology, self.topology, "profile topology")
        )
        object.__setattr__(
            self,
            "successful_flow_stages",
            _ordered_enum_tuple(
                self.successful_flow_stages, FlowStage, "profile successful_flow_stages"
            ),
        )
        object.__setattr__(
            self,
            "lifecycle_obligations",
            _unique_enum_tuple(
                self.lifecycle_obligations,
                LifecycleObligation,
                "profile lifecycle_obligations",
            ),
        )
        expected = AUTHENTICATION_MODE_PROFILES.get((self.mode, self.topology))
        if expected is None or self.content() != expected.to_dict():
            raise TargetAuthenticationContractError(
                "profile evidence does not match the immutable profile matrix"
            )
        identity, digest = _identity(
            "TAPE", "target_authentication_profile_evidence", self.content()
        )
        object.__setattr__(self, "profile_id", identity)
        object.__setattr__(self, "profile_sha256", digest)

    def content(self) -> dict[str, Any]:
        return {
            "carrier": self.carrier.value,
            "factors": [item.value for item in self.factors],
            "lifecycle_obligations": [item.value for item in self.lifecycle_obligations],
            "mode": self.mode.value,
            "protocol": self.protocol.value,
            "successful_flow_stages": [item.value for item in self.successful_flow_stages],
            "topology": self.topology.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.content(),
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
        }

    @classmethod
    def for_mode(
        cls, mode: AuthenticationMode, topology: PrincipalTopology
    ) -> AuthenticationProfileEvidence:
        try:
            profile = AUTHENTICATION_MODE_PROFILES[(mode, topology)]
        except KeyError as exc:
            raise TargetAuthenticationContractError(
                "mode and topology profile is unsupported"
            ) from exc
        return cls(**profile.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AuthenticationProfileEvidence:
        values = _exact(
            raw,
            {
                "carrier",
                "factors",
                "lifecycle_obligations",
                "mode",
                "profile_id",
                "profile_sha256",
                "protocol",
                "successful_flow_stages",
                "topology",
            },
            "authentication profile evidence",
        )
        record = cls(
            mode=values["mode"],
            protocol=values["protocol"],
            factors=tuple(_array(values["factors"], "profile factors")),
            carrier=values["carrier"],
            topology=values["topology"],
            successful_flow_stages=tuple(
                _array(values["successful_flow_stages"], "profile successful_flow_stages")
            ),
            lifecycle_obligations=tuple(
                _array(values["lifecycle_obligations"], "profile lifecycle_obligations")
            ),
        )
        return _verify_identity(raw, record, "profile_id", "profile_sha256")


@dataclass(frozen=True, slots=True)
class V1TargetSessionEvidenceBinding:
    execution_policy_id: str
    execution_policy_sha256: str
    intent_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    runtime_policy_id: str
    runtime_policy_sha256: str
    runtime_receipt_id: str
    runtime_receipt_sha256: str

    def __post_init__(self) -> None:
        for name, pattern in UPSTREAM_RECORD_ID_PATTERNS.items():
            value = getattr(self, name)
            if type(value) is not str or pattern.fullmatch(value) is None:
                raise TargetAuthenticationContractError(f"{name} has the wrong record type")
        for name in (
            "execution_policy_sha256",
            "intent_sha256",
            "execution_request_sha256",
            "admission_receipt_sha256",
            "runtime_policy_sha256",
            "runtime_receipt_sha256",
        ):
            _digest(getattr(self, name), name)

    def to_dict(self) -> dict[str, str]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "intent_sha256": self.intent_sha256,
            "runtime_policy_id": self.runtime_policy_id,
            "runtime_policy_sha256": self.runtime_policy_sha256,
            "runtime_receipt_id": self.runtime_receipt_id,
            "runtime_receipt_sha256": self.runtime_receipt_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> V1TargetSessionEvidenceBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "v1 target session evidence"))


@dataclass(frozen=True, slots=True)
class TargetAuthenticationProviderBinding:
    record_kind: ClassVar[str] = "target_authentication_provider_binding"

    provider_ref: str
    instance_ref: str
    implementation_name: str
    implementation_version: str
    execution_environment: ExecutionEnvironment
    artifact_sha256: str
    configuration_sha256: str
    environment_attestation_sha256: str
    supported_profiles: tuple[AuthenticationProfileEvidence, ...]
    supported_operations: tuple[AuthenticationOperation, ...]
    issued_at: str
    expires_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider_ref", _reference(self.provider_ref, "provider_ref", "providerref")
        )
        object.__setattr__(
            self, "instance_ref", _reference(self.instance_ref, "instance_ref", "instanceref")
        )
        object.__setattr__(
            self,
            "implementation_name",
            _identifier(self.implementation_name, "implementation_name"),
        )
        object.__setattr__(
            self,
            "implementation_version",
            _identifier(self.implementation_version, "implementation_version", version=True),
        )
        object.__setattr__(
            self,
            "execution_environment",
            _enum(ExecutionEnvironment, self.execution_environment, "execution_environment"),
        )
        _digest(self.artifact_sha256, "artifact_sha256")
        _digest(self.configuration_sha256, "configuration_sha256")
        _digest(self.environment_attestation_sha256, "environment_attestation_sha256")
        if type(self.supported_profiles) not in {list, tuple}:
            raise TargetAuthenticationContractError("supported_profiles must be a sequence")
        profiles = tuple(self.supported_profiles)
        if not profiles or not all(
            isinstance(item, AuthenticationProfileEvidence) for item in profiles
        ):
            raise TargetAuthenticationContractError("supported_profiles are invalid")
        if len({item.profile_id for item in profiles}) != len(profiles):
            raise TargetAuthenticationContractError("supported_profiles contain duplicates")
        if len(profiles) > len(AUTHENTICATION_MODE_PROFILES):
            raise TargetAuthenticationContractError("supported_profiles exceed the closed matrix")
        object.__setattr__(
            self, "supported_profiles", tuple(sorted(profiles, key=lambda item: item.profile_id))
        )
        object.__setattr__(
            self,
            "supported_operations",
            _unique_enum_tuple(
                self.supported_operations, AuthenticationOperation, "supported_operations"
            ),
        )
        _window(self.issued_at, self.expires_at, "provider binding")
        identity, digest = _identity("TAPB", self.record_kind, self.body())
        object.__setattr__(self, "binding_id", identity)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "artifact_sha256": self.artifact_sha256,
                "configuration_sha256": self.configuration_sha256,
                "environment_attestation_sha256": self.environment_attestation_sha256,
                "execution_environment": self.execution_environment.value,
                "expires_at": self.expires_at,
                "implementation_name": self.implementation_name,
                "implementation_version": self.implementation_version,
                "instance_ref": self.instance_ref,
                "issued_at": self.issued_at,
                "provider_ref": self.provider_ref,
                "supported_profiles": [item.to_dict() for item in self.supported_profiles],
                "supported_operations": [item.value for item in self.supported_operations],
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "binding_id": self.binding_id, "binding_sha256": self.binding_sha256}

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.binding_id, self.binding_sha256)


@dataclass(frozen=True, slots=True)
class TargetCredentialProvenance:
    record_kind: ClassVar[str] = "target_credential_provenance"
    reference_relation: ClassVar[str] = "source_reference_to_transport_reference_digest"

    provider_binding: ContentAddressBinding
    principal_ref: str
    factor: AuthenticationFactor
    descriptor_id: str
    descriptor_sha256: str
    lease_id: str
    lease_sha256: str
    lease_mode: CredentialLeaseMode
    lease_issued_at: str
    lease_expires_at: str
    lease_use_number: int
    source_credential_ref: str
    transport_credential_ref_sha256: str
    mapping_attestation_sha256: str
    created_at: str
    provenance_id: str = field(init=False)
    provenance_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_binding_prefix(self.provider_binding, "provider_binding", "TAPB")
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(
            self, "factor", _enum(AuthenticationFactor, self.factor, "authentication factor")
        )
        if (
            type(self.descriptor_id) is not str
            or CREDENTIAL_DESCRIPTOR_ID_RE.fullmatch(self.descriptor_id) is None
        ):
            raise TargetAuthenticationContractError("descriptor_id must identify a CBD record")
        _digest(self.descriptor_sha256, "descriptor_sha256")
        if (
            type(self.lease_id) is not str
            or CREDENTIAL_LEASE_ID_RE.fullmatch(self.lease_id) is None
        ):
            raise TargetAuthenticationContractError("lease_id must identify a CLZ record")
        _digest(self.lease_sha256, "lease_sha256")
        object.__setattr__(
            self, "lease_mode", _enum(CredentialLeaseMode, self.lease_mode, "lease_mode")
        )
        _window(self.lease_issued_at, self.lease_expires_at, "credential lease")
        _positive_int(self.lease_use_number, "lease_use_number", 100)
        if self.lease_mode is CredentialLeaseMode.ONE_TIME and self.lease_use_number != 1:
            raise TargetAuthenticationContractError("one-time lease must use number one")
        object.__setattr__(
            self,
            "source_credential_ref",
            _credential_reference(self.source_credential_ref, "source_credential_ref", source=True),
        )
        _digest(self.transport_credential_ref_sha256, "transport_credential_ref_sha256")
        _digest(self.mapping_attestation_sha256, "mapping_attestation_sha256")
        _timestamp(self.created_at, "created_at")
        if not (
            _instant(self.lease_issued_at)
            <= _instant(self.created_at)
            < _instant(self.lease_expires_at)
        ):
            raise TargetAuthenticationContractError(
                "credential provenance must be created inside the lease window"
            )
        identity, digest = _identity("TACP", self.record_kind, self.body())
        object.__setattr__(self, "provenance_id", identity)
        object.__setattr__(self, "provenance_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "created_at": self.created_at,
                "descriptor_id": self.descriptor_id,
                "descriptor_sha256": self.descriptor_sha256,
                "factor": self.factor.value,
                "lease_expires_at": self.lease_expires_at,
                "lease_id": self.lease_id,
                "lease_issued_at": self.lease_issued_at,
                "lease_mode": self.lease_mode.value,
                "lease_sha256": self.lease_sha256,
                "lease_use_number": self.lease_use_number,
                "mapping_attestation_sha256": self.mapping_attestation_sha256,
                "principal_ref": self.principal_ref,
                "provider_binding": self.provider_binding.to_dict(),
                "reference_relation": self.reference_relation,
                "source_credential_ref": self.source_credential_ref,
                "transport_credential_ref_sha256": self.transport_credential_ref_sha256,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "provenance_id": self.provenance_id,
            "provenance_sha256": self.provenance_sha256,
        }

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.provenance_id, self.provenance_sha256)


@dataclass(frozen=True, slots=True)
class TargetAuthenticationPolicy:
    record_kind: ClassVar[str] = "target_authentication_policy"

    tenant_ref: str
    mission_ref: str
    scope_ref: str
    target_ref: str
    provider_binding: ContentAddressBinding
    mode: AuthenticationMode
    profile_evidence: AuthenticationProfileEvidence
    v1_evidence: V1TargetSessionEvidenceBinding
    credential_provenance: tuple[ContentAddressBinding, ...]
    lifecycle_obligations: tuple[LifecycleObligation, ...]
    maximum_attempts: int
    issued_at: str
    expires_at: str
    policy_id: str = field(init=False)
    policy_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _require_binding_prefix(self.provider_binding, "provider_binding", "TAPB")
        object.__setattr__(self, "mode", _enum(AuthenticationMode, self.mode, "mode"))
        if not isinstance(self.profile_evidence, AuthenticationProfileEvidence):
            raise TargetAuthenticationContractError("profile_evidence is invalid")
        if self.profile_evidence.mode is not self.mode:
            raise TargetAuthenticationContractError("policy mode and profile evidence mismatch")
        if not isinstance(self.v1_evidence, V1TargetSessionEvidenceBinding):
            raise TargetAuthenticationContractError("v1_evidence is invalid")
        credentials = _content_bindings(self.credential_provenance, "credential_provenance")
        if any(not item.record_id.startswith("TACP-") for item in credentials):
            raise TargetAuthenticationContractError(
                "credential_provenance contains a non-provenance binding"
            )
        factor_count = len(self.profile_evidence.factors)
        if self.profile_evidence.topology is PrincipalTopology.MULTI_PRINCIPAL:
            valid_count = (
                len(credentials) >= 2 * factor_count and len(credentials) % factor_count == 0
            )
        else:
            valid_count = len(credentials) == factor_count
        if not valid_count:
            raise TargetAuthenticationContractError(
                "credential provenance count is invalid for mode"
            )
        object.__setattr__(self, "credential_provenance", credentials)
        obligations = _unique_enum_tuple(
            self.lifecycle_obligations, LifecycleObligation, "lifecycle_obligations"
        )
        if obligations != self.profile_evidence.lifecycle_obligations:
            raise TargetAuthenticationContractError(
                "lifecycle obligations do not match mode profile"
            )
        object.__setattr__(self, "lifecycle_obligations", obligations)
        _positive_int(self.maximum_attempts, "maximum_attempts", 1)
        _window(self.issued_at, self.expires_at, "policy")
        identity, digest = _identity("TAAP", self.record_kind, self.body())
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "credential_provenance": [item.to_dict() for item in self.credential_provenance],
                "expires_at": self.expires_at,
                "issued_at": self.issued_at,
                "lifecycle_obligations": [item.value for item in self.lifecycle_obligations],
                "maximum_attempts": self.maximum_attempts,
                "mission_ref": self.mission_ref,
                "mode": self.mode.value,
                "profile_evidence": self.profile_evidence.to_dict(),
                "provider_binding": self.provider_binding.to_dict(),
                "scope_ref": self.scope_ref,
                "target_ref": self.target_ref,
                "tenant_ref": self.tenant_ref,
                "v1_evidence": self.v1_evidence.to_dict(),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "policy_id": self.policy_id, "policy_sha256": self.policy_sha256}

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.policy_id, self.policy_sha256)


@dataclass(frozen=True, slots=True)
class TargetAuthenticationCommand:
    record_kind: ClassVar[str] = "target_authentication_command"

    policy_binding: ContentAddressBinding
    provider_binding: ContentAddressBinding
    execution_environment: ExecutionEnvironment
    operation: AuthenticationOperation
    mode: AuthenticationMode
    profile_evidence: AuthenticationProfileEvidence
    v1_evidence: V1TargetSessionEvidenceBinding
    credential_provenance: tuple[ContentAddressBinding, ...]
    lifecycle_obligations: tuple[LifecycleObligation, ...]
    requested_session_ref: str | None
    predecessor_session_ref: str | None
    fixture_scenario_ref: str | None
    issued_at: str
    expires_at: str
    command_id: str = field(init=False)
    command_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_binding_prefix(self.policy_binding, "policy_binding", "TAAP")
        _require_binding_prefix(self.provider_binding, "provider_binding", "TAPB")
        object.__setattr__(
            self,
            "execution_environment",
            _enum(ExecutionEnvironment, self.execution_environment, "execution_environment"),
        )
        object.__setattr__(
            self, "operation", _enum(AuthenticationOperation, self.operation, "operation")
        )
        object.__setattr__(self, "mode", _enum(AuthenticationMode, self.mode, "mode"))
        if not isinstance(self.profile_evidence, AuthenticationProfileEvidence):
            raise TargetAuthenticationContractError("profile_evidence is invalid")
        if self.profile_evidence.mode is not self.mode:
            raise TargetAuthenticationContractError("command mode and profile evidence mismatch")
        if not isinstance(self.v1_evidence, V1TargetSessionEvidenceBinding):
            raise TargetAuthenticationContractError("v1_evidence is invalid")
        object.__setattr__(
            self,
            "credential_provenance",
            _content_bindings(self.credential_provenance, "credential_provenance"),
        )
        if any(not item.record_id.startswith("TACP-") for item in self.credential_provenance):
            raise TargetAuthenticationContractError(
                "credential_provenance contains a non-provenance binding"
            )
        factor_count = len(self.profile_evidence.factors)
        if self.profile_evidence.topology is PrincipalTopology.MULTI_PRINCIPAL:
            valid_count = (
                len(self.credential_provenance) >= 2 * factor_count
                and len(self.credential_provenance) % factor_count == 0
            )
        else:
            valid_count = len(self.credential_provenance) == factor_count
        if not valid_count:
            raise TargetAuthenticationContractError(
                "command credential provenance count is invalid for profile"
            )
        object.__setattr__(
            self,
            "lifecycle_obligations",
            _unique_enum_tuple(
                self.lifecycle_obligations, LifecycleObligation, "lifecycle_obligations"
            ),
        )
        for name in ("requested_session_ref", "predecessor_session_ref"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _reference(value, name, "sessionref"))
        if self.fixture_scenario_ref is not None:
            object.__setattr__(
                self,
                "fixture_scenario_ref",
                _reference(self.fixture_scenario_ref, "fixture_scenario_ref", "fixtureref"),
            )
        if (self.execution_environment is ExecutionEnvironment.DETERMINISTIC_FIXTURE) != (
            self.fixture_scenario_ref is not None
        ):
            raise TargetAuthenticationContractError(
                "fixture execution requires exactly one fixture scenario reference"
            )
        if self.operation is AuthenticationOperation.ACQUIRE_SESSION:
            if self.requested_session_ref is None or self.predecessor_session_ref is not None:
                raise TargetAuthenticationContractError(
                    "acquire command session references are invalid"
                )
        elif self.operation is AuthenticationOperation.REFRESH_SESSION:
            if (
                self.requested_session_ref is None
                or self.predecessor_session_ref is None
                or self.requested_session_ref == self.predecessor_session_ref
            ):
                raise TargetAuthenticationContractError(
                    "refresh command session references are invalid"
                )
            if LifecycleObligation.REFRESH_PREDECESSOR_BOUND not in self.lifecycle_obligations:
                raise TargetAuthenticationContractError(
                    "refresh command lacks predecessor obligation"
                )
        elif self.requested_session_ref is not None or self.predecessor_session_ref is None:
            raise TargetAuthenticationContractError(
                "terminate command session references are invalid"
            )
        expected_obligations = set(self.profile_evidence.lifecycle_obligations)
        if self.operation is AuthenticationOperation.REFRESH_SESSION:
            expected_obligations.add(LifecycleObligation.REFRESH_PREDECESSOR_BOUND)
        if set(self.lifecycle_obligations) != expected_obligations:
            raise TargetAuthenticationContractError(
                "command lifecycle obligations do not match mode and operation"
            )
        _window(self.issued_at, self.expires_at, "command")
        identity, digest = _identity("TAAC", self.record_kind, self.body())
        object.__setattr__(self, "command_id", identity)
        object.__setattr__(self, "command_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "credential_provenance": [item.to_dict() for item in self.credential_provenance],
                "execution_environment": self.execution_environment.value,
                "expires_at": self.expires_at,
                "fixture_scenario_ref": self.fixture_scenario_ref,
                "issued_at": self.issued_at,
                "lifecycle_obligations": [item.value for item in self.lifecycle_obligations],
                "mode": self.mode.value,
                "operation": self.operation.value,
                "policy_binding": self.policy_binding.to_dict(),
                "predecessor_session_ref": self.predecessor_session_ref,
                "profile_evidence": self.profile_evidence.to_dict(),
                "provider_binding": self.provider_binding.to_dict(),
                "requested_session_ref": self.requested_session_ref,
                "v1_evidence": self.v1_evidence.to_dict(),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "command_id": self.command_id, "command_sha256": self.command_sha256}

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.command_id, self.command_sha256)


@dataclass(frozen=True, slots=True)
class TargetAuthenticationFlowEvidence:
    record_kind: ClassVar[str] = "target_authentication_flow_evidence"

    command_binding: ContentAddressBinding
    provider_binding: ContentAddressBinding
    execution_environment: ExecutionEnvironment
    stage: FlowStage
    sequence: int
    input_evidence_sha256: str
    output_evidence_sha256: str | None
    provider_attestation_sha256: str | None
    environment_attestation_sha256: str | None
    failure_code: AuthenticationFailureCode | None
    observed_at: str
    evidence_id: str = field(init=False)
    evidence_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_binding_prefix(self.command_binding, "command_binding", "TAAC")
        _require_binding_prefix(self.provider_binding, "provider_binding", "TAPB")
        object.__setattr__(
            self,
            "execution_environment",
            _enum(ExecutionEnvironment, self.execution_environment, "execution_environment"),
        )
        object.__setattr__(self, "stage", _enum(FlowStage, self.stage, "stage"))
        _positive_int(self.sequence, "sequence", MAX_FLOW_EVIDENCE)
        _digest(self.input_evidence_sha256, "input_evidence_sha256")
        if self.output_evidence_sha256 is not None:
            _digest(self.output_evidence_sha256, "output_evidence_sha256")
        for name in ("provider_attestation_sha256", "environment_attestation_sha256"):
            value = getattr(self, name)
            if value is not None:
                _digest(value, name)
        external = self.execution_environment is ExecutionEnvironment.EXTERNAL_RUNTIME_OBSERVATION
        if external and (
            self.provider_attestation_sha256 is None or self.environment_attestation_sha256 is None
        ):
            raise TargetAuthenticationContractError(
                "external flow evidence requires provider and environment attestations"
            )
        if external and self.provider_attestation_sha256 == self.environment_attestation_sha256:
            raise TargetAuthenticationContractError(
                "provider and environment flow attestations must be distinct"
            )
        if not external and (
            self.provider_attestation_sha256 is not None
            or self.environment_attestation_sha256 is not None
        ):
            raise TargetAuthenticationContractError(
                "fixture flow evidence cannot claim runtime attestations"
            )
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                _enum(AuthenticationFailureCode, self.failure_code, "failure_code"),
            )
        if (self.stage is FlowStage.FAILURE_OBSERVED) != (self.failure_code is not None):
            raise TargetAuthenticationContractError(
                "failure evidence requires one closed failure code"
            )
        _timestamp(self.observed_at, "observed_at")
        identity, digest = _identity("TAFE", self.record_kind, self.body())
        object.__setattr__(self, "evidence_id", identity)
        object.__setattr__(self, "evidence_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "command_binding": self.command_binding.to_dict(),
                "execution_environment": self.execution_environment.value,
                "failure_code": self.failure_code.value if self.failure_code else None,
                "environment_attestation_sha256": self.environment_attestation_sha256,
                "input_evidence_sha256": self.input_evidence_sha256,
                "observed_at": self.observed_at,
                "output_evidence_sha256": self.output_evidence_sha256,
                "provider_binding": self.provider_binding.to_dict(),
                "provider_attestation_sha256": self.provider_attestation_sha256,
                "sequence": self.sequence,
                "stage": self.stage.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
        }

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.evidence_id, self.evidence_sha256)


@dataclass(frozen=True, slots=True)
class TargetAuthenticationResult:
    record_kind: ClassVar[str] = "target_authentication_result"

    command_binding: ContentAddressBinding
    provider_binding: ContentAddressBinding
    execution_environment: ExecutionEnvironment
    outcome: AuthenticationOutcome
    failure_code: AuthenticationFailureCode | None
    flow_evidence: tuple[ContentAddressBinding, ...]
    resulting_session_ref: str | None
    session_evidence_sha256: str | None
    provider_attestation_sha256: str | None
    environment_attestation_sha256: str | None
    satisfied_lifecycle_obligations: tuple[LifecycleObligation, ...]
    pending_lifecycle_obligations: tuple[LifecycleObligation, ...]
    completed_at: str
    result_id: str = field(init=False)
    result_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_binding_prefix(self.command_binding, "command_binding", "TAAC")
        _require_binding_prefix(self.provider_binding, "provider_binding", "TAPB")
        object.__setattr__(
            self,
            "execution_environment",
            _enum(ExecutionEnvironment, self.execution_environment, "execution_environment"),
        )
        object.__setattr__(self, "outcome", _enum(AuthenticationOutcome, self.outcome, "outcome"))
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                _enum(AuthenticationFailureCode, self.failure_code, "failure_code"),
            )
        object.__setattr__(
            self, "flow_evidence", _content_bindings(self.flow_evidence, "flow_evidence")
        )
        if any(not item.record_id.startswith("TAFE-") for item in self.flow_evidence):
            raise TargetAuthenticationContractError("flow_evidence contains a non-evidence binding")
        if self.resulting_session_ref is not None:
            object.__setattr__(
                self,
                "resulting_session_ref",
                _reference(self.resulting_session_ref, "resulting_session_ref", "sessionref"),
            )
        if self.session_evidence_sha256 is not None:
            _digest(self.session_evidence_sha256, "session_evidence_sha256")
        for name in ("provider_attestation_sha256", "environment_attestation_sha256"):
            value = getattr(self, name)
            if value is not None:
                _digest(value, name)
        external = self.execution_environment is ExecutionEnvironment.EXTERNAL_RUNTIME_OBSERVATION
        if external and (
            self.provider_attestation_sha256 is None or self.environment_attestation_sha256 is None
        ):
            raise TargetAuthenticationContractError(
                "external result requires provider and environment attestations"
            )
        if external and self.provider_attestation_sha256 == self.environment_attestation_sha256:
            raise TargetAuthenticationContractError(
                "provider and environment result attestations must be distinct"
            )
        if not external and (
            self.provider_attestation_sha256 is not None
            or self.environment_attestation_sha256 is not None
        ):
            raise TargetAuthenticationContractError(
                "fixture result cannot claim runtime attestations"
            )
        satisfied = _unique_enum_tuple(
            self.satisfied_lifecycle_obligations,
            LifecycleObligation,
            "satisfied_lifecycle_obligations",
            minimum=0,
        )
        pending = _unique_enum_tuple(
            self.pending_lifecycle_obligations,
            LifecycleObligation,
            "pending_lifecycle_obligations",
            minimum=0,
        )
        if set(satisfied) & set(pending):
            raise TargetAuthenticationContractError("lifecycle obligation sets overlap")
        object.__setattr__(self, "satisfied_lifecycle_obligations", satisfied)
        object.__setattr__(self, "pending_lifecycle_obligations", pending)
        if self.outcome in {AuthenticationOutcome.FAILED, AuthenticationOutcome.STOPPED}:
            if self.failure_code is None or self.resulting_session_ref is not None:
                raise TargetAuthenticationContractError("unsuccessful result fields are invalid")
            if self.session_evidence_sha256 is not None:
                raise TargetAuthenticationContractError("unsuccessful result cannot bind a session")
        elif self.failure_code is not None:
            raise TargetAuthenticationContractError("successful result cannot have a failure code")
        elif self.outcome is AuthenticationOutcome.AUTHENTICATED:
            if self.resulting_session_ref is None or self.session_evidence_sha256 is None:
                raise TargetAuthenticationContractError(
                    "authenticated result requires session evidence"
                )
        elif self.resulting_session_ref is not None or self.session_evidence_sha256 is not None:
            raise TargetAuthenticationContractError("terminated result cannot retain a session")
        if self.outcome is AuthenticationOutcome.STOPPED and self.failure_code not in {
            AuthenticationFailureCode.OPERATOR_STOP,
            AuthenticationFailureCode.MISSION_STOP,
        }:
            raise TargetAuthenticationContractError("stopped result requires a stop failure code")
        _timestamp(self.completed_at, "completed_at")
        identity, digest = _identity("TAAR", self.record_kind, self.body())
        object.__setattr__(self, "result_id", identity)
        object.__setattr__(self, "result_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "command_binding": self.command_binding.to_dict(),
                "completed_at": self.completed_at,
                "execution_environment": self.execution_environment.value,
                "environment_attestation_sha256": self.environment_attestation_sha256,
                "failure_code": self.failure_code.value if self.failure_code else None,
                "flow_evidence": [item.to_dict() for item in self.flow_evidence],
                "outcome": self.outcome.value,
                "pending_lifecycle_obligations": [
                    item.value for item in self.pending_lifecycle_obligations
                ],
                "provider_binding": self.provider_binding.to_dict(),
                "provider_attestation_sha256": self.provider_attestation_sha256,
                "resulting_session_ref": self.resulting_session_ref,
                "satisfied_lifecycle_obligations": [
                    item.value for item in self.satisfied_lifecycle_obligations
                ],
                "session_evidence_sha256": self.session_evidence_sha256,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "result_id": self.result_id, "result_sha256": self.result_sha256}

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.result_id, self.result_sha256)


@dataclass(frozen=True, slots=True)
class TargetAuthenticationReceipt:
    record_kind: ClassVar[str] = "target_authentication_receipt"
    verification_status: ClassVar[str] = "verified_contract_chain"

    provider_binding: ContentAddressBinding
    policy_binding: ContentAddressBinding
    command_binding: ContentAddressBinding
    result_binding: ContentAddressBinding
    flow_evidence: tuple[ContentAddressBinding, ...]
    execution_environment: ExecutionEnvironment
    lifecycle_complete: bool
    issued_at: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name, prefix in (
            ("provider_binding", "TAPB"),
            ("policy_binding", "TAAP"),
            ("command_binding", "TAAC"),
            ("result_binding", "TAAR"),
        ):
            _require_binding_prefix(getattr(self, name), name, prefix)
        object.__setattr__(
            self, "flow_evidence", _content_bindings(self.flow_evidence, "flow_evidence")
        )
        if any(not item.record_id.startswith("TAFE-") for item in self.flow_evidence):
            raise TargetAuthenticationContractError("flow_evidence contains a non-evidence binding")
        object.__setattr__(
            self,
            "execution_environment",
            _enum(ExecutionEnvironment, self.execution_environment, "execution_environment"),
        )
        if type(self.lifecycle_complete) is not bool:
            raise TargetAuthenticationContractError("lifecycle_complete must be boolean")
        _timestamp(self.issued_at, "issued_at")
        identity, digest = _identity("TAAT", self.record_kind, self.body())
        object.__setattr__(self, "receipt_id", identity)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return _record_body(
            self.record_kind,
            {
                "command_binding": self.command_binding.to_dict(),
                "execution_environment": self.execution_environment.value,
                "flow_evidence": [item.to_dict() for item in self.flow_evidence],
                "issued_at": self.issued_at,
                "lifecycle_complete": self.lifecycle_complete,
                "policy_binding": self.policy_binding.to_dict(),
                "provider_binding": self.provider_binding.to_dict(),
                "result_binding": self.result_binding.to_dict(),
                "verification_status": self.verification_status,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    @property
    def content_binding(self) -> ContentAddressBinding:
        return ContentAddressBinding(self.receipt_id, self.receipt_sha256)


def _content_bindings(
    values: Sequence[ContentAddressBinding], label: str
) -> tuple[ContentAddressBinding, ...]:
    if type(values) not in {list, tuple}:
        raise TargetAuthenticationContractError(f"{label} must be a sequence")
    normalized = tuple(values)
    if len(normalized) > MAX_FLOW_EVIDENCE or not all(
        isinstance(item, ContentAddressBinding) for item in normalized
    ):
        raise TargetAuthenticationContractError(f"{label} contains invalid bindings")
    if len({item.record_id for item in normalized}) != len(normalized):
        raise TargetAuthenticationContractError(f"{label} contains duplicate bindings")
    return tuple(sorted(normalized, key=lambda item: item.record_id))


def _binding(record: Any) -> ContentAddressBinding:
    for id_name, digest_name in (
        ("binding_id", "binding_sha256"),
        ("provenance_id", "provenance_sha256"),
        ("policy_id", "policy_sha256"),
        ("command_id", "command_sha256"),
        ("evidence_id", "evidence_sha256"),
        ("result_id", "result_sha256"),
        ("receipt_id", "receipt_sha256"),
    ):
        if hasattr(record, id_name):
            return ContentAddressBinding(getattr(record, id_name), getattr(record, digest_name))
    raise TargetAuthenticationContractError("record has no content address")


def verify_target_authentication_chain(
    provider: TargetAuthenticationProviderBinding,
    provenance: Sequence[TargetCredentialProvenance],
    policy: TargetAuthenticationPolicy,
    command: TargetAuthenticationCommand,
    flow_evidence: Sequence[TargetAuthenticationFlowEvidence],
    result: TargetAuthenticationResult,
    receipt: TargetAuthenticationReceipt | None = None,
) -> None:
    """Verify exact binding, flow, environment, and lifecycle relationships."""

    provider_binding = _binding(provider)
    if policy.provider_binding != provider_binding or command.provider_binding != provider_binding:
        raise TargetAuthenticationContractError("provider identity binding mismatch")
    if result.provider_binding != provider_binding:
        raise TargetAuthenticationContractError("result provider identity binding mismatch")
    if command.policy_binding != _binding(policy):
        raise TargetAuthenticationContractError("command policy binding mismatch")
    if command.execution_environment is not provider.execution_environment:
        raise TargetAuthenticationContractError("command provider environment mismatch")
    if command.operation not in provider.supported_operations:
        raise TargetAuthenticationContractError("provider does not support the command operation")
    if result.execution_environment is not command.execution_environment:
        raise TargetAuthenticationContractError("result execution environment mismatch")
    if command.mode is not policy.mode or command.profile_evidence != policy.profile_evidence:
        raise TargetAuthenticationContractError("authentication mode binding mismatch")
    if command.v1_evidence != policy.v1_evidence:
        raise TargetAuthenticationContractError("v1 target session evidence binding mismatch")
    if not (
        _instant(provider.issued_at)
        <= _instant(policy.issued_at)
        <= _instant(command.issued_at)
        < _instant(command.expires_at)
        <= _instant(policy.expires_at)
        <= _instant(provider.expires_at)
    ):
        raise TargetAuthenticationContractError("provider, policy, and command times are invalid")
    if policy.profile_evidence.profile_id not in {
        item.profile_id for item in provider.supported_profiles
    }:
        raise TargetAuthenticationContractError("provider does not support the exact profile")
    expected_provenance = tuple(
        sorted((_binding(item) for item in provenance), key=lambda x: x.record_id)
    )
    if not expected_provenance or expected_provenance != policy.credential_provenance:
        raise TargetAuthenticationContractError("policy credential provenance mismatch")
    if expected_provenance != command.credential_provenance:
        raise TargetAuthenticationContractError("command credential provenance mismatch")
    if any(item.provider_binding != provider_binding for item in provenance):
        raise TargetAuthenticationContractError("credential provenance provider mismatch")
    factor_pairs = [(item.principal_ref, item.factor) for item in provenance]
    if len(factor_pairs) != len(set(factor_pairs)):
        raise TargetAuthenticationContractError(
            "credential provenance contains a duplicate principal factor"
        )
    required_factors = set(policy.profile_evidence.factors)
    factor_coverage: dict[str, set[AuthenticationFactor]] = {}
    for item in provenance:
        factor_coverage.setdefault(item.principal_ref, set()).add(item.factor)
    if any(factors != required_factors for factors in factor_coverage.values()):
        raise TargetAuthenticationContractError(
            "credential provenance factor coverage does not match the profile"
        )
    if any(
        not (
            _instant(item.lease_issued_at)
            <= _instant(command.issued_at)
            < _instant(command.expires_at)
            <= _instant(item.lease_expires_at)
        )
        for item in provenance
    ):
        raise TargetAuthenticationContractError("command exceeds a credential lease window")
    if command.operation is AuthenticationOperation.REFRESH_SESSION and any(
        item.lease_mode is not CredentialLeaseMode.SESSION_BOUND for item in provenance
    ):
        raise TargetAuthenticationContractError("refresh requires session-bound credential leases")
    principal_count = len(factor_coverage)
    topology = policy.profile_evidence.topology
    if topology is PrincipalTopology.MULTI_PRINCIPAL and principal_count < 2:
        raise TargetAuthenticationContractError("multi-principal mode lacks distinct principals")
    if topology is not PrincipalTopology.MULTI_PRINCIPAL and principal_count != 1:
        raise TargetAuthenticationContractError("single-principal mode has multiple principals")
    expected_command_obligations = set(policy.lifecycle_obligations)
    if command.operation is AuthenticationOperation.REFRESH_SESSION:
        expected_command_obligations.add(LifecycleObligation.REFRESH_PREDECESSOR_BOUND)
    if set(command.lifecycle_obligations) != expected_command_obligations:
        raise TargetAuthenticationContractError("command lifecycle obligations mismatch")
    evidence = tuple(sorted(flow_evidence, key=lambda item: item.sequence))
    if not evidence or len(evidence) > MAX_FLOW_EVIDENCE:
        raise TargetAuthenticationContractError("flow evidence count is invalid")
    if tuple(item.sequence for item in evidence) != tuple(range(1, len(evidence) + 1)):
        raise TargetAuthenticationContractError("flow evidence sequence is not contiguous")
    evidence_times = tuple(_instant(item.observed_at) for item in evidence)
    if evidence_times != tuple(sorted(evidence_times)) or not all(
        _instant(command.issued_at) <= item < _instant(command.expires_at)
        for item in evidence_times
    ):
        raise TargetAuthenticationContractError("flow evidence times are invalid")
    if any(
        item.command_binding != _binding(command)
        or item.provider_binding != provider_binding
        or item.execution_environment is not command.execution_environment
        for item in evidence
    ):
        raise TargetAuthenticationContractError("flow evidence binding mismatch")
    if command.execution_environment is ExecutionEnvironment.EXTERNAL_RUNTIME_OBSERVATION:
        if any(
            item.environment_attestation_sha256 != provider.environment_attestation_sha256
            for item in evidence
        ):
            raise TargetAuthenticationContractError("flow environment attestation mismatch")
        if result.environment_attestation_sha256 != provider.environment_attestation_sha256:
            raise TargetAuthenticationContractError("result environment attestation mismatch")
        if result.provider_attestation_sha256 != evidence[-1].provider_attestation_sha256:
            raise TargetAuthenticationContractError("terminal provider attestation mismatch")
    evidence_bindings = tuple(
        sorted((_binding(item) for item in evidence), key=lambda x: x.record_id)
    )
    if evidence_bindings != result.flow_evidence or result.command_binding != _binding(command):
        raise TargetAuthenticationContractError("result evidence or command binding mismatch")
    if not evidence_times[-1] <= _instant(result.completed_at) <= _instant(command.expires_at):
        raise TargetAuthenticationContractError("result completion time is invalid")
    ordered_stages = tuple(item.stage for item in evidence)
    stages = set(ordered_stages)
    if result.outcome is AuthenticationOutcome.AUTHENTICATED:
        required = policy.profile_evidence.successful_flow_stages
        required_index = 0
        for stage in ordered_stages:
            if required_index < len(required) and stage is required[required_index]:
                required_index += 1
        if (
            required_index != len(required)
            or ordered_stages[0] is not FlowStage.CREDENTIAL_REFERENCE_BOUND
            or ordered_stages[-1] is not FlowStage.SESSION_OBSERVED
            or FlowStage.FAILURE_OBSERVED in stages
        ):
            raise TargetAuthenticationContractError("authenticated result flow order is invalid")
        if command.operation is AuthenticationOperation.TERMINATE_SESSION:
            raise TargetAuthenticationContractError("terminate command cannot authenticate")
        if result.resulting_session_ref != command.requested_session_ref:
            raise TargetAuthenticationContractError("resulting session binding mismatch")
    elif result.outcome is AuthenticationOutcome.TERMINATED:
        if command.operation is not AuthenticationOperation.TERMINATE_SESSION:
            raise TargetAuthenticationContractError("non-terminate command cannot terminate")
        if ordered_stages[-1] is not FlowStage.TERMINATION_OBSERVED:
            raise TargetAuthenticationContractError(
                "terminated result requires terminal termination evidence"
            )
    else:
        if ordered_stages[-1] is not FlowStage.FAILURE_OBSERVED:
            raise TargetAuthenticationContractError(
                "unsuccessful result requires terminal failure evidence"
            )
        if evidence[-1].failure_code is not result.failure_code:
            raise TargetAuthenticationContractError("terminal failure code mismatch")
    all_obligations = set(command.lifecycle_obligations)
    satisfied = set(result.satisfied_lifecycle_obligations)
    pending = set(result.pending_lifecycle_obligations)
    if satisfied | pending != all_obligations:
        raise TargetAuthenticationContractError(
            "result lifecycle obligation partition is incomplete"
        )
    if result.outcome is AuthenticationOutcome.TERMINATED and pending:
        raise TargetAuthenticationContractError("terminated result retains lifecycle obligations")
    if result.outcome is AuthenticationOutcome.AUTHENTICATED:
        expected_pending = {
            LifecycleObligation.LOGOUT_REQUIRED,
            LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
        }
        expected_satisfied = all_obligations - expected_pending
        if pending != expected_pending or satisfied != expected_satisfied:
            raise TargetAuthenticationContractError(
                "authenticated result lifecycle states are invalid"
            )
    if receipt is not None and (
        receipt.provider_binding != provider_binding
        or receipt.policy_binding != _binding(policy)
        or receipt.command_binding != _binding(command)
        or receipt.result_binding != _binding(result)
        or receipt.flow_evidence != evidence_bindings
        or receipt.execution_environment is not command.execution_environment
        or receipt.lifecycle_complete is not (not pending)
        or _instant(receipt.issued_at) < _instant(result.completed_at)
        or _instant(receipt.issued_at) > _instant(provider.expires_at)
    ):
        raise TargetAuthenticationContractError("receipt chain binding mismatch")


def issue_target_authentication_receipt(
    provider: TargetAuthenticationProviderBinding,
    provenance: Sequence[TargetCredentialProvenance],
    policy: TargetAuthenticationPolicy,
    command: TargetAuthenticationCommand,
    flow_evidence: Sequence[TargetAuthenticationFlowEvidence],
    result: TargetAuthenticationResult,
    *,
    issued_at: str,
) -> TargetAuthenticationReceipt:
    """Issue a receipt only after the complete contract chain verifies."""

    verify_target_authentication_chain(provider, provenance, policy, command, flow_evidence, result)
    receipt = TargetAuthenticationReceipt(
        provider_binding=_binding(provider),
        policy_binding=_binding(policy),
        command_binding=_binding(command),
        result_binding=_binding(result),
        flow_evidence=tuple(_binding(item) for item in flow_evidence),
        execution_environment=command.execution_environment,
        lifecycle_complete=not result.pending_lifecycle_obligations,
        issued_at=issued_at,
    )
    verify_target_authentication_chain(
        provider, provenance, policy, command, flow_evidence, result, receipt
    )
    return receipt


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TargetAuthenticationContractError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _load(document: str, label: str) -> Mapping[str, Any]:
    _ascii(document, label, maximum=1_000_000)
    try:
        raw = json.loads(document, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, TypeError) as exc:
        raise TargetAuthenticationContractError(f"{label} is invalid JSON") from exc
    if not isinstance(raw, Mapping) or canonical_json(raw) != document:
        raise TargetAuthenticationContractError(f"{label} must be canonical JSON")
    return raw


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise TargetAuthenticationContractError(f"{label} fields are invalid")
    return dict(raw)


def _payload(raw: Mapping[str, Any], record_kind: str, ids: set[str]) -> dict[str, Any]:
    if not ids <= set(raw):
        raise TargetAuthenticationContractError("record identity fields are missing")
    body = dict(raw)
    for name in ids:
        body.pop(name)
    _metadata(body, record_kind)
    return body


def _verify_identity(raw: Mapping[str, Any], record: Any, id_name: str, digest_name: str) -> Any:
    if raw.get(id_name) != getattr(record, id_name) or raw.get(digest_name) != getattr(
        record, digest_name
    ):
        raise TargetAuthenticationContractError("content address does not match record")
    return record


def _binding_from(raw: Any) -> ContentAddressBinding:
    return ContentAddressBinding.from_dict(raw)


def _bindings_from(raw: Any, label: str) -> tuple[ContentAddressBinding, ...]:
    if type(raw) is not list:
        raise TargetAuthenticationContractError(f"{label} must be an array")
    return tuple(_binding_from(item) for item in raw)


def parse_target_authentication_provider_binding(
    document: str,
) -> TargetAuthenticationProviderBinding:
    raw = _load(document, "provider binding")
    fields = {
        "artifact_sha256",
        "binding_id",
        "binding_sha256",
        "claims",
        "configuration_sha256",
        "effects",
        "environment_attestation_sha256",
        "execution_environment",
        "expires_at",
        "implementation_name",
        "implementation_version",
        "instance_ref",
        "issued_at",
        "provider_ref",
        "record_kind",
        "schema_version",
        "supported_profiles",
        "supported_operations",
    }
    values = _exact(raw, fields, "provider binding")
    _payload(raw, TargetAuthenticationProviderBinding.record_kind, {"binding_id", "binding_sha256"})
    record = TargetAuthenticationProviderBinding(
        provider_ref=values["provider_ref"],
        instance_ref=values["instance_ref"],
        implementation_name=values["implementation_name"],
        implementation_version=values["implementation_version"],
        execution_environment=values["execution_environment"],
        artifact_sha256=values["artifact_sha256"],
        configuration_sha256=values["configuration_sha256"],
        environment_attestation_sha256=values["environment_attestation_sha256"],
        supported_profiles=tuple(
            AuthenticationProfileEvidence.from_dict(item)
            for item in _array(values["supported_profiles"], "supported_profiles")
        ),
        supported_operations=tuple(_array(values["supported_operations"], "supported_operations")),
        issued_at=values["issued_at"],
        expires_at=values["expires_at"],
    )
    return _verify_identity(raw, record, "binding_id", "binding_sha256")


def parse_target_credential_provenance(document: str) -> TargetCredentialProvenance:
    raw = _load(document, "credential provenance")
    fields = {
        "claims",
        "created_at",
        "descriptor_id",
        "descriptor_sha256",
        "effects",
        "factor",
        "lease_expires_at",
        "lease_id",
        "lease_issued_at",
        "lease_mode",
        "lease_sha256",
        "lease_use_number",
        "mapping_attestation_sha256",
        "principal_ref",
        "provenance_id",
        "provenance_sha256",
        "provider_binding",
        "record_kind",
        "reference_relation",
        "schema_version",
        "source_credential_ref",
        "transport_credential_ref_sha256",
    }
    values = _exact(raw, fields, "credential provenance")
    _payload(raw, TargetCredentialProvenance.record_kind, {"provenance_id", "provenance_sha256"})
    if values["reference_relation"] != TargetCredentialProvenance.reference_relation:
        raise TargetAuthenticationContractError("credential reference relation is invalid")
    record = TargetCredentialProvenance(
        provider_binding=_binding_from(values["provider_binding"]),
        principal_ref=values["principal_ref"],
        factor=values["factor"],
        descriptor_id=values["descriptor_id"],
        descriptor_sha256=values["descriptor_sha256"],
        lease_id=values["lease_id"],
        lease_sha256=values["lease_sha256"],
        lease_mode=values["lease_mode"],
        lease_issued_at=values["lease_issued_at"],
        lease_expires_at=values["lease_expires_at"],
        lease_use_number=values["lease_use_number"],
        source_credential_ref=values["source_credential_ref"],
        transport_credential_ref_sha256=values["transport_credential_ref_sha256"],
        mapping_attestation_sha256=values["mapping_attestation_sha256"],
        created_at=values["created_at"],
    )
    return _verify_identity(raw, record, "provenance_id", "provenance_sha256")


def parse_target_authentication_policy(document: str) -> TargetAuthenticationPolicy:
    raw = _load(document, "authentication policy")
    fields = {
        "claims",
        "credential_provenance",
        "effects",
        "expires_at",
        "issued_at",
        "lifecycle_obligations",
        "maximum_attempts",
        "mission_ref",
        "mode",
        "policy_id",
        "policy_sha256",
        "profile_evidence",
        "provider_binding",
        "record_kind",
        "schema_version",
        "scope_ref",
        "target_ref",
        "tenant_ref",
        "v1_evidence",
    }
    values = _exact(raw, fields, "authentication policy")
    _payload(raw, TargetAuthenticationPolicy.record_kind, {"policy_id", "policy_sha256"})
    record = TargetAuthenticationPolicy(
        tenant_ref=values["tenant_ref"],
        mission_ref=values["mission_ref"],
        scope_ref=values["scope_ref"],
        target_ref=values["target_ref"],
        provider_binding=_binding_from(values["provider_binding"]),
        mode=values["mode"],
        profile_evidence=AuthenticationProfileEvidence.from_dict(values["profile_evidence"]),
        v1_evidence=V1TargetSessionEvidenceBinding.from_dict(values["v1_evidence"]),
        credential_provenance=_bindings_from(
            values["credential_provenance"], "credential_provenance"
        ),
        lifecycle_obligations=tuple(
            _array(values["lifecycle_obligations"], "lifecycle_obligations")
        ),
        maximum_attempts=values["maximum_attempts"],
        issued_at=values["issued_at"],
        expires_at=values["expires_at"],
    )
    return _verify_identity(raw, record, "policy_id", "policy_sha256")


def parse_target_authentication_command(document: str) -> TargetAuthenticationCommand:
    raw = _load(document, "authentication command")
    fields = {
        "claims",
        "command_id",
        "command_sha256",
        "credential_provenance",
        "effects",
        "execution_environment",
        "expires_at",
        "fixture_scenario_ref",
        "issued_at",
        "lifecycle_obligations",
        "mode",
        "operation",
        "policy_binding",
        "predecessor_session_ref",
        "profile_evidence",
        "provider_binding",
        "record_kind",
        "requested_session_ref",
        "schema_version",
        "v1_evidence",
    }
    values = _exact(raw, fields, "authentication command")
    _payload(raw, TargetAuthenticationCommand.record_kind, {"command_id", "command_sha256"})
    record = TargetAuthenticationCommand(
        policy_binding=_binding_from(values["policy_binding"]),
        provider_binding=_binding_from(values["provider_binding"]),
        execution_environment=values["execution_environment"],
        operation=values["operation"],
        mode=values["mode"],
        profile_evidence=AuthenticationProfileEvidence.from_dict(values["profile_evidence"]),
        v1_evidence=V1TargetSessionEvidenceBinding.from_dict(values["v1_evidence"]),
        credential_provenance=_bindings_from(
            values["credential_provenance"], "credential_provenance"
        ),
        lifecycle_obligations=tuple(
            _array(values["lifecycle_obligations"], "lifecycle_obligations")
        ),
        requested_session_ref=values["requested_session_ref"],
        predecessor_session_ref=values["predecessor_session_ref"],
        fixture_scenario_ref=values["fixture_scenario_ref"],
        issued_at=values["issued_at"],
        expires_at=values["expires_at"],
    )
    return _verify_identity(raw, record, "command_id", "command_sha256")


def parse_target_authentication_flow_evidence(
    document: str,
) -> TargetAuthenticationFlowEvidence:
    raw = _load(document, "authentication flow evidence")
    fields = {
        "claims",
        "command_binding",
        "effects",
        "evidence_id",
        "evidence_sha256",
        "environment_attestation_sha256",
        "execution_environment",
        "failure_code",
        "input_evidence_sha256",
        "observed_at",
        "output_evidence_sha256",
        "provider_binding",
        "provider_attestation_sha256",
        "record_kind",
        "schema_version",
        "sequence",
        "stage",
    }
    values = _exact(raw, fields, "authentication flow evidence")
    _payload(raw, TargetAuthenticationFlowEvidence.record_kind, {"evidence_id", "evidence_sha256"})
    record = TargetAuthenticationFlowEvidence(
        command_binding=_binding_from(values["command_binding"]),
        provider_binding=_binding_from(values["provider_binding"]),
        execution_environment=values["execution_environment"],
        stage=values["stage"],
        sequence=values["sequence"],
        input_evidence_sha256=values["input_evidence_sha256"],
        output_evidence_sha256=values["output_evidence_sha256"],
        provider_attestation_sha256=values["provider_attestation_sha256"],
        environment_attestation_sha256=values["environment_attestation_sha256"],
        failure_code=values["failure_code"],
        observed_at=values["observed_at"],
    )
    return _verify_identity(raw, record, "evidence_id", "evidence_sha256")


def parse_target_authentication_result(document: str) -> TargetAuthenticationResult:
    raw = _load(document, "authentication result")
    fields = {
        "claims",
        "command_binding",
        "completed_at",
        "effects",
        "environment_attestation_sha256",
        "execution_environment",
        "failure_code",
        "flow_evidence",
        "outcome",
        "pending_lifecycle_obligations",
        "provider_binding",
        "provider_attestation_sha256",
        "record_kind",
        "result_id",
        "result_sha256",
        "resulting_session_ref",
        "satisfied_lifecycle_obligations",
        "schema_version",
        "session_evidence_sha256",
    }
    values = _exact(raw, fields, "authentication result")
    _payload(raw, TargetAuthenticationResult.record_kind, {"result_id", "result_sha256"})
    record = TargetAuthenticationResult(
        command_binding=_binding_from(values["command_binding"]),
        provider_binding=_binding_from(values["provider_binding"]),
        execution_environment=values["execution_environment"],
        outcome=values["outcome"],
        failure_code=values["failure_code"],
        flow_evidence=_bindings_from(values["flow_evidence"], "flow_evidence"),
        resulting_session_ref=values["resulting_session_ref"],
        session_evidence_sha256=values["session_evidence_sha256"],
        provider_attestation_sha256=values["provider_attestation_sha256"],
        environment_attestation_sha256=values["environment_attestation_sha256"],
        satisfied_lifecycle_obligations=tuple(
            _array(
                values["satisfied_lifecycle_obligations"],
                "satisfied_lifecycle_obligations",
            )
        ),
        pending_lifecycle_obligations=tuple(
            _array(
                values["pending_lifecycle_obligations"],
                "pending_lifecycle_obligations",
            )
        ),
        completed_at=values["completed_at"],
    )
    return _verify_identity(raw, record, "result_id", "result_sha256")


def parse_target_authentication_receipt(document: str) -> TargetAuthenticationReceipt:
    raw = _load(document, "authentication receipt")
    fields = {
        "claims",
        "command_binding",
        "effects",
        "execution_environment",
        "flow_evidence",
        "issued_at",
        "lifecycle_complete",
        "policy_binding",
        "provider_binding",
        "receipt_id",
        "receipt_sha256",
        "record_kind",
        "result_binding",
        "schema_version",
        "verification_status",
    }
    values = _exact(raw, fields, "authentication receipt")
    _payload(raw, TargetAuthenticationReceipt.record_kind, {"receipt_id", "receipt_sha256"})
    if values["verification_status"] != TargetAuthenticationReceipt.verification_status:
        raise TargetAuthenticationContractError("receipt verification status is invalid")
    record = TargetAuthenticationReceipt(
        provider_binding=_binding_from(values["provider_binding"]),
        policy_binding=_binding_from(values["policy_binding"]),
        command_binding=_binding_from(values["command_binding"]),
        result_binding=_binding_from(values["result_binding"]),
        flow_evidence=_bindings_from(values["flow_evidence"], "flow_evidence"),
        execution_environment=values["execution_environment"],
        lifecycle_complete=values["lifecycle_complete"],
        issued_at=values["issued_at"],
    )
    return _verify_identity(raw, record, "receipt_id", "receipt_sha256")


RECORD_PARSERS = MappingProxyType(
    {
        TargetAuthenticationProviderBinding.record_kind: (
            parse_target_authentication_provider_binding
        ),
        TargetCredentialProvenance.record_kind: parse_target_credential_provenance,
        TargetAuthenticationPolicy.record_kind: parse_target_authentication_policy,
        TargetAuthenticationCommand.record_kind: parse_target_authentication_command,
        TargetAuthenticationFlowEvidence.record_kind: parse_target_authentication_flow_evidence,
        TargetAuthenticationResult.record_kind: parse_target_authentication_result,
        TargetAuthenticationReceipt.record_kind: parse_target_authentication_receipt,
    }
)


def parse_target_authentication_record(document: str) -> Any:
    """Parse one canonical version 2 record using its closed record kind."""

    raw = _load(document, "target authentication record")
    parser = RECORD_PARSERS.get(raw.get("record_kind"))
    if parser is None:
        raise TargetAuthenticationContractError("target authentication record kind is invalid")
    return parser(document)


__all__ = [
    "AUTHENTICATION_MODE_PROFILES",
    "MAX_FLOW_EVIDENCE",
    "MAX_WINDOW_SECONDS",
    "NO_CLAIMS",
    "NO_EFFECTS",
    "RECORD_PARSERS",
    "SCHEMA_VERSION",
    "AuthenticationFailureCode",
    "AuthenticationFactor",
    "AuthenticationMode",
    "AuthenticationModeProfile",
    "AuthenticationOperation",
    "AuthenticationOutcome",
    "AuthenticationProfileEvidence",
    "AuthenticationProtocol",
    "ContentAddressBinding",
    "CredentialLeaseMode",
    "ExecutionEnvironment",
    "FlowStage",
    "LifecycleObligation",
    "PrincipalTopology",
    "SessionCarrier",
    "TargetAuthenticationCommand",
    "TargetAuthenticationContractError",
    "TargetAuthenticationFlowEvidence",
    "TargetAuthenticationPolicy",
    "TargetAuthenticationProviderBinding",
    "TargetAuthenticationReceipt",
    "TargetAuthenticationResult",
    "TargetCredentialProvenance",
    "V1TargetSessionEvidenceBinding",
    "canonical_json",
    "canonical_sha256",
    "issue_target_authentication_receipt",
    "parse_target_authentication_command",
    "parse_target_authentication_flow_evidence",
    "parse_target_authentication_policy",
    "parse_target_authentication_provider_binding",
    "parse_target_authentication_receipt",
    "parse_target_authentication_record",
    "parse_target_authentication_result",
    "parse_target_credential_provenance",
    "transport_credential_reference_sha256",
    "verify_target_authentication_chain",
]
