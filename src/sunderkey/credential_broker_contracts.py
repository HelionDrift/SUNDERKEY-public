"""Fail-closed credential broker contracts with no secret resolution.

The records in this module describe opaque references, approvals, leases,
receipts, and follow-up obligations. They never resolve credential material,
contact a provider, create a session, authenticate, decrypt, or execute work.
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

NO_EFFECTS = MappingProxyType(
    {
        "approval_authority": "none",
        "authentication": "none",
        "credential_values": "none",
        "decryption": "none",
        "execution": "none",
        "login": "none",
        "network": "none",
        "provider_calls": "none",
        "secret_resolution": "none",
        "session_creation": "none",
        "vault_clients": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|taskref|principalref|targetref|techniqueref|"
    r"purposeref|credentialref|providerref|adapterref|scoperef|roleref|"
    r"sessionref|issuanceref|obligationref|reasonref|evidenceref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@|"
    r"\b(?:password|passwd|token|private_key|cookie|otp|magic_link)\s*[:=])",
    re.IGNORECASE,
)

MAX_TTL_SECONDS = 86_400
MAX_USES_PER_LEASE = 100
MIN_APPROVERS = MappingProxyType({"R0": 1, "R1": 1, "R2": 2, "R3": 2, "R4": 3, "R5": 3})
REQUIRED_ROLES = MappingProxyType(
    {
        "R0": frozenset({"roleref:credential-control"}),
        "R1": frozenset({"roleref:credential-control"}),
        "R2": frozenset({"roleref:credential-control", "roleref:independent-assurance"}),
        "R3": frozenset({"roleref:credential-control", "roleref:independent-assurance"}),
        "R4": frozenset(
            {
                "roleref:credential-control",
                "roleref:independent-assurance",
                "roleref:risk-owner",
            }
        ),
        "R5": frozenset(
            {
                "roleref:credential-control",
                "roleref:independent-assurance",
                "roleref:risk-owner",
            }
        ),
    }
)


class CredentialBrokerContractError(ValueError):
    """Raised when a credential contract fails closed."""


class LeaseMode(StrEnum):
    """Supported bounded lease modes."""

    ONE_TIME = "one_time"
    SESSION_BOUND = "session_bound"


class UsageOutcome(StrEnum):
    """Closed usage result vocabulary."""

    USED = "used"
    DENIED = "denied"
    FAILED = "failed"


class ObligationStatus(StrEnum):
    """Closed lifecycle status for follow-up obligations."""

    PENDING = "pending"
    COMPLETED = "completed"


def canonical_json(value: Any) -> str:
    """Return printable ASCII canonical JSON after rejecting secret material."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_MATERIAL_RE.search(encoded):
        raise CredentialBrokerContractError("credential material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def verify_content_address(
    raw: Mapping[str, Any], *, id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    """Verify a serialized record without trusting its declared address."""

    if not isinstance(raw, Mapping):
        raise CredentialBrokerContractError("record must be a mapping")
    if id_field not in raw or digest_field not in raw:
        raise CredentialBrokerContractError("record content address is missing")
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise CredentialBrokerContractError("record content address does not match content")


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise CredentialBrokerContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CredentialBrokerContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise CredentialBrokerContractError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise CredentialBrokerContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise CredentialBrokerContractError(f"{label} must use the {namespace} namespace")
    if SECRET_MATERIAL_RE.search(value):
        raise CredentialBrokerContractError(f"{label} contains forbidden credential material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CredentialBrokerContractError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CredentialBrokerContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CredentialBrokerContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise CredentialBrokerContractError("time must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise CredentialBrokerContractError(f"{label} must be an exact numeric version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise CredentialBrokerContractError(f"{label} must not be a moving alias")
    return value


def _positive(value: Any, label: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
        raise CredentialBrokerContractError(f"{label} must be between 1 and {ceiling}")
    return value


def _references(
    values: Sequence[str], label: str, namespace: str, *, minimum: int = 1
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise CredentialBrokerContractError(f"{label} must be a sequence")
    normalized = tuple(_reference(item, f"{label} item", namespace) for item in values)
    if len(normalized) < minimum:
        raise CredentialBrokerContractError(f"{label} has too few entries")
    if len(normalized) != len(set(normalized)):
        raise CredentialBrokerContractError(f"{label} must contain unique entries")
    return tuple(sorted(normalized))


def _digests(values: Sequence[str], label: str, *, minimum: int = 0) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise CredentialBrokerContractError(f"{label} must be a sequence")
    normalized = tuple(_digest(item, f"{label} item") for item in values)
    if len(normalized) < minimum:
        raise CredentialBrokerContractError(f"{label} has too few entries")
    if len(normalized) != len(set(normalized)):
        raise CredentialBrokerContractError(f"{label} must contain unique entries")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    """Pinned provider adapter identity with no client implementation."""

    provider_ref: str
    adapter_ref: str
    adapter_version: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider_ref", _reference(self.provider_ref, "provider_ref", "providerref")
        )
        object.__setattr__(
            self, "adapter_ref", _reference(self.adapter_ref, "adapter_ref", "adapterref")
        )
        object.__setattr__(
            self, "adapter_version", _version(self.adapter_version, "adapter_version")
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "adapter_ref": self.adapter_ref,
            "adapter_version": self.adapter_version,
            "provider_ref": self.provider_ref,
        }


@dataclass(frozen=True, slots=True)
class CredentialDescriptor:
    """Opaque credential capability envelope, never credential material."""

    tenant_ref: str
    assessment_ref: str
    credential_ref: str
    subject_principal_ref: str
    adapter: ProviderAdapter
    allowed_target_refs: tuple[str, ...]
    allowed_technique_refs: tuple[str, ...]
    allowed_purpose_refs: tuple[str, ...]
    allowed_scope_refs: tuple[str, ...]
    allowed_modes: tuple[LeaseMode, ...]
    max_lease_ttl_seconds: int
    max_uses_per_lease: int
    revocation_obligation_ref: str
    rotation_obligation_ref: str
    created_at: str
    expires_at: str
    descriptor_id: str = field(init=False)
    descriptor_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-descriptor.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("credential_ref", "credentialref"),
            ("subject_principal_ref", "principalref"),
            ("revocation_obligation_ref", "obligationref"),
            ("rotation_obligation_ref", "obligationref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        if not isinstance(self.adapter, ProviderAdapter):
            raise CredentialBrokerContractError("adapter must be a ProviderAdapter")
        for name, namespace in (
            ("allowed_target_refs", "targetref"),
            ("allowed_technique_refs", "techniqueref"),
            ("allowed_purpose_refs", "purposeref"),
            ("allowed_scope_refs", "scoperef"),
        ):
            object.__setattr__(self, name, _references(getattr(self, name), name, namespace))
        if not isinstance(self.allowed_modes, tuple) or not self.allowed_modes:
            raise CredentialBrokerContractError("allowed_modes must be a non-empty tuple")
        modes = tuple(sorted((LeaseMode(mode) for mode in self.allowed_modes), key=str))
        if len(modes) != len(set(modes)):
            raise CredentialBrokerContractError("allowed_modes must be unique")
        object.__setattr__(self, "allowed_modes", modes)
        _positive(self.max_lease_ttl_seconds, "max_lease_ttl_seconds", MAX_TTL_SECONDS)
        _positive(self.max_uses_per_lease, "max_uses_per_lease", MAX_USES_PER_LEASE)
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.created_at):
            raise CredentialBrokerContractError("descriptor must expire after creation")
        body = self._body()
        descriptor_id, digest = _identity("CBD", self.KIND, body)
        object.__setattr__(self, "descriptor_id", descriptor_id)
        object.__setattr__(self, "descriptor_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter.to_dict(),
            "allowed_modes": [mode.value for mode in self.allowed_modes],
            "allowed_purpose_refs": list(self.allowed_purpose_refs),
            "allowed_scope_refs": list(self.allowed_scope_refs),
            "allowed_target_refs": list(self.allowed_target_refs),
            "allowed_technique_refs": list(self.allowed_technique_refs),
            "assessment_ref": self.assessment_ref,
            "created_at": self.created_at,
            "credential_ref": self.credential_ref,
            "expires_at": self.expires_at,
            "max_lease_ttl_seconds": self.max_lease_ttl_seconds,
            "max_uses_per_lease": self.max_uses_per_lease,
            "revocation_obligation_ref": self.revocation_obligation_ref,
            "rotation_obligation_ref": self.rotation_obligation_ref,
            "subject_principal_ref": self.subject_principal_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor_id": self.descriptor_id,
            "descriptor_sha256": self.descriptor_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class CredentialAccessRequest:
    """Least privilege request bound to one assessment action."""

    descriptor_sha256: str
    tenant_ref: str
    assessment_ref: str
    task_ref: str
    requester_principal_ref: str
    subject_principal_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    requested_scope_refs: tuple[str, ...]
    action_tier: str
    lease_mode: LeaseMode
    requested_ttl_seconds: int
    requested_max_uses: int
    requested_at: str
    expires_at: str
    renewal_of_lease_sha256: str | None = None
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-access-request.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "descriptor_sha256", _digest(self.descriptor_sha256, "descriptor_sha256")
        )
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("task_ref", "taskref"),
            ("requester_principal_ref", "principalref"),
            ("subject_principal_ref", "principalref"),
            ("target_ref", "targetref"),
            ("technique_ref", "techniqueref"),
            ("purpose_ref", "purposeref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        object.__setattr__(
            self,
            "requested_scope_refs",
            _references(self.requested_scope_refs, "requested_scope_refs", "scoperef"),
        )
        if self.action_tier not in MIN_APPROVERS:
            raise CredentialBrokerContractError("action_tier is invalid")
        object.__setattr__(self, "lease_mode", LeaseMode(self.lease_mode))
        _positive(self.requested_ttl_seconds, "requested_ttl_seconds", MAX_TTL_SECONDS)
        _positive(self.requested_max_uses, "requested_max_uses", MAX_USES_PER_LEASE)
        if self.lease_mode is LeaseMode.ONE_TIME and self.requested_max_uses != 1:
            raise CredentialBrokerContractError("one_time requests must allow exactly one use")
        object.__setattr__(self, "requested_at", _timestamp(self.requested_at, "requested_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.requested_at):
            raise CredentialBrokerContractError("request must expire after creation")
        if self.renewal_of_lease_sha256 is not None:
            object.__setattr__(
                self,
                "renewal_of_lease_sha256",
                _digest(self.renewal_of_lease_sha256, "renewal_of_lease_sha256"),
            )
        request_id, digest = _identity("CAR", self.KIND, self._body())
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier,
            "assessment_ref": self.assessment_ref,
            "descriptor_sha256": self.descriptor_sha256,
            "expires_at": self.expires_at,
            "lease_mode": self.lease_mode.value,
            "purpose_ref": self.purpose_ref,
            "renewal_of_lease_sha256": self.renewal_of_lease_sha256,
            "requested_at": self.requested_at,
            "requested_max_uses": self.requested_max_uses,
            "requested_scope_refs": list(self.requested_scope_refs),
            "requested_ttl_seconds": self.requested_ttl_seconds,
            "requester_principal_ref": self.requester_principal_ref,
            "subject_principal_ref": self.subject_principal_ref,
            "target_ref": self.target_ref,
            "task_ref": self.task_ref,
            "technique_ref": self.technique_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class ApprovalAttestation:
    """One independent human or service-principal attestation reference."""

    approver_principal_ref: str
    role_ref: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "approver_principal_ref",
            _reference(self.approver_principal_ref, "approver_principal_ref", "principalref"),
        )
        object.__setattr__(self, "role_ref", _reference(self.role_ref, "role_ref", "roleref"))
        object.__setattr__(
            self, "evidence_sha256", _digest(self.evidence_sha256, "evidence_sha256")
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "approver_principal_ref": self.approver_principal_ref,
            "evidence_sha256": self.evidence_sha256,
            "role_ref": self.role_ref,
        }


@dataclass(frozen=True, slots=True)
class IndependentApprovalBinding:
    """Independent approval bound to exactly one access request."""

    request_sha256: str
    action_tier: str
    approved_scope_refs: tuple[str, ...]
    approved_ttl_seconds: int
    approved_max_uses: int
    lease_mode: LeaseMode
    attestations: tuple[ApprovalAttestation, ...]
    approved_at: str
    expires_at: str
    approval_id: str = field(init=False)
    approval_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-independent-approval.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_sha256", _digest(self.request_sha256, "request_sha256"))
        if self.action_tier not in MIN_APPROVERS:
            raise CredentialBrokerContractError("action_tier is invalid")
        object.__setattr__(
            self,
            "approved_scope_refs",
            _references(self.approved_scope_refs, "approved_scope_refs", "scoperef"),
        )
        _positive(self.approved_ttl_seconds, "approved_ttl_seconds", MAX_TTL_SECONDS)
        _positive(self.approved_max_uses, "approved_max_uses", MAX_USES_PER_LEASE)
        object.__setattr__(self, "lease_mode", LeaseMode(self.lease_mode))
        if self.lease_mode is LeaseMode.ONE_TIME and self.approved_max_uses != 1:
            raise CredentialBrokerContractError("one_time approvals must allow exactly one use")
        if not isinstance(self.attestations, tuple) or not all(
            isinstance(item, ApprovalAttestation) for item in self.attestations
        ):
            raise CredentialBrokerContractError("attestations must be ApprovalAttestation values")
        ordered = tuple(sorted(self.attestations, key=lambda item: item.approver_principal_ref))
        if len({item.approver_principal_ref for item in ordered}) != len(ordered):
            raise CredentialBrokerContractError("approval principals must be unique")
        if len({item.role_ref for item in ordered}) != len(ordered):
            raise CredentialBrokerContractError("approval roles must be separated")
        if len(ordered) < MIN_APPROVERS[self.action_tier]:
            raise CredentialBrokerContractError("action tier requires more independent approvals")
        roles = {item.role_ref for item in ordered}
        if not REQUIRED_ROLES[self.action_tier].issubset(roles):
            raise CredentialBrokerContractError("action tier separation roles are incomplete")
        object.__setattr__(self, "attestations", ordered)
        object.__setattr__(self, "approved_at", _timestamp(self.approved_at, "approved_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.approved_at):
            raise CredentialBrokerContractError("approval must expire after approval time")
        approval_id, digest = _identity("CAB", self.KIND, self._body())
        object.__setattr__(self, "approval_id", approval_id)
        object.__setattr__(self, "approval_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier,
            "approved_at": self.approved_at,
            "approved_max_uses": self.approved_max_uses,
            "approved_scope_refs": list(self.approved_scope_refs),
            "approved_ttl_seconds": self.approved_ttl_seconds,
            "attestations": [item.to_dict() for item in self.attestations],
            "expires_at": self.expires_at,
            "lease_mode": self.lease_mode.value,
            "request_sha256": self.request_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approval_sha256": self.approval_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class PrincipalCredentialBinding:
    """Opaque binding used to prove test principals stay separate."""

    principal_ref: str
    descriptor_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(
            self, "descriptor_sha256", _digest(self.descriptor_sha256, "descriptor_sha256")
        )

    def to_dict(self) -> dict[str, str]:
        return {"descriptor_sha256": self.descriptor_sha256, "principal_ref": self.principal_ref}


@dataclass(frozen=True, slots=True)
class MultiPrincipalTestIdentitySet:
    """At least two distinct principal and descriptor references."""

    tenant_ref: str
    assessment_ref: str
    bindings: tuple[PrincipalCredentialBinding, ...]
    identity_set_id: str = field(init=False)
    identity_set_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.multi-principal-test-identity-set.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_ref", _reference(self.tenant_ref, "tenant_ref", "tenantref")
        )
        object.__setattr__(
            self,
            "assessment_ref",
            _reference(self.assessment_ref, "assessment_ref", "assessmentref"),
        )
        if not isinstance(self.bindings, tuple) or len(self.bindings) < 2:
            raise CredentialBrokerContractError(
                "multi-principal tests require at least two bindings"
            )
        if not all(isinstance(item, PrincipalCredentialBinding) for item in self.bindings):
            raise CredentialBrokerContractError("identity bindings are invalid")
        ordered = tuple(sorted(self.bindings, key=lambda item: item.principal_ref))
        if len({item.principal_ref for item in ordered}) != len(ordered):
            raise CredentialBrokerContractError("test principals must be distinct")
        if len({item.descriptor_sha256 for item in ordered}) != len(ordered):
            raise CredentialBrokerContractError("test principals must use separate credentials")
        object.__setattr__(self, "bindings", ordered)
        identity_set_id, digest = _identity("CIS", self.KIND, self._body())
        object.__setattr__(self, "identity_set_id", identity_set_id)
        object.__setattr__(self, "identity_set_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "bindings": [item.to_dict() for item in self.bindings],
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_set_id": self.identity_set_id,
            "identity_set_sha256": self.identity_set_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class CredentialLease:
    """Time and use bounded authority reference, without credential material."""

    descriptor_sha256: str
    request_sha256: str
    approval_sha256: str
    tenant_ref: str
    assessment_ref: str
    task_ref: str
    requester_principal_ref: str
    subject_principal_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    scope_refs: tuple[str, ...]
    action_tier: str
    lease_mode: LeaseMode
    issuance_ref: str
    session_ref: str | None
    issued_at: str
    expires_at: str
    max_uses: int
    renewal_of_lease_sha256: str | None
    lease_id: str = field(init=False)
    lease_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-lease.v1"

    def __post_init__(self) -> None:
        for name in ("descriptor_sha256", "request_sha256", "approval_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("task_ref", "taskref"),
            ("requester_principal_ref", "principalref"),
            ("subject_principal_ref", "principalref"),
            ("target_ref", "targetref"),
            ("technique_ref", "techniqueref"),
            ("purpose_ref", "purposeref"),
            ("issuance_ref", "issuanceref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "scope_refs", _references(self.scope_refs, "scope_refs", "scoperef")
        )
        if self.action_tier not in MIN_APPROVERS:
            raise CredentialBrokerContractError("action_tier is invalid")
        object.__setattr__(self, "lease_mode", LeaseMode(self.lease_mode))
        if self.lease_mode is LeaseMode.ONE_TIME:
            if self.session_ref is not None or self.max_uses != 1:
                raise CredentialBrokerContractError(
                    "one_time lease cannot be session bound and must allow one use"
                )
        elif self.session_ref is None:
            raise CredentialBrokerContractError("session_bound lease requires session_ref")
        if self.session_ref is not None:
            object.__setattr__(
                self, "session_ref", _reference(self.session_ref, "session_ref", "sessionref")
            )
        _positive(self.max_uses, "max_uses", MAX_USES_PER_LEASE)
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "issued_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.issued_at):
            raise CredentialBrokerContractError("lease must expire after issuance")
        if self.renewal_of_lease_sha256 is not None:
            object.__setattr__(
                self,
                "renewal_of_lease_sha256",
                _digest(self.renewal_of_lease_sha256, "renewal_of_lease_sha256"),
            )
        lease_id, digest = _identity("CLZ", self.KIND, self._body())
        object.__setattr__(self, "lease_id", lease_id)
        object.__setattr__(self, "lease_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier,
            "approval_sha256": self.approval_sha256,
            "assessment_ref": self.assessment_ref,
            "descriptor_sha256": self.descriptor_sha256,
            "expires_at": self.expires_at,
            "issuance_ref": self.issuance_ref,
            "issued_at": self.issued_at,
            "lease_mode": self.lease_mode.value,
            "max_uses": self.max_uses,
            "purpose_ref": self.purpose_ref,
            "renewal_of_lease_sha256": self.renewal_of_lease_sha256,
            "request_sha256": self.request_sha256,
            "requester_principal_ref": self.requester_principal_ref,
            "scope_refs": list(self.scope_refs),
            "session_ref": self.session_ref,
            "subject_principal_ref": self.subject_principal_ref,
            "target_ref": self.target_ref,
            "task_ref": self.task_ref,
            "technique_ref": self.technique_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"lease_id": self.lease_id, "lease_sha256": self.lease_sha256, **self._body()}


@dataclass(frozen=True, slots=True)
class CredentialUsageReceipt:
    """Immutable proof that a numbered lease use was consumed."""

    lease_sha256: str
    tenant_ref: str
    assessment_ref: str
    task_ref: str
    subject_principal_ref: str
    target_ref: str
    technique_ref: str
    purpose_ref: str
    session_ref: str | None
    use_number: int
    outcome: UsageOutcome
    used_at: str
    evidence_hashes: tuple[str, ...]
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-usage-receipt.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "lease_sha256", _digest(self.lease_sha256, "lease_sha256"))
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("task_ref", "taskref"),
            ("subject_principal_ref", "principalref"),
            ("target_ref", "targetref"),
            ("technique_ref", "techniqueref"),
            ("purpose_ref", "purposeref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        if self.session_ref is not None:
            object.__setattr__(
                self, "session_ref", _reference(self.session_ref, "session_ref", "sessionref")
            )
        _positive(self.use_number, "use_number", MAX_USES_PER_LEASE)
        object.__setattr__(self, "outcome", UsageOutcome(self.outcome))
        object.__setattr__(self, "used_at", _timestamp(self.used_at, "used_at"))
        object.__setattr__(
            self, "evidence_hashes", _digests(self.evidence_hashes, "evidence_hashes", minimum=1)
        )
        receipt_id, digest = _identity("CUR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "evidence_hashes": list(self.evidence_hashes),
            "lease_sha256": self.lease_sha256,
            "outcome": self.outcome.value,
            "purpose_ref": self.purpose_ref,
            "session_ref": self.session_ref,
            "subject_principal_ref": self.subject_principal_ref,
            "target_ref": self.target_ref,
            "task_ref": self.task_ref,
            "technique_ref": self.technique_ref,
            "tenant_ref": self.tenant_ref,
            "use_number": self.use_number,
            "used_at": self.used_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class CredentialLifecycleObligation:
    """Revocation or rotation duty represented without performing it."""

    obligation_kind: str
    obligation_ref: str
    descriptor_sha256: str
    lease_sha256: str | None
    trigger_sha256: str
    tenant_ref: str
    assessment_ref: str
    responsible_role_ref: str
    reason_ref: str
    required_by: str
    status: ObligationStatus
    completed_at: str | None = None
    completion_evidence_sha256: str | None = None
    obligation_id: str = field(init=False)
    obligation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.credential-lifecycle-obligation.v1"

    def __post_init__(self) -> None:
        if self.obligation_kind not in {"revocation", "rotation"}:
            raise CredentialBrokerContractError("obligation_kind is invalid")
        for name, namespace in (
            ("obligation_ref", "obligationref"),
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("responsible_role_ref", "roleref"),
            ("reason_ref", "reasonref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "descriptor_sha256", _digest(self.descriptor_sha256, "descriptor_sha256")
        )
        object.__setattr__(self, "trigger_sha256", _digest(self.trigger_sha256, "trigger_sha256"))
        if self.lease_sha256 is not None:
            object.__setattr__(self, "lease_sha256", _digest(self.lease_sha256, "lease_sha256"))
        object.__setattr__(self, "required_by", _timestamp(self.required_by, "required_by"))
        object.__setattr__(self, "status", ObligationStatus(self.status))
        if self.status is ObligationStatus.PENDING:
            if self.completed_at is not None or self.completion_evidence_sha256 is not None:
                raise CredentialBrokerContractError(
                    "pending obligation cannot include completion proof"
                )
        else:
            if self.completed_at is None or self.completion_evidence_sha256 is None:
                raise CredentialBrokerContractError(
                    "completed obligation requires completion proof"
                )
            object.__setattr__(self, "completed_at", _timestamp(self.completed_at, "completed_at"))
            object.__setattr__(
                self,
                "completion_evidence_sha256",
                _digest(self.completion_evidence_sha256, "completion_evidence_sha256"),
            )
        obligation_id, digest = _identity("CLO", self.KIND, self._body())
        object.__setattr__(self, "obligation_id", obligation_id)
        object.__setattr__(self, "obligation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "completed_at": self.completed_at,
            "completion_evidence_sha256": self.completion_evidence_sha256,
            "descriptor_sha256": self.descriptor_sha256,
            "lease_sha256": self.lease_sha256,
            "obligation_kind": self.obligation_kind,
            "obligation_ref": self.obligation_ref,
            "reason_ref": self.reason_ref,
            "required_by": self.required_by,
            "responsible_role_ref": self.responsible_role_ref,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
            "trigger_sha256": self.trigger_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "obligation_sha256": self.obligation_sha256,
            **self._body(),
        }


def validate_access_request(
    descriptor: CredentialDescriptor,
    request: CredentialAccessRequest,
    *,
    now: datetime,
) -> None:
    """Validate exact bindings and least privilege. Silence is never approval."""

    current = now.astimezone(UTC)
    if current < _instant(descriptor.created_at) or current < _instant(request.requested_at):
        raise CredentialBrokerContractError("descriptor or request is not yet active")
    if current >= _instant(descriptor.expires_at) or current >= _instant(request.expires_at):
        raise CredentialBrokerContractError("descriptor or request is expired")
    checks = (
        (request.descriptor_sha256, descriptor.descriptor_sha256, "descriptor"),
        (request.tenant_ref, descriptor.tenant_ref, "tenant"),
        (request.assessment_ref, descriptor.assessment_ref, "assessment"),
        (request.subject_principal_ref, descriptor.subject_principal_ref, "principal"),
    )
    for actual, expected, label in checks:
        if actual != expected:
            raise CredentialBrokerContractError(f"{label} binding mismatch")
    if request.target_ref not in descriptor.allowed_target_refs:
        raise CredentialBrokerContractError("target is not allowed")
    if request.technique_ref not in descriptor.allowed_technique_refs:
        raise CredentialBrokerContractError("technique is not allowed")
    if request.purpose_ref not in descriptor.allowed_purpose_refs:
        raise CredentialBrokerContractError("purpose is not allowed")
    if not set(request.requested_scope_refs).issubset(descriptor.allowed_scope_refs):
        raise CredentialBrokerContractError("requested scopes exceed least privilege envelope")
    if request.lease_mode not in descriptor.allowed_modes:
        raise CredentialBrokerContractError("lease mode is not allowed")
    if request.requested_ttl_seconds > descriptor.max_lease_ttl_seconds:
        raise CredentialBrokerContractError("requested TTL exceeds descriptor ceiling")
    if request.requested_max_uses > descriptor.max_uses_per_lease:
        raise CredentialBrokerContractError("requested uses exceed descriptor ceiling")


def issue_lease(
    descriptor: CredentialDescriptor,
    request: CredentialAccessRequest,
    approval: IndependentApprovalBinding,
    *,
    issuance_ref: str,
    session_ref: str | None,
    now: datetime,
    consumed_approval_sha256s: Sequence[str] = (),
    prior_lease: CredentialLease | None = None,
) -> CredentialLease:
    """Create a lease record after every fail-closed contract check."""

    validate_access_request(descriptor, request, now=now)
    current = now.astimezone(UTC)
    if current < _instant(approval.approved_at):
        raise CredentialBrokerContractError("approval is not yet active")
    if current >= _instant(approval.expires_at):
        raise CredentialBrokerContractError("approval is expired")
    consumed = _digests(consumed_approval_sha256s, "consumed_approval_sha256s")
    if approval.approval_sha256 in consumed:
        raise CredentialBrokerContractError("approval replay is forbidden")
    if approval.request_sha256 != request.request_sha256:
        raise CredentialBrokerContractError("approval is not bound to this request")
    approvers = {item.approver_principal_ref for item in approval.attestations}
    if request.requester_principal_ref in approvers:
        raise CredentialBrokerContractError("requester cannot self-approve")
    if request.subject_principal_ref in approvers:
        raise CredentialBrokerContractError("subject principal cannot approve its own lease")
    if approval.action_tier != request.action_tier:
        raise CredentialBrokerContractError("approval action tier mismatch")
    if approval.lease_mode is not request.lease_mode:
        raise CredentialBrokerContractError("approval lease mode mismatch")
    if not set(approval.approved_scope_refs).issubset(request.requested_scope_refs):
        raise CredentialBrokerContractError("approval scopes exceed request")
    if approval.approved_ttl_seconds > request.requested_ttl_seconds:
        raise CredentialBrokerContractError("approval TTL exceeds request")
    if approval.approved_max_uses > request.requested_max_uses:
        raise CredentialBrokerContractError("approval uses exceed request")
    if request.renewal_of_lease_sha256 is None:
        if prior_lease is not None:
            raise CredentialBrokerContractError("prior lease supplied for a non-renewal")
    else:
        if prior_lease is None or prior_lease.lease_sha256 != request.renewal_of_lease_sha256:
            raise CredentialBrokerContractError("renewal must bind the exact prior lease")
        if approval.approval_sha256 == prior_lease.approval_sha256:
            raise CredentialBrokerContractError("renewal requires a new approval")
        if descriptor.descriptor_sha256 != prior_lease.descriptor_sha256:
            raise CredentialBrokerContractError("renewal descriptor substitution is forbidden")
    issued_at = _format_time(current)
    expires_at = _format_time(
        min(
            current + timedelta(seconds=approval.approved_ttl_seconds),
            _instant(descriptor.expires_at),
            _instant(request.expires_at),
            _instant(approval.expires_at),
        )
    )
    return CredentialLease(
        descriptor_sha256=descriptor.descriptor_sha256,
        request_sha256=request.request_sha256,
        approval_sha256=approval.approval_sha256,
        tenant_ref=request.tenant_ref,
        assessment_ref=request.assessment_ref,
        task_ref=request.task_ref,
        requester_principal_ref=request.requester_principal_ref,
        subject_principal_ref=request.subject_principal_ref,
        target_ref=request.target_ref,
        technique_ref=request.technique_ref,
        purpose_ref=request.purpose_ref,
        scope_refs=approval.approved_scope_refs,
        action_tier=request.action_tier,
        lease_mode=request.lease_mode,
        issuance_ref=issuance_ref,
        session_ref=session_ref,
        issued_at=issued_at,
        expires_at=expires_at,
        max_uses=approval.approved_max_uses,
        renewal_of_lease_sha256=request.renewal_of_lease_sha256,
    )


def record_usage(
    lease: CredentialLease,
    *,
    tenant_ref: str,
    assessment_ref: str,
    task_ref: str,
    subject_principal_ref: str,
    target_ref: str,
    technique_ref: str,
    purpose_ref: str,
    session_ref: str | None,
    outcome: UsageOutcome,
    evidence_hashes: Sequence[str],
    now: datetime,
    prior_receipts: Sequence[CredentialUsageReceipt] = (),
    revoked_lease_sha256s: Sequence[str] = (),
) -> CredentialUsageReceipt:
    """Consume one numbered use while rejecting expiry, replay, and substitution."""

    current = now.astimezone(UTC)
    if current < _instant(lease.issued_at) or current >= _instant(lease.expires_at):
        raise CredentialBrokerContractError("lease is not active")
    if lease.lease_sha256 in _digests(revoked_lease_sha256s, "revoked_lease_sha256s"):
        raise CredentialBrokerContractError("lease is revoked")
    supplied = (
        (tenant_ref, lease.tenant_ref, "tenant"),
        (assessment_ref, lease.assessment_ref, "assessment"),
        (task_ref, lease.task_ref, "task"),
        (subject_principal_ref, lease.subject_principal_ref, "principal"),
        (target_ref, lease.target_ref, "target"),
        (technique_ref, lease.technique_ref, "technique"),
        (purpose_ref, lease.purpose_ref, "purpose"),
        (session_ref, lease.session_ref, "session"),
    )
    for actual, expected, label in supplied:
        if actual != expected:
            raise CredentialBrokerContractError(f"{label} substitution is forbidden")
    for item in prior_receipts:
        if not isinstance(item, CredentialUsageReceipt):
            raise CredentialBrokerContractError("prior_receipts contains an invalid record")
        if item.lease_sha256 != lease.lease_sha256:
            raise CredentialBrokerContractError("prior receipt lease mismatch")
    use_numbers = {item.use_number for item in prior_receipts}
    if len(use_numbers) != len(prior_receipts):
        raise CredentialBrokerContractError("usage receipt replay was detected")
    use_number = len(prior_receipts) + 1
    if use_number > lease.max_uses:
        raise CredentialBrokerContractError("lease use count is exhausted")
    return CredentialUsageReceipt(
        lease_sha256=lease.lease_sha256,
        tenant_ref=lease.tenant_ref,
        assessment_ref=lease.assessment_ref,
        task_ref=lease.task_ref,
        subject_principal_ref=lease.subject_principal_ref,
        target_ref=lease.target_ref,
        technique_ref=lease.technique_ref,
        purpose_ref=lease.purpose_ref,
        session_ref=lease.session_ref,
        use_number=use_number,
        outcome=outcome,
        used_at=_format_time(current),
        evidence_hashes=tuple(evidence_hashes),
    )
