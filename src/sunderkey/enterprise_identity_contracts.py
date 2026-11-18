"""Offline enterprise identity, authorization, and provisioning contracts.

This module only validates and projects immutable values. It does not contact
an identity provider, validate an identity-provider signature, mutate a
directory, revoke a session, grant authority, or perform network activity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

SCHEMA_VERSION = 1
CONTRACT_KIND = "sunderkey.enterprise-identity-contract.v1"

MAX_ROLES = 256
MAX_ROLE_BINDINGS = 10_000
MAX_PERMISSIONS_PER_ROLE = 64
MAX_GROUP_MEMBERSHIPS = 1_000
MAX_PROVISIONING_COMMANDS = 10_000
MAX_SESSION_IDS = 1_000

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
RECORD_ID_RE = re.compile(r"EIC-[0-9A-F]{32}\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bbasic\s+[A-Za-z0-9+/=]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)

NO_EFFECTS = {
    "authority": "none",
    "credential_values": "none",
    "directory": "none",
    "execution": "none",
    "identity_provider": "none",
    "network": "none",
    "provisioning": "none",
    "qualification": "none",
    "routing": "none",
    "sessions": "none",
}


class EnterpriseIdentityError(ValueError):
    """Raised when an enterprise identity contract fails closed."""


class Permission(StrEnum):
    """Closed permission vocabulary."""

    MISSION_READ = "mission_read"
    MISSION_PROPOSE = "mission_propose"
    MISSION_APPROVE = "mission_approve"
    MISSION_EXECUTE = "mission_execute"
    CONTROL_REVIEW = "control_review"
    ASSURANCE_REVIEW = "assurance_review"
    EVIDENCE_CUSTODY = "evidence_custody"
    FINDINGS_REVIEW = "findings_review"
    IDENTITY_ADMIN = "identity_admin"
    SESSION_REVOKE = "session_revoke"


class BindingStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TOMBSTONED = "tombstoned"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ResourceKind(StrEnum):
    USER = "user"
    GROUP = "group"
    MEMBERSHIP = "membership"


class ProvisioningOperation(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DEACTIVATE = "deactivate"
    TOMBSTONE = "tombstone"
    ADD_MEMBER = "add_member"
    REMOVE_MEMBER = "remove_member"
    REVOKE_SESSIONS = "revoke_sessions"


DEPROVISIONING_OPERATIONS = frozenset(
    {
        ProvisioningOperation.DEACTIVATE,
        ProvisioningOperation.TOMBSTONE,
        ProvisioningOperation.REMOVE_MEMBER,
    }
)


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
        raise EnterpriseIdentityError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _record_identity(kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"domain": kind, "content": dict(body)})
    return f"EIC-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise EnterpriseIdentityError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        if len(value) > MAX_PROVISIONING_COMMANDS:
            raise EnterpriseIdentityError(f"{label} exceeds the item limit")
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise EnterpriseIdentityError(f"{label} exceeds the member limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise EnterpriseIdentityError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise EnterpriseIdentityError(f"{label} contains an unsupported value")


def _safe_text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EnterpriseIdentityError(f"{label} must be non-empty text")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise EnterpriseIdentityError(f"{label} contains unsafe text")
    if SECRET_RE.search(value):
        raise EnterpriseIdentityError(f"{label} contains secret-like material")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise EnterpriseIdentityError(f"{label} must be a safe identifier")
    return _safe_text(value, label, maximum=256)


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise EnterpriseIdentityError(f"{label} must be a token")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EnterpriseIdentityError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EnterpriseIdentityError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EnterpriseIdentityError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise EnterpriseIdentityError(f"{label} must be between 1 and {maximum}")
    return value


def _non_negative_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise EnterpriseIdentityError(f"{label} must be between 0 and {maximum}")
    return value


def _ordered_unique(
    values: Sequence[Any], label: str, validator: Any, *, maximum: int, allow_empty: bool = True
) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise EnterpriseIdentityError(f"{label} must be a sequence")
    if len(values) > maximum:
        raise EnterpriseIdentityError(f"{label} exceeds the item limit")
    normalized = tuple(validator(item, f"{label} item") for item in values)
    if not normalized and not allow_empty:
        raise EnterpriseIdentityError(f"{label} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise EnterpriseIdentityError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise EnterpriseIdentityError(f"{label} is invalid") from exc


def _record_body(record: Any) -> dict[str, Any]:
    return record._body()  # noqa: SLF001


@dataclass(frozen=True)
class DutyConstraint:
    """One symmetric separation-of-duty pair."""

    left: str
    right: str
    reason: str

    def __post_init__(self) -> None:
        left = _enum(self.left, Permission, "constraint left").value
        right = _enum(self.right, Permission, "constraint right").value
        if left == right:
            raise EnterpriseIdentityError("duty constraint permissions must differ")
        if right < left:
            left, right = right, left
        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)
        object.__setattr__(
            self, "reason", _safe_text(self.reason, "constraint reason", maximum=256)
        )

    def to_dict(self) -> dict[str, str]:
        return {"left": self.left, "reason": self.reason, "right": self.right}


REQUIRED_DUTY_CONSTRAINTS = (
    DutyConstraint(
        Permission.MISSION_APPROVE,
        Permission.MISSION_EXECUTE,
        "Mission approval must remain separate from mission execution.",
    ),
    DutyConstraint(
        Permission.CONTROL_REVIEW,
        Permission.ASSURANCE_REVIEW,
        "Control and Assurance review must remain independent.",
    ),
    DutyConstraint(
        Permission.EVIDENCE_CUSTODY,
        Permission.FINDINGS_REVIEW,
        "Evidence custody must remain separate from findings review.",
    ),
)


@dataclass(frozen=True)
class RoleDefinition:
    tenant_id: str
    role_id: str
    permissions: tuple[str, ...]
    description: str
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.enterprise-role.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "role tenant_id"))
        object.__setattr__(self, "role_id", _identifier(self.role_id, "role_id"))
        permissions = _ordered_unique(
            self.permissions,
            "role permissions",
            lambda item, label: _enum(item, Permission, label).value,
            maximum=MAX_PERMISSIONS_PER_ROLE,
            allow_empty=False,
        )
        object.__setattr__(self, "permissions", permissions)
        object.__setattr__(self, "description", _safe_text(self.description, "role description"))
        for constraint in REQUIRED_DUTY_CONSTRAINTS:
            if constraint.left in permissions and constraint.right in permissions:
                raise EnterpriseIdentityError("role violates a required duty constraint")
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "permissions": list(self.permissions),
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "role_id": self.role_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class RoleBinding:
    tenant_id: str
    subject_id: str
    role_ids: tuple[str, ...]
    status: str
    version: int
    valid_from: str
    valid_until: str
    group_ids: tuple[str, ...] = ()
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.enterprise-role-binding.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "binding tenant_id"))
        object.__setattr__(self, "subject_id", _identifier(self.subject_id, "binding subject_id"))
        object.__setattr__(
            self,
            "role_ids",
            _ordered_unique(
                self.role_ids,
                "binding role_ids",
                _identifier,
                maximum=MAX_ROLES,
                allow_empty=False,
            ),
        )
        object.__setattr__(
            self,
            "group_ids",
            _ordered_unique(
                self.group_ids,
                "binding group_ids",
                _identifier,
                maximum=MAX_GROUP_MEMBERSHIPS,
            ),
        )
        object.__setattr__(
            self, "status", _enum(self.status, BindingStatus, "binding status").value
        )
        _positive_int(self.version, "binding version", 2_147_483_647)
        object.__setattr__(self, "valid_from", _timestamp(self.valid_from, "binding valid_from"))
        object.__setattr__(self, "valid_until", _timestamp(self.valid_until, "binding valid_until"))
        if _instant(self.valid_until) <= _instant(self.valid_from):
            raise EnterpriseIdentityError("binding validity interval is empty")
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "group_ids": list(self.group_ids),
            "kind": self.KIND,
            "role_ids": list(self.role_ids),
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "version": self.version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class SsoTrustPolicy:
    tenant_id: str
    issuer: str
    audience: str
    accepted_assurance_contexts: tuple[str, ...]
    require_mfa: bool
    maximum_auth_age_seconds: int
    maximum_session_seconds: int
    clock_skew_seconds: int = 60
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.sso-trust-policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "SSO tenant_id"))
        object.__setattr__(self, "issuer", _identifier(self.issuer, "SSO issuer"))
        object.__setattr__(self, "audience", _identifier(self.audience, "SSO audience"))
        object.__setattr__(
            self,
            "accepted_assurance_contexts",
            _ordered_unique(
                self.accepted_assurance_contexts,
                "accepted assurance contexts",
                _identifier,
                maximum=32,
                allow_empty=False,
            ),
        )
        if not isinstance(self.require_mfa, bool):
            raise EnterpriseIdentityError("require_mfa must be boolean")
        _positive_int(self.maximum_auth_age_seconds, "maximum_auth_age_seconds", 86_400)
        _positive_int(self.maximum_session_seconds, "maximum_session_seconds", 604_800)
        _non_negative_int(self.clock_skew_seconds, "clock_skew_seconds", 300)
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "accepted_assurance_contexts": list(self.accepted_assurance_contexts),
            "audience": self.audience,
            "clock_skew_seconds": self.clock_skew_seconds,
            "effects": dict(NO_EFFECTS),
            "issuer": self.issuer,
            "kind": self.KIND,
            "maximum_auth_age_seconds": self.maximum_auth_age_seconds,
            "maximum_session_seconds": self.maximum_session_seconds,
            "require_mfa": self.require_mfa,
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class VerifiedSsoAssertion:
    """Claims already verified by a separate trusted verifier."""

    tenant_id: str
    issuer: str
    audience: str
    subject_id: str
    auth_time: str
    issued_at: str
    expires_at: str
    mfa_present: bool
    assurance_context: str
    session_id: str
    verification_evidence_sha256: str
    externally_verified: bool = True
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.verified-sso-assertion.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "issuer", "audience", "subject_id", "session_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"SSO {name}"))
        for name in ("auth_time", "issued_at", "expires_at"):
            object.__setattr__(self, name, _timestamp(getattr(self, name), f"SSO {name}"))
        if not isinstance(self.mfa_present, bool):
            raise EnterpriseIdentityError("mfa_present must be boolean")
        object.__setattr__(
            self,
            "assurance_context",
            _identifier(self.assurance_context, "SSO assurance_context"),
        )
        object.__setattr__(
            self,
            "verification_evidence_sha256",
            _digest(self.verification_evidence_sha256, "SSO verification evidence"),
        )
        if self.externally_verified is not True:
            raise EnterpriseIdentityError("SSO claims must already be externally verified")
        auth_time = _instant(self.auth_time)
        issued_at = _instant(self.issued_at)
        expires_at = _instant(self.expires_at)
        if auth_time > issued_at or issued_at >= expires_at:
            raise EnterpriseIdentityError("SSO claim time ordering is invalid")
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assurance_context": self.assurance_context,
            "audience": self.audience,
            "auth_time": self.auth_time,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "externally_verified": self.externally_verified,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "kind": self.KIND,
            "mfa_present": self.mfa_present,
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "verification_evidence_sha256": self.verification_evidence_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class AuthorizationRequest:
    tenant_id: str
    subject_id: str
    permission: str
    resource_tenant_id: str
    resource_id: str
    requested_at: str
    session_id: str
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.authorization-request.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "subject_id", "resource_tenant_id", "resource_id", "session_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"request {name}"))
        object.__setattr__(
            self, "permission", _enum(self.permission, Permission, "request permission").value
        )
        object.__setattr__(self, "requested_at", _timestamp(self.requested_at, "requested_at"))
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "permission": self.permission,
            "requested_at": self.requested_at,
            "resource_id": self.resource_id,
            "resource_tenant_id": self.resource_tenant_id,
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class IdentityDecision:
    decision_type: str
    tenant_id: str
    subject_id: str
    decision: str
    reason_codes: tuple[str, ...]
    source_record_sha256: str
    policy_sha256: str
    evaluated_at: str
    effective_permissions: tuple[str, ...] = ()
    session_revocation_required: bool = False
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.enterprise-identity-decision.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_type", _token(self.decision_type, "decision_type"))
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "decision tenant_id"))
        object.__setattr__(self, "subject_id", _identifier(self.subject_id, "decision subject_id"))
        object.__setattr__(self, "decision", _enum(self.decision, Decision, "decision").value)
        object.__setattr__(
            self,
            "reason_codes",
            _ordered_unique(
                self.reason_codes,
                "decision reason_codes",
                _token,
                maximum=32,
                allow_empty=False,
            ),
        )
        object.__setattr__(
            self,
            "source_record_sha256",
            _digest(self.source_record_sha256, "decision source_record_sha256"),
        )
        object.__setattr__(
            self, "policy_sha256", _digest(self.policy_sha256, "decision policy_sha256")
        )
        object.__setattr__(self, "evaluated_at", _timestamp(self.evaluated_at, "evaluated_at"))
        object.__setattr__(
            self,
            "effective_permissions",
            _ordered_unique(
                self.effective_permissions,
                "effective_permissions",
                lambda item, label: _enum(item, Permission, label).value,
                maximum=len(Permission),
            ),
        )
        if not isinstance(self.session_revocation_required, bool):
            raise EnterpriseIdentityError("session_revocation_required must be boolean")
        if self.decision == Decision.ALLOW and self.reason_codes != ("authorized",):
            raise EnterpriseIdentityError("allow decisions require only the authorized reason")
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "decision_type": self.decision_type,
            "effective_permissions": list(self.effective_permissions),
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": self.KIND,
            "policy_sha256": self.policy_sha256,
            "reason_codes": list(self.reason_codes),
            "schema_version": SCHEMA_VERSION,
            "session_revocation_required": self.session_revocation_required,
            "source_record_sha256": self.source_record_sha256,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class ProvisioningCommand:
    tenant_id: str
    actor_subject_id: str
    operation: str
    resource_kind: str
    resource_id: str
    external_id: str
    idempotency_key: str
    expected_version: int
    new_version: int
    issued_at: str
    precondition_sha256: str | None = None
    attribute_digests: tuple[str, ...] = ()
    member_subject_id: str | None = None
    session_ids: tuple[str, ...] = ()
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.scim-provisioning-command.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "actor_subject_id", "resource_id", "external_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"command {name}"))
        operation = _enum(self.operation, ProvisioningOperation, "command operation")
        kind = _enum(self.resource_kind, ResourceKind, "command resource_kind")
        object.__setattr__(self, "operation", operation.value)
        object.__setattr__(self, "resource_kind", kind.value)
        object.__setattr__(
            self, "idempotency_key", _identifier(self.idempotency_key, "command idempotency_key")
        )
        _non_negative_int(self.expected_version, "command expected_version", 2_147_483_646)
        _positive_int(self.new_version, "command new_version", 2_147_483_647)
        if self.new_version != self.expected_version + 1:
            raise EnterpriseIdentityError("command new_version must increment expected_version")
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "command issued_at"))
        if self.precondition_sha256 is not None:
            object.__setattr__(
                self,
                "precondition_sha256",
                _digest(self.precondition_sha256, "command precondition_sha256"),
            )
        object.__setattr__(
            self,
            "attribute_digests",
            _ordered_unique(
                self.attribute_digests,
                "command attribute_digests",
                _digest,
                maximum=64,
            ),
        )
        if self.member_subject_id is not None:
            object.__setattr__(
                self,
                "member_subject_id",
                _identifier(self.member_subject_id, "command member_subject_id"),
            )
        object.__setattr__(
            self,
            "session_ids",
            _ordered_unique(
                self.session_ids,
                "command session_ids",
                _identifier,
                maximum=MAX_SESSION_IDS,
            ),
        )
        self._validate_shape(operation, kind)
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _validate_shape(self, operation: ProvisioningOperation, kind: ResourceKind) -> None:
        if operation is ProvisioningOperation.CREATE:
            if self.expected_version != 0 or self.precondition_sha256 is not None:
                raise EnterpriseIdentityError("create requires version zero and no precondition")
        elif self.precondition_sha256 is None:
            raise EnterpriseIdentityError("non-create commands require a precondition")
        membership = operation in {
            ProvisioningOperation.ADD_MEMBER,
            ProvisioningOperation.REMOVE_MEMBER,
        }
        if membership != (kind is ResourceKind.MEMBERSHIP):
            raise EnterpriseIdentityError("membership operations require membership resources")
        if membership != (self.member_subject_id is not None):
            raise EnterpriseIdentityError("membership operations require a member subject")
        if operation is ProvisioningOperation.REVOKE_SESSIONS:
            if kind is not ResourceKind.USER or not self.session_ids:
                raise EnterpriseIdentityError("session revocation requires a user and session IDs")
        elif self.session_ids:
            raise EnterpriseIdentityError("only session revocation commands may carry session IDs")

    @property
    def deprovisioning(self) -> bool:
        return ProvisioningOperation(self.operation) in DEPROVISIONING_OPERATIONS

    @property
    def session_revocation_required(self) -> bool:
        return self.deprovisioning

    @property
    def tombstone_required(self) -> bool:
        return self.operation == ProvisioningOperation.TOMBSTONE

    def _body(self) -> dict[str, Any]:
        return {
            "actor_subject_id": self.actor_subject_id,
            "attribute_digests": list(self.attribute_digests),
            "deprovisioning": self.deprovisioning,
            "effects": dict(NO_EFFECTS),
            "expected_version": self.expected_version,
            "external_id": self.external_id,
            "idempotency_key": self.idempotency_key,
            "issued_at": self.issued_at,
            "kind": self.KIND,
            "member_subject_id": self.member_subject_id,
            "new_version": self.new_version,
            "operation": self.operation,
            "precondition_sha256": self.precondition_sha256,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind,
            "schema_version": SCHEMA_VERSION,
            "session_ids": list(self.session_ids),
            "session_revocation_required": self.session_revocation_required,
            "tenant_id": self.tenant_id,
            "tombstone_required": self.tombstone_required,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class EnterpriseIdentityPolicy:
    tenant_id: str
    roles: tuple[RoleDefinition, ...]
    sso_trust: SsoTrustPolicy
    duty_constraints: tuple[DutyConstraint, ...] = REQUIRED_DUTY_CONSTRAINTS
    default_decision: str = Decision.DENY
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.enterprise-identity-policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "policy tenant_id"))
        if not isinstance(self.roles, tuple) or not self.roles or len(self.roles) > MAX_ROLES:
            raise EnterpriseIdentityError("policy roles must be a bounded non-empty tuple")
        if not all(isinstance(role, RoleDefinition) for role in self.roles):
            raise EnterpriseIdentityError("policy role entries are invalid")
        if any(role.tenant_id != self.tenant_id for role in self.roles):
            raise EnterpriseIdentityError("policy roles cross a tenant boundary")
        if len({role.role_id for role in self.roles}) != len(self.roles):
            raise EnterpriseIdentityError("policy role IDs must be unique")
        object.__setattr__(self, "roles", tuple(sorted(self.roles, key=lambda item: item.role_id)))
        if (
            not isinstance(self.sso_trust, SsoTrustPolicy)
            or self.sso_trust.tenant_id != self.tenant_id
        ):
            raise EnterpriseIdentityError("policy SSO trust crosses a tenant boundary")
        if not isinstance(self.duty_constraints, tuple):
            raise EnterpriseIdentityError("policy duty_constraints must be a tuple")
        required = {(item.left, item.right) for item in REQUIRED_DUTY_CONSTRAINTS}
        actual = set()
        for item in self.duty_constraints:
            if not isinstance(item, DutyConstraint):
                raise EnterpriseIdentityError("policy duty constraint entry is invalid")
            actual.add((item.left, item.right))
        if not required.issubset(actual):
            raise EnterpriseIdentityError("policy omits a required duty constraint")
        if len(actual) != len(self.duty_constraints):
            raise EnterpriseIdentityError("policy duty constraints must be unique")
        object.__setattr__(
            self,
            "duty_constraints",
            tuple(sorted(self.duty_constraints, key=lambda item: (item.left, item.right))),
        )
        if _enum(self.default_decision, Decision, "default_decision") is not Decision.DENY:
            raise EnterpriseIdentityError("enterprise authorization must deny by default")
        object.__setattr__(self, "default_decision", Decision.DENY.value)
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "default_decision": self.default_decision,
            "duty_constraints": [item.to_dict() for item in self.duty_constraints],
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "roles": [item.to_dict() for item in self.roles],
            "schema_version": SCHEMA_VERSION,
            "sso_trust": self.sso_trust.to_dict(),
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class EnterpriseIdentityContract:
    policy: EnterpriseIdentityPolicy
    bindings: tuple[RoleBinding, ...]
    assertions: tuple[VerifiedSsoAssertion, ...]
    decisions: tuple[IdentityDecision, ...]
    provisioning_commands: tuple[ProvisioningCommand, ...]
    record_id: str = field(init=False)
    record_sha256: str = field(init=False)

    KIND: ClassVar[str] = CONTRACT_KIND

    def __post_init__(self) -> None:
        if not isinstance(self.policy, EnterpriseIdentityPolicy):
            raise EnterpriseIdentityError("contract policy is invalid")
        bounded = (
            (self.bindings, RoleBinding, MAX_ROLE_BINDINGS, "bindings"),
            (self.assertions, VerifiedSsoAssertion, MAX_ROLE_BINDINGS, "assertions"),
            (self.decisions, IdentityDecision, MAX_PROVISIONING_COMMANDS, "decisions"),
            (
                self.provisioning_commands,
                ProvisioningCommand,
                MAX_PROVISIONING_COMMANDS,
                "provisioning_commands",
            ),
        )
        for values, expected, maximum, label in bounded:
            if not isinstance(values, tuple) or len(values) > maximum:
                raise EnterpriseIdentityError(f"contract {label} is not a bounded tuple")
            if not all(isinstance(item, expected) for item in values):
                raise EnterpriseIdentityError(f"contract {label} contains an invalid entry")
            if any(item.tenant_id != self.policy.tenant_id for item in values):
                raise EnterpriseIdentityError(f"contract {label} crosses a tenant boundary")
        for binding in self.bindings:
            effective_permissions(self.policy, binding)
        if len({item.idempotency_key for item in self.provisioning_commands}) != len(
            self.provisioning_commands
        ):
            raise EnterpriseIdentityError("contract provisioning idempotency keys must be unique")
        for name in ("bindings", "assertions", "decisions", "provisioning_commands"):
            object.__setattr__(
                self, name, tuple(sorted(getattr(self, name), key=lambda item: item.record_id))
            )
        record_id, digest = _record_identity(self.KIND, self._body())
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "record_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assertions": [item.to_dict() for item in self.assertions],
            "bindings": [item.to_dict() for item in self.bindings],
            "decisions": [item.to_dict() for item in self.decisions],
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "policy": self.policy.to_dict(),
            "provisioning_commands": [item.to_dict() for item in self.provisioning_commands],
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.policy.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "record_id": self.record_id, "record_sha256": self.record_sha256}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def effective_permissions(
    policy: EnterpriseIdentityPolicy, binding: RoleBinding
) -> tuple[str, ...]:
    """Resolve a binding and reject unknown roles or combined duty conflicts."""

    if binding.tenant_id != policy.tenant_id:
        raise EnterpriseIdentityError("binding crosses a tenant boundary")
    roles = {role.role_id: role for role in policy.roles}
    unknown = set(binding.role_ids).difference(roles)
    if unknown:
        raise EnterpriseIdentityError("binding references an unknown role")
    permissions = tuple(
        sorted(
            {
                permission
                for role_id in binding.role_ids
                for permission in roles[role_id].permissions
            }
        )
    )
    for constraint in policy.duty_constraints:
        if constraint.left in permissions and constraint.right in permissions:
            raise EnterpriseIdentityError("combined roles violate a duty constraint")
    return permissions


def admit_sso_assertion(
    policy: EnterpriseIdentityPolicy,
    assertion: VerifiedSsoAssertion,
    *,
    evaluated_at: str,
) -> IdentityDecision:
    """Evaluate already-verified SSO claims without parsing or verifying tokens."""

    evaluated_at = _timestamp(evaluated_at, "evaluated_at")
    reasons: list[str] = []
    trust = policy.sso_trust
    now = _instant(evaluated_at)
    if assertion.tenant_id != policy.tenant_id:
        reasons.append("tenant_mismatch")
    if assertion.issuer != trust.issuer:
        reasons.append("issuer_mismatch")
    if assertion.audience != trust.audience:
        reasons.append("audience_mismatch")
    if assertion.assurance_context not in trust.accepted_assurance_contexts:
        reasons.append("assurance_rejected")
    if trust.require_mfa and not assertion.mfa_present:
        reasons.append("mfa_required")
    if now < _instant(assertion.issued_at) - _seconds(trust.clock_skew_seconds):
        reasons.append("not_yet_valid")
    if now >= _instant(assertion.expires_at) + _seconds(trust.clock_skew_seconds):
        reasons.append("expired")
    if now - _instant(assertion.auth_time) > _seconds(trust.maximum_auth_age_seconds):
        reasons.append("authentication_too_old")
    if _instant(assertion.expires_at) - _instant(assertion.issued_at) > _seconds(
        trust.maximum_session_seconds
    ):
        reasons.append("session_too_long")
    return IdentityDecision(
        decision_type="sso_admission",
        tenant_id=policy.tenant_id,
        subject_id=assertion.subject_id,
        decision=Decision.DENY if reasons else Decision.ALLOW,
        reason_codes=tuple(reasons or ["authorized"]),
        source_record_sha256=assertion.record_sha256,
        policy_sha256=policy.record_sha256,
        evaluated_at=evaluated_at,
    )


def authorize(
    policy: EnterpriseIdentityPolicy,
    bindings: Sequence[RoleBinding],
    request: AuthorizationRequest,
) -> IdentityDecision:
    """Apply tenant isolation and deny-by-default RBAC authorization."""

    reasons: list[str] = []
    if request.tenant_id != policy.tenant_id or request.resource_tenant_id != policy.tenant_id:
        reasons.append("tenant_mismatch")
    candidates = [
        binding
        for binding in bindings
        if binding.tenant_id == policy.tenant_id and binding.subject_id == request.subject_id
    ]
    if len(candidates) != 1:
        reasons.append("binding_not_unique")
        permissions: tuple[str, ...] = ()
    else:
        binding = candidates[0]
        permissions = effective_permissions(policy, binding)
        requested_at = _instant(request.requested_at)
        if binding.status != BindingStatus.ACTIVE:
            reasons.append("binding_inactive")
        if not (_instant(binding.valid_from) <= requested_at < _instant(binding.valid_until)):
            reasons.append("binding_outside_validity")
        if request.permission not in permissions:
            reasons.append("permission_missing")
    return IdentityDecision(
        decision_type="authorization",
        tenant_id=policy.tenant_id,
        subject_id=request.subject_id,
        decision=Decision.DENY if reasons else Decision.ALLOW,
        reason_codes=tuple(reasons or ["authorized"]),
        source_record_sha256=request.record_sha256,
        policy_sha256=policy.record_sha256,
        evaluated_at=request.requested_at,
        effective_permissions=permissions,
    )


def validate_provisioning_command(
    policy: EnterpriseIdentityPolicy,
    command: ProvisioningCommand,
    *,
    actor_binding: RoleBinding | None,
    current_version: int | None,
    current_sha256: str | None,
    seen_idempotency: Mapping[str, str],
    evaluated_at: str,
) -> IdentityDecision:
    """Validate an offline SCIM-style command and declare follow-up obligations."""

    evaluated_at = _timestamp(evaluated_at, "evaluated_at")
    reasons: list[str] = []
    if command.tenant_id != policy.tenant_id:
        reasons.append("tenant_mismatch")
    previous = seen_idempotency.get(command.idempotency_key)
    if previous is not None and previous != command.record_sha256:
        reasons.append("idempotency_conflict")
    if previous == command.record_sha256:
        reasons.append("duplicate_command")
    if actor_binding is None or actor_binding.subject_id != command.actor_subject_id:
        reasons.append("actor_binding_missing")
    else:
        try:
            permissions = effective_permissions(policy, actor_binding)
        except EnterpriseIdentityError:
            permissions = ()
            reasons.append("actor_binding_invalid")
        if actor_binding.status != BindingStatus.ACTIVE:
            reasons.append("actor_binding_inactive")
        if not (
            _instant(actor_binding.valid_from)
            <= _instant(evaluated_at)
            < _instant(actor_binding.valid_until)
        ):
            reasons.append("actor_binding_outside_validity")
        if Permission.IDENTITY_ADMIN not in permissions:
            reasons.append("identity_admin_required")
    if current_version is None:
        if command.operation != ProvisioningOperation.CREATE:
            reasons.append("resource_missing")
    elif command.operation == ProvisioningOperation.CREATE:
        reasons.append("resource_exists")
    else:
        if command.expected_version != current_version:
            reasons.append("version_mismatch")
        if current_sha256 is None or command.precondition_sha256 != current_sha256:
            reasons.append("precondition_failed")
    return IdentityDecision(
        decision_type="provisioning",
        tenant_id=policy.tenant_id,
        subject_id=command.actor_subject_id,
        decision=Decision.DENY if reasons else Decision.ALLOW,
        reason_codes=tuple(reasons or ["authorized"]),
        source_record_sha256=command.record_sha256,
        policy_sha256=policy.record_sha256,
        evaluated_at=evaluated_at,
        session_revocation_required=command.session_revocation_required,
    )


def _seconds(value: int):
    from datetime import timedelta

    return timedelta(seconds=value)


__all__ = [
    "CONTRACT_KIND",
    "DEPROVISIONING_OPERATIONS",
    "NO_EFFECTS",
    "REQUIRED_DUTY_CONSTRAINTS",
    "AuthorizationRequest",
    "BindingStatus",
    "Decision",
    "DutyConstraint",
    "EnterpriseIdentityContract",
    "EnterpriseIdentityError",
    "EnterpriseIdentityPolicy",
    "IdentityDecision",
    "Permission",
    "ProvisioningCommand",
    "ProvisioningOperation",
    "ResourceKind",
    "RoleBinding",
    "RoleDefinition",
    "SsoTrustPolicy",
    "VerifiedSsoAssertion",
    "admit_sso_assertion",
    "authorize",
    "canonical_json",
    "canonical_sha256",
    "effective_permissions",
    "validate_provisioning_command",
]
