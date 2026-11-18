"""Provider-neutral identity and cross-surface reasoning contracts.

This module reasons over caller-supplied, content-addressed records. It never
contacts a provider, uses a credential, changes a policy, or executes an
exploit. Runtime effects require separate systems and authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
SNAPSHOT_DOMAIN = "sunderkey.identity-cloud-reasoning.v1"
MAX_RECORDS = 512
MAX_CONDITIONS = 16
MAX_VALUES = 16
MAX_DEPTH = 16
MAX_PATHS = 64

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
ACTION_RE = re.compile(r"(?:\*|[a-z][a-z0-9._:/-]{0,127})\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

CONDITION_KEYS = frozenset(
    {
        "audience",
        "environment",
        "network_zone",
        "region",
        "resource_class",
        "session_assurance",
        "tenant_id",
        "workload_namespace",
    }
)

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_use": "none",
        "network": "none",
        "policy_mutation": "none",
        "provider_call": "none",
        "target_action": "none",
    }
)


class IdentityCloudReasoningError(ValueError):
    """Raised when an identity reasoning contract fails closed."""


class Surface(StrEnum):
    APPLICATION = "application"
    CONTAINER = "container"
    WORKLOAD = "workload"
    IDENTITY = "identity"
    CLOUD = "cloud"
    DATA = "data"


class PrincipalKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    MACHINE = "machine"
    FEDERATED = "federated"


class CredentialKind(StrEnum):
    REFERENCE = "reference"
    CERTIFICATE_REFERENCE = "certificate_reference"
    WORKLOAD_TOKEN_REFERENCE = "workload_token_reference"
    SESSION_REFERENCE = "session_reference"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ConditionOperator(StrEnum):
    EQUALS = "equals"
    IN = "in"
    PRESENT = "present"


class TransitionKind(StrEnum):
    ASSUME_ROLE = "assume_role"
    FEDERATE_SESSION = "federate_session"
    EXCHANGE_TOKEN = "exchange_token"
    BIND_WORKLOAD = "bind_workload"


class EvidenceState(StrEnum):
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


class ResolutionState(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"


class PathState(StrEnum):
    COMPLETE = "complete"
    BLOCKED = "blocked"
    INDETERMINATE = "indeterminate"


class ConflictKind(StrEnum):
    ALLOW_DENY = "allow_deny"
    GRAPH_CYCLE = "graph_cycle"
    UNKNOWN_EVIDENCE = "unknown_evidence"
    STALE_EVIDENCE = "stale_evidence"


class ReviewerRole(StrEnum):
    INDEPENDENT_IDENTITY = "independent_identity"
    INDEPENDENT_ASSURANCE = "independent_assurance"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as exc:
        raise IdentityCloudReasoningError("value cannot be canonicalized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise IdentityCloudReasoningError(f"{label} must be a safe identifier")
    if SECRET_RE.search(value):
        raise IdentityCloudReasoningError(f"{label} appears to contain secret material")
    return value


def _action(value: Any, label: str = "action") -> str:
    if not isinstance(value, str) or ACTION_RE.fullmatch(value) is None:
        raise IdentityCloudReasoningError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise IdentityCloudReasoningError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise IdentityCloudReasoningError(f"{label} must be a UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise IdentityCloudReasoningError(f"{label} is invalid") from exc


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise IdentityCloudReasoningError(f"{label} fields do not match the contract")
    return raw


def _bounded(values: Sequence[Any], label: str, *, allow_empty: bool = True) -> tuple[Any, ...]:
    result = tuple(values)
    if (not allow_empty and not result) or len(result) > MAX_RECORDS:
        raise IdentityCloudReasoningError(f"{label} exceeds its size budget")
    return result


def _same_context(tenant_id: str, context_id: str) -> None:
    _identifier(tenant_id, "tenant_id")
    _identifier(context_id, "context_id")


def _verify_address(
    raw: Mapping[str, Any], built: Any, id_name: str, sha_name: str, label: str
) -> None:
    if raw[id_name] != getattr(built, id_name) or raw[sha_name] != getattr(built, sha_name):
        raise IdentityCloudReasoningError(f"{label} content address is invalid")


@dataclass(frozen=True, order=True)
class Condition:
    key: str
    operator: ConditionOperator | str
    values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.key not in CONDITION_KEYS:
            raise IdentityCloudReasoningError("condition key is outside the bounded vocabulary")
        object.__setattr__(self, "operator", _enum(ConditionOperator, self.operator, "operator"))
        values = tuple(self.values)
        if len(values) > MAX_VALUES or len(set(values)) != len(values):
            raise IdentityCloudReasoningError("condition values exceed their budget or repeat")
        for value in values:
            _identifier(value, "condition value")
        if self.operator == ConditionOperator.PRESENT and values:
            raise IdentityCloudReasoningError("present conditions cannot carry values")
        if self.operator != ConditionOperator.PRESENT and not values:
            raise IdentityCloudReasoningError("value conditions require values")
        object.__setattr__(self, "values", tuple(sorted(values)))

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "operator": self.operator.value, "values": list(self.values)}

    @classmethod
    def from_dict(cls, raw: Any) -> Condition:
        value = _exact(raw, {"key", "operator", "values"}, "condition")
        return cls(value["key"], value["operator"], tuple(value["values"]))


def _conditions(values: Sequence[Condition]) -> tuple[Condition, ...]:
    result = tuple(values)
    if len(result) > MAX_CONDITIONS or len({item.key for item in result}) != len(result):
        raise IdentityCloudReasoningError("conditions exceed their budget or repeat keys")
    return tuple(sorted(result))


class _Addressed:
    ID_FIELD: ClassVar[str]
    SHA_FIELD: ClassVar[str]

    @classmethod
    def from_dict(cls, raw: Any) -> Any:
        value = _exact(raw, cls._fields(), cls.__name__)
        kwargs = cls._kwargs(value)
        built = cls(**kwargs)
        _verify_address(value, built, cls.ID_FIELD, cls.SHA_FIELD, cls.__name__)
        return built

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in raw.items() if key not in {cls.ID_FIELD, cls.SHA_FIELD}
        }

    @classmethod
    def _fields(cls) -> set[str]:
        raise NotImplementedError


@dataclass(frozen=True)
class EvidenceBinding(_Addressed):
    tenant_id: str
    context_id: str
    artifact_sha256: str
    observed_at: str
    expires_at: str
    state: EvidenceState | str = EvidenceState.VERIFIED
    evidence_id: str = field(init=False)
    evidence_sha256: str = field(init=False)

    ID_FIELD: ClassVar[str] = "evidence_id"
    SHA_FIELD: ClassVar[str] = "evidence_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _sha256(self.artifact_sha256, "artifact_sha256")
        observed = _timestamp(self.observed_at, "observed_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= observed:
            raise IdentityCloudReasoningError("expires_at must follow observed_at")
        object.__setattr__(self, "state", _enum(EvidenceState, self.state, "evidence state"))
        body = self._body()
        record_id, digest = _identity("IEB", "evidence", body)
        object.__setattr__(self, "evidence_id", record_id)
        object.__setattr__(self, "evidence_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "context_id": self.context_id,
            "expires_at": self.expires_at,
            "observed_at": self.observed_at,
            "state": self.state.value,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "artifact_sha256",
            "context_id",
            "evidence_id",
            "evidence_sha256",
            "expires_at",
            "observed_at",
            "state",
            "tenant_id",
        }


class _Entity(_Addressed):
    PREFIX: ClassVar[str]
    DOMAIN: ClassVar[str]

    def _finish(self, body: Mapping[str, Any]) -> None:
        record_id, digest = _identity(self.PREFIX, self.DOMAIN, body)
        object.__setattr__(self, self.ID_FIELD, record_id)
        object.__setattr__(self, self.SHA_FIELD, digest)


@dataclass(frozen=True)
class Principal(_Entity):
    tenant_id: str
    context_id: str
    principal_key: str
    principal_kind: PrincipalKind | str
    surface: Surface | str
    evidence_id: str
    principal_id: str = field(init=False)
    principal_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IPR"
    DOMAIN: ClassVar[str] = "principal"
    ID_FIELD: ClassVar[str] = "principal_id"
    SHA_FIELD: ClassVar[str] = "principal_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _identifier(self.principal_key, "principal_key")
        _identifier(self.evidence_id, "evidence_id")
        object.__setattr__(
            self, "principal_kind", _enum(PrincipalKind, self.principal_kind, "principal_kind")
        )
        object.__setattr__(self, "surface", _enum(Surface, self.surface, "surface"))
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "principal_key": self.principal_key,
            "principal_kind": self.principal_kind.value,
            "surface": self.surface.value,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "principal_id": self.principal_id,
            "principal_sha256": self.principal_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return set(cls("t", "c", "p", "human", "identity", "IEB-X").to_dict())


@dataclass(frozen=True)
class Group(_Entity):
    tenant_id: str
    context_id: str
    group_key: str
    member_ids: tuple[str, ...]
    evidence_id: str
    group_id: str = field(init=False)
    group_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IGR"
    DOMAIN: ClassVar[str] = "group"
    ID_FIELD: ClassVar[str] = "group_id"
    SHA_FIELD: ClassVar[str] = "group_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _identifier(self.group_key, "group_key")
        members = _bounded(self.member_ids, "member_ids", allow_empty=False)
        for value in members:
            _identifier(value, "member_id")
        if len(set(members)) != len(members):
            raise IdentityCloudReasoningError("member_ids repeat")
        object.__setattr__(self, "member_ids", tuple(sorted(members)))
        _identifier(self.evidence_id, "evidence_id")
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "group_key": self.group_key,
            "member_ids": list(self.member_ids),
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "group_id": self.group_id, "group_sha256": self.group_sha256}

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "context_id",
            "evidence_id",
            "group_id",
            "group_key",
            "group_sha256",
            "member_ids",
            "tenant_id",
        }

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        value = super()._kwargs(raw)
        value["member_ids"] = tuple(value["member_ids"])
        return value


@dataclass(frozen=True)
class Role(_Entity):
    tenant_id: str
    context_id: str
    role_key: str
    evidence_id: str
    role_id: str = field(init=False)
    role_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IRL"
    DOMAIN: ClassVar[str] = "role"
    ID_FIELD: ClassVar[str] = "role_id"
    SHA_FIELD: ClassVar[str] = "role_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _identifier(self.role_key, "role_key")
        _identifier(self.evidence_id, "evidence_id")
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "role_key": self.role_key,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "role_id": self.role_id, "role_sha256": self.role_sha256}

    @classmethod
    def _fields(cls) -> set[str]:
        return {"context_id", "evidence_id", "role_id", "role_key", "role_sha256", "tenant_id"}


@dataclass(frozen=True)
class Resource(_Entity):
    tenant_id: str
    context_id: str
    resource_key: str
    resource_type: str
    surface: Surface | str
    evidence_id: str
    parent_resource_id: str | None = None
    resource_id: str = field(init=False)
    resource_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IRS"
    DOMAIN: ClassVar[str] = "resource"
    ID_FIELD: ClassVar[str] = "resource_id"
    SHA_FIELD: ClassVar[str] = "resource_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _identifier(self.resource_key, "resource_key")
        _identifier(self.resource_type, "resource_type")
        _identifier(self.evidence_id, "evidence_id")
        if self.parent_resource_id is not None:
            _identifier(self.parent_resource_id, "parent_resource_id")
        surface = _enum(Surface, self.surface, "surface")
        if surface not in {Surface.CLOUD, Surface.DATA}:
            raise IdentityCloudReasoningError("resources must use cloud or data surface")
        object.__setattr__(self, "surface", surface)
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "parent_resource_id": self.parent_resource_id,
            "resource_key": self.resource_key,
            "resource_type": self.resource_type,
            "surface": self.surface.value,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "resource_id": self.resource_id,
            "resource_sha256": self.resource_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "context_id",
            "evidence_id",
            "parent_resource_id",
            "resource_id",
            "resource_key",
            "resource_sha256",
            "resource_type",
            "surface",
            "tenant_id",
        }


@dataclass(frozen=True)
class CredentialReference(_Entity):
    tenant_id: str
    context_id: str
    credential_key: str
    owner_id: str
    credential_kind: CredentialKind | str
    expires_at: str
    evidence_id: str
    credential_id: str = field(init=False)
    credential_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "ICR"
    DOMAIN: ClassVar[str] = "credential-reference"
    ID_FIELD: ClassVar[str] = "credential_id"
    SHA_FIELD: ClassVar[str] = "credential_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        for name in ("credential_key", "owner_id", "evidence_id"):
            _identifier(getattr(self, name), name)
        _timestamp(self.expires_at, "expires_at")
        object.__setattr__(
            self, "credential_kind", _enum(CredentialKind, self.credential_kind, "credential_kind")
        )
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "credential_key": self.credential_key,
            "credential_kind": self.credential_kind.value,
            "evidence_id": self.evidence_id,
            "expires_at": self.expires_at,
            "owner_id": self.owner_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "credential_id": self.credential_id,
            "credential_sha256": self.credential_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "context_id",
            "credential_id",
            "credential_key",
            "credential_kind",
            "credential_sha256",
            "evidence_id",
            "expires_at",
            "owner_id",
            "tenant_id",
        }


@dataclass(frozen=True)
class WorkloadIdentity(_Entity):
    tenant_id: str
    context_id: str
    workload_key: str
    surface: Surface | str
    principal_id: str
    evidence_id: str
    workload_identity_id: str = field(init=False)
    workload_identity_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IWI"
    DOMAIN: ClassVar[str] = "workload-identity"
    ID_FIELD: ClassVar[str] = "workload_identity_id"
    SHA_FIELD: ClassVar[str] = "workload_identity_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        for name in ("workload_key", "principal_id", "evidence_id"):
            _identifier(getattr(self, name), name)
        surface = _enum(Surface, self.surface, "surface")
        if surface not in {Surface.APPLICATION, Surface.CONTAINER, Surface.WORKLOAD}:
            raise IdentityCloudReasoningError("workload identity surface is invalid")
        object.__setattr__(self, "surface", surface)
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "principal_id": self.principal_id,
            "surface": self.surface.value,
            "tenant_id": self.tenant_id,
            "workload_key": self.workload_key,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "workload_identity_id": self.workload_identity_id,
            "workload_identity_sha256": self.workload_identity_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "context_id",
            "evidence_id",
            "principal_id",
            "surface",
            "tenant_id",
            "workload_identity_id",
            "workload_identity_sha256",
            "workload_key",
        }


@dataclass(frozen=True)
class TrustRelation(_Entity):
    tenant_id: str
    context_id: str
    source_id: str
    target_role_id: str
    conditions: tuple[Condition, ...]
    evidence_id: str
    trust_relation_id: str = field(init=False)
    trust_relation_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "ITR"
    DOMAIN: ClassVar[str] = "trust-relation"
    ID_FIELD: ClassVar[str] = "trust_relation_id"
    SHA_FIELD: ClassVar[str] = "trust_relation_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        for name in ("source_id", "target_role_id", "evidence_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(self, "conditions", _conditions(self.conditions))
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "conditions": [item.to_dict() for item in self.conditions],
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "target_role_id": self.target_role_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "trust_relation_id": self.trust_relation_id,
            "trust_relation_sha256": self.trust_relation_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "conditions",
            "context_id",
            "evidence_id",
            "source_id",
            "target_role_id",
            "tenant_id",
            "trust_relation_id",
            "trust_relation_sha256",
        }

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        value = super()._kwargs(raw)
        value["conditions"] = tuple(Condition.from_dict(item) for item in value["conditions"])
        return value


@dataclass(frozen=True)
class PermissionFact(_Entity):
    tenant_id: str
    context_id: str
    subject_id: str
    resource_id: str
    action: str
    effect: Effect | str
    conditions: tuple[Condition, ...]
    evidence_id: str
    permission_fact_id: str = field(init=False)
    permission_fact_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IPF"
    DOMAIN: ClassVar[str] = "permission-fact"
    ID_FIELD: ClassVar[str] = "permission_fact_id"
    SHA_FIELD: ClassVar[str] = "permission_fact_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        for name in ("subject_id", "resource_id", "evidence_id"):
            _identifier(getattr(self, name), name)
        _action(self.action)
        object.__setattr__(self, "effect", _enum(Effect, self.effect, "effect"))
        object.__setattr__(self, "conditions", _conditions(self.conditions))
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "conditions": [item.to_dict() for item in self.conditions],
            "context_id": self.context_id,
            "effect": self.effect.value,
            "evidence_id": self.evidence_id,
            "resource_id": self.resource_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "permission_fact_id": self.permission_fact_id,
            "permission_fact_sha256": self.permission_fact_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "action",
            "conditions",
            "context_id",
            "effect",
            "evidence_id",
            "permission_fact_id",
            "permission_fact_sha256",
            "resource_id",
            "subject_id",
            "tenant_id",
        }

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        value = super()._kwargs(raw)
        value["conditions"] = tuple(Condition.from_dict(item) for item in value["conditions"])
        return value


@dataclass(frozen=True)
class Policy(_Entity):
    tenant_id: str
    context_id: str
    policy_key: str
    attached_subject_ids: tuple[str, ...]
    permission_fact_ids: tuple[str, ...]
    evidence_id: str
    policy_id: str = field(init=False)
    policy_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IPO"
    DOMAIN: ClassVar[str] = "policy"
    ID_FIELD: ClassVar[str] = "policy_id"
    SHA_FIELD: ClassVar[str] = "policy_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _identifier(self.policy_key, "policy_key")
        for name in ("attached_subject_ids", "permission_fact_ids"):
            values = _bounded(getattr(self, name), name, allow_empty=False)
            if len(set(values)) != len(values):
                raise IdentityCloudReasoningError(f"{name} repeat")
            for value in values:
                _identifier(value, name)
            object.__setattr__(self, name, tuple(sorted(values)))
        _identifier(self.evidence_id, "evidence_id")
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "attached_subject_ids": list(self.attached_subject_ids),
            "context_id": self.context_id,
            "evidence_id": self.evidence_id,
            "permission_fact_ids": list(self.permission_fact_ids),
            "policy_key": self.policy_key,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "policy_id": self.policy_id, "policy_sha256": self.policy_sha256}

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "attached_subject_ids",
            "context_id",
            "evidence_id",
            "permission_fact_ids",
            "policy_id",
            "policy_key",
            "policy_sha256",
            "tenant_id",
        }

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        value = super()._kwargs(raw)
        value["attached_subject_ids"] = tuple(value["attached_subject_ids"])
        value["permission_fact_ids"] = tuple(value["permission_fact_ids"])
        return value


@dataclass(frozen=True)
class SessionTransition(_Entity):
    tenant_id: str
    context_id: str
    source_id: str
    target_id: str
    transition_kind: TransitionKind | str
    credential_id: str | None
    conditions: tuple[Condition, ...]
    evidence_id: str
    session_transition_id: str = field(init=False)
    session_transition_sha256: str = field(init=False)
    PREFIX: ClassVar[str] = "IST"
    DOMAIN: ClassVar[str] = "session-transition"
    ID_FIELD: ClassVar[str] = "session_transition_id"
    SHA_FIELD: ClassVar[str] = "session_transition_sha256"

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        for name in ("source_id", "target_id", "evidence_id"):
            _identifier(getattr(self, name), name)
        if self.credential_id is not None:
            _identifier(self.credential_id, "credential_id")
        object.__setattr__(
            self, "transition_kind", _enum(TransitionKind, self.transition_kind, "transition_kind")
        )
        object.__setattr__(self, "conditions", _conditions(self.conditions))
        self._finish(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "conditions": [item.to_dict() for item in self.conditions],
            "context_id": self.context_id,
            "credential_id": self.credential_id,
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "tenant_id": self.tenant_id,
            "transition_kind": self.transition_kind.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "session_transition_id": self.session_transition_id,
            "session_transition_sha256": self.session_transition_sha256,
        }

    @classmethod
    def _fields(cls) -> set[str]:
        return {
            "conditions",
            "context_id",
            "credential_id",
            "evidence_id",
            "session_transition_id",
            "session_transition_sha256",
            "source_id",
            "target_id",
            "tenant_id",
            "transition_kind",
        }

    @classmethod
    def _kwargs(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        value = super()._kwargs(raw)
        value["conditions"] = tuple(Condition.from_dict(item) for item in value["conditions"])
        return value


RECORD_COLLECTIONS: tuple[tuple[str, type[_Addressed]], ...] = (
    ("evidence_bindings", EvidenceBinding),
    ("principals", Principal),
    ("groups", Group),
    ("roles", Role),
    ("policies", Policy),
    ("resources", Resource),
    ("credentials", CredentialReference),
    ("workload_identities", WorkloadIdentity),
    ("trust_relations", TrustRelation),
    ("permission_facts", PermissionFact),
    ("session_transitions", SessionTransition),
)


@dataclass(frozen=True)
class IdentityCloudSnapshot:
    tenant_id: str
    context_id: str
    observed_at: str
    evidence_bindings: tuple[EvidenceBinding, ...]
    principals: tuple[Principal, ...]
    groups: tuple[Group, ...]
    roles: tuple[Role, ...]
    policies: tuple[Policy, ...]
    resources: tuple[Resource, ...]
    credentials: tuple[CredentialReference, ...]
    workload_identities: tuple[WorkloadIdentity, ...]
    trust_relations: tuple[TrustRelation, ...]
    permission_facts: tuple[PermissionFact, ...]
    session_transitions: tuple[SessionTransition, ...]
    snapshot_id: str = field(init=False)
    snapshot_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _same_context(self.tenant_id, self.context_id)
        _timestamp(self.observed_at, "observed_at")
        total = 0
        all_ids: set[str] = set()
        for name, _ in RECORD_COLLECTIONS:
            items = _bounded(getattr(self, name), name)
            total += len(items)
            for item in items:
                if item.tenant_id != self.tenant_id or item.context_id != self.context_id:
                    raise IdentityCloudReasoningError("tenant or context isolation violation")
                record_id = getattr(item, item.ID_FIELD)
                if record_id in all_ids:
                    raise IdentityCloudReasoningError("record identifiers must be unique")
                all_ids.add(record_id)
            object.__setattr__(
                self, name, tuple(sorted(items, key=lambda item: getattr(item, item.ID_FIELD)))
            )
        if total > MAX_RECORDS:
            raise IdentityCloudReasoningError("snapshot record budget exceeded")
        self._validate_references()
        body = self._body()
        record_id, digest = _identity("ICS", SNAPSHOT_DOMAIN, body)
        object.__setattr__(self, "snapshot_id", record_id)
        object.__setattr__(self, "snapshot_sha256", digest)

    def _validate_references(self) -> None:
        evidence_ids = {item.evidence_id for item in self.evidence_bindings}
        principal_ids = {item.principal_id for item in self.principals}
        role_ids = {item.role_id for item in self.roles}
        subjects = {
            *(item.principal_id for item in self.principals),
            *(item.group_id for item in self.groups),
            *(item.role_id for item in self.roles),
            *(item.workload_identity_id for item in self.workload_identities),
        }
        resources = {item.resource_id for item in self.resources}
        credentials = {item.credential_id for item in self.credentials}
        facts = {item.permission_fact_id for item in self.permission_facts}
        facts_by_id = {item.permission_fact_id: item for item in self.permission_facts}
        for name, _ in RECORD_COLLECTIONS[1:]:
            for item in getattr(self, name):
                if item.evidence_id not in evidence_ids:
                    raise IdentityCloudReasoningError("record references unknown evidence")
        for group in self.groups:
            if not set(group.member_ids) <= subjects:
                raise IdentityCloudReasoningError("group references unknown member")
        for workload in self.workload_identities:
            if workload.principal_id not in principal_ids:
                raise IdentityCloudReasoningError("workload references unknown principal")
        for credential in self.credentials:
            if credential.owner_id not in subjects:
                raise IdentityCloudReasoningError("credential references unknown owner")
        for relation in self.trust_relations:
            if relation.source_id not in subjects or relation.target_role_id not in role_ids:
                raise IdentityCloudReasoningError("trust relation references unknown subject")
        for fact in self.permission_facts:
            if fact.subject_id not in subjects or fact.resource_id not in resources:
                raise IdentityCloudReasoningError("permission fact references unknown record")
        for policy in self.policies:
            if (
                not set(policy.attached_subject_ids) <= subjects
                or not set(policy.permission_fact_ids) <= facts
            ):
                raise IdentityCloudReasoningError("policy references unknown records")
            if any(
                facts_by_id[fact_id].subject_id not in policy.attached_subject_ids
                for fact_id in policy.permission_fact_ids
            ):
                raise IdentityCloudReasoningError("policy fact subject is outside its attachments")
        for transition in self.session_transitions:
            if transition.source_id not in subjects or transition.target_id not in subjects:
                raise IdentityCloudReasoningError("session transition references unknown subject")
            if transition.credential_id is not None and transition.credential_id not in credentials:
                raise IdentityCloudReasoningError(
                    "session transition references unknown credential"
                )
            credential_required = transition.transition_kind in {
                TransitionKind.ASSUME_ROLE,
                TransitionKind.EXCHANGE_TOKEN,
                TransitionKind.FEDERATE_SESSION,
            }
            if credential_required != (transition.credential_id is not None):
                raise IdentityCloudReasoningError("session transition credential policy is invalid")
            if transition.credential_id is not None:
                credential = next(
                    item
                    for item in self.credentials
                    if item.credential_id == transition.credential_id
                )
                if credential.owner_id != transition.source_id:
                    raise IdentityCloudReasoningError(
                        "session transition credential owner is invalid"
                    )
        for resource in self.resources:
            if (
                resource.parent_resource_id is not None
                and resource.parent_resource_id not in resources
            ):
                raise IdentityCloudReasoningError("resource references unknown parent")

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            **{
                name: [item.to_dict() for item in getattr(self, name)]
                for name, _ in RECORD_COLLECTIONS
            },
            "effects": dict(NO_EFFECTS),
            "kind": SNAPSHOT_DOMAIN,
            "observed_at": self.observed_at,
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IdentityCloudSnapshot:
        fields = {
            "context_id",
            "effects",
            "kind",
            "observed_at",
            "schema_version",
            "snapshot_id",
            "snapshot_sha256",
            "tenant_id",
            *(name for name, _ in RECORD_COLLECTIONS),
        }
        value = _exact(raw, fields, "identity cloud snapshot")
        if value["kind"] != SNAPSHOT_DOMAIN or value["schema_version"] != SCHEMA_VERSION:
            raise IdentityCloudReasoningError("snapshot version is invalid")
        if dict(value["effects"]) != dict(NO_EFFECTS):
            raise IdentityCloudReasoningError("snapshot effects are invalid")
        kwargs = {
            name: tuple(record_type.from_dict(item) for item in value[name])
            for name, record_type in RECORD_COLLECTIONS
        }
        built = cls(value["tenant_id"], value["context_id"], value["observed_at"], **kwargs)
        _verify_address(value, built, "snapshot_id", "snapshot_sha256", "snapshot")
        return built


def _evaluate_conditions(
    conditions: Sequence[Condition], attributes: Mapping[str, str]
) -> bool | None:
    for condition in conditions:
        current = attributes.get(condition.key)
        if current is None:
            return None
        if condition.operator == ConditionOperator.PRESENT:
            continue
        if condition.operator == ConditionOperator.EQUALS and current != condition.values[0]:
            return False
        if condition.operator == ConditionOperator.IN and current not in condition.values:
            return False
    return True


def _evidence_quality(snapshot: IdentityCloudSnapshot, evidence_id: str, as_of: str) -> str:
    instant = _timestamp(as_of, "as_of")
    evidence = next(item for item in snapshot.evidence_bindings if item.evidence_id == evidence_id)
    if evidence.state != EvidenceState.VERIFIED:
        return "unknown"
    if _timestamp(evidence.observed_at, "observed_at") > instant:
        return "unknown"
    if _timestamp(evidence.expires_at, "expires_at") <= instant:
        return "stale"
    return "current"


@dataclass(frozen=True)
class PermissionResolution:
    subject_id: str
    resource_id: str
    action: str
    state: ResolutionState | str
    expanded_subject_ids: tuple[str, ...]
    allow_fact_ids: tuple[str, ...]
    deny_fact_ids: tuple[str, ...]
    unknown_fact_ids: tuple[str, ...]
    provenance_ids: tuple[str, ...]
    cycle_ids: tuple[str, ...]
    conflict: bool
    resolution_id: str = field(init=False)
    resolution_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("subject_id", "resource_id"):
            _identifier(getattr(self, name), name)
        _action(self.action)
        object.__setattr__(self, "state", _enum(ResolutionState, self.state, "resolution state"))
        for name in (
            "expanded_subject_ids",
            "allow_fact_ids",
            "deny_fact_ids",
            "unknown_fact_ids",
            "provenance_ids",
            "cycle_ids",
        ):
            values = tuple(sorted(set(getattr(self, name))))
            if len(values) > MAX_RECORDS:
                raise IdentityCloudReasoningError(f"{name} exceeds its budget")
            for value in values:
                _identifier(value, name)
            object.__setattr__(self, name, values)
        body = self._body()
        record_id, digest = _identity("IER", "permission-resolution", body)
        object.__setattr__(self, "resolution_id", record_id)
        object.__setattr__(self, "resolution_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "allow_fact_ids": list(self.allow_fact_ids),
            "conflict": self.conflict,
            "cycle_ids": list(self.cycle_ids),
            "deny_fact_ids": list(self.deny_fact_ids),
            "expanded_subject_ids": list(self.expanded_subject_ids),
            "provenance_ids": list(self.provenance_ids),
            "resource_id": self.resource_id,
            "state": self.state.value,
            "subject_id": self.subject_id,
            "unknown_fact_ids": list(self.unknown_fact_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "resolution_id": self.resolution_id,
            "resolution_sha256": self.resolution_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> PermissionResolution:
        fields = {
            "action",
            "allow_fact_ids",
            "conflict",
            "cycle_ids",
            "deny_fact_ids",
            "expanded_subject_ids",
            "provenance_ids",
            "resolution_id",
            "resolution_sha256",
            "resource_id",
            "state",
            "subject_id",
            "unknown_fact_ids",
        }
        value = _exact(raw, fields, "permission resolution")
        kwargs = {key: value[key] for key in fields - {"resolution_id", "resolution_sha256"}}
        for name in (
            "allow_fact_ids",
            "cycle_ids",
            "deny_fact_ids",
            "expanded_subject_ids",
            "provenance_ids",
            "unknown_fact_ids",
        ):
            kwargs[name] = tuple(kwargs[name])
        built = cls(**kwargs)
        _verify_address(value, built, "resolution_id", "resolution_sha256", "permission resolution")
        return built


def resolve_effective_permission(
    snapshot: IdentityCloudSnapshot,
    *,
    subject_id: str,
    resource_id: str,
    action: str,
    attributes: Mapping[str, str],
    as_of: str,
) -> PermissionResolution:
    """Resolve one effective permission with deny precedence and provenance."""

    _identifier(subject_id, "subject_id")
    _identifier(resource_id, "resource_id")
    _action(action)
    _timestamp(as_of, "as_of")
    if attributes.get("tenant_id") not in {None, snapshot.tenant_id}:
        raise IdentityCloudReasoningError("attribute tenant isolation violation")
    subject_records = {
        **{item.principal_id: item for item in snapshot.principals},
        **{item.group_id: item for item in snapshot.groups},
        **{item.role_id: item for item in snapshot.roles},
        **{item.workload_identity_id: item for item in snapshot.workload_identities},
    }
    resources = {item.resource_id: item for item in snapshot.resources}
    if subject_id not in subject_records or resource_id not in resources:
        raise IdentityCloudReasoningError("resolution references unknown subject or resource")

    subject_current = (
        _evidence_quality(snapshot, subject_records[subject_id].evidence_id, as_of) == "current"
    )
    resource_current = (
        _evidence_quality(snapshot, resources[resource_id].evidence_id, as_of) == "current"
    )
    expanded = {subject_id} if subject_current else set()
    provenance: set[str] = set()
    cycles: set[str] = set()
    unknown_relation_ids: set[str] = set()
    if not subject_current:
        unknown_relation_ids.add(subject_id)
    if not resource_current:
        unknown_relation_ids.add(resource_id)
    unknown_relation = bool(unknown_relation_ids)
    processed_relations: set[str] = set()
    workloads = {item.workload_identity_id: item for item in snapshot.workload_identities}
    if subject_id in workloads and subject_current:
        workload = workloads[subject_id]
        if (
            _evidence_quality(snapshot, subject_records[workload.principal_id].evidence_id, as_of)
            == "current"
        ):
            expanded.add(workload.principal_id)
            provenance.add(workload.workload_identity_id)
        else:
            unknown_relation = True
            unknown_relation_ids.add(workload.principal_id)
    changed = True
    rounds = 0
    while changed and rounds <= MAX_DEPTH:
        changed = False
        rounds += 1
        for group in snapshot.groups:
            if expanded.intersection(group.member_ids):
                if _evidence_quality(snapshot, group.evidence_id, as_of) != "current":
                    unknown_relation = True
                    unknown_relation_ids.add(group.group_id)
                    continue
                if group.group_id in expanded:
                    if group.group_id in group.member_ids:
                        cycles.add(group.group_id)
                else:
                    expanded.add(group.group_id)
                    provenance.add(group.group_id)
                    changed = True
        for relation in snapshot.trust_relations:
            if (
                relation.source_id not in expanded
                or relation.trust_relation_id in processed_relations
            ):
                continue
            processed_relations.add(relation.trust_relation_id)
            quality = _evidence_quality(snapshot, relation.evidence_id, as_of)
            condition = _evaluate_conditions(relation.conditions, attributes)
            if quality != "current" or condition is None:
                unknown_relation = True
                unknown_relation_ids.add(relation.trust_relation_id)
                continue
            if condition is False:
                continue
            if (
                _evidence_quality(
                    snapshot, subject_records[relation.target_role_id].evidence_id, as_of
                )
                != "current"
            ):
                unknown_relation = True
                unknown_relation_ids.add(relation.target_role_id)
                continue
            if relation.target_role_id in expanded:
                cycles.add(relation.trust_relation_id)
            else:
                expanded.add(relation.target_role_id)
                provenance.add(relation.trust_relation_id)
                changed = True
    if changed:
        cycles.add("depth_budget_exhausted")

    allow: set[str] = set()
    deny: set[str] = set()
    unknown: set[str] = set(unknown_relation_ids)
    policies_by_fact: dict[str, list[Policy]] = defaultdict(list)
    for policy in snapshot.policies:
        for fact_id in policy.permission_fact_ids:
            policies_by_fact[fact_id].append(policy)
    for fact in snapshot.permission_facts:
        if (
            fact.subject_id not in expanded
            or fact.resource_id != resource_id
            or fact.action not in {action, "*"}
        ):
            continue
        condition = _evaluate_conditions(fact.conditions, attributes)
        if condition is False:
            continue
        attached_policies = policies_by_fact.get(fact.permission_fact_id, ())
        if not attached_policies:
            continue
        current_policies = tuple(
            policy
            for policy in attached_policies
            if _evidence_quality(snapshot, policy.evidence_id, as_of) == "current"
        )
        if not current_policies:
            unknown.add(fact.permission_fact_id)
            unknown.update(policy.policy_id for policy in attached_policies)
            continue
        provenance.update(policy.policy_id for policy in current_policies)
        quality = _evidence_quality(snapshot, fact.evidence_id, as_of)
        if quality != "current" or condition is None:
            unknown.add(fact.permission_fact_id)
        elif condition:
            (deny if fact.effect == Effect.DENY else allow).add(fact.permission_fact_id)
    conflict = bool(allow and deny)
    if deny:
        state = ResolutionState.DENIED
    elif unknown or unknown_relation or cycles:
        state = ResolutionState.INDETERMINATE
    elif allow:
        state = ResolutionState.ALLOWED
    else:
        state = ResolutionState.NOT_APPLICABLE
    return PermissionResolution(
        subject_id,
        resource_id,
        action,
        state,
        tuple(expanded),
        tuple(allow),
        tuple(deny),
        tuple(unknown),
        tuple(provenance | allow | deny | unknown),
        tuple(cycles),
        conflict,
    )


@dataclass(frozen=True)
class CrossSurfacePath:
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    resolution_id: str
    path_id: str = field(init=False)
    path_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not 2 <= len(self.node_ids) <= MAX_DEPTH + 2
            or len(self.edge_ids) != len(self.node_ids) - 2
        ):
            raise IdentityCloudReasoningError("path shape or depth is invalid")
        for value in (*self.node_ids, *self.edge_ids, self.resolution_id):
            _identifier(value, "path reference")
        body = self._body()
        record_id, digest = _identity("ICP", "cross-surface-path", body)
        object.__setattr__(self, "path_id", record_id)
        object.__setattr__(self, "path_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "edge_ids": list(self.edge_ids),
            "node_ids": list(self.node_ids),
            "resolution_id": self.resolution_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "path_id": self.path_id, "path_sha256": self.path_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> CrossSurfacePath:
        fields = {"edge_ids", "node_ids", "path_id", "path_sha256", "resolution_id"}
        value = _exact(raw, fields, "cross surface path")
        built = cls(tuple(value["node_ids"]), tuple(value["edge_ids"]), value["resolution_id"])
        _verify_address(value, built, "path_id", "path_sha256", "cross surface path")
        return built


@dataclass(frozen=True)
class PathSearchResult:
    snapshot_sha256: str
    start_id: str
    target_resource_id: str
    action: str
    state: PathState | str
    paths: tuple[CrossSurfacePath, ...]
    indeterminate_edge_ids: tuple[str, ...]
    cycle_ids: tuple[str, ...]
    max_depth: int
    max_paths: int
    truncated: bool
    result_id: str = field(init=False)
    result_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        _identifier(self.start_id, "start_id")
        _identifier(self.target_resource_id, "target_resource_id")
        _action(self.action)
        object.__setattr__(self, "state", _enum(PathState, self.state, "path state"))
        if not 1 <= self.max_depth <= MAX_DEPTH or not 1 <= self.max_paths <= MAX_PATHS:
            raise IdentityCloudReasoningError("path search budget is invalid")
        paths = tuple(sorted(self.paths, key=lambda item: item.path_id))
        if len(paths) > self.max_paths:
            raise IdentityCloudReasoningError("path count exceeds its budget")
        object.__setattr__(self, "paths", paths)
        for name in ("indeterminate_edge_ids", "cycle_ids"):
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        if self.state == PathState.COMPLETE and (
            not paths or self.indeterminate_edge_ids or self.truncated
        ):
            raise IdentityCloudReasoningError("complete path result is inconsistent")
        if self.state == PathState.BLOCKED and (
            paths or self.indeterminate_edge_ids or self.truncated
        ):
            raise IdentityCloudReasoningError("blocked path result is inconsistent")
        if self.state == PathState.INDETERMINATE and not (
            paths or self.indeterminate_edge_ids or self.truncated or self.cycle_ids
        ):
            raise IdentityCloudReasoningError("indeterminate path result lacks a reason")
        body = self._body()
        record_id, digest = _identity("ISR", "path-search-result", body)
        object.__setattr__(self, "result_id", record_id)
        object.__setattr__(self, "result_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "cycle_ids": list(self.cycle_ids),
            "indeterminate_edge_ids": list(self.indeterminate_edge_ids),
            "max_depth": self.max_depth,
            "max_paths": self.max_paths,
            "paths": [item.to_dict() for item in self.paths],
            "snapshot_sha256": self.snapshot_sha256,
            "start_id": self.start_id,
            "state": self.state.value,
            "target_resource_id": self.target_resource_id,
            "truncated": self.truncated,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_id": self.result_id, "result_sha256": self.result_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> PathSearchResult:
        fields = {
            "action",
            "cycle_ids",
            "indeterminate_edge_ids",
            "max_depth",
            "max_paths",
            "paths",
            "result_id",
            "result_sha256",
            "snapshot_sha256",
            "start_id",
            "state",
            "target_resource_id",
            "truncated",
        }
        value = _exact(raw, fields, "path search result")
        built = cls(
            snapshot_sha256=value["snapshot_sha256"],
            start_id=value["start_id"],
            target_resource_id=value["target_resource_id"],
            action=value["action"],
            state=value["state"],
            paths=tuple(CrossSurfacePath.from_dict(item) for item in value["paths"]),
            indeterminate_edge_ids=tuple(value["indeterminate_edge_ids"]),
            cycle_ids=tuple(value["cycle_ids"]),
            max_depth=value["max_depth"],
            max_paths=value["max_paths"],
            truncated=value["truncated"],
        )
        _verify_address(value, built, "result_id", "result_sha256", "path search result")
        return built


def search_cross_surface_paths(
    snapshot: IdentityCloudSnapshot,
    *,
    start_id: str,
    target_resource_id: str,
    action: str,
    attributes: Mapping[str, str],
    as_of: str,
    max_depth: int = 8,
    max_paths: int = 32,
) -> PathSearchResult:
    """Search inert identity transitions from workload surfaces to a resource."""

    if not 1 <= max_depth <= MAX_DEPTH or not 1 <= max_paths <= MAX_PATHS:
        raise IdentityCloudReasoningError("path search budget is invalid")
    workload = next(
        (item for item in snapshot.workload_identities if item.workload_identity_id == start_id),
        None,
    )
    resource = next(
        (item for item in snapshot.resources if item.resource_id == target_resource_id), None
    )
    if workload is None or resource is None:
        raise IdentityCloudReasoningError("path endpoints are unknown")
    if resource.surface not in {Surface.CLOUD, Surface.DATA}:
        raise IdentityCloudReasoningError("target resource surface is invalid")
    edges: dict[str, list[tuple[str, str, tuple[Condition, ...], str, str | None]]] = defaultdict(
        list
    )
    edges[start_id].append(
        (
            workload.principal_id,
            workload.workload_identity_id,
            (),
            workload.evidence_id,
            None,
        )
    )
    for relation in snapshot.trust_relations:
        edges[relation.source_id].append(
            (
                relation.target_role_id,
                relation.trust_relation_id,
                relation.conditions,
                relation.evidence_id,
                None,
            )
        )
    for transition in snapshot.session_transitions:
        edges[transition.source_id].append(
            (
                transition.target_id,
                transition.session_transition_id,
                transition.conditions,
                transition.evidence_id,
                transition.credential_id,
            )
        )
    for values in edges.values():
        values.sort()

    queue = deque([(start_id, (start_id,), ())])
    paths: list[CrossSurfacePath] = []
    indeterminate: set[str] = set()
    cycles: set[str] = set()
    truncated = False
    while queue:
        node, nodes, edge_ids = queue.popleft()
        resolution = resolve_effective_permission(
            snapshot,
            subject_id=node,
            resource_id=target_resource_id,
            action=action,
            attributes=attributes,
            as_of=as_of,
        )
        direct_allow = any(
            fact.permission_fact_id in resolution.allow_fact_ids and fact.subject_id == node
            for fact in snapshot.permission_facts
        )
        if resolution.state == ResolutionState.ALLOWED and direct_allow:
            paths.append(
                CrossSurfacePath((*nodes, target_resource_id), edge_ids, resolution.resolution_id)
            )
            if len(paths) >= max_paths:
                truncated = bool(queue)
                break
        elif resolution.state == ResolutionState.INDETERMINATE:
            indeterminate.update(resolution.unknown_fact_ids)
            cycles.update(resolution.cycle_ids)
        if len(edge_ids) >= max_depth:
            if edges.get(node):
                truncated = True
            continue
        for target, edge_id, conditions, evidence_id, credential_id in edges.get(node, ()):
            if target in nodes:
                cycles.add(edge_id)
                continue
            quality = _evidence_quality(snapshot, evidence_id, as_of)
            condition = _evaluate_conditions(conditions, attributes)
            if credential_id is not None:
                credential = next(
                    item for item in snapshot.credentials if item.credential_id == credential_id
                )
                if (
                    _timestamp(credential.expires_at, "credential expires_at")
                    <= _timestamp(as_of, "as_of")
                    or _evidence_quality(snapshot, credential.evidence_id, as_of) != "current"
                ):
                    quality = "stale"
            if quality != "current" or condition is None:
                indeterminate.add(edge_id)
                continue
            if condition:
                queue.append((target, (*nodes, target), (*edge_ids, edge_id)))
    state = (
        PathState.COMPLETE
        if paths and not truncated and not indeterminate and not cycles
        else PathState.INDETERMINATE
        if paths or indeterminate or truncated or cycles
        else PathState.BLOCKED
    )
    return PathSearchResult(
        snapshot.snapshot_sha256,
        start_id,
        target_resource_id,
        action,
        state,
        tuple(paths),
        tuple(indeterminate),
        tuple(cycles),
        max_depth,
        max_paths,
        truncated,
    )


@dataclass(frozen=True)
class ReasoningConflict:
    conflict_kind: ConflictKind | str
    record_ids: tuple[str, ...]
    conflict_id: str = field(init=False)
    conflict_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "conflict_kind", _enum(ConflictKind, self.conflict_kind, "conflict kind")
        )
        records = tuple(sorted(set(self.record_ids)))
        if not records:
            raise IdentityCloudReasoningError("conflict requires records")
        for value in records:
            _identifier(value, "conflict record")
        object.__setattr__(self, "record_ids", records)
        body = {"conflict_kind": self.conflict_kind.value, "record_ids": list(records)}
        record_id, digest = _identity("ICF", "reasoning-conflict", body)
        object.__setattr__(self, "conflict_id", record_id)
        object.__setattr__(self, "conflict_sha256", digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "conflict_kind": self.conflict_kind.value,
            "conflict_sha256": self.conflict_sha256,
            "record_ids": list(self.record_ids),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ReasoningConflict:
        fields = {"conflict_id", "conflict_kind", "conflict_sha256", "record_ids"}
        value = _exact(raw, fields, "reasoning conflict")
        built = cls(value["conflict_kind"], tuple(value["record_ids"]))
        _verify_address(value, built, "conflict_id", "conflict_sha256", "reasoning conflict")
        return built


@dataclass(frozen=True)
class ConflictReport:
    snapshot_sha256: str
    conflicts: tuple[ReasoningConflict, ...]
    report_id: str = field(init=False)
    report_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        conflicts = tuple(sorted(self.conflicts, key=lambda item: item.conflict_id))
        object.__setattr__(self, "conflicts", conflicts)
        body = {
            "conflicts": [item.to_dict() for item in conflicts],
            "snapshot_sha256": self.snapshot_sha256,
        }
        record_id, digest = _identity("ICR", "conflict-report", body)
        object.__setattr__(self, "report_id", record_id)
        object.__setattr__(self, "report_sha256", digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflicts": [item.to_dict() for item in self.conflicts],
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ConflictReport:
        fields = {
            "conflicts",
            "report_id",
            "report_sha256",
            "snapshot_sha256",
        }
        value = _exact(raw, fields, "conflict report")
        built = cls(
            value["snapshot_sha256"],
            tuple(ReasoningConflict.from_dict(item) for item in value["conflicts"]),
        )
        _verify_address(value, built, "report_id", "report_sha256", "conflict report")
        return built


def detect_reasoning_conflicts(snapshot: IdentityCloudSnapshot, *, as_of: str) -> ConflictReport:
    """Detect contradictory facts, cycles, and untrusted evidence."""

    conflicts: list[ReasoningConflict] = []
    grouped: dict[tuple[str, str, str, str], dict[Effect, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for fact in snapshot.permission_facts:
        key = (
            fact.subject_id,
            fact.resource_id,
            fact.action,
            canonical_json([item.to_dict() for item in fact.conditions]),
        )
        grouped[key][fact.effect].append(fact.permission_fact_id)
    for effects in grouped.values():
        if effects[Effect.ALLOW] and effects[Effect.DENY]:
            conflicts.append(
                ReasoningConflict(
                    ConflictKind.ALLOW_DENY, tuple(effects[Effect.ALLOW] + effects[Effect.DENY])
                )
            )
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for relation in snapshot.trust_relations:
        adjacency[relation.source_id].append((relation.target_role_id, relation.trust_relation_id))
    for transition in snapshot.session_transitions:
        adjacency[transition.source_id].append(
            (transition.target_id, transition.session_transition_id)
        )
    visiting: set[str] = set()
    visited: set[str] = set()
    stack_edges: list[str] = []

    def visit(node: str) -> None:
        visiting.add(node)
        for target, edge_id in adjacency.get(node, ()):
            if target in visiting:
                conflicts.append(
                    ReasoningConflict(ConflictKind.GRAPH_CYCLE, tuple([*stack_edges, edge_id]))
                )
            elif target not in visited:
                stack_edges.append(edge_id)
                visit(target)
                stack_edges.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(adjacency):
        if node not in visited:
            visit(node)
    for evidence in snapshot.evidence_bindings:
        quality = _evidence_quality(snapshot, evidence.evidence_id, as_of)
        if quality == "unknown":
            conflicts.append(
                ReasoningConflict(ConflictKind.UNKNOWN_EVIDENCE, (evidence.evidence_id,))
            )
        elif quality == "stale":
            conflicts.append(
                ReasoningConflict(ConflictKind.STALE_EVIDENCE, (evidence.evidence_id,))
            )
    unique = {item.conflict_id: item for item in conflicts}
    return ConflictReport(snapshot.snapshot_sha256, tuple(unique.values()))


@dataclass(frozen=True)
class IndependentPathReview:
    reviewer_id: str
    reviewer_role: ReviewerRole | str
    path_set_sha256: str
    evidence_sha256: str
    reviewed_at: str
    evaluation_context_sha256: str
    decision: str = "accepted"
    review_id: str = field(init=False)
    review_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.reviewer_id, "reviewer_id")
        object.__setattr__(
            self, "reviewer_role", _enum(ReviewerRole, self.reviewer_role, "reviewer role")
        )
        for name in ("path_set_sha256", "evidence_sha256", "evaluation_context_sha256"):
            _sha256(getattr(self, name), name)
        _timestamp(self.reviewed_at, "reviewed_at")
        if self.decision != "accepted":
            raise IdentityCloudReasoningError("independent review must be accepted")
        body = self._body()
        record_id, digest = _identity("IPR", "independent-path-review", body)
        object.__setattr__(self, "review_id", record_id)
        object.__setattr__(self, "review_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "evidence_sha256": self.evidence_sha256,
            "evaluation_context_sha256": self.evaluation_context_sha256,
            "path_set_sha256": self.path_set_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "review_id": self.review_id, "review_sha256": self.review_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentPathReview:
        fields = {
            "decision",
            "evidence_sha256",
            "evaluation_context_sha256",
            "path_set_sha256",
            "review_id",
            "review_sha256",
            "reviewed_at",
            "reviewer_id",
            "reviewer_role",
        }
        value = _exact(raw, fields, "independent path review")
        kwargs = {
            key: item for key, item in value.items() if key not in {"review_id", "review_sha256"}
        }
        built = cls(**kwargs)
        _verify_address(value, built, "review_id", "review_sha256", "independent path review")
        return built


@dataclass(frozen=True)
class CompletePathValidationPlan:
    snapshot_sha256: str
    search_result_sha256: str
    path_ids: tuple[str, ...]
    reviews: tuple[IndependentPathReview, ...]
    maximum_validation_steps: int
    attributes_sha256: str
    evaluated_at: str
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        _sha256(self.search_result_sha256, "search_result_sha256")
        _sha256(self.attributes_sha256, "attributes_sha256")
        _timestamp(self.evaluated_at, "evaluated_at")
        paths = tuple(sorted(set(self.path_ids)))
        if not paths or len(paths) > MAX_PATHS:
            raise IdentityCloudReasoningError("validation plan path set is invalid")
        for value in paths:
            _identifier(value, "path_id")
        object.__setattr__(self, "path_ids", paths)
        if not 1 <= self.maximum_validation_steps <= MAX_PATHS * (MAX_DEPTH + 1):
            raise IdentityCloudReasoningError("validation step budget is invalid")
        reviews = tuple(sorted(self.reviews, key=lambda item: item.reviewer_role.value))
        if (
            len(reviews) != 2
            or len({item.reviewer_id for item in reviews}) != 2
            or {item.reviewer_role for item in reviews} != set(ReviewerRole)
        ):
            raise IdentityCloudReasoningError(
                "two distinct independent reviewer roles are required"
            )
        path_digest = canonical_sha256(list(paths))
        if any(item.path_set_sha256 != path_digest for item in reviews):
            raise IdentityCloudReasoningError("review path set binding is invalid")
        context_digest = canonical_sha256(
            {
                "attributes_sha256": self.attributes_sha256,
                "evaluated_at": self.evaluated_at,
                "search_result_sha256": self.search_result_sha256,
                "snapshot_sha256": self.snapshot_sha256,
            }
        )
        if any(item.evaluation_context_sha256 != context_digest for item in reviews):
            raise IdentityCloudReasoningError("review evaluation context binding is invalid")
        object.__setattr__(self, "reviews", reviews)
        body = self._body()
        record_id, digest = _identity("IVP", "complete-path-validation-plan", body)
        object.__setattr__(self, "plan_id", record_id)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "attributes_sha256": self.attributes_sha256,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "maximum_validation_steps": self.maximum_validation_steps,
            "path_ids": list(self.path_ids),
            "reviews": [item.to_dict() for item in self.reviews],
            "search_result_sha256": self.search_result_sha256,
            "snapshot_sha256": self.snapshot_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> CompletePathValidationPlan:
        fields = {
            "attributes_sha256",
            "effects",
            "evaluated_at",
            "maximum_validation_steps",
            "path_ids",
            "plan_id",
            "plan_sha256",
            "reviews",
            "search_result_sha256",
            "snapshot_sha256",
        }
        value = _exact(raw, fields, "complete path validation plan")
        if dict(value["effects"]) != dict(NO_EFFECTS):
            raise IdentityCloudReasoningError("validation plan effects are invalid")
        built = cls(
            snapshot_sha256=value["snapshot_sha256"],
            search_result_sha256=value["search_result_sha256"],
            path_ids=tuple(value["path_ids"]),
            reviews=tuple(IndependentPathReview.from_dict(item) for item in value["reviews"]),
            maximum_validation_steps=value["maximum_validation_steps"],
            attributes_sha256=value["attributes_sha256"],
            evaluated_at=value["evaluated_at"],
        )
        _verify_address(value, built, "plan_id", "plan_sha256", "validation plan")
        return built


def build_complete_path_validation_plan(
    snapshot: IdentityCloudSnapshot,
    result: PathSearchResult,
    *,
    reviews: Sequence[IndependentPathReview],
    attributes: Mapping[str, str],
    as_of: str,
) -> CompletePathValidationPlan:
    """Replay the graph before building an inert, context-bound reviewed plan."""

    if result.snapshot_sha256 != snapshot.snapshot_sha256:
        raise IdentityCloudReasoningError("search result snapshot binding is invalid")
    instant = _timestamp(as_of, "as_of")
    if instant < _timestamp(snapshot.observed_at, "snapshot observed_at"):
        raise IdentityCloudReasoningError("evaluation predates the snapshot")
    if not isinstance(attributes, Mapping):
        raise IdentityCloudReasoningError("path attributes must be a mapping")
    bounded_attributes: dict[str, str] = {}
    if len(attributes) > len(CONDITION_KEYS):
        raise IdentityCloudReasoningError("path attribute count exceeds its budget")
    for key, value in attributes.items():
        if (
            not isinstance(key, str)
            or key not in CONDITION_KEYS
            or not isinstance(value, str)
            or not 1 <= len(value) <= 256
        ):
            raise IdentityCloudReasoningError("path attribute is invalid")
        if SECRET_RE.search(value):
            raise IdentityCloudReasoningError("path attribute appears to contain secret material")
        bounded_attributes[key] = value
    replayed = search_cross_surface_paths(
        snapshot,
        start_id=result.start_id,
        target_resource_id=result.target_resource_id,
        action=result.action,
        attributes=bounded_attributes,
        as_of=as_of,
        max_depth=result.max_depth,
        max_paths=result.max_paths,
    )
    if replayed != result:
        raise IdentityCloudReasoningError("search result does not match snapshot replay")
    if result.state != PathState.COMPLETE or result.truncated or not result.paths:
        raise IdentityCloudReasoningError("only a complete untruncated path set can be validated")
    path_ids = tuple(item.path_id for item in result.paths)
    steps = sum(len(item.edge_ids) + 1 for item in result.paths)
    return CompletePathValidationPlan(
        snapshot.snapshot_sha256,
        result.result_sha256,
        path_ids,
        tuple(reviews),
        steps,
        canonical_sha256(bounded_attributes),
        as_of,
    )


def verify_complete_path_validation_plan(
    snapshot: IdentityCloudSnapshot,
    result: PathSearchResult,
    plan: CompletePathValidationPlan,
    *,
    attributes: Mapping[str, str],
    as_of: str,
) -> CompletePathValidationPlan:
    """Require source replay before any later use of a stored inert plan."""

    expected = build_complete_path_validation_plan(
        snapshot, result, reviews=plan.reviews, attributes=attributes, as_of=as_of
    )
    if expected != plan:
        raise IdentityCloudReasoningError("validation plan does not match source replay")
    return plan


def parse_snapshot(raw: Mapping[str, Any]) -> IdentityCloudSnapshot:
    return IdentityCloudSnapshot.from_dict(raw)


__all__ = [
    "CONDITION_KEYS",
    "MAX_CONDITIONS",
    "MAX_DEPTH",
    "MAX_PATHS",
    "MAX_RECORDS",
    "MAX_VALUES",
    "NO_EFFECTS",
    "CompletePathValidationPlan",
    "Condition",
    "ConditionOperator",
    "ConflictKind",
    "ConflictReport",
    "CredentialKind",
    "CredentialReference",
    "CrossSurfacePath",
    "Effect",
    "EvidenceBinding",
    "EvidenceState",
    "Group",
    "IdentityCloudReasoningError",
    "IdentityCloudSnapshot",
    "IndependentPathReview",
    "PathSearchResult",
    "PathState",
    "PermissionFact",
    "PermissionResolution",
    "Policy",
    "Principal",
    "PrincipalKind",
    "ReasoningConflict",
    "ResolutionState",
    "Resource",
    "ReviewerRole",
    "Role",
    "SessionTransition",
    "Surface",
    "TransitionKind",
    "TrustRelation",
    "WorkloadIdentity",
    "build_complete_path_validation_plan",
    "canonical_json",
    "canonical_sha256",
    "detect_reasoning_conflicts",
    "parse_snapshot",
    "resolve_effective_permission",
    "search_cross_surface_paths",
    "verify_complete_path_validation_plan",
]
