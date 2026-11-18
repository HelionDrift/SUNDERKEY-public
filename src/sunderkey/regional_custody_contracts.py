"""Tenant isolation, regional custody, and retention policy contracts.

These immutable records have no persistence, network, transfer, deletion, key
access, authorization, or qualification effects.
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
        "authorization": "none",
        "deletion": "none",
        "encryption_key_access": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "storage": "none",
        "transfer": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REGION_RE = re.compile(r"[a-z][a-z0-9-]{1,62}\Z")
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|artifactref|evidenceref|scoperef|policyref|keyref|approvalref|"
    r"principalref|roleref|legalbasisref|scheduleref|holdref|authorityref|"
    r"operationref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@)",
    re.IGNORECASE,
)
REQUIRED_TRANSFER_ROLES = frozenset(
    {"roleref:independent-assurance", "roleref:independent-control"}
)


class RegionalCustodyContractError(ValueError):
    """Raised when a custody contract fails closed."""


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class TransferPurpose(StrEnum):
    STORAGE = "storage"
    PROCESSING = "processing"


class HoldKind(StrEnum):
    LITIGATION = "litigation"
    INCIDENT = "incident"
    REGULATORY = "regulatory"


class HoldStatus(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"


class OperationKind(StrEnum):
    STORE = "store"
    PROCESS = "process"
    TRANSFER = "transfer"
    DELETE = "delete"


class AdmissionStatus(StrEnum):
    DENIED = "denied"
    ELIGIBLE_FOR_EXTERNAL_AUTHORIZATION = "eligible_for_external_authorization"


class DeletionStatus(StrEnum):
    INELIGIBLE = "ineligible"
    ELIGIBLE_FOR_EXTERNAL_EXECUTION = "eligible_for_external_execution"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret screening."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if SECRET_RE.search(encoded):
        raise RegionalCustodyContractError("raw key or secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 12:
        raise RegionalCustodyContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 10_000:
            raise RegionalCustodyContractError(f"{label} exceeds the item limit")
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RegionalCustodyContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise RegionalCustodyContractError(f"{label} contains an unsupported value")


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise RegionalCustodyContractError(f"{label} fields are invalid")


def _ref(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
        or SECRET_RE.search(value)
    ):
        raise RegionalCustodyContractError(f"{label} must be a safe {namespace} reference")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RegionalCustodyContractError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise RegionalCustodyContractError(f"{label} must be an exact numeric version")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise RegionalCustodyContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RegionalCustodyContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _region(value: Any, label: str) -> str:
    if not isinstance(value, str) or REGION_RE.fullmatch(value) is None:
        raise RegionalCustodyContractError(f"{label} must be a canonical region code")
    return value


def _regions(values: Sequence[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise RegionalCustodyContractError(f"{label} must be a non-empty sequence")
    result = tuple(sorted(_region(item, f"{label} item") for item in values))
    if len(result) != len(set(result)):
        raise RegionalCustodyContractError(f"{label} must contain unique values")
    return result


def _codes(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RegionalCustodyContractError("blocker_codes must be a sequence")
    result = tuple(sorted(values))
    if any(not isinstance(item, str) or CODE_RE.fullmatch(item) is None for item in result):
        raise RegionalCustodyContractError("blocker_codes contain an invalid value")
    if len(result) != len(set(result)):
        raise RegionalCustodyContractError("blocker_codes must be unique")
    return result


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise RegionalCustodyContractError(f"{label} is invalid") from exc


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if raw.get("kind") != kind or raw.get("schema_version") != SCHEMA_VERSION:
        raise RegionalCustodyContractError("contract metadata is invalid")
    if raw.get("effects") != dict(NO_EFFECTS):
        raise RegionalCustodyContractError("contract attempts effect escalation")


def _addressed(instance: Any, id_name: str, hash_name: str) -> dict[str, Any]:
    return {
        **instance._body(),  # noqa: SLF001
        id_name: getattr(instance, id_name),
        hash_name: getattr(instance, hash_name),
    }


def _verify(raw: Mapping[str, Any], candidate: Any) -> Any:
    if dict(raw) != candidate.to_dict():
        raise RegionalCustodyContractError("record identity or contents are invalid")
    return candidate


def _load(raw: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RegionalCustodyContractError("contract JSON is invalid") from exc
    if not isinstance(value, Mapping) or canonical_json(value) != raw:
        raise RegionalCustodyContractError("contract JSON must be canonical")
    return value


class _JsonRecord:
    def to_json(self) -> str:
        return canonical_json(self.to_dict())  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class TenantRegionBinding(_JsonRecord):
    tenant_ref: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    home_region: str
    allowed_storage_regions: tuple[str, ...]
    allowed_processing_regions: tuple[str, ...]
    encryption_key_ref: str
    effective_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.tenant-region-binding.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_ref", _ref(self.tenant_ref, "tenant_ref", "tenantref"))
        object.__setattr__(self, "policy_ref", _ref(self.policy_ref, "policy_ref", "policyref"))
        object.__setattr__(self, "policy_sha256", _digest(self.policy_sha256, "policy_sha256"))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(self, "home_region", _region(self.home_region, "home_region"))
        object.__setattr__(
            self,
            "allowed_storage_regions",
            _regions(self.allowed_storage_regions, "storage regions"),
        )
        object.__setattr__(
            self,
            "allowed_processing_regions",
            _regions(self.allowed_processing_regions, "processing regions"),
        )
        if self.home_region not in self.allowed_storage_regions:
            raise RegionalCustodyContractError("home_region must be an allowed storage region")
        object.__setattr__(
            self,
            "encryption_key_ref",
            _ref(self.encryption_key_ref, "encryption_key_ref", "keyref"),
        )
        object.__setattr__(self, "effective_at", _time(self.effective_at, "effective_at"))
        identifier, digest = _identity("TRB", self.KIND, self._body())
        object.__setattr__(self, "binding_id", identifier)
        object.__setattr__(self, "binding_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "allowed_processing_regions": list(self.allowed_processing_regions),
            "allowed_storage_regions": list(self.allowed_storage_regions),
            "effects": dict(NO_EFFECTS),
            "effective_at": self.effective_at,
            "encryption_key_ref": self.encryption_key_ref,
            "home_region": self.home_region,
            "kind": self.KIND,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "schema_version": SCHEMA_VERSION,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "binding_id", "binding_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TenantRegionBinding:
        fields = {
            "allowed_processing_regions",
            "allowed_storage_regions",
            "binding_id",
            "binding_sha256",
            "effects",
            "effective_at",
            "encryption_key_ref",
            "home_region",
            "kind",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "schema_version",
            "tenant_ref",
        }
        _exact(raw, fields, "tenant region binding")
        _metadata(raw, cls.KIND)
        return _verify(
            raw,
            cls(
                tenant_ref=raw["tenant_ref"],
                policy_ref=raw["policy_ref"],
                policy_sha256=raw["policy_sha256"],
                policy_version=raw["policy_version"],
                home_region=raw["home_region"],
                allowed_storage_regions=tuple(raw["allowed_storage_regions"]),
                allowed_processing_regions=tuple(raw["allowed_processing_regions"]),
                encryption_key_ref=raw["encryption_key_ref"],
                effective_at=raw["effective_at"],
            ),
        )

    @classmethod
    def from_json(cls, raw: str) -> TenantRegionBinding:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class ArtifactCustodyDescriptor(_JsonRecord):
    tenant_ref: str
    artifact_ref: str
    artifact_sha256: str
    evidence_ref: str
    evidence_sha256: str
    scope_ref: str
    scope_sha256: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    retention_schedule_ref: str
    retention_schedule_version: str
    classification: Classification
    storage_region: str
    processing_region: str
    encryption_key_ref: str
    captured_at: str
    descriptor_id: str = field(init=False)
    descriptor_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.artifact-custody-descriptor.v1"

    def __post_init__(self) -> None:
        namespaces = {
            "tenant_ref": "tenantref",
            "artifact_ref": "artifactref",
            "evidence_ref": "evidenceref",
            "scope_ref": "scoperef",
            "policy_ref": "policyref",
            "retention_schedule_ref": "scheduleref",
            "encryption_key_ref": "keyref",
        }
        for name, namespace in namespaces.items():
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        for name in ("artifact_sha256", "evidence_sha256", "scope_sha256", "policy_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(
            self,
            "retention_schedule_version",
            _version(self.retention_schedule_version, "retention_schedule_version"),
        )
        object.__setattr__(
            self, "classification", _enum(self.classification, Classification, "classification")
        )
        object.__setattr__(self, "storage_region", _region(self.storage_region, "storage_region"))
        object.__setattr__(
            self, "processing_region", _region(self.processing_region, "processing_region")
        )
        object.__setattr__(self, "captured_at", _time(self.captured_at, "captured_at"))
        identifier, digest = _identity("ACD", self.KIND, self._body())
        object.__setattr__(self, "descriptor_id", identifier)
        object.__setattr__(self, "descriptor_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "captured_at": self.captured_at,
            "classification": self.classification.value,
            "effects": dict(NO_EFFECTS),
            "encryption_key_ref": self.encryption_key_ref,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "kind": self.KIND,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "processing_region": self.processing_region,
            "retention_schedule_ref": self.retention_schedule_ref,
            "retention_schedule_version": self.retention_schedule_version,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "storage_region": self.storage_region,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "descriptor_id", "descriptor_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactCustodyDescriptor:
        ignored = {"descriptor_id", "descriptor_sha256", "effects", "kind", "schema_version"}
        fields = {
            "artifact_ref",
            "artifact_sha256",
            "captured_at",
            "classification",
            "descriptor_id",
            "descriptor_sha256",
            "effects",
            "encryption_key_ref",
            "evidence_ref",
            "evidence_sha256",
            "kind",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "processing_region",
            "retention_schedule_ref",
            "retention_schedule_version",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "storage_region",
            "tenant_ref",
        }
        _exact(raw, fields, "artifact custody descriptor")
        _metadata(raw, cls.KIND)
        return _verify(raw, cls(**{key: raw[key] for key in fields - ignored}))

    @classmethod
    def from_json(cls, raw: str) -> ArtifactCustodyDescriptor:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class TransferApproval:
    approval_ref: str
    principal_ref: str
    role_ref: str
    approved_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "approval_ref", _ref(self.approval_ref, "approval_ref", "approvalref")
        )
        object.__setattr__(
            self, "principal_ref", _ref(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(self, "role_ref", _ref(self.role_ref, "role_ref", "roleref"))
        object.__setattr__(self, "approved_at", _time(self.approved_at, "approved_at"))

    def to_dict(self) -> dict[str, str]:
        return {
            "approval_ref": self.approval_ref,
            "approved_at": self.approved_at,
            "principal_ref": self.principal_ref,
            "role_ref": self.role_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TransferApproval:
        _exact(raw, {"approval_ref", "approved_at", "principal_ref", "role_ref"}, "approval")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class CrossRegionTransferRequest(_JsonRecord):
    tenant_ref: str
    artifact_ref: str
    artifact_sha256: str
    evidence_ref: str
    evidence_sha256: str
    scope_ref: str
    scope_sha256: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    source_region: str
    destination_region: str
    purpose: TransferPurpose
    legal_basis_ref: str
    approvals: tuple[TransferApproval, ...]
    requested_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.cross-region-transfer-request.v1"

    def __post_init__(self) -> None:
        namespaces = {
            "tenant_ref": "tenantref",
            "artifact_ref": "artifactref",
            "evidence_ref": "evidenceref",
            "scope_ref": "scoperef",
            "policy_ref": "policyref",
            "legal_basis_ref": "legalbasisref",
        }
        for name, namespace in namespaces.items():
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        for name in ("artifact_sha256", "evidence_sha256", "scope_sha256", "policy_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(self, "source_region", _region(self.source_region, "source_region"))
        object.__setattr__(
            self, "destination_region", _region(self.destination_region, "destination_region")
        )
        if self.source_region == self.destination_region:
            raise RegionalCustodyContractError("cross-region transfer regions must differ")
        object.__setattr__(self, "purpose", _enum(self.purpose, TransferPurpose, "purpose"))
        if not isinstance(self.approvals, tuple) or any(
            not isinstance(item, TransferApproval) for item in self.approvals
        ):
            raise RegionalCustodyContractError("approvals must be TransferApproval values")
        approvals = tuple(sorted(self.approvals, key=lambda item: item.approval_ref))
        if len(approvals) != 2 or {item.role_ref for item in approvals} != REQUIRED_TRANSFER_ROLES:
            raise RegionalCustodyContractError(
                "cross-region transfer requires both independent roles"
            )
        if len({item.principal_ref for item in approvals}) != 2:
            raise RegionalCustodyContractError("cross-region approvers must be independent")
        object.__setattr__(self, "approvals", approvals)
        object.__setattr__(self, "requested_at", _time(self.requested_at, "requested_at"))
        if any(_instant(item.approved_at) > _instant(self.requested_at) for item in approvals):
            raise RegionalCustodyContractError("approval cannot postdate transfer request")
        identifier, digest = _identity("CRT", self.KIND, self._body())
        object.__setattr__(self, "request_id", identifier)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "approvals": [item.to_dict() for item in self.approvals],
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "destination_region": self.destination_region,
            "effects": dict(NO_EFFECTS),
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "execution_status": "planned_only",
            "kind": self.KIND,
            "legal_basis_ref": self.legal_basis_ref,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "purpose": self.purpose.value,
            "requested_at": self.requested_at,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "source_region": self.source_region,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "request_id", "request_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> CrossRegionTransferRequest:
        ignored = {
            "request_id",
            "request_sha256",
            "effects",
            "execution_status",
            "kind",
            "schema_version",
            "approvals",
        }
        fields = {
            "approvals",
            "artifact_ref",
            "artifact_sha256",
            "destination_region",
            "effects",
            "evidence_ref",
            "evidence_sha256",
            "execution_status",
            "kind",
            "legal_basis_ref",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "purpose",
            "request_id",
            "request_sha256",
            "requested_at",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "source_region",
            "tenant_ref",
        }
        _exact(raw, fields, "cross-region transfer request")
        _metadata(raw, cls.KIND)
        if raw["execution_status"] != "planned_only":
            raise RegionalCustodyContractError("transfer cannot claim execution")
        values = {key: raw[key] for key in fields - ignored}
        values["approvals"] = tuple(TransferApproval.from_dict(item) for item in raw["approvals"])
        return _verify(raw, cls(**values))

    @classmethod
    def from_json(cls, raw: str) -> CrossRegionTransferRequest:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class RetentionSchedule(_JsonRecord):
    tenant_ref: str
    schedule_ref: str
    schedule_version: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    classification: Classification
    required_minimum_days: int
    retention_days: int
    deletion_grace_days: int
    effective_at: str
    schedule_id: str = field(init=False)
    schedule_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.retention-schedule.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_ref", _ref(self.tenant_ref, "tenant_ref", "tenantref"))
        object.__setattr__(
            self, "schedule_ref", _ref(self.schedule_ref, "schedule_ref", "scheduleref")
        )
        object.__setattr__(
            self, "schedule_version", _version(self.schedule_version, "schedule_version")
        )
        object.__setattr__(self, "policy_ref", _ref(self.policy_ref, "policy_ref", "policyref"))
        object.__setattr__(self, "policy_sha256", _digest(self.policy_sha256, "policy_sha256"))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(
            self, "classification", _enum(self.classification, Classification, "classification")
        )
        for name, maximum in (
            ("required_minimum_days", 36_500),
            ("retention_days", 36_500),
            ("deletion_grace_days", 3_650),
        ):
            value = getattr(self, name)
            minimum = 0 if name == "deletion_grace_days" else 1
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise RegionalCustodyContractError(f"{name} is outside the supported range")
        if self.retention_days < self.required_minimum_days:
            raise RegionalCustodyContractError("retention schedule truncates the required minimum")
        object.__setattr__(self, "effective_at", _time(self.effective_at, "effective_at"))
        identifier, digest = _identity("RSC", self.KIND, self._body())
        object.__setattr__(self, "schedule_id", identifier)
        object.__setattr__(self, "schedule_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "deletion_grace_days": self.deletion_grace_days,
            "effects": dict(NO_EFFECTS),
            "effective_at": self.effective_at,
            "kind": self.KIND,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "required_minimum_days": self.required_minimum_days,
            "retention_days": self.retention_days,
            "schedule_ref": self.schedule_ref,
            "schedule_version": self.schedule_version,
            "schema_version": SCHEMA_VERSION,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "schedule_id", "schedule_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RetentionSchedule:
        ignored = {"schedule_id", "schedule_sha256", "effects", "kind", "schema_version"}
        fields = {
            "classification",
            "deletion_grace_days",
            "effects",
            "effective_at",
            "kind",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "required_minimum_days",
            "retention_days",
            "schedule_id",
            "schedule_ref",
            "schedule_sha256",
            "schedule_version",
            "schema_version",
            "tenant_ref",
        }
        _exact(raw, fields, "retention schedule")
        _metadata(raw, cls.KIND)
        return _verify(raw, cls(**{key: raw[key] for key in fields - ignored}))

    @classmethod
    def from_json(cls, raw: str) -> RetentionSchedule:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class CustodyHold(_JsonRecord):
    tenant_ref: str
    artifact_ref: str
    artifact_sha256: str
    evidence_ref: str
    evidence_sha256: str
    scope_ref: str
    scope_sha256: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    hold_ref: str
    hold_kind: HoldKind
    authority_ref: str
    status: HoldStatus
    placed_at: str
    released_at: str | None
    hold_id: str = field(init=False)
    hold_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.custody-hold.v1"

    def __post_init__(self) -> None:
        namespaces = {
            "tenant_ref": "tenantref",
            "artifact_ref": "artifactref",
            "evidence_ref": "evidenceref",
            "scope_ref": "scoperef",
            "policy_ref": "policyref",
            "hold_ref": "holdref",
            "authority_ref": "authorityref",
        }
        for name, namespace in namespaces.items():
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        for name in (
            "artifact_sha256",
            "evidence_sha256",
            "scope_sha256",
            "policy_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(self, "hold_kind", _enum(self.hold_kind, HoldKind, "hold_kind"))
        object.__setattr__(self, "status", _enum(self.status, HoldStatus, "status"))
        object.__setattr__(self, "placed_at", _time(self.placed_at, "placed_at"))
        if self.status is HoldStatus.ACTIVE and self.released_at is not None:
            raise RegionalCustodyContractError("active hold cannot have released_at")
        if self.status is HoldStatus.RELEASED:
            if self.released_at is None:
                raise RegionalCustodyContractError("released hold requires released_at")
            object.__setattr__(self, "released_at", _time(self.released_at, "released_at"))
            if _instant(self.released_at) <= _instant(self.placed_at):
                raise RegionalCustodyContractError("hold release must follow placement")
        identifier, digest = _identity("HLD", self.KIND, self._body())
        object.__setattr__(self, "hold_id", identifier)
        object.__setattr__(self, "hold_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "authority_ref": self.authority_ref,
            "effects": dict(NO_EFFECTS),
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "hold_kind": self.hold_kind.value,
            "hold_ref": self.hold_ref,
            "kind": self.KIND,
            "placed_at": self.placed_at,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "released_at": self.released_at,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "hold_id", "hold_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> CustodyHold:
        ignored = {"hold_id", "hold_sha256", "effects", "kind", "schema_version"}
        fields = {
            "artifact_ref",
            "artifact_sha256",
            "authority_ref",
            "effects",
            "evidence_ref",
            "evidence_sha256",
            "hold_id",
            "hold_kind",
            "hold_ref",
            "hold_sha256",
            "kind",
            "placed_at",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "released_at",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "status",
            "tenant_ref",
        }
        _exact(raw, fields, "custody hold")
        _metadata(raw, cls.KIND)
        return _verify(raw, cls(**{key: raw[key] for key in fields - ignored}))

    @classmethod
    def from_json(cls, raw: str) -> CustodyHold:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class DeletionEligibilityPlan(_JsonRecord):
    tenant_ref: str
    artifact_ref: str
    artifact_sha256: str
    evidence_ref: str
    evidence_sha256: str
    scope_ref: str
    scope_sha256: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    schedule_id: str
    schedule_sha256: str
    evaluated_at: str
    retention_expires_at: str
    active_hold_ids: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    status: DeletionStatus
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.deletion-eligibility-plan.v1"

    def __post_init__(self) -> None:
        namespaces = {
            "tenant_ref": "tenantref",
            "artifact_ref": "artifactref",
            "evidence_ref": "evidenceref",
            "scope_ref": "scoperef",
            "policy_ref": "policyref",
        }
        for name, namespace in namespaces.items():
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        for name in (
            "artifact_sha256",
            "evidence_sha256",
            "scope_sha256",
            "policy_sha256",
            "schedule_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        if (
            not isinstance(self.schedule_id, str)
            or re.fullmatch(r"RSC-[0-9A-F]{32}", self.schedule_id) is None
        ):
            raise RegionalCustodyContractError("schedule_id is invalid")
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        object.__setattr__(
            self, "retention_expires_at", _time(self.retention_expires_at, "retention_expires_at")
        )
        holds = tuple(sorted(self.active_hold_ids))
        if len(holds) != len(set(holds)) or any(
            re.fullmatch(r"HLD-[0-9A-F]{32}", item) is None for item in holds
        ):
            raise RegionalCustodyContractError("active_hold_ids are invalid")
        object.__setattr__(self, "active_hold_ids", holds)
        blockers = _codes(self.blocker_codes)
        object.__setattr__(self, "blocker_codes", blockers)
        object.__setattr__(self, "status", _enum(self.status, DeletionStatus, "status"))
        if self.status is DeletionStatus.ELIGIBLE_FOR_EXTERNAL_EXECUTION:
            if (
                blockers
                or holds
                or _instant(self.evaluated_at) < _instant(self.retention_expires_at)
            ):
                raise RegionalCustodyContractError("eligible deletion plan has unresolved blockers")
        elif not blockers:
            raise RegionalCustodyContractError("ineligible deletion plan requires blockers")
        identifier, digest = _identity("DEP", self.KIND, self._body())
        object.__setattr__(self, "plan_id", identifier)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "active_hold_ids": list(self.active_hold_ids),
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "blocker_codes": list(self.blocker_codes),
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "execution_status": "planned_only",
            "kind": self.KIND,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "retention_expires_at": self.retention_expires_at,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "plan_id", "plan_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DeletionEligibilityPlan:
        ignored = {
            "plan_id",
            "plan_sha256",
            "effects",
            "execution_status",
            "kind",
            "schema_version",
        }
        fields = {
            "active_hold_ids",
            "artifact_ref",
            "artifact_sha256",
            "blocker_codes",
            "effects",
            "evaluated_at",
            "evidence_ref",
            "evidence_sha256",
            "execution_status",
            "kind",
            "plan_id",
            "plan_sha256",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "retention_expires_at",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "status",
            "tenant_ref",
        }
        _exact(raw, fields, "deletion eligibility plan")
        _metadata(raw, cls.KIND)
        if raw["execution_status"] != "planned_only":
            raise RegionalCustodyContractError("deletion plan cannot claim execution")
        values = {key: raw[key] for key in fields - ignored}
        values["active_hold_ids"] = tuple(values["active_hold_ids"])
        values["blocker_codes"] = tuple(values["blocker_codes"])
        return _verify(raw, cls(**values))

    @classmethod
    def from_json(cls, raw: str) -> DeletionEligibilityPlan:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class OperationAdmissionDecision(_JsonRecord):
    operation_ref: str
    operation: OperationKind
    tenant_ref: str
    artifact_ref: str
    artifact_sha256: str
    evidence_ref: str
    evidence_sha256: str
    scope_ref: str
    scope_sha256: str
    policy_ref: str
    policy_sha256: str
    policy_version: str
    requested_region: str
    evaluated_at: str
    transfer_request_id: str | None
    transfer_request_sha256: str | None
    deletion_plan_id: str | None
    deletion_plan_sha256: str | None
    blocker_codes: tuple[str, ...]
    status: AdmissionStatus
    decision_id: str = field(init=False)
    decision_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.regional-operation-admission.v1"

    def __post_init__(self) -> None:
        namespaces = {
            "operation_ref": "operationref",
            "tenant_ref": "tenantref",
            "artifact_ref": "artifactref",
            "evidence_ref": "evidenceref",
            "scope_ref": "scoperef",
            "policy_ref": "policyref",
        }
        for name, namespace in namespaces.items():
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(self, "operation", _enum(self.operation, OperationKind, "operation"))
        for name in ("artifact_sha256", "evidence_sha256", "scope_sha256", "policy_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(self, "policy_version", _version(self.policy_version, "policy_version"))
        object.__setattr__(
            self, "requested_region", _region(self.requested_region, "requested_region")
        )
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        _optional_address(self.transfer_request_id, self.transfer_request_sha256, "CRT", "transfer")
        _optional_address(self.deletion_plan_id, self.deletion_plan_sha256, "DEP", "deletion")
        blockers = _codes(self.blocker_codes)
        object.__setattr__(self, "blocker_codes", blockers)
        object.__setattr__(self, "status", _enum(self.status, AdmissionStatus, "status"))
        if self.status is AdmissionStatus.ELIGIBLE_FOR_EXTERNAL_AUTHORIZATION and blockers:
            raise RegionalCustodyContractError("admissible operation has blockers")
        if self.status is AdmissionStatus.DENIED and not blockers:
            raise RegionalCustodyContractError("denied operation requires blockers")
        identifier, digest = _identity("RAD", self.KIND, self._body())
        object.__setattr__(self, "decision_id", identifier)
        object.__setattr__(self, "decision_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "authorization_effect": "none",
            "blocker_codes": list(self.blocker_codes),
            "deletion_plan_id": self.deletion_plan_id,
            "deletion_plan_sha256": self.deletion_plan_sha256,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "kind": self.KIND,
            "operation": self.operation.value,
            "operation_ref": self.operation_ref,
            "policy_ref": self.policy_ref,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "requested_region": self.requested_region,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
            "transfer_request_id": self.transfer_request_id,
            "transfer_request_sha256": self.transfer_request_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "decision_id", "decision_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> OperationAdmissionDecision:
        ignored = {
            "decision_id",
            "decision_sha256",
            "authorization_effect",
            "effects",
            "kind",
            "schema_version",
        }
        fields = {
            "artifact_ref",
            "artifact_sha256",
            "authorization_effect",
            "blocker_codes",
            "decision_id",
            "decision_sha256",
            "deletion_plan_id",
            "deletion_plan_sha256",
            "effects",
            "evaluated_at",
            "evidence_ref",
            "evidence_sha256",
            "kind",
            "operation",
            "operation_ref",
            "policy_ref",
            "policy_sha256",
            "policy_version",
            "requested_region",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "status",
            "tenant_ref",
            "transfer_request_id",
            "transfer_request_sha256",
        }
        _exact(raw, fields, "operation admission decision")
        _metadata(raw, cls.KIND)
        if raw["authorization_effect"] != "none":
            raise RegionalCustodyContractError("decision attempts authorization")
        values = {key: raw[key] for key in fields - ignored}
        values["blocker_codes"] = tuple(values["blocker_codes"])
        return _verify(raw, cls(**values))

    @classmethod
    def from_json(cls, raw: str) -> OperationAdmissionDecision:
        return cls.from_dict(_load(raw))


def evaluate_deletion_eligibility(
    descriptor: ArtifactCustodyDescriptor,
    schedule: RetentionSchedule,
    holds: Sequence[CustodyHold],
    *,
    evaluated_at: str,
) -> DeletionEligibilityPlan:
    """Create a deletion eligibility plan without deleting anything."""

    if not isinstance(descriptor, ArtifactCustodyDescriptor) or not isinstance(
        schedule, RetentionSchedule
    ):
        raise RegionalCustodyContractError("descriptor and schedule types are required")
    when = _time(evaluated_at, "evaluated_at")
    blockers = _schedule_blockers(descriptor, schedule)
    active: list[str] = []
    seen: set[str] = set()
    for hold in holds:
        if not isinstance(hold, CustodyHold) or hold.hold_id in seen:
            raise RegionalCustodyContractError("holds must be unique CustodyHold values")
        seen.add(hold.hold_id)
        if not _hold_matches(descriptor, hold):
            blockers.add("hold_binding_mismatch")
        elif hold.status is HoldStatus.ACTIVE:
            active.append(hold.hold_id)
    if active:
        blockers.add("active_hold")
    expiry = _instant(descriptor.captured_at) + timedelta(
        days=schedule.retention_days + schedule.deletion_grace_days
    )
    if _instant(when) < expiry:
        blockers.add("retention_not_expired")
    return DeletionEligibilityPlan(
        tenant_ref=descriptor.tenant_ref,
        artifact_ref=descriptor.artifact_ref,
        artifact_sha256=descriptor.artifact_sha256,
        evidence_ref=descriptor.evidence_ref,
        evidence_sha256=descriptor.evidence_sha256,
        scope_ref=descriptor.scope_ref,
        scope_sha256=descriptor.scope_sha256,
        policy_ref=descriptor.policy_ref,
        policy_sha256=descriptor.policy_sha256,
        policy_version=descriptor.policy_version,
        schedule_id=schedule.schedule_id,
        schedule_sha256=schedule.schedule_sha256,
        evaluated_at=when,
        retention_expires_at=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        active_hold_ids=tuple(active),
        blocker_codes=tuple(blockers),
        status=(
            DeletionStatus.INELIGIBLE
            if blockers
            else DeletionStatus.ELIGIBLE_FOR_EXTERNAL_EXECUTION
        ),
    )


def evaluate_operation_admission(
    binding: TenantRegionBinding,
    descriptor: ArtifactCustodyDescriptor,
    *,
    operation_ref: str,
    operation: OperationKind | str,
    requested_region: str,
    evaluated_at: str,
    transfer: CrossRegionTransferRequest | None = None,
    deletion_plan: DeletionEligibilityPlan | None = None,
) -> OperationAdmissionDecision:
    """Evaluate complete bindings without authorizing or executing work."""

    if not isinstance(binding, TenantRegionBinding) or not isinstance(
        descriptor, ArtifactCustodyDescriptor
    ):
        raise RegionalCustodyContractError("binding and descriptor types are required")
    selected = _enum(operation, OperationKind, "operation")
    region = _region(requested_region, "requested_region")
    blockers = _binding_blockers(binding, descriptor)
    transfer_id = transfer_hash = deletion_id = deletion_hash = None
    if selected is OperationKind.STORE:
        if region not in binding.allowed_storage_regions:
            blockers.add("unknown_or_disallowed_storage_region")
        if transfer is not None or deletion_plan is not None:
            blockers.add("unexpected_supporting_record")
    elif selected is OperationKind.PROCESS:
        if region not in binding.allowed_processing_regions:
            blockers.add("unknown_or_disallowed_processing_region")
        if transfer is not None or deletion_plan is not None:
            blockers.add("unexpected_supporting_record")
    elif selected is OperationKind.TRANSFER:
        if transfer is None:
            blockers.add("transfer_request_required")
        else:
            transfer_id, transfer_hash = transfer.request_id, transfer.request_sha256
            blockers.update(_transfer_blockers(binding, descriptor, transfer, region))
        if deletion_plan is not None:
            blockers.add("unexpected_deletion_plan")
    else:
        if deletion_plan is None:
            blockers.add("deletion_plan_required")
        else:
            deletion_id, deletion_hash = deletion_plan.plan_id, deletion_plan.plan_sha256
            if not _exact_binding(descriptor, deletion_plan):
                blockers.add("deletion_binding_mismatch")
            if region != descriptor.storage_region:
                blockers.add("deletion_region_mismatch")
            if deletion_plan.status is not DeletionStatus.ELIGIBLE_FOR_EXTERNAL_EXECUTION:
                blockers.add("deletion_plan_ineligible")
        if transfer is not None:
            blockers.add("unexpected_transfer_request")
    return OperationAdmissionDecision(
        operation_ref=operation_ref,
        operation=selected,
        tenant_ref=descriptor.tenant_ref,
        artifact_ref=descriptor.artifact_ref,
        artifact_sha256=descriptor.artifact_sha256,
        evidence_ref=descriptor.evidence_ref,
        evidence_sha256=descriptor.evidence_sha256,
        scope_ref=descriptor.scope_ref,
        scope_sha256=descriptor.scope_sha256,
        policy_ref=descriptor.policy_ref,
        policy_sha256=descriptor.policy_sha256,
        policy_version=descriptor.policy_version,
        requested_region=region,
        evaluated_at=_time(evaluated_at, "evaluated_at"),
        transfer_request_id=transfer_id,
        transfer_request_sha256=transfer_hash,
        deletion_plan_id=deletion_id,
        deletion_plan_sha256=deletion_hash,
        blocker_codes=tuple(blockers),
        status=(
            AdmissionStatus.DENIED
            if blockers
            else AdmissionStatus.ELIGIBLE_FOR_EXTERNAL_AUTHORIZATION
        ),
    )


def parse_contract(raw: Mapping[str, Any]) -> Any:
    """Parse a strict top-level regional custody contract."""

    types = {
        item.KIND: item
        for item in (
            TenantRegionBinding,
            ArtifactCustodyDescriptor,
            CrossRegionTransferRequest,
            RetentionSchedule,
            CustodyHold,
            DeletionEligibilityPlan,
            OperationAdmissionDecision,
        )
    }
    if not isinstance(raw, Mapping) or raw.get("kind") not in types:
        raise RegionalCustodyContractError("unsupported regional custody contract kind")
    return types[raw["kind"]].from_dict(raw)


def _optional_address(identifier: str | None, digest: str | None, prefix: str, label: str) -> None:
    if (identifier is None) != (digest is None):
        raise RegionalCustodyContractError(f"{label} address must be complete")
    if identifier is not None:
        if re.fullmatch(rf"{prefix}-[0-9A-F]{{32}}", identifier) is None:
            raise RegionalCustodyContractError(f"{label} id is invalid")
        _digest(digest, f"{label} digest")


def _binding_blockers(
    binding: TenantRegionBinding, descriptor: ArtifactCustodyDescriptor
) -> set[str]:
    blockers: set[str] = set()
    if binding.tenant_ref != descriptor.tenant_ref:
        blockers.add("tenant_binding_mismatch")
    if (binding.policy_ref, binding.policy_sha256, binding.policy_version) != (
        descriptor.policy_ref,
        descriptor.policy_sha256,
        descriptor.policy_version,
    ):
        blockers.add("policy_binding_mismatch")
    if binding.encryption_key_ref != descriptor.encryption_key_ref:
        blockers.add("encryption_key_binding_mismatch")
    if descriptor.storage_region not in binding.allowed_storage_regions:
        blockers.add("current_storage_region_disallowed")
    if descriptor.processing_region not in binding.allowed_processing_regions:
        blockers.add("current_processing_region_disallowed")
    return blockers


def _exact_binding(left: Any, right: Any) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in (
            "tenant_ref",
            "artifact_ref",
            "artifact_sha256",
            "evidence_ref",
            "evidence_sha256",
            "scope_ref",
            "scope_sha256",
            "policy_ref",
            "policy_sha256",
            "policy_version",
        )
    )


def _transfer_blockers(
    binding: TenantRegionBinding,
    descriptor: ArtifactCustodyDescriptor,
    transfer: CrossRegionTransferRequest,
    requested_region: str,
) -> set[str]:
    blockers: set[str] = set()
    if not _exact_binding(descriptor, transfer):
        blockers.add("transfer_binding_mismatch")
    if transfer.source_region != descriptor.storage_region:
        blockers.add("transfer_source_mismatch")
    if transfer.destination_region != requested_region:
        blockers.add("transfer_destination_mismatch")
    allowed = (
        binding.allowed_storage_regions
        if transfer.purpose is TransferPurpose.STORAGE
        else binding.allowed_processing_regions
    )
    if transfer.destination_region not in allowed:
        blockers.add("unknown_or_disallowed_transfer_region")
    return blockers


def _schedule_blockers(
    descriptor: ArtifactCustodyDescriptor, schedule: RetentionSchedule
) -> set[str]:
    blockers: set[str] = set()
    if descriptor.tenant_ref != schedule.tenant_ref:
        blockers.add("tenant_binding_mismatch")
    if (descriptor.policy_ref, descriptor.policy_sha256, descriptor.policy_version) != (
        schedule.policy_ref,
        schedule.policy_sha256,
        schedule.policy_version,
    ):
        blockers.add("policy_binding_mismatch")
    if (descriptor.retention_schedule_ref, descriptor.retention_schedule_version) != (
        schedule.schedule_ref,
        schedule.schedule_version,
    ):
        blockers.add("retention_schedule_binding_mismatch")
    if descriptor.classification is not schedule.classification:
        blockers.add("classification_mismatch")
    return blockers


def _hold_matches(descriptor: ArtifactCustodyDescriptor, hold: CustodyHold) -> bool:
    return all(
        getattr(descriptor, name) == getattr(hold, name)
        for name in (
            "tenant_ref",
            "artifact_ref",
            "artifact_sha256",
            "evidence_ref",
            "evidence_sha256",
            "scope_ref",
            "scope_sha256",
            "policy_ref",
            "policy_sha256",
            "policy_version",
        )
    )
