"""Deterministic disaster recovery proof contracts with no runtime effects.

The records in this module describe recovery objectives, backup evidence,
rehearsal intent, observed restoration results, and readiness assessments.
They do not create backups, restore data, access keys, mutate persistence,
contact a network, deploy systems, authorize action, or qualify a service.
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
MAX_ITEMS = 4096

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "backup": "none",
        "credential_or_key_access": "none",
        "deletion": "none",
        "deployment": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "restore": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|systemref|backupref|keyref|registrysnapshotref|artifactref|"
    r"eventref|evidenceref|custodyref|verificationref|planref|observationref|"
    r"signatureref|reviewerref|principalref|manifestref|recoveryref|gapref|"
    r"migrationref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)


class DisasterRecoveryContractError(ValueError):
    """Raised when a disaster recovery proof contract fails closed."""


class GapKind(StrEnum):
    MISSING = "missing"
    DIGEST_MISMATCH = "digest_mismatch"
    CUSTODY_BREAK = "custody_break"
    UNAVAILABLE = "unavailable"


class GapSubject(StrEnum):
    ARTIFACT = "artifact"
    EVENT = "event"
    EVIDENCE = "evidence"
    KEY = "key"
    REGISTRY = "registry"


class ReadinessStatus(StrEnum):
    NOT_READY = "not_ready"
    CONTRACT_READY_UNVERIFIED = "contract_ready_unverified"


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
        raise DisasterRecoveryContractError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 14:
        raise DisasterRecoveryContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DisasterRecoveryContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise DisasterRecoveryContractError(f"{label} has an unsupported value")


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DisasterRecoveryContractError(f"{label} fields are invalid")
    return raw


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise DisasterRecoveryContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise DisasterRecoveryContractError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DisasterRecoveryContractError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise DisasterRecoveryContractError(f"{label} must be an exact version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise DisasterRecoveryContractError(f"{label} must not be a moving alias")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DisasterRecoveryContractError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DisasterRecoveryContractError(f"{label} must be valid") from exc


def _positive(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DisasterRecoveryContractError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DisasterRecoveryContractError(f"{label} must be between 0 and {maximum}")
    return value


def _references(
    values: Sequence[Any], label: str, namespace: str, *, minimum: int = 1
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise DisasterRecoveryContractError(f"{label} must be a sequence")
    result = tuple(_reference(item, f"{label} item", namespace) for item in values)
    if not minimum <= len(result) <= MAX_ITEMS or len(result) != len(set(result)):
        raise DisasterRecoveryContractError(f"{label} must be a bounded unique sequence")
    return tuple(sorted(result))


def _records(values: Sequence[Any], label: str, factory: Any) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)):
        raise DisasterRecoveryContractError(f"{label} must be a sequence")
    result = tuple(
        item if isinstance(item, factory) else factory.from_dict(item)
        for item in values
    )
    if not 1 <= len(result) <= MAX_ITEMS:
        raise DisasterRecoveryContractError(f"{label} must be a bounded non-empty sequence")
    references = tuple(item.reference for item in result)
    if len(references) != len(set(references)):
        raise DisasterRecoveryContractError(f"{label} contains duplicate references")
    return tuple(sorted(result, key=lambda item: item.reference))


def _verify_effects(raw: Any) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != dict(NO_EFFECTS):
        raise DisasterRecoveryContractError("effects must preserve the no-effect boundary")


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {
        key: value
        for key, value in raw.items()
        if key not in {id_field, digest_field}
    }
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise DisasterRecoveryContractError("record content address does not match content")


@dataclass(frozen=True, slots=True)
class CustodiedObjectBinding:
    """Exact content, version, and custody binding for an artifact or evidence item."""

    reference: str
    sha256: str
    version: str
    custody_ref: str
    custody_sha256: str

    def __post_init__(self) -> None:
        namespace = (
            self.reference.split(":", maxsplit=1)[0]
            if isinstance(self.reference, str)
            else ""
        )
        if namespace not in {"artifactref", "evidenceref"}:
            raise DisasterRecoveryContractError(
                "reference must use the artifactref or evidenceref namespace"
            )
        _reference(self.reference, "reference", namespace)
        _digest(self.sha256, "sha256")
        _version(self.version, "version")
        _reference(self.custody_ref, "custody_ref", "custodyref")
        _digest(self.custody_sha256, "custody_sha256")

    def to_dict(self) -> dict[str, str]:
        return {
            "custody_ref": self.custody_ref,
            "custody_sha256": self.custody_sha256,
            "reference": self.reference,
            "sha256": self.sha256,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CustodiedObjectBinding:
        value = _exact(
            raw,
            {"reference", "sha256", "version", "custody_ref", "custody_sha256"},
            "custodied object binding",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class KeySnapshotBinding:
    """Opaque key descriptor binding without key material or access."""

    key_ref: str
    key_version: str
    key_descriptor_sha256: str
    custody_ref: str
    custody_sha256: str

    def __post_init__(self) -> None:
        _reference(self.key_ref, "key_ref", "keyref")
        _version(self.key_version, "key_version")
        _digest(self.key_descriptor_sha256, "key_descriptor_sha256")
        _reference(self.custody_ref, "custody_ref", "custodyref")
        _digest(self.custody_sha256, "custody_sha256")

    def to_dict(self) -> dict[str, str]:
        return {
            "custody_ref": self.custody_ref,
            "custody_sha256": self.custody_sha256,
            "key_descriptor_sha256": self.key_descriptor_sha256,
            "key_ref": self.key_ref,
            "key_version": self.key_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> KeySnapshotBinding:
        value = _exact(
            raw,
            {
                "key_ref",
                "key_version",
                "key_descriptor_sha256",
                "custody_ref",
                "custody_sha256",
            },
            "key snapshot binding",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class RegistrySnapshotBinding:
    """Unambiguous registry snapshot and rollback lineage binding."""

    registry_snapshot_ref: str
    registry_version: str
    registry_sha256: str
    parent_snapshot_ref: str
    parent_snapshot_sha256: str
    rollback_manifest_ref: str
    rollback_manifest_sha256: str
    sequence: int

    def __post_init__(self) -> None:
        _reference(
            self.registry_snapshot_ref,
            "registry_snapshot_ref",
            "registrysnapshotref",
        )
        _version(self.registry_version, "registry_version")
        _digest(self.registry_sha256, "registry_sha256")
        _reference(
            self.parent_snapshot_ref,
            "parent_snapshot_ref",
            "registrysnapshotref",
        )
        _digest(self.parent_snapshot_sha256, "parent_snapshot_sha256")
        _reference(self.rollback_manifest_ref, "rollback_manifest_ref", "migrationref")
        _digest(self.rollback_manifest_sha256, "rollback_manifest_sha256")
        _positive(self.sequence, "sequence")
        if self.parent_snapshot_ref == self.registry_snapshot_ref:
            raise DisasterRecoveryContractError("registry rollback lineage must have a parent")

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_snapshot_ref": self.parent_snapshot_ref,
            "parent_snapshot_sha256": self.parent_snapshot_sha256,
            "registry_sha256": self.registry_sha256,
            "registry_snapshot_ref": self.registry_snapshot_ref,
            "registry_version": self.registry_version,
            "rollback_manifest_ref": self.rollback_manifest_ref,
            "rollback_manifest_sha256": self.rollback_manifest_sha256,
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RegistrySnapshotBinding:
        value = _exact(
            raw,
            {
                "registry_snapshot_ref",
                "registry_version",
                "registry_sha256",
                "parent_snapshot_ref",
                "parent_snapshot_sha256",
                "rollback_manifest_ref",
                "rollback_manifest_sha256",
                "sequence",
            },
            "registry snapshot binding",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class EventStoreCheckpoint:
    """Verified event chain head used as a restoration continuity boundary."""

    event_ref: str
    event_sequence: int
    event_sha256: str
    verification_ref: str
    verification_sha256: str
    verified_at: str
    verification_passed: bool

    def __post_init__(self) -> None:
        _reference(self.event_ref, "event_ref", "eventref")
        _positive(self.event_sequence, "event_sequence")
        _digest(self.event_sha256, "event_sha256")
        _reference(self.verification_ref, "verification_ref", "verificationref")
        _digest(self.verification_sha256, "verification_sha256")
        _timestamp(self.verified_at, "verified_at")
        if not isinstance(self.verification_passed, bool):
            raise DisasterRecoveryContractError("verification_passed must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_ref": self.event_ref,
            "event_sequence": self.event_sequence,
            "event_sha256": self.event_sha256,
            "verification_passed": self.verification_passed,
            "verification_ref": self.verification_ref,
            "verification_sha256": self.verification_sha256,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EventStoreCheckpoint:
        value = _exact(
            raw,
            {
                "event_ref",
                "event_sequence",
                "event_sha256",
                "verification_ref",
                "verification_sha256",
                "verified_at",
                "verification_passed",
            },
            "event store checkpoint",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class RecoveryObjective:
    """Versioned RPO, RTO, freshness, and required continuity objective."""

    tenant_ref: str
    system_ref: str
    system_version: str
    objective_version: str
    max_rpo_seconds: int
    max_rto_seconds: int
    max_backup_age_seconds: int
    required_artifact_refs: tuple[str, ...]
    required_event_refs: tuple[str, ...]
    required_evidence_refs: tuple[str, ...]
    created_at: str
    reviewer_ref: str
    reviewer_signature_ref: str
    reviewer_signature_sha256: str
    objective_id: str = field(init=False)
    objective_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-objective.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        _version(self.objective_version, "objective_version")
        _positive(self.max_rpo_seconds, "max_rpo_seconds")
        _positive(self.max_rto_seconds, "max_rto_seconds")
        _positive(self.max_backup_age_seconds, "max_backup_age_seconds")
        object.__setattr__(
            self,
            "required_artifact_refs",
            _references(self.required_artifact_refs, "required_artifact_refs", "artifactref"),
        )
        object.__setattr__(
            self,
            "required_event_refs",
            _references(self.required_event_refs, "required_event_refs", "eventref"),
        )
        if len(self.required_event_refs) != 1:
            raise DisasterRecoveryContractError(
                "required_event_refs must identify exactly one verified event chain head"
            )
        object.__setattr__(
            self,
            "required_evidence_refs",
            _references(self.required_evidence_refs, "required_evidence_refs", "evidenceref"),
        )
        _timestamp(self.created_at, "created_at")
        _reference(self.reviewer_ref, "reviewer_ref", "reviewerref")
        _reference(
            self.reviewer_signature_ref,
            "reviewer_signature_ref",
            "signatureref",
        )
        _digest(self.reviewer_signature_sha256, "reviewer_signature_sha256")
        objective_id, digest = _identity("DRO", self.KIND, self._body())
        object.__setattr__(self, "objective_id", objective_id)
        object.__setattr__(self, "objective_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "max_backup_age_seconds": self.max_backup_age_seconds,
            "max_rpo_seconds": self.max_rpo_seconds,
            "max_rto_seconds": self.max_rto_seconds,
            "objective_version": self.objective_version,
            "required_artifact_refs": list(self.required_artifact_refs),
            "required_event_refs": list(self.required_event_refs),
            "required_evidence_refs": list(self.required_evidence_refs),
            "reviewer_ref": self.reviewer_ref,
            "reviewer_signature_ref": self.reviewer_signature_ref,
            "reviewer_signature_sha256": self.reviewer_signature_sha256,
            "schema_version": SCHEMA_VERSION,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RecoveryObjective:
        fields = {
            "schema_version", "kind", "objective_id", "objective_sha256", "tenant_ref",
            "system_ref", "system_version", "objective_version", "max_rpo_seconds",
            "max_rto_seconds", "max_backup_age_seconds", "required_artifact_refs",
            "required_event_refs", "required_evidence_refs", "created_at", "reviewer_ref",
            "reviewer_signature_ref", "reviewer_signature_sha256", "effects",
        }
        value = _exact(raw, fields, "recovery objective")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryContractError("recovery objective discriminator is invalid")
        _verify_effects(value["effects"])
        _verify_address(value, "objective_id", "objective_sha256", "DRO", cls.KIND)
        return cls(
            tenant_ref=value["tenant_ref"],
            system_ref=value["system_ref"],
            system_version=value["system_version"],
            objective_version=value["objective_version"],
            max_rpo_seconds=value["max_rpo_seconds"],
            max_rto_seconds=value["max_rto_seconds"],
            max_backup_age_seconds=value["max_backup_age_seconds"],
            required_artifact_refs=tuple(value["required_artifact_refs"]),
            required_event_refs=tuple(value["required_event_refs"]),
            required_evidence_refs=tuple(value["required_evidence_refs"]),
            created_at=value["created_at"],
            reviewer_ref=value["reviewer_ref"],
            reviewer_signature_ref=value["reviewer_signature_ref"],
            reviewer_signature_sha256=value["reviewer_signature_sha256"],
        )


@dataclass(frozen=True, slots=True)
class BackupManifest:
    """Signed verification evidence for a content-addressed backup set."""

    tenant_ref: str
    system_ref: str
    system_version: str
    backup_ref: str
    backup_version: str
    created_at: str
    verified_at: str
    verification_ref: str
    verification_sha256: str
    verification_signature_ref: str
    verification_signature_sha256: str
    verifier_ref: str
    verification_passed: bool
    key_snapshot: KeySnapshotBinding
    registry_snapshot: RegistrySnapshotBinding
    artifacts: tuple[CustodiedObjectBinding, ...]
    event_checkpoint: EventStoreCheckpoint
    evidence: tuple[CustodiedObjectBinding, ...]
    manifest_id: str = field(init=False)
    manifest_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-backup-manifest.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        _reference(self.backup_ref, "backup_ref", "backupref")
        _version(self.backup_version, "backup_version")
        created = _timestamp(self.created_at, "created_at")
        verified = _timestamp(self.verified_at, "verified_at")
        if verified < created:
            raise DisasterRecoveryContractError("backup verification predates backup creation")
        _reference(self.verification_ref, "verification_ref", "verificationref")
        _digest(self.verification_sha256, "verification_sha256")
        _reference(
            self.verification_signature_ref,
            "verification_signature_ref",
            "signatureref",
        )
        _digest(self.verification_signature_sha256, "verification_signature_sha256")
        _reference(self.verifier_ref, "verifier_ref", "reviewerref")
        if not isinstance(self.verification_passed, bool):
            raise DisasterRecoveryContractError("verification_passed must be boolean")
        key = (
            self.key_snapshot
            if isinstance(self.key_snapshot, KeySnapshotBinding)
            else KeySnapshotBinding.from_dict(self.key_snapshot)
        )
        registry = (
            self.registry_snapshot
            if isinstance(self.registry_snapshot, RegistrySnapshotBinding)
            else RegistrySnapshotBinding.from_dict(self.registry_snapshot)
        )
        event = (
            self.event_checkpoint
            if isinstance(self.event_checkpoint, EventStoreCheckpoint)
            else EventStoreCheckpoint.from_dict(self.event_checkpoint)
        )
        object.__setattr__(self, "key_snapshot", key)
        object.__setattr__(self, "registry_snapshot", registry)
        object.__setattr__(self, "event_checkpoint", event)
        if _timestamp(event.verified_at, "event_checkpoint.verified_at") > verified:
            raise DisasterRecoveryContractError(
                "event checkpoint verification exceeds backup verification time"
            )
        artifacts = _records(self.artifacts, "artifacts", CustodiedObjectBinding)
        evidence = _records(self.evidence, "evidence", CustodiedObjectBinding)
        if any(item.reference.startswith("evidenceref:") for item in artifacts):
            raise DisasterRecoveryContractError("artifacts must use artifactref references")
        if any(item.reference.startswith("artifactref:") for item in evidence):
            raise DisasterRecoveryContractError("evidence must use evidenceref references")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "evidence", evidence)
        manifest_id, digest = _identity("DRB", self.KIND, self._body())
        object.__setattr__(self, "manifest_id", manifest_id)
        object.__setattr__(self, "manifest_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifacts": [item.to_dict() for item in self.artifacts],
            "backup_ref": self.backup_ref,
            "backup_version": self.backup_version,
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "event_checkpoint": self.event_checkpoint.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "key_snapshot": self.key_snapshot.to_dict(),
            "kind": self.KIND,
            "registry_snapshot": self.registry_snapshot.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
            "verification_passed": self.verification_passed,
            "verification_ref": self.verification_ref,
            "verification_sha256": self.verification_sha256,
            "verification_signature_ref": self.verification_signature_ref,
            "verification_signature_sha256": self.verification_signature_sha256,
            "verified_at": self.verified_at,
            "verifier_ref": self.verifier_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BackupManifest:
        fields = {
            "schema_version", "kind", "manifest_id", "manifest_sha256", "tenant_ref",
            "system_ref", "system_version", "backup_ref", "backup_version", "created_at",
            "verified_at", "verification_ref", "verification_sha256",
            "verification_signature_ref", "verification_signature_sha256", "verifier_ref",
            "verification_passed", "key_snapshot", "registry_snapshot", "artifacts",
            "event_checkpoint", "evidence", "effects",
        }
        value = _exact(raw, fields, "backup manifest")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryContractError("backup manifest discriminator is invalid")
        _verify_effects(value["effects"])
        _verify_address(value, "manifest_id", "manifest_sha256", "DRB", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in fields
                if key
                not in {"schema_version", "kind", "manifest_id", "manifest_sha256", "effects"}
            }
        )


@dataclass(frozen=True, slots=True)
class RestorationRehearsalPlan:
    """Bounded rehearsal intent that cannot cause a restoration."""

    tenant_ref: str
    system_ref: str
    system_version: str
    rehearsal_version: str
    objective_id: str
    objective_sha256: str
    backup_manifest_id: str
    backup_manifest_sha256: str
    backup_ref: str
    backup_version: str
    key_snapshot: KeySnapshotBinding
    registry_snapshot: RegistrySnapshotBinding
    required_artifact_refs: tuple[str, ...]
    required_event_refs: tuple[str, ...]
    required_evidence_refs: tuple[str, ...]
    simulated_failure_at: str
    restore_point_at: str
    planned_at: str
    executor_ref: str
    reviewer_ref: str
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-rehearsal-plan.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        _version(self.rehearsal_version, "rehearsal_version")
        if not isinstance(self.objective_id, str) or not self.objective_id.startswith("DRO-"):
            raise DisasterRecoveryContractError("objective_id is invalid")
        _digest(self.objective_sha256, "objective_sha256")
        if not isinstance(
            self.backup_manifest_id, str
        ) or not self.backup_manifest_id.startswith("DRB-"):
            raise DisasterRecoveryContractError("backup_manifest_id is invalid")
        _digest(self.backup_manifest_sha256, "backup_manifest_sha256")
        _reference(self.backup_ref, "backup_ref", "backupref")
        _version(self.backup_version, "backup_version")
        key = (
            self.key_snapshot
            if isinstance(self.key_snapshot, KeySnapshotBinding)
            else KeySnapshotBinding.from_dict(self.key_snapshot)
        )
        registry = (
            self.registry_snapshot
            if isinstance(self.registry_snapshot, RegistrySnapshotBinding)
            else RegistrySnapshotBinding.from_dict(self.registry_snapshot)
        )
        object.__setattr__(self, "key_snapshot", key)
        object.__setattr__(self, "registry_snapshot", registry)
        object.__setattr__(
            self,
            "required_artifact_refs",
            _references(
                self.required_artifact_refs, "required_artifact_refs", "artifactref"
            ),
        )
        object.__setattr__(
            self,
            "required_event_refs",
            _references(self.required_event_refs, "required_event_refs", "eventref"),
        )
        object.__setattr__(
            self,
            "required_evidence_refs",
            _references(
                self.required_evidence_refs, "required_evidence_refs", "evidenceref"
            ),
        )
        failure = _timestamp(self.simulated_failure_at, "simulated_failure_at")
        restore = _timestamp(self.restore_point_at, "restore_point_at")
        planned = _timestamp(self.planned_at, "planned_at")
        if restore > failure or planned > failure:
            raise DisasterRecoveryContractError("rehearsal timestamps are inconsistent")
        _reference(self.executor_ref, "executor_ref", "principalref")
        _reference(self.reviewer_ref, "reviewer_ref", "reviewerref")
        if self.executor_ref.split(":", 1)[1] == self.reviewer_ref.split(":", 1)[1]:
            raise DisasterRecoveryContractError("rehearsal executor cannot review its own work")
        plan_id, digest = _identity("DRP", self.KIND, self._body())
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "backup_manifest_id": self.backup_manifest_id,
            "backup_manifest_sha256": self.backup_manifest_sha256,
            "backup_ref": self.backup_ref,
            "backup_version": self.backup_version,
            "effects": dict(NO_EFFECTS),
            "executor_ref": self.executor_ref,
            "key_snapshot": self.key_snapshot.to_dict(),
            "kind": self.KIND,
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
            "planned_at": self.planned_at,
            "rehearsal_version": self.rehearsal_version,
            "registry_snapshot": self.registry_snapshot.to_dict(),
            "required_artifact_refs": list(self.required_artifact_refs),
            "required_event_refs": list(self.required_event_refs),
            "required_evidence_refs": list(self.required_evidence_refs),
            "restore_point_at": self.restore_point_at,
            "reviewer_ref": self.reviewer_ref,
            "schema_version": SCHEMA_VERSION,
            "simulated_failure_at": self.simulated_failure_at,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> RestorationRehearsalPlan:
        fields = {
            "schema_version", "kind", "plan_id", "plan_sha256", "tenant_ref",
            "system_ref", "system_version", "rehearsal_version", "objective_id",
            "objective_sha256", "backup_manifest_id", "backup_manifest_sha256",
            "backup_ref", "backup_version", "key_snapshot", "registry_snapshot",
            "required_artifact_refs", "required_event_refs", "required_evidence_refs",
            "simulated_failure_at", "restore_point_at", "planned_at", "executor_ref",
            "reviewer_ref", "effects",
        }
        value = _exact(raw, fields, "restoration rehearsal plan")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryContractError("rehearsal plan discriminator is invalid")
        _verify_effects(value["effects"])
        _verify_address(value, "plan_id", "plan_sha256", "DRP", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in fields
                if key not in {"schema_version", "kind", "plan_id", "plan_sha256", "effects"}
            }
        )


@dataclass(frozen=True, slots=True)
class UnrecoverableGap:
    """Content-addressed record for a restoration continuity gap."""

    subject: GapSubject
    kind: GapKind
    expected_ref: str
    expected_sha256: str
    observed_ref: str | None
    observed_sha256: str | None
    detected_at: str
    reason: str
    gap_id: str = field(init=False)
    gap_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-gap.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", GapSubject(self.subject))
        object.__setattr__(self, "kind", GapKind(self.kind))
        namespace = {
            GapSubject.ARTIFACT: "artifactref",
            GapSubject.EVENT: "eventref",
            GapSubject.EVIDENCE: "evidenceref",
            GapSubject.KEY: "keyref",
            GapSubject.REGISTRY: "registrysnapshotref",
        }[self.subject]
        _reference(self.expected_ref, "expected_ref", namespace)
        _digest(self.expected_sha256, "expected_sha256")
        if (self.observed_ref is None) != (self.observed_sha256 is None):
            raise DisasterRecoveryContractError("observed gap binding must be complete")
        if self.observed_ref is not None:
            _reference(self.observed_ref, "observed_ref", namespace)
            _digest(self.observed_sha256, "observed_sha256")
        _timestamp(self.detected_at, "detected_at")
        if not isinstance(self.reason, str) or not 3 <= len(self.reason) <= 500:
            raise DisasterRecoveryContractError("reason must be bounded explanatory text")
        gap_id, digest = _identity("DRG", self.KIND, self._body())
        object.__setattr__(self, "gap_id", gap_id)
        object.__setattr__(self, "gap_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "detected_at": self.detected_at,
            "expected_ref": self.expected_ref,
            "expected_sha256": self.expected_sha256,
            "kind": self.kind,
            "observed_ref": self.observed_ref,
            "observed_sha256": self.observed_sha256,
            "reason": self.reason,
            "schema_version": SCHEMA_VERSION,
            "subject": self.subject,
            "type": self.KIND,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "gap_id": self.gap_id, "gap_sha256": self.gap_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> UnrecoverableGap:
        fields = {
            "schema_version", "type", "gap_id", "gap_sha256", "subject", "kind",
            "expected_ref", "expected_sha256", "observed_ref", "observed_sha256",
            "detected_at", "reason",
        }
        value = _exact(raw, fields, "unrecoverable gap")
        if value["schema_version"] != SCHEMA_VERSION or value["type"] != cls.KIND:
            raise DisasterRecoveryContractError("unrecoverable gap discriminator is invalid")
        _verify_address(value, "gap_id", "gap_sha256", "DRG", cls.KIND)
        return cls(
            subject=value["subject"], kind=value["kind"], expected_ref=value["expected_ref"],
            expected_sha256=value["expected_sha256"], observed_ref=value["observed_ref"],
            observed_sha256=value["observed_sha256"], detected_at=value["detected_at"],
            reason=value["reason"],
        )


@dataclass(frozen=True, slots=True)
class ObservedRestorationResult:
    """Signed, observed result from an externally performed rehearsal."""

    tenant_ref: str
    system_ref: str
    system_version: str
    result_version: str
    plan_id: str
    plan_sha256: str
    backup_ref: str
    backup_version: str
    key_snapshot: KeySnapshotBinding
    registry_snapshot: RegistrySnapshotBinding
    artifacts: tuple[CustodiedObjectBinding, ...]
    event_checkpoint: EventStoreCheckpoint
    evidence: tuple[CustodiedObjectBinding, ...]
    gaps: tuple[UnrecoverableGap, ...]
    started_at: str
    completed_at: str
    restore_point_at: str
    observer_ref: str
    observation_ref: str
    observation_sha256: str
    observation_signature_ref: str
    observation_signature_sha256: str
    observation_signed: bool
    restoration_claimed: bool
    result_id: str = field(init=False)
    result_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-observed-result.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        _version(self.result_version, "result_version")
        if not isinstance(self.plan_id, str) or not self.plan_id.startswith("DRP-"):
            raise DisasterRecoveryContractError("plan_id is invalid")
        _digest(self.plan_sha256, "plan_sha256")
        _reference(self.backup_ref, "backup_ref", "backupref")
        _version(self.backup_version, "backup_version")
        key = (
            self.key_snapshot
            if isinstance(self.key_snapshot, KeySnapshotBinding)
            else KeySnapshotBinding.from_dict(self.key_snapshot)
        )
        registry = (
            self.registry_snapshot
            if isinstance(self.registry_snapshot, RegistrySnapshotBinding)
            else RegistrySnapshotBinding.from_dict(self.registry_snapshot)
        )
        event = (
            self.event_checkpoint
            if isinstance(self.event_checkpoint, EventStoreCheckpoint)
            else EventStoreCheckpoint.from_dict(self.event_checkpoint)
        )
        object.__setattr__(self, "key_snapshot", key)
        object.__setattr__(self, "registry_snapshot", registry)
        object.__setattr__(self, "event_checkpoint", event)
        artifacts = _records(self.artifacts, "artifacts", CustodiedObjectBinding)
        evidence = _records(self.evidence, "evidence", CustodiedObjectBinding)
        if any(item.reference.startswith("evidenceref:") for item in artifacts):
            raise DisasterRecoveryContractError("artifacts must use artifactref references")
        if any(item.reference.startswith("artifactref:") for item in evidence):
            raise DisasterRecoveryContractError("evidence must use evidenceref references")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "evidence", evidence)
        if isinstance(self.gaps, (str, bytes)):
            raise DisasterRecoveryContractError("gaps must be a sequence")
        gaps = tuple(
            item
            if isinstance(item, UnrecoverableGap)
            else UnrecoverableGap.from_dict(item)
            for item in self.gaps
        )
        if len(gaps) > MAX_ITEMS or len({item.gap_id for item in gaps}) != len(gaps):
            raise DisasterRecoveryContractError("gaps must be a bounded unique sequence")
        object.__setattr__(self, "gaps", tuple(sorted(gaps, key=lambda item: item.gap_id)))
        started = _timestamp(self.started_at, "started_at")
        completed = _timestamp(self.completed_at, "completed_at")
        restored = _timestamp(self.restore_point_at, "restore_point_at")
        if completed < started or restored > completed:
            raise DisasterRecoveryContractError("restoration result timestamps are inconsistent")
        _reference(self.observer_ref, "observer_ref", "principalref")
        _reference(self.observation_ref, "observation_ref", "observationref")
        _digest(self.observation_sha256, "observation_sha256")
        _reference(self.observation_signature_ref, "observation_signature_ref", "signatureref")
        _digest(self.observation_signature_sha256, "observation_signature_sha256")
        if not isinstance(self.observation_signed, bool) or not isinstance(
            self.restoration_claimed, bool
        ):
            raise DisasterRecoveryContractError("observation flags must be boolean")
        if self.restoration_claimed and not self.observation_signed:
            raise DisasterRecoveryContractError(
                "restored state cannot be claimed without a signed observation"
            )
        result_id, digest = _identity("DRR", self.KIND, self._body())
        object.__setattr__(self, "result_id", result_id)
        object.__setattr__(self, "result_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifacts": [item.to_dict() for item in self.artifacts],
            "backup_ref": self.backup_ref,
            "backup_version": self.backup_version,
            "completed_at": self.completed_at,
            "effects": dict(NO_EFFECTS),
            "event_checkpoint": self.event_checkpoint.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "gaps": [item.to_dict() for item in self.gaps],
            "key_snapshot": self.key_snapshot.to_dict(),
            "kind": self.KIND,
            "observation_ref": self.observation_ref,
            "observation_sha256": self.observation_sha256,
            "observation_signature_ref": self.observation_signature_ref,
            "observation_signature_sha256": self.observation_signature_sha256,
            "observation_signed": self.observation_signed,
            "observer_ref": self.observer_ref,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "registry_snapshot": self.registry_snapshot.to_dict(),
            "restoration_claimed": self.restoration_claimed,
            "restore_point_at": self.restore_point_at,
            "result_version": self.result_version,
            "schema_version": SCHEMA_VERSION,
            "started_at": self.started_at,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_id": self.result_id, "result_sha256": self.result_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> ObservedRestorationResult:
        fields = {
            "schema_version", "kind", "result_id", "result_sha256", "tenant_ref",
            "system_ref", "system_version", "result_version", "plan_id", "plan_sha256",
            "backup_ref", "backup_version", "key_snapshot", "registry_snapshot",
            "artifacts", "event_checkpoint", "evidence", "gaps", "started_at",
            "completed_at", "restore_point_at", "observer_ref", "observation_ref",
            "observation_sha256", "observation_signature_ref",
            "observation_signature_sha256", "observation_signed", "restoration_claimed",
            "effects",
        }
        value = _exact(raw, fields, "observed restoration result")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryContractError("observed result discriminator is invalid")
        _verify_effects(value["effects"])
        _verify_address(value, "result_id", "result_sha256", "DRR", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in fields
                if key not in {"schema_version", "kind", "result_id", "result_sha256", "effects"}
            }
        )


@dataclass(frozen=True, slots=True)
class RecoveryReadinessAssessment:
    """Fail-closed readiness conclusion from bound recovery evidence."""

    tenant_ref: str
    system_ref: str
    system_version: str
    objective_id: str
    objective_sha256: str
    backup_manifest_id: str
    backup_manifest_sha256: str
    plan_id: str
    plan_sha256: str
    result_id: str
    result_sha256: str
    assessed_at: str
    reviewer_ref: str
    reviewer_signature_ref: str
    reviewer_signature_sha256: str
    observed_rpo_seconds: int
    observed_rto_seconds: int
    backup_age_seconds: int
    artifact_continuity_passed: bool
    event_continuity_passed: bool
    evidence_continuity_passed: bool
    key_binding_passed: bool
    registry_lineage_passed: bool
    status: ReadinessStatus
    reasons: tuple[str, ...]
    gap_ids: tuple[str, ...]
    assessment_id: str = field(init=False)
    assessment_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-readiness-assessment.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        for name, prefix in (
            ("objective_id", "DRO-"), ("backup_manifest_id", "DRB-"),
            ("plan_id", "DRP-"), ("result_id", "DRR-"),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith(prefix):
                raise DisasterRecoveryContractError(f"{name} is invalid")
        for name in (
            "objective_sha256", "backup_manifest_sha256", "plan_sha256", "result_sha256",
            "reviewer_signature_sha256",
        ):
            _digest(getattr(self, name), name)
        _timestamp(self.assessed_at, "assessed_at")
        _reference(self.reviewer_ref, "reviewer_ref", "reviewerref")
        _reference(self.reviewer_signature_ref, "reviewer_signature_ref", "signatureref")
        _nonnegative(self.observed_rpo_seconds, "observed_rpo_seconds")
        _nonnegative(self.observed_rto_seconds, "observed_rto_seconds")
        _nonnegative(self.backup_age_seconds, "backup_age_seconds")
        for name in (
            "artifact_continuity_passed", "event_continuity_passed",
            "evidence_continuity_passed", "key_binding_passed", "registry_lineage_passed",
        ):
            if not isinstance(getattr(self, name), bool):
                raise DisasterRecoveryContractError(f"{name} must be boolean")
        object.__setattr__(self, "status", ReadinessStatus(self.status))
        if not self.reasons or len(self.reasons) != len(set(self.reasons)):
            raise DisasterRecoveryContractError("reasons must be a non-empty unique sequence")
        if any(not isinstance(item, str) or not 2 <= len(item) <= 200 for item in self.reasons):
            raise DisasterRecoveryContractError("reasons contain invalid text")
        object.__setattr__(self, "reasons", tuple(sorted(self.reasons)))
        if len(self.gap_ids) != len(set(self.gap_ids)):
            raise DisasterRecoveryContractError("gap_ids must be unique")
        if any(not isinstance(item, str) or not item.startswith("DRG-") for item in self.gap_ids):
            raise DisasterRecoveryContractError("gap_ids contain an invalid identity")
        object.__setattr__(self, "gap_ids", tuple(sorted(self.gap_ids)))
        assessment_id, digest = _identity("DRA", self.KIND, self._body())
        object.__setattr__(self, "assessment_id", assessment_id)
        object.__setattr__(self, "assessment_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_continuity_passed": self.artifact_continuity_passed,
            "assessed_at": self.assessed_at,
            "backup_age_seconds": self.backup_age_seconds,
            "backup_manifest_id": self.backup_manifest_id,
            "backup_manifest_sha256": self.backup_manifest_sha256,
            "effects": dict(NO_EFFECTS),
            "event_continuity_passed": self.event_continuity_passed,
            "evidence_continuity_passed": self.evidence_continuity_passed,
            "gap_ids": list(self.gap_ids),
            "key_binding_passed": self.key_binding_passed,
            "kind": self.KIND,
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
            "observed_rpo_seconds": self.observed_rpo_seconds,
            "observed_rto_seconds": self.observed_rto_seconds,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "reasons": list(self.reasons),
            "registry_lineage_passed": self.registry_lineage_passed,
            "result_id": self.result_id,
            "result_sha256": self.result_sha256,
            "reviewer_ref": self.reviewer_ref,
            "reviewer_signature_ref": self.reviewer_signature_ref,
            "reviewer_signature_sha256": self.reviewer_signature_sha256,
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RecoveryReadinessAssessment:
        fields = {
            "schema_version", "kind", "assessment_id", "assessment_sha256", "tenant_ref",
            "system_ref", "system_version", "objective_id", "objective_sha256",
            "backup_manifest_id", "backup_manifest_sha256", "plan_id", "plan_sha256",
            "result_id", "result_sha256", "assessed_at", "reviewer_ref",
            "reviewer_signature_ref", "reviewer_signature_sha256", "observed_rpo_seconds",
            "observed_rto_seconds", "backup_age_seconds", "artifact_continuity_passed",
            "event_continuity_passed", "evidence_continuity_passed", "key_binding_passed",
            "registry_lineage_passed", "status", "reasons", "gap_ids", "effects",
        }
        value = _exact(raw, fields, "recovery readiness assessment")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryContractError("readiness assessment discriminator is invalid")
        _verify_effects(value["effects"])
        _verify_address(value, "assessment_id", "assessment_sha256", "DRA", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in fields
                if key
                not in {
                    "schema_version",
                    "kind",
                    "assessment_id",
                    "assessment_sha256",
                    "effects",
                }
            }
        )


def assess_recovery_readiness(
    objective: RecoveryObjective,
    backup: BackupManifest,
    plan: RestorationRehearsalPlan,
    result: ObservedRestorationResult,
    *,
    assessed_at: str,
    reviewer_ref: str,
    reviewer_signature_ref: str,
    reviewer_signature_sha256: str,
) -> RecoveryReadinessAssessment:
    """Evaluate exact recovery evidence and fail closed on every inconsistency."""

    assessed = _timestamp(assessed_at, "assessed_at")
    _reference(reviewer_ref, "reviewer_ref", "reviewerref")
    _reference(reviewer_signature_ref, "reviewer_signature_ref", "signatureref")
    _digest(reviewer_signature_sha256, "reviewer_signature_sha256")
    reviewer_identity = reviewer_ref.split(":", 1)[1]
    prohibited_reviewers = {
        objective.reviewer_ref.split(":", 1)[1],
        plan.executor_ref.split(":", 1)[1],
        result.observer_ref.split(":", 1)[1],
    }
    if reviewer_identity in prohibited_reviewers:
        raise DisasterRecoveryContractError("recovery readiness requires independent review")
    if reviewer_ref != plan.reviewer_ref:
        raise DisasterRecoveryContractError(
            "recovery readiness reviewer does not match the rehearsal plan"
        )

    expected_context = (objective.tenant_ref, objective.system_ref, objective.system_version)
    for label, record in (("backup", backup), ("plan", plan), ("result", result)):
        observed = (record.tenant_ref, record.system_ref, record.system_version)
        if observed != expected_context:
            raise DisasterRecoveryContractError(f"{label} context does not match the objective")
    if (plan.objective_id, plan.objective_sha256) != (
        objective.objective_id,
        objective.objective_sha256,
    ):
        raise DisasterRecoveryContractError("plan does not bind the objective")
    if (plan.backup_manifest_id, plan.backup_manifest_sha256) != (
        backup.manifest_id,
        backup.manifest_sha256,
    ):
        raise DisasterRecoveryContractError("plan does not bind the backup manifest")
    if (result.plan_id, result.plan_sha256) != (plan.plan_id, plan.plan_sha256):
        raise DisasterRecoveryContractError("result does not bind the rehearsal plan")
    expected_backup = (backup.backup_ref, backup.backup_version)
    if (plan.backup_ref, plan.backup_version) != expected_backup or (
        result.backup_ref,
        result.backup_version,
    ) != expected_backup:
        raise DisasterRecoveryContractError("backup identity or version binding is inconsistent")

    reasons: set[str] = set()
    if not backup.verification_passed:
        reasons.add("backup_verification_failed")
    if not backup.event_checkpoint.verification_passed:
        reasons.add("backup_event_chain_unverified")
    backup_age = int(
        (assessed - _timestamp(backup.verified_at, "backup.verified_at")).total_seconds()
    )
    if backup_age < 0:
        raise DisasterRecoveryContractError("assessment predates backup verification")
    if backup_age > objective.max_backup_age_seconds:
        reasons.add("backup_is_stale")
    if not result.observation_signed or not result.restoration_claimed:
        reasons.add("signed_restoration_observation_missing")
    if result.gaps:
        reasons.add("unrecoverable_gaps_present")
    if result.restore_point_at != plan.restore_point_at:
        reasons.add("restore_point_binding_mismatch")
    if _timestamp(plan.restore_point_at, "plan.restore_point_at") > _timestamp(
        backup.created_at, "backup.created_at"
    ):
        reasons.add("restore_point_exceeds_backup_creation")

    key_binding_passed = (
        backup.key_snapshot == plan.key_snapshot == result.key_snapshot
    )
    if not key_binding_passed:
        reasons.add("key_snapshot_mismatch")
    registry_lineage_passed = (
        backup.registry_snapshot == plan.registry_snapshot == result.registry_snapshot
    )
    if not registry_lineage_passed:
        reasons.add("registry_rollback_lineage_ambiguous")

    expected_artifacts = {item.reference: item for item in backup.artifacts}
    observed_artifacts = {item.reference: item for item in result.artifacts}
    artifact_continuity_passed = (
        expected_artifacts == observed_artifacts
        and set(objective.required_artifact_refs) <= set(expected_artifacts)
        and set(plan.required_artifact_refs) == set(objective.required_artifact_refs)
    )
    if not artifact_continuity_passed:
        reasons.add("artifact_continuity_failed")

    expected_evidence = {item.reference: item for item in backup.evidence}
    observed_evidence = {item.reference: item for item in result.evidence}
    evidence_continuity_passed = (
        expected_evidence == observed_evidence
        and set(objective.required_evidence_refs) <= set(expected_evidence)
        and set(plan.required_evidence_refs) == set(objective.required_evidence_refs)
    )
    if not evidence_continuity_passed:
        reasons.add("evidence_custody_continuity_failed")

    event_continuity_passed = (
        backup.event_checkpoint == result.event_checkpoint
        and result.event_checkpoint.verification_passed
        and backup.event_checkpoint.event_ref in objective.required_event_refs
        and set(plan.required_event_refs) == set(objective.required_event_refs)
    )
    if not event_continuity_passed:
        reasons.add("event_store_continuity_failed")

    failure_at = _timestamp(plan.simulated_failure_at, "plan.simulated_failure_at")
    restore_point = _timestamp(result.restore_point_at, "result.restore_point_at")
    completed_at = _timestamp(result.completed_at, "result.completed_at")
    observed_rpo = int((failure_at - restore_point).total_seconds())
    observed_rto = int((completed_at - failure_at).total_seconds())
    if observed_rpo < 0 or observed_rto < 0:
        raise DisasterRecoveryContractError("RPO or RTO calculation would be negative")
    if observed_rpo > objective.max_rpo_seconds:
        reasons.add("rpo_objective_violated")
    if observed_rto > objective.max_rto_seconds:
        reasons.add("rto_objective_violated")

    if reasons:
        status = ReadinessStatus.NOT_READY
    else:
        status = ReadinessStatus.CONTRACT_READY_UNVERIFIED
        reasons.add("repository_contract_only_external_rehearsal_not_qualified")

    return RecoveryReadinessAssessment(
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        system_version=objective.system_version,
        objective_id=objective.objective_id,
        objective_sha256=objective.objective_sha256,
        backup_manifest_id=backup.manifest_id,
        backup_manifest_sha256=backup.manifest_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        result_id=result.result_id,
        result_sha256=result.result_sha256,
        assessed_at=assessed_at,
        reviewer_ref=reviewer_ref,
        reviewer_signature_ref=reviewer_signature_ref,
        reviewer_signature_sha256=reviewer_signature_sha256,
        observed_rpo_seconds=observed_rpo,
        observed_rto_seconds=observed_rto,
        backup_age_seconds=backup_age,
        artifact_continuity_passed=artifact_continuity_passed,
        event_continuity_passed=event_continuity_passed,
        evidence_continuity_passed=evidence_continuity_passed,
        key_binding_passed=key_binding_passed,
        registry_lineage_passed=registry_lineage_passed,
        status=status,
        reasons=tuple(reasons),
        gap_ids=tuple(item.gap_id for item in result.gaps),
    )


__all__ = [
    "BackupManifest",
    "CustodiedObjectBinding",
    "DisasterRecoveryContractError",
    "EventStoreCheckpoint",
    "GapKind",
    "GapSubject",
    "KeySnapshotBinding",
    "NO_EFFECTS",
    "ObservedRestorationResult",
    "ReadinessStatus",
    "RecoveryObjective",
    "RecoveryReadinessAssessment",
    "RegistrySnapshotBinding",
    "RestorationRehearsalPlan",
    "SCHEMA_VERSION",
    "UnrecoverableGap",
    "assess_recovery_readiness",
    "canonical_json",
    "canonical_sha256",
]
