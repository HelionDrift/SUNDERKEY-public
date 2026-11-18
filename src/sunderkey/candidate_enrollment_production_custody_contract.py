"""Provider-neutral production custody contracts authorized by D012."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, is_dataclass
from dataclasses import fields as dataclass_fields
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .candidate_enrollment_production_custody_decision import (
    PROHIBITED_EFFECTS,
    CandidateEnrollmentProductionCustodyDecisionRecord,
    verify_candidate_enrollment_production_custody_decision_record,
)
from .candidate_enrollment_production_custody_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    NONNEGOTIABLE_REQUIREMENTS,
    RECOMMENDED_OPTIONS,
    REQUIRED_OWNER_INPUTS,
    CandidateEnrollmentProductionCustodyDossier,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
CONTRACT_DOMAIN = "sunderkey.production-custody-provider-contract.d012.v1"

EXPECTED_DOSSIER_ID = "PCD-28D9E7D3DECE4A4103645CE0F0828D9A"
EXPECTED_DOSSIER_SHA256 = (
    "sha256:28d9e7d3dece4a4103645ce0f0828d9a5ffec5c2541f408f077d7613ae6c5667"
)
EXPECTED_DECISION_ID = "PCR-A2ACC5733A815AA349F5F6B7F1FBE5A3"
EXPECTED_DECISION_SHA256 = (
    "sha256:a2acc5733a815aa349f5f6b7f1fbe5a30881446417a9268923e96dea3c1624de"
)

AUTHORIZED_IMPLEMENTATION_STEP = (
    "define_production_custody_provider_interfaces_and_conformance_suite"
)

_CONTRACT_ID_PATTERN = re.compile(r"PCC-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_REJECTION_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,127}")
_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)

SEPARATION_REQUIREMENTS = (
    "checkpoint_ledger_and_catalog_use_distinct_least_privilege_authority_scopes",
    "ledger_and_catalog_use_separate_namespaces",
    "ledger_and_catalog_use_independent_failure_domains",
    "release_signer_private_key_remains_external_to_sunderkey_state",
    "release_head_verification_remains_independent_from_release_head_signing",
    "deployment_owner_platform_custodian_and_independent_control_are_distinct",
)

CONFORMANCE_CASE_IDS = (
    "exact_checkpoint_identity",
    "interrupted_checkpoint_replacement",
    "ledger_put_if_absent",
    "retention_lock",
    "conditional_head_cas_race",
    "ledger_lineage_integrity",
    "immutable_catalog_objects",
    "custody_separation",
    "workload_identity_lifecycle",
    "signed_head_verification",
    "audit_append_blocks_release",
    "partial_release_recovery",
)

PROVIDER_INTERFACE_DESCRIPTORS = (
    {
        "interface_id": "native_checkpoint_access",
        "protocol_class": "NativeCheckpointAccessProvider",
        "required_operations": [
            "verify_exact_service_identity",
            "protect_directory",
            "verify_directory",
            "protect_file",
            "verify_file",
            "sync_directory",
        ],
        "request_types": ["CheckpointAccessVerificationRequest"],
        "receipt_types": ["CheckpointAccessVerificationReceipt"],
        "failure_mode": "fail_closed_without_insecure_fallback",
    },
    {
        "interface_id": "retention_locked_ledger_objects",
        "protocol_class": "RetentionLockedLedgerObjectProvider",
        "required_operations": [
            "put_if_absent",
            "read_verified",
            "read_retention_state",
        ],
        "request_types": [
            "LedgerObjectPutRequest",
            "LedgerObjectReadRequest",
            "RetentionStateReadRequest",
        ],
        "receipt_types": [
            "LedgerObjectPutReceipt",
            "LedgerObjectReadReceipt",
            "RetentionStateReadReceipt",
        ],
        "failure_mode": "reject_overwrite_deletion_gap_and_unlocked_retention",
    },
    {
        "interface_id": "conditional_ledger_head",
        "protocol_class": "ConditionalLedgerHeadProvider",
        "required_operations": ["read_head", "compare_and_swap_head"],
        "request_types": [
            "LedgerHeadReadRequest",
            "LedgerHeadCompareAndSwapRequest",
        ],
        "receipt_types": [
            "LedgerHeadReadReceipt",
            "LedgerHeadCompareAndSwapReceipt",
        ],
        "failure_mode": "reject_stale_head_fork_gap_and_nonmonotonic_advance",
    },
    {
        "interface_id": "immutable_catalog_objects",
        "protocol_class": "ImmutableCatalogObjectProvider",
        "required_operations": ["put_sha256_object", "read_sha256_object"],
        "request_types": ["CatalogObjectPutRequest", "CatalogObjectReadRequest"],
        "receipt_types": ["CatalogObjectPutReceipt", "CatalogObjectReadReceipt"],
        "failure_mode": "reject_overwrite_digest_mismatch_and_mutable_alias",
    },
    {
        "interface_id": "workload_identity",
        "protocol_class": "WorkloadIdentityVerifier",
        "required_operations": [
            "verify_identity",
            "verify_scope",
            "verify_freshness",
        ],
        "request_types": ["WorkloadIdentityVerificationRequest"],
        "receipt_types": ["WorkloadIdentityVerificationReceipt"],
        "failure_mode": "reject_unknown_stale_or_overprivileged_identity",
    },
    {
        "interface_id": "release_head_signing",
        "protocol_class": "ReleaseHeadSigner",
        "required_operations": ["sign_head"],
        "request_types": ["ReleaseHeadSigningRequest"],
        "receipt_types": ["ReleaseHeadSigningReceipt"],
        "failure_mode": "reject_unknown_key_disallowed_algorithm_and_signing_failure",
    },
    {
        "interface_id": "release_head_verification",
        "protocol_class": "ReleaseHeadVerifier",
        "required_operations": ["verify_signed_head"],
        "request_types": ["ReleaseHeadVerificationRequest"],
        "receipt_types": ["ReleaseHeadVerificationReceipt"],
        "failure_mode": "reject_unknown_signer_bad_signature_fork_and_rollback",
    },
    {
        "interface_id": "release_audit",
        "protocol_class": "ReleaseAuditSink",
        "required_operations": ["append_audit_event"],
        "request_types": ["ReleaseAuditAppendRequest"],
        "receipt_types": ["ReleaseAuditAppendReceipt"],
        "failure_mode": "audit_append_failure_blocks_release",
    },
)


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")


def _sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical SHA-256 digest")


def _timestamp(value: str, label: str) -> None:
    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc


def _positive_size(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")


def _require_bytes_digest(payload: bytes, expected: str, label: str) -> None:
    if not isinstance(payload, bytes):
        raise ValueError(f"{label} must be bytes")
    actual = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ValueError(f"{label} digest does not match")


def _provider_public_summary(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_sha256": "sha256:" + hashlib.sha256(value).hexdigest()}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _provider_public_summary(getattr(value, field.name))
            for field in dataclass_fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): _provider_public_summary(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_provider_public_summary(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ValueError("Provider rejection subject is unsupported")


def provider_subject_sha256(value: Any) -> str:
    """Return the canonical public digest used to bind a provider rejection."""

    return _canonical_sha256(_provider_public_summary(value))


class ProviderPolicyRejection(QualificationError):
    """Typed, request-bound rejection returned by a custody provider."""

    def __init__(
        self,
        rejection_code: str,
        request_id: str,
        subject_sha256: str,
    ) -> None:
        if (
            not isinstance(rejection_code, str)
            or _REJECTION_CODE_PATTERN.fullmatch(rejection_code) is None
        ):
            raise ValueError("rejection_code is invalid")
        _identifier(request_id, "request_id")
        _sha256(subject_sha256, "subject_sha256")
        self.rejection_code = rejection_code
        self.request_id = request_id
        self.subject_sha256 = subject_sha256
        super().__init__("Custody provider rejected the bound request")


@dataclass(frozen=True)
class CheckpointResourceDescriptor:
    """Provider-neutral identity for one protected checkpoint resource."""

    resource_id: str
    namespace_id: str
    failure_domain_id: str
    service_identity_scope_id: str

    def __post_init__(self) -> None:
        for field, value in (
            ("resource_id", self.resource_id),
            ("namespace_id", self.namespace_id),
            ("failure_domain_id", self.failure_domain_id),
            ("service_identity_scope_id", self.service_identity_scope_id),
        ):
            _identifier(value, field)


@dataclass(frozen=True)
class LedgerObjectDescriptor:
    """Immutable ledger object metadata without provider coordinates."""

    object_id: str
    sha256: str
    size_bytes: int
    retention_until: str
    namespace_id: str
    failure_domain_id: str

    def __post_init__(self) -> None:
        _identifier(self.object_id, "object_id")
        _sha256(self.sha256, "sha256")
        _positive_size(self.size_bytes, "size_bytes")
        _timestamp(self.retention_until, "retention_until")
        _identifier(self.namespace_id, "namespace_id")
        _identifier(self.failure_domain_id, "failure_domain_id")


@dataclass(frozen=True)
class CatalogObjectDescriptor:
    """Content-addressed catalog object metadata without mutable aliases."""

    object_id: str
    sha256: str
    size_bytes: int
    namespace_id: str
    failure_domain_id: str

    def __post_init__(self) -> None:
        _identifier(self.object_id, "object_id")
        _sha256(self.sha256, "sha256")
        _positive_size(self.size_bytes, "size_bytes")
        _identifier(self.namespace_id, "namespace_id")
        _identifier(self.failure_domain_id, "failure_domain_id")


@dataclass(frozen=True)
class LedgerHeadDescriptor:
    """Monotonic authoritative ledger head metadata."""

    deployment_id: str
    ledger_sequence: int
    entry_id: str
    entry_sha256: str
    previous_head_sha256: str | None

    def __post_init__(self) -> None:
        _identifier(self.deployment_id, "deployment_id")
        if (
            isinstance(self.ledger_sequence, bool)
            or not isinstance(self.ledger_sequence, int)
            or self.ledger_sequence < 1
        ):
            raise ValueError("ledger_sequence must be a positive integer")
        _identifier(self.entry_id, "entry_id")
        _sha256(self.entry_sha256, "entry_sha256")
        if self.ledger_sequence == 1:
            if self.previous_head_sha256 is not None:
                raise ValueError("Initial ledger head cannot have a predecessor")
        elif self.previous_head_sha256 is None:
            raise ValueError("Non-initial ledger head requires a predecessor")
        else:
            _sha256(self.previous_head_sha256, "previous_head_sha256")


@dataclass(frozen=True)
class WorkloadIdentityDescriptor:
    """Public identity claims required for custody authorization."""

    provider_id: str
    identity_id: str
    audience: str
    scope_ids: tuple[str, ...]
    issued_at: str
    expires_at: str
    rotation_id: str
    rotation_state: str

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "provider_id")
        _identifier(self.identity_id, "identity_id")
        _identifier(self.audience, "audience")
        if not isinstance(self.scope_ids, tuple) or not self.scope_ids:
            raise ValueError("scope_ids must be a non-empty tuple")
        if len(set(self.scope_ids)) != len(self.scope_ids):
            raise ValueError("scope_ids must be unique")
        for scope_id in self.scope_ids:
            _identifier(scope_id, "scope_id")
        _timestamp(self.issued_at, "issued_at")
        _timestamp(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        _identifier(self.rotation_id, "rotation_id")
        if self.rotation_state not in {"current", "retiring"}:
            raise ValueError("rotation_state is invalid")


@dataclass(frozen=True)
class SignedReleaseHeadDescriptor:
    """Signed public release head material suitable for offline verification."""

    head: LedgerHeadDescriptor
    signer_key_id: str
    offline_root_authorization_sha256: str
    signing_algorithm: str
    signature: bytes
    signed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.head, LedgerHeadDescriptor):
            raise ValueError("head must be a LedgerHeadDescriptor")
        _identifier(self.signer_key_id, "signer_key_id")
        _sha256(
            self.offline_root_authorization_sha256,
            "offline_root_authorization_sha256",
        )
        _identifier(self.signing_algorithm, "signing_algorithm")
        if not isinstance(self.signature, bytes) or not self.signature:
            raise ValueError("signature must be non-empty bytes")
        _timestamp(self.signed_at, "signed_at")


@dataclass(frozen=True)
class ReleaseAuditEventDescriptor:
    """Public audit event metadata for one custody transition."""

    event_id: str
    event_type: str
    artifact_sha256: str
    actor_identity_id: str
    occurred_at: str

    def __post_init__(self) -> None:
        _identifier(self.event_id, "event_id")
        _identifier(self.event_type, "event_type")
        _sha256(self.artifact_sha256, "artifact_sha256")
        _identifier(self.actor_identity_id, "actor_identity_id")
        _timestamp(self.occurred_at, "occurred_at")


@dataclass(frozen=True)
class CheckpointAccessVerificationRequest:
    request_id: str
    resource: CheckpointResourceDescriptor
    expected_identity_id: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.resource, CheckpointResourceDescriptor):
            raise ValueError("resource must be a CheckpointResourceDescriptor")
        _identifier(self.expected_identity_id, "expected_identity_id")


@dataclass(frozen=True)
class CheckpointAccessVerificationReceipt:
    request_id: str
    resource_id: str
    expected_identity_id: str
    observed_identity_id: str
    identity_verified: bool
    least_privilege_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.resource_id, "resource_id")
        _identifier(self.expected_identity_id, "expected_identity_id")
        _identifier(self.observed_identity_id, "observed_identity_id")
        if self.identity_verified is not True or self.least_privilege_verified is not True:
            raise ValueError("Checkpoint access receipt must represent verified access")


@dataclass(frozen=True)
class LedgerObjectPutRequest:
    request_id: str
    object: LedgerObjectDescriptor
    payload: bytes

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, LedgerObjectDescriptor):
            raise ValueError("object must be a LedgerObjectDescriptor")
        _require_bytes_digest(self.payload, self.object.sha256, "payload")


@dataclass(frozen=True)
class LedgerObjectPutReceipt:
    request_id: str
    object: LedgerObjectDescriptor
    write_status: str
    retention_lock_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, LedgerObjectDescriptor):
            raise ValueError("object must be a LedgerObjectDescriptor")
        if self.write_status not in {"created", "already_present_same_digest"}:
            raise ValueError("write_status is invalid")
        if self.retention_lock_verified is not True:
            raise ValueError("retention_lock_verified must be true")


@dataclass(frozen=True)
class LedgerObjectReadRequest:
    request_id: str
    object_id: str
    expected_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.object_id, "object_id")
        _sha256(self.expected_sha256, "expected_sha256")


@dataclass(frozen=True)
class LedgerObjectReadReceipt:
    request_id: str
    object: LedgerObjectDescriptor
    payload: bytes
    digest_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, LedgerObjectDescriptor):
            raise ValueError("object must be a LedgerObjectDescriptor")
        _require_bytes_digest(self.payload, self.object.sha256, "payload")
        if self.digest_verified is not True:
            raise ValueError("digest_verified must be true")


@dataclass(frozen=True)
class RetentionStateReadRequest:
    request_id: str
    object_id: str
    required_retention_until: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.object_id, "object_id")
        _timestamp(self.required_retention_until, "required_retention_until")


@dataclass(frozen=True)
class RetentionStateReadReceipt:
    request_id: str
    object: LedgerObjectDescriptor
    retention_lock_verified: bool
    deletion_protection_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, LedgerObjectDescriptor):
            raise ValueError("object must be a LedgerObjectDescriptor")
        if (
            self.retention_lock_verified is not True
            or self.deletion_protection_verified is not True
        ):
            raise ValueError("Retention state receipt must represent protected storage")


@dataclass(frozen=True)
class LedgerHeadReadRequest:
    request_id: str
    deployment_id: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.deployment_id, "deployment_id")


@dataclass(frozen=True)
class LedgerHeadReadReceipt:
    request_id: str
    head: LedgerHeadDescriptor | None

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if self.head is not None and not isinstance(self.head, LedgerHeadDescriptor):
            raise ValueError("head must be a LedgerHeadDescriptor or None")


@dataclass(frozen=True)
class LedgerHeadCompareAndSwapRequest:
    request_id: str
    expected_head_sha256: str | None
    proposed_head: LedgerHeadDescriptor

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.proposed_head, LedgerHeadDescriptor):
            raise ValueError("proposed_head must be a LedgerHeadDescriptor")
        if self.expected_head_sha256 is None:
            if self.proposed_head.ledger_sequence != 1:
                raise ValueError("Only an initial head can have no expected head")
        else:
            _sha256(self.expected_head_sha256, "expected_head_sha256")
            if self.proposed_head.previous_head_sha256 != self.expected_head_sha256:
                raise ValueError("Proposed head predecessor does not match expected head")


@dataclass(frozen=True)
class LedgerHeadCompareAndSwapReceipt:
    request_id: str
    head: LedgerHeadDescriptor
    compare_and_swap_status: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.head, LedgerHeadDescriptor):
            raise ValueError("head must be a LedgerHeadDescriptor")
        if self.compare_and_swap_status not in {
            "advanced",
            "already_current_same_digest",
        }:
            raise ValueError("compare_and_swap_status is invalid")


@dataclass(frozen=True)
class CatalogObjectPutRequest:
    request_id: str
    object: CatalogObjectDescriptor
    payload: bytes

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, CatalogObjectDescriptor):
            raise ValueError("object must be a CatalogObjectDescriptor")
        _require_bytes_digest(self.payload, self.object.sha256, "payload")


@dataclass(frozen=True)
class CatalogObjectPutReceipt:
    request_id: str
    object: CatalogObjectDescriptor
    write_status: str
    immutable_storage_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, CatalogObjectDescriptor):
            raise ValueError("object must be a CatalogObjectDescriptor")
        if self.write_status not in {"created", "already_present_same_digest"}:
            raise ValueError("write_status is invalid")
        if self.immutable_storage_verified is not True:
            raise ValueError("immutable_storage_verified must be true")


@dataclass(frozen=True)
class CatalogObjectReadRequest:
    request_id: str
    object_id: str
    expected_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.object_id, "object_id")
        _sha256(self.expected_sha256, "expected_sha256")


@dataclass(frozen=True)
class CatalogObjectReadReceipt:
    request_id: str
    object: CatalogObjectDescriptor
    payload: bytes
    digest_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.object, CatalogObjectDescriptor):
            raise ValueError("object must be a CatalogObjectDescriptor")
        _require_bytes_digest(self.payload, self.object.sha256, "payload")
        if self.digest_verified is not True:
            raise ValueError("digest_verified must be true")


@dataclass(frozen=True)
class WorkloadIdentityVerificationRequest:
    request_id: str
    identity: WorkloadIdentityDescriptor
    required_provider_id: str
    required_scope_ids: tuple[str, ...]
    required_rotation_id: str
    required_rotation_state: str
    verified_at: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.identity, WorkloadIdentityDescriptor):
            raise ValueError("identity must be a WorkloadIdentityDescriptor")
        _identifier(self.required_provider_id, "required_provider_id")
        if self.identity.provider_id != self.required_provider_id:
            raise ValueError("Identity provider does not match the required provider")
        if not isinstance(self.required_scope_ids, tuple) or not self.required_scope_ids:
            raise ValueError("required_scope_ids must be a non-empty tuple")
        if len(set(self.required_scope_ids)) != len(self.required_scope_ids):
            raise ValueError("required_scope_ids must be unique")
        for scope_id in self.required_scope_ids:
            _identifier(scope_id, "required_scope_id")
        if not set(self.required_scope_ids).issubset(self.identity.scope_ids):
            raise ValueError("Identity does not contain every required scope")
        _identifier(self.required_rotation_id, "required_rotation_id")
        if self.identity.rotation_id != self.required_rotation_id:
            raise ValueError("Identity rotation does not match the required rotation")
        if self.required_rotation_state != "current":
            raise ValueError("required_rotation_state must be current")
        if self.identity.rotation_state != self.required_rotation_state:
            raise ValueError("Identity rotation state is not current")
        _timestamp(self.verified_at, "verified_at")
        if not self.identity.issued_at <= self.verified_at < self.identity.expires_at:
            raise ValueError("Identity is not fresh at verified_at")


@dataclass(frozen=True)
class WorkloadIdentityVerificationReceipt:
    request_id: str
    identity: WorkloadIdentityDescriptor
    identity_verified: bool
    scope_verified: bool
    freshness_verified: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.identity, WorkloadIdentityDescriptor):
            raise ValueError("identity must be a WorkloadIdentityDescriptor")
        if (
            self.identity_verified is not True
            or self.scope_verified is not True
            or self.freshness_verified is not True
        ):
            raise ValueError("Identity receipt must represent a successful verification")


@dataclass(frozen=True)
class ReleaseHeadSigningRequest:
    request_id: str
    head: LedgerHeadDescriptor
    signer_key_id: str
    offline_root_authorization_sha256: str
    signing_algorithm: str
    requested_at: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.head, LedgerHeadDescriptor):
            raise ValueError("head must be a LedgerHeadDescriptor")
        _identifier(self.signer_key_id, "signer_key_id")
        _sha256(
            self.offline_root_authorization_sha256,
            "offline_root_authorization_sha256",
        )
        _identifier(self.signing_algorithm, "signing_algorithm")
        _timestamp(self.requested_at, "requested_at")


@dataclass(frozen=True)
class ReleaseHeadSigningReceipt:
    request_id: str
    signed_head: SignedReleaseHeadDescriptor

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.signed_head, SignedReleaseHeadDescriptor):
            raise ValueError("signed_head must be a SignedReleaseHeadDescriptor")


@dataclass(frozen=True)
class ReleaseHeadVerificationRequest:
    request_id: str
    signed_head: SignedReleaseHeadDescriptor
    expected_offline_root_authorization_sha256: str
    expected_previous_head_sha256: str | None
    verified_at: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.signed_head, SignedReleaseHeadDescriptor):
            raise ValueError("signed_head must be a SignedReleaseHeadDescriptor")
        _sha256(
            self.expected_offline_root_authorization_sha256,
            "expected_offline_root_authorization_sha256",
        )
        if (
            self.signed_head.offline_root_authorization_sha256
            != self.expected_offline_root_authorization_sha256
        ):
            raise ValueError("Signed head does not bind the expected root authorization")
        if self.expected_previous_head_sha256 is None:
            if self.signed_head.head.ledger_sequence != 1:
                raise ValueError("Only an initial head can have no expected predecessor")
        else:
            _sha256(self.expected_previous_head_sha256, "expected_previous_head_sha256")
            if (
                self.signed_head.head.previous_head_sha256
                != self.expected_previous_head_sha256
            ):
                raise ValueError("Signed head predecessor does not match expected head")
        _timestamp(self.verified_at, "verified_at")


@dataclass(frozen=True)
class ReleaseHeadVerificationReceipt:
    request_id: str
    signed_head: SignedReleaseHeadDescriptor
    signature_verified: bool
    predecessor_verified: bool
    rollback_checked: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.signed_head, SignedReleaseHeadDescriptor):
            raise ValueError("signed_head must be a SignedReleaseHeadDescriptor")
        if (
            self.signature_verified is not True
            or self.predecessor_verified is not True
            or self.rollback_checked is not True
        ):
            raise ValueError("Release head receipt must represent verified lineage")


@dataclass(frozen=True)
class ReleaseAuditAppendRequest:
    request_id: str
    event: ReleaseAuditEventDescriptor

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.event, ReleaseAuditEventDescriptor):
            raise ValueError("event must be a ReleaseAuditEventDescriptor")


@dataclass(frozen=True)
class ReleaseAuditAppendReceipt:
    request_id: str
    event: ReleaseAuditEventDescriptor
    audit_sequence: int
    append_status: str

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.event, ReleaseAuditEventDescriptor):
            raise ValueError("event must be a ReleaseAuditEventDescriptor")
        if (
            isinstance(self.audit_sequence, bool)
            or not isinstance(self.audit_sequence, int)
            or self.audit_sequence < 1
        ):
            raise ValueError("audit_sequence must be a positive integer")
        if self.append_status not in {"appended", "already_appended_same_digest"}:
            raise ValueError("append_status is invalid")


@runtime_checkable
class NativeCheckpointAccessProvider(Protocol):
    """Native checkpoint identity and access-control boundary."""

    def verify_exact_service_identity(
        self, request: CheckpointAccessVerificationRequest
    ) -> CheckpointAccessVerificationReceipt: ...

    def protect_directory(self, path: Path) -> None: ...

    def verify_directory(self, path: Path) -> None: ...

    def protect_file(self, path: Path) -> None: ...

    def verify_file(self, path: Path) -> None: ...

    def sync_directory(self, path: Path) -> None: ...


@runtime_checkable
class RetentionLockedLedgerObjectProvider(Protocol):
    """Retention-locked immutable ledger object boundary."""

    def put_if_absent(self, request: LedgerObjectPutRequest) -> LedgerObjectPutReceipt: ...

    def read_verified(self, request: LedgerObjectReadRequest) -> LedgerObjectReadReceipt: ...

    def read_retention_state(
        self, request: RetentionStateReadRequest
    ) -> RetentionStateReadReceipt: ...


@runtime_checkable
class ConditionalLedgerHeadProvider(Protocol):
    """Compare-and-swap ledger head boundary."""

    def read_head(self, request: LedgerHeadReadRequest) -> LedgerHeadReadReceipt: ...

    def compare_and_swap_head(
        self, request: LedgerHeadCompareAndSwapRequest
    ) -> LedgerHeadCompareAndSwapReceipt: ...


@runtime_checkable
class ImmutableCatalogObjectProvider(Protocol):
    """Immutable SHA-256 addressed catalog object boundary."""

    def put_sha256_object(
        self, request: CatalogObjectPutRequest
    ) -> CatalogObjectPutReceipt: ...

    def read_sha256_object(
        self, request: CatalogObjectReadRequest
    ) -> CatalogObjectReadReceipt: ...


@runtime_checkable
class WorkloadIdentityVerifier(Protocol):
    """Exact workload identity, scope, and freshness verification boundary."""

    def verify_identity(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt: ...

    def verify_scope(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt: ...

    def verify_freshness(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt: ...


@runtime_checkable
class ReleaseHeadSigner(Protocol):
    """External release head signing boundary."""

    def sign_head(self, request: ReleaseHeadSigningRequest) -> ReleaseHeadSigningReceipt: ...


@runtime_checkable
class ReleaseHeadVerifier(Protocol):
    """Independent signed release head verification boundary."""

    def verify_signed_head(
        self, request: ReleaseHeadVerificationRequest
    ) -> ReleaseHeadVerificationReceipt: ...


@runtime_checkable
class ReleaseAuditSink(Protocol):
    """Fail-closed append-only release audit boundary."""

    def append_audit_event(
        self, request: ReleaseAuditAppendRequest
    ) -> ReleaseAuditAppendReceipt: ...


def _validate_exact_source_bindings(value: dict[str, Any]) -> None:
    dossier = _mapping(value.get("source_dossier"), "source_dossier")
    _exact_fields(dossier, {"report_id", "sha256"}, "source_dossier")
    if dossier != {
        "report_id": EXPECTED_DOSSIER_ID,
        "sha256": EXPECTED_DOSSIER_SHA256,
    }:
        raise QualificationError("Production custody dossier binding is not current")
    decision = _mapping(value.get("source_decision"), "source_decision")
    _exact_fields(decision, {"record_id", "sha256"}, "source_decision")
    if decision != {
        "record_id": EXPECTED_DECISION_ID,
        "sha256": EXPECTED_DECISION_SHA256,
    }:
        raise QualificationError("Production custody decision binding is not current")


@dataclass(frozen=True)
class ProductionCustodyProviderContract:
    """Content-addressed provider-neutral D012 interface contract."""

    contract_id: str
    contract_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProductionCustodyProviderContract:
        value = _mapping(raw, "production custody provider contract")
        fields = {
            "schema_version",
            "contract_id",
            "contract_sha256",
            "source_dossier",
            "source_decision",
            "selected_architecture",
            "required_owner_inputs",
            "nonnegotiable_requirements",
            "prohibited_effects",
            "approved_next_steps",
            "implementation_authorization",
            "provider_interfaces",
            "conformance_case_ids",
            "separation_requirements",
            "contract_status",
            "provider_selected",
            "contains_provider_implementation",
            "construction_effects",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "production custody provider contract")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Production custody contract schema is invalid")
        contract_id = value.get("contract_id")
        contract_sha256 = value.get("contract_sha256")
        if (
            not isinstance(contract_id, str)
            or _CONTRACT_ID_PATTERN.fullmatch(contract_id) is None
            or not isinstance(contract_sha256, str)
            or _SHA256_PATTERN.fullmatch(contract_sha256) is None
        ):
            raise QualificationError("Production custody contract identity is invalid")
        _validate_exact_source_bindings(value)
        expected = {
            "selected_architecture": dict(RECOMMENDED_OPTIONS),
            "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
            "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
            "prohibited_effects": list(PROHIBITED_EFFECTS),
            "approved_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
            "implementation_authorization": {
                "authorized_steps": [AUTHORIZED_IMPLEMENTATION_STEP],
                "deferred_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED[1:]),
            },
            "provider_interfaces": [dict(item) for item in PROVIDER_INTERFACE_DESCRIPTORS],
            "conformance_case_ids": list(CONFORMANCE_CASE_IDS),
            "separation_requirements": list(SEPARATION_REQUIREMENTS),
            "contract_status": "provider_neutral_interfaces_defined_inactive",
            "provider_selected": False,
            "contains_provider_implementation": False,
            "construction_effects": {
                "network_call_performed": False,
                "provider_call_performed": False,
                "filesystem_mutation_performed": False,
                "sqlite_mutation_performed": False,
                "runtime_state_mutation_performed": False,
            },
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise QualificationError(f"Production custody contract {field} is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"contract_id", "contract_sha256"}
        }
        digest = _canonical_sha256({"domain": CONTRACT_DOMAIN, "contract": body})
        expected_id = "PCC-" + digest.removeprefix("sha256:")[:32].upper()
        if contract_sha256 != digest or contract_id != expected_id:
            raise QualificationError("Production custody contract hash is invalid")
        return cls(contract_id, contract_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Production custody contract is invalid")
        return value


def build_production_custody_provider_contract(
    dossier: CandidateEnrollmentProductionCustodyDossier,
    decision: CandidateEnrollmentProductionCustodyDecisionRecord,
) -> ProductionCustodyProviderContract:
    """Build the exact approved D012 interface contract without runtime effects."""

    if not isinstance(dossier, CandidateEnrollmentProductionCustodyDossier):
        raise QualificationError("dossier must be the approved D012 source dossier")
    if not isinstance(decision, CandidateEnrollmentProductionCustodyDecisionRecord):
        raise QualificationError("decision must be the approved D012 decision")
    dossier = CandidateEnrollmentProductionCustodyDossier.from_dict(dossier.to_dict())
    decision = CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(
        decision.to_dict()
    )
    if (
        dossier.report_id != EXPECTED_DOSSIER_ID
        or dossier.report_sha256 != EXPECTED_DOSSIER_SHA256
    ):
        raise QualificationError("D012 dossier is not the verified current artifact")
    if (
        decision.record_id != EXPECTED_DECISION_ID
        or decision.record_sha256 != EXPECTED_DECISION_SHA256
    ):
        raise QualificationError("D012 decision is not the verified current artifact")
    verify_candidate_enrollment_production_custody_decision_record(decision, dossier)
    document = decision.to_dict()
    expected_decision = {
        "selected_options": dict(RECOMMENDED_OPTIONS),
        "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
    }
    for field, expected in expected_decision.items():
        if document.get(field) != expected:
            raise QualificationError(f"D012 decision {field} is not the approved bundle")
    if (
        document.get("decision_status") != "approved_operator_asserted_unsigned"
        or document.get("decision_effect")
        != "production_custody_contract_implementation_authorized"
        or document.get("implementation_status") != "not_started"
        or document.get("recommendation_alignment")
        != {
            "selected_option_count": 8,
            "selected_recommended_option_count": 8,
            "all_recommended_options_selected": True,
        }
    ):
        raise QualificationError("D012 decision does not authorize this contract")
    body = {
        "schema_version": SCHEMA_VERSION,
        "source_dossier": {
            "report_id": dossier.report_id,
            "sha256": dossier.report_sha256,
        },
        "source_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "selected_architecture": dict(RECOMMENDED_OPTIONS),
        "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "approved_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        "implementation_authorization": {
            "authorized_steps": [AUTHORIZED_IMPLEMENTATION_STEP],
            "deferred_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED[1:]),
        },
        "provider_interfaces": [dict(item) for item in PROVIDER_INTERFACE_DESCRIPTORS],
        "conformance_case_ids": list(CONFORMANCE_CASE_IDS),
        "separation_requirements": list(SEPARATION_REQUIREMENTS),
        "contract_status": "provider_neutral_interfaces_defined_inactive",
        "provider_selected": False,
        "contains_provider_implementation": False,
        "construction_effects": {
            "network_call_performed": False,
            "provider_call_performed": False,
            "filesystem_mutation_performed": False,
            "sqlite_mutation_performed": False,
            "runtime_state_mutation_performed": False,
        },
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": CONTRACT_DOMAIN, "contract": body})
    return ProductionCustodyProviderContract.from_dict(
        {
            **body,
            "contract_id": "PCC-" + digest.removeprefix("sha256:")[:32].upper(),
            "contract_sha256": digest,
        }
    )


def load_production_custody_provider_contract(
    path: str | Path,
) -> ProductionCustodyProviderContract:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load custody contract: {resolved}") from exc
    return ProductionCustodyProviderContract.from_dict(raw)


__all__ = [
    "AUTHORIZED_IMPLEMENTATION_STEP",
    "CatalogObjectDescriptor",
    "CatalogObjectPutReceipt",
    "CatalogObjectPutRequest",
    "CatalogObjectReadReceipt",
    "CatalogObjectReadRequest",
    "CheckpointAccessVerificationReceipt",
    "CheckpointAccessVerificationRequest",
    "CheckpointResourceDescriptor",
    "CONFORMANCE_CASE_IDS",
    "ConditionalLedgerHeadProvider",
    "ImmutableCatalogObjectProvider",
    "LedgerHeadCompareAndSwapReceipt",
    "LedgerHeadCompareAndSwapRequest",
    "LedgerHeadDescriptor",
    "LedgerHeadReadReceipt",
    "LedgerHeadReadRequest",
    "LedgerObjectDescriptor",
    "LedgerObjectPutReceipt",
    "LedgerObjectPutRequest",
    "LedgerObjectReadReceipt",
    "LedgerObjectReadRequest",
    "NativeCheckpointAccessProvider",
    "ProductionCustodyProviderContract",
    "ProviderPolicyRejection",
    "ReleaseAuditAppendReceipt",
    "ReleaseAuditAppendRequest",
    "ReleaseAuditEventDescriptor",
    "ReleaseAuditSink",
    "ReleaseHeadSigner",
    "ReleaseHeadSigningReceipt",
    "ReleaseHeadSigningRequest",
    "ReleaseHeadVerificationReceipt",
    "ReleaseHeadVerificationRequest",
    "ReleaseHeadVerifier",
    "RetentionLockedLedgerObjectProvider",
    "RetentionStateReadReceipt",
    "RetentionStateReadRequest",
    "SignedReleaseHeadDescriptor",
    "WorkloadIdentityDescriptor",
    "WorkloadIdentityVerificationReceipt",
    "WorkloadIdentityVerificationRequest",
    "WorkloadIdentityVerifier",
    "build_production_custody_provider_contract",
    "load_production_custody_provider_contract",
    "provider_subject_sha256",
]
