"""Provider-neutral lifecycle policy contract for retained evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import QualificationError
from .provider_evidence_custody_decision import (
    ProviderEvidenceCustodyDecisionRecord,
)
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp
from .validation import is_ascii_text

SCHEMA_VERSION = 1
POLICY_DOMAIN = "sunderkey.provider-evidence-lifecycle-policy.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
CLASSIFICATIONS = (
    "restricted_raw",
    "restricted_derived",
    "redacted_reviewer",
)
MINIMUM_RETENTION_SECONDS = 3600
MAXIMUM_RETENTION_SECONDS = 315_360_000
MINIMUM_DELETION_DEADLINE_SECONDS = 3600
MAXIMUM_DELETION_DEADLINE_SECONDS = 2_592_000
MAXIMUM_ACCESS_SECONDS = 86_400


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} is invalid")
    return value


def _positive_integer(
    value: Any,
    label: str,
    *,
    minimum: int = 1,
    maximum: int,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise QualificationError(f"{label} is invalid")
    return value


def _binding(raw: Any, label: str, fields: set[str]) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


def _validate_policy_document(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "provider evidence lifecycle policy")
    fields = {
        "schema_version",
        "policy_id",
        "policy_sha256",
        "policy_version",
        "custody_decision",
        "mission",
        "classification",
        "retention",
        "deletion",
        "encryption",
        "access",
        "residency",
        "content_safety",
        "created_at",
        "policy_status",
        "activation_effect",
        "runtime_effect",
    }
    _exact_fields(value, fields, "provider evidence lifecycle policy")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise QualificationError("Evidence lifecycle policy schema is invalid")
    policy_id = value.get("policy_id")
    policy_sha256 = value.get("policy_sha256")
    if not isinstance(policy_id, str) or re.fullmatch(r"ELP-[0-9A-F]{32}", policy_id) is None:
        raise QualificationError("Evidence lifecycle policy identity is invalid")
    _sha256(policy_sha256, "policy_sha256")
    _positive_integer(value.get("policy_version"), "policy_version", maximum=2**31 - 1)

    decision = _binding(
        value.get("custody_decision"),
        "custody decision",
        {"record_id", "record_sha256"},
    )
    if (
        not isinstance(decision.get("record_id"), str)
        or re.fullmatch(r"ECR-[0-9A-F]{32}", decision["record_id"]) is None
    ):
        raise QualificationError("Evidence lifecycle decision identity is invalid")
    _sha256(decision.get("record_sha256"), "custody_decision.record_sha256")

    mission = _binding(
        value.get("mission"),
        "mission binding",
        {"mission_id", "mission_sha256", "scope_reference_sha256"},
    )
    _identifier(mission.get("mission_id"), "mission.mission_id")
    _sha256(mission.get("mission_sha256"), "mission.mission_sha256")
    _sha256(
        mission.get("scope_reference_sha256"),
        "mission.scope_reference_sha256",
    )

    classification = _binding(
        value.get("classification"),
        "classification policy",
        {
            "raw_classification",
            "derived_classification",
            "redacted_classification",
            "raw_object_immutable",
            "in_place_redaction_permitted",
            "derivative_provenance_required",
        },
    )
    if (
        classification.get("raw_classification") != "restricted_raw"
        or classification.get("derived_classification") != "restricted_derived"
        or classification.get("redacted_classification") != "redacted_reviewer"
        or classification.get("raw_object_immutable") is not True
        or classification.get("in_place_redaction_permitted") is not False
        or classification.get("derivative_provenance_required") is not True
    ):
        raise QualificationError("Evidence classification policy is invalid")

    retention = _binding(
        value.get("retention"),
        "retention policy",
        {
            "retention_seconds",
            "legal_hold_authority_role",
            "independent_legal_hold_required",
            "hold_release_dual_control_required",
            "expiry_requires_deletion_transition",
        },
    )
    _positive_integer(
        retention.get("retention_seconds"),
        "retention.retention_seconds",
        minimum=MINIMUM_RETENTION_SECONDS,
        maximum=MAXIMUM_RETENTION_SECONDS,
    )
    _identifier(
        retention.get("legal_hold_authority_role"),
        "retention.legal_hold_authority_role",
    )
    if (
        retention.get("independent_legal_hold_required") is not True
        or retention.get("hold_release_dual_control_required") is not True
        or retention.get("expiry_requires_deletion_transition") is not True
    ):
        raise QualificationError("Evidence legal hold policy is invalid")

    deletion = _binding(
        value.get("deletion"),
        "deletion policy",
        {
            "method",
            "signed_tombstone_required",
            "all_versions_required",
            "replica_and_backup_key_material_required",
            "deletion_deadline_seconds",
        },
    )
    if (
        deletion.get("method") != "cryptographic_erasure"
        or deletion.get("signed_tombstone_required") is not True
        or deletion.get("all_versions_required") is not True
        or deletion.get("replica_and_backup_key_material_required") is not True
    ):
        raise QualificationError("Evidence deletion policy is invalid")
    _positive_integer(
        deletion.get("deletion_deadline_seconds"),
        "deletion.deletion_deadline_seconds",
        minimum=MINIMUM_DELETION_DEADLINE_SECONDS,
        maximum=MAXIMUM_DELETION_DEADLINE_SECONDS,
    )

    encryption = _binding(
        value.get("encryption"),
        "encryption policy",
        {
            "profile_id",
            "profile_sha256",
            "organization_kms_required",
            "separate_evidence_key_scope_required",
            "key_material_in_sunderkey_prohibited",
        },
    )
    _identifier(encryption.get("profile_id"), "encryption.profile_id")
    _sha256(encryption.get("profile_sha256"), "encryption.profile_sha256")
    if (
        encryption.get("organization_kms_required") is not True
        or encryption.get("separate_evidence_key_scope_required") is not True
        or encryption.get("key_material_in_sunderkey_prohibited") is not True
    ):
        raise QualificationError("Evidence encryption policy is invalid")

    access = _binding(
        value.get("access"),
        "access policy",
        {
            "policy_id",
            "policy_sha256",
            "dedicated_service_identity_required",
            "mission_scope_required",
            "time_bound_required",
            "maximum_access_seconds",
            "audit_required",
        },
    )
    _identifier(access.get("policy_id"), "access.policy_id")
    _sha256(access.get("policy_sha256"), "access.policy_sha256")
    _positive_integer(
        access.get("maximum_access_seconds"),
        "access.maximum_access_seconds",
        maximum=MAXIMUM_ACCESS_SECONDS,
    )
    if (
        access.get("dedicated_service_identity_required") is not True
        or access.get("mission_scope_required") is not True
        or access.get("time_bound_required") is not True
        or access.get("audit_required") is not True
    ):
        raise QualificationError("Evidence access policy is invalid")

    residency = _binding(
        value.get("residency"),
        "residency policy",
        {
            "policy_id",
            "policy_sha256",
            "allowed_region_ids",
            "minimum_replica_count",
            "unlisted_regions_prohibited",
            "recovery_drill_required",
        },
    )
    _identifier(residency.get("policy_id"), "residency.policy_id")
    _sha256(residency.get("policy_sha256"), "residency.policy_sha256")
    regions = residency.get("allowed_region_ids")
    if (
        not isinstance(regions, list)
        or not regions
        or len(regions) != len(set(regions))
        or any(
            not isinstance(region, str)
            or not is_ascii_text(region)
            or IDENTIFIER_PATTERN.fullmatch(region) is None
            for region in regions
        )
    ):
        raise QualificationError("Evidence residency regions are invalid")
    _positive_integer(
        residency.get("minimum_replica_count"),
        "residency.minimum_replica_count",
        minimum=2,
        maximum=16,
    )
    if (
        residency.get("unlisted_regions_prohibited") is not True
        or residency.get("recovery_drill_required") is not True
    ):
        raise QualificationError("Evidence residency policy is invalid")

    content_safety = _binding(
        value.get("content_safety"),
        "content safety policy",
        {
            "quarantine_required",
            "passive_type_detection_required",
            "direct_rendering_prohibited",
            "direct_execution_prohibited",
            "sandboxed_derivation_required",
        },
    )
    if any(item is not True for item in content_safety.values()):
        raise QualificationError("Evidence content safety policy is invalid")

    parse_timestamp(value.get("created_at"), "created_at")
    if (
        value.get("policy_status") != "prepared_not_activated"
        or value.get("activation_effect") != "none"
        or value.get("runtime_effect") != "none"
    ):
        raise QualificationError("Evidence lifecycle policy boundary is invalid")
    body = {key: item for key, item in value.items() if key not in {"policy_id", "policy_sha256"}}
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    expected_id = "ELP-" + digest.removeprefix("sha256:")[:32].upper()
    if policy_sha256 != digest or policy_id != expected_id:
        raise QualificationError("Evidence lifecycle policy hash is invalid")
    return json.loads(_canonical_json(value))


@dataclass(frozen=True)
class ProviderEvidenceLifecyclePolicy:
    """Prepared mission policy with no storage or activation effect."""

    policy_id: str
    policy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceLifecyclePolicy:
        value = _validate_policy_document(raw)
        return cls(
            str(value["policy_id"]),
            str(value["policy_sha256"]),
            _canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Evidence lifecycle policy is invalid")
        return value


def build_provider_evidence_lifecycle_policy(
    decision: ProviderEvidenceCustodyDecisionRecord,
    *,
    policy_version: int,
    mission_id: str,
    mission_sha256: str,
    scope_reference_sha256: str,
    retention_seconds: int,
    legal_hold_authority_role: str,
    deletion_deadline_seconds: int,
    encryption_profile_id: str,
    encryption_profile_sha256: str,
    access_policy_id: str,
    access_policy_sha256: str,
    maximum_access_seconds: int,
    residency_policy_id: str,
    residency_policy_sha256: str,
    allowed_region_ids: list[str],
    minimum_replica_count: int,
    created_at: str,
) -> ProviderEvidenceLifecyclePolicy:
    """Build a deployment-input policy without selecting or activating values."""

    decision = ProviderEvidenceCustodyDecisionRecord.from_dict(decision.to_dict())
    decision_document = decision.to_dict()
    if (
        decision_document["decision_effect"]
        != "provider_evidence_custody_contract_implementation_authorized"
        or not decision_document["recommendation_alignment"]["all_recommended_options_selected"]
    ):
        raise QualificationError("Evidence custody decision is not authorized")
    body = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": policy_version,
        "custody_decision": {
            "record_id": decision.record_id,
            "record_sha256": decision.record_sha256,
        },
        "mission": {
            "mission_id": mission_id,
            "mission_sha256": mission_sha256,
            "scope_reference_sha256": scope_reference_sha256,
        },
        "classification": {
            "raw_classification": "restricted_raw",
            "derived_classification": "restricted_derived",
            "redacted_classification": "redacted_reviewer",
            "raw_object_immutable": True,
            "in_place_redaction_permitted": False,
            "derivative_provenance_required": True,
        },
        "retention": {
            "retention_seconds": retention_seconds,
            "legal_hold_authority_role": legal_hold_authority_role,
            "independent_legal_hold_required": True,
            "hold_release_dual_control_required": True,
            "expiry_requires_deletion_transition": True,
        },
        "deletion": {
            "method": "cryptographic_erasure",
            "signed_tombstone_required": True,
            "all_versions_required": True,
            "replica_and_backup_key_material_required": True,
            "deletion_deadline_seconds": deletion_deadline_seconds,
        },
        "encryption": {
            "profile_id": encryption_profile_id,
            "profile_sha256": encryption_profile_sha256,
            "organization_kms_required": True,
            "separate_evidence_key_scope_required": True,
            "key_material_in_sunderkey_prohibited": True,
        },
        "access": {
            "policy_id": access_policy_id,
            "policy_sha256": access_policy_sha256,
            "dedicated_service_identity_required": True,
            "mission_scope_required": True,
            "time_bound_required": True,
            "maximum_access_seconds": maximum_access_seconds,
            "audit_required": True,
        },
        "residency": {
            "policy_id": residency_policy_id,
            "policy_sha256": residency_policy_sha256,
            "allowed_region_ids": allowed_region_ids,
            "minimum_replica_count": minimum_replica_count,
            "unlisted_regions_prohibited": True,
            "recovery_drill_required": True,
        },
        "content_safety": {
            "quarantine_required": True,
            "passive_type_detection_required": True,
            "direct_rendering_prohibited": True,
            "direct_execution_prohibited": True,
            "sandboxed_derivation_required": True,
        },
        "created_at": created_at,
        "policy_status": "prepared_not_activated",
        "activation_effect": "none",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    return ProviderEvidenceLifecyclePolicy.from_dict(
        {
            **body,
            "policy_id": "ELP-" + digest.removeprefix("sha256:")[:32].upper(),
            "policy_sha256": digest,
        }
    )


__all__ = [
    "CLASSIFICATIONS",
    "MAXIMUM_ACCESS_SECONDS",
    "MAXIMUM_DELETION_DEADLINE_SECONDS",
    "MAXIMUM_RETENTION_SECONDS",
    "MINIMUM_DELETION_DEADLINE_SECONDS",
    "MINIMUM_RETENTION_SECONDS",
    "ProviderEvidenceLifecyclePolicy",
    "build_provider_evidence_lifecycle_policy",
]
