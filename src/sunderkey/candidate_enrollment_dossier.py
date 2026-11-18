"""Deterministic decision dossier for candidate enrollment decision D009."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import (
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .qualification_authority_decision import (
    QualificationAuthorityDecisionRecord,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

REPORT_SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.candidate-enrollment-decision-dossier.v1"
REPORT_ID_PATTERN = re.compile(r"CED-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SEMVER_PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
)
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
DECISION_ID = "D009"
RECOMMENDED_ALTERNATIVE_ID = "organization_signed_enrollment_catalog"

ENROLLMENT_BINDING_REQUIREMENTS = (
    "qualification_policy_identity",
    "specialist_profile_identity",
    "candidate_identity_and_version",
    "candidate_artifact_sha256",
    "candidate_owner_identity",
    "candidate_owner_public_key_sha256",
    "evidence_repository_logical_identity",
    "content_address_scheme",
    "enrollment_validity_window",
    "previous_enrollment_or_rotation_record",
)

SEPARATION_REQUIREMENTS = (
    "owner_key_distinct_from_qualification_authority_keys",
    "owner_key_distinct_from_reviewer_keys",
    "independent_control_review",
    "independent_assurance_review",
    "enrollment_signer_distinct_from_candidate_owner",
    "repository_credentials_excluded_from_enrollment_artifact",
)

FAIL_CLOSED_REQUIREMENTS = (
    "untrusted_self_declared_owner_rejected",
    "untrusted_self_declared_repository_rejected",
    "stale_or_rolled_back_enrollment_rejected",
    "expired_enrollment_rejected_for_live_evidence",
    "revoked_owner_key_rejected",
    "revoked_repository_identity_rejected",
    "candidate_namespace_escape_rejected",
    "unknown_rotation_predecessor_rejected",
)

ALTERNATIVES = (
    {
        "alternative_id": "organization_signed_enrollment_catalog",
        "name": "Organization signed enrollment catalog",
        "recommended": True,
        "authority_location": "organization_qualification_trust_boundary",
        "enrollment_record": "reviewed_signed_versioned_catalog",
        "operational_complexity": "moderate",
        "offline_verification": "supported",
        "independence_strength": "strong",
        "strengths": [
            "matches_the_approved_d008_offline_root_model",
            "supports_repository_review_and_release_distribution",
            "keeps_private_keys_and_repository_credentials_out_of_sunderkey",
            "provides_portable_rotation_revocation_and_rollback_protection",
        ],
        "risks": [
            "requires_disciplined_catalog_release_distribution",
            "requires_a_new_separated_enrollment_signer_key_use",
            "emergency_revocation_speed_depends_on_release_operations",
        ],
        "required_components": [
            "signed_candidate_enrollment_catalog_contract",
            "control_and_assurance_review_bindings",
            "owner_key_rotation_and_revocation_records",
            "repository_identity_rotation_and_revocation_records",
            "monotonic_version_and_expiry_enforcement",
        ],
    },
    {
        "alternative_id": "enterprise_pki_artifact_registry_binding",
        "name": "Enterprise PKI and artifact registry binding",
        "recommended": False,
        "authority_location": "enterprise_identity_and_artifact_services",
        "enrollment_record": "certificate_and_registry_identity_profile",
        "operational_complexity": "moderate",
        "offline_verification": "limited",
        "independence_strength": "strong",
        "strengths": [
            "reuses_enterprise_lifecycle_and_audit_operations",
            "centralizes_certificate_revocation",
            "can_align_with_existing_workload_identity",
        ],
        "risks": [
            "generic_certificates_may_lack_candidate_scope_semantics",
            "artifact_registry_identity_can_be_endpoint_specific",
            "offline_verification_requires_snapshot_and_revocation_exports",
            "enterprise_service_outages_can_block_live_evidence_acceptance",
        ],
        "required_components": [
            "candidate_specific_certificate_profile",
            "artifact_registry_identity_contract",
            "offline_chain_and_revocation_snapshot",
            "certificate_to_candidate_scope_validation",
            "cross_system_rotation_reconciliation",
        ],
    },
    {
        "alternative_id": "external_supply_chain_attestation_authority",
        "name": "External supply chain attestation authority",
        "recommended": False,
        "authority_location": "external_attestation_service",
        "enrollment_record": "externally_signed_identity_attestation",
        "operational_complexity": "high",
        "offline_verification": "limited",
        "independence_strength": "strong",
        "strengths": [
            "separates_enrollment_operations_from_sunderkey_operators",
            "can_scale_across_multiple_organizations",
            "may_integrate_with_existing_software_supply_chain_attestations",
        ],
        "risks": [
            "adds_external_availability_and_governance_dependencies",
            "requires_import_replay_and_freshness_controls",
            "requires_mapping_external_subjects_to_sunderkey_candidate_ids",
            "revocation_latency_depends_on_external_distribution",
        ],
        "required_components": [
            "external_attestation_profile",
            "signed_import_and_replay_contract",
            "subject_to_candidate_mapping_rules",
            "revocation_and_freshness_feed",
            "offline_snapshot_verification",
        ],
    },
    {
        "alternative_id": "deployment_local_static_allowlist",
        "name": "Deployment local static allowlist",
        "recommended": False,
        "authority_location": "deployment_local_configuration",
        "enrollment_record": "operator_managed_static_mapping",
        "operational_complexity": "low",
        "offline_verification": "supported",
        "independence_strength": "weak",
        "strengths": [
            "simple_for_isolated_development",
            "has_no_online_service_dependency",
            "supports_small_nonproduction_fixtures",
        ],
        "risks": [
            "deployments_can_diverge_without_detection",
            "local_operators_can_replace_the_expected_authority",
            "rotation_and_revocation_are_manual_and_error_prone",
            "does_not_provide_a_portable_reviewed_history",
        ],
        "required_components": [
            "local_configuration_integrity_control",
            "manual_rotation_and_revocation_runbook",
            "deployment_specific_audit_export",
            "explicit_nonproduction_restriction",
        ],
    },
)

DECISION_QUESTIONS = (
    {
        "question_id": "enrollment_authority_model",
        "prompt": "Which authority enrolls candidate owners and repositories?",
        "option_ids": [
            "organization_signed_enrollment_catalog",
            "enterprise_pki_artifact_registry_binding",
            "external_supply_chain_attestation_authority",
            "deployment_local_static_allowlist",
        ],
        "recommended_option_id": RECOMMENDED_ALTERNATIVE_ID,
    },
    {
        "question_id": "owner_key_scope",
        "prompt": "How narrowly is an owner key scoped?",
        "option_ids": [
            "exact_candidate_identity",
            "bounded_candidate_namespace",
            "specialist_profile_identity",
        ],
        "recommended_option_id": "exact_candidate_identity",
    },
    {
        "question_id": "repository_identity",
        "prompt": "How is the approved evidence repository identified?",
        "option_ids": [
            "organization_logical_repository_id",
            "enterprise_artifact_registry_identity",
            "external_evidence_service_identity",
        ],
        "recommended_option_id": "organization_logical_repository_id",
    },
    {
        "question_id": "enrollment_review",
        "prompt": "Which independent review is required before enrollment?",
        "option_ids": [
            "independent_control_and_assurance",
            "enterprise_pki_approval_only",
            "external_authority_approval_only",
        ],
        "recommended_option_id": "independent_control_and_assurance",
    },
    {
        "question_id": "rotation_model",
        "prompt": "How are owner keys and repository identities rotated?",
        "option_ids": [
            "signed_predecessor_successor_overlap",
            "immediate_replacement_without_overlap",
            "provider_managed_rotation",
        ],
        "recommended_option_id": "signed_predecessor_successor_overlap",
    },
    {
        "question_id": "revocation_distribution",
        "prompt": "How are enrollment revocations distributed?",
        "option_ids": [
            "signed_catalog_record_and_release",
            "online_revocation_feed",
            "deployment_local_removal",
        ],
        "recommended_option_id": "signed_catalog_record_and_release",
    },
    {
        "question_id": "freshness_and_rollback",
        "prompt": "How is stale enrollment state rejected?",
        "option_ids": [
            "monotonic_version_expiry_and_last_seen_digest",
            "online_current_state_lookup",
            "operator_managed_version_pin",
        ],
        "recommended_option_id": (
            "monotonic_version_expiry_and_last_seen_digest"
        ),
    },
    {
        "question_id": "enrollment_lifetime",
        "prompt": "How long does an enrollment remain authoritative?",
        "option_ids": [
            "time_bounded_with_reviewed_renewal",
            "indefinite_until_revoked",
            "single_manifest_only",
        ],
        "recommended_option_id": "time_bounded_with_reviewed_renewal",
    },
    {
        "question_id": "repository_locator_policy",
        "prompt": "What repository location data belongs in enrollment?",
        "option_ids": [
            "logical_id_and_content_address_scheme_only",
            "network_endpoint_without_credentials",
            "provider_specific_connection_profile",
        ],
        "recommended_option_id": (
            "logical_id_and_content_address_scheme_only"
        ),
    },
)

RECOMMENDATION = {
    "alternative_id": RECOMMENDED_ALTERNATIVE_ID,
    "rationale": [
        "extends_the_owner_approved_d008_repository_boundary",
        "preserves_offline_verification",
        "keeps_private_keys_endpoints_and_credentials_out_of_sunderkey",
        "supports_reviewed_rotation_revocation_and_rollback_protection",
        "provides_exact_candidate_and_repository_scope",
    ],
    "selection_state": "not_selected",
}

IMPLEMENTATION_SEQUENCE = (
    "approve_d009_enrollment_architecture_decision",
    "define_candidate_enrollment_catalog_schema",
    "define_separated_enrollment_signer_key_use",
    "define_owner_key_and_repository_identity_bindings",
    "define_rotation_and_revocation_record_schemas",
    "implement_signature_scope_expiry_and_rollback_verification",
    "integrate_verified_enrollment_with_evidence_manifest_verification",
    "add_adversarial_rotation_revocation_and_migration_tests",
)

LIMITATIONS = (
    (
        "This dossier catalogs D009 requirements and alternatives. It does "
        "not select, approve, or apply an enrollment model."
    ),
    (
        "The recommendation is design guidance, not authorization to create "
        "keys, enroll an owner, trust a repository, or accept live evidence."
    ),
    (
        "No owner, public key, repository, endpoint, credential, reviewer, "
        "signer, provider, model, tool, target, or runtime worker is chosen."
    ),
    (
        "Live evidence acceptance and live qualification remain blocked "
        "until D009 is explicitly decided and implemented."
    ),
)


def _non_negative_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise QualificationError(f"{label} must be a non-negative integer")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _catalog_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "version", "sha256"}, label)
    identifier = value.get("id")
    version = value.get("version")
    if (
        not isinstance(identifier, str)
        or IDENTIFIER_PATTERN.fullmatch(identifier) is None
    ):
        raise QualificationError(f"{label}.id is invalid")
    if not isinstance(version, str) or SEMVER_PATTERN.fullmatch(version) is None:
        raise QualificationError(f"{label}.version is invalid")
    return {
        "id": identifier,
        "version": version,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _decision_binding(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "qualification_authority_decision")
    _exact_fields(
        value,
        {"decision_id", "record_id", "sha256"},
        "qualification_authority_decision",
    )
    if value.get("decision_id") != "D008":
        raise QualificationError(
            "qualification_authority_decision.decision_id must be D008"
        )
    record_id = value.get("record_id")
    if (
        not isinstance(record_id, str)
        or re.fullmatch(r"QDR-[0-9A-F]{32}", record_id) is None
    ):
        raise QualificationError(
            "qualification_authority_decision.record_id is invalid"
        )
    return {
        "decision_id": "D008",
        "record_id": record_id,
        "sha256": _sha256(
            value.get("sha256"),
            "qualification_authority_decision.sha256",
        ),
    }


def _validate_scope(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "current_scope")
    fields = {
        "specialist_count",
        "status_counts",
        "profiles_with_qualification_chain_head",
        "checked_live_enrollment_artifact_count",
        "live_evidence_acceptance",
    }
    _exact_fields(value, fields, "current_scope")
    status_counts = _mapping(value.get("status_counts"), "current_scope.status_counts")
    statuses = {"defined", "qualified", "suspended", "revoked", "retired"}
    _exact_fields(status_counts, statuses, "current_scope.status_counts")
    parsed_counts = {
        status: _non_negative_integer(
            status_counts.get(status),
            f"current_scope.status_counts.{status}",
        )
        for status in sorted(statuses)
    }
    specialist_count = _non_negative_integer(
        value.get("specialist_count"),
        "current_scope.specialist_count",
    )
    if sum(parsed_counts.values()) != specialist_count:
        raise QualificationError(
            "current_scope status counts do not match specialist_count"
        )
    chain_heads = _non_negative_integer(
        value.get("profiles_with_qualification_chain_head"),
        "current_scope.profiles_with_qualification_chain_head",
    )
    if chain_heads > specialist_count:
        raise QualificationError(
            "current_scope qualification chain head count is invalid"
        )
    if value.get("checked_live_enrollment_artifact_count") != 0:
        raise QualificationError(
            "current_scope checked live enrollment artifact count must be zero"
        )
    if value.get("live_evidence_acceptance") != "blocked_by_d009":
        raise QualificationError(
            "current_scope live evidence acceptance must be blocked by D009"
        )
    return {
        "specialist_count": specialist_count,
        "status_counts": parsed_counts,
        "profiles_with_qualification_chain_head": chain_heads,
        "checked_live_enrollment_artifact_count": 0,
        "live_evidence_acceptance": "blocked_by_d009",
    }


def _require_exact(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        raise QualificationError(f"{label} does not match the D009 contract")


@dataclass(frozen=True)
class CandidateEnrollmentDecisionDossier:
    """Self-identifying, non-deciding D009 requirements and alternatives."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentDecisionDossier:
        value = _mapping(raw, "candidate enrollment decision dossier")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "decision_effect",
            "decision_id",
            "registry",
            "capability_catalog",
            "qualification_standard",
            "qualification_authority_decision",
            "current_scope",
            "nonnegotiable_requirements",
            "alternatives",
            "decision_questions",
            "recommendation",
            "implementation_sequence_after_decision",
            "limitations",
        }
        _exact_fields(value, fields, "candidate enrollment decision dossier")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Candidate enrollment dossier schema version is invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
        ):
            raise QualificationError(
                "Candidate enrollment dossier report ID is invalid"
            )
        _sha256(report_sha256, "report_sha256")
        if value.get("status") != "decision_required":
            raise QualificationError(
                "Candidate enrollment dossier status must be decision_required"
            )
        if value.get("decision_effect") != "none":
            raise QualificationError(
                "Candidate enrollment dossier decision effect must be none"
            )
        if value.get("decision_id") != DECISION_ID:
            raise QualificationError(
                "Candidate enrollment dossier decision ID must be D009"
            )
        _catalog_binding(value.get("registry"), "registry")
        _catalog_binding(value.get("capability_catalog"), "capability_catalog")
        _catalog_binding(
            value.get("qualification_standard"),
            "qualification_standard",
        )
        _decision_binding(value.get("qualification_authority_decision"))
        _validate_scope(value.get("current_scope"))
        _require_exact(
            value.get("nonnegotiable_requirements"),
            {
                "enrollment_binding_requirements": list(
                    ENROLLMENT_BINDING_REQUIREMENTS
                ),
                "separation_requirements": list(SEPARATION_REQUIREMENTS),
                "fail_closed_requirements": list(FAIL_CLOSED_REQUIREMENTS),
                "private_key_storage_in_sunderkey": False,
                "repository_credentials_in_enrollment": False,
                "offline_verification_required": True,
            },
            "nonnegotiable_requirements",
        )
        _require_exact(value.get("alternatives"), list(ALTERNATIVES), "alternatives")
        _require_exact(
            value.get("decision_questions"),
            list(DECISION_QUESTIONS),
            "decision_questions",
        )
        _require_exact(value.get("recommendation"), RECOMMENDATION, "recommendation")
        _require_exact(
            value.get("implementation_sequence_after_decision"),
            list(IMPLEMENTATION_SEQUENCE),
            "implementation_sequence_after_decision",
        )
        _require_exact(value.get("limitations"), list(LIMITATIONS), "limitations")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_sha256 != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError(
                "Candidate enrollment dossier hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Candidate enrollment dossier document is invalid"
            )
        return value


def assess_candidate_enrollment_decision(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    authority_decision: QualificationAuthorityDecisionRecord,
) -> CandidateEnrollmentDecisionDossier:
    """Build the D009 choice set without making or applying a decision."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(standard, QualificationStandard):
        raise QualificationError("standard must be a QualificationStandard")
    if not isinstance(
        authority_decision,
        QualificationAuthorityDecisionRecord,
    ):
        raise QualificationError(
            "authority_decision must be a QualificationAuthorityDecisionRecord"
        )
    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
    standard = standard.revalidated(registry, capability_catalog)
    authority_decision = QualificationAuthorityDecisionRecord.from_dict(
        authority_decision.to_dict()
    )
    registry_binding = {
        "id": registry.catalog_id,
        "version": registry.catalog_version,
        "sha256": _canonical_sha256(registry.to_dict()),
    }
    capability_binding = {
        "id": capability_catalog.catalog_id,
        "version": capability_catalog.catalog_version,
        "sha256": capability_catalog.canonical_sha256,
    }
    standard_binding = {
        "id": standard.standard_id,
        "version": standard.standard_version,
        "sha256": standard.canonical_sha256,
    }
    specialists = tuple(
        profile
        for profile in registry.profiles
        if profile.kind is ProfileKind.SPECIALIST
    )
    statuses = ("defined", "qualified", "suspended", "revoked", "retired")
    status_counts = {
        status: sum(profile.status == status for profile in specialists)
        for status in statuses
    }
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "decision_required",
        "decision_effect": "none",
        "decision_id": DECISION_ID,
        "registry": registry_binding,
        "capability_catalog": capability_binding,
        "qualification_standard": standard_binding,
        "qualification_authority_decision": {
            "decision_id": "D008",
            "record_id": authority_decision.record_id,
            "sha256": authority_decision.record_sha256,
        },
        "current_scope": {
            "specialist_count": len(specialists),
            "status_counts": status_counts,
            "profiles_with_qualification_chain_head": sum(
                profile.qualification is not None for profile in specialists
            ),
            "checked_live_enrollment_artifact_count": 0,
            "live_evidence_acceptance": "blocked_by_d009",
        },
        "nonnegotiable_requirements": {
            "enrollment_binding_requirements": list(
                ENROLLMENT_BINDING_REQUIREMENTS
            ),
            "separation_requirements": list(SEPARATION_REQUIREMENTS),
            "fail_closed_requirements": list(FAIL_CLOSED_REQUIREMENTS),
            "private_key_storage_in_sunderkey": False,
            "repository_credentials_in_enrollment": False,
            "offline_verification_required": True,
        },
        "alternatives": copy.deepcopy(list(ALTERNATIVES)),
        "decision_questions": copy.deepcopy(list(DECISION_QUESTIONS)),
        "recommendation": copy.deepcopy(RECOMMENDATION),
        "implementation_sequence_after_decision": list(
            IMPLEMENTATION_SEQUENCE
        ),
        "limitations": list(LIMITATIONS),
    }
    report_hash = _report_hash(body)
    return CandidateEnrollmentDecisionDossier.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def load_candidate_enrollment_decision_dossier(
    path: str | Path,
) -> CandidateEnrollmentDecisionDossier:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment decision dossier: {resolved}"
        ) from exc
    return CandidateEnrollmentDecisionDossier.from_dict(raw)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "CED-" + report_hash.removeprefix("sha256:")[:32].upper()


__all__ = [
    "CandidateEnrollmentDecisionDossier",
    "assess_candidate_enrollment_decision",
    "load_candidate_enrollment_decision_dossier",
]
