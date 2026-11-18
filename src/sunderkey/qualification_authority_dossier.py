"""Deterministic decision dossier for qualification authority decision D008."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import QualificationError
from .implementation_roadmap import SpecialistImplementationRoadmapReport
from .implementation_work_packages import ImplementationWorkPackageReport
from .qualification import (
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

REPORT_SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.qualification-authority-decision-dossier.v1"
REPORT_ID_PATTERN = re.compile(r"QAD-[0-9A-F]{32}")
DECISION_ID = "D008"
RECOMMENDED_ALTERNATIVE_ID = "repository_revision_signed_manifest"

EXACT_BINDING_REQUIREMENTS = (
    "expert_profile_id_and_version",
    "capability_catalog_identity",
    "qualification_standard_identity",
    "candidate_artifact_identity",
    "candidate_blueprint_identity",
    "candidate_component_identities",
    "qualification_suite_and_scenario_set_identity",
    "evaluator_identities_and_roles",
    "signed_evidence_manifest_identity",
    "decision_issuance_and_validity_window",
    "previous_decision_and_revocation_chain",
)

AUTHORITY_OPERATIONS = (
    "approve_initial_qualification",
    "renew_qualification",
    "suspend_qualification",
    "revoke_qualification",
)

ALTERNATIVES = (
    {
        "alternative_id": "repository_revision_signed_manifest",
        "name": "Signed evidence with reviewed registry revision",
        "recommended": True,
        "authority_location": "organization_managed_repository_boundary",
        "decision_record": "signed_manifest_and_versioned_registry_revision",
        "operational_complexity": "moderate",
        "independence_strength": "strong",
        "offline_operation": "supported",
        "strengths": [
            "immutable_reviewed_history",
            "clear_candidate_and_registry_binding",
            "works_with_existing_source_review_controls",
            "does_not_require_runtime_qualification_state",
        ],
        "risks": [
            "slower_decision_turnaround",
            "requires_secure_signer_key_operations",
            "revocation_requires_registry_distribution_discipline",
        ],
        "required_components": [
            "signed_evidence_manifest_contract",
            "reviewer_attestation_contracts",
            "qualification_decision_contract",
            "qualification_trust_policy",
            "versioned_registry_revision_process",
        ],
    },
    {
        "alternative_id": "external_authority_import",
        "name": "External qualification authority with signed import",
        "recommended": False,
        "authority_location": "separate_qualification_service",
        "decision_record": "externally_signed_decision_import",
        "operational_complexity": "high",
        "independence_strength": "strong",
        "offline_operation": "limited",
        "strengths": [
            "strong_service_separation",
            "centralized_reviewer_and_key_governance",
            "scales_across_multiple_sunderkey_deployments",
        ],
        "risks": [
            "external_service_dependency",
            "synchronization_and_availability_failure_modes",
            "more_complex_trust_and_revocation_integration",
            "requires_secure_import_replay_protection",
        ],
        "required_components": [
            "external_authority_api_contract",
            "signed_decision_import_contract",
            "qualification_trust_policy",
            "import_replay_ledger",
            "revocation_synchronization_protocol",
        ],
    },
    {
        "alternative_id": "local_runtime_qualification_ledger",
        "name": "Local runtime qualification ledger",
        "recommended": False,
        "authority_location": "deployment_local_runtime",
        "decision_record": "signed_runtime_qualification_state",
        "operational_complexity": "moderate",
        "independence_strength": "weaker",
        "offline_operation": "supported",
        "strengths": [
            "fast_local_decision_application",
            "immediate_local_suspension_and_revocation",
            "natural_integration_with_runtime admission checks",
        ],
        "risks": [
            "registry_and_runtime_state_can_diverge",
            "larger mutable security boundary",
            "backup_restore and replication affect authority state",
            "higher risk of deployment-specific qualification drift",
        ],
        "required_components": [
            "signed_runtime_decision_contract",
            "qualification_trust_policy",
            "immutable_local_decision_ledger",
            "runtime_admission_integration",
            "backup_replication_and_recovery_policy",
        ],
    },
)

DECISION_QUESTIONS = (
    {
        "question_id": "authority_model",
        "prompt": "Where is the authoritative qualification decision made?",
        "option_ids": [
            "repository_revision_signed_manifest",
            "external_authority_import",
            "local_runtime_qualification_ledger",
        ],
        "recommended_option_id": RECOMMENDED_ALTERNATIVE_ID,
    },
    {
        "question_id": "trust_root_ownership",
        "prompt": "Who owns the qualification signing trust root?",
        "option_ids": [
            "organization_owned_offline_root",
            "existing_enterprise_pki",
            "external_qualification_authority_root",
        ],
        "recommended_option_id": "organization_owned_offline_root",
    },
    {
        "question_id": "reviewer_credential_issuance",
        "prompt": "How are evaluator and reviewer signing credentials issued?",
        "option_ids": [
            "role_scoped_short_lived_certificates",
            "enterprise_identity_certificates",
            "external_authority_credentials",
        ],
        "recommended_option_id": "role_scoped_short_lived_certificates",
    },
    {
        "question_id": "evidence_storage",
        "prompt": "Where is immutable qualification evidence retained?",
        "option_ids": [
            "organization_content_addressed_repository",
            "external_immutable_evidence_service",
            "deployment_local_evidence_store",
        ],
        "recommended_option_id": (
            "organization_content_addressed_repository"
        ),
    },
    {
        "question_id": "decision_application",
        "prompt": "How does an approved decision become routing state?",
        "option_ids": [
            "reviewed_versioned_registry_revision",
            "signed_external_claim_import",
            "signed_runtime_status_overlay",
        ],
        "recommended_option_id": "reviewed_versioned_registry_revision",
    },
    {
        "question_id": "emergency_suspension",
        "prompt": "Who may suspend qualification before full revocation review?",
        "option_ids": [
            "independent_control_with_signed_reason",
            "three_role_quorum",
            "external_authority_only",
        ],
        "recommended_option_id": "independent_control_with_signed_reason",
    },
    {
        "question_id": "revocation_distribution",
        "prompt": "How are suspension and revocation distributed?",
        "option_ids": [
            "signed_registry_revision_and_release",
            "signed_online_revocation_feed",
            "local_store_replication",
        ],
        "recommended_option_id": "signed_registry_revision_and_release",
    },
)


@dataclass(frozen=True)
class QualificationAuthorityDecisionDossier:
    """Self-identifying, non-deciding D008 requirements and alternatives."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationAuthorityDecisionDossier:
        value = _mapping(raw, "qualification authority decision dossier")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "decision_effect",
                "decision_id",
                "registry",
                "capability_catalog",
                "qualification_standard",
                "implementation_roadmap",
                "implementation_work_packages",
                "current_scope",
                "nonnegotiable_requirements",
                "alternatives",
                "decision_questions",
                "recommendation",
                "implementation_sequence_after_decision",
                "limitations",
            },
            "qualification authority decision dossier",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Qualification authority dossier schema version is invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Qualification authority dossier identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if (
            report_sha256 != expected_hash
            or report_id != _report_id(expected_hash)
        ):
            raise QualificationError(
                "Qualification authority dossier hash is invalid"
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
                "Qualification authority dossier document is invalid"
            )
        return value


def assess_qualification_authority_decision(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    roadmap: SpecialistImplementationRoadmapReport,
    work_packages: ImplementationWorkPackageReport,
) -> QualificationAuthorityDecisionDossier:
    """Build the D008 choice set without making or applying a decision."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(standard, QualificationStandard):
        raise QualificationError("standard must be a QualificationStandard")
    if not isinstance(roadmap, SpecialistImplementationRoadmapReport):
        raise QualificationError(
            "roadmap must be a SpecialistImplementationRoadmapReport"
        )
    if not isinstance(work_packages, ImplementationWorkPackageReport):
        raise QualificationError(
            "work_packages must be an ImplementationWorkPackageReport"
        )

    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
    standard = standard.revalidated(registry, capability_catalog)
    roadmap = SpecialistImplementationRoadmapReport.from_dict(
        roadmap.to_dict()
    )
    work_packages = ImplementationWorkPackageReport.from_dict(
        work_packages.to_dict()
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
    roadmap_document = roadmap.to_dict()
    work_package_document = work_packages.to_dict()
    if roadmap_document["registry"] != registry_binding:
        raise QualificationError(
            "Implementation roadmap registry binding is stale"
        )
    if roadmap_document["capability_catalog"] != capability_binding:
        raise QualificationError(
            "Implementation roadmap capability binding is stale"
        )
    if roadmap_document["qualification_standard"] != standard_binding:
        raise QualificationError(
            "Implementation roadmap qualification standard binding is stale"
        )
    if work_package_document["registry"] != registry_binding:
        raise QualificationError(
            "Implementation work package registry binding is stale"
        )
    if work_package_document["implementation_roadmap"] != {
        "report_id": roadmap.report_id,
        "sha256": roadmap.report_sha256,
    }:
        raise QualificationError(
            "Implementation work package roadmap binding is stale"
        )
    policy = standard.decision_policy
    summary = work_package_document["summary"]
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "decision_required",
        "decision_effect": "none",
        "decision_id": DECISION_ID,
        "registry": registry_binding,
        "capability_catalog": capability_binding,
        "qualification_standard": standard_binding,
        "implementation_roadmap": {
            "report_id": roadmap.report_id,
            "sha256": roadmap.report_sha256,
        },
        "implementation_work_packages": {
            "report_id": work_packages.report_id,
            "sha256": work_packages.report_sha256,
        },
        "current_scope": {
            "specialist_count": roadmap_document["summary"][
                "specialist_count"
            ],
            "implementation_gap_count": roadmap_document["summary"][
                "implementation_gap_count"
            ],
            "work_item_count": summary["work_item_count"],
            "authoritative_qualification_work_item_count": summary[
                "authoritative_qualification_work_item_count"
            ],
            "decision_blocked_work_item_count": summary[
                "decision_blocked_work_item_count"
            ],
        },
        "nonnegotiable_requirements": {
            "minimum_distinct_evaluators": (
                policy.minimum_distinct_evaluators
            ),
            "independent_control_review_required": (
                policy.require_independent_control_review
            ),
            "independent_assurance_review_required": (
                policy.require_independent_assurance_review
            ),
            "self_attestation_allowed": policy.allow_self_attestation,
            "qualification_validity_days": policy.qualification_validity_days,
            "authority_operations": list(AUTHORITY_OPERATIONS),
            "exact_binding_requirements": list(EXACT_BINDING_REQUIREMENTS),
            "fail_closed_requirements": [
                "distinct_candidate_owner_and_reviewers",
                "invalid_or_expired_signatures_rejected",
                "stale_candidate_or_standard_bindings_rejected",
                "suspension_and_revocation_preserve_history",
                "routing_rejects_expired_suspended_or_revoked_qualification",
                "no_unsigned_runtime_status_override",
            ],
        },
        "alternatives": list(ALTERNATIVES),
        "decision_questions": list(DECISION_QUESTIONS),
        "recommendation": {
            "alternative_id": RECOMMENDED_ALTERNATIVE_ID,
            "rationale": [
                "preserves_versioned_registry_as_routing_source",
                "keeps_qualification_state_out_of_mutable_runtime_store",
                "supports_offline_verification_and_review",
                "provides_immutable_candidate_and_evidence_binding",
                "matches_existing_externally_issued_credential_boundary",
            ],
            "selection_state": "not_selected",
        },
        "implementation_sequence_after_decision": [
            "approve_d008_architecture_decision",
            "define_qualification_trust_policy_schema",
            "define_signed_evidence_manifest_schema",
            "define_reviewer_attestation_schemas",
            "define_qualification_decision_and_revocation_schemas",
            "implement_fail_closed_signature_and_binding_validation",
            "implement_versioned_registry_revision_application",
            "add_adversarial_and_migration_test_matrix",
        ],
        "limitations": [
            (
                "This dossier catalogs requirements and alternatives. It "
                "does not select, approve, or apply an authority model."
            ),
            (
                "Recommended options are design guidance, not authorization "
                "to create keys, issue credentials, accept evidence, or "
                "change registry status."
            ),
            (
                "No reviewer, signer, trust root, evidence repository, "
                "provider, model, tool, target, or runtime worker is chosen."
            ),
            (
                "All authoritative qualification work remains blocked until "
                "D008 is explicitly decided and implemented."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return QualificationAuthorityDecisionDossier.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "QAD-" + report_hash.removeprefix("sha256:")[:32].upper()
