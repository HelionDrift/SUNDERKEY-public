# ruff: noqa: E501
"""Deterministic D013 provider evidence custody decision dossier."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
DOSSIER_DOMAIN = "sunderkey.provider-evidence-custody.d013.v1"
_DOSSIER_ID_PATTERN = re.compile(r"ECD-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def _option(option_id: str, name: str, impact: str, recommended: bool) -> dict[str, object]:
    return {
        "option_id": option_id,
        "name": name,
        "impact": impact,
        "recommended": recommended,
    }


DECISION_QUESTIONS = (
    {
        "question_id": "artifact_repository",
        "prompt": "What substrate should retain provider evidence artifacts?",
        "recommended_option_id": "immutable_content_addressed_object_repository",
        "options": [
            _option(
                "immutable_content_addressed_object_repository",
                "Immutable content-addressed object repository",
                "Separates large evidence from the control database and supports digest identity, version retention, and independent integrity checks",
                True,
            ),
            _option(
                "postgresql_large_object_repository",
                "PostgreSQL large-object repository",
                "Can unify transactions but expands database privilege, backup, performance, and sensitive-data exposure boundaries",
                False,
            ),
            _option(
                "local_filesystem_repository",
                "Local filesystem repository",
                "Has low initial complexity but weakens multi-host durability, immutable retention, recovery evidence, and access separation",
                False,
            ),
        ],
    },
    {
        "question_id": "control_data_separation",
        "prompt": "How should evidence bytes and control-plane records be separated?",
        "recommended_option_id": "metadata_receipts_in_control_plane_bytes_in_repository",
        "options": [
            _option(
                "metadata_receipts_in_control_plane_bytes_in_repository",
                "Metadata in control plane, bytes in repository",
                "Keeps SQLite or a future PostgreSQL service free of raw evidence while retaining exact immutable repository bindings",
                True,
            ),
            _option(
                "encrypted_evidence_bytes_in_control_database",
                "Encrypted bytes in control database",
                "Reduces components but couples sensitive evidence retention to every database replica, backup, operator, and migration",
                False,
            ),
            _option(
                "repository_only_without_control_receipts",
                "Repository only without control receipts",
                "Minimizes control-plane records but prevents authoritative mission, report, retention, and deletion reconciliation",
                False,
            ),
        ],
    },
    {
        "question_id": "encryption_key_custody",
        "prompt": "How should retained evidence be encrypted and keys controlled?",
        "recommended_option_id": "envelope_encryption_organization_kms_separate_key_scope",
        "options": [
            _option(
                "envelope_encryption_organization_kms_separate_key_scope",
                "Envelope encryption with separate organization KMS scope",
                "Provides auditable key use, rotation, access separation, and cryptographic erasure without embedding key material in SUNDERKEY",
                True,
            ),
            _option(
                "repository_managed_encryption_default_key",
                "Repository-managed encryption with default key",
                "Reduces operations but weakens separation between storage administration and evidence decryption authority",
                False,
            ),
            _option(
                "application_managed_static_key",
                "Application-managed static key",
                "Avoids provider key dependencies but creates rotation, distribution, recovery, and compromise concentration risks",
                False,
            ),
        ],
    },
    {
        "question_id": "access_identity_scope",
        "prompt": "What identity and authorization model should access evidence?",
        "recommended_option_id": "dedicated_service_identity_mission_scoped_time_bounded_access",
        "options": [
            _option(
                "dedicated_service_identity_mission_scoped_time_bounded_access",
                "Dedicated identity with mission-scoped time-bounded access",
                "Limits each workload and reviewer to exact mission evidence with explicit purpose, expiry, and audit records",
                True,
            ),
            _option(
                "shared_application_identity_repository_wide_access",
                "Shared application identity with repository-wide access",
                "Simplifies credentials but turns one service compromise into broad cross-mission evidence exposure",
                False,
            ),
            _option(
                "operator_accounts_direct_repository_access",
                "Operator accounts with direct repository access",
                "Supports manual response but weakens reproducibility, least privilege, and separation between operators and evidence custodians",
                False,
            ),
        ],
    },
    {
        "question_id": "retention_legal_hold",
        "prompt": "How should retention expiration and legal hold interact?",
        "recommended_option_id": "mission_policy_retention_with_independent_legal_hold_override",
        "options": [
            _option(
                "mission_policy_retention_with_independent_legal_hold_override",
                "Mission policy retention with independent legal hold",
                "Bounds normal exposure while allowing an accountable authority to suspend expiry without silently changing the original policy",
                True,
            ),
            _option(
                "single_global_retention_period",
                "Single global retention period",
                "Is simple to administer but cannot match mission sensitivity, authorization terms, contractual duties, or jurisdiction",
                False,
            ),
            _option(
                "indefinite_retention_by_default",
                "Indefinite retention by default",
                "Maximizes later availability but produces unnecessary target-data exposure and growing breach and compliance consequences",
                False,
            ),
        ],
    },
    {
        "question_id": "deletion_accountability",
        "prompt": "How should authorized evidence deletion be completed and proven?",
        "recommended_option_id": "cryptographic_erasure_and_signed_tombstone_receipt",
        "options": [
            _option(
                "cryptographic_erasure_and_signed_tombstone_receipt",
                "Cryptographic erasure and signed tombstone receipt",
                "Removes decryptability, preserves non-sensitive accountability metadata, and makes deletion reviewable without retaining the evidence",
                True,
            ),
            _option(
                "repository_delete_with_provider_audit_log",
                "Repository delete with provider audit log",
                "Uses native operations but leaves independent verification dependent on mutable provider-side log access and retention",
                False,
            ),
            _option(
                "overwrite_or_unlink_without_receipt",
                "Overwrite or unlink without receipt",
                "May remove a local object but cannot prove replica, version, backup, key, or policy disposition",
                False,
            ),
        ],
    },
    {
        "question_id": "integrity_immutability",
        "prompt": "What controls should preserve evidence integrity after ingest?",
        "recommended_option_id": "conditional_create_version_lock_and_digest_reverification",
        "options": [
            _option(
                "conditional_create_version_lock_and_digest_reverification",
                "Conditional create, version lock, and digest reverification",
                "Rejects accidental replacement and supports scheduled proof that retained bytes still match the authenticated provider report",
                True,
            ),
            _option(
                "versioning_without_retention_lock",
                "Versioning without retention lock",
                "Retains history under ordinary operation but privileged deletion or lifecycle errors can still remove all versions",
                False,
            ),
            _option(
                "mutable_object_with_periodic_backup",
                "Mutable object with periodic backup",
                "Supports recovery from some failures but permits undetected replacement between backup and verification events",
                False,
            ),
        ],
    },
    {
        "question_id": "repository_provenance",
        "prompt": "What proof should bind repository acceptance to the authenticated report?",
        "recommended_option_id": "signed_repository_receipt_bound_to_object_version_and_identity",
        "options": [
            _option(
                "signed_repository_receipt_bound_to_object_version_and_identity",
                "Signed repository receipt bound to object version and identity",
                "Makes the accepting repository, workload identity, immutable version, digest, policy, and time independently verifiable",
                True,
            ),
            _option(
                "provider_request_identifier_only",
                "Provider request identifier only",
                "Helps support investigations but does not independently authenticate the accepted object or its policy state",
                False,
            ),
            _option(
                "application_success_flag_only",
                "Application success flag only",
                "Confirms a code path returned but supplies no durable repository, version, identity, or policy evidence",
                False,
            ),
        ],
    },
    {
        "question_id": "content_safety",
        "prompt": "How should potentially hostile evidence content be handled?",
        "recommended_option_id": "quarantine_passive_detection_and_sandboxed_derivation",
        "options": [
            _option(
                "quarantine_passive_detection_and_sandboxed_derivation",
                "Quarantine, passive detection, and sandboxed derivation",
                "Prevents direct rendering or execution while allowing separately authorized parsers to create bounded derived artifacts",
                True,
            ),
            _option(
                "antivirus_scan_then_general_access",
                "Antivirus scan followed by general access",
                "Catches known signatures but does not safely cover malformed formats, active content, parser flaws, or unknown payloads",
                False,
            ),
            _option(
                "trusted_provider_content_direct_processing",
                "Direct processing of provider content",
                "Reduces latency but incorrectly treats report provenance as proof that evidence bytes are safe to parse or render",
                False,
            ),
        ],
    },
    {
        "question_id": "classification_redaction",
        "prompt": "How should raw, derived, and redacted evidence relate?",
        "recommended_option_id": "restricted_raw_and_separately_addressed_provenance_linked_derivatives",
        "options": [
            _option(
                "restricted_raw_and_separately_addressed_provenance_linked_derivatives",
                "Restricted raw evidence with provenance-linked derivatives",
                "Preserves original integrity while allowing separately classified redacted artifacts with exact derivation records",
                True,
            ),
            _option(
                "redact_raw_object_in_place",
                "Redact the raw object in place",
                "Reduces duplicate storage but destroys the authenticated byte identity and weakens later independent review",
                False,
            ),
            _option(
                "single_classification_for_all_artifacts",
                "Single classification for all artifacts",
                "Simplifies policy but either overexposes raw data or prevents useful low-risk derivative access",
                False,
            ),
        ],
    },
    {
        "question_id": "residency_resilience",
        "prompt": "How should residency and recovery copies be constrained?",
        "recommended_option_id": "mission_allowed_regions_replication_and_integrity_drills",
        "options": [
            _option(
                "mission_allowed_regions_replication_and_integrity_drills",
                "Mission-allowed regions, replication, and integrity drills",
                "Keeps every copy within approved jurisdictions and proves restoration without weakening digest, key, or access bindings",
                True,
            ),
            _option(
                "provider_default_multiregion_replication",
                "Provider-default multiregion replication",
                "Improves availability but may place evidence or keys outside mission-approved legal and contractual boundaries",
                False,
            ),
            _option(
                "single_copy_no_recovery_replica",
                "Single copy without recovery replica",
                "Minimizes exposure and cost but makes one storage or administrative failure permanently destroy authorized evidence",
                False,
            ),
        ],
    },
    {
        "question_id": "rollout_gate",
        "prompt": "What rollout gate should precede retention of authorized target evidence?",
        "recommended_option_id": "synthetic_canary_then_explicit_authorized_environment_canary",
        "options": [
            _option(
                "synthetic_canary_then_explicit_authorized_environment_canary",
                "Synthetic canary then authorized-environment canary",
                "Proves lifecycle controls without target data before one explicitly approved mission exercises the production path",
                True,
            ),
            _option(
                "authorized_environment_canary_without_synthetic_drills",
                "Authorized-environment canary without synthetic drills",
                "Reaches realistic conditions sooner but discovers custody defects only after sensitive evidence enters the system",
                False,
            ),
            _option(
                "broad_activation_after_unit_tests",
                "Broad activation after unit tests",
                "Provides coverage fastest but skips provider conformance, recovery, deletion, access, and incident drills",
                False,
            ),
        ],
    },
)

RECOMMENDED_OPTIONS = {
    item["question_id"]: item["recommended_option_id"] for item in DECISION_QUESTIONS
}

REQUIRED_OWNER_INPUTS = (
    "selected_immutable_object_repository_and_account_boundary",
    "selected_organization_kms_and_evidence_key_hierarchy",
    "selected_workload_identity_provider_and_access_approval_roles",
    "mission_retention_classes_legal_hold_authority_and_deletion_sla",
    "allowed_residency_regions_replication_scope_and_recovery_objectives",
    "evidence_classification_redaction_and_malware_handling_policy",
    "named_evidence_custodian_security_owner_privacy_owner_and_independent_control",
)

NONNEGOTIABLE_REQUIREMENTS = (
    "raw_evidence_bytes_must_never_be_stored_in_the_control_plane_database",
    "every_retained_object_must_match_an_authenticated_provider_report_digest",
    "repository_writes_must_be_conditional_immutable_and_version_identified",
    "evidence_encryption_keys_must_remain_outside_sunderkey_records_and_logs",
    "access_must_be_least_privilege_mission_scoped_time_bounded_and_audited",
    "untrusted_content_must_not_be_directly_rendered_executed_or_parsed",
    "derived_and_redacted_artifacts_must_have_distinct_digests_and_provenance",
    "retention_legal_hold_and_deletion_must_produce_verifiable_state_transitions",
    "every_replica_backup_and_key_copy_must_obey_the_same_residency_policy",
    "repository_failure_must_fail_closed_without_local_insecure_fallback",
    "production_adapters_must_pass_ingest_access_recovery_and_deletion_drills",
    "target_evidence_ingest_must_require_separate_explicit_canary_authority",
)

AUTHORIZED_NEXT_STEPS_IF_APPROVED = (
    "define_evidence_repository_provider_interfaces_and_conformance_contracts",
    "define_authenticated_ingest_repository_and_deletion_receipt_contracts",
    "define_retention_legal_hold_classification_and_residency_policy_contracts",
    "implement_provider_neutral_quarantine_and_content_derivation_boundaries",
    "implement_atomic_metadata_commit_and_repository_reconciliation_workflow",
    "implement_integrity_access_recovery_and_cryptographic_erasure_drill_harness",
    "prepare_synthetic_evidence_custody_canary_packet",
    "prepare_separate_authorized_environment_canary_decision_packet",
)

LIMITATIONS = (
    "does_not_select_or_approve_a_d013_option",
    "does_not_select_a_repository_kms_identity_region_or_retention_period",
    "does_not_create_cloud_accounts_buckets_keys_roles_or_service_identities",
    "does_not_store_evidence_credentials_endpoints_or_target_information",
    "does_not_persist_raw_evidence_or_durable_verification_metadata",
    "does_not_parse_render_execute_redact_or_classify_evidence_content",
    "does_not_delete_hold_restore_replicate_or_export_evidence",
    "does_not_authorize_a_target_provider_or_network_operation",
    "does_not_complete_or_project_an_executor_operation",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
)

_EXPECTED_BOUNDARY = {
    "authenticated_provider_report_custody_status": "implemented",
    "transient_exact_byte_digest_verification_status": "implemented",
    "raw_evidence_retention_status": "not_implemented",
    "durable_verification_custody_status": "not_implemented",
    "repository_provider_status": "not_selected",
    "retention_and_deletion_policy_status": "not_selected",
    "hostile_content_handling_status": "not_selected",
    "authorized_target_evidence_ingest_status": "blocked",
}

_RATIONALE = [
    "separates_sensitive_evidence_bytes_from_control_plane_state",
    "preserves_exact_digest_identity_and_immutable_repository_provenance",
    "uses_organization_key_custody_and_mission_scoped_access",
    "bounds_retention_while_preserving_independent_legal_hold_authority",
    "treats_provider_evidence_as_hostile_until_safely_derived",
    "makes_deletion_recovery_and_replica_behavior_auditable",
    "proves_the_full_lifecycle_with_synthetic_data_before_target_evidence",
]


@dataclass(frozen=True)
class ProviderEvidenceCustodyDossier:
    """Content-addressed D013 choices with no selected production authority."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceCustodyDossier:
        value = _mapping(raw, "provider evidence custody dossier")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "decision_id",
            "status",
            "source_contracts",
            "current_boundary",
            "decision_questions",
            "recommendation",
            "required_owner_inputs",
            "nonnegotiable_requirements",
            "authorized_next_steps_if_approved",
            "limitations",
            "decision_effect",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "provider evidence custody dossier")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Evidence custody dossier schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or _DOSSIER_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Evidence custody dossier identity is invalid")
        if value.get("decision_id") != "D013" or value.get("status") != "decision_required":
            raise QualificationError("Evidence custody decision state is invalid")
        sources = _mapping(value.get("source_contracts"), "evidence custody sources")
        expected_sources = {
            "provider_report_authentication": "registry/schemas/collaboration-executor-provider-report-authentication-v1.schema.json",
            "provider_evidence_verification_receipt": "registry/schemas/collaboration-executor-provider-evidence-verification-receipt-v1.schema.json",
        }
        _exact_fields(sources, set(expected_sources), "evidence custody sources")
        for source_name, artifact_path in expected_sources.items():
            source = _mapping(sources.get(source_name), source_name)
            _exact_fields(source, {"artifact_path", "sha256"}, source_name)
            if (
                source.get("artifact_path") != artifact_path
                or not isinstance(source.get("sha256"), str)
                or _SHA256_PATTERN.fullmatch(str(source["sha256"])) is None
            ):
                raise QualificationError(f"Evidence custody {source_name} is invalid")
        if value.get("current_boundary") != _EXPECTED_BOUNDARY:
            raise QualificationError("Evidence custody boundary is invalid")
        if value.get("decision_questions") != [dict(item) for item in DECISION_QUESTIONS]:
            raise QualificationError("Evidence custody decision questions are invalid")
        expected_recommendation = {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": _RATIONALE,
        }
        if value.get("recommendation") != expected_recommendation:
            raise QualificationError("Evidence custody recommendation is invalid")
        expected_lists = {
            "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
            "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
            "authorized_next_steps_if_approved": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
            "limitations": list(LIMITATIONS),
        }
        for field, expected in expected_lists.items():
            if value.get(field) != expected:
                raise QualificationError(f"Evidence custody {field} is invalid")
        if (
            value.get("decision_effect") != "none"
            or value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Evidence custody dossier effect is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"report_id", "report_sha256"}
        }
        digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
        expected_id = "ECD-" + digest.removeprefix("sha256:")[:32].upper()
        if report_sha256 != digest or report_id != expected_id:
            raise QualificationError("Evidence custody dossier hash is invalid")
        return cls(report_id, report_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Evidence custody dossier is invalid")
        return value


def build_provider_evidence_custody_dossier(
    source_contracts: dict[str, dict[str, str]],
) -> ProviderEvidenceCustodyDossier:
    """Package evidence custody choices without selecting infrastructure."""

    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D013",
        "status": "decision_required",
        "source_contracts": source_contracts,
        "current_boundary": _EXPECTED_BOUNDARY,
        "decision_questions": [dict(item) for item in DECISION_QUESTIONS],
        "recommendation": {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": _RATIONALE,
        },
        "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "authorized_next_steps_if_approved": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        "limitations": list(LIMITATIONS),
        "decision_effect": "none",
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
    return ProviderEvidenceCustodyDossier.from_dict(
        {
            **body,
            "report_id": "ECD-" + digest.removeprefix("sha256:")[:32].upper(),
            "report_sha256": digest,
        }
    )


def load_provider_evidence_custody_dossier(path: str | Path) -> ProviderEvidenceCustodyDossier:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load evidence custody dossier: {resolved}") from exc
    return ProviderEvidenceCustodyDossier.from_dict(raw)


__all__ = [
    "ProviderEvidenceCustodyDossier",
    "build_provider_evidence_custody_dossier",
    "load_provider_evidence_custody_dossier",
]
