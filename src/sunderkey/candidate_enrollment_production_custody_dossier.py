"""Deterministic D012 production custody decision dossier."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_activation_implementation import (
    CandidateEnrollmentActivationImplementationReport,
)
from .candidate_enrollment_canary import CandidateEnrollmentCanaryPreparationPacket
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
DOSSIER_DOMAIN = "sunderkey.candidate-enrollment-production-custody.d012.v1"
_DOSSIER_ID_PATTERN = re.compile(r"PCD-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

DECISION_QUESTIONS = (
    {
        "question_id": "deployment_runtime",
        "prompt": "What runtime topology should host the first production canary?",
        "recommended_option_id": "single_host_native_service",
        "options": [
            {
                "option_id": "single_host_native_service",
                "name": "Single-host native service",
                "impact": (
                    "Matches the current local authority model and bounds the first canary; "
                    "the exact operating system remains an owner input"
                ),
                "recommended": True,
            },
            {
                "option_id": "managed_container_service",
                "name": "Managed container service",
                "impact": (
                    "Improves portability but makes checkpoint ACL and durable-volume "
                    "behavior dependent on the orchestration platform"
                ),
                "recommended": False,
            },
            {
                "option_id": "multi_instance_service",
                "name": "Multi-instance service",
                "impact": (
                    "Adds availability but requires distributed coordination and a separate "
                    "production database decision beyond the current SQLite boundary"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "implementation_ownership",
        "prompt": "Who should own the production custody adapter code?",
        "recommended_option_id": "sunderkey_owned_minimal_adapters",
        "options": [
            {
                "option_id": "sunderkey_owned_minimal_adapters",
                "name": "SUNDERKEY-owned minimal adapters",
                "impact": (
                    "Keeps security behavior testable in this repository while limiting "
                    "provider coupling to small explicit interfaces"
                ),
                "recommended": True,
            },
            {
                "option_id": "organization_supplied_adapters",
                "name": "Organization-supplied adapters",
                "impact": (
                    "Reuses existing infrastructure but moves implementation assurance and "
                    "release timing outside the repository"
                ),
                "recommended": False,
            },
            {
                "option_id": "third_party_custody_agent",
                "name": "Third-party custody agent",
                "impact": (
                    "Reduces local code but adds another privileged service, trust boundary, "
                    "availability dependency, and vendor review"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "checkpoint_access_control",
        "prompt": "How should the local checkpoint be protected on the deployment host?",
        "recommended_option_id": "native_os_acl_dedicated_service_identity",
        "options": [
            {
                "option_id": "native_os_acl_dedicated_service_identity",
                "name": "Native OS ACL and dedicated service identity",
                "impact": (
                    "Provides enforceable least privilege and preserves offline reads; each "
                    "supported operating system needs its own verified provider"
                ),
                "recommended": True,
            },
            {
                "option_id": "platform_secret_store_checkpoint",
                "name": "Platform secret-store checkpoint",
                "impact": (
                    "Centralizes access policy but can prevent offline verification and binds "
                    "checkpoint availability to a remote control plane"
                ),
                "recommended": False,
            },
            {
                "option_id": "application_encryption_only",
                "name": "Application encryption only",
                "impact": (
                    "Protects confidentiality but does not prevent deletion, replacement, or "
                    "rollback by an actor with filesystem access"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "authoritative_ledger_storage",
        "prompt": "What durable substrate should hold the authoritative append-only ledger?",
        "recommended_option_id": "retention_locked_object_ledger_with_conditional_head",
        "options": [
            {
                "option_id": "retention_locked_object_ledger_with_conditional_head",
                "name": "Retention-locked object ledger with conditional head",
                "impact": (
                    "Provides immutable entry objects, compare-and-swap ordering, retained "
                    "checkpoint artifacts, and low canary operations overhead"
                ),
                "recommended": True,
            },
            {
                "option_id": "serializable_database_ledger_with_immutable_archive",
                "name": "Serializable database ledger with immutable archive",
                "impact": (
                    "Supports rich queries and transactions but adds database operations and "
                    "still needs a separately protected immutable archive"
                ),
                "recommended": False,
            },
            {
                "option_id": "dedicated_transparency_log_service",
                "name": "Dedicated transparency log service",
                "impact": (
                    "Offers strong consistency proofs but introduces the largest new service "
                    "and operational surface for a one-candidate canary"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "catalog_repository_storage",
        "prompt": "What durable substrate should distribute content-addressed catalogs?",
        "recommended_option_id": "immutable_content_addressed_object_storage",
        "options": [
            {
                "option_id": "immutable_content_addressed_object_storage",
                "name": "Immutable content-addressed object storage",
                "impact": (
                    "Directly matches SHA-256 catalog addressing and can share audited storage "
                    "primitives with the ledger while retaining separate access policy"
                ),
                "recommended": True,
            },
            {
                "option_id": "organization_artifact_registry",
                "name": "Organization artifact registry",
                "impact": (
                    "May reuse release infrastructure but tag mutability and retention behavior "
                    "need independent conformance proof"
                ),
                "recommended": False,
            },
            {
                "option_id": "release_database_blob_store",
                "name": "Release database blob store",
                "impact": (
                    "Centralizes metadata but couples immutable catalog distribution to database "
                    "backup, migration, and administrator controls"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "custody_separation",
        "prompt": "How strongly should ledger and catalog custody be separated?",
        "recommended_option_id": "separate_namespaces_credentials_and_failure_domains",
        "options": [
            {
                "option_id": "separate_namespaces_credentials_and_failure_domains",
                "name": "Separate namespaces, credentials, and failure domains",
                "impact": (
                    "Limits one credential or storage failure from rewriting release history and "
                    "published catalogs together"
                ),
                "recommended": True,
            },
            {
                "option_id": "shared_account_separate_namespaces",
                "name": "Shared account with separate namespaces",
                "impact": (
                    "Costs less to operate but account-level compromise or policy error affects "
                    "both authoritative records"
                ),
                "recommended": False,
            },
            {
                "option_id": "same_host_combined_storage",
                "name": "Same-host combined storage",
                "impact": (
                    "Is simplest but defeats cross-host rollback evidence and creates a single "
                    "loss and compromise domain"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "release_authentication",
        "prompt": "How should authoritative ledger heads and recovery artifacts be authenticated?",
        "recommended_option_id": "offline_root_authorized_release_signer_and_signed_heads",
        "options": [
            {
                "option_id": "offline_root_authorized_release_signer_and_signed_heads",
                "name": "Offline-root authorized release signer and signed heads",
                "impact": (
                    "Extends the existing trust root to ledger heads and recovery artifacts while "
                    "keeping the offline root out of routine operations"
                ),
                "recommended": True,
            },
            {
                "option_id": "workload_identity_and_provider_audit_only",
                "name": "Workload identity and provider audit only",
                "impact": (
                    "Simplifies key operations but makes verification depend on provider logs and "
                    "online identity infrastructure"
                ),
                "recommended": False,
            },
            {
                "option_id": "dual_control_unsigned_release_records",
                "name": "Dual-control unsigned release records",
                "impact": (
                    "Preserves human approval but cannot authenticate artifacts after export or "
                    "independent recovery"
                ),
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "resilience_and_rollout",
        "prompt": "What evidence should be required before the first production activation?",
        "recommended_option_id": "conformance_drills_dual_control_single_canary",
        "options": [
            {
                "option_id": "conformance_drills_dual_control_single_canary",
                "name": "Conformance drills, dual control, single canary",
                "impact": (
                    "Proves rollback, fork, corruption, interruption, and recovery behavior before "
                    "one exact candidate is activated"
                ),
                "recommended": True,
            },
            {
                "option_id": "manual_preflight_single_canary",
                "name": "Manual preflight and single canary",
                "impact": (
                    "Starts sooner but leaves important failure modes unproven until production "
                    "state already exists"
                ),
                "recommended": False,
            },
            {
                "option_id": "immediate_multi_candidate_activation",
                "name": "Immediate multi-candidate activation",
                "impact": (
                    "Provides coverage fastest but conflicts with the approved D011 canary limit "
                    "and materially increases first-release risk"
                ),
                "recommended": False,
            },
        ],
    },
)

RECOMMENDED_OPTIONS = {
    item["question_id"]: item["recommended_option_id"] for item in DECISION_QUESTIONS
}

REQUIRED_OWNER_INPUTS = (
    "exact_initial_host_operating_system_and_service_manager",
    "selected_immutable_object_storage_provider_or_compatible_implementation",
    "selected_workload_identity_provider_and_service_identity_scope",
    "required_data_residency_retention_and_audit_periods",
    "named_deployment_owner_platform_custodian_and_independent_control",
)

NONNEGOTIABLE_REQUIREMENTS = (
    "production_adapters_must_pass_the_same_provider_conformance_suite",
    "checkpoint_access_must_be_verified_for_the_exact_service_identity",
    "ledger_append_must_use_compare_and_swap_and_reject_forks_and_gaps",
    "ledger_entries_and_checkpoint_artifacts_must_be_retention_protected",
    "catalog_objects_must_be_immutable_and_verified_by_sha256",
    "ledger_catalog_and_checkpoint_credentials_must_be_least_privilege",
    "release_and_recovery_artifacts_must_be_independently_authenticatable",
    "private_keys_credentials_and_endpoints_must_remain_outside_catalogs",
    "all_d011_drills_must_pass_before_the_canary_go_no_go",
    "production_activation_must_remain_a_separate_dual_control_decision",
)

AUTHORIZED_NEXT_STEPS_IF_APPROVED = (
    "define_production_custody_provider_interfaces_and_conformance_suite",
    "implement_native_checkpoint_acl_provider_for_selected_operating_system",
    "implement_retention_locked_conditional_object_ledger_adapter",
    "implement_immutable_content_addressed_catalog_repository_adapter",
    "implement_release_head_signing_and_offline_verification",
    "implement_production_failure_and_recovery_drill_harness",
    "prepare_exact_single_candidate_production_go_no_go_packet",
)

LIMITATIONS = (
    "does_not_select_or_approve_a_d012_option",
    "does_not_select_an_operating_system_storage_provider_or_identity_provider",
    "does_not_create_cloud_accounts_buckets_databases_or_service_identities",
    "does_not_store_keys_credentials_endpoints_or_live_configuration",
    "does_not_persist_a_production_checkpoint_or_release_ledger_entry",
    "does_not_publish_a_catalog_activate_enrollment_or_accept_live_evidence",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
)


@dataclass(frozen=True)
class CandidateEnrollmentProductionCustodyDossier:
    """Content-addressed D012 choices with no selected production authority."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentProductionCustodyDossier:
        value = _mapping(raw, "candidate enrollment production custody dossier")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "decision_id",
            "status",
            "source_bindings",
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
        _exact_fields(value, fields, "candidate enrollment production custody dossier")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Production custody dossier schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or _DOSSIER_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Production custody dossier identity is invalid")
        if value.get("decision_id") != "D012" or value.get("status") != "decision_required":
            raise QualificationError("Production custody decision state is invalid")
        sources = _mapping(value.get("source_bindings"), "production custody sources")
        source_patterns = {
            "d011_implementation": ("report_id", r"CAI-[0-9A-F]{32}"),
            "canary_preparation": ("packet_id", r"CAP-[0-9A-F]{32}"),
        }
        _exact_fields(sources, set(source_patterns), "production custody sources")
        for source_name, (id_field, pattern) in source_patterns.items():
            source = _mapping(sources.get(source_name), source_name)
            _exact_fields(source, {id_field, "sha256"}, source_name)
            if (
                not isinstance(source.get(id_field), str)
                or re.fullmatch(pattern, str(source[id_field])) is None
                or not isinstance(source.get("sha256"), str)
                or _SHA256_PATTERN.fullmatch(str(source["sha256"])) is None
            ):
                raise QualificationError(f"Production custody {source_name} is invalid")
        expected_boundary = {
            "d011_contract_implementation_status": "complete",
            "production_checkpoint_provider_status": "not_selected",
            "production_release_ledger_provider_status": "not_selected",
            "production_catalog_repository_provider_status": "not_selected",
            "deployment_runtime_and_identity_status": "not_selected",
            "live_activation_status": "blocked",
        }
        if value.get("current_boundary") != expected_boundary:
            raise QualificationError("Production custody boundary is invalid")
        if value.get("decision_questions") != [dict(item) for item in DECISION_QUESTIONS]:
            raise QualificationError("Production custody decision questions are invalid")
        expected_recommendation = {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": [
                "preserves_single_host_canary_scope_and_current_sqlite_authority",
                "keeps_adapter_security_behavior_owned_and_testable_in_repository",
                "separates_local_enforcement_from_retention_locked_authoritative_history",
                "uses_content_addressing_and_conditional_writes_for_deterministic_recovery",
                "extends_offline_root_authentication_without_using_the_root_online",
                "requires_failure_drills_and_dual_control_before_any_live_activation",
            ],
        }
        if value.get("recommendation") != expected_recommendation:
            raise QualificationError("Production custody recommendation is invalid")
        expected_lists = {
            "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
            "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
            "authorized_next_steps_if_approved": list(
                AUTHORIZED_NEXT_STEPS_IF_APPROVED
            ),
            "limitations": list(LIMITATIONS),
        }
        for field, expected in expected_lists.items():
            if value.get(field) != expected:
                raise QualificationError(f"Production custody {field} is invalid")
        if (
            value.get("decision_effect") != "none"
            or value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Production custody dossier effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
        expected_id = "PCD-" + digest.removeprefix("sha256:")[:32].upper()
        if report_sha256 != digest or report_id != expected_id:
            raise QualificationError("Production custody dossier hash is invalid")
        return cls(report_id, report_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Production custody dossier is invalid")
        return value


def build_candidate_enrollment_production_custody_dossier(
    implementation: CandidateEnrollmentActivationImplementationReport,
    canary: CandidateEnrollmentCanaryPreparationPacket,
) -> CandidateEnrollmentProductionCustodyDossier:
    """Package production custody choices without selecting infrastructure."""

    implementation = CandidateEnrollmentActivationImplementationReport.from_dict(
        implementation.to_dict()
    )
    canary = CandidateEnrollmentCanaryPreparationPacket.from_dict(canary.to_dict())
    implementation_document = implementation.to_dict()
    canary_document = canary.to_dict()
    if (
        implementation_document["implementation_status"]
        != "approved_bundle_contract_implementation_complete"
        or implementation_document["live_activation_status"]
        != "blocked_pending_production_inputs_and_go_no_go"
        or implementation_document["canary_preparation"]
        != {"packet_id": canary.packet_id, "sha256": canary.packet_sha256}
        or canary_document["preparation_status"]
        != "awaiting_external_inputs_and_explicit_go_no_go"
    ):
        raise QualificationError("D012 source boundary is inconsistent")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D012",
        "status": "decision_required",
        "source_bindings": {
            "d011_implementation": {
                "report_id": implementation.report_id,
                "sha256": implementation.report_sha256,
            },
            "canary_preparation": {
                "packet_id": canary.packet_id,
                "sha256": canary.packet_sha256,
            },
        },
        "current_boundary": {
            "d011_contract_implementation_status": "complete",
            "production_checkpoint_provider_status": "not_selected",
            "production_release_ledger_provider_status": "not_selected",
            "production_catalog_repository_provider_status": "not_selected",
            "deployment_runtime_and_identity_status": "not_selected",
            "live_activation_status": "blocked",
        },
        "decision_questions": [dict(item) for item in DECISION_QUESTIONS],
        "recommendation": {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": [
                "preserves_single_host_canary_scope_and_current_sqlite_authority",
                "keeps_adapter_security_behavior_owned_and_testable_in_repository",
                "separates_local_enforcement_from_retention_locked_authoritative_history",
                "uses_content_addressing_and_conditional_writes_for_deterministic_recovery",
                "extends_offline_root_authentication_without_using_the_root_online",
                "requires_failure_drills_and_dual_control_before_any_live_activation",
            ],
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
    return CandidateEnrollmentProductionCustodyDossier.from_dict(
        {
            **body,
            "report_id": "PCD-" + digest.removeprefix("sha256:")[:32].upper(),
            "report_sha256": digest,
        }
    )


def load_candidate_enrollment_production_custody_dossier(
    path: str | Path,
) -> CandidateEnrollmentProductionCustodyDossier:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load production custody dossier: {resolved}") from exc
    return CandidateEnrollmentProductionCustodyDossier.from_dict(raw)


__all__ = [
    "CandidateEnrollmentProductionCustodyDossier",
    "build_candidate_enrollment_production_custody_dossier",
    "load_candidate_enrollment_production_custody_dossier",
]
