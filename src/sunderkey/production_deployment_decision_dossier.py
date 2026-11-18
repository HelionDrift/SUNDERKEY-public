"""Deterministic provider-neutral D014 production deployment dossier."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_backend_conformance import ContainmentConformanceSuiteCatalog
from .candidate_enrollment_production_custody_decision import (
    CandidateEnrollmentProductionCustodyDecisionRecord,
)
from .candidate_enrollment_release_contract import CandidateEnrollmentReleasePolicy
from .deployment_manifests import DeploymentManifestBundle
from .errors import QualificationError
from .provider_evidence_custody_decision import ProviderEvidenceCustodyDecisionRecord
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
DOSSIER_DOMAIN = "sunderkey.production-deployment-decision-dossier.d014.v1"
_DOSSIER_ID_PATTERN = re.compile(r"PDD-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

EXPECTED_SOURCE_IDENTITIES = {
    "production_custody_decision": {
        "record_id": "PCR-A2ACC5733A815AA349F5F6B7F1FBE5A3",
        "sha256": ("sha256:a2acc5733a815aa349f5f6b7f1fbe5a30881446417a9268923e96dea3c1624de"),
    },
    "provider_evidence_custody_decision": {
        "record_id": "ECR-24E4D6CE3E9902A20ACCCE2E2C74B6F6",
        "sha256": ("sha256:24e4d6ce3e9902a20accce2e2c74b6f61f99e27aff96280ba56178c84e140b9c"),
    },
    "deployment_manifest_bundle": {
        "bundle_id": "DMB-3D8C8D4CACA83A3520B7A23B20B43FCB",
        "sha256": ("sha256:3d8c8d4caca83a3520b7a23b20b43fcb3006f4007d398ec7b9dd10839594401f"),
    },
    "containment_conformance_catalog": {
        "catalog_id": "sunderkey-containment-conformance-suites-v1",
        "sha256": ("sha256:857bc288348d5e6bcd15deb92caf2b1a9c48df0678562af835aa7ad8086382c2"),
    },
    "candidate_release_policy": {
        "policy_id": "CRP-CB268855D98EC59A1C8D758550848EF5",
        "sha256": ("sha256:cb268855d98ec59a1c8d758550848ef5b5e2f0170d2e9f69d855bc7247a6bdde"),
    },
}

EXPECTED_REPOSITORY_EVIDENCE = (
    {
        "evidence_area": "deployment_profiles",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/deployment-profile-contract-v1.schema.json",
        "file_sha256": ("sha256:42c020bcf0442403199d51cbb6e86b0c8300c89e0696f0e0bd881070378a307c"),
    },
    {
        "evidence_area": "regional_custody",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/regional-custody-contract-v1.schema.json",
        "file_sha256": ("sha256:8ec875ea47f24fafa7660d901ab6c4f60ea8c5e25ab013bd16e95897236ba2ee"),
    },
    {
        "evidence_area": "high_availability",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/ha-coordination-contract-v1.schema.json",
        "file_sha256": ("sha256:1c68c9fdce17ee990a0bd76fde99354c6758a4e27fddb6e67731c67c727d67e2"),
    },
    {
        "evidence_area": "postgresql_runtime",
        "evidence_kind": "receipt_schema",
        "repository_path": ("registry/schemas/postgresql-runtime-adapter-receipt-v1.schema.json"),
        "file_sha256": ("sha256:5490233bae2691a6786de866af4bf06f32f89b8adc1690b3e6a8b2ee80b1e8a1"),
    },
    {
        "evidence_area": "evidence_lifecycle",
        "evidence_kind": "schema_contract",
        "repository_path": ("registry/schemas/provider-evidence-lifecycle-policy-v1.schema.json"),
        "file_sha256": ("sha256:2075a47716a8a7909000d38ed5d8b66e2958c6aff90d2d4bce687806eb237220"),
    },
    {
        "evidence_area": "evidence_authentication",
        "evidence_kind": "schema_contract",
        "repository_path": (
            "registry/schemas/provider-evidence-repository-ingest-authentication-v1.schema.json"
        ),
        "file_sha256": ("sha256:268e53c50fe8a4bf608f889fd077914ce5286230b74c8a1a8cbfbc4776d5b334"),
    },
    {
        "evidence_area": "oci_containment",
        "evidence_kind": "fixture_schema",
        "repository_path": ("registry/schemas/local-oci-containment-fixture-v1.schema.json"),
        "file_sha256": ("sha256:8b4dfa7bb92f83aded4eea6e35e7c01e0b05112824cdb4b99dd7ac8d33cb7cd2"),
    },
    {
        "evidence_area": "microvm_containment",
        "evidence_kind": "fixture_schema",
        "repository_path": ("registry/schemas/local-microvm-containment-fixture-v1.schema.json"),
        "file_sha256": ("sha256:3d65f92784e5f6a6c1106661840deca106df0e9eb74b222f6aeacc6e76100851"),
    },
    {
        "evidence_area": "browser_workers",
        "evidence_kind": "receipt_schema",
        "repository_path": ("registry/schemas/authorized-browser-action-receipt-v1.schema.json"),
        "file_sha256": ("sha256:4c8c72718a6c67fa64f04d2ac2642bec02ed00ddc82e4eb6005b1a81b8234b22"),
    },
    {
        "evidence_area": "specialist_workers",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/specialist-adapter-contract-v1.schema.json",
        "file_sha256": ("sha256:56da358d48fdd57ca9f39bd568a0881e07e959ee316eeb63a7df7d2e797c4c89"),
    },
    {
        "evidence_area": "target_authentication",
        "evidence_kind": "schema_contract",
        "repository_path": (
            "registry/schemas/target-authentication-adapter-contract-v2.schema.json"
        ),
        "file_sha256": ("sha256:4e6212c31f9d2e461bdb819170624614b9465610a97c60ca11cbdadbbf8064e9"),
    },
    {
        "evidence_area": "target_health",
        "evidence_kind": "observation_schema",
        "repository_path": ("registry/schemas/authorized-target-health-observation-v1.schema.json"),
        "file_sha256": ("sha256:07efb8d8f186ec11cab967024f2b0e722c6ef742576f2e2f695b752ea95b5c96"),
    },
    {
        "evidence_area": "service_health",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/health-state-contract-v1.schema.json",
        "file_sha256": ("sha256:5d087b67676b71f80289fbd3e1e5c8acb02d4bd8efdd00f01c5d90a8f68350ec"),
    },
    {
        "evidence_area": "monitoring_telemetry",
        "evidence_kind": "schema_contract",
        "repository_path": ("registry/schemas/defender-telemetry-adapter-contract-v1.schema.json"),
        "file_sha256": ("sha256:64e54f9ca306c96ca4362a47bc0fbedb6c014e92cb1f49aaae53b710b9fa1687"),
    },
    {
        "evidence_area": "disaster_recovery",
        "evidence_kind": "schema_contract",
        "repository_path": "registry/schemas/disaster-recovery-contract-v1.schema.json",
        "file_sha256": ("sha256:bd60ea7d966f3d390a133b19e5e14fa7900b00806fe765c7427edde28ed38e25"),
    },
    {
        "evidence_area": "disaster_recovery_commands",
        "evidence_kind": "receipt_schema",
        "repository_path": ("registry/schemas/disaster-recovery-command-receipt-v1.schema.json"),
        "file_sha256": ("sha256:421180ad376d129c1c8f8422c45d815f323885507006297e5545d2413fa85952"),
    },
)


def _question(
    question_id: str,
    prompt: str,
    *options: tuple[str, str, str],
) -> dict[str, Any]:
    return {
        "question_id": question_id,
        "prompt": prompt,
        "selection_status": "not_selected",
        "selected_option_id": None,
        "recommendation_status": "not_provided",
        "recommended_option_id": None,
        "option_order_effect": "none",
        "options": [
            {"option_id": option_id, "name": name, "impact": impact}
            for option_id, name, impact in options
        ],
    }


DECISION_QUESTIONS = (
    _question(
        "deployment_model",
        (
            "Which single primary responsibility model should host the production "
            "control plane and workers?"
        ),
        (
            "managed_control_plane_mixed_workers",
            "Managed control plane with mixed workers",
            "Centralizes control-plane operations while allowing managed or customer workers.",
        ),
        (
            "customer_hosted_private_platform",
            "Customer-hosted private platform",
            "Places the control plane and workers inside customer-operated infrastructure.",
        ),
        (
            "restricted_or_disconnected_platform",
            "Restricted or disconnected platform",
            "Uses signed relays or offline bundles and adds synchronization duties.",
        ),
    ),
    _question(
        "account_boundary",
        (
            "Which single primary account ownership and isolation bundle should "
            "govern production resources?"
        ),
        (
            "dedicated_accounts_per_environment",
            "Dedicated accounts per environment",
            "Provides strong blast-radius and administrator separation at higher overhead.",
        ),
        (
            "shared_account_separate_projects",
            "Shared account with separate projects",
            "Reduces overhead but increases the effect of account-level compromise.",
        ),
        (
            "customer_owned_accounts",
            "Customer-owned accounts",
            "Places infrastructure custody and some operational dependencies with customers.",
        ),
    ),
    _question(
        "region_topology",
        "Which single primary production region topology should be used?",
        (
            "single_region_multi_zone",
            "Single region with zonal redundancy",
            "Limits residency complexity but leaves regional recovery dependent on backups.",
        ),
        (
            "paired_regions_active_passive",
            "Paired regions active-passive",
            "Adds warm recovery capacity and cross-region custody requirements.",
        ),
        (
            "multiple_regions_active_active",
            "Multiple regions active-active",
            "Improves regional availability but adds distributed consistency complexity.",
        ),
    ),
    _question(
        "data_residency",
        "Which single primary policy key should govern storage and processing residency?",
        (
            "tenant_pinned_region_allowlist",
            "Tenant-pinned region allowlist",
            "Makes each tenant boundary explicit and denies unapproved transfers.",
        ),
        (
            "classification_policy_allowlist",
            "Classification policy allowlist",
            "Maps data classes to allowed regions and requires classification governance.",
        ),
        (
            "single_organization_boundary",
            "Single organization boundary",
            "Simplifies operations but supports fewer tenant-specific residency obligations.",
        ),
    ),
    _question(
        "workload_identity",
        "Which single primary workload identity and rotation model should services use?",
        (
            "federated_short_lived_identity",
            "Federated short-lived identity",
            "Avoids static credentials and requires trusted federation and rotation controls.",
        ),
        (
            "platform_managed_service_identity",
            "Platform-managed service identity",
            "Reduces credential handling while coupling identity to the selected platform.",
        ),
        (
            "organization_pki_workload_identity",
            "Organization PKI workload identity",
            "Uses organization-issued certificates and requires lifecycle automation.",
        ),
    ),
    _question(
        "operator_authentication",
        (
            "Which single primary trust and authentication model should operators "
            "and independent reviewers use?"
        ),
        (
            "enterprise_oidc_hardware_mfa",
            "Enterprise OIDC with hardware MFA",
            "Provides centralized lifecycle controls with phishing-resistant authentication.",
        ),
        (
            "enterprise_pki_and_sso",
            "Enterprise PKI and SSO",
            "Adds mutual authentication and certificate lifecycle obligations.",
        ),
        (
            "customer_identity_federation",
            "Customer identity federation",
            "Delegates operator identity proofing while requiring tenant trust configuration.",
        ),
    ),
    _question(
        "postgresql_topology",
        "Which single primary PostgreSQL production topology should hold control-plane state?",
        (
            "single_node_with_pitr",
            "Single node with point-in-time recovery",
            "Minimizes operations but accepts a longer database recovery interval.",
        ),
        (
            "regional_ha_managed_postgresql",
            "Regional HA managed PostgreSQL",
            "Provides managed failover while adding provider control-plane dependency.",
        ),
        (
            "self_managed_quorum_postgresql",
            "Self-managed quorum PostgreSQL",
            "Maximizes control while requiring database and fencing expertise.",
        ),
    ),
    _question(
        "object_and_evidence_storage",
        "Which single primary custody boundary should hold catalogs, ledgers, and evidence?",
        (
            "separate_immutable_object_domains",
            "Separate immutable object domains",
            "Separates credentials, namespaces, and failure domains for each custody class.",
        ),
        (
            "customer_owned_immutable_repositories",
            "Customer-owned immutable repositories",
            "Keeps evidence custody with customers and adds integration obligations.",
        ),
        (
            "private_object_compatible_storage",
            "Private object-compatible storage",
            "Supports private deployments but requires independent retention conformance.",
        ),
    ),
    _question(
        "kms_and_release_signing",
        "Which single primary custody model should hold encryption and release signing keys?",
        (
            "organization_kms_external_offline_root",
            "Organization KMS with external offline root",
            "Separates routine envelope encryption from release authorization custody.",
        ),
        (
            "customer_kms_and_release_signer",
            "Customer KMS and release signer",
            "Places key custody with customers and requires verified signing integration.",
        ),
        (
            "dedicated_hsm_key_domains",
            "Dedicated HSM key domains",
            "Provides strong key isolation with higher cost and operational complexity.",
        ),
    ),
    _question(
        "retention_legal_hold_and_deletion",
        "Which single primary evidence lifecycle authority model should apply?",
        (
            "classification_schedules_independent_hold",
            "Classification schedules with independent hold",
            "Uses class-specific retention and separate legal-hold authority.",
        ),
        (
            "tenant_contract_schedules",
            "Tenant contract schedules",
            "Supports tenant-specific periods and increases policy reconciliation work.",
        ),
        (
            "organization_fixed_schedules",
            "Organization fixed schedules",
            "Simplifies enforcement but supports fewer contractual variations.",
        ),
    ),
    _question(
        "oci_workers",
        "Which single primary deployment model should OCI containment workers use?",
        (
            "rootless_dedicated_nodes",
            "Rootless dedicated nodes",
            "Provides explicit host isolation and requires node lifecycle management.",
        ),
        (
            "orchestrated_ephemeral_pods",
            "Orchestrated ephemeral pods",
            "Improves elasticity and requires verified runtime and node isolation.",
        ),
        (
            "oci_workers_disabled",
            "OCI workers disabled",
            "Removes this execution class and limits supported specialist actions.",
        ),
    ),
    _question(
        "microvm_workers",
        "Which single primary deployment model should microVM containment workers use?",
        (
            "jailed_dedicated_workers",
            "Jailed dedicated workers",
            "Provides strong local isolation and requires host-specific hardening.",
        ),
        (
            "managed_microvm_workers",
            "Managed microVM workers",
            "Moves some isolation operations to a provider and requires provider evidence.",
        ),
        (
            "microvm_workers_disabled",
            "MicroVM workers disabled",
            "Avoids this runtime dependency and reduces high-isolation capacity.",
        ),
    ),
    _question(
        "browser_workers",
        "Which single primary isolation model should browser automation workers use?",
        (
            "ephemeral_browser_per_mission",
            "Ephemeral browser per mission",
            "Maximizes cleanup isolation with higher startup and capacity cost.",
        ),
        (
            "dedicated_tenant_browser_pools",
            "Dedicated tenant browser pools",
            "Balances reuse and isolation while requiring tenant pool hygiene.",
        ),
        (
            "browser_workers_disabled",
            "Browser workers disabled",
            "Removes browser execution and limits browser-dependent coverage.",
        ),
    ),
    _question(
        "specialist_workers",
        "Which single primary partitioning model should specialist workers use?",
        (
            "ephemeral_worker_per_work_item",
            "Ephemeral worker per work item",
            "Provides narrow isolation with higher provisioning overhead.",
        ),
        (
            "dedicated_tenant_specialist_pools",
            "Dedicated tenant specialist pools",
            "Provides tenant isolation with reserved capacity requirements.",
        ),
        (
            "shared_stateless_specialist_pool",
            "Shared stateless specialist pool",
            "Improves utilization and requires strong identity and cleanup controls.",
        ),
    ),
    _question(
        "monitoring_and_observability",
        (
            "Which single primary system of record should monitor health, audit, "
            "security, and cost telemetry?"
        ),
        (
            "organization_siem_and_observability",
            "Organization SIEM and observability",
            "Centralizes monitoring and requires scoped integration and retention controls.",
        ),
        (
            "dedicated_service_monitoring",
            "Dedicated service monitoring",
            "Isolates service telemetry and requires a separate staffed on-call function.",
        ),
        (
            "customer_telemetry_export",
            "Customer telemetry export",
            "Places monitoring with customers and requires delivery and acknowledgement SLAs.",
        ),
    ),
    _question(
        "incident_response",
        (
            "Which single primary ownership model should govern incident command "
            "and evidence preservation?"
        ),
        (
            "internal_security_incident_command",
            "Internal security incident command",
            "Keeps command internal and requires a continuously staffed response function.",
        ),
        (
            "shared_provider_response",
            "Shared provider response",
            "Uses provider escalation paths and requires explicit responsibility mapping.",
        ),
        (
            "customer_led_response",
            "Customer-led response",
            "Places incident command with customers and requires custody handoff contracts.",
        ),
    ),
    _question(
        "capacity_and_cost",
        "Which single primary control model should govern capacity and cost limits?",
        (
            "fixed_quotas_and_budget_ceiling",
            "Fixed quotas and budget ceiling",
            "Provides predictable spend and can limit burst response capacity.",
        ),
        (
            "autoscaling_with_hard_spend_caps",
            "Autoscaling with hard spend caps",
            "Handles demand changes while requiring reliable cost enforcement.",
        ),
        (
            "reserved_baseline_with_burst_pool",
            "Reserved baseline with burst pool",
            "Balances steady capacity and bursts with more planning complexity.",
        ),
    ),
    _question(
        "backup_and_disaster_recovery",
        "Which single primary backup and disaster-recovery model should be required?",
        (
            "same_region_pitr_cross_region_backup",
            "Same-region PITR with cross-region backup",
            "Provides durable recovery and requires approved cross-region custody.",
        ),
        (
            "paired_region_warm_standby",
            "Paired-region warm standby",
            "Reduces recovery time with higher standing cost and coordination needs.",
        ),
        (
            "customer_operated_backup_restore",
            "Customer-operated backup and restore",
            "Delegates recovery custody and requires verified drill evidence.",
        ),
    ),
    _question(
        "custodians_and_reviewers",
        (
            "Which single primary responsibility model should assign accountable "
            "owners, custodians, and independent reviewers?"
        ),
        (
            "separated_internal_roles",
            "Separated internal roles",
            "Names distinct deployment, platform, security, privacy, control, and assurance roles.",
        ),
        (
            "shared_responsibility_roles",
            "Shared responsibility roles",
            "Splits duties with providers and requires exact escalation ownership.",
        ),
        (
            "customer_custody_internal_review",
            "Customer custody with internal review",
            "Places operational custody with customers while retaining independent review.",
        ),
    ),
)

REQUIRED_OWNER_INPUTS = (
    "selected_deployment_model_and_control_plane_responsibility_boundary",
    "selected_provider_account_subscription_project_and_environment_hierarchy",
    "selected_primary_recovery_and_prohibited_regions",
    "tenant_and_classification_specific_storage_and_processing_residency",
    "selected_workload_identity_provider_scopes_rotation_and_revocation_model",
    "selected_operator_identity_provider_mfa_and_break_glass_controls",
    "selected_postgresql_service_version_topology_fencing_and_failover_model",
    "selected_catalog_ledger_evidence_backup_and_replica_storage_boundaries",
    "selected_kms_hierarchy_release_signer_and_offline_root_custodians",
    "retention_schedules_legal_hold_authority_deletion_sla_and_erasure_proof",
    "selected_oci_runtime_hosts_node_isolation_and_capacity",
    "selected_microvm_runtime_hosts_jailer_configuration_and_capacity",
    "selected_browser_runtime_pool_isolation_cleanup_and_capacity",
    "selected_specialist_worker_partitioning_identity_tools_and_capacity",
    "selected_monitoring_logging_siem_paging_and_telemetry_retention",
    "incident_command_escalation_forensics_notification_and_evidence_preservation",
    "service_level_capacity_concurrency_cost_targets_and_hard_budget_limits",
    "rpo_rto_backup_replication_restore_failover_and_failback_drill_schedule",
    "named_deployment_owner_platform_custodian_security_privacy_control_and_assurance",
)

NONNEGOTIABLE_REQUIREMENTS = (
    "no_provider_account_region_identity_or_endpoint_may_be_inferred_from_this_dossier",
    "production_state_requires_postgresql_with_tls_migrations_backups_and_restore_drills",
    "high_availability_requires_quorum_epoch_fencing_and_stale_writer_rejection",
    "all_storage_and_processing_must_enforce_the_selected_residency_policy",
    "catalog_ledger_checkpoint_and_evidence_custody_must_remain_separated",
    "raw_evidence_bytes_must_remain_outside_the_control_plane_database",
    "workload_and_operator_identity_must_be_short_lived_revocable_and_auditable",
    "release_and_recovery_artifacts_must_be_independently_authenticatable",
    "retention_legal_hold_deletion_and_key_erasure_must_produce_verifiable_receipts",
    "oci_and_microvm_backends_must_pass_the_published_containment_suites",
    "browser_and_specialist_workers_must_enforce_scope_egress_cleanup_and_custody",
    "health_integrity_dependency_and_recovery_states_must_fail_closed_on_unknown",
    "security_audit_health_capacity_and_cost_telemetry_must_have_named_responders",
    "backup_restore_failover_failback_and_regional_loss_drills_must_be_evidenced",
    "production_activation_requires_a_separate_dual_control_go_no_go_decision",
    "future_selection_must_choose_exactly_one_option_per_question_or_publish_a_new_dossier_revision",
)

FOLLOW_UP_STEPS_AFTER_AUTHENTICATED_OWNER_SELECTION = (
    "record_a_separately_authenticated_owner_selected_d014_deployment_bundle",
    "build_the_selected_provider_and_account_specific_implementation_plan",
    "bind_exact_regions_identities_storage_key_and_runtime_resources",
    "execute_external_security_capacity_recovery_and_custody_conformance",
    "prepare_a_separate_dual_control_production_go_no_go_packet",
)

LIMITATIONS = (
    "does_not_select_or_approve_any_d014_option",
    "does_not_select_a_provider_account_subscription_project_region_or_endpoint",
    "does_not_select_or_create_a_workload_identity_operator_identity_key_or_secret",
    "does_not_create_deploy_modify_or_delete_infrastructure_or_runtime_state",
    "does_not_connect_to_a_network_database_provider_kms_repository_or_target",
    "does_not_store_credentials_evidence_target_information_or_live_configuration",
    "does_not_authorize_production_activation_target_action_or_provider_execution",
    "does_not_qualify_a_specialist_change_routing_or_complete_external_conformance",
    "does_not_mutate_sqlite_or_postgresql_state",
    "does_not_treat_review_publication_or_acknowledgement_as_selection_or_approval",
)

RELATED_PENDING_OWNER_DECISIONS = (
    {
        "decision_id": "PHASE186D-RUNTIME-ENTRYPOINT",
        "status": "approved_operator_asserted_unsigned",
        "question": (
            "Should the generic Phase 186B2 caller-provided verifier remain an "
            "explicitly limited compatibility boundary, or should every runtime "
            "replacement enter through Phase 186D signed custody?"
        ),
        "selection_status": "selected_for_implementation_only",
        "selected_option_id": "mandatory_phase186d_signed_custody_for_runtime",
        "authority_effect": "none",
        "required_boundary": (
            "runtime_replacement_requires_phase186d_signed_custody_while_"
            "phase186b2_is_internal_atomic_persistence_or_isolated_legacy_tests"
        ),
    },
    {
        "decision_id": "PHASE186D-INDEPENDENT-REVIEWER-ADMISSION",
        "status": "approved_operator_asserted_unsigned",
        "question": (
            "How should missions obtain sufficient assigned, non-owner independent "
            "Control and Assurance principals for conditional replacement review?"
        ),
        "selection_status": "selected_for_implementation_only",
        "selected_option_id": "explicit_signed_mission_scoped_reserve_pool",
        "authority_effect": "none",
        "required_boundary": (
            "reviewer_assignment_requires_an_explicit_signed_admission_path_and_"
            "cannot_grant_implicit_unassigned_privilege"
        ),
    },
)

_EXPECTED_SOURCE_IDENTITIES_JSON = _canonical_json(EXPECTED_SOURCE_IDENTITIES)
_EXPECTED_REPOSITORY_EVIDENCE_JSON = _canonical_json(
    [dict(item) for item in EXPECTED_REPOSITORY_EVIDENCE]
)
_DECISION_QUESTIONS_JSON = _canonical_json([dict(item) for item in DECISION_QUESTIONS])
_RELATED_PENDING_OWNER_DECISIONS_JSON = _canonical_json(
    [dict(item) for item in RELATED_PENDING_OWNER_DECISIONS]
)


def expected_repository_evidence() -> tuple[dict[str, str], ...]:
    """Return a fresh copy of the exact repository evidence contract."""

    value = json.loads(_EXPECTED_REPOSITORY_EVIDENCE_JSON)
    if not isinstance(value, list):
        raise QualificationError("Repository evidence contract is invalid")
    return tuple(dict(item) for item in value)


def _expected_source_identities() -> dict[str, Any]:
    value = json.loads(_EXPECTED_SOURCE_IDENTITIES_JSON)
    if not isinstance(value, dict):
        raise QualificationError("D014 source identity contract is invalid")
    return value


def _decision_questions() -> list[dict[str, Any]]:
    value = json.loads(_DECISION_QUESTIONS_JSON)
    if not isinstance(value, list):
        raise QualificationError("D014 decision question contract is invalid")
    questions = [dict(item) for item in value]
    if len(questions) != 19:
        raise QualificationError("D014 decision question contract is invalid")
    for question in questions:
        if (
            set(question)
            != {
                "question_id",
                "prompt",
                "selection_status",
                "selected_option_id",
                "recommendation_status",
                "recommended_option_id",
                "option_order_effect",
                "options",
            }
            or question.get("selection_status") != "not_selected"
            or question.get("selected_option_id") is not None
            or question.get("recommendation_status") != "not_provided"
            or question.get("recommended_option_id") is not None
            or question.get("option_order_effect") != "none"
        ):
            raise QualificationError("D014 decision question contract is invalid")
        options = question.get("options")
        if not isinstance(options, list) or len(options) != 3:
            raise QualificationError("D014 decision option contract is invalid")
        if any(
            not isinstance(option, Mapping)
            or set(option) != {"option_id", "name", "impact"}
            or any(
                not isinstance(option.get(field), str) or not option.get(field)
                for field in ("option_id", "name", "impact")
            )
            for option in options
        ):
            raise QualificationError("D014 decision option contract is invalid")
        identities = {option.get("option_id") for option in options if isinstance(option, Mapping)}
        if len(identities) != 3:
            raise QualificationError("D014 decision option contract is invalid")
    return questions


def _related_pending_owner_decisions() -> list[dict[str, Any]]:
    value = json.loads(_RELATED_PENDING_OWNER_DECISIONS_JSON)
    if not isinstance(value, list) or len(value) != 2:
        raise QualificationError("Related pending owner decision contract is invalid")
    decisions = [dict(item) for item in value]
    expected_fields = {
        "decision_id",
        "status",
        "question",
        "selection_status",
        "selected_option_id",
        "authority_effect",
        "required_boundary",
    }
    for decision in decisions:
        if (
            set(decision) != expected_fields
            or decision.get("status") != "approved_operator_asserted_unsigned"
            or decision.get("selection_status") != "selected_for_implementation_only"
            or decision.get("selected_option_id")
            != {
                "PHASE186D-RUNTIME-ENTRYPOINT": "mandatory_phase186d_signed_custody_for_runtime",
                "PHASE186D-INDEPENDENT-REVIEWER-ADMISSION": (
                    "explicit_signed_mission_scoped_reserve_pool"
                ),
            }.get(decision.get("decision_id"))
            or decision.get("authority_effect") != "none"
            or any(
                not isinstance(decision.get(field), str) or not decision.get(field)
                for field in ("decision_id", "question", "required_boundary")
            )
        ):
            raise QualificationError("Related pending owner decision contract is invalid")
    if {item["decision_id"] for item in decisions} != {
        "PHASE186D-RUNTIME-ENTRYPOINT",
        "PHASE186D-INDEPENDENT-REVIEWER-ADMISSION",
    }:
        raise QualificationError("Related pending owner decision contract is invalid")
    return decisions


def _repository_evidence(raw: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise QualificationError("Repository evidence must be an array")
    result: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        value = _mapping(item, f"repository_evidence[{index}]")
        _exact_fields(
            value,
            {"evidence_area", "evidence_kind", "repository_path", "file_sha256"},
            f"repository_evidence[{index}]",
        )
        digest = value.get("file_sha256")
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise QualificationError("Repository evidence digest is invalid")
        result.append(dict(value))
    if result != list(expected_repository_evidence()):
        raise QualificationError("Repository evidence does not match the current contracts")
    return result


def _validate_source_bindings(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "source_bindings")
    expected_identities = _expected_source_identities()
    _exact_fields(value, set(expected_identities), "source_bindings")
    for field, expected in expected_identities.items():
        if value.get(field) != expected:
            raise QualificationError(f"D014 source binding {field} is invalid")
    return dict(value)


@dataclass(frozen=True)
class ProductionDeploymentDecisionDossier:
    """Content-addressed D014 owner decision packet with no selected option."""

    dossier_id: str
    dossier_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProductionDeploymentDecisionDossier:
        value = _mapping(raw, "production deployment decision dossier")
        fields = {
            "schema_version",
            "dossier_id",
            "dossier_sha256",
            "decision_id",
            "status",
            "source_bindings",
            "repository_evidence",
            "current_boundary",
            "related_pending_owner_decisions",
            "decision_questions",
            "required_owner_inputs",
            "nonnegotiable_requirements",
            "follow_up_steps_after_authenticated_owner_selection",
            "limitations",
            "decision_effect",
            "recommendation_effect",
            "authorization_effect",
            "network_call_performed",
            "runtime_effect",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "production deployment decision dossier")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Production deployment dossier schema is invalid")
        dossier_id = value.get("dossier_id")
        dossier_sha256 = value.get("dossier_sha256")
        if (
            not isinstance(dossier_id, str)
            or _DOSSIER_ID_PATTERN.fullmatch(dossier_id) is None
            or not isinstance(dossier_sha256, str)
            or _SHA256_PATTERN.fullmatch(dossier_sha256) is None
        ):
            raise QualificationError("Production deployment dossier identity is invalid")
        if value.get("decision_id") != "D014" or value.get("status") != "decision_required":
            raise QualificationError("Production deployment dossier state is invalid")
        _validate_source_bindings(value.get("source_bindings"))
        _repository_evidence(value.get("repository_evidence"))
        expected = {
            "current_boundary": {
                "d012_production_custody_decision": (
                    "approved_contract_partially_implemented_provider_unselected"
                ),
                "d013_evidence_custody_decision": (
                    "approved_contract_partially_implemented_provider_unselected"
                ),
                "deployment_manifest_status": "repository_complete_infrastructure_blocked",
                "containment_suite_status": "defined_nonqualifying",
                "provider_account_region_identity_status": "not_selected",
                "live_deployment_status": "not_performed",
                "production_activation_status": "blocked",
            },
            "related_pending_owner_decisions": _related_pending_owner_decisions(),
            "decision_questions": _decision_questions(),
            "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
            "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
            "follow_up_steps_after_authenticated_owner_selection": list(
                FOLLOW_UP_STEPS_AFTER_AUTHENTICATED_OWNER_SELECTION
            ),
            "limitations": list(LIMITATIONS),
            "decision_effect": "none",
            "recommendation_effect": "none",
            "authorization_effect": "none",
            "network_call_performed": False,
            "runtime_effect": "none",
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise QualificationError(f"Production deployment dossier {field} is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"dossier_id", "dossier_sha256"}
        }
        digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
        expected_id = "PDD-" + digest.removeprefix("sha256:")[:32].upper()
        if dossier_sha256 != digest or dossier_id != expected_id:
            raise QualificationError("Production deployment dossier hash is invalid")
        return cls(dossier_id, dossier_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ProductionDeploymentDecisionDossier:
            raise QualificationError("Production deployment dossier type is invalid")
        if not isinstance(self.document_json, str):
            raise QualificationError("Production deployment dossier is invalid")
        try:
            value = json.loads(self.document_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise QualificationError("Production deployment dossier is invalid") from exc
        if not isinstance(value, dict):
            raise QualificationError("Production deployment dossier is invalid")
        validated = ProductionDeploymentDecisionDossier.from_dict(value)
        if (
            validated.dossier_id != self.dossier_id
            or validated.dossier_sha256 != self.dossier_sha256
            or validated.document_json != self.document_json
        ):
            raise QualificationError("Production deployment dossier was mutated")
        return json.loads(validated.document_json)


def build_production_deployment_decision_dossier(
    *,
    production_custody_decision: CandidateEnrollmentProductionCustodyDecisionRecord,
    evidence_custody_decision: ProviderEvidenceCustodyDecisionRecord,
    deployment_manifest: DeploymentManifestBundle,
    containment_catalog: ContainmentConformanceSuiteCatalog,
    release_policy: CandidateEnrollmentReleasePolicy,
    repository_evidence: Sequence[Mapping[str, str]],
) -> ProductionDeploymentDecisionDossier:
    """Build the D014 decision packet without selecting or applying infrastructure."""

    if not isinstance(
        production_custody_decision,
        CandidateEnrollmentProductionCustodyDecisionRecord,
    ):
        raise QualificationError("production_custody_decision is invalid")
    production_custody_decision = CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(
        production_custody_decision.to_dict()
    )
    if not isinstance(evidence_custody_decision, ProviderEvidenceCustodyDecisionRecord):
        raise QualificationError("evidence_custody_decision is invalid")
    evidence_custody_decision = ProviderEvidenceCustodyDecisionRecord.from_dict(
        evidence_custody_decision.to_dict()
    )
    if not isinstance(deployment_manifest, DeploymentManifestBundle):
        raise QualificationError("deployment_manifest is invalid")
    deployment_manifest = DeploymentManifestBundle.from_dict(deployment_manifest.to_dict())
    if not isinstance(containment_catalog, ContainmentConformanceSuiteCatalog):
        raise QualificationError("containment_catalog is invalid")
    containment_catalog = ContainmentConformanceSuiteCatalog.from_dict(
        containment_catalog.to_dict()
    )
    if not isinstance(release_policy, CandidateEnrollmentReleasePolicy):
        raise QualificationError("release_policy is invalid")
    release_policy = CandidateEnrollmentReleasePolicy.from_dict(release_policy.to_dict())
    source_bindings = {
        "production_custody_decision": {
            "record_id": production_custody_decision.record_id,
            "sha256": production_custody_decision.record_sha256,
        },
        "provider_evidence_custody_decision": {
            "record_id": evidence_custody_decision.record_id,
            "sha256": evidence_custody_decision.record_sha256,
        },
        "deployment_manifest_bundle": {
            "bundle_id": deployment_manifest.bundle_id,
            "sha256": deployment_manifest.bundle_sha256,
        },
        "containment_conformance_catalog": {
            "catalog_id": containment_catalog.to_dict()["catalog_id"],
            "sha256": containment_catalog.catalog_sha256,
        },
        "candidate_release_policy": {
            "policy_id": release_policy.policy_id,
            "sha256": release_policy.policy_sha256,
        },
    }
    _validate_source_bindings(source_bindings)
    evidence = _repository_evidence(repository_evidence)
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D014",
        "status": "decision_required",
        "source_bindings": source_bindings,
        "repository_evidence": evidence,
        "current_boundary": {
            "d012_production_custody_decision": (
                "approved_contract_partially_implemented_provider_unselected"
            ),
            "d013_evidence_custody_decision": (
                "approved_contract_partially_implemented_provider_unselected"
            ),
            "deployment_manifest_status": "repository_complete_infrastructure_blocked",
            "containment_suite_status": "defined_nonqualifying",
            "provider_account_region_identity_status": "not_selected",
            "live_deployment_status": "not_performed",
            "production_activation_status": "blocked",
        },
        "related_pending_owner_decisions": _related_pending_owner_decisions(),
        "decision_questions": _decision_questions(),
        "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "follow_up_steps_after_authenticated_owner_selection": list(
            FOLLOW_UP_STEPS_AFTER_AUTHENTICATED_OWNER_SELECTION
        ),
        "limitations": list(LIMITATIONS),
        "decision_effect": "none",
        "recommendation_effect": "none",
        "authorization_effect": "none",
        "network_call_performed": False,
        "runtime_effect": "none",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
    return ProductionDeploymentDecisionDossier.from_dict(
        {
            **body,
            "dossier_id": "PDD-" + digest.removeprefix("sha256:")[:32].upper(),
            "dossier_sha256": digest,
        }
    )


def load_production_deployment_decision_dossier(
    path: str | Path,
) -> ProductionDeploymentDecisionDossier:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load D014 dossier: {resolved}") from exc
    return ProductionDeploymentDecisionDossier.from_dict(raw)


__all__ = [
    "DECISION_QUESTIONS",
    "EXPECTED_REPOSITORY_EVIDENCE",
    "EXPECTED_SOURCE_IDENTITIES",
    "FOLLOW_UP_STEPS_AFTER_AUTHENTICATED_OWNER_SELECTION",
    "LIMITATIONS",
    "NONNEGOTIABLE_REQUIREMENTS",
    "ProductionDeploymentDecisionDossier",
    "RELATED_PENDING_OWNER_DECISIONS",
    "REQUIRED_OWNER_INPUTS",
    "build_production_deployment_decision_dossier",
    "expected_repository_evidence",
    "load_production_deployment_decision_dossier",
]
