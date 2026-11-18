"""Deterministic decision dossier for collaboration authority decisions."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collaboration import _canonical_json
from .collaboration import _sha256 as _canonical_sha256
from .errors import CollaborationPlanError
from .registry import ExpertRegistry
from .routing import CapabilityCatalog, RoutingPolicy
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

REPORT_SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.collaboration-authority-decision-dossier.v1"
REPORT_ID_PATTERN = re.compile(r"CAD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SEMVER_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
DECISION_IDS = ("D001", "D002", "D003", "D004", "D005")
RECOMMENDED_ALTERNATIVE_ID = "reviewed_reconfiguration_ledger"
CURRENT_SQLITE_SCHEMA_VERSION = 15

AUTHORITY_BINDING_REQUIREMENTS = (
    "mission_identity",
    "active_collaboration_plan_identity_and_sha256",
    "work_item_identity_and_objective",
    "current_owner_identity",
    "proposed_owner_identity",
    "current_ownership_chain_head",
    "requested_transition_and_reason",
    "authorization_policy_identity",
    "validity_window",
    "execution_session_fence_when_applicable",
)

SEPARATION_REQUIREMENTS = (
    "current_owner_authorization",
    "proposed_owner_acceptance",
    "independent_control_review",
    "second_control_or_mission_authority_for_control_replacement",
    "assurance_independence_preserved",
    "execution_acknowledger_distinct_from_control_plane_requester",
)

FAIL_CLOSED_REQUIREMENTS = (
    "unknown_current_ownership_head_rejected",
    "ownership_cycle_rejected",
    "maximum_delegation_depth_enforced",
    "stale_plan_or_work_item_binding_rejected",
    "unqualified_or_incapable_owner_rejected",
    "unmapped_completed_work_not_carried_forward",
    "unacknowledged_external_execution_transfer_not_effective",
    "expired_or_revoked_authority_rejected",
    "partial_reconfiguration_not_committed",
)

HISTORY_REQUIREMENTS = (
    "append_only_ownership_chain",
    "immutable_prior_plan_and_work_history",
    "completed_result_provenance_preserved",
    "cancelled_and_unmapped_work_retained",
    "assertions_remain_bound_to_original_plan_and_owner_epoch",
    "deterministic_replay_returns_original_result",
)

ALTERNATIVES = (
    {
        "alternative_id": "reviewed_reconfiguration_ledger",
        "name": "Reviewed reconfiguration ledger",
        "recommended": True,
        "authority_location": "sunderkey_reviewed_control_plane",
        "decision_record": "signed_append_only_reconfiguration_record",
        "operational_complexity": "moderate",
        "independence_strength": "strong",
        "distributed_execution_support": "explicit_protocol_required",
        "strengths": [
            "preserves_current_owner_and_candidate_consent",
            "keeps_control_and_assurance_independence_explicit",
            "supports_bounded_ownership_chains_and_replay",
            "binds_cross_command_change_to_reviewed_plan_replacement",
            "separates_control_plane_authority_from_execution_acknowledgement",
        ],
        "risks": [
            "requires_new_signed_reconfiguration_contracts",
            "requires_atomic_item_mapping_and_chain_state",
            "requires_a_separate_fenced_execution_channel_protocol",
        ],
        "required_components": [
            "reconfiguration_authority_policy",
            "bounded_ownership_chain_contract",
            "reviewed_plan_replacement_contract",
            "cross_command_capability_and_qualification_review",
            "fenced_execution_acknowledgement_protocol",
        ],
    },
    {
        "alternative_id": "centralized_mission_authority",
        "name": "Centralized mission authority",
        "recommended": False,
        "authority_location": "single_mission_authority",
        "decision_record": "mission_authority_signed_change_record",
        "operational_complexity": "low",
        "independence_strength": "moderate",
        "distributed_execution_support": "external_integration_required",
        "strengths": [
            "provides_one_clear_escalation_point",
            "simplifies_conflict_resolution",
            "can_coordinate_cross_command_changes",
        ],
        "risks": [
            "creates_an_authority_bottleneck",
            "can_bypass_owner_and_independent_review",
            "concentrates_plan_replacement_power",
            "does_not_itself_fence_external_workers",
        ],
        "required_components": [
            "mission_authority_credential",
            "owner_notification_and_acceptance_policy",
            "independent_review_override_policy",
            "central_reconfiguration_audit_log",
            "external_execution_connector",
        ],
    },
    {
        "alternative_id": "commander_federated_reconfiguration",
        "name": "Commander federated reconfiguration",
        "recommended": False,
        "authority_location": "domain_and_maneuver_commanders",
        "decision_record": "commander_approved_transfer_record",
        "operational_complexity": "moderate",
        "independence_strength": "moderate",
        "distributed_execution_support": "connector_specific",
        "strengths": [
            "keeps_domain_context_near_transfer_decisions",
            "can_reduce_central_review_latency",
            "matches_existing_command_hierarchy",
        ],
        "risks": [
            "cross_command_authority_can_be_ambiguous",
            "commander_interests_can_conflict_with_assurance_independence",
            "different_commands_can_apply_inconsistent_chain_limits",
            "connector_specific_acknowledgement_can_fragment_provenance",
        ],
        "required_components": [
            "commander_authority_scope_contract",
            "cross_command_dual_commander_review",
            "control_and_assurance_veto_policy",
            "shared_ownership_chain_rules",
            "connector_acknowledgement_profiles",
        ],
    },
    {
        "alternative_id": "runtime_local_ownership",
        "name": "Runtime local ownership",
        "recommended": False,
        "authority_location": "execution_runtime",
        "decision_record": "runtime_local_ownership_state",
        "operational_complexity": "low",
        "independence_strength": "weak",
        "distributed_execution_support": "implicit",
        "strengths": [
            "minimizes_control_plane_coordination",
            "can_react_quickly_to_local_worker_failure",
        ],
        "risks": [
            "lets_execution_state_select_its_own_authority",
            "cannot_prove_consistent_cross_runtime_ownership",
            "can_bypass_scope_control_and_assurance_review",
            "breaks_deterministic_replay_and_portable_audit",
            "can_leave_multiple_workers_acting_on_the_same_item",
        ],
        "required_components": [
            "runtime_specific_locking",
            "runtime_specific_recovery",
            "out_of_band_audit_export",
        ],
    },
)

DECISION_QUESTIONS = (
    {
        "decision_id": "D001",
        "question_id": "privileged_reassignment_authority",
        "prompt": (
            "Who may reassign readiness, synthesis, integration, commander, "
            "Control, or Assurance work?"
        ),
        "option_ids": [
            "owner_replacement_and_independent_control",
            "mission_authority_only",
            "domain_commander_and_candidate",
            "runtime_local_authority",
        ],
        "recommended_option_id": "owner_replacement_and_independent_control",
    },
    {
        "decision_id": "D002",
        "question_id": "delegation_lifecycle",
        "prompt": "How do repeated delegation, return, and Control revocation work?",
        "option_ids": [
            "versioned_bounded_chain_with_return_and_control_revocation",
            "retain_single_handoff_per_item",
            "unlimited_recursive_delegation",
            "runtime_managed_chain",
        ],
        "recommended_option_id": "versioned_bounded_chain_with_return_and_control_revocation",
    },
    {
        "decision_id": "D003",
        "question_id": "cross_command_transfer",
        "prompt": "How can work move outside its original domain command or maneuver group?",
        "option_ids": [
            "reviewed_plan_replacement_with_capability_revalidation",
            "same_command_only_permanently",
            "commander_approved_direct_cross_command_handoff",
            "runtime_local_cross_command_transfer",
        ],
        "recommended_option_id": "reviewed_plan_replacement_with_capability_revalidation",
    },
    {
        "decision_id": "D004",
        "question_id": "activated_plan_replacement",
        "prompt": "How can a new collaboration plan replace an active plan?",
        "option_ids": [
            "independently_reviewed_exact_item_mapping",
            "replace_all_and_restart",
            "mission_authority_unilateral_replacement",
            "in_place_plan_mutation",
        ],
        "recommended_option_id": "independently_reviewed_exact_item_mapping",
    },
    {
        "decision_id": "D005",
        "question_id": "distributed_execution_transfer",
        "prompt": "How must an external execution system acknowledge transfer or cancellation?",
        "option_ids": [
            "fenced_sessions_signed_acknowledgement_and_timeout",
            "control_plane_record_only",
            "best_effort_runtime_notice",
            "runtime_local_transfer",
        ],
        "recommended_option_id": "fenced_sessions_signed_acknowledgement_and_timeout",
    },
)

RECOMMENDATION = {
    "alternative_id": RECOMMENDED_ALTERNATIVE_ID,
    "recommended_option_bundle": {
        item["decision_id"]: item["recommended_option_id"] for item in DECISION_QUESTIONS
    },
    "rationale": [
        "preserves_existing_authenticated_handoff_guarantees",
        "makes_privileged_role_changes_independently_reviewable",
        "keeps_cross_command_change_at_the_plan_boundary",
        "preserves_immutable_history_and_deterministic_replay",
        "requires_external_execution_to_acknowledge_a_fenced_transition",
    ],
    "selection_state": "not_selected",
}

IMPLEMENTATION_SEQUENCE = (
    "approve_d001_through_d005_collaboration_authority_bundle",
    "define_reconfiguration_authority_policy",
    "define_bounded_ownership_chain_and_revocation_contracts",
    "define_reviewed_plan_replacement_and_item_mapping_contracts",
    "define_cross_command_capability_and_qualification_review",
    "define_fenced_external_execution_acknowledgement_protocol",
    "implement_atomic_persistence_and_replay_validation",
    "add_adversarial_concurrency_cycle_stale_plan_and_partial_ack_tests",
)

LIMITATIONS = (
    "This dossier does not select, approve, or apply a collaboration authority model.",
    (
        "The recommendation does not authorize reassignment, repeated "
        "delegation, cross-command transfer, or plan replacement."
    ),
    (
        "No mission authority, owner, reviewer, commander, worker, runtime, "
        "provider, endpoint, tool, credential, target, or execution connector "
        "is selected."
    ),
    (
        "The existing single-handoff, same-command, specialist-only boundary "
        "remains authoritative until a later decision is approved and implemented."
    ),
)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CollaborationPlanError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise CollaborationPlanError(f"{label} keys must be strings")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unsupported: " + ", ".join(extra))
        raise CollaborationPlanError(f"{label} fields are invalid; " + "; ".join(details))


def _non_negative_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CollaborationPlanError(f"{label} must be a non-negative integer")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} must be a canonical SHA-256 digest")
    return value


def _catalog_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "version", "sha256"}, label)
    identifier = value.get("id")
    version = value.get("version")
    if not isinstance(identifier, str) or IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise CollaborationPlanError(f"{label}.id is invalid")
    if not isinstance(version, str) or SEMVER_PATTERN.fullmatch(version) is None:
        raise CollaborationPlanError(f"{label}.version is invalid")
    return {
        "id": identifier,
        "version": version,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _validate_scope(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "current_scope")
    fields = {
        "specialist_count",
        "qualified_specialist_count",
        "domain_command_count",
        "domain_commander_count",
        "shared_profile_count",
        "sqlite_schema_version",
        "transferable_work_item_kinds",
        "maximum_handoffs_per_work_item",
        "cross_command_handoff",
        "activated_plan_replacement",
        "distributed_execution_acknowledgement",
    }
    _exact_fields(value, fields, "current_scope")
    parsed = {
        "specialist_count": _non_negative_integer(
            value.get("specialist_count"), "current_scope.specialist_count"
        ),
        "qualified_specialist_count": _non_negative_integer(
            value.get("qualified_specialist_count"),
            "current_scope.qualified_specialist_count",
        ),
        "domain_command_count": _non_negative_integer(
            value.get("domain_command_count"), "current_scope.domain_command_count"
        ),
        "domain_commander_count": _non_negative_integer(
            value.get("domain_commander_count"),
            "current_scope.domain_commander_count",
        ),
        "shared_profile_count": _non_negative_integer(
            value.get("shared_profile_count"), "current_scope.shared_profile_count"
        ),
        "sqlite_schema_version": value.get("sqlite_schema_version"),
        "transferable_work_item_kinds": value.get("transferable_work_item_kinds"),
        "maximum_handoffs_per_work_item": value.get("maximum_handoffs_per_work_item"),
        "cross_command_handoff": value.get("cross_command_handoff"),
        "activated_plan_replacement": value.get("activated_plan_replacement"),
        "distributed_execution_acknowledgement": value.get(
            "distributed_execution_acknowledgement"
        ),
    }
    if parsed["qualified_specialist_count"] > parsed["specialist_count"]:
        raise CollaborationPlanError("current_scope qualified specialist count is invalid")
    exact = {
        "sqlite_schema_version": CURRENT_SQLITE_SCHEMA_VERSION,
        "transferable_work_item_kinds": ["specialist_analysis"],
        "maximum_handoffs_per_work_item": 1,
        "cross_command_handoff": False,
        "activated_plan_replacement": False,
        "distributed_execution_acknowledgement": False,
    }
    for key, expected in exact.items():
        if parsed[key] != expected:
            raise CollaborationPlanError(f"current_scope.{key} does not match the boundary")
    return parsed


def _require_exact(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        raise CollaborationPlanError(f"{label} does not match the D001-D005 contract")


@dataclass(frozen=True)
class CollaborationAuthorityDecisionDossier:
    """Self-identifying, non-deciding collaboration authority dossier."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationAuthorityDecisionDossier:
        value = _mapping(raw, "collaboration authority decision dossier")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "decision_effect",
            "decision_ids",
            "registry",
            "capability_catalog",
            "routing_policy",
            "current_scope",
            "nonnegotiable_requirements",
            "alternatives",
            "decision_questions",
            "recommendation",
            "implementation_sequence_after_decision",
            "limitations",
        }
        _exact_fields(value, fields, "collaboration authority decision dossier")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise CollaborationPlanError(
                "Collaboration authority dossier schema version is invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if not isinstance(report_id, str) or REPORT_ID_PATTERN.fullmatch(report_id) is None:
            raise CollaborationPlanError("Collaboration authority dossier report ID is invalid")
        _sha256(report_sha256, "report_sha256")
        if value.get("status") != "decision_required":
            raise CollaborationPlanError(
                "Collaboration authority dossier status must be decision_required"
            )
        if value.get("decision_effect") != "none":
            raise CollaborationPlanError(
                "Collaboration authority dossier decision effect must be none"
            )
        _require_exact(value.get("decision_ids"), list(DECISION_IDS), "decision_ids")
        _catalog_binding(value.get("registry"), "registry")
        _catalog_binding(value.get("capability_catalog"), "capability_catalog")
        _catalog_binding(value.get("routing_policy"), "routing_policy")
        _validate_scope(value.get("current_scope"))
        _require_exact(
            value.get("nonnegotiable_requirements"),
            {
                "authority_binding_requirements": list(AUTHORITY_BINDING_REQUIREMENTS),
                "separation_requirements": list(SEPARATION_REQUIREMENTS),
                "fail_closed_requirements": list(FAIL_CLOSED_REQUIREMENTS),
                "history_requirements": list(HISTORY_REQUIREMENTS),
                "private_key_storage_in_sunderkey": False,
                "execution_credentials_in_reconfiguration": False,
                "direct_runtime_control": False,
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
            raise CollaborationPlanError("Collaboration authority dossier hash is invalid")
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Collaboration authority dossier document is invalid")
        return value


def assess_collaboration_authority_decisions(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    routing_policy: RoutingPolicy,
) -> CollaborationAuthorityDecisionDossier:
    """Build the D001-D005 choice set without making or applying decisions."""

    if not isinstance(registry, ExpertRegistry):
        raise CollaborationPlanError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise CollaborationPlanError("capability_catalog must be a CapabilityCatalog")
    if not isinstance(routing_policy, RoutingPolicy):
        raise CollaborationPlanError("routing_policy must be a RoutingPolicy")
    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
    routing_policy = routing_policy.revalidated(capability_catalog)
    specialists = tuple(
        profile for profile in registry.profiles if profile.kind is ProfileKind.SPECIALIST
    )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "decision_required",
        "decision_effect": "none",
        "decision_ids": list(DECISION_IDS),
        "registry": {
            "id": registry.catalog_id,
            "version": registry.catalog_version,
            "sha256": _canonical_sha256(registry.to_dict()),
        },
        "capability_catalog": {
            "id": capability_catalog.catalog_id,
            "version": capability_catalog.catalog_version,
            "sha256": capability_catalog.canonical_sha256,
        },
        "routing_policy": {
            "id": routing_policy.policy_id,
            "version": routing_policy.policy_version,
            "sha256": routing_policy.canonical_sha256,
        },
        "current_scope": {
            "specialist_count": len(specialists),
            "qualified_specialist_count": sum(
                profile.status in routing_policy.allowed_statuses
                and (not routing_policy.require_pilot or profile.pilot)
                for profile in specialists
            ),
            "domain_command_count": len(registry.commands),
            "domain_commander_count": sum(
                profile.kind is ProfileKind.DOMAIN_COMMANDER for profile in registry.profiles
            ),
            "shared_profile_count": sum(
                profile.kind is ProfileKind.SHARED for profile in registry.profiles
            ),
            "sqlite_schema_version": CURRENT_SQLITE_SCHEMA_VERSION,
            "transferable_work_item_kinds": ["specialist_analysis"],
            "maximum_handoffs_per_work_item": 1,
            "cross_command_handoff": False,
            "activated_plan_replacement": False,
            "distributed_execution_acknowledgement": False,
        },
        "nonnegotiable_requirements": {
            "authority_binding_requirements": list(AUTHORITY_BINDING_REQUIREMENTS),
            "separation_requirements": list(SEPARATION_REQUIREMENTS),
            "fail_closed_requirements": list(FAIL_CLOSED_REQUIREMENTS),
            "history_requirements": list(HISTORY_REQUIREMENTS),
            "private_key_storage_in_sunderkey": False,
            "execution_credentials_in_reconfiguration": False,
            "direct_runtime_control": False,
        },
        "alternatives": copy.deepcopy(list(ALTERNATIVES)),
        "decision_questions": copy.deepcopy(list(DECISION_QUESTIONS)),
        "recommendation": copy.deepcopy(RECOMMENDATION),
        "implementation_sequence_after_decision": list(IMPLEMENTATION_SEQUENCE),
        "limitations": list(LIMITATIONS),
    }
    report_hash = _report_hash(body)
    return CollaborationAuthorityDecisionDossier.from_dict(
        {**body, "report_id": _report_id(report_hash), "report_sha256": report_hash}
    )


def load_collaboration_authority_decision_dossier(
    path: str | Path,
) -> CollaborationAuthorityDecisionDossier:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load collaboration authority decision dossier: {resolved}"
        ) from exc
    return CollaborationAuthorityDecisionDossier.from_dict(raw)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})


def _report_id(report_hash: str) -> str:
    return "CAD-" + report_hash.removeprefix("sha256:")[:32].upper()


__all__ = [
    "CollaborationAuthorityDecisionDossier",
    "assess_collaboration_authority_decisions",
    "load_collaboration_authority_decision_dossier",
]
