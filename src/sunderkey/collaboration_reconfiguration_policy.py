"""Decision-bound collaboration reconfiguration authority policy contract."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collaboration_authority_decision import CollaborationAuthorityDecisionRecord
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
POLICY_DOMAIN = "sunderkey.collaboration-reconfiguration-authority-policy.v1"
POLICY_ID_PATTERN = re.compile(r"RAP-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

TRANSITION_RULES = (
    {
        "decision_id": "D001",
        "transition_family": "privileged_role_reassignment",
        "approved_rule": "owner_replacement_and_independent_control",
        "required_parties": [
            "current_owner",
            "proposed_replacement",
            "independent_control",
        ],
        "conditional_parties": [
            "second_control_or_mission_authority_for_control_replacement"
        ],
        "result_boundary": "new_owner_epoch_after_atomic_commit",
    },
    {
        "decision_id": "D002",
        "transition_family": "delegation_return_and_revocation",
        "approved_rule": "versioned_bounded_chain_with_return_and_control_revocation",
        "required_parties": [
            "current_owner",
            "proposed_owner_for_delegation_or_return",
            "independent_control",
        ],
        "conditional_parties": ["control_revocation_authority_for_revocation"],
        "result_boundary": "new_chain_head_and_owner_epoch_after_atomic_commit",
    },
    {
        "decision_id": "D003",
        "transition_family": "cross_command_transfer",
        "approved_rule": "reviewed_plan_replacement_with_capability_revalidation",
        "required_parties": [
            "current_owner",
            "proposed_owner",
            "source_command",
            "destination_command",
            "independent_control",
        ],
        "conditional_parties": ["independent_assurance_when_assurance_work_changes"],
        "result_boundary": "replacement_plan_only_after_capability_and_qualification_review",
    },
    {
        "decision_id": "D004",
        "transition_family": "activated_plan_replacement",
        "approved_rule": "independently_reviewed_exact_item_mapping",
        "required_parties": [
            "mission_owner",
            "affected_current_owners",
            "affected_proposed_owners",
            "independent_control",
        ],
        "conditional_parties": ["second_control_for_control_role_mapping"],
        "result_boundary": "replacement_plan_and_mapping_commit_atomically",
    },
    {
        "decision_id": "D005",
        "transition_family": "distributed_execution_transfer_or_cancellation",
        "approved_rule": "fenced_sessions_signed_acknowledgement_and_timeout",
        "required_parties": [
            "control_plane_request_authority",
            "external_execution_acknowledger",
        ],
        "conditional_parties": ["independent_control_for_timeout_or_forced_cancellation"],
        "result_boundary": "effective_only_after_valid_fenced_acknowledgement",
    },
)

PARAMETER_CONTRACTS = (
    {
        "parameter_id": "maximum_delegation_depth",
        "value_type": "integer",
        "minimum": 1,
        "maximum": 8,
        "selected_value": None,
        "selection_authority": "signed_mission_reconfiguration_policy",
    },
    {
        "parameter_id": "reconfiguration_validity_seconds",
        "value_type": "integer",
        "minimum": 60,
        "maximum": 86400,
        "selected_value": None,
        "selection_authority": "signed_mission_reconfiguration_policy",
    },
    {
        "parameter_id": "execution_ack_timeout_seconds",
        "value_type": "integer",
        "minimum": 1,
        "maximum": 3600,
        "selected_value": None,
        "selection_authority": "signed_execution_channel_policy",
    },
    {
        "parameter_id": "maximum_plan_replacement_items",
        "value_type": "integer",
        "minimum": 1,
        "maximum": 10000,
        "selected_value": None,
        "selection_authority": "signed_mission_reconfiguration_policy",
    },
)

CURRENT_BOUNDARY = {
    "policy_status": "contract_defined_inactive",
    "maximum_handoffs_per_work_item": 1,
    "cross_command_handoff_enabled": False,
    "activated_plan_replacement_enabled": False,
    "distributed_execution_acknowledgement_enabled": False,
    "authorized_next_action": "implement_bounded_ownership_chain_and_revocation_contracts",
}

LIMITATIONS = (
    "does_not_select_live_policy_parameter_values",
    "does_not_create_signatures_credentials_or_execution_sessions",
    "does_not_reassign_transfer_cancel_or_replace_live_work",
    "does_not_activate_cross_command_or_repeated_delegation",
    "does_not_create_or_accept_external_execution_acknowledgements",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
    "does_not_qualify_a_specialist_or_change_routing",
)


@dataclass(frozen=True)
class CollaborationReconfigurationAuthorityPolicy:
    """Content-addressed inactive authority policy derived from the decision."""

    policy_id: str
    policy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationReconfigurationAuthorityPolicy:
        value = _mapping(raw, "collaboration reconfiguration authority policy")
        fields = {
            "schema_version",
            "policy_id",
            "policy_sha256",
            "decision",
            "approved_model",
            "transition_rules",
            "nonnegotiable_requirements",
            "parameter_contracts",
            "current_boundary",
            "limitations",
            "network_call_performed",
            "runtime_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "collaboration reconfiguration authority policy")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Reconfiguration policy schema is invalid")
        policy_id = value.get("policy_id")
        policy_sha256 = value.get("policy_sha256")
        if (
            not isinstance(policy_id, str)
            or POLICY_ID_PATTERN.fullmatch(policy_id) is None
            or not isinstance(policy_sha256, str)
            or SHA256_PATTERN.fullmatch(policy_sha256) is None
        ):
            raise CollaborationPlanError("Reconfiguration policy identity is invalid")
        decision = _mapping(value.get("decision"), "reconfiguration policy decision")
        _exact_fields(decision, {"record_id", "sha256"}, "reconfiguration policy decision")
        if (
            not isinstance(decision.get("record_id"), str)
            or re.fullmatch(r"CRD-[0-9A-F]{32}", str(decision["record_id"])) is None
            or not isinstance(decision.get("sha256"), str)
            or SHA256_PATTERN.fullmatch(str(decision["sha256"])) is None
        ):
            raise CollaborationPlanError("Reconfiguration policy decision is invalid")
        expected = {
            "approved_model": "reviewed_reconfiguration_ledger",
            "transition_rules": [dict(item) for item in TRANSITION_RULES],
            "parameter_contracts": [dict(item) for item in PARAMETER_CONTRACTS],
            "current_boundary": CURRENT_BOUNDARY,
            "limitations": list(LIMITATIONS),
            "network_call_performed": False,
            "runtime_effect": "none",
            "registry_effect": "none",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise CollaborationPlanError(f"Reconfiguration policy {field} is invalid")
        requirements = _mapping(
            value.get("nonnegotiable_requirements"),
            "reconfiguration policy requirements",
        )
        expected_requirement_fields = {
            "authority_binding_requirements",
            "separation_requirements",
            "fail_closed_requirements",
            "history_requirements",
            "private_key_storage_in_sunderkey",
            "execution_credentials_in_reconfiguration",
            "direct_runtime_control",
        }
        _exact_fields(
            requirements,
            expected_requirement_fields,
            "reconfiguration policy requirements",
        )
        for field in (
            "authority_binding_requirements",
            "separation_requirements",
            "fail_closed_requirements",
            "history_requirements",
        ):
            items = requirements.get(field)
            if (
                not isinstance(items, list)
                or not items
                or not all(isinstance(item, str) and item for item in items)
                or len(items) != len(set(items))
            ):
                raise CollaborationPlanError(f"Reconfiguration policy {field} is invalid")
        for field in (
            "private_key_storage_in_sunderkey",
            "execution_credentials_in_reconfiguration",
            "direct_runtime_control",
        ):
            if requirements.get(field) is not False:
                raise CollaborationPlanError(f"Reconfiguration policy {field} is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"policy_id", "policy_sha256"}
        }
        digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
        expected_id = "RAP-" + digest.removeprefix("sha256:")[:32].upper()
        if policy_sha256 != digest or policy_id != expected_id:
            raise CollaborationPlanError("Reconfiguration policy hash is invalid")
        return cls(policy_id, policy_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Reconfiguration policy is invalid")
        return value


def build_collaboration_reconfiguration_authority_policy(
    decision: CollaborationAuthorityDecisionRecord,
) -> CollaborationReconfigurationAuthorityPolicy:
    """Build the inactive policy contract from the approved owner decision."""

    decision = CollaborationAuthorityDecisionRecord.from_dict(decision.to_dict())
    document = decision.to_dict()
    if (
        document["decision_status"] != "approved_operator_asserted_unsigned"
        or document["decision_effect"]
        != "collaboration_reconfiguration_contract_implementation_authorized"
        or not document["recommendation_alignment"]["all_recommended_options_selected"]
        or not document["recommendation_alignment"]["recommended_alternative_selected"]
    ):
        raise CollaborationPlanError("Decision does not authorize the policy contract")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "approved_model": document["selected_alternative"],
        "transition_rules": [dict(item) for item in TRANSITION_RULES],
        "nonnegotiable_requirements": document["nonnegotiable_requirements"],
        "parameter_contracts": [dict(item) for item in PARAMETER_CONTRACTS],
        "current_boundary": CURRENT_BOUNDARY,
        "limitations": list(LIMITATIONS),
        "network_call_performed": False,
        "runtime_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    return CollaborationReconfigurationAuthorityPolicy.from_dict(
        {
            **body,
            "policy_id": "RAP-" + digest.removeprefix("sha256:")[:32].upper(),
            "policy_sha256": digest,
        }
    )


def load_collaboration_reconfiguration_authority_policy(
    path: str | Path,
) -> CollaborationReconfigurationAuthorityPolicy:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load reconfiguration policy: {resolved}") from exc
    return CollaborationReconfigurationAuthorityPolicy.from_dict(raw)


__all__ = [
    "CollaborationReconfigurationAuthorityPolicy",
    "build_collaboration_reconfiguration_authority_policy",
    "load_collaboration_reconfiguration_authority_policy",
]
