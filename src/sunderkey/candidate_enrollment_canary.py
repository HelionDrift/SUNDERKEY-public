"""Deterministic single-candidate canary activation preparation packet."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_activation_decision import (
    CandidateEnrollmentActivationDecisionRecord,
)
from .candidate_enrollment_release_contract import CandidateEnrollmentReleasePolicy
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
PACKET_DOMAIN = "sunderkey.candidate-enrollment-canary-preparation.d011.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

REQUIRED_EXTERNAL_INPUTS = (
    {
        "input_id": "select_production_deployment_and_service_identity",
        "accountable_roles": ["deployment_owner", "platform_custodian"],
        "required_evidence": [
            "deployment_identifier",
            "service_identity_identifier",
            "service_identity_ownership_record",
        ],
    },
    {
        "input_id": "verify_platform_checkpoint_acl_and_durability_provider",
        "accountable_roles": ["platform_custodian", "independent_control"],
        "required_evidence": [
            "provider_implementation_digest",
            "service_identity_acl_test",
            "directory_durability_test",
            "symbolic_link_and_replacement_attack_test",
        ],
    },
    {
        "input_id": "verify_append_only_release_ledger_provider",
        "accountable_roles": ["release_ledger_custodian", "independent_control"],
        "required_evidence": [
            "provider_implementation_digest",
            "append_compare_and_swap_test",
            "fork_and_sequence_gap_rejection_test",
            "checkpoint_artifact_retrieval_test",
            "retention_policy_binding",
        ],
    },
    {
        "input_id": "verify_content_addressed_catalog_repository_provider",
        "accountable_roles": ["catalog_repository_custodian", "independent_control"],
        "required_evidence": [
            "logical_repository_identifier",
            "provider_implementation_digest",
            "same_digest_idempotency_test",
            "digest_collision_rejection_test",
            "retention_policy_binding",
        ],
    },
    {
        "input_id": "supply_verified_controlled_release_outcome",
        "accountable_roles": ["enrollment_release_operator", "independent_control"],
        "required_evidence": [
            "release_completion_or_recovery_receipt",
            "receipt_schema_validation",
            "phase72_reverification_record",
            "current_checkpoint_binding",
            "current_release_ledger_tail_binding",
        ],
    },
    {
        "input_id": "select_exact_single_candidate_enrollment",
        "accountable_roles": ["deployment_owner", "candidate_owner"],
        "required_evidence": [
            "profile_identifier",
            "candidate_identifier",
            "enrollment_identifier",
            "candidate_artifact_sha256",
            "candidate_owner_public_key_sha256",
            "logical_evidence_repository_identifier",
        ],
    },
    {
        "input_id": "complete_rollback_revocation_and_partial_failure_drills",
        "accountable_roles": ["independent_control", "independent_assurance"],
        "required_evidence": [
            "rollback_rejection_result",
            "same_version_digest_replacement_rejection_result",
            "revocation_distribution_result",
            "checkpoint_corruption_result",
            "promotion_interruption_recovery_result",
            "ledger_fork_rejection_result",
        ],
    },
    {
        "input_id": "define_canary_observation_and_stop_plan",
        "accountable_roles": ["deployment_owner", "independent_control"],
        "required_evidence": [
            "observation_window",
            "health_and_security_signals",
            "named_stop_authority",
            "candidate_deactivation_procedure",
            "incident_evidence_custody_plan",
        ],
    },
    {
        "input_id": "record_explicit_canary_go_no_go_decision",
        "accountable_roles": ["deployment_owner", "independent_control"],
        "required_evidence": [
            "deployment_owner_decision",
            "independent_control_decision",
            "exact_input_bundle_sha256",
            "decision_timestamp",
        ],
    },
)

ACTIVATION_GATES = (
    "all_external_inputs_present_and_content_addressed",
    "phase72_receipt_and_catalog_reverified",
    "controlled_release_receipt_verified",
    "checkpoint_and_ledger_tail_match_release",
    "platform_acl_and_durability_provider_verified",
    "append_only_ledger_provider_verified",
    "content_addressed_repository_provider_verified",
    "exactly_one_current_nonrevoked_enrollment_selected",
    "rollback_revocation_corruption_and_interruption_drills_passed",
    "observation_stop_and_deactivation_plan_approved",
    "deployment_owner_and_independent_control_go_decisions_match",
)

CRITICAL_STOP_CONDITIONS = (
    "any_digest_or_identifier_binding_mismatch",
    "checkpoint_missing_corrupt_stale_or_ambiguous",
    "ledger_missing_forked_gapped_or_not_append_only",
    "catalog_missing_expired_revoked_or_not_current",
    "release_outcome_not_completed_or_recovered_same_digest",
    "more_or_less_than_one_candidate_selected",
    "acl_or_directory_durability_not_proven",
    "rollback_revocation_or_partial_failure_drill_failure",
    "owner_and_control_decisions_missing_stale_or_disagreeing",
    "unexpected_network_target_tool_or_evidence_activity",
)

LIMITATIONS = (
    "does_not_select_a_deployment_service_identity_or_candidate",
    "does_not_supply_a_production_acl_ledger_or_repository_adapter",
    "does_not_create_or_accept_a_release_outcome",
    "does_not_activate_enrollment_or_accept_live_evidence",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_mutate_sqlite_runtime_checkpoint_or_ledger_state",
)


@dataclass(frozen=True)
class CandidateEnrollmentCanaryPreparationPacket:
    """Content-addressed external-input plan with no activation authority."""

    packet_id: str
    packet_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCanaryPreparationPacket:
        value = _mapping(raw, "candidate enrollment canary preparation packet")
        fields = {
            "schema_version",
            "packet_id",
            "packet_sha256",
            "d011_decision",
            "release_policy",
            "accepted_release_outcome_schemas",
            "preparation_status",
            "canary_scope",
            "required_external_inputs",
            "activation_gates",
            "critical_stop_conditions",
            "authorized_next_action",
            "limitations",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment canary preparation packet")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Canary preparation schema is invalid")
        packet_id = value.get("packet_id")
        packet_sha256 = value.get("packet_sha256")
        if (
            not isinstance(packet_id, str)
            or re.fullmatch(r"CAP-[0-9A-F]{32}", packet_id) is None
            or not isinstance(packet_sha256, str)
            or SHA256_PATTERN.fullmatch(packet_sha256) is None
        ):
            raise QualificationError("Canary preparation identity is invalid")
        sources = {
            "d011_decision": ("record_id", r"CAR-[0-9A-F]{32}"),
            "release_policy": ("policy_id", r"CRP-[0-9A-F]{32}"),
        }
        for field, (id_field, pattern) in sources.items():
            source = _mapping(value.get(field), field)
            _exact_fields(source, {id_field, "sha256"}, field)
            if (
                not isinstance(source.get(id_field), str)
                or re.fullmatch(pattern, str(source[id_field])) is None
                or not isinstance(source.get("sha256"), str)
                or SHA256_PATTERN.fullmatch(str(source["sha256"])) is None
            ):
                raise QualificationError(f"Canary preparation {field} is invalid")
        schemas = _mapping(
            value.get("accepted_release_outcome_schemas"),
            "accepted release outcome schemas",
        )
        _exact_fields(
            schemas,
            {"normal_completion", "recovery_completion"},
            "accepted release outcome schemas",
        )
        expected_schema_ids = {
            "normal_completion": (
                "https://schemas.sunderkey.dev/"
                "candidate-enrollment-release-completion-receipt-v1.json"
            ),
            "recovery_completion": (
                "https://schemas.sunderkey.dev/"
                "candidate-enrollment-release-recovery-receipt-v1.json"
            ),
        }
        for name, expected_id in expected_schema_ids.items():
            schema = _mapping(schemas.get(name), f"{name} schema")
            _exact_fields(schema, {"schema_id", "sha256"}, f"{name} schema")
            if (
                schema.get("schema_id") != expected_id
                or not isinstance(schema.get("sha256"), str)
                or SHA256_PATTERN.fullmatch(str(schema["sha256"])) is None
            ):
                raise QualificationError(f"Canary preparation {name} schema is invalid")
        expected_values = {
            "preparation_status": "awaiting_external_inputs_and_explicit_go_no_go",
            "canary_scope": {
                "maximum_candidate_count": 1,
                "activation_mode": "single_candidate_canary",
                "automatic_expansion_allowed": False,
                "live_evidence_before_activation_allowed": False,
            },
            "required_external_inputs": [dict(item) for item in REQUIRED_EXTERNAL_INPUTS],
            "activation_gates": list(ACTIVATION_GATES),
            "critical_stop_conditions": list(CRITICAL_STOP_CONDITIONS),
            "authorized_next_action": "collect_inputs_and_record_separate_canary_go_no_go",
            "limitations": list(LIMITATIONS),
            "network_call_performed": False,
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        for field, expected in expected_values.items():
            if value.get(field) != expected:
                raise QualificationError(f"Canary preparation {field} is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"packet_id", "packet_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
        expected_id = "CAP-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if packet_sha256 != expected_hash or packet_id != expected_id:
            raise QualificationError("Canary preparation packet hash is invalid")
        return cls(packet_id, packet_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Canary preparation packet is invalid")
        return value


def build_candidate_enrollment_canary_preparation(
    decision: CandidateEnrollmentActivationDecisionRecord,
    policy: CandidateEnrollmentReleasePolicy,
    normal_completion_schema: Any,
    recovery_completion_schema: Any,
) -> CandidateEnrollmentCanaryPreparationPacket:
    """Prepare the approved canary inputs without selecting live values."""

    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    policy = CandidateEnrollmentReleasePolicy.from_dict(policy.to_dict())
    if policy.to_dict()["d011_decision"] != {
        "record_id": decision.record_id,
        "sha256": decision.record_sha256,
    }:
        raise QualificationError("Canary release policy does not match D011")
    schemas: dict[str, dict[str, str]] = {}
    expected_ids = {
        "normal_completion": (
            "https://schemas.sunderkey.dev/"
            "candidate-enrollment-release-completion-receipt-v1.json"
        ),
        "recovery_completion": (
            "https://schemas.sunderkey.dev/"
            "candidate-enrollment-release-recovery-receipt-v1.json"
        ),
    }
    for name, raw_schema in (
        ("normal_completion", normal_completion_schema),
        ("recovery_completion", recovery_completion_schema),
    ):
        schema = _mapping(raw_schema, f"{name} schema")
        if schema.get("$id") != expected_ids[name]:
            raise QualificationError(f"Canary {name} schema identity is invalid")
        schemas[name] = {
            "schema_id": str(schema["$id"]),
            "sha256": _canonical_sha256(schema),
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "d011_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "release_policy": {
            "policy_id": policy.policy_id,
            "sha256": policy.policy_sha256,
        },
        "accepted_release_outcome_schemas": schemas,
        "preparation_status": "awaiting_external_inputs_and_explicit_go_no_go",
        "canary_scope": {
            "maximum_candidate_count": 1,
            "activation_mode": "single_candidate_canary",
            "automatic_expansion_allowed": False,
            "live_evidence_before_activation_allowed": False,
        },
        "required_external_inputs": [dict(item) for item in REQUIRED_EXTERNAL_INPUTS],
        "activation_gates": list(ACTIVATION_GATES),
        "critical_stop_conditions": list(CRITICAL_STOP_CONDITIONS),
        "authorized_next_action": "collect_inputs_and_record_separate_canary_go_no_go",
        "limitations": list(LIMITATIONS),
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
    return CandidateEnrollmentCanaryPreparationPacket.from_dict(
        {
            **body,
            "packet_id": "CAP-" + digest.removeprefix("sha256:")[:32].upper(),
            "packet_sha256": digest,
        }
    )


def load_candidate_enrollment_canary_preparation(
    path: str | Path,
) -> CandidateEnrollmentCanaryPreparationPacket:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load canary preparation: {resolved}") from exc
    return CandidateEnrollmentCanaryPreparationPacket.from_dict(raw)


__all__ = [
    "CandidateEnrollmentCanaryPreparationPacket",
    "build_candidate_enrollment_canary_preparation",
    "load_candidate_enrollment_canary_preparation",
]
