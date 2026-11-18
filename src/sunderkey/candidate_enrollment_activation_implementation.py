"""Deterministic D011 checkpoint and activation implementation report."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_activation_decision import (
    CandidateEnrollmentActivationDecisionRecord,
)
from .candidate_enrollment_canary import CandidateEnrollmentCanaryPreparationPacket
from .candidate_enrollment_release_contract import CandidateEnrollmentReleasePolicy
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.candidate-enrollment-activation-implementation.d011.v1"
_REPORT_ID_PATTERN = re.compile(r"CAI-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

IMPLEMENTED_STEPS = (
    {
        "step_id": "define_checkpoint_store_and_release_ledger_contracts",
        "phase": 75,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_release_contract.py",
            "registry/candidate-enrollment-release-policy-d011.json",
            "tests/agents/test_candidate_enrollment_release_contract_phase75.py",
        ],
    },
    {
        "step_id": "implement_atomic_local_checkpoint_adapter",
        "phase": 76,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_checkpoint_store.py",
            "registry/schemas/candidate-enrollment-checkpoint-commit-receipt-v1.schema.json",
            "tests/agents/test_candidate_enrollment_checkpoint_store_phase76.py",
        ],
    },
    {
        "step_id": "implement_release_intent_promotion_and_completion_protocol",
        "phase": 77,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_release_protocol.py",
            "registry/schemas/candidate-enrollment-release-completion-receipt-v1.schema.json",
            "tests/agents/test_candidate_enrollment_release_protocol_phase77.py",
        ],
    },
    {
        "step_id": "implement_fail_closed_crash_and_recovery_state_machine",
        "phase": 78,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_release_recovery.py",
            "registry/schemas/candidate-enrollment-release-recovery-receipt-v1.schema.json",
            "tests/agents/test_candidate_enrollment_release_recovery_phase78.py",
        ],
    },
    {
        "step_id": "add_adversarial_rollback_corruption_and_partial_failure_tests",
        "phase": 78,
        "artifacts": [
            "tests/agents/test_candidate_enrollment_checkpoint_store_phase76.py",
            "tests/agents/test_candidate_enrollment_release_protocol_phase77.py",
            "tests/agents/test_candidate_enrollment_release_recovery_phase78.py",
        ],
    },
    {
        "step_id": "prepare_single_candidate_canary_activation_packet",
        "phase": 79,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_canary.py",
            "registry/candidate-enrollment-canary-preparation-d011.json",
            "tests/agents/test_candidate_enrollment_canary_phase79.py",
        ],
    },
)

IMPLEMENTED_SECURITY_PROPERTIES = (
    "monotonic_version_and_digest_checkpoint_validation",
    "same_version_same_digest_idempotent_retry_only",
    "atomic_checkpoint_replace_with_verified_access_control",
    "checkpoint_commit_before_catalog_promotion",
    "append_only_hash_chained_release_event_contract",
    "exact_phase72_verification_receipt_binding",
    "dual_control_initialization_and_recovery",
    "fail_closed_partial_state_assessment",
    "same_digest_recovery_without_history_rewrite",
    "single_candidate_canary_without_automatic_expansion",
)

PRODUCTION_PREREQUISITES = (
    "select_production_deployment_and_service_identity",
    "verify_platform_checkpoint_acl_and_durability_provider",
    "verify_append_only_release_ledger_provider",
    "verify_content_addressed_catalog_repository_provider",
    "supply_verified_controlled_release_outcome",
    "select_exact_single_candidate_enrollment",
    "complete_rollback_revocation_and_partial_failure_drills",
    "define_canary_observation_and_stop_plan",
    "record_explicit_canary_go_no_go_decision",
)

PROHIBITED_EFFECTS = (
    "does_not_supply_production_acl_ledger_or_repository_adapters",
    "does_not_select_a_deployment_identity_or_candidate",
    "does_not_persist_or_initialize_a_production_checkpoint",
    "does_not_publish_or_promote_a_production_catalog",
    "does_not_activate_enrollment_or_accept_live_evidence",
    "does_not_generate_keys_credentials_signatures_or_attestations",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})


def _report_id(report_hash: str) -> str:
    return "CAI-" + report_hash.removeprefix("sha256:")[:32].upper()


@dataclass(frozen=True)
class CandidateEnrollmentActivationImplementationReport:
    """Evidence that D011 contract work exists without activation authority."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls, raw: Any
    ) -> CandidateEnrollmentActivationImplementationReport:
        value = _mapping(raw, "candidate enrollment activation implementation report")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "decision",
            "release_policy",
            "canary_preparation",
            "implementation_status",
            "implemented_steps",
            "implemented_security_properties",
            "production_prerequisites",
            "live_activation_status",
            "authorized_next_action",
            "prohibited_effects",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(
            value,
            fields,
            "candidate enrollment activation implementation report",
        )
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Activation implementation schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or _REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Activation implementation identity is invalid")
        bindings = {
            "decision": ("record_id", r"CAR-[0-9A-F]{32}"),
            "release_policy": ("policy_id", r"CRP-[0-9A-F]{32}"),
            "canary_preparation": ("packet_id", r"CAP-[0-9A-F]{32}"),
        }
        for field, (id_field, pattern) in bindings.items():
            binding = _mapping(value.get(field), field)
            _exact_fields(binding, {id_field, "sha256"}, field)
            if (
                not isinstance(binding.get(id_field), str)
                or re.fullmatch(pattern, str(binding[id_field])) is None
                or not isinstance(binding.get("sha256"), str)
                or _SHA256_PATTERN.fullmatch(str(binding["sha256"])) is None
            ):
                raise QualificationError(f"Activation implementation {field} is invalid")
        expected_values = {
            "implementation_status": "approved_bundle_contract_implementation_complete",
            "implemented_steps": [dict(item) for item in IMPLEMENTED_STEPS],
            "implemented_security_properties": list(IMPLEMENTED_SECURITY_PROPERTIES),
            "production_prerequisites": list(PRODUCTION_PREREQUISITES),
            "live_activation_status": "blocked_pending_production_inputs_and_go_no_go",
            "authorized_next_action": "select_production_custody_and_deployment_inputs",
            "prohibited_effects": list(PROHIBITED_EFFECTS),
            "network_call_performed": False,
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        for field, expected in expected_values.items():
            if value.get(field) != expected:
                raise QualificationError(f"Activation implementation {field} is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_sha256 != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError("Activation implementation report hash is invalid")
        return cls(report_id, report_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Activation implementation report is invalid")
        return value


def build_candidate_enrollment_activation_implementation_report(
    decision: CandidateEnrollmentActivationDecisionRecord,
    policy: CandidateEnrollmentReleasePolicy,
    canary: CandidateEnrollmentCanaryPreparationPacket,
) -> CandidateEnrollmentActivationImplementationReport:
    """Bind all approved D011 outputs while retaining the closed live gate."""

    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    policy = CandidateEnrollmentReleasePolicy.from_dict(policy.to_dict())
    canary = CandidateEnrollmentCanaryPreparationPacket.from_dict(canary.to_dict())
    decision_document = decision.to_dict()
    if (
        decision_document["decision_id"] != "D011"
        or decision_document["decision_effect"]
        != "checkpoint_and_release_contract_implementation_authorized"
        or not decision_document["recommendation_alignment"][
            "all_recommended_options_selected"
        ]
        or decision_document["authorized_next_steps"]
        != [item["step_id"] for item in IMPLEMENTED_STEPS]
    ):
        raise QualificationError("D011 does not authorize the implementation report")
    decision_binding = {
        "record_id": decision.record_id,
        "sha256": decision.record_sha256,
    }
    if policy.to_dict()["d011_decision"] != decision_binding:
        raise QualificationError("Activation implementation policy does not match D011")
    canary_document = canary.to_dict()
    if canary_document["d011_decision"] != decision_binding or canary_document[
        "release_policy"
    ] != {
        "policy_id": policy.policy_id,
        "sha256": policy.policy_sha256,
    }:
        raise QualificationError("Activation implementation canary inputs do not match")
    if [item["input_id"] for item in canary_document["required_external_inputs"]] != list(
        PRODUCTION_PREREQUISITES
    ):
        raise QualificationError("Activation implementation prerequisites do not match")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision_binding,
        "release_policy": {
            "policy_id": policy.policy_id,
            "sha256": policy.policy_sha256,
        },
        "canary_preparation": {
            "packet_id": canary.packet_id,
            "sha256": canary.packet_sha256,
        },
        "implementation_status": "approved_bundle_contract_implementation_complete",
        "implemented_steps": [dict(item) for item in IMPLEMENTED_STEPS],
        "implemented_security_properties": list(IMPLEMENTED_SECURITY_PROPERTIES),
        "production_prerequisites": list(PRODUCTION_PREREQUISITES),
        "live_activation_status": "blocked_pending_production_inputs_and_go_no_go",
        "authorized_next_action": "select_production_custody_and_deployment_inputs",
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _report_hash(body)
    return CandidateEnrollmentActivationImplementationReport.from_dict(
        {
            **body,
            "report_id": _report_id(digest),
            "report_sha256": digest,
        }
    )


def load_candidate_enrollment_activation_implementation_report(
    path: str | Path,
) -> CandidateEnrollmentActivationImplementationReport:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load activation implementation report: {resolved}"
        ) from exc
    return CandidateEnrollmentActivationImplementationReport.from_dict(raw)


__all__ = [
    "CandidateEnrollmentActivationImplementationReport",
    "build_candidate_enrollment_activation_implementation_report",
    "load_candidate_enrollment_activation_implementation_report",
]
