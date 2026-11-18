"""Deterministic D011 checkpoint custody and activation decision dossier."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_decision import CandidateEnrollmentDecisionRecord
from .candidate_enrollment_deployment import (
    CandidateEnrollmentDeploymentPreparationPacket,
)
from .candidate_enrollment_implementation import (
    CandidateEnrollmentImplementationReport,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
DOSSIER_DOMAIN = "sunderkey.candidate-enrollment-activation-dossier.d011.v1"
_DOSSIER_ID_PATTERN = re.compile(r"CAD-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

DECISION_QUESTIONS = (
    {
        "question_id": "checkpoint_authority",
        "prompt": "What is the authoritative anti-rollback checkpoint record?",
        "recommended_option_id": "append_only_release_ledger_with_local_mirror",
        "options": [
            {
                "option_id": "append_only_release_ledger_with_local_mirror",
                "name": "Append-only release ledger with local mirror",
                "impact": (
                    "Strong cross-host audit and offline enforcement with moderate operations"
                ),
                "recommended": True,
            },
            {
                "option_id": "deployment_local_checkpoint_only",
                "name": "Deployment-local checkpoint only",
                "impact": "Simple and offline but vulnerable to whole-host rollback",
                "recommended": False,
            },
            {
                "option_id": "hardware_monotonic_checkpoint",
                "name": "Hardware monotonic checkpoint",
                "impact": "Strong local rollback resistance with high platform complexity",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "local_checkpoint_storage",
        "prompt": "How is the offline enforcement mirror stored locally?",
        "recommended_option_id": "atomic_versioned_file_with_protected_acl_and_backup",
        "options": [
            {
                "option_id": "atomic_versioned_file_with_protected_acl_and_backup",
                "name": "Atomic versioned file with protected ACL and backup",
                "impact": "Keeps trust state separate from runtime data and supports recovery",
                "recommended": True,
            },
            {
                "option_id": "sqlite_checkpoint_row",
                "name": "SQLite checkpoint row",
                "impact": "Simple transactions but couples trust rollback to database recovery",
                "recommended": False,
            },
            {
                "option_id": "external_secret_store_only",
                "name": "External secret store only",
                "impact": "Central policy control but weakens offline availability",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "release_transaction",
        "prompt": "What ordering controls checkpoint and catalog publication?",
        "recommended_option_id": "verify_intent_checkpoint_promote_completion",
        "options": [
            {
                "option_id": "verify_intent_checkpoint_promote_completion",
                "name": "Verify, record intent, checkpoint, promote, record completion",
                "impact": "Supports crash recovery and safe same-digest retry",
                "recommended": True,
            },
            {
                "option_id": "publish_then_checkpoint",
                "name": "Publish then checkpoint",
                "impact": "Shorter flow but consumers may observe state before rollback protection",
                "recommended": False,
            },
            {
                "option_id": "checkpoint_then_manual_publish",
                "name": "Checkpoint then manual publish",
                "impact": "Offline simple but creates a long partial-release window",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "commit_and_recovery_authority",
        "prompt": "Who may advance, initialize, or recover checkpoint state?",
        "recommended_option_id": "automatic_advance_dual_control_initialization_and_recovery",
        "options": [
            {
                "option_id": "automatic_advance_dual_control_initialization_and_recovery",
                "name": "Automatic monotonic advance with dual-control initialization and recovery",
                "impact": "Keeps normal releases efficient and exceptional trust changes reviewed",
                "recommended": True,
            },
            {
                "option_id": "dual_control_every_advance",
                "name": "Dual control for every checkpoint advance",
                "impact": "Maximum manual oversight with slower revocation distribution",
                "recommended": False,
            },
            {
                "option_id": "deployment_owner_only",
                "name": "Deployment owner only",
                "impact": "Fast but weakens independent control over trust recovery",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "partial_failure_and_recovery",
        "prompt": "How does activation recover from interruption or corruption?",
        "recommended_option_id": "fail_closed_same_digest_retry_and_ledger_recovery",
        "options": [
            {
                "option_id": "fail_closed_same_digest_retry_and_ledger_recovery",
                "name": "Fail closed, retry same digest, recover from signed ledger",
                "impact": "Prevents rollback while making each interrupted step resumable",
                "recommended": True,
            },
            {
                "option_id": "operator_reset_to_last_backup",
                "name": "Operator reset to last backup",
                "impact": "Easy recovery but may reintroduce an older checkpoint",
                "recommended": False,
            },
            {
                "option_id": "automatic_checkpoint_recreation",
                "name": "Automatic checkpoint recreation",
                "impact": "High availability but trusts currently presented state after loss",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "catalog_distribution",
        "prompt": "Where is the reviewed signed catalog release distributed?",
        "recommended_option_id": "organization_content_addressed_artifact_repository",
        "options": [
            {
                "option_id": "organization_content_addressed_artifact_repository",
                "name": "Organization-controlled content-addressed artifact repository",
                "impact": "Matches D008 and D009 custody while keeping endpoints out of catalogs",
                "recommended": True,
            },
            {
                "option_id": "source_repository_release",
                "name": "Source repository release",
                "impact": (
                    "Auditable and simple but couples trust distribution to development access"
                ),
                "recommended": False,
            },
            {
                "option_id": "deployment_local_copy",
                "name": "Deployment-local copy",
                "impact": "Offline and simple but weak for revocation fanout and shared history",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "initial_activation_scope",
        "prompt": "How broad is the first live enrollment activation?",
        "recommended_option_id": "single_candidate_canary",
        "options": [
            {
                "option_id": "single_candidate_canary",
                "name": "Single candidate canary",
                "impact": "Bounds operational risk and validates rollback and revocation handling",
                "recommended": True,
            },
            {
                "option_id": "single_domain_wave",
                "name": "Single domain wave",
                "impact": "Faster coverage with a larger first-release blast radius",
                "recommended": False,
            },
            {
                "option_id": "full_army_activation",
                "name": "Full Army activation",
                "impact": "Fastest rollout with the largest untested operational exposure",
                "recommended": False,
            },
        ],
    },
    {
        "question_id": "release_chain_retention",
        "prompt": "How long are catalogs, checkpoints, intents, and outcomes retained?",
        "recommended_option_id": "full_chain_for_deployment_lifetime_plus_audit_period",
        "options": [
            {
                "option_id": "full_chain_for_deployment_lifetime_plus_audit_period",
                "name": "Full chain for deployment lifetime plus audit period",
                "impact": "Preserves rollback evidence and leaves audit duration to policy",
                "recommended": True,
            },
            {
                "option_id": "current_and_predecessor_only",
                "name": "Current and predecessor only",
                "impact": "Low storage with limited historical investigation",
                "recommended": False,
            },
            {
                "option_id": "fixed_seven_year_retention",
                "name": "Fixed seven-year retention",
                "impact": "Predictable but may conflict with organization or jurisdiction policy",
                "recommended": False,
            },
        ],
    },
)

RECOMMENDED_OPTIONS = {
    item["question_id"]: item["recommended_option_id"] for item in DECISION_QUESTIONS
}

NONNEGOTIABLE_REQUIREMENTS = (
    "no_checkpoint_version_or_digest_decrease",
    "same_version_requires_same_catalog_digest",
    "checkpoint_commit_precedes_catalog_promotion",
    "missing_corrupt_or_ambiguous_checkpoint_fails_closed",
    "recovery_never_trusts_self_declared_current_catalog_state",
    "private_keys_credentials_and_endpoints_remain_outside_checkpoint_records",
    "every_release_binds_the_phase72_verification_receipt",
    "no_live_evidence_acceptance_before_controlled_release_completion",
)

AUTHORIZED_NEXT_STEPS_IF_APPROVED = (
    "define_checkpoint_store_and_release_ledger_contracts",
    "implement_atomic_local_checkpoint_adapter",
    "implement_release_intent_promotion_and_completion_protocol",
    "implement_fail_closed_crash_and_recovery_state_machine",
    "add_adversarial_rollback_corruption_and_partial_failure_tests",
    "prepare_single_candidate_canary_activation_packet",
)

LIMITATIONS = (
    "does_not_select_or_approve_a_d011_option",
    "does_not_create_a_checkpoint_store_or_release_ledger",
    "does_not_persist_a_checkpoint_or_publish_a_catalog",
    "does_not_select_a_live_candidate_owner_key_repository_or_reviewer",
    "does_not_enroll_a_live_candidate_or_accept_live_evidence",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_a_network_request_or_mutate_sqlite",
)


@dataclass(frozen=True)
class CandidateEnrollmentActivationDecisionDossier:
    """Content-addressed D011 choices with no selected activation authority."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentActivationDecisionDossier:
        value = _mapping(raw, "candidate enrollment activation decision dossier")
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
            "nonnegotiable_requirements",
            "authorized_next_steps_if_approved",
            "limitations",
            "decision_effect",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment activation decision dossier")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment activation dossier schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or _DOSSIER_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Candidate enrollment activation dossier identity is invalid")
        if value.get("decision_id") != "D011" or value.get("status") != "decision_required":
            raise QualificationError("Candidate enrollment activation decision state is invalid")
        sources = _mapping(value.get("source_bindings"), "activation dossier sources")
        expected_source_fields = {
            "d009_decision",
            "implementation_report",
            "deployment_preparation",
            "verification_receipt_schema",
        }
        _exact_fields(sources, expected_source_fields, "activation dossier sources")
        source_patterns = {
            "d009_decision": ("record_id", r"CER-[0-9A-F]{32}"),
            "implementation_report": ("report_id", r"CEI-[0-9A-F]{32}"),
            "deployment_preparation": ("packet_id", r"CDP-[0-9A-F]{32}"),
            "verification_receipt_schema": ("schema_id", r"https://schemas\.sunderkey\.dev/[A-Za-z0-9._/-]+"),
        }
        for source_name, (id_field, pattern) in source_patterns.items():
            source = _mapping(sources.get(source_name), f"activation source {source_name}")
            _exact_fields(source, {id_field, "sha256"}, f"activation source {source_name}")
            if (
                not isinstance(source.get(id_field), str)
                or re.fullmatch(pattern, str(source[id_field])) is None
                or not isinstance(source.get("sha256"), str)
                or _SHA256_PATTERN.fullmatch(str(source["sha256"])) is None
            ):
                raise QualificationError(
                    f"Candidate enrollment activation source {source_name} is invalid"
                )
        expected_boundary = {
            "d009_contract_status": "complete",
            "deployment_documentation_status": "contract_available_inputs_not_supplied",
            "cryptographic_verification_status": "contract_available_no_live_receipt",
            "checkpoint_persistence_status": "not_implemented",
            "controlled_catalog_release_status": "not_implemented",
            "live_enrollment_status": "not_started",
        }
        if value.get("current_boundary") != expected_boundary:
            raise QualificationError("Candidate enrollment activation boundary is invalid")
        if value.get("decision_questions") != [dict(item) for item in DECISION_QUESTIONS]:
            raise QualificationError("Candidate enrollment activation questions are invalid")
        if value.get("recommendation") != {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": [
                "preserves_offline_verification_and_cross_host_audit",
                "keeps_normal_monotonic_advances_automatable",
                "requires_independent_control_for_initialization_and_recovery",
                "makes_partial_release_states_resumable_without_rollback",
                "bounds_first_activation_to_one_candidate",
            ],
        }:
            raise QualificationError("Candidate enrollment activation recommendation is invalid")
        if value.get("nonnegotiable_requirements") != list(NONNEGOTIABLE_REQUIREMENTS):
            raise QualificationError("Candidate enrollment activation requirements are invalid")
        if value.get("authorized_next_steps_if_approved") != list(
            AUTHORIZED_NEXT_STEPS_IF_APPROVED
        ):
            raise QualificationError("Candidate enrollment activation next steps are invalid")
        if value.get("limitations") != list(LIMITATIONS):
            raise QualificationError("Candidate enrollment activation limitations are invalid")
        if (
            value.get("decision_effect") != "none"
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment activation dossier effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
        expected_id = "CAD-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if report_sha256 != expected_hash or report_id != expected_id:
            raise QualificationError("Candidate enrollment activation dossier hash is invalid")
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment activation dossier is invalid")
        return value


def build_candidate_enrollment_activation_decision_dossier(
    d009_decision: CandidateEnrollmentDecisionRecord,
    implementation_report: CandidateEnrollmentImplementationReport,
    deployment_preparation: CandidateEnrollmentDeploymentPreparationPacket,
    verification_receipt_schema: Any,
) -> CandidateEnrollmentActivationDecisionDossier:
    """Package the unresolved activation choices without selecting an option."""

    if not isinstance(d009_decision, CandidateEnrollmentDecisionRecord):
        raise QualificationError("d009_decision is invalid")
    if not isinstance(implementation_report, CandidateEnrollmentImplementationReport):
        raise QualificationError("implementation_report is invalid")
    if not isinstance(
        deployment_preparation,
        CandidateEnrollmentDeploymentPreparationPacket,
    ):
        raise QualificationError("deployment_preparation is invalid")
    d009 = CandidateEnrollmentDecisionRecord.from_dict(d009_decision.to_dict())
    implementation = CandidateEnrollmentImplementationReport.from_dict(
        implementation_report.to_dict()
    )
    preparation = CandidateEnrollmentDeploymentPreparationPacket.from_dict(
        deployment_preparation.to_dict()
    )
    schema = _mapping(verification_receipt_schema, "verification receipt schema")
    schema_id = schema.get("$id")
    if schema_id != (
        "https://schemas.sunderkey.dev/"
        "candidate-enrollment-deployment-verification-receipt-v1.json"
    ):
        raise QualificationError("Verification receipt schema identity is invalid")
    if (
        d009.to_dict()["decision_status"] != "approved_operator_asserted_unsigned"
        or d009.to_dict()["decision_effect"] != "contract_implementation_authorized"
        or implementation.to_dict()["implementation_status"]
        != "contract_implementation_complete"
        or preparation.to_dict()["deployment_status"] != "awaiting_external_inputs"
    ):
        raise QualificationError("D011 source boundary is inconsistent")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D011",
        "status": "decision_required",
        "source_bindings": {
            "d009_decision": {
                "record_id": d009.record_id,
                "sha256": d009.record_sha256,
            },
            "implementation_report": {
                "report_id": implementation.report_id,
                "sha256": implementation.report_sha256,
            },
            "deployment_preparation": {
                "packet_id": preparation.packet_id,
                "sha256": preparation.packet_sha256,
            },
            "verification_receipt_schema": {
                "schema_id": schema_id,
                "sha256": _canonical_sha256(schema),
            },
        },
        "current_boundary": {
            "d009_contract_status": "complete",
            "deployment_documentation_status": "contract_available_inputs_not_supplied",
            "cryptographic_verification_status": "contract_available_no_live_receipt",
            "checkpoint_persistence_status": "not_implemented",
            "controlled_catalog_release_status": "not_implemented",
            "live_enrollment_status": "not_started",
        },
        "decision_questions": [dict(item) for item in DECISION_QUESTIONS],
        "recommendation": {
            "selection_state": "not_selected",
            "recommended_options": RECOMMENDED_OPTIONS,
            "rationale": [
                "preserves_offline_verification_and_cross_host_audit",
                "keeps_normal_monotonic_advances_automatable",
                "requires_independent_control_for_initialization_and_recovery",
                "makes_partial_release_states_resumable_without_rollback",
                "bounds_first_activation_to_one_candidate",
            ],
        },
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "authorized_next_steps_if_approved": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        "limitations": list(LIMITATIONS),
        "decision_effect": "none",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    report_sha256 = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
    return CandidateEnrollmentActivationDecisionDossier.from_dict(
        {
            **body,
            "report_id": "CAD-" + report_sha256.removeprefix("sha256:")[:32].upper(),
            "report_sha256": report_sha256,
        }
    )


def load_candidate_enrollment_activation_decision_dossier(
    path: str | Path,
) -> CandidateEnrollmentActivationDecisionDossier:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment activation dossier: {resolved}"
        ) from exc
    return CandidateEnrollmentActivationDecisionDossier.from_dict(raw)


__all__ = [
    "CandidateEnrollmentActivationDecisionDossier",
    "build_candidate_enrollment_activation_decision_dossier",
    "load_candidate_enrollment_activation_decision_dossier",
]
