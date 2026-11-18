"""Offline preparation packet for deployment-owned candidate enrollment work."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_implementation import (
    OPERATIONAL_PREREQUISITES,
    CandidateEnrollmentImplementationReport,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
PACKET_DOMAIN = "sunderkey.candidate-enrollment-deployment-preparation.v1"
_PACKET_ID_PATTERN = re.compile(r"CDP-[0-9A-F]{32}")
_REPORT_ID_PATTERN = re.compile(r"CEI-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

EXTERNAL_INPUTS = (
    {
        "input_id": "select_organization_issuer_audience_and_catalog_identity",
        "input_kind": "organization_namespace_selection",
        "accountable_roles": ["deployment_owner", "independent_control"],
        "completion_evidence": [
            "approved_issuer_identifier",
            "approved_audience_identifier",
            "approved_logical_catalog_identifier",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "obtain_d008_offline_root_public_key_through_out_of_band_trust",
        "input_kind": "out_of_band_trust_anchor",
        "accountable_roles": ["offline_root_custodian", "deployment_owner"],
        "completion_evidence": [
            "root_key_identifier",
            "ed25519_public_key",
            "independent_fingerprint_verification_record",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "issue_root_signed_enrollment_signer_authorization",
        "input_kind": "root_signed_authorization",
        "accountable_roles": ["offline_root_custodian", "enrollment_release_operator"],
        "completion_evidence": [
            "separated_signer_public_key",
            "signed_signer_authorization",
            "authorization_validity_and_key_separation_review",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "issue_role_scoped_control_and_assurance_reviewer_credentials",
        "input_kind": "separated_reviewer_credentials",
        "accountable_roles": [
            "qualification_credential_issuer",
            "independent_control",
            "independent_assurance",
        ],
        "completion_evidence": [
            "control_reviewer_credential",
            "assurance_reviewer_credential",
            "reviewer_identity_and_key_separation_review",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "select_exact_candidate_owner_identity_and_public_key",
        "input_kind": "candidate_owner_binding",
        "accountable_roles": ["candidate_owner", "deployment_owner"],
        "completion_evidence": [
            "exact_profile_and_candidate_binding",
            "candidate_owner_identifier",
            "candidate_owner_ed25519_public_key",
            "candidate_artifact_sha256",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "select_organization_logical_evidence_repository_identity",
        "input_kind": "logical_repository_selection",
        "accountable_roles": ["evidence_custodian", "deployment_owner"],
        "completion_evidence": [
            "logical_repository_identifier",
            "sha256_content_addressing_confirmation",
            "credential_and_endpoint_exclusion_review",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "produce_independently_reviewed_and_signed_enrollment_catalog",
        "input_kind": "reviewed_signed_release",
        "accountable_roles": [
            "enrollment_release_operator",
            "independent_control",
            "independent_assurance",
        ],
        "completion_evidence": [
            "signed_control_release_review",
            "signed_assurance_release_review",
            "signed_enrollment_catalog",
            "offline_verification_receipt",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "distribute_catalog_and_revocations_through_reviewed_release_process",
        "input_kind": "reviewed_distribution",
        "accountable_roles": ["enrollment_release_operator", "deployment_owner"],
        "completion_evidence": [
            "content_addressed_catalog_release",
            "revocation_distribution_procedure",
            "consumer_verification_instructions",
        ],
        "status": "external_input_required",
    },
    {
        "input_id": "protect_last_seen_catalog_checkpoint_against_rollback",
        "input_kind": "rollback_checkpoint_custody",
        "accountable_roles": ["deployment_owner", "independent_control"],
        "completion_evidence": [
            "checkpoint_custodian_assignment",
            "protected_storage_and_recovery_procedure",
            "rollback_response_procedure",
        ],
        "status": "external_input_required",
    },
)

CEREMONIES = (
    {
        "ceremony_id": "establish_organization_namespace",
        "sequence": 1,
        "depends_on": [],
        "input_ids": [EXTERNAL_INPUTS[0]["input_id"]],
        "acceptance_checks": [
            "identifiers_are_stable_and_environment_specific",
            "catalog_identity_contains_no_network_endpoint",
        ],
    },
    {
        "ceremony_id": "establish_separated_trust_roles",
        "sequence": 2,
        "depends_on": ["establish_organization_namespace"],
        "input_ids": [
            EXTERNAL_INPUTS[1]["input_id"],
            EXTERNAL_INPUTS[2]["input_id"],
            EXTERNAL_INPUTS[3]["input_id"],
        ],
        "acceptance_checks": [
            "root_signer_reviewer_and_owner_keys_are_distinct",
            "credential_and_authorization_scopes_are_exact",
            "all_validity_windows_are_bounded",
        ],
    },
    {
        "ceremony_id": "bind_candidate_owner_and_repository",
        "sequence": 3,
        "depends_on": ["establish_separated_trust_roles"],
        "input_ids": [
            EXTERNAL_INPUTS[4]["input_id"],
            EXTERNAL_INPUTS[5]["input_id"],
        ],
        "acceptance_checks": [
            "candidate_binding_is_exact_and_content_addressed",
            "repository_identity_is_logical_and_uses_sha256",
            "private_keys_credentials_and_endpoints_are_excluded",
        ],
    },
    {
        "ceremony_id": "review_sign_and_distribute_catalog",
        "sequence": 4,
        "depends_on": ["bind_candidate_owner_and_repository"],
        "input_ids": [
            EXTERNAL_INPUTS[6]["input_id"],
            EXTERNAL_INPUTS[7]["input_id"],
        ],
        "acceptance_checks": [
            "control_and_assurance_reviews_are_independent_and_valid",
            "catalog_signature_scope_expiry_and_predecessor_are_valid",
            "release_is_content_addressed_and_offline_verifiable",
        ],
    },
    {
        "ceremony_id": "establish_checkpoint_custody",
        "sequence": 5,
        "depends_on": ["review_sign_and_distribute_catalog"],
        "input_ids": [EXTERNAL_INPUTS[8]["input_id"]],
        "acceptance_checks": [
            "last_seen_version_and_digest_survive_restart",
            "rollback_detection_fails_closed",
            "recovery_requires_reviewed_operator_action",
        ],
    },
)

PROHIBITED_CONTENT = (
    "private_keys",
    "private_key_references",
    "repository_credentials",
    "repository_connection_profiles",
    "network_endpoints",
    "provider_credentials",
)

PROHIBITED_EFFECTS = (
    "does_not_generate_import_store_or_select_private_keys",
    "does_not_issue_credentials_authorizations_reviews_or_signatures",
    "does_not_enroll_a_live_owner_candidate_or_repository",
    "does_not_publish_or_distribute_a_live_catalog",
    "does_not_accept_or_retrieve_live_evidence",
    "does_not_qualify_a_candidate_or_specialist",
    "does_not_change_registry_status_or_routing_eligibility",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_runtime_or_sqlite_state",
)


def _packet_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})


def _packet_id(packet_hash: str) -> str:
    return "CDP-" + packet_hash.removeprefix("sha256:")[:32].upper()


@dataclass(frozen=True)
class CandidateEnrollmentDeploymentPreparationPacket:
    """Deterministic instructions for the organization-owned enrollment ceremony."""

    packet_id: str
    packet_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CandidateEnrollmentDeploymentPreparationPacket:
        value = _mapping(raw, "candidate enrollment deployment preparation packet")
        fields = {
            "schema_version",
            "packet_id",
            "packet_sha256",
            "implementation_report",
            "deployment_status",
            "external_inputs",
            "ceremonies",
            "readiness",
            "prohibited_content",
            "prohibited_effects",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment deployment preparation packet")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment deployment schema is invalid")
        packet_id = value.get("packet_id")
        packet_sha256 = value.get("packet_sha256")
        if not isinstance(packet_id, str) or _PACKET_ID_PATTERN.fullmatch(packet_id) is None:
            raise QualificationError("Candidate enrollment deployment packet ID is invalid")
        if (
            not isinstance(packet_sha256, str)
            or _SHA256_PATTERN.fullmatch(packet_sha256) is None
        ):
            raise QualificationError("Candidate enrollment deployment digest is invalid")
        implementation = _mapping(
            value.get("implementation_report"),
            "deployment implementation report",
        )
        _exact_fields(
            implementation,
            {"report_id", "sha256", "implementation_status"},
            "deployment implementation report",
        )
        if (
            not isinstance(implementation.get("report_id"), str)
            or _REPORT_ID_PATTERN.fullmatch(str(implementation["report_id"])) is None
            or not isinstance(implementation.get("sha256"), str)
            or _SHA256_PATTERN.fullmatch(str(implementation["sha256"])) is None
            or implementation.get("implementation_status")
            != "contract_implementation_complete"
        ):
            raise QualificationError("Candidate enrollment implementation binding is invalid")
        if value.get("deployment_status") != "awaiting_external_inputs":
            raise QualificationError("Candidate enrollment deployment status is invalid")
        if value.get("external_inputs") != [dict(item) for item in EXTERNAL_INPUTS]:
            raise QualificationError("Candidate enrollment external inputs are invalid")
        if value.get("ceremonies") != [dict(item) for item in CEREMONIES]:
            raise QualificationError("Candidate enrollment ceremonies are invalid")
        readiness = _mapping(value.get("readiness"), "deployment readiness")
        _exact_fields(
            readiness,
            {
                "ready_for_live_enrollment",
                "pending_input_count",
                "pending_input_ids",
                "next_action",
            },
            "deployment readiness",
        )
        expected_ids = [item["input_id"] for item in EXTERNAL_INPUTS]
        if readiness != {
            "ready_for_live_enrollment": False,
            "pending_input_count": len(expected_ids),
            "pending_input_ids": expected_ids,
            "next_action": "complete_external_inputs_under_organization_change_control",
        }:
            raise QualificationError("Candidate enrollment deployment readiness is invalid")
        if value.get("prohibited_content") != list(PROHIBITED_CONTENT):
            raise QualificationError("Candidate enrollment prohibited content is invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment prohibited effects are invalid")
        if (
            value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment deployment boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"packet_id", "packet_sha256"}
        }
        expected_hash = _packet_hash(body)
        if packet_sha256 != expected_hash or packet_id != _packet_id(expected_hash):
            raise QualificationError("Candidate enrollment deployment packet hash is invalid")
        return cls(
            packet_id=packet_id,
            packet_sha256=packet_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment deployment packet is invalid")
        return value


def build_candidate_enrollment_deployment_preparation(
    implementation: CandidateEnrollmentImplementationReport,
) -> CandidateEnrollmentDeploymentPreparationPacket:
    """Prepare offline ceremonies without fabricating organization-owned inputs."""

    if not isinstance(implementation, CandidateEnrollmentImplementationReport):
        raise QualificationError(
            "implementation must be a CandidateEnrollmentImplementationReport"
        )
    implementation = CandidateEnrollmentImplementationReport.from_dict(
        implementation.to_dict()
    )
    report = implementation.to_dict()
    if (
        report["implementation_status"] != "contract_implementation_complete"
        or report["live_enrollment_status"] != "not_started"
        or report["operational_prerequisites"] != list(OPERATIONAL_PREREQUISITES)
    ):
        raise QualificationError("Candidate enrollment implementation is not ready to prepare")
    pending_ids = [item["input_id"] for item in EXTERNAL_INPUTS]
    body = {
        "schema_version": SCHEMA_VERSION,
        "implementation_report": {
            "report_id": implementation.report_id,
            "sha256": implementation.report_sha256,
            "implementation_status": report["implementation_status"],
        },
        "deployment_status": "awaiting_external_inputs",
        "external_inputs": [dict(item) for item in EXTERNAL_INPUTS],
        "ceremonies": [dict(item) for item in CEREMONIES],
        "readiness": {
            "ready_for_live_enrollment": False,
            "pending_input_count": len(pending_ids),
            "pending_input_ids": pending_ids,
            "next_action": "complete_external_inputs_under_organization_change_control",
        },
        "prohibited_content": list(PROHIBITED_CONTENT),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    packet_hash = _packet_hash(body)
    return CandidateEnrollmentDeploymentPreparationPacket.from_dict(
        {
            **body,
            "packet_id": _packet_id(packet_hash),
            "packet_sha256": packet_hash,
        }
    )


def load_candidate_enrollment_deployment_preparation(
    path: str | Path,
) -> CandidateEnrollmentDeploymentPreparationPacket:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment deployment preparation: {resolved}"
        ) from exc
    return CandidateEnrollmentDeploymentPreparationPacket.from_dict(raw)


__all__ = [
    "CandidateEnrollmentDeploymentPreparationPacket",
    "build_candidate_enrollment_deployment_preparation",
    "load_candidate_enrollment_deployment_preparation",
]
