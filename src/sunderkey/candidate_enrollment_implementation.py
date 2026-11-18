"""Deterministic D009 candidate enrollment implementation completion report."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_decision import CandidateEnrollmentDecisionRecord
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.candidate-enrollment-implementation-report.v1"
_REPORT_ID_PATTERN = re.compile(r"CEI-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

IMPLEMENTED_STEPS = (
    {
        "step_id": "define_candidate_enrollment_catalog_schema",
        "phase": 66,
        "artifacts": [
            "registry/schemas/candidate-enrollment-catalog.schema.json",
            "src/sunderkey/candidate_enrollment.py",
        ],
    },
    {
        "step_id": "define_separated_enrollment_signer_key_use",
        "phase": 66,
        "artifacts": [
            "registry/schemas/candidate-enrollment-signer-authorization.schema.json",
            "src/sunderkey/candidate_enrollment.py",
        ],
    },
    {
        "step_id": "define_owner_key_and_repository_identity_bindings",
        "phase": 66,
        "artifacts": [
            "registry/schemas/candidate-enrollment-catalog.schema.json",
            "src/sunderkey/candidate_enrollment.py",
        ],
    },
    {
        "step_id": "define_rotation_and_revocation_record_schemas",
        "phase": 66,
        "artifacts": [
            "registry/schemas/candidate-enrollment-catalog.schema.json",
            "src/sunderkey/candidate_enrollment.py",
        ],
    },
    {
        "step_id": "implement_signature_scope_expiry_and_rollback_verification",
        "phase": 67,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_verification.py",
            "tests/agents/test_candidate_enrollment_verification_phase67.py",
        ],
    },
    {
        "step_id": "integrate_verified_enrollment_with_evidence_manifest_verification",
        "phase": 68,
        "artifacts": [
            "src/sunderkey/candidate_enrollment_evidence.py",
            "tests/agents/test_candidate_enrollment_evidence_phase68.py",
        ],
    },
    {
        "step_id": "add_adversarial_rotation_revocation_and_migration_tests",
        "phase": 69,
        "artifacts": [
            "tests/agents/test_candidate_enrollment_adversarial_phase69.py",
            "tests/agents/test_candidate_enrollment_implementation_phase69.py",
        ],
    },
)

SECURITY_PROPERTIES = (
    "offline_d008_root_authentication",
    "separated_candidate_enrollment_catalog_signer",
    "exact_candidate_owner_key_scope",
    "logical_repository_identity_and_sha256_addressing_only",
    "credential_signed_independent_control_and_assurance_review",
    "time_bounded_reviewed_renewal",
    "signed_predecessor_successor_rotation_overlap",
    "signed_catalog_revocation_distribution",
    "monotonic_version_expiry_and_last_seen_digest_rollback_protection",
    "verified_enrollment_bound_evidence_manifest_acceptance",
)

OPERATIONAL_PREREQUISITES = (
    "select_organization_issuer_audience_and_catalog_identity",
    "obtain_d008_offline_root_public_key_through_out_of_band_trust",
    "issue_root_signed_enrollment_signer_authorization",
    "issue_role_scoped_control_and_assurance_reviewer_credentials",
    "select_exact_candidate_owner_identity_and_public_key",
    "select_organization_logical_evidence_repository_identity",
    "produce_independently_reviewed_and_signed_enrollment_catalog",
    "distribute_catalog_and_revocations_through_reviewed_release_process",
    "protect_last_seen_catalog_checkpoint_against_rollback",
)

PROHIBITED_EFFECTS = (
    "does_not_generate_import_store_or_select_private_keys",
    "does_not_enroll_a_live_owner_candidate_or_repository",
    "does_not_accept_or_retrieve_live_evidence",
    "does_not_create_a_signature_credential_or_review",
    "does_not_qualify_a_candidate_or_specialist",
    "does_not_change_registry_status_or_routing_eligibility",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_runtime_or_sqlite_state",
)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})


def _report_id(report_hash: str) -> str:
    return "CEI-" + report_hash.removeprefix("sha256:")[:32].upper()


@dataclass(frozen=True)
class CandidateEnrollmentImplementationReport:
    """Qualification-neutral evidence that every approved contract step exists."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentImplementationReport:
        value = _mapping(raw, "candidate enrollment implementation report")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "decision",
            "implementation_status",
            "implemented_steps",
            "security_properties",
            "operational_prerequisites",
            "prohibited_effects",
            "live_enrollment_status",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment implementation report")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment implementation schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if not isinstance(report_id, str) or _REPORT_ID_PATTERN.fullmatch(report_id) is None:
            raise QualificationError("Candidate enrollment implementation report ID is invalid")
        if (
            not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Candidate enrollment implementation digest is invalid")
        if value.get("implementation_status") != "contract_implementation_complete":
            raise QualificationError("Candidate enrollment implementation status is invalid")
        if value.get("implemented_steps") != [dict(item) for item in IMPLEMENTED_STEPS]:
            raise QualificationError("Candidate enrollment implemented steps are invalid")
        if value.get("security_properties") != list(SECURITY_PROPERTIES):
            raise QualificationError("Candidate enrollment security properties are invalid")
        if value.get("operational_prerequisites") != list(OPERATIONAL_PREREQUISITES):
            raise QualificationError("Candidate enrollment prerequisites are invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment prohibited effects are invalid")
        if (
            value.get("live_enrollment_status") != "not_started"
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment operational boundary is invalid")
        decision = _mapping(value.get("decision"), "implementation report decision")
        _exact_fields(
            decision,
            {"decision_id", "record_id", "sha256"},
            "implementation report decision",
        )
        if (
            decision.get("decision_id") != "D009"
            or not isinstance(decision.get("record_id"), str)
            or not str(decision["record_id"]).startswith("CER-")
            or not isinstance(decision.get("sha256"), str)
            or _SHA256_PATTERN.fullmatch(str(decision["sha256"])) is None
        ):
            raise QualificationError("Candidate enrollment decision binding is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_sha256 != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError("Candidate enrollment implementation report hash is invalid")
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment implementation report is invalid")
        return value


def build_candidate_enrollment_implementation_report(
    decision: CandidateEnrollmentDecisionRecord,
) -> CandidateEnrollmentImplementationReport:
    """Record completion of the authorized contracts without live enrollment."""

    if not isinstance(decision, CandidateEnrollmentDecisionRecord):
        raise QualificationError("decision must be a CandidateEnrollmentDecisionRecord")
    decision = CandidateEnrollmentDecisionRecord.from_dict(decision.to_dict())
    document = decision.to_dict()
    if (
        document["decision_id"] != "D009"
        or document["decision_effect"] != "contract_implementation_authorized"
        or not document["recommendation_alignment"]["all_recommended_options_selected"]
    ):
        raise QualificationError("D009 does not authorize the implemented contract bundle")
    if document["authorized_next_steps"] != [
        item["step_id"] for item in IMPLEMENTED_STEPS
    ]:
        raise QualificationError("D009 implementation sequence is inconsistent")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision": {
            "decision_id": "D009",
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "implementation_status": "contract_implementation_complete",
        "implemented_steps": [dict(item) for item in IMPLEMENTED_STEPS],
        "security_properties": list(SECURITY_PROPERTIES),
        "operational_prerequisites": list(OPERATIONAL_PREREQUISITES),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "live_enrollment_status": "not_started",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    report_hash = _report_hash(body)
    return CandidateEnrollmentImplementationReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def load_candidate_enrollment_implementation_report(
    path: str | Path,
) -> CandidateEnrollmentImplementationReport:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment implementation report: {resolved}"
        ) from exc
    return CandidateEnrollmentImplementationReport.from_dict(raw)


__all__ = [
    "CandidateEnrollmentImplementationReport",
    "build_candidate_enrollment_implementation_report",
    "load_candidate_enrollment_implementation_report",
]
