"""Strict human decision records for candidate enrollment decision D009."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .candidate_enrollment_dossier import (
    DECISION_ID,
    DECISION_QUESTIONS,
    IMPLEMENTATION_SEQUENCE,
    CandidateEnrollmentDecisionDossier,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RECORD_DOMAIN = "sunderkey.candidate-enrollment-decision-record.v1"
RECORD_ID_PATTERN = re.compile(r"CER-[0-9A-F]{32}")
DOSSIER_ID_PATTERN = re.compile(r"CED-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

PROHIBITED_EFFECTS = (
    "does_not_create_generate_import_or_enroll_keys",
    "does_not_enroll_a_candidate_owner_or_repository",
    "does_not_accept_a_repository_or_evidence_manifest",
    "does_not_issue_reviewer_credentials",
    "does_not_create_signatures_or_attestations",
    "does_not_qualify_a_candidate_or_specialist",
    "does_not_change_registry_status_or_routing_eligibility",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_runtime_or_sqlite_state",
)


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    try:
        value = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load {label}: {resolved}") from exc
    return dict(_mapping(value, label))


def _text(value: Any, label: str, maximum: int = 2000) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
        or len(value) > maximum
    ):
        raise QualificationError(f"{label} must be non-empty visible ASCII text")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    timestamp = _text(value, label, 20)
    if TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise QualificationError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is not a valid timestamp") from exc
    return timestamp


def _record_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": RECORD_DOMAIN, "record": body})


def _record_id(record_hash: str) -> str:
    return "CER-" + record_hash.removeprefix("sha256:")[:32].upper()


def _question_contract() -> dict[str, dict[str, Any]]:
    return {
        str(question["question_id"]): dict(question)
        for question in DECISION_QUESTIONS
    }


def _recommended_options() -> dict[str, str]:
    return {
        question_id: str(question["recommended_option_id"])
        for question_id, question in _question_contract().items()
    }


def _validate_source_dossier(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "source_dossier")
    _exact_fields(value, {"report_id", "sha256"}, "source_dossier")
    report_id = value.get("report_id")
    if not isinstance(report_id, str) or DOSSIER_ID_PATTERN.fullmatch(report_id) is None:
        raise QualificationError("source_dossier.report_id is invalid")
    return {
        "report_id": report_id,
        "sha256": _sha256(value.get("sha256"), "source_dossier.sha256"),
    }


def _validate_selected_options(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "selected_options")
    questions = _question_contract()
    _exact_fields(value, set(questions), "selected_options")
    selected: dict[str, str] = {}
    for question_id, question in questions.items():
        option = value.get(question_id)
        if not isinstance(option, str) or option not in question["option_ids"]:
            raise QualificationError(
                f"selected_options.{question_id} is not allowed by the D009 dossier"
            )
        selected[question_id] = option
    return selected


def _validate_approval(raw: Any, *, template: bool) -> dict[str, Any]:
    value = _mapping(raw, "approval")
    _exact_fields(
        value,
        {
            "decision_status",
            "authority_role",
            "approver_id",
            "approved_at",
            "rationale",
            "identity_assurance",
        },
        "approval",
    )
    if value.get("authority_role") != "repository_owner":
        raise QualificationError("approval.authority_role is invalid")
    if value.get("identity_assurance") != "operator_asserted_unsigned":
        raise QualificationError("approval.identity_assurance is invalid")
    if template:
        for field in ("decision_status", "approver_id", "approved_at", "rationale"):
            if value.get(field) is not None:
                raise QualificationError(f"approval.{field} must be completed by the owner")
        return dict(value)
    if value.get("decision_status") != "approved":
        raise QualificationError("approval.decision_status must be approved")
    return {
        "decision_status": "approved",
        "authority_role": "repository_owner",
        "approver_id": _text(value.get("approver_id"), "approval.approver_id", 128),
        "approved_at": _timestamp(value.get("approved_at"), "approval.approved_at"),
        "rationale": _text(value.get("rationale"), "approval.rationale"),
        "identity_assurance": "operator_asserted_unsigned",
    }


def build_candidate_enrollment_decision_submission_template(
    dossier: CandidateEnrollmentDecisionDossier,
) -> dict[str, Any]:
    """Prepare the recommended D009 bundle for explicit owner review."""

    if not isinstance(dossier, CandidateEnrollmentDecisionDossier):
        raise QualificationError("dossier must be a CandidateEnrollmentDecisionDossier")
    dossier = CandidateEnrollmentDecisionDossier.from_dict(dossier.to_dict())
    source = dossier.to_dict()
    if (
        source["decision_id"] != DECISION_ID
        or source["status"] != "decision_required"
        or source["decision_effect"] != "none"
    ):
        raise QualificationError("Candidate enrollment dossier is not awaiting D009")
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_id": DECISION_ID,
        "source_dossier": {
            "report_id": dossier.report_id,
            "sha256": dossier.report_sha256,
        },
        "approval": {
            "decision_status": None,
            "authority_role": "repository_owner",
            "approver_id": None,
            "approved_at": None,
            "rationale": None,
            "identity_assurance": "operator_asserted_unsigned",
        },
        "selected_options": _recommended_options(),
        "submission_effect": "none_until_recorded",
    }


def load_candidate_enrollment_decision_submission(path: str | Path) -> dict[str, Any]:
    value = _load_json(path, "candidate enrollment decision submission")
    _exact_fields(
        value,
        {
            "schema_version",
            "decision_id",
            "source_dossier",
            "approval",
            "selected_options",
            "submission_effect",
        },
        "candidate enrollment decision submission",
    )
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != DECISION_ID:
        raise QualificationError("Candidate enrollment decision submission is invalid")
    _validate_source_dossier(value.get("source_dossier"))
    _validate_approval(value.get("approval"), template=False)
    _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Candidate enrollment submission effect is invalid")
    return value


@dataclass(frozen=True)
class CandidateEnrollmentDecisionRecord:
    """Content-addressed owner decision that authorizes D009 contract work."""

    record_id: str
    record_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentDecisionRecord:
        value = _mapping(raw, "candidate enrollment decision record")
        fields = {
            "schema_version",
            "record_id",
            "record_sha256",
            "decision_id",
            "decision_status",
            "decision_effect",
            "source_dossier",
            "approval",
            "selected_options",
            "recommendation_alignment",
            "nonnegotiable_contract",
            "authorized_next_steps",
            "prohibited_effects",
            "implementation_status",
            "qualification_effect",
        }
        _exact_fields(value, fields, "candidate enrollment decision record")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment decision schema is invalid")
        record_id = value.get("record_id")
        if not isinstance(record_id, str) or RECORD_ID_PATTERN.fullmatch(record_id) is None:
            raise QualificationError("Candidate enrollment decision record ID is invalid")
        record_sha256 = _sha256(value.get("record_sha256"), "record_sha256")
        if (
            value.get("decision_id") != DECISION_ID
            or value.get("decision_status") != "approved_operator_asserted_unsigned"
            or value.get("decision_effect") != "contract_implementation_authorized"
        ):
            raise QualificationError("Candidate enrollment decision state is invalid")
        _validate_source_dossier(value.get("source_dossier"))
        approval = _validate_approval(value.get("approval"), template=False)
        selected = _validate_selected_options(value.get("selected_options"))
        recommended = _recommended_options()
        selected_recommended_count = sum(
            selected[key] == recommended[key] for key in recommended
        )
        expected_alignment = {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": selected_recommended_count,
            "all_recommended_options_selected": selected == recommended,
        }
        if value.get("recommendation_alignment") != expected_alignment:
            raise QualificationError("Candidate enrollment recommendation alignment is invalid")
        if value.get("nonnegotiable_contract") != {
            "offline_verification_required": True,
            "private_key_storage_in_sunderkey": False,
            "repository_credentials_in_enrollment": False,
            "live_evidence_acceptance_before_implementation": False,
        }:
            raise QualificationError("Candidate enrollment nonnegotiable contract is invalid")
        if value.get("authorized_next_steps") != list(IMPLEMENTATION_SEQUENCE[1:]):
            raise QualificationError("Candidate enrollment next steps are invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment prohibited effects are invalid")
        if (
            value.get("implementation_status") != "not_started"
            or value.get("qualification_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment implementation boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"record_id", "record_sha256"}
        }
        expected_hash = _record_hash(body)
        if record_sha256 != expected_hash or record_id != _record_id(expected_hash):
            raise QualificationError("Candidate enrollment decision record hash is invalid")
        return cls(
            record_id=record_id,
            record_sha256=record_sha256,
            document_json=_canonical_json({**value, "approval": approval}),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment decision record is invalid")
        return value


def record_candidate_enrollment_decision(
    dossier: CandidateEnrollmentDecisionDossier,
    submission: dict[str, Any],
) -> CandidateEnrollmentDecisionRecord:
    """Record one explicit owner-selected D009 bundle without applying it."""

    template = build_candidate_enrollment_decision_submission_template(dossier)
    value = _mapping(submission, "candidate enrollment decision submission")
    _exact_fields(value, set(template), "candidate enrollment decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != DECISION_ID:
        raise QualificationError("Candidate enrollment decision submission is invalid")
    if value.get("source_dossier") != template["source_dossier"]:
        raise QualificationError("Candidate enrollment decision dossier binding is invalid")
    approval = _validate_approval(value.get("approval"), template=False)
    selected = _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Candidate enrollment submission effect is invalid")
    recommended = _recommended_options()
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": DECISION_ID,
        "decision_status": "approved_operator_asserted_unsigned",
        "decision_effect": "contract_implementation_authorized",
        "source_dossier": dict(template["source_dossier"]),
        "approval": approval,
        "selected_options": selected,
        "recommendation_alignment": {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": sum(
                selected[key] == recommended[key] for key in recommended
            ),
            "all_recommended_options_selected": selected == recommended,
        },
        "nonnegotiable_contract": {
            "offline_verification_required": True,
            "private_key_storage_in_sunderkey": False,
            "repository_credentials_in_enrollment": False,
            "live_evidence_acceptance_before_implementation": False,
        },
        "authorized_next_steps": list(IMPLEMENTATION_SEQUENCE[1:]),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "implementation_status": "not_started",
        "qualification_effect": "none",
    }
    record_hash = _record_hash(body)
    return CandidateEnrollmentDecisionRecord.from_dict(
        {
            **body,
            "record_id": _record_id(record_hash),
            "record_sha256": record_hash,
        }
    )


def verify_candidate_enrollment_decision_record(
    record: CandidateEnrollmentDecisionRecord,
    dossier: CandidateEnrollmentDecisionDossier,
) -> CandidateEnrollmentDecisionRecord:
    document = record.to_dict()
    expected = record_candidate_enrollment_decision(
        dossier,
        {
            "schema_version": SCHEMA_VERSION,
            "decision_id": DECISION_ID,
            "source_dossier": document["source_dossier"],
            "approval": document["approval"],
            "selected_options": document["selected_options"],
            "submission_effect": "none_until_recorded",
        },
    )
    if record != expected:
        raise QualificationError("Candidate enrollment decision record does not match dossier")
    return record


def load_candidate_enrollment_decision_record(
    path: str | Path,
) -> CandidateEnrollmentDecisionRecord:
    return CandidateEnrollmentDecisionRecord.from_dict(
        _load_json(path, "candidate enrollment decision record")
    )


__all__ = [
    "CandidateEnrollmentDecisionRecord",
    "build_candidate_enrollment_decision_submission_template",
    "load_candidate_enrollment_decision_record",
    "load_candidate_enrollment_decision_submission",
    "record_candidate_enrollment_decision",
    "verify_candidate_enrollment_decision_record",
]
