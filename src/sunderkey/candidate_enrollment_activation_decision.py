"""Strict owner decision records for D011 checkpoint custody and activation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .candidate_enrollment_activation_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    DECISION_QUESTIONS,
    NONNEGOTIABLE_REQUIREMENTS,
    RECOMMENDED_OPTIONS,
    CandidateEnrollmentActivationDecisionDossier,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RECORD_DOMAIN = "sunderkey.candidate-enrollment-activation-decision-record.d011.v1"
RECORD_ID_PATTERN = re.compile(r"CAR-[0-9A-F]{32}")
DOSSIER_ID_PATTERN = re.compile(r"CAD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)

PROHIBITED_EFFECTS = (
    "does_not_create_a_checkpoint_store_or_release_ledger",
    "does_not_persist_or_initialize_a_checkpoint",
    "does_not_publish_or_promote_a_catalog",
    "does_not_select_live_candidate_keys_repositories_or_reviewers",
    "does_not_enroll_a_live_candidate_or_accept_live_evidence",
    "does_not_create_keys_credentials_signatures_or_attestations",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_requests_or_mutate_sqlite",
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
    return "CAR-" + record_hash.removeprefix("sha256:")[:32].upper()


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
    _exact_fields(value, set(RECOMMENDED_OPTIONS), "selected_options")
    selected: dict[str, str] = {}
    allowed_options = {
        str(question["question_id"]): {
            str(option["option_id"]) for option in question["options"]
        }
        for question in DECISION_QUESTIONS
    }
    for question_id in RECOMMENDED_OPTIONS:
        option = value.get(question_id)
        if not isinstance(option, str) or option not in allowed_options[question_id]:
            raise QualificationError(f"selected_options.{question_id} is invalid")
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


def build_candidate_enrollment_activation_decision_submission_template(
    dossier: CandidateEnrollmentActivationDecisionDossier,
) -> dict[str, Any]:
    """Prepare the recommended D011 bundle for explicit owner review."""

    if not isinstance(dossier, CandidateEnrollmentActivationDecisionDossier):
        raise QualificationError("dossier must be a D011 activation decision dossier")
    dossier = CandidateEnrollmentActivationDecisionDossier.from_dict(dossier.to_dict())
    source = dossier.to_dict()
    if (
        source["decision_id"] != "D011"
        or source["status"] != "decision_required"
        or source["decision_effect"] != "none"
    ):
        raise QualificationError("Candidate enrollment activation dossier is not awaiting D011")
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D011",
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
        "selected_options": dict(RECOMMENDED_OPTIONS),
        "submission_effect": "none_until_recorded",
    }


def load_candidate_enrollment_activation_decision_submission(
    path: str | Path,
) -> dict[str, Any]:
    value = _load_json(path, "candidate enrollment activation decision submission")
    fields = {
        "schema_version",
        "decision_id",
        "source_dossier",
        "approval",
        "selected_options",
        "submission_effect",
    }
    _exact_fields(value, fields, "candidate enrollment activation decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != "D011":
        raise QualificationError("Candidate enrollment activation submission is invalid")
    _validate_source_dossier(value.get("source_dossier"))
    _validate_approval(value.get("approval"), template=False)
    _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Candidate enrollment activation submission effect is invalid")
    return value


@dataclass(frozen=True)
class CandidateEnrollmentActivationDecisionRecord:
    """Content-addressed owner decision authorizing D011 contract work."""

    record_id: str
    record_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentActivationDecisionRecord:
        value = _mapping(raw, "candidate enrollment activation decision record")
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
            "nonnegotiable_requirements",
            "authorized_next_steps",
            "prohibited_effects",
            "implementation_status",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment activation decision record")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment activation decision schema is invalid")
        record_id = value.get("record_id")
        if not isinstance(record_id, str) or RECORD_ID_PATTERN.fullmatch(record_id) is None:
            raise QualificationError("Candidate enrollment activation decision ID is invalid")
        record_sha256 = _sha256(value.get("record_sha256"), "record_sha256")
        if (
            value.get("decision_id") != "D011"
            or value.get("decision_status") != "approved_operator_asserted_unsigned"
            or value.get("decision_effect")
            != "checkpoint_and_release_contract_implementation_authorized"
        ):
            raise QualificationError("Candidate enrollment activation decision state is invalid")
        _validate_source_dossier(value.get("source_dossier"))
        approval = _validate_approval(value.get("approval"), template=False)
        selected = _validate_selected_options(value.get("selected_options"))
        expected_alignment = {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": sum(
                selected[key] == RECOMMENDED_OPTIONS[key] for key in RECOMMENDED_OPTIONS
            ),
            "all_recommended_options_selected": selected == RECOMMENDED_OPTIONS,
        }
        if value.get("recommendation_alignment") != expected_alignment:
            raise QualificationError("Candidate enrollment activation alignment is invalid")
        if value.get("nonnegotiable_requirements") != list(NONNEGOTIABLE_REQUIREMENTS):
            raise QualificationError("Candidate enrollment activation requirements are invalid")
        if value.get("authorized_next_steps") != list(AUTHORIZED_NEXT_STEPS_IF_APPROVED):
            raise QualificationError("Candidate enrollment activation next steps are invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment activation effects are invalid")
        if (
            value.get("implementation_status") != "not_started"
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment activation boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"record_id", "record_sha256"}
        }
        expected_hash = _record_hash(body)
        if record_sha256 != expected_hash or record_id != _record_id(expected_hash):
            raise QualificationError("Candidate enrollment activation decision hash is invalid")
        return cls(
            record_id=record_id,
            record_sha256=record_sha256,
            document_json=_canonical_json({**value, "approval": approval}),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment activation decision is invalid")
        return value


def record_candidate_enrollment_activation_decision(
    dossier: CandidateEnrollmentActivationDecisionDossier,
    submission: dict[str, Any],
) -> CandidateEnrollmentActivationDecisionRecord:
    """Record one explicit owner-selected D011 bundle without applying it."""

    template = build_candidate_enrollment_activation_decision_submission_template(dossier)
    value = _mapping(submission, "candidate enrollment activation decision submission")
    _exact_fields(value, set(template), "candidate enrollment activation decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != "D011":
        raise QualificationError("Candidate enrollment activation submission is invalid")
    if value.get("source_dossier") != template["source_dossier"]:
        raise QualificationError("Candidate enrollment activation dossier binding is invalid")
    approval = _validate_approval(value.get("approval"), template=False)
    selected = _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Candidate enrollment activation submission effect is invalid")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D011",
        "decision_status": "approved_operator_asserted_unsigned",
        "decision_effect": "checkpoint_and_release_contract_implementation_authorized",
        "source_dossier": dict(template["source_dossier"]),
        "approval": approval,
        "selected_options": selected,
        "recommendation_alignment": {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": sum(
                selected[key] == RECOMMENDED_OPTIONS[key] for key in RECOMMENDED_OPTIONS
            ),
            "all_recommended_options_selected": selected == RECOMMENDED_OPTIONS,
        },
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "implementation_status": "not_started",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    record_hash = _record_hash(body)
    return CandidateEnrollmentActivationDecisionRecord.from_dict(
        {
            **body,
            "record_id": _record_id(record_hash),
            "record_sha256": record_hash,
        }
    )


def verify_candidate_enrollment_activation_decision_record(
    record: CandidateEnrollmentActivationDecisionRecord,
    dossier: CandidateEnrollmentActivationDecisionDossier,
) -> CandidateEnrollmentActivationDecisionRecord:
    document = record.to_dict()
    expected = record_candidate_enrollment_activation_decision(
        dossier,
        {
            "schema_version": SCHEMA_VERSION,
            "decision_id": "D011",
            "source_dossier": document["source_dossier"],
            "approval": document["approval"],
            "selected_options": document["selected_options"],
            "submission_effect": "none_until_recorded",
        },
    )
    if record != expected:
        raise QualificationError(
            "Candidate enrollment activation decision does not match dossier"
        )
    return record


def load_candidate_enrollment_activation_decision_record(
    path: str | Path,
) -> CandidateEnrollmentActivationDecisionRecord:
    return CandidateEnrollmentActivationDecisionRecord.from_dict(
        _load_json(path, "candidate enrollment activation decision record")
    )


__all__ = [
    "CandidateEnrollmentActivationDecisionRecord",
    "build_candidate_enrollment_activation_decision_submission_template",
    "load_candidate_enrollment_activation_decision_record",
    "load_candidate_enrollment_activation_decision_submission",
    "record_candidate_enrollment_activation_decision",
    "verify_candidate_enrollment_activation_decision_record",
]
