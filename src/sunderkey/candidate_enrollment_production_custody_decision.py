"""Strict owner decision records for D012 production custody."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .candidate_enrollment_production_custody_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    DECISION_QUESTIONS,
    NONNEGOTIABLE_REQUIREMENTS,
    RECOMMENDED_OPTIONS,
    REQUIRED_OWNER_INPUTS,
    CandidateEnrollmentProductionCustodyDossier,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RECORD_DOMAIN = "sunderkey.candidate-enrollment-production-custody-decision.d012.v1"
RECORD_ID_PATTERN = re.compile(r"PCR-[0-9A-F]{32}")
DOSSIER_ID_PATTERN = re.compile(r"PCD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)

PROHIBITED_EFFECTS = (
    "does_not_select_an_operating_system_storage_provider_or_identity_provider",
    "does_not_create_cloud_accounts_buckets_databases_or_service_identities",
    "does_not_store_keys_credentials_endpoints_or_live_configuration",
    "does_not_persist_a_production_checkpoint_or_release_ledger_entry",
    "does_not_publish_a_catalog_activate_enrollment_or_accept_live_evidence",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
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
    return "PCR-" + record_hash.removeprefix("sha256:")[:32].upper()


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
    allowed_options = {
        str(question["question_id"]): {
            str(option["option_id"]) for option in question["options"]
        }
        for question in DECISION_QUESTIONS
    }
    selected: dict[str, str] = {}
    for question_id in RECOMMENDED_OPTIONS:
        option = value.get(question_id)
        if not isinstance(option, str) or option not in allowed_options[question_id]:
            raise QualificationError(f"selected_options.{question_id} is invalid")
        selected[question_id] = option
    return selected


def _validate_approval(raw: Any, *, template: bool) -> dict[str, Any]:
    value = _mapping(raw, "approval")
    fields = {
        "decision_status",
        "authority_role",
        "approver_id",
        "approved_at",
        "rationale",
        "identity_assurance",
    }
    _exact_fields(value, fields, "approval")
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


def build_candidate_enrollment_production_custody_decision_submission_template(
    dossier: CandidateEnrollmentProductionCustodyDossier,
) -> dict[str, Any]:
    """Prepare the recommended D012 bundle for explicit owner review."""

    dossier = CandidateEnrollmentProductionCustodyDossier.from_dict(dossier.to_dict())
    source = dossier.to_dict()
    if (
        source["decision_id"] != "D012"
        or source["status"] != "decision_required"
        or source["decision_effect"] != "none"
    ):
        raise QualificationError("Production custody dossier is not awaiting D012")
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D012",
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


def load_candidate_enrollment_production_custody_decision_submission(
    path: str | Path,
) -> dict[str, Any]:
    value = _load_json(path, "production custody decision submission")
    fields = {
        "schema_version",
        "decision_id",
        "source_dossier",
        "approval",
        "selected_options",
        "submission_effect",
    }
    _exact_fields(value, fields, "production custody decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != "D012":
        raise QualificationError("Production custody submission is invalid")
    _validate_source_dossier(value.get("source_dossier"))
    _validate_approval(value.get("approval"), template=False)
    _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Production custody submission effect is invalid")
    return value


@dataclass(frozen=True)
class CandidateEnrollmentProductionCustodyDecisionRecord:
    """Content-addressed owner decision authorizing D012 contract work."""

    record_id: str
    record_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls, raw: Any
    ) -> CandidateEnrollmentProductionCustodyDecisionRecord:
        value = _mapping(raw, "production custody decision record")
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
            "required_owner_inputs",
            "nonnegotiable_requirements",
            "authorized_next_steps",
            "prohibited_effects",
            "implementation_status",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "production custody decision record")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Production custody decision schema is invalid")
        record_id = value.get("record_id")
        if not isinstance(record_id, str) or RECORD_ID_PATTERN.fullmatch(record_id) is None:
            raise QualificationError("Production custody decision ID is invalid")
        record_sha256 = _sha256(value.get("record_sha256"), "record_sha256")
        if (
            value.get("decision_id") != "D012"
            or value.get("decision_status") != "approved_operator_asserted_unsigned"
            or value.get("decision_effect")
            != "production_custody_contract_implementation_authorized"
        ):
            raise QualificationError("Production custody decision state is invalid")
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
            raise QualificationError("Production custody alignment is invalid")
        expected_lists = {
            "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
            "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
            "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
            "prohibited_effects": list(PROHIBITED_EFFECTS),
        }
        for field, expected in expected_lists.items():
            if value.get(field) != expected:
                raise QualificationError(f"Production custody {field} is invalid")
        if (
            value.get("implementation_status") != "not_started"
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Production custody decision boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"record_id", "record_sha256"}
        }
        digest = _record_hash(body)
        if record_sha256 != digest or record_id != _record_id(digest):
            raise QualificationError("Production custody decision hash is invalid")
        return cls(record_id, record_sha256, _canonical_json({**value, "approval": approval}))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Production custody decision is invalid")
        return value


def record_candidate_enrollment_production_custody_decision(
    dossier: CandidateEnrollmentProductionCustodyDossier,
    submission: dict[str, Any],
) -> CandidateEnrollmentProductionCustodyDecisionRecord:
    """Record one explicit owner-selected D012 bundle without applying it."""

    template = build_candidate_enrollment_production_custody_decision_submission_template(
        dossier
    )
    value = _mapping(submission, "production custody decision submission")
    _exact_fields(value, set(template), "production custody decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_id") != "D012":
        raise QualificationError("Production custody submission is invalid")
    if value.get("source_dossier") != template["source_dossier"]:
        raise QualificationError("Production custody dossier binding is invalid")
    approval = _validate_approval(value.get("approval"), template=False)
    selected = _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise QualificationError("Production custody submission effect is invalid")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "D012",
        "decision_status": "approved_operator_asserted_unsigned",
        "decision_effect": "production_custody_contract_implementation_authorized",
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
        "required_owner_inputs": list(REQUIRED_OWNER_INPUTS),
        "nonnegotiable_requirements": list(NONNEGOTIABLE_REQUIREMENTS),
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "implementation_status": "not_started",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _record_hash(body)
    return CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(
        {**body, "record_id": _record_id(digest), "record_sha256": digest}
    )


def verify_candidate_enrollment_production_custody_decision_record(
    record: CandidateEnrollmentProductionCustodyDecisionRecord,
    dossier: CandidateEnrollmentProductionCustodyDossier,
) -> CandidateEnrollmentProductionCustodyDecisionRecord:
    document = record.to_dict()
    expected = record_candidate_enrollment_production_custody_decision(
        dossier,
        {
            "schema_version": SCHEMA_VERSION,
            "decision_id": "D012",
            "source_dossier": document["source_dossier"],
            "approval": document["approval"],
            "selected_options": document["selected_options"],
            "submission_effect": "none_until_recorded",
        },
    )
    if record != expected:
        raise QualificationError("Production custody decision does not match dossier")
    return record


def load_candidate_enrollment_production_custody_decision_record(
    path: str | Path,
) -> CandidateEnrollmentProductionCustodyDecisionRecord:
    return CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(
        _load_json(path, "production custody decision record")
    )


__all__ = [
    "CandidateEnrollmentProductionCustodyDecisionRecord",
    "build_candidate_enrollment_production_custody_decision_submission_template",
    "load_candidate_enrollment_production_custody_decision_record",
    "load_candidate_enrollment_production_custody_decision_submission",
    "record_candidate_enrollment_production_custody_decision",
    "verify_candidate_enrollment_production_custody_decision_record",
]
