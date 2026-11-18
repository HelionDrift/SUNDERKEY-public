"""Strict owner decision records for D001 through D005 collaboration authority."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration_authority_dossier import (
    AUTHORITY_BINDING_REQUIREMENTS,
    DECISION_IDS,
    DECISION_QUESTIONS,
    FAIL_CLOSED_REQUIREMENTS,
    HISTORY_REQUIREMENTS,
    IMPLEMENTATION_SEQUENCE,
    RECOMMENDATION,
    RECOMMENDED_ALTERNATIVE_ID,
    SEPARATION_REQUIREMENTS,
    CollaborationAuthorityDecisionDossier,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RECORD_DOMAIN = "sunderkey.collaboration-authority-decision.d001-d005.v1"
RECORD_ID_PATTERN = re.compile(r"CRD-[0-9A-F]{32}")
DOSSIER_ID_PATTERN = re.compile(r"CAD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)

RECOMMENDED_OPTIONS = dict(RECOMMENDATION["recommended_option_bundle"])
AUTHORIZED_NEXT_STEPS = tuple(IMPLEMENTATION_SEQUENCE[1:])
NONNEGOTIABLE_REQUIREMENTS = {
    "authority_binding_requirements": list(AUTHORITY_BINDING_REQUIREMENTS),
    "separation_requirements": list(SEPARATION_REQUIREMENTS),
    "fail_closed_requirements": list(FAIL_CLOSED_REQUIREMENTS),
    "history_requirements": list(HISTORY_REQUIREMENTS),
    "private_key_storage_in_sunderkey": False,
    "execution_credentials_in_reconfiguration": False,
    "direct_runtime_control": False,
}
PROHIBITED_EFFECTS = (
    "does_not_reassign_transfer_cancel_or_replace_live_work",
    "does_not_change_the_current_single_handoff_same_command_boundary",
    "does_not_create_a_reconfiguration_ledger_or_owner_chain",
    "does_not_create_or_accept_external_execution_acknowledgements",
    "does_not_select_mission_owners_reviewers_workers_runtimes_or_connectors",
    "does_not_create_keys_credentials_signatures_or_attestations",
    "does_not_qualify_a_specialist_or_change_routing",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_sqlite_runtime_state",
)


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    try:
        value = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load {label}: {resolved}") from exc
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
        raise CollaborationPlanError(f"{label} must be non-empty visible ASCII text")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} must be a canonical SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    timestamp = _text(value, label, 20)
    if TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise CollaborationPlanError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is not a valid timestamp") from exc
    return timestamp


def _record_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": RECORD_DOMAIN, "record": body})


def _record_id(record_hash: str) -> str:
    return "CRD-" + record_hash.removeprefix("sha256:")[:32].upper()


def _validate_source_dossier(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "source_dossier")
    _exact_fields(value, {"report_id", "sha256"}, "source_dossier")
    report_id = value.get("report_id")
    if not isinstance(report_id, str) or DOSSIER_ID_PATTERN.fullmatch(report_id) is None:
        raise CollaborationPlanError("source_dossier.report_id is invalid")
    return {
        "report_id": report_id,
        "sha256": _sha256(value.get("sha256"), "source_dossier.sha256"),
    }


def _validate_selected_options(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "selected_options")
    _exact_fields(value, set(DECISION_IDS), "selected_options")
    allowed = {
        str(question["decision_id"]): set(question["option_ids"])
        for question in DECISION_QUESTIONS
    }
    selected: dict[str, str] = {}
    for decision_id in DECISION_IDS:
        option = value.get(decision_id)
        if not isinstance(option, str) or option not in allowed[decision_id]:
            raise CollaborationPlanError(f"selected_options.{decision_id} is invalid")
        selected[decision_id] = option
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
        raise CollaborationPlanError("approval.authority_role is invalid")
    if value.get("identity_assurance") != "operator_asserted_unsigned":
        raise CollaborationPlanError("approval.identity_assurance is invalid")
    if template:
        for field in ("decision_status", "approver_id", "approved_at", "rationale"):
            if value.get(field) is not None:
                raise CollaborationPlanError(f"approval.{field} must be completed by the owner")
        return dict(value)
    if value.get("decision_status") != "approved":
        raise CollaborationPlanError("approval.decision_status must be approved")
    return {
        "decision_status": "approved",
        "authority_role": "repository_owner",
        "approver_id": _text(value.get("approver_id"), "approval.approver_id", 128),
        "approved_at": _timestamp(value.get("approved_at"), "approval.approved_at"),
        "rationale": _text(value.get("rationale"), "approval.rationale"),
        "identity_assurance": "operator_asserted_unsigned",
    }


def build_collaboration_authority_decision_submission_template(
    dossier: CollaborationAuthorityDecisionDossier,
) -> dict[str, Any]:
    """Prepare the recommended D001 through D005 bundle for owner review."""

    dossier = CollaborationAuthorityDecisionDossier.from_dict(dossier.to_dict())
    source = dossier.to_dict()
    if source["status"] != "decision_required" or source["decision_effect"] != "none":
        raise CollaborationPlanError("Collaboration dossier is not awaiting a decision")
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_ids": list(DECISION_IDS),
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
        "selected_alternative": RECOMMENDED_ALTERNATIVE_ID,
        "selected_options": dict(RECOMMENDED_OPTIONS),
        "submission_effect": "none_until_recorded",
    }


def load_collaboration_authority_decision_submission(path: str | Path) -> dict[str, Any]:
    value = _load_json(path, "collaboration authority decision submission")
    fields = {
        "schema_version",
        "decision_ids",
        "source_dossier",
        "approval",
        "selected_alternative",
        "selected_options",
        "submission_effect",
    }
    _exact_fields(value, fields, "collaboration authority decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_ids") != list(
        DECISION_IDS
    ):
        raise CollaborationPlanError("Collaboration authority submission is invalid")
    _validate_source_dossier(value.get("source_dossier"))
    _validate_approval(value.get("approval"), template=False)
    if value.get("selected_alternative") != RECOMMENDED_ALTERNATIVE_ID:
        raise CollaborationPlanError("selected_alternative is invalid")
    _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise CollaborationPlanError("Collaboration authority submission effect is invalid")
    return value


@dataclass(frozen=True)
class CollaborationAuthorityDecisionRecord:
    """Content-addressed owner decision authorizing reconfiguration contracts."""

    record_id: str
    record_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationAuthorityDecisionRecord:
        value = _mapping(raw, "collaboration authority decision record")
        fields = {
            "schema_version",
            "record_id",
            "record_sha256",
            "decision_ids",
            "decision_status",
            "decision_effect",
            "source_dossier",
            "approval",
            "selected_alternative",
            "selected_options",
            "recommendation_alignment",
            "nonnegotiable_requirements",
            "authorized_next_steps",
            "prohibited_effects",
            "implementation_status",
            "runtime_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "collaboration authority decision record")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Collaboration decision schema is invalid")
        record_id = value.get("record_id")
        if not isinstance(record_id, str) or RECORD_ID_PATTERN.fullmatch(record_id) is None:
            raise CollaborationPlanError("Collaboration decision ID is invalid")
        record_sha256 = _sha256(value.get("record_sha256"), "record_sha256")
        if (
            value.get("decision_ids") != list(DECISION_IDS)
            or value.get("decision_status") != "approved_operator_asserted_unsigned"
            or value.get("decision_effect")
            != "collaboration_reconfiguration_contract_implementation_authorized"
        ):
            raise CollaborationPlanError("Collaboration decision state is invalid")
        _validate_source_dossier(value.get("source_dossier"))
        approval = _validate_approval(value.get("approval"), template=False)
        if value.get("selected_alternative") != RECOMMENDED_ALTERNATIVE_ID:
            raise CollaborationPlanError("Collaboration selected alternative is invalid")
        selected = _validate_selected_options(value.get("selected_options"))
        expected_alignment = {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": sum(
                selected[key] == RECOMMENDED_OPTIONS[key] for key in DECISION_IDS
            ),
            "all_recommended_options_selected": selected == RECOMMENDED_OPTIONS,
            "recommended_alternative_selected": True,
        }
        if value.get("recommendation_alignment") != expected_alignment:
            raise CollaborationPlanError("Collaboration recommendation alignment is invalid")
        if value.get("nonnegotiable_requirements") != NONNEGOTIABLE_REQUIREMENTS:
            raise CollaborationPlanError("Collaboration requirements are invalid")
        if value.get("authorized_next_steps") != list(AUTHORIZED_NEXT_STEPS):
            raise CollaborationPlanError("Collaboration authorized next steps are invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise CollaborationPlanError("Collaboration prohibited effects are invalid")
        if (
            value.get("implementation_status") != "not_started"
            or value.get("runtime_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise CollaborationPlanError("Collaboration decision boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"record_id", "record_sha256"}
        }
        digest = _record_hash(body)
        if record_sha256 != digest or record_id != _record_id(digest):
            raise CollaborationPlanError("Collaboration decision hash is invalid")
        return cls(record_id, record_sha256, _canonical_json({**value, "approval": approval}))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Collaboration decision is invalid")
        return value


def record_collaboration_authority_decision(
    dossier: CollaborationAuthorityDecisionDossier,
    submission: dict[str, Any],
) -> CollaborationAuthorityDecisionRecord:
    """Record the approved bundle without applying it to live mission state."""

    template = build_collaboration_authority_decision_submission_template(dossier)
    value = _mapping(submission, "collaboration authority decision submission")
    _exact_fields(value, set(template), "collaboration authority decision submission")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("decision_ids") != list(
        DECISION_IDS
    ):
        raise CollaborationPlanError("Collaboration authority submission is invalid")
    if value.get("source_dossier") != template["source_dossier"]:
        raise CollaborationPlanError("Collaboration dossier binding is invalid")
    approval = _validate_approval(value.get("approval"), template=False)
    if value.get("selected_alternative") != RECOMMENDED_ALTERNATIVE_ID:
        raise CollaborationPlanError("Collaboration selected alternative is invalid")
    selected = _validate_selected_options(value.get("selected_options"))
    if value.get("submission_effect") != "none_until_recorded":
        raise CollaborationPlanError("Collaboration submission effect is invalid")
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_ids": list(DECISION_IDS),
        "decision_status": "approved_operator_asserted_unsigned",
        "decision_effect": "collaboration_reconfiguration_contract_implementation_authorized",
        "source_dossier": dict(template["source_dossier"]),
        "approval": approval,
        "selected_alternative": RECOMMENDED_ALTERNATIVE_ID,
        "selected_options": selected,
        "recommendation_alignment": {
            "selected_option_count": len(selected),
            "selected_recommended_option_count": sum(
                selected[key] == RECOMMENDED_OPTIONS[key] for key in DECISION_IDS
            ),
            "all_recommended_options_selected": selected == RECOMMENDED_OPTIONS,
            "recommended_alternative_selected": True,
        },
        "nonnegotiable_requirements": NONNEGOTIABLE_REQUIREMENTS,
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "implementation_status": "not_started",
        "runtime_effect": "none",
        "registry_effect": "none",
    }
    digest = _record_hash(body)
    return CollaborationAuthorityDecisionRecord.from_dict(
        {**body, "record_id": _record_id(digest), "record_sha256": digest}
    )


def verify_collaboration_authority_decision_record(
    record: CollaborationAuthorityDecisionRecord,
    dossier: CollaborationAuthorityDecisionDossier,
) -> CollaborationAuthorityDecisionRecord:
    document = record.to_dict()
    expected = record_collaboration_authority_decision(
        dossier,
        {
            "schema_version": SCHEMA_VERSION,
            "decision_ids": list(DECISION_IDS),
            "source_dossier": document["source_dossier"],
            "approval": document["approval"],
            "selected_alternative": document["selected_alternative"],
            "selected_options": document["selected_options"],
            "submission_effect": "none_until_recorded",
        },
    )
    if record != expected:
        raise CollaborationPlanError("Collaboration decision does not match dossier")
    return record


def load_collaboration_authority_decision_record(
    path: str | Path,
) -> CollaborationAuthorityDecisionRecord:
    return CollaborationAuthorityDecisionRecord.from_dict(
        _load_json(path, "collaboration authority decision record")
    )


__all__ = [
    "CollaborationAuthorityDecisionRecord",
    "build_collaboration_authority_decision_submission_template",
    "load_collaboration_authority_decision_record",
    "load_collaboration_authority_decision_submission",
    "record_collaboration_authority_decision",
    "verify_collaboration_authority_decision_record",
]
