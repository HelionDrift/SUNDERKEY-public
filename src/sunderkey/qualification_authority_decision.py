"""Deterministic approved decision record for D008 qualification authority."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import (
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .qualification_authority_dossier import (
    DECISION_ID,
    QualificationAuthorityDecisionDossier,
)
from .validation import loads_json_without_duplicate_keys

RECORD_SCHEMA_VERSION = 1
RECORD_DOMAIN = "sunderkey.qualification-authority-decision-record.v1"
RECORD_ID_PATTERN = re.compile(r"QDR-[0-9A-F]{32}")
DOSSIER_ID_PATTERN = re.compile(r"QAD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

APPROVED_OPTIONS = {
    "authority_model": "repository_revision_signed_manifest",
    "trust_root_ownership": "organization_owned_offline_root",
    "reviewer_credential_issuance": (
        "role_scoped_short_lived_certificates"
    ),
    "evidence_storage": "organization_content_addressed_repository",
    "decision_application": "reviewed_versioned_registry_revision",
    "emergency_suspension": "independent_control_with_signed_reason",
    "revocation_distribution": "signed_registry_revision_and_release",
}

AUTHORIZED_NEXT_STEPS = (
    "define_qualification_trust_policy_contract",
    "define_signed_evidence_manifest_contract",
    "define_reviewer_credential_and_attestation_contracts",
    "define_qualification_decision_contract",
    "define_suspension_and_revocation_contracts",
    "implement_fail_closed_signature_and_binding_validation",
    "implement_reviewed_registry_revision_application",
    "add_adversarial_expiry_suspension_and_revocation_tests",
)

PROHIBITED_EFFECTS = (
    "does_not_create_or_enroll_a_trust_root",
    "does_not_generate_or_accept_signing_keys",
    "does_not_issue_reviewer_credentials",
    "does_not_select_reviewer_identities",
    "does_not_accept_evidence_or_attestations",
    "does_not_qualify_renew_suspend_reinstate_or_revoke_a_specialist",
    "does_not_change_registry_status_or_routing_eligibility",
    "does_not_mutate_runtime_state",
    "does_not_assign_dispatch_or_execute_work",
)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _string(value: Any, expected: str, label: str) -> str:
    if value != expected:
        raise QualificationError(f"{label} must be {expected}")
    return expected


def _exact_string_list(
    value: Any,
    expected: tuple[str, ...],
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise QualificationError(f"{label} must be a list of strings")
    items = tuple(value)
    if items != expected:
        raise QualificationError(f"{label} does not match the approved contract")
    return items


@dataclass(frozen=True)
class QualificationAuthorityDecisionRecord:
    """Content-addressed record of the owner-approved D008 option bundle."""

    record_id: str
    record_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationAuthorityDecisionRecord:
        value = _mapping(raw, "qualification authority decision record")
        _exact_fields(
            value,
            {
                "schema_version",
                "record_id",
                "record_sha256",
                "decision_id",
                "decision_status",
                "decision_effect",
                "source_dossier",
                "approval_basis",
                "selected_options",
                "operational_contract",
                "authorized_next_steps",
                "prohibited_effects",
            },
            "qualification authority decision record",
        )
        if value.get("schema_version") != RECORD_SCHEMA_VERSION:
            raise QualificationError(
                "Qualification authority decision record schema version is invalid"
            )
        record_id = value.get("record_id")
        record_sha256 = value.get("record_sha256")
        if (
            not isinstance(record_id, str)
            or RECORD_ID_PATTERN.fullmatch(record_id) is None
        ):
            raise QualificationError(
                "Qualification authority decision record ID is invalid"
            )
        _sha256(record_sha256, "record_sha256")
        _string(value.get("decision_id"), DECISION_ID, "decision_id")
        _string(value.get("decision_status"), "approved", "decision_status")
        _string(
            value.get("decision_effect"),
            "contract_implementation_authorized",
            "decision_effect",
        )
        cls._validate_source_dossier(value.get("source_dossier"))
        cls._validate_approval_basis(value.get("approval_basis"))
        cls._validate_selected_options(value.get("selected_options"))
        cls._validate_operational_contract(value.get("operational_contract"))
        _exact_string_list(
            value.get("authorized_next_steps"),
            AUTHORIZED_NEXT_STEPS,
            "authorized_next_steps",
        )
        _exact_string_list(
            value.get("prohibited_effects"),
            PROHIBITED_EFFECTS,
            "prohibited_effects",
        )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"record_id", "record_sha256"}
        }
        expected_hash = _record_hash(body)
        if (
            record_sha256 != expected_hash
            or record_id != _record_id(expected_hash)
        ):
            raise QualificationError(
                "Qualification authority decision record hash is invalid"
            )
        return cls(
            record_id=record_id,
            record_sha256=record_sha256,
            document_json=_canonical_json(value),
        )

    @staticmethod
    def _validate_source_dossier(raw: Any) -> None:
        value = _mapping(raw, "source_dossier")
        _exact_fields(
            value,
            {"report_id", "sha256"},
            "source_dossier",
        )
        report_id = value.get("report_id")
        if (
            not isinstance(report_id, str)
            or DOSSIER_ID_PATTERN.fullmatch(report_id) is None
        ):
            raise QualificationError("source_dossier.report_id is invalid")
        _sha256(value.get("sha256"), "source_dossier.sha256")

    @staticmethod
    def _validate_approval_basis(raw: Any) -> None:
        value = _mapping(raw, "approval_basis")
        _exact_fields(
            value,
            {"authority_role", "approval_channel", "recording_mechanism"},
            "approval_basis",
        )
        _string(
            value.get("authority_role"),
            "repository_owner",
            "approval_basis.authority_role",
        )
        _string(
            value.get("approval_channel"),
            "explicit_owner_decision",
            "approval_basis.approval_channel",
        )
        _string(
            value.get("recording_mechanism"),
            "reviewed_versioned_registry_revision",
            "approval_basis.recording_mechanism",
        )

    @staticmethod
    def _validate_selected_options(raw: Any) -> None:
        value = _mapping(raw, "selected_options")
        _exact_fields(value, set(APPROVED_OPTIONS), "selected_options")
        for question_id, option_id in APPROVED_OPTIONS.items():
            _string(
                value.get(question_id),
                option_id,
                f"selected_options.{question_id}",
            )

    @staticmethod
    def _validate_operational_contract(raw: Any) -> None:
        value = _mapping(raw, "operational_contract")
        _exact_fields(
            value,
            {
                "authoritative_routing_source",
                "qualification_state_in_runtime_store",
                "offline_verification_required",
                "evidence_binding",
                "reviewer_roles",
                "emergency_suspension",
                "reinstatement",
                "revocation_distribution",
            },
            "operational_contract",
        )
        _string(
            value.get("authoritative_routing_source"),
            "reviewed_versioned_registry",
            "operational_contract.authoritative_routing_source",
        )
        if value.get("qualification_state_in_runtime_store") is not False:
            raise QualificationError(
                "operational_contract.qualification_state_in_runtime_store "
                "must be false"
            )
        if value.get("offline_verification_required") is not True:
            raise QualificationError(
                "operational_contract.offline_verification_required must be true"
            )
        _string(
            value.get("evidence_binding"),
            "content_addressed_signed_manifest",
            "operational_contract.evidence_binding",
        )
        _exact_string_list(
            value.get("reviewer_roles"),
            (
                "technical_evaluator",
                "independent_control",
                "independent_assurance",
            ),
            "operational_contract.reviewer_roles",
        )
        suspension = _mapping(
            value.get("emergency_suspension"),
            "operational_contract.emergency_suspension",
        )
        _exact_fields(
            suspension,
            {
                "authorized_role",
                "signed_reason_required",
                "may_grant_qualification",
                "may_reinstate",
            },
            "operational_contract.emergency_suspension",
        )
        _string(
            suspension.get("authorized_role"),
            "independent_control",
            "operational_contract.emergency_suspension.authorized_role",
        )
        if suspension.get("signed_reason_required") is not True:
            raise QualificationError(
                "Emergency suspension must require a signed reason"
            )
        if suspension.get("may_grant_qualification") is not False:
            raise QualificationError(
                "Emergency suspension authority must not grant qualification"
            )
        if suspension.get("may_reinstate") is not False:
            raise QualificationError(
                "Emergency suspension authority must not reinstate qualification"
            )
        _string(
            value.get("reinstatement"),
            "full_independent_review_required",
            "operational_contract.reinstatement",
        )
        _string(
            value.get("revocation_distribution"),
            "signed_registry_revision_and_release",
            "operational_contract.revocation_distribution",
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Qualification authority decision record is invalid"
            )
        return value


def record_qualification_authority_decision(
    dossier: QualificationAuthorityDecisionDossier,
) -> QualificationAuthorityDecisionRecord:
    """Record explicit owner approval of every recommended D008 option."""

    if not isinstance(dossier, QualificationAuthorityDecisionDossier):
        raise QualificationError(
            "dossier must be a QualificationAuthorityDecisionDossier"
        )
    dossier = QualificationAuthorityDecisionDossier.from_dict(
        dossier.to_dict()
    )
    source = dossier.to_dict()
    if source.get("decision_id") != DECISION_ID:
        raise QualificationError("Qualification authority dossier is not D008")
    if source.get("status") != "decision_required":
        raise QualificationError(
            "Qualification authority dossier is not awaiting a decision"
        )
    if source.get("decision_effect") != "none":
        raise QualificationError(
            "Qualification authority dossier already has a decision effect"
        )
    recommendation = _mapping(source.get("recommendation"), "recommendation")
    if recommendation.get("selection_state") != "not_selected":
        raise QualificationError(
            "Qualification authority dossier recommendation is already selected"
        )
    questions = source.get("decision_questions")
    if not isinstance(questions, list) or len(questions) != len(APPROVED_OPTIONS):
        raise QualificationError(
            "Qualification authority dossier decision questions are incomplete"
        )
    recommended = {}
    for index, raw_question in enumerate(questions):
        question = _mapping(raw_question, f"decision_questions[{index}]")
        question_id = question.get("question_id")
        option_id = question.get("recommended_option_id")
        if not isinstance(question_id, str) or not isinstance(option_id, str):
            raise QualificationError(
                "Qualification authority dossier recommendation is invalid"
            )
        if question_id in recommended:
            raise QualificationError(
                "Qualification authority dossier has duplicate decision questions"
            )
        recommended[question_id] = option_id
    if recommended != APPROVED_OPTIONS:
        raise QualificationError(
            "Qualification authority dossier recommendations do not match "
            "the approved D008 bundle"
        )
    body = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "decision_id": DECISION_ID,
        "decision_status": "approved",
        "decision_effect": "contract_implementation_authorized",
        "source_dossier": {
            "report_id": dossier.report_id,
            "sha256": dossier.report_sha256,
        },
        "approval_basis": {
            "authority_role": "repository_owner",
            "approval_channel": "explicit_owner_decision",
            "recording_mechanism": "reviewed_versioned_registry_revision",
        },
        "selected_options": dict(APPROVED_OPTIONS),
        "operational_contract": {
            "authoritative_routing_source": "reviewed_versioned_registry",
            "qualification_state_in_runtime_store": False,
            "offline_verification_required": True,
            "evidence_binding": "content_addressed_signed_manifest",
            "reviewer_roles": [
                "technical_evaluator",
                "independent_control",
                "independent_assurance",
            ],
            "emergency_suspension": {
                "authorized_role": "independent_control",
                "signed_reason_required": True,
                "may_grant_qualification": False,
                "may_reinstate": False,
            },
            "reinstatement": "full_independent_review_required",
            "revocation_distribution": (
                "signed_registry_revision_and_release"
            ),
        },
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
    }
    record_hash = _record_hash(body)
    return QualificationAuthorityDecisionRecord.from_dict(
        {
            **body,
            "record_id": _record_id(record_hash),
            "record_sha256": record_hash,
        }
    )


def load_qualification_authority_decision_record(
    path: str | Path,
) -> QualificationAuthorityDecisionRecord:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load qualification authority decision record: {resolved}"
        ) from exc
    return QualificationAuthorityDecisionRecord.from_dict(raw)


def _record_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": RECORD_DOMAIN,
            "record": body,
        }
    )


def _record_id(record_hash: str) -> str:
    return "QDR-" + record_hash.removeprefix("sha256:")[:32].upper()


__all__ = [
    "APPROVED_OPTIONS",
    "QualificationAuthorityDecisionRecord",
    "load_qualification_authority_decision_record",
    "record_qualification_authority_decision",
]
