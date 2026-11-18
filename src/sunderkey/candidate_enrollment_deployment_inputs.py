"""Editable deployment worksheet and qualification-neutral readiness preflight."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment_deployment import (
    EXTERNAL_INPUTS,
    PROHIBITED_CONTENT,
    CandidateEnrollmentDeploymentPreparationPacket,
)
from .errors import QualificationError
from .identity import _identifier
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_trust import _auth_value, _sha256, _timestamp_value
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
TEMPLATE_DOMAIN = "sunderkey.candidate-enrollment-deployment-worksheet-template.v1"
REPORT_DOMAIN = "sunderkey.candidate-enrollment-deployment-preflight.v1"
_TEMPLATE_ID_PATTERN = re.compile(r"CDT-[0-9A-F]{32}")
_REPORT_ID_PATTERN = re.compile(r"CDR-[0-9A-F]{32}")
_PACKET_ID_PATTERN = re.compile(r"CDP-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

PROHIBITED_EFFECTS = (
    "does_not_treat_self_reported_evidence_as_cryptographic_trust",
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


def _template_body(packet: CandidateEnrollmentDeploymentPreparationPacket) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "preparation_packet": {
            "packet_id": packet.packet_id,
            "sha256": packet.packet_sha256,
        },
        "input_layout": [
            {
                "input_id": item["input_id"],
                "accountable_roles": item["accountable_roles"],
                "completion_evidence_ids": item["completion_evidence"],
            }
            for item in EXTERNAL_INPUTS
        ],
    }


def _template_identity(
    packet: CandidateEnrollmentDeploymentPreparationPacket,
) -> tuple[str, str]:
    template_sha256 = _canonical_sha256(
        {"domain": TEMPLATE_DOMAIN, "template": _template_body(packet)}
    )
    return (
        "CDT-" + template_sha256.removeprefix("sha256:")[:32].upper(),
        template_sha256,
    )


def _nullable_identifier(value: Any, label: str) -> str | None:
    return None if value is None else _auth_value(_identifier, value, label)


def _nullable_timestamp(value: Any, label: str) -> str | None:
    return None if value is None else _timestamp_value(value, label)


def _nullable_sha256(value: Any, label: str) -> str | None:
    return None if value is None else _sha256(value, label)


@dataclass(frozen=True)
class CandidateEnrollmentDeploymentWorksheet:
    """Strict editable worksheet that contains only public completion references."""

    template_id: str
    template_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentDeploymentWorksheet:
        value = _mapping(raw, "candidate enrollment deployment worksheet")
        fields = {
            "schema_version",
            "template_id",
            "template_sha256",
            "preparation_packet",
            "deployment_id",
            "prepared_by",
            "prepared_at",
            "inputs",
            "prohibited_content",
            "worksheet_effect",
        }
        _exact_fields(value, fields, "candidate enrollment deployment worksheet")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment worksheet schema is invalid")
        template_id = value.get("template_id")
        template_sha256 = value.get("template_sha256")
        if (
            not isinstance(template_id, str)
            or _TEMPLATE_ID_PATTERN.fullmatch(template_id) is None
            or not isinstance(template_sha256, str)
            or _SHA256_PATTERN.fullmatch(template_sha256) is None
        ):
            raise QualificationError("Candidate enrollment worksheet template is invalid")
        packet = _mapping(value.get("preparation_packet"), "worksheet preparation packet")
        _exact_fields(packet, {"packet_id", "sha256"}, "worksheet preparation packet")
        if (
            not isinstance(packet.get("packet_id"), str)
            or _PACKET_ID_PATTERN.fullmatch(str(packet["packet_id"])) is None
            or not isinstance(packet.get("sha256"), str)
            or _SHA256_PATTERN.fullmatch(str(packet["sha256"])) is None
        ):
            raise QualificationError("Candidate enrollment worksheet packet is invalid")
        deployment_id = _nullable_identifier(value.get("deployment_id"), "deployment_id")
        prepared_by = _nullable_identifier(value.get("prepared_by"), "prepared_by")
        prepared_at = _nullable_timestamp(value.get("prepared_at"), "prepared_at")
        raw_inputs = value.get("inputs")
        if not isinstance(raw_inputs, list) or len(raw_inputs) != len(EXTERNAL_INPUTS):
            raise QualificationError("Candidate enrollment worksheet inputs are invalid")
        inputs: list[dict[str, Any]] = []
        for index, (raw_input, expected) in enumerate(
            zip(raw_inputs, EXTERNAL_INPUTS, strict=True)
        ):
            label = f"worksheet.inputs[{index}]"
            item = _mapping(raw_input, label)
            _exact_fields(
                item,
                {"input_id", "role_assignments", "completion_evidence", "completed_at"},
                label,
            )
            if item.get("input_id") != expected["input_id"]:
                raise QualificationError(f"{label}.input_id is invalid")
            raw_assignments = item.get("role_assignments")
            if not isinstance(raw_assignments, list) or len(raw_assignments) != len(
                expected["accountable_roles"]
            ):
                raise QualificationError(f"{label}.role_assignments are invalid")
            assignments: list[dict[str, str | None]] = []
            for assignment_index, (raw_assignment, expected_role) in enumerate(
                zip(raw_assignments, expected["accountable_roles"], strict=True)
            ):
                assignment_label = f"{label}.role_assignments[{assignment_index}]"
                assignment = _mapping(raw_assignment, assignment_label)
                _exact_fields(assignment, {"role", "principal_id"}, assignment_label)
                if assignment.get("role") != expected_role:
                    raise QualificationError(f"{assignment_label}.role is invalid")
                assignments.append(
                    {
                        "role": expected_role,
                        "principal_id": _nullable_identifier(
                            assignment.get("principal_id"),
                            f"{assignment_label}.principal_id",
                        ),
                    }
                )
            raw_evidence = item.get("completion_evidence")
            if not isinstance(raw_evidence, list) or len(raw_evidence) != len(
                expected["completion_evidence"]
            ):
                raise QualificationError(f"{label}.completion_evidence is invalid")
            evidence: list[dict[str, str | None]] = []
            for evidence_index, (raw_artifact, expected_id) in enumerate(
                zip(raw_evidence, expected["completion_evidence"], strict=True)
            ):
                evidence_label = f"{label}.completion_evidence[{evidence_index}]"
                artifact = _mapping(raw_artifact, evidence_label)
                _exact_fields(artifact, {"evidence_id", "artifact_sha256"}, evidence_label)
                if artifact.get("evidence_id") != expected_id:
                    raise QualificationError(f"{evidence_label}.evidence_id is invalid")
                evidence.append(
                    {
                        "evidence_id": expected_id,
                        "artifact_sha256": _nullable_sha256(
                            artifact.get("artifact_sha256"),
                            f"{evidence_label}.artifact_sha256",
                        ),
                    }
                )
            inputs.append(
                {
                    "input_id": expected["input_id"],
                    "role_assignments": assignments,
                    "completion_evidence": evidence,
                    "completed_at": _nullable_timestamp(
                        item.get("completed_at"),
                        f"{label}.completed_at",
                    ),
                }
            )
        if value.get("prohibited_content") != list(PROHIBITED_CONTENT):
            raise QualificationError("Candidate enrollment worksheet prohibited content is invalid")
        if value.get("worksheet_effect") != "planning_only":
            raise QualificationError("Candidate enrollment worksheet effect is invalid")
        normalized = {
            "schema_version": SCHEMA_VERSION,
            "template_id": template_id,
            "template_sha256": template_sha256,
            "preparation_packet": dict(packet),
            "deployment_id": deployment_id,
            "prepared_by": prepared_by,
            "prepared_at": prepared_at,
            "inputs": inputs,
            "prohibited_content": list(PROHIBITED_CONTENT),
            "worksheet_effect": "planning_only",
        }
        return cls(
            template_id=template_id,
            template_sha256=template_sha256,
            document_json=_canonical_json(normalized),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment worksheet is invalid")
        return value


@dataclass(frozen=True)
class CandidateEnrollmentDeploymentPreflightReport:
    """Content-addressed completeness result with no trust or enrollment effect."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentDeploymentPreflightReport:
        value = _mapping(raw, "candidate enrollment deployment preflight")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "preparation_packet",
            "worksheet",
            "input_results",
            "readiness",
            "prohibited_effects",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment deployment preflight")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment preflight schema is invalid")
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or _REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
            or _SHA256_PATTERN.fullmatch(report_sha256) is None
        ):
            raise QualificationError("Candidate enrollment preflight identity is invalid")
        packet = _mapping(value.get("preparation_packet"), "preflight preparation packet")
        _exact_fields(packet, {"packet_id", "sha256"}, "preflight preparation packet")
        worksheet = _mapping(value.get("worksheet"), "preflight worksheet")
        _exact_fields(
            worksheet,
            {"template_id", "template_sha256", "worksheet_sha256"},
            "preflight worksheet",
        )
        for digest in (
            packet.get("sha256"),
            worksheet.get("template_sha256"),
            worksheet.get("worksheet_sha256"),
        ):
            if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
                raise QualificationError("Candidate enrollment preflight binding is invalid")
        if (
            not isinstance(packet.get("packet_id"), str)
            or _PACKET_ID_PATTERN.fullmatch(str(packet["packet_id"])) is None
            or not isinstance(worksheet.get("template_id"), str)
            or _TEMPLATE_ID_PATTERN.fullmatch(str(worksheet["template_id"])) is None
        ):
            raise QualificationError("Candidate enrollment preflight binding is invalid")
        results = value.get("input_results")
        if not isinstance(results, list) or len(results) != len(EXTERNAL_INPUTS):
            raise QualificationError("Candidate enrollment preflight results are invalid")
        allowed_statuses = {"pending", "externally_documented"}
        pending_result_count = 0
        for index, (result_raw, expected) in enumerate(
            zip(results, EXTERNAL_INPUTS, strict=True)
        ):
            result = _mapping(result_raw, f"preflight.input_results[{index}]")
            _exact_fields(
                result,
                {
                    "input_id",
                    "input_status",
                    "missing_role_assignments",
                    "missing_completion_evidence",
                    "completed_at_present",
                },
                f"preflight.input_results[{index}]",
            )
            if result.get("input_id") != expected["input_id"] or result.get(
                "input_status"
            ) not in allowed_statuses:
                raise QualificationError("Candidate enrollment preflight result is invalid")
            missing_roles = result.get("missing_role_assignments")
            missing_evidence = result.get("missing_completion_evidence")
            completed_at_present = result.get("completed_at_present")
            if (
                not isinstance(missing_roles, list)
                or len(missing_roles) != len(set(missing_roles))
                or not set(missing_roles).issubset(expected["accountable_roles"])
                or not isinstance(missing_evidence, list)
                or len(missing_evidence) != len(set(missing_evidence))
                or not set(missing_evidence).issubset(expected["completion_evidence"])
                or not isinstance(completed_at_present, bool)
            ):
                raise QualificationError("Candidate enrollment preflight gaps are invalid")
            documented = not missing_roles and not missing_evidence and completed_at_present
            expected_status = "externally_documented" if documented else "pending"
            if result.get("input_status") != expected_status:
                raise QualificationError("Candidate enrollment preflight result is inconsistent")
            pending_result_count += not documented
        readiness = _mapping(value.get("readiness"), "preflight readiness")
        _exact_fields(
            readiness,
            {
                "submission_completeness_status",
                "ready_for_cryptographic_artifact_verification",
                "ready_for_live_enrollment",
                "pending_global_fields",
                "pending_input_count",
                "next_action",
                "self_reported_evidence_only",
            },
            "preflight readiness",
        )
        pending_global_fields = readiness.get("pending_global_fields")
        if (
            readiness.get("submission_completeness_status") not in {"complete", "incomplete"}
            or not isinstance(readiness.get("ready_for_cryptographic_artifact_verification"), bool)
            or readiness.get("ready_for_live_enrollment") is not False
            or not isinstance(pending_global_fields, list)
            or len(pending_global_fields) != len(set(pending_global_fields))
            or not set(pending_global_fields).issubset(
                {"deployment_id", "prepared_by", "prepared_at"}
            )
            or not isinstance(readiness.get("pending_input_count"), int)
            or readiness.get("self_reported_evidence_only") is not True
            or readiness.get("next_action")
            not in {
                "complete_missing_external_input_documentation",
                "perform_independent_cryptographic_artifact_verification",
            }
        ):
            raise QualificationError("Candidate enrollment preflight readiness is invalid")
        complete = not pending_global_fields and pending_result_count == 0
        if readiness != {
            "submission_completeness_status": "complete" if complete else "incomplete",
            "ready_for_cryptographic_artifact_verification": complete,
            "ready_for_live_enrollment": False,
            "pending_global_fields": pending_global_fields,
            "pending_input_count": pending_result_count,
            "next_action": (
                "perform_independent_cryptographic_artifact_verification"
                if complete
                else "complete_missing_external_input_documentation"
            ),
            "self_reported_evidence_only": True,
        }:
            raise QualificationError("Candidate enrollment preflight readiness is inconsistent")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment preflight effects are invalid")
        if (
            value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment preflight boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
        expected_id = "CDR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if report_sha256 != expected_hash or report_id != expected_id:
            raise QualificationError("Candidate enrollment preflight hash is invalid")
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment preflight is invalid")
        return value


def build_candidate_enrollment_deployment_worksheet(
    packet: CandidateEnrollmentDeploymentPreparationPacket,
) -> CandidateEnrollmentDeploymentWorksheet:
    """Create an all-pending worksheet with no fabricated deployment values."""

    if not isinstance(packet, CandidateEnrollmentDeploymentPreparationPacket):
        raise QualificationError(
            "packet must be a CandidateEnrollmentDeploymentPreparationPacket"
        )
    packet = CandidateEnrollmentDeploymentPreparationPacket.from_dict(packet.to_dict())
    template_id, template_sha256 = _template_identity(packet)
    return CandidateEnrollmentDeploymentWorksheet.from_dict(
        {
            "schema_version": SCHEMA_VERSION,
            "template_id": template_id,
            "template_sha256": template_sha256,
            "preparation_packet": {
                "packet_id": packet.packet_id,
                "sha256": packet.packet_sha256,
            },
            "deployment_id": None,
            "prepared_by": None,
            "prepared_at": None,
            "inputs": [
                {
                    "input_id": item["input_id"],
                    "role_assignments": [
                        {"role": role, "principal_id": None}
                        for role in item["accountable_roles"]
                    ],
                    "completion_evidence": [
                        {"evidence_id": evidence_id, "artifact_sha256": None}
                        for evidence_id in item["completion_evidence"]
                    ],
                    "completed_at": None,
                }
                for item in EXTERNAL_INPUTS
            ],
            "prohibited_content": list(PROHIBITED_CONTENT),
            "worksheet_effect": "planning_only",
        }
    )


def assess_candidate_enrollment_deployment_inputs(
    packet: CandidateEnrollmentDeploymentPreparationPacket,
    worksheet: CandidateEnrollmentDeploymentWorksheet,
) -> CandidateEnrollmentDeploymentPreflightReport:
    """Assess documentation completeness without treating it as verified trust."""

    if not isinstance(packet, CandidateEnrollmentDeploymentPreparationPacket):
        raise QualificationError(
            "packet must be a CandidateEnrollmentDeploymentPreparationPacket"
        )
    if not isinstance(worksheet, CandidateEnrollmentDeploymentWorksheet):
        raise QualificationError(
            "worksheet must be a CandidateEnrollmentDeploymentWorksheet"
        )
    packet = CandidateEnrollmentDeploymentPreparationPacket.from_dict(packet.to_dict())
    worksheet = CandidateEnrollmentDeploymentWorksheet.from_dict(worksheet.to_dict())
    document = worksheet.to_dict()
    template_id, template_sha256 = _template_identity(packet)
    if document["preparation_packet"] != {
        "packet_id": packet.packet_id,
        "sha256": packet.packet_sha256,
    } or (worksheet.template_id, worksheet.template_sha256) != (
        template_id,
        template_sha256,
    ):
        raise QualificationError("Candidate enrollment worksheet has wrong packet binding")
    pending_global_fields = [
        field
        for field in ("deployment_id", "prepared_by", "prepared_at")
        if document[field] is None
    ]
    input_results: list[dict[str, Any]] = []
    for item in document["inputs"]:
        missing_roles = [
            assignment["role"]
            for assignment in item["role_assignments"]
            if assignment["principal_id"] is None
        ]
        missing_evidence = [
            evidence["evidence_id"]
            for evidence in item["completion_evidence"]
            if evidence["artifact_sha256"] is None
        ]
        documented = not missing_roles and not missing_evidence and item["completed_at"] is not None
        input_results.append(
            {
                "input_id": item["input_id"],
                "input_status": "externally_documented" if documented else "pending",
                "missing_role_assignments": missing_roles,
                "missing_completion_evidence": missing_evidence,
                "completed_at_present": item["completed_at"] is not None,
            }
        )
    pending_input_count = sum(
        result["input_status"] == "pending" for result in input_results
    )
    complete = not pending_global_fields and pending_input_count == 0
    worksheet_sha256 = _canonical_sha256(document)
    body = {
        "schema_version": SCHEMA_VERSION,
        "preparation_packet": {
            "packet_id": packet.packet_id,
            "sha256": packet.packet_sha256,
        },
        "worksheet": {
            "template_id": worksheet.template_id,
            "template_sha256": worksheet.template_sha256,
            "worksheet_sha256": worksheet_sha256,
        },
        "input_results": input_results,
        "readiness": {
            "submission_completeness_status": "complete" if complete else "incomplete",
            "ready_for_cryptographic_artifact_verification": complete,
            "ready_for_live_enrollment": False,
            "pending_global_fields": pending_global_fields,
            "pending_input_count": pending_input_count,
            "next_action": (
                "perform_independent_cryptographic_artifact_verification"
                if complete
                else "complete_missing_external_input_documentation"
            ),
            "self_reported_evidence_only": True,
        },
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    report_sha256 = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
    return CandidateEnrollmentDeploymentPreflightReport.from_dict(
        {
            **body,
            "report_id": "CDR-" + report_sha256.removeprefix("sha256:")[:32].upper(),
            "report_sha256": report_sha256,
        }
    )


def load_candidate_enrollment_deployment_worksheet(
    path: str | Path,
) -> CandidateEnrollmentDeploymentWorksheet:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment deployment worksheet: {resolved}"
        ) from exc
    return CandidateEnrollmentDeploymentWorksheet.from_dict(raw)


def load_candidate_enrollment_deployment_preflight(
    path: str | Path,
) -> CandidateEnrollmentDeploymentPreflightReport:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load candidate enrollment deployment preflight: {resolved}"
        ) from exc
    return CandidateEnrollmentDeploymentPreflightReport.from_dict(raw)


__all__ = [
    "CandidateEnrollmentDeploymentPreflightReport",
    "CandidateEnrollmentDeploymentWorksheet",
    "assess_candidate_enrollment_deployment_inputs",
    "build_candidate_enrollment_deployment_worksheet",
    "load_candidate_enrollment_deployment_preflight",
    "load_candidate_enrollment_deployment_worksheet",
]
