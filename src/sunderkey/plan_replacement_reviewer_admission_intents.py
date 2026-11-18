"""Unsigned approval inputs for externally signed reviewer admission assertions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import PrincipalAuthenticationError
from .identity import (
    _MAX_CREDENTIAL_BYTES,
    PrincipalOperation,
    _load_json_file,
    compute_operation_intent_hash,
)
from .plan_replacement_reviewer_admission import (
    PlanReplacementReviewerAdmissionRequest,
    _native_json,
    _object,
    reviewer_admission_operation_intent,
)
from .store import canonical_json, sha256_text

APPROVAL_INTENTS_DOMAIN = (
    "sunderkey.collaboration.plan-replacement.reviewer-admission-approval-intents.v1"
)
APPROVAL_INTENTS_PACKET_ID_PATTERN = re.compile(r"RAI-[0-9A-F]{32}\Z")
MAX_APPROVAL_INTENTS_BYTES = _MAX_CREDENTIAL_BYTES
_FIELDS = {
    "schema_version",
    "packet_id",
    "packet_sha256",
    "admission",
    "approval_intents",
    "approval_status",
    "approver_assignment",
    "authority_effect",
    "runtime_effect",
    "target_authority",
    "qualification_effect",
}
_APPROVAL_OPERATIONS = MappingProxyType(
    {
        "mission_owner": PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE,
        "independent_control": (
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE
        ),
    }
)
_INTENT_FIELDS = {
    "operation",
    "principal_profile_id",
    "operation_intent",
    "operation_intent_sha256",
}


def _packet_body(
    request: PlanReplacementReviewerAdmissionRequest,
    mission_owner_profile_id: str,
    independent_control_profile_id: str,
) -> dict[str, Any]:
    if type(request) is not PlanReplacementReviewerAdmissionRequest:
        raise PrincipalAuthenticationError("Approval intents require an exact admission request")
    request = PlanReplacementReviewerAdmissionRequest.from_dict(request.to_dict())
    profiles = {
        "mission_owner": mission_owner_profile_id,
        "independent_control": independent_control_profile_id,
    }
    if any(type(profile_id) is not str for profile_id in profiles.values()):
        raise PrincipalAuthenticationError("Approval intent profile IDs must be native text")
    if len({*profiles.values(), request.to_dict()["reviewer"]["profile_id"]}) != 3:
        raise PrincipalAuthenticationError("Approvers and prospective reviewer must be distinct")
    approvals = {}
    for role, operation in _APPROVAL_OPERATIONS.items():
        intent = reviewer_admission_operation_intent(
            request,
            principal_profile_id=profiles[role],
            role=role,
        )
        approvals[role] = {
            "operation": operation.value,
            "principal_profile_id": profiles[role],
            "operation_intent": intent,
            "operation_intent_sha256": compute_operation_intent_hash(operation, intent),
        }
    return {
        "schema_version": 1,
        "admission": request.to_dict(),
        "approval_intents": approvals,
        "approval_status": "unsigned",
        "approver_assignment": "not_verified",
        "authority_effect": "none",
        "runtime_effect": "none",
        "target_authority": "none",
        "qualification_effect": "none",
    }


def _packet_document(body: dict[str, Any]) -> dict[str, Any]:
    digest = sha256_text(canonical_json({"domain": APPROVAL_INTENTS_DOMAIN, "packet": body}))
    return {
        **body,
        "packet_id": "RAI-" + digest[7:39].upper(),
        "packet_sha256": digest,
    }


def _parse_packet(raw: Any) -> dict[str, Any]:
    value = _object(raw, _FIELDS, "Reviewer admission approval intents")
    _native_json(value)
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is int and not -(2**63) <= item <= 2**63 - 1:
            raise PrincipalAuthenticationError(
                "Approval intents integer exceeds signed 64-bit range"
            )
        if type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise PrincipalAuthenticationError("Approval intents schema_version must be integer 1")
    request = PlanReplacementReviewerAdmissionRequest.from_dict(value["admission"])
    approvals = _object(
        value["approval_intents"],
        set(_APPROVAL_OPERATIONS),
        "Approval intents",
    )
    for role in _APPROVAL_OPERATIONS:
        _object(approvals[role], _INTENT_FIELDS, f"Approval intents {role}")
    expected = _packet_document(
        _packet_body(
            request,
            approvals["mission_owner"]["principal_profile_id"],
            approvals["independent_control"]["principal_profile_id"],
        )
    )
    if value != expected:
        raise PrincipalAuthenticationError(
            "Approval intents do not match their exact unsigned inputs"
        )
    if len(canonical_json(expected).encode("utf-8")) > MAX_APPROVAL_INTENTS_BYTES:
        raise PrincipalAuthenticationError("Approval intents exceed the bounded credential size")
    return expected


@dataclass(frozen=True)
class PlanReplacementReviewerAdmissionApprovalIntentPacket:
    """Content-addressed signing inputs, never verified assignment or authority."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, raw: Any) -> PlanReplacementReviewerAdmissionApprovalIntentPacket:
        try:
            return cls(canonical_json(_parse_packet(raw)))
        except RecursionError as exc:
            raise PrincipalAuthenticationError("Approval intents nesting is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        if type(self.document_json) is not str:
            raise PrincipalAuthenticationError("Approval intents must be canonical JSON text")
        try:
            document_size = len(self.document_json.encode("utf-8"))
        except UnicodeError as exc:
            raise PrincipalAuthenticationError(
                "Approval intents contain invalid UTF-8 text"
            ) from exc
        if document_size > MAX_APPROVAL_INTENTS_BYTES:
            raise PrincipalAuthenticationError(
                "Approval intents exceed the bounded credential size"
            )
        try:
            # Reconstruction also rejects duplicate-key text as noncanonical.
            value = _parse_packet(json.loads(self.document_json))
        except (ValueError, RecursionError) as exc:
            raise PrincipalAuthenticationError("Approval intents contain invalid JSON") from exc
        if canonical_json(value) != self.document_json:
            raise PrincipalAuthenticationError("Approval intents JSON is not canonical")
        return value

    @property
    def packet_id(self) -> str:
        return self.to_dict()["packet_id"]

    @property
    def packet_sha256(self) -> str:
        return self.to_dict()["packet_sha256"]

    @property
    def content_sha256(self) -> str:
        return self.packet_sha256


def build_plan_replacement_reviewer_admission_approval_intents(
    request: PlanReplacementReviewerAdmissionRequest,
    *,
    mission_owner_profile_id: str,
    independent_control_profile_id: str,
) -> PlanReplacementReviewerAdmissionApprovalIntentPacket:
    """Export exact unsigned intents without checking assignment or signing them."""

    return PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
        _packet_document(
            _packet_body(request, mission_owner_profile_id, independent_control_profile_id)
        )
    )


def load_plan_replacement_reviewer_admission_approval_intents(
    path: str | Path,
) -> PlanReplacementReviewerAdmissionApprovalIntentPacket:
    """Read one bounded strict packet file; its signature and authority remain absent."""

    return PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
        _load_json_file(path, "plan replacement reviewer admission approval intents")
    )


__all__ = [
    "APPROVAL_INTENTS_DOMAIN",
    "MAX_APPROVAL_INTENTS_BYTES",
    "PlanReplacementReviewerAdmissionApprovalIntentPacket",
    "build_plan_replacement_reviewer_admission_approval_intents",
    "load_plan_replacement_reviewer_admission_approval_intents",
]
