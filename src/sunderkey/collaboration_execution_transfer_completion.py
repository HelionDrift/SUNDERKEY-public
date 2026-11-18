"""Successful external execution transfer completion contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_transfer_authentication import (
    AuthenticatedCollaborationExecutionAcknowledgement,
    AuthenticatedCollaborationExecutionTransferRequest,
    validate_authenticated_collaboration_execution_acknowledgement_set,
    validate_authenticated_collaboration_execution_transfer_request,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
COMPLETION_DOMAIN = "sunderkey.collaboration-execution-transfer-completion.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
ACKNOWLEDGEMENT_KINDS = {"source_released", "target_accepted", "source_cancelled"}
REQUIRED_ACKNOWLEDGEMENTS = {
    "ownership_handoff": ("source_released", "target_accepted"),
    "work_cancellation": ("source_cancelled",),
}


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _content_binding(
    raw: Any,
    label: str,
    *,
    id_field: str,
    id_pattern: str,
) -> dict[str, str]:
    value = _mapping(raw, label)
    hash_field = id_field.removesuffix("_id") + "_sha256"
    _exact_fields(value, {id_field, hash_field}, label)
    identifier = value.get(id_field)
    if not isinstance(identifier, str) or re.fullmatch(id_pattern, identifier) is None:
        raise CollaborationPlanError(f"{label}.{id_field} is invalid")
    return {
        id_field: identifier,
        hash_field: _sha256(value.get(hash_field), f"{label}.{hash_field}"),
    }


def _completed_acknowledgement(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    fields = {
        "acknowledgement_kind",
        "acknowledgement_id",
        "acknowledgement_sha256",
        "authentication_id",
        "authentication_sha256",
        "session_id",
        "session_sha256",
        "acknowledged_at",
    }
    _exact_fields(value, fields, label)
    kind = value.get("acknowledgement_kind")
    if kind not in ACKNOWLEDGEMENT_KINDS:
        raise CollaborationPlanError(f"{label}.acknowledgement_kind is invalid")
    acknowledgement_id = value.get("acknowledgement_id")
    if (
        not isinstance(acknowledgement_id, str)
        or re.fullmatch(r"EAK-[0-9A-F]{32}", acknowledgement_id) is None
    ):
        raise CollaborationPlanError(f"{label}.acknowledgement_id is invalid")
    authentication_id = value.get("authentication_id")
    if (
        not isinstance(authentication_id, str)
        or re.fullmatch(r"EAA-[0-9A-F]{32}", authentication_id) is None
    ):
        raise CollaborationPlanError(f"{label}.authentication_id is invalid")
    session_id = value.get("session_id")
    if not isinstance(session_id, str) or re.fullmatch(r"ECS-[0-9A-F]{32}", session_id) is None:
        raise CollaborationPlanError(f"{label}.session_id is invalid")
    return {
        "acknowledgement_kind": kind,
        "acknowledgement_id": acknowledgement_id,
        "acknowledgement_sha256": _sha256(
            value.get("acknowledgement_sha256"), f"{label}.acknowledgement_sha256"
        ),
        "authentication_id": authentication_id,
        "authentication_sha256": _sha256(
            value.get("authentication_sha256"), f"{label}.authentication_sha256"
        ),
        "session_id": session_id,
        "session_sha256": _sha256(value.get("session_sha256"), f"{label}.session_sha256"),
        "acknowledged_at": _timestamp(value.get("acknowledged_at"), f"{label}.acknowledged_at"),
    }


def _acknowledgement_binding(
    authenticated: AuthenticatedCollaborationExecutionAcknowledgement,
) -> dict[str, str]:
    acknowledgement = authenticated.acknowledgement
    document = acknowledgement.to_dict()
    return {
        "acknowledgement_kind": document["acknowledgement_kind"],
        "acknowledgement_id": acknowledgement.acknowledgement_id,
        "acknowledgement_sha256": acknowledgement.acknowledgement_sha256,
        "authentication_id": authenticated.authentication_id,
        "authentication_sha256": authenticated.authentication_sha256,
        "session_id": document["session"]["session_id"],
        "session_sha256": document["session"]["session_sha256"],
        "acknowledged_at": document["acknowledged_at"],
    }


@dataclass(frozen=True)
class CollaborationExecutionTransferCompletion:
    """One content-addressed, no-effect successful transfer completion."""

    completion_id: str
    completion_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionTransferCompletion:
        value = _mapping(raw, "collaboration execution transfer completion")
        fields = {
            "schema_version",
            "completion_id",
            "completion_sha256",
            "request_authentication",
            "transfer_request",
            "channel_policy",
            "mission_id",
            "work_item_id",
            "transfer_kind",
            "required_acknowledgement_kinds",
            "completed_acknowledgements",
            "completed_at",
            "completion_outcome",
            "source_session_disposition",
            "target_session_disposition",
            "durable_commit_required",
            "activation_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution transfer completion")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution transfer completion schema is invalid")
        completion_id = value.get("completion_id")
        completion_sha256 = value.get("completion_sha256")
        if (
            not isinstance(completion_id, str)
            or re.fullmatch(r"ETC-[0-9A-F]{32}", completion_id) is None
        ):
            raise CollaborationPlanError("Execution transfer completion identity is invalid")
        _sha256(completion_sha256, "completion_sha256")
        request_authentication = _content_binding(
            value.get("request_authentication"),
            "request_authentication",
            id_field="authentication_id",
            id_pattern=r"ERA-[0-9A-F]{32}",
        )
        transfer_request = _content_binding(
            value.get("transfer_request"),
            "transfer_request",
            id_field="request_id",
            id_pattern=r"ETR-[0-9A-F]{32}",
        )
        channel_policy = _content_binding(
            value.get("channel_policy"),
            "channel_policy",
            id_field="channel_policy_id",
            id_pattern=r"ECP-[0-9A-F]{32}",
        )
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("work_item_id"), "work_item_id")
        transfer_kind = value.get("transfer_kind")
        if transfer_kind not in REQUIRED_ACKNOWLEDGEMENTS:
            raise CollaborationPlanError("Execution transfer completion kind is invalid")
        required = value.get("required_acknowledgement_kinds")
        expected_required = list(REQUIRED_ACKNOWLEDGEMENTS[transfer_kind])
        if required != expected_required:
            raise CollaborationPlanError("Execution transfer required acknowledgements are invalid")
        raw_completed = value.get("completed_acknowledgements")
        if not isinstance(raw_completed, list):
            raise CollaborationPlanError("Completed acknowledgements must be a list")
        completed = [
            _completed_acknowledgement(item, f"completed_acknowledgements[{index}]")
            for index, item in enumerate(raw_completed)
        ]
        if [item["acknowledgement_kind"] for item in completed] != expected_required:
            raise CollaborationPlanError("Completed acknowledgement set is invalid")
        completed_at = _timestamp(value.get("completed_at"), "completed_at")
        if completed_at != max(item["acknowledged_at"] for item in completed):
            raise CollaborationPlanError("Execution transfer completed time is invalid")
        if value.get("completion_outcome") != "acknowledged_complete":
            raise CollaborationPlanError("Execution transfer completion outcome is invalid")
        if value.get("source_session_disposition") != "revoked_unavailable":
            raise CollaborationPlanError("Source session completion disposition is invalid")
        target_disposition = (
            "eligible_after_atomic_commit"
            if transfer_kind == "ownership_handoff"
            else "not_applicable"
        )
        if value.get("target_session_disposition") != target_disposition:
            raise CollaborationPlanError("Target session completion disposition is invalid")
        if value.get("durable_commit_required") is not True:
            raise CollaborationPlanError("Execution transfer must require durable commit")
        if value.get("activation_status") != "pending_atomic_durable_commit":
            raise CollaborationPlanError("Execution transfer activation status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution transfer completion runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"completion_id", "completion_sha256"}
        }
        digest = _canonical_sha256({"domain": COMPLETION_DOMAIN, "completion": body})
        expected_id = "ETC-" + digest.removeprefix("sha256:")[:32].upper()
        if completion_sha256 != digest or completion_id != expected_id:
            raise CollaborationPlanError("Execution transfer completion hash is invalid")
        return cls(
            completion_id,
            completion_sha256,
            _canonical_json(
                {
                    **value,
                    "request_authentication": request_authentication,
                    "transfer_request": transfer_request,
                    "channel_policy": channel_policy,
                    "completed_acknowledgements": completed,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution transfer completion is invalid")
        return value


def build_collaboration_execution_transfer_completion(
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
) -> CollaborationExecutionTransferCompletion:
    """Build a successful no-effect completion from a complete authenticated set."""

    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    verified = validate_authenticated_collaboration_execution_acknowledgement_set(
        request_authentication,
        acknowledgements,
    )
    request = request_authentication.request
    request_document = request.to_dict()
    order = {
        kind: index for index, kind in enumerate(request_document["required_acknowledgement_kinds"])
    }
    completed = [_acknowledgement_binding(item[0]) for item in acknowledgements]
    completed.sort(key=lambda item: order[item["acknowledgement_kind"]])
    body = {
        "schema_version": SCHEMA_VERSION,
        "request_authentication": {
            "authentication_id": request_authentication.authentication_id,
            "authentication_sha256": request_authentication.authentication_sha256,
        },
        "transfer_request": {
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
        },
        "channel_policy": request_document["channel_policy"],
        "mission_id": request_document["mission_id"],
        "work_item_id": request_document["work_item_id"],
        "transfer_kind": request_document["transfer_kind"],
        "required_acknowledgement_kinds": request_document["required_acknowledgement_kinds"],
        "completed_acknowledgements": completed,
        "completed_at": verified.completed_at,
        "completion_outcome": "acknowledged_complete",
        "source_session_disposition": "revoked_unavailable",
        "target_session_disposition": (
            "eligible_after_atomic_commit"
            if request_document["transfer_kind"] == "ownership_handoff"
            else "not_applicable"
        ),
        "durable_commit_required": True,
        "activation_status": "pending_atomic_durable_commit",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": COMPLETION_DOMAIN, "completion": body})
    return CollaborationExecutionTransferCompletion.from_dict(
        {
            **body,
            "completion_id": "ETC-" + digest.removeprefix("sha256:")[:32].upper(),
            "completion_sha256": digest,
        }
    )


def validate_collaboration_execution_transfer_completion(
    completion: CollaborationExecutionTransferCompletion,
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
) -> CollaborationExecutionTransferCompletion:
    """Validate complete acknowledgement custody against one completion."""

    parsed = CollaborationExecutionTransferCompletion.from_dict(completion.to_dict())
    expected = build_collaboration_execution_transfer_completion(
        authenticated_request=authenticated_request,
        acknowledgements=acknowledgements,
    )
    if parsed.to_dict() != expected.to_dict():
        raise CollaborationPlanError("Execution transfer completion custody is stale")
    return parsed


def load_collaboration_execution_transfer_completion(
    path: str | Path,
) -> CollaborationExecutionTransferCompletion:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution transfer completion: {resolved}"
        ) from exc
    return CollaborationExecutionTransferCompletion.from_dict(raw)


__all__ = [
    "CollaborationExecutionTransferCompletion",
    "build_collaboration_execution_transfer_completion",
    "load_collaboration_execution_transfer_completion",
    "validate_collaboration_execution_transfer_completion",
]
