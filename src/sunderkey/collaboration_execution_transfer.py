"""External execution transfer request and acknowledgement contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .collaboration_execution_channel import (
    CollaborationExecutionChannelPolicy,
    CollaborationFencedWorkerSession,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
REQUEST_DOMAIN = "sunderkey.collaboration-execution-transfer-request.v1"
ACKNOWLEDGEMENT_DOMAIN = "sunderkey.collaboration-execution-acknowledgement.v1"
REQUEST_SELECTION_DOMAIN = "sunderkey.collaboration-execution-transfer-request-selection.v1"
ACKNOWLEDGEMENT_SELECTION_DOMAIN = "sunderkey.collaboration-execution-acknowledgement-selection.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")
TRANSFER_KINDS = {"ownership_handoff", "work_cancellation"}
ACKNOWLEDGEMENT_KINDS = {
    "source_released",
    "target_accepted",
    "source_cancelled",
}
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
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is invalid") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} must be a positive integer")
    return value


def _optional_identifier(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, label)


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _content_binding(
    raw: Any,
    label: str,
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


def _assertion_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"profile_id", "assertion_id", "assertion_sha256"}, label)
    assertion_id = value.get("assertion_id")
    if not isinstance(assertion_id, str) or ASSERTION_ID_PATTERN.fullmatch(assertion_id) is None:
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    return {
        "profile_id": _identifier(value.get("profile_id"), f"{label}.profile_id"),
        "assertion_id": assertion_id,
        "assertion_sha256": _sha256(value.get("assertion_sha256"), f"{label}.assertion_sha256"),
    }


def _session_binding(raw: Any, label: str, *, optional: bool) -> dict[str, Any]:
    value = _mapping(raw, label)
    fields = {
        "session_id",
        "session_sha256",
        "worker_principal_id",
        "fence_generation",
        "credential_reference_id",
        "credential_sha256",
    }
    _exact_fields(value, fields, label)
    if optional and all(item is None for item in value.values()):
        return {field: None for field in fields}
    session_id = value.get("session_id")
    if not isinstance(session_id, str) or re.fullmatch(r"ECS-[0-9A-F]{32}", session_id) is None:
        raise CollaborationPlanError(f"{label}.session_id is invalid")
    return {
        "session_id": session_id,
        "session_sha256": _sha256(value.get("session_sha256"), f"{label}.session_sha256"),
        "worker_principal_id": _identifier(
            value.get("worker_principal_id"), f"{label}.worker_principal_id"
        ),
        "fence_generation": _positive_integer(
            value.get("fence_generation"), f"{label}.fence_generation"
        ),
        "credential_reference_id": _identifier(
            value.get("credential_reference_id"), f"{label}.credential_reference_id"
        ),
        "credential_sha256": _sha256(value.get("credential_sha256"), f"{label}.credential_sha256"),
    }


def _session_binding_from_session(
    session: CollaborationFencedWorkerSession,
) -> dict[str, Any]:
    parsed = CollaborationFencedWorkerSession.from_dict(session.to_dict())
    document = parsed.to_dict()
    return {
        "session_id": parsed.session_id,
        "session_sha256": parsed.session_sha256,
        "worker_principal_id": document["worker_principal_id"],
        "fence_generation": document["fence_generation"],
        "credential_reference_id": document["credential_reference_id"],
        "credential_sha256": document["credential_sha256"],
    }


def _empty_session_binding() -> dict[str, None]:
    return {
        "session_id": None,
        "session_sha256": None,
        "worker_principal_id": None,
        "fence_generation": None,
        "credential_reference_id": None,
        "credential_sha256": None,
    }


def _control_transition(raw: Any, transfer_kind: str) -> dict[str, str]:
    value = _mapping(raw, "execution transfer control_transition")
    _exact_fields(value, {"transition_id", "transition_sha256"}, "control_transition")
    transition_id = value.get("transition_id")
    pattern = r"OCE-[0-9A-F]{32}" if transfer_kind == "ownership_handoff" else r"WCN-[0-9A-F]{32}"
    if not isinstance(transition_id, str) or re.fullmatch(pattern, transition_id) is None:
        raise CollaborationPlanError("Execution transfer control transition is invalid")
    return {
        "transition_id": transition_id,
        "transition_sha256": _sha256(
            value.get("transition_sha256"), "control_transition.transition_sha256"
        ),
    }


@dataclass(frozen=True)
class CollaborationExecutionTransferRequest:
    """One inactive request for external release, transfer, or cancellation."""

    request_id: str
    request_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionTransferRequest:
        value = _mapping(raw, "collaboration execution transfer request")
        fields = {
            "schema_version",
            "request_id",
            "request_sha256",
            "channel_policy",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "work_item_id",
            "work_item_objective_sha256",
            "transfer_kind",
            "control_transition",
            "control_plane_requester",
            "source_session",
            "target_session",
            "required_acknowledgement_kinds",
            "requested_at",
            "acknowledgement_deadline",
            "request_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution transfer request")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution transfer request schema is invalid")
        request_id = value.get("request_id")
        request_sha256 = value.get("request_sha256")
        if not isinstance(request_id, str) or re.fullmatch(r"ETR-[0-9A-F]{32}", request_id) is None:
            raise CollaborationPlanError("Execution transfer request identity is invalid")
        _sha256(request_sha256, "request_sha256")
        channel_policy = _content_binding(
            value.get("channel_policy"),
            "channel_policy",
            "channel_policy_id",
            r"ECP-[0-9A-F]{32}",
        )
        for field in ("mission_id", "collaboration_plan_id", "work_item_id"):
            _identifier(value.get(field), field)
        for field in ("collaboration_plan_sha256", "work_item_objective_sha256"):
            _sha256(value.get(field), field)
        transfer_kind = value.get("transfer_kind")
        if transfer_kind not in TRANSFER_KINDS:
            raise CollaborationPlanError("Execution transfer kind is invalid")
        transition = _control_transition(value.get("control_transition"), transfer_kind)
        requester = _assertion_binding(
            value.get("control_plane_requester"), "control_plane_requester"
        )
        source = _session_binding(value.get("source_session"), "source_session", optional=False)
        target = _session_binding(value.get("target_session"), "target_session", optional=True)
        if transfer_kind == "ownership_handoff":
            if all(item is None for item in target.values()):
                raise CollaborationPlanError("Ownership handoff requires a target session")
            if target["fence_generation"] != source["fence_generation"] + 1:
                raise CollaborationPlanError("Target session fence generation is stale")
            if target["credential_reference_id"] == source["credential_reference_id"]:
                raise CollaborationPlanError("Target session must rotate credentials")
        elif any(item is not None for item in target.values()):
            raise CollaborationPlanError("Work cancellation cannot create a target session")
        required = value.get("required_acknowledgement_kinds")
        if (
            not isinstance(required, list)
            or tuple(required) != REQUIRED_ACKNOWLEDGEMENTS[transfer_kind]
        ):
            raise CollaborationPlanError("Required execution acknowledgements are invalid")
        requested_at = _timestamp(value.get("requested_at"), "requested_at")
        deadline = _timestamp(value.get("acknowledgement_deadline"), "acknowledgement_deadline")
        if _timestamp_value(deadline) <= _timestamp_value(requested_at):
            raise CollaborationPlanError("Execution acknowledgement deadline is invalid")
        if value.get("request_status") != "pending_external_acknowledgement":
            raise CollaborationPlanError("Execution transfer request status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution transfer request runtime effect is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"request_id", "request_sha256"}
        }
        digest = _canonical_sha256({"domain": REQUEST_DOMAIN, "request": body})
        expected_id = "ETR-" + digest.removeprefix("sha256:")[:32].upper()
        if request_sha256 != digest or request_id != expected_id:
            raise CollaborationPlanError("Execution transfer request hash is invalid")
        return cls(
            request_id,
            request_sha256,
            _canonical_json(
                {
                    **value,
                    "channel_policy": channel_policy,
                    "control_transition": transition,
                    "control_plane_requester": requester,
                    "source_session": source,
                    "target_session": target,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution transfer request is invalid")
        return value


def build_collaboration_execution_transfer_request(
    *,
    channel_policy: CollaborationExecutionChannelPolicy,
    source_session: CollaborationFencedWorkerSession,
    target_session: CollaborationFencedWorkerSession | None,
    transfer_kind: str,
    control_transition_id: str,
    control_transition_sha256: str,
    control_plane_requester: dict[str, str],
    requested_at: str,
) -> CollaborationExecutionTransferRequest:
    """Build one request whose deadline is fixed by the channel policy."""

    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    policy_document = policy.to_dict()
    source = CollaborationFencedWorkerSession.from_dict(source_session.to_dict())
    source_document = source.to_dict()
    target = (
        CollaborationFencedWorkerSession.from_dict(target_session.to_dict())
        if target_session is not None
        else None
    )
    if transfer_kind not in TRANSFER_KINDS:
        raise CollaborationPlanError("Execution transfer kind is invalid")
    requested = _timestamp(requested_at, "requested_at")
    deadline = _timestamp_value(requested) + timedelta(
        seconds=policy_document["acknowledgement_timeout_seconds"]
    )
    deadline_text = deadline.isoformat().replace("+00:00", "Z")
    if deadline > _timestamp_value(policy_document["expires_at"]):
        raise CollaborationPlanError("Execution transfer deadline exceeds the channel policy")
    body = {
        "schema_version": SCHEMA_VERSION,
        "channel_policy": {
            "channel_policy_id": policy.channel_policy_id,
            "channel_policy_sha256": policy.channel_policy_sha256,
        },
        "mission_id": policy_document["mission_id"],
        "collaboration_plan_id": policy_document["collaboration_plan_id"],
        "collaboration_plan_sha256": policy_document["collaboration_plan_sha256"],
        "work_item_id": source_document["work_item_id"],
        "work_item_objective_sha256": source_document["work_item_objective_sha256"],
        "transfer_kind": transfer_kind,
        "control_transition": {
            "transition_id": control_transition_id,
            "transition_sha256": control_transition_sha256,
        },
        "control_plane_requester": control_plane_requester,
        "source_session": _session_binding_from_session(source),
        "target_session": (
            _session_binding_from_session(target)
            if target is not None
            else _empty_session_binding()
        ),
        "required_acknowledgement_kinds": list(REQUIRED_ACKNOWLEDGEMENTS[transfer_kind]),
        "requested_at": requested,
        "acknowledgement_deadline": deadline_text,
        "request_status": "pending_external_acknowledgement",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": REQUEST_DOMAIN, "request": body})
    request = CollaborationExecutionTransferRequest.from_dict(
        {
            **body,
            "request_id": "ETR-" + digest.removeprefix("sha256:")[:32].upper(),
            "request_sha256": digest,
        }
    )
    return validate_collaboration_execution_transfer_request(
        request,
        channel_policy=policy,
        source_session=source,
        target_session=target,
    )


def collaboration_execution_transfer_request_selection_sha256(
    request: CollaborationExecutionTransferRequest,
) -> str:
    """Hash every request choice except its circular assertion binding."""

    document = CollaborationExecutionTransferRequest.from_dict(request.to_dict()).to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key not in {"request_id", "request_sha256", "control_plane_requester"}
    }
    return _canonical_sha256({"domain": REQUEST_SELECTION_DOMAIN, "request_selection": selection})


def validate_collaboration_execution_transfer_request(
    request: CollaborationExecutionTransferRequest,
    *,
    channel_policy: CollaborationExecutionChannelPolicy,
    source_session: CollaborationFencedWorkerSession,
    target_session: CollaborationFencedWorkerSession | None,
) -> CollaborationExecutionTransferRequest:
    """Validate channel, work, session, deadline, and fence bindings."""

    parsed = CollaborationExecutionTransferRequest.from_dict(request.to_dict())
    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    source = CollaborationFencedWorkerSession.from_dict(source_session.to_dict())
    target = (
        CollaborationFencedWorkerSession.from_dict(target_session.to_dict())
        if target_session is not None
        else None
    )
    document = parsed.to_dict()
    policy_document = policy.to_dict()
    source_document = source.to_dict()
    if document["channel_policy"] != {
        "channel_policy_id": policy.channel_policy_id,
        "channel_policy_sha256": policy.channel_policy_sha256,
    }:
        raise CollaborationPlanError("Execution transfer channel policy is stale")
    for field in ("mission_id", "collaboration_plan_id", "collaboration_plan_sha256"):
        if document[field] != policy_document[field] or document[field] != source_document[field]:
            raise CollaborationPlanError("Execution transfer mission binding is stale")
    for field in ("work_item_id", "work_item_objective_sha256"):
        if document[field] != source_document[field]:
            raise CollaborationPlanError("Execution transfer work-item binding is stale")
    if document["source_session"] != _session_binding_from_session(source):
        raise CollaborationPlanError("Execution transfer source session is stale")
    expected_target = (
        _session_binding_from_session(target) if target is not None else _empty_session_binding()
    )
    if document["target_session"] != expected_target:
        raise CollaborationPlanError("Execution transfer target session is stale")
    if target is not None:
        target_document = target.to_dict()
        for field in (
            "channel_policy",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "work_item_id",
            "work_item_objective_sha256",
            "ownership_chain_id",
        ):
            if target_document[field] != source_document[field]:
                raise CollaborationPlanError("Execution transfer target anchor changed")
    expected_deadline = _timestamp_value(document["requested_at"]) + timedelta(
        seconds=policy_document["acknowledgement_timeout_seconds"]
    )
    if _timestamp_value(document["acknowledgement_deadline"]) != expected_deadline:
        raise CollaborationPlanError("Execution acknowledgement deadline is stale")
    return parsed


def _revocation_proof(raw: Any, *, required: bool) -> dict[str, str | None]:
    value = _mapping(raw, "execution acknowledgement revocation_proof")
    fields = {
        "credential_reference_id",
        "credential_sha256",
        "revocation_reference_id",
        "revocation_sha256",
    }
    _exact_fields(value, fields, "execution acknowledgement revocation_proof")
    result = {
        "credential_reference_id": _optional_identifier(
            value.get("credential_reference_id"), "revocation_proof.credential_reference_id"
        ),
        "credential_sha256": _optional_sha256(
            value.get("credential_sha256"), "revocation_proof.credential_sha256"
        ),
        "revocation_reference_id": _optional_identifier(
            value.get("revocation_reference_id"), "revocation_proof.revocation_reference_id"
        ),
        "revocation_sha256": _optional_sha256(
            value.get("revocation_sha256"), "revocation_proof.revocation_sha256"
        ),
    }
    present = {key for key, item in result.items() if item is not None}
    if required and present != fields:
        raise CollaborationPlanError("Source acknowledgement requires credential revocation")
    if not required and present:
        raise CollaborationPlanError("Target acknowledgement cannot revoke its credential")
    return result


@dataclass(frozen=True)
class CollaborationExecutionAcknowledgement:
    """One explicit but unauthenticated external execution acknowledgement."""

    acknowledgement_id: str
    acknowledgement_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionAcknowledgement:
        value = _mapping(raw, "collaboration execution acknowledgement")
        fields = {
            "schema_version",
            "acknowledgement_id",
            "acknowledgement_sha256",
            "request",
            "channel_policy",
            "acknowledgement_kind",
            "session",
            "external_acknowledger",
            "revocation_proof",
            "acknowledged_at",
            "authentication_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution acknowledgement")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution acknowledgement schema is invalid")
        acknowledgement_id = value.get("acknowledgement_id")
        acknowledgement_sha256 = value.get("acknowledgement_sha256")
        if (
            not isinstance(acknowledgement_id, str)
            or re.fullmatch(r"EAK-[0-9A-F]{32}", acknowledgement_id) is None
        ):
            raise CollaborationPlanError("Execution acknowledgement identity is invalid")
        _sha256(acknowledgement_sha256, "acknowledgement_sha256")
        request = _content_binding(
            value.get("request"), "request", "request_id", r"ETR-[0-9A-F]{32}"
        )
        channel_policy = _content_binding(
            value.get("channel_policy"),
            "channel_policy",
            "channel_policy_id",
            r"ECP-[0-9A-F]{32}",
        )
        kind = value.get("acknowledgement_kind")
        if kind not in ACKNOWLEDGEMENT_KINDS:
            raise CollaborationPlanError("Execution acknowledgement kind is invalid")
        session = _session_binding(value.get("session"), "session", optional=False)
        acknowledger = _assertion_binding(
            value.get("external_acknowledger"), "external_acknowledger"
        )
        revocation = _revocation_proof(
            value.get("revocation_proof"),
            required=kind in {"source_released", "source_cancelled"},
        )
        _timestamp(value.get("acknowledged_at"), "acknowledged_at")
        if value.get("authentication_status") != "assertion_pending_verification":
            raise CollaborationPlanError("Execution acknowledgement status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution acknowledgement runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"acknowledgement_id", "acknowledgement_sha256"}
        }
        digest = _canonical_sha256({"domain": ACKNOWLEDGEMENT_DOMAIN, "acknowledgement": body})
        expected_id = "EAK-" + digest.removeprefix("sha256:")[:32].upper()
        if acknowledgement_sha256 != digest or acknowledgement_id != expected_id:
            raise CollaborationPlanError("Execution acknowledgement hash is invalid")
        return cls(
            acknowledgement_id,
            acknowledgement_sha256,
            _canonical_json(
                {
                    **value,
                    "request": request,
                    "channel_policy": channel_policy,
                    "session": session,
                    "external_acknowledger": acknowledger,
                    "revocation_proof": revocation,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution acknowledgement is invalid")
        return value


def build_collaboration_execution_acknowledgement(
    *,
    request: CollaborationExecutionTransferRequest,
    acknowledgement_kind: str,
    session: CollaborationFencedWorkerSession,
    external_acknowledger: dict[str, str],
    revocation_reference_id: str | None,
    revocation_sha256: str | None,
    acknowledged_at: str,
) -> CollaborationExecutionAcknowledgement:
    """Build one explicit external acknowledgement with no runtime effect."""

    parsed_request = CollaborationExecutionTransferRequest.from_dict(request.to_dict())
    session = CollaborationFencedWorkerSession.from_dict(session.to_dict())
    request_document = parsed_request.to_dict()
    session_binding = _session_binding_from_session(session)
    requires_revocation = acknowledgement_kind in {
        "source_released",
        "source_cancelled",
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "request": {
            "request_id": parsed_request.request_id,
            "request_sha256": parsed_request.request_sha256,
        },
        "channel_policy": request_document["channel_policy"],
        "acknowledgement_kind": acknowledgement_kind,
        "session": session_binding,
        "external_acknowledger": external_acknowledger,
        "revocation_proof": {
            "credential_reference_id": (
                session_binding["credential_reference_id"] if requires_revocation else None
            ),
            "credential_sha256": (
                session_binding["credential_sha256"] if requires_revocation else None
            ),
            "revocation_reference_id": revocation_reference_id,
            "revocation_sha256": revocation_sha256,
        },
        "acknowledged_at": acknowledged_at,
        "authentication_status": "assertion_pending_verification",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": ACKNOWLEDGEMENT_DOMAIN, "acknowledgement": body})
    acknowledgement = CollaborationExecutionAcknowledgement.from_dict(
        {
            **body,
            "acknowledgement_id": ("EAK-" + digest.removeprefix("sha256:")[:32].upper()),
            "acknowledgement_sha256": digest,
        }
    )
    return validate_collaboration_execution_acknowledgement(
        acknowledgement,
        request=parsed_request,
        session=session,
    )


def collaboration_execution_acknowledgement_selection_sha256(
    acknowledgement: CollaborationExecutionAcknowledgement,
) -> str:
    """Hash every acknowledgement choice except its circular assertion binding."""

    document = CollaborationExecutionAcknowledgement.from_dict(acknowledgement.to_dict()).to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key
        not in {
            "acknowledgement_id",
            "acknowledgement_sha256",
            "external_acknowledger",
        }
    }
    return _canonical_sha256(
        {
            "domain": ACKNOWLEDGEMENT_SELECTION_DOMAIN,
            "acknowledgement_selection": selection,
        }
    )


def validate_collaboration_execution_acknowledgement(
    acknowledgement: CollaborationExecutionAcknowledgement,
    *,
    request: CollaborationExecutionTransferRequest,
    session: CollaborationFencedWorkerSession,
) -> CollaborationExecutionAcknowledgement:
    """Validate request, session, role separation, revocation, and deadline."""

    parsed = CollaborationExecutionAcknowledgement.from_dict(acknowledgement.to_dict())
    request = CollaborationExecutionTransferRequest.from_dict(request.to_dict())
    session = CollaborationFencedWorkerSession.from_dict(session.to_dict())
    document = parsed.to_dict()
    request_document = request.to_dict()
    if document["request"] != {
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
    }:
        raise CollaborationPlanError("Execution acknowledgement request is stale")
    if document["channel_policy"] != request_document["channel_policy"]:
        raise CollaborationPlanError("Execution acknowledgement channel policy is stale")
    kind = document["acknowledgement_kind"]
    if kind not in request_document["required_acknowledgement_kinds"]:
        raise CollaborationPlanError("Execution acknowledgement is not required")
    expected_session = (
        request_document["target_session"]
        if kind == "target_accepted"
        else request_document["source_session"]
    )
    if document["session"] != expected_session:
        raise CollaborationPlanError("Execution acknowledgement session is stale")
    if document["session"] != _session_binding_from_session(session):
        raise CollaborationPlanError("Execution acknowledgement session proof is stale")
    if (
        document["external_acknowledger"]["profile_id"]
        == request_document["control_plane_requester"]["profile_id"]
    ):
        raise CollaborationPlanError(
            "External acknowledger must differ from the control-plane requester"
        )
    acknowledged_at = _timestamp_value(document["acknowledged_at"])
    if acknowledged_at < _timestamp_value(request_document["requested_at"]):
        raise CollaborationPlanError("Execution acknowledgement predates its request")
    if acknowledged_at > _timestamp_value(request_document["acknowledgement_deadline"]):
        raise CollaborationPlanError("Execution acknowledgement missed its deadline")
    if kind in {"source_released", "source_cancelled"}:
        proof = document["revocation_proof"]
        if (
            proof["credential_reference_id"]
            != request_document["source_session"]["credential_reference_id"]
            or proof["credential_sha256"] != request_document["source_session"]["credential_sha256"]
        ):
            raise CollaborationPlanError("Execution credential revocation proof is stale")
    return parsed


@dataclass(frozen=True)
class VerifiedCollaborationExecutionAcknowledgementSet:
    request_id: str
    acknowledgement_ids: tuple[str, ...]
    completed_at: str


def validate_collaboration_execution_acknowledgement_set(
    request: CollaborationExecutionTransferRequest,
    acknowledgements: list[
        tuple[
            CollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
) -> VerifiedCollaborationExecutionAcknowledgementSet:
    """Require every exact acknowledgement once before later activation."""

    request = CollaborationExecutionTransferRequest.from_dict(request.to_dict())
    if not isinstance(acknowledgements, list):
        raise CollaborationPlanError("Execution acknowledgements must be a list")
    parsed: list[CollaborationExecutionAcknowledgement] = []
    for item in acknowledgements:
        if not isinstance(item, tuple) or len(item) != 2:
            raise CollaborationPlanError("Execution acknowledgement entry is invalid")
        acknowledgement, session = item
        parsed.append(
            validate_collaboration_execution_acknowledgement(
                acknowledgement,
                request=request,
                session=session,
            )
        )
    kinds = tuple(item.to_dict()["acknowledgement_kind"] for item in parsed)
    required = tuple(request.to_dict()["required_acknowledgement_kinds"])
    if len(set(kinds)) != len(kinds) or set(kinds) != set(required):
        raise CollaborationPlanError("Execution acknowledgement set is incomplete")
    completed_at = max(item.to_dict()["acknowledged_at"] for item in parsed)
    return VerifiedCollaborationExecutionAcknowledgementSet(
        request_id=request.request_id,
        acknowledgement_ids=tuple(item.acknowledgement_id for item in parsed),
        completed_at=completed_at,
    )


def load_collaboration_execution_transfer_request(
    path: str | Path,
) -> CollaborationExecutionTransferRequest:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution transfer request: {resolved}"
        ) from exc
    return CollaborationExecutionTransferRequest.from_dict(raw)


def load_collaboration_execution_acknowledgement(
    path: str | Path,
) -> CollaborationExecutionAcknowledgement:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution acknowledgement: {resolved}"
        ) from exc
    return CollaborationExecutionAcknowledgement.from_dict(raw)


__all__ = [
    "CollaborationExecutionAcknowledgement",
    "CollaborationExecutionTransferRequest",
    "VerifiedCollaborationExecutionAcknowledgementSet",
    "build_collaboration_execution_acknowledgement",
    "build_collaboration_execution_transfer_request",
    "collaboration_execution_acknowledgement_selection_sha256",
    "collaboration_execution_transfer_request_selection_sha256",
    "load_collaboration_execution_acknowledgement",
    "load_collaboration_execution_transfer_request",
    "validate_collaboration_execution_acknowledgement",
    "validate_collaboration_execution_acknowledgement_set",
    "validate_collaboration_execution_transfer_request",
]
