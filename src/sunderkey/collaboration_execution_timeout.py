"""Fail-closed resolution contracts for incomplete execution transfers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_transfer_authentication import (
    AuthenticatedCollaborationExecutionAcknowledgement,
    AuthenticatedCollaborationExecutionTransferRequest,
    validate_authenticated_collaboration_execution_acknowledgement,
    validate_authenticated_collaboration_execution_transfer_request,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RESOLUTION_DOMAIN = "sunderkey.collaboration-execution-timeout-resolution.v1"
SELECTION_DOMAIN = "sunderkey.collaboration-execution-timeout-resolution-selection.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")
REQUEST_AUTHENTICATION_ID_PATTERN = re.compile(r"ERA-[0-9A-F]{32}")
ACKNOWLEDGEMENT_AUTHENTICATION_ID_PATTERN = re.compile(r"EAA-[0-9A-F]{32}")


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


def _content_binding(
    raw: Any,
    label: str,
    id_field: str,
    pattern: re.Pattern[str],
) -> dict[str, str]:
    value = _mapping(raw, label)
    hash_field = id_field.removesuffix("_id") + "_sha256"
    _exact_fields(value, {id_field, hash_field}, label)
    identifier = value.get(id_field)
    if not isinstance(identifier, str) or pattern.fullmatch(identifier) is None:
        raise CollaborationPlanError(f"{label}.{id_field} is invalid")
    return {
        id_field: identifier,
        hash_field: _sha256(value.get(hash_field), f"{label}.{hash_field}"),
    }


def _observed_acknowledgement(raw: Any, label: str) -> dict[str, str]:
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
    if kind not in {"source_released", "target_accepted", "source_cancelled"}:
        raise CollaborationPlanError(f"{label}.acknowledgement_kind is invalid")
    identifiers = {
        "acknowledgement_id": r"EAK-[0-9A-F]{32}",
        "authentication_id": r"EAA-[0-9A-F]{32}",
        "session_id": r"ECS-[0-9A-F]{32}",
    }
    result = {"acknowledgement_kind": kind}
    for field, pattern in identifiers.items():
        identifier = value.get(field)
        if not isinstance(identifier, str) or re.fullmatch(pattern, identifier) is None:
            raise CollaborationPlanError(f"{label}.{field} is invalid")
        result[field] = identifier
    for field in (
        "acknowledgement_sha256",
        "authentication_sha256",
        "session_sha256",
    ):
        result[field] = _sha256(value.get(field), f"{label}.{field}")
    result["acknowledged_at"] = _timestamp(value.get("acknowledged_at"), f"{label}.acknowledged_at")
    return result


@dataclass(frozen=True)
class CollaborationExecutionTimeoutResolution:
    """One inactive fail-closed decision for an incomplete transfer."""

    resolution_id: str
    resolution_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionTimeoutResolution:
        value = _mapping(raw, "collaboration execution timeout resolution")
        fields = {
            "schema_version",
            "resolution_id",
            "resolution_sha256",
            "request_authentication",
            "transfer_request",
            "channel_policy",
            "mission_id",
            "work_item_id",
            "transfer_kind",
            "required_acknowledgement_kinds",
            "observed_acknowledgements",
            "missing_acknowledgement_kinds",
            "decision_owner",
            "resolved_at",
            "resolution",
            "source_session_disposition",
            "target_session_disposition",
            "recovery_required",
            "resolution_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution timeout resolution")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution timeout resolution schema is invalid")
        resolution_id = value.get("resolution_id")
        resolution_sha256 = value.get("resolution_sha256")
        if (
            not isinstance(resolution_id, str)
            or re.fullmatch(r"ETD-[0-9A-F]{32}", resolution_id) is None
        ):
            raise CollaborationPlanError("Execution timeout resolution identity is invalid")
        _sha256(resolution_sha256, "resolution_sha256")
        request_authentication = _content_binding(
            value.get("request_authentication"),
            "request_authentication",
            "authentication_id",
            REQUEST_AUTHENTICATION_ID_PATTERN,
        )
        transfer_request = _content_binding(
            value.get("transfer_request"),
            "transfer_request",
            "request_id",
            re.compile(r"ETR-[0-9A-F]{32}"),
        )
        channel_policy = _content_binding(
            value.get("channel_policy"),
            "channel_policy",
            "channel_policy_id",
            re.compile(r"ECP-[0-9A-F]{32}"),
        )
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("work_item_id"), "work_item_id")
        transfer_kind = value.get("transfer_kind")
        required = value.get("required_acknowledgement_kinds")
        expected_required = (
            ["source_released", "target_accepted"]
            if transfer_kind == "ownership_handoff"
            else ["source_cancelled"]
            if transfer_kind == "work_cancellation"
            else None
        )
        if expected_required is None or required != expected_required:
            raise CollaborationPlanError("Execution timeout required acknowledgements are invalid")
        raw_observed = value.get("observed_acknowledgements")
        if not isinstance(raw_observed, list):
            raise CollaborationPlanError("Observed acknowledgements must be a list")
        observed = [
            _observed_acknowledgement(item, f"observed_acknowledgements[{index}]")
            for index, item in enumerate(raw_observed)
        ]
        observed_kinds = [item["acknowledgement_kind"] for item in observed]
        expected_order = [item for item in expected_required if item in observed_kinds]
        if (
            observed_kinds != expected_order
            or len(set(observed_kinds)) != len(observed_kinds)
            or set(observed_kinds) == set(expected_required)
        ):
            raise CollaborationPlanError("Observed acknowledgement set is invalid")
        missing = value.get("missing_acknowledgement_kinds")
        expected_missing = [item for item in expected_required if item not in observed_kinds]
        if missing != expected_missing:
            raise CollaborationPlanError("Missing acknowledgement set is invalid")
        decision_owner = _assertion_binding(value.get("decision_owner"), "decision_owner")
        _timestamp(value.get("resolved_at"), "resolved_at")
        if value.get("resolution") != "failed_closed_timeout":
            raise CollaborationPlanError("Execution timeout resolution is invalid")
        source_disposition = (
            "revoked_unavailable"
            if {"source_released", "source_cancelled"} & set(observed_kinds)
            else "fenced_pending_recovery"
        )
        if value.get("source_session_disposition") != source_disposition:
            raise CollaborationPlanError("Source session disposition is invalid")
        target_disposition = (
            "blocked_never_activated" if transfer_kind == "ownership_handoff" else "not_applicable"
        )
        if value.get("target_session_disposition") != target_disposition:
            raise CollaborationPlanError("Target session disposition is invalid")
        if value.get("recovery_required") is not True:
            raise CollaborationPlanError("Execution timeout must require recovery")
        if value.get("resolution_status") != "pending_control_authentication":
            raise CollaborationPlanError("Execution timeout status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution timeout runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"resolution_id", "resolution_sha256"}
        }
        digest = _canonical_sha256({"domain": RESOLUTION_DOMAIN, "resolution": body})
        expected_id = "ETD-" + digest.removeprefix("sha256:")[:32].upper()
        if resolution_sha256 != digest or resolution_id != expected_id:
            raise CollaborationPlanError("Execution timeout resolution hash is invalid")
        return cls(
            resolution_id,
            resolution_sha256,
            _canonical_json(
                {
                    **value,
                    "request_authentication": request_authentication,
                    "transfer_request": transfer_request,
                    "channel_policy": channel_policy,
                    "observed_acknowledgements": observed,
                    "decision_owner": decision_owner,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution timeout resolution is invalid")
        return value


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


def build_collaboration_execution_timeout_resolution(
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    observed_acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
    decision_owner: dict[str, str],
    resolved_at: str,
) -> CollaborationExecutionTimeoutResolution:
    """Build a no-effect resolution after an incomplete acknowledgement deadline."""

    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    request = request_authentication.request
    request_document = request.to_dict()
    resolved = _timestamp(resolved_at, "resolved_at")
    if _timestamp_value(resolved) <= _timestamp_value(request_document["acknowledgement_deadline"]):
        raise CollaborationPlanError("Execution timeout cannot resolve before its deadline")
    if not isinstance(observed_acknowledgements, list):
        raise CollaborationPlanError("Observed acknowledgements must be a list")
    observed: list[dict[str, str]] = []
    for item in observed_acknowledgements:
        if not isinstance(item, tuple) or len(item) != 2:
            raise CollaborationPlanError("Observed acknowledgement entry is invalid")
        authentication = validate_authenticated_collaboration_execution_acknowledgement(
            item[0],
            authenticated_request=request_authentication,
            session=item[1],
        )
        observed.append(_acknowledgement_binding(authentication))
    required = request_document["required_acknowledgement_kinds"]
    order = {kind: index for index, kind in enumerate(required)}
    try:
        observed.sort(key=lambda item: order[item["acknowledgement_kind"]])
    except KeyError as exc:
        raise CollaborationPlanError("Observed acknowledgement is not required") from exc
    observed_kinds = [item["acknowledgement_kind"] for item in observed]
    if len(set(observed_kinds)) != len(observed_kinds):
        raise CollaborationPlanError("Observed acknowledgement is duplicated")
    missing = [item for item in required if item not in observed_kinds]
    if not missing:
        raise CollaborationPlanError("Complete execution transfer cannot time out")
    source_disposition = (
        "revoked_unavailable"
        if {"source_released", "source_cancelled"} & set(observed_kinds)
        else "fenced_pending_recovery"
    )
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
        "required_acknowledgement_kinds": required,
        "observed_acknowledgements": observed,
        "missing_acknowledgement_kinds": missing,
        "decision_owner": decision_owner,
        "resolved_at": resolved,
        "resolution": "failed_closed_timeout",
        "source_session_disposition": source_disposition,
        "target_session_disposition": (
            "blocked_never_activated"
            if request_document["transfer_kind"] == "ownership_handoff"
            else "not_applicable"
        ),
        "recovery_required": True,
        "resolution_status": "pending_control_authentication",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": RESOLUTION_DOMAIN, "resolution": body})
    resolution = CollaborationExecutionTimeoutResolution.from_dict(
        {
            **body,
            "resolution_id": "ETD-" + digest.removeprefix("sha256:")[:32].upper(),
            "resolution_sha256": digest,
        }
    )
    return validate_collaboration_execution_timeout_resolution(
        resolution,
        authenticated_request=request_authentication,
        observed_acknowledgements=observed_acknowledgements,
    )


def validate_collaboration_execution_timeout_resolution(
    resolution: CollaborationExecutionTimeoutResolution,
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    observed_acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
) -> CollaborationExecutionTimeoutResolution:
    """Validate request authentication and every observed acknowledgement proof."""

    parsed = CollaborationExecutionTimeoutResolution.from_dict(resolution.to_dict())
    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    document = parsed.to_dict()
    request = request_authentication.request
    request_document = request.to_dict()
    if document["request_authentication"] != {
        "authentication_id": request_authentication.authentication_id,
        "authentication_sha256": request_authentication.authentication_sha256,
    }:
        raise CollaborationPlanError("Execution timeout request authentication is stale")
    if document["transfer_request"] != {
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
    }:
        raise CollaborationPlanError("Execution timeout transfer request is stale")
    for field in (
        "channel_policy",
        "mission_id",
        "work_item_id",
        "transfer_kind",
        "required_acknowledgement_kinds",
    ):
        if document[field] != request_document[field]:
            raise CollaborationPlanError("Execution timeout request binding is stale")
    expected_observed: list[dict[str, str]] = []
    for item in observed_acknowledgements:
        authentication = validate_authenticated_collaboration_execution_acknowledgement(
            item[0],
            authenticated_request=request_authentication,
            session=item[1],
        )
        expected_observed.append(_acknowledgement_binding(authentication))
    order = {kind: index for index, kind in enumerate(document["required_acknowledgement_kinds"])}
    expected_observed.sort(key=lambda item: order[item["acknowledgement_kind"]])
    if document["observed_acknowledgements"] != expected_observed:
        raise CollaborationPlanError("Execution timeout acknowledgement custody is stale")
    return parsed


def collaboration_execution_timeout_resolution_selection_sha256(
    resolution: CollaborationExecutionTimeoutResolution,
) -> str:
    """Hash every timeout choice except its circular Control assertion binding."""

    document = CollaborationExecutionTimeoutResolution.from_dict(resolution.to_dict()).to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key not in {"resolution_id", "resolution_sha256", "decision_owner"}
    }
    return _canonical_sha256({"domain": SELECTION_DOMAIN, "resolution_selection": selection})


def load_collaboration_execution_timeout_resolution(
    path: str | Path,
) -> CollaborationExecutionTimeoutResolution:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution timeout resolution: {resolved}"
        ) from exc
    return CollaborationExecutionTimeoutResolution.from_dict(raw)


__all__ = [
    "CollaborationExecutionTimeoutResolution",
    "build_collaboration_execution_timeout_resolution",
    "collaboration_execution_timeout_resolution_selection_sha256",
    "load_collaboration_execution_timeout_resolution",
    "validate_collaboration_execution_timeout_resolution",
]
