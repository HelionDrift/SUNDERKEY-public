"""Provider-neutral execution-channel policy and fenced session contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration_mission_policy import CollaborationMissionReconfigurationPolicy
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
CHANNEL_POLICY_DOMAIN = "sunderkey.collaboration-execution-channel-policy.v1"
SESSION_DOMAIN = "sunderkey.collaboration-fenced-worker-session.v1"
CHANNEL_POLICY_SELECTION_DOMAIN = (
    "sunderkey.collaboration-execution-channel-policy-selection.v1"
)
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")

PROTOCOL_CONTROLS = {
    "credential_revocation_before_successor_activation": True,
    "external_acknowledger_distinct_from_control_plane_requester": True,
    "explicit_release_acknowledgement_required": True,
    "fail_closed_on_timeout": True,
    "session_fence_required": True,
    "transfer_not_inferred_from_control_plane_state": True,
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


def _binding(raw: Any, label: str, id_field: str, id_pattern: str) -> dict[str, str]:
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


def _approval_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"profile_id", "assertion_id", "assertion_sha256"}, label)
    assertion_id = value.get("assertion_id")
    if not isinstance(assertion_id, str) or ASSERTION_ID_PATTERN.fullmatch(assertion_id) is None:
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    return {
        "profile_id": _identifier(value.get("profile_id"), f"{label}.profile_id"),
        "assertion_id": assertion_id,
        "assertion_sha256": _sha256(
            value.get("assertion_sha256"), f"{label}.assertion_sha256"
        ),
    }


def _approval_bindings(raw: Any) -> dict[str, dict[str, str]]:
    value = _mapping(raw, "execution channel approval_bindings")
    _exact_fields(
        value,
        {"mission_owner", "independent_control"},
        "execution channel approval_bindings",
    )
    owner = _approval_binding(value.get("mission_owner"), "mission_owner")
    control = _approval_binding(value.get("independent_control"), "independent_control")
    if owner["profile_id"] == control["profile_id"]:
        raise CollaborationPlanError("Execution channel approvers must be distinct")
    if owner["assertion_id"] == control["assertion_id"]:
        raise CollaborationPlanError("Execution channel approvals must use distinct assertions")
    return {"mission_owner": owner, "independent_control": control}


def _protocol_controls(raw: Any) -> dict[str, bool]:
    value = _mapping(raw, "execution channel protocol_controls")
    _exact_fields(value, set(PROTOCOL_CONTROLS), "execution channel protocol_controls")
    if value != PROTOCOL_CONTROLS:
        raise CollaborationPlanError("Execution channel protocol controls are invalid")
    return dict(PROTOCOL_CONTROLS)


@dataclass(frozen=True)
class CollaborationExecutionChannelPolicy:
    """One signed-selection candidate for the D005 execution channel."""

    channel_policy_id: str
    channel_policy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionChannelPolicy:
        value = _mapping(raw, "collaboration execution channel policy")
        fields = {
            "schema_version",
            "channel_policy_id",
            "channel_policy_sha256",
            "authority_policy",
            "mission_policy",
            "policy_version",
            "previous_channel_policy_sha256",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "acknowledgement_timeout_seconds",
            "protocol_controls",
            "approval_bindings",
            "effective_at",
            "expires_at",
            "authentication_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution channel policy")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution channel policy schema is invalid")
        channel_policy_id = value.get("channel_policy_id")
        channel_policy_sha256 = value.get("channel_policy_sha256")
        if (
            not isinstance(channel_policy_id, str)
            or re.fullmatch(r"ECP-[0-9A-F]{32}", channel_policy_id) is None
        ):
            raise CollaborationPlanError("Execution channel policy identity is invalid")
        _sha256(channel_policy_sha256, "channel_policy_sha256")
        authority_policy = _binding(
            value.get("authority_policy"),
            "authority_policy",
            "policy_id",
            r"RAP-[0-9A-F]{32}",
        )
        mission_policy = _binding(
            value.get("mission_policy"),
            "mission_policy",
            "policy_id",
            r"MRP-[0-9A-F]{32}",
        )
        policy_version = _positive_integer(value.get("policy_version"), "policy_version")
        previous = value.get("previous_channel_policy_sha256")
        if policy_version == 1:
            if previous is not None:
                raise CollaborationPlanError("Initial execution channel policy has no predecessor")
        else:
            _sha256(previous, "previous_channel_policy_sha256")
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("collaboration_plan_id"), "collaboration_plan_id")
        _sha256(value.get("collaboration_plan_sha256"), "collaboration_plan_sha256")
        timeout = _positive_integer(
            value.get("acknowledgement_timeout_seconds"),
            "acknowledgement_timeout_seconds",
        )
        if timeout > 3600:
            raise CollaborationPlanError("Execution acknowledgement timeout exceeds policy bounds")
        controls = _protocol_controls(value.get("protocol_controls"))
        approvals = _approval_bindings(value.get("approval_bindings"))
        effective_at = _timestamp(value.get("effective_at"), "effective_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(effective_at):
            raise CollaborationPlanError("Execution channel policy window is invalid")
        if value.get("authentication_status") != "assertions_pending_verification":
            raise CollaborationPlanError("Execution channel authentication status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution channel runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"channel_policy_id", "channel_policy_sha256"}
        }
        digest = _canonical_sha256({"domain": CHANNEL_POLICY_DOMAIN, "policy": body})
        expected_id = "ECP-" + digest.removeprefix("sha256:")[:32].upper()
        if channel_policy_sha256 != digest or channel_policy_id != expected_id:
            raise CollaborationPlanError("Execution channel policy hash is invalid")
        return cls(
            channel_policy_id,
            channel_policy_sha256,
            _canonical_json(
                {
                    **value,
                    "authority_policy": authority_policy,
                    "mission_policy": mission_policy,
                    "protocol_controls": controls,
                    "approval_bindings": approvals,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution channel policy is invalid")
        return value


def build_collaboration_execution_channel_policy(
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    policy_version: int,
    previous_channel_policy_sha256: str | None,
    mission_owner_approval: dict[str, str],
    independent_control_approval: dict[str, str],
    effective_at: str,
    expires_at: str,
) -> CollaborationExecutionChannelPolicy:
    """Build one inactive execution-channel policy selection."""

    authority = CollaborationReconfigurationAuthorityPolicy.from_dict(
        authority_policy.to_dict()
    )
    mission = CollaborationMissionReconfigurationPolicy.from_dict(mission_policy.to_dict())
    authority_document = authority.to_dict()
    mission_document = mission.to_dict()
    if mission_document["authority_policy"] != {
        "policy_id": authority.policy_id,
        "policy_sha256": authority.policy_sha256,
    }:
        raise CollaborationPlanError("Execution channel authority binding is stale")
    transition = "distributed_execution_transfer_or_cancellation"
    if not mission_document["transition_activation"][transition]:
        raise CollaborationPlanError("Mission policy has not activated distributed execution")
    timeout = mission_document["selected_parameters"]["execution_ack_timeout_seconds"]
    contracts = {
        item["parameter_id"]: item for item in authority_document["parameter_contracts"]
    }
    contract = contracts.get("execution_ack_timeout_seconds")
    if contract is None or timeout < contract["minimum"] or timeout > contract["maximum"]:
        raise CollaborationPlanError("Execution acknowledgement timeout is outside policy bounds")
    selected_effective_at = _timestamp(effective_at, "effective_at")
    selected_expires_at = _timestamp(expires_at, "expires_at")
    if (
        _timestamp_value(selected_effective_at)
        < _timestamp_value(mission_document["effective_at"])
        or _timestamp_value(selected_expires_at)
        > _timestamp_value(mission_document["expires_at"])
    ):
        raise CollaborationPlanError("Execution channel exceeds the mission policy window")
    body = {
        "schema_version": SCHEMA_VERSION,
        "authority_policy": {
            "policy_id": authority.policy_id,
            "policy_sha256": authority.policy_sha256,
        },
        "mission_policy": {
            "policy_id": mission.policy_id,
            "policy_sha256": mission.policy_sha256,
        },
        "policy_version": policy_version,
        "previous_channel_policy_sha256": previous_channel_policy_sha256,
        "mission_id": mission_document["mission_id"],
        "collaboration_plan_id": mission_document["collaboration_plan_id"],
        "collaboration_plan_sha256": mission_document["collaboration_plan_sha256"],
        "acknowledgement_timeout_seconds": timeout,
        "protocol_controls": dict(PROTOCOL_CONTROLS),
        "approval_bindings": {
            "mission_owner": mission_owner_approval,
            "independent_control": independent_control_approval,
        },
        "effective_at": selected_effective_at,
        "expires_at": selected_expires_at,
        "authentication_status": "assertions_pending_verification",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": CHANNEL_POLICY_DOMAIN, "policy": body})
    return CollaborationExecutionChannelPolicy.from_dict(
        {
            **body,
            "channel_policy_id": "ECP-" + digest.removeprefix("sha256:")[:32].upper(),
            "channel_policy_sha256": digest,
        }
    )


def collaboration_execution_channel_selection_sha256(
    policy: CollaborationExecutionChannelPolicy,
) -> str:
    """Hash the policy selection without its circular assertion bindings."""

    parsed = CollaborationExecutionChannelPolicy.from_dict(policy.to_dict())
    document = parsed.to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key
        not in {
            "approval_bindings",
            "channel_policy_id",
            "channel_policy_sha256",
        }
    }
    return _canonical_sha256(
        {"domain": CHANNEL_POLICY_SELECTION_DOMAIN, "selection": selection}
    )


def validate_collaboration_execution_channel_policy(
    policy: CollaborationExecutionChannelPolicy,
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    previous_policy: CollaborationExecutionChannelPolicy | None = None,
) -> CollaborationExecutionChannelPolicy:
    """Validate the exact authority, mission, timeout, and predecessor selection."""

    parsed = CollaborationExecutionChannelPolicy.from_dict(policy.to_dict())
    expected = build_collaboration_execution_channel_policy(
        authority_policy=authority_policy,
        mission_policy=mission_policy,
        policy_version=parsed.to_dict()["policy_version"],
        previous_channel_policy_sha256=parsed.to_dict()["previous_channel_policy_sha256"],
        mission_owner_approval=parsed.to_dict()["approval_bindings"]["mission_owner"],
        independent_control_approval=parsed.to_dict()["approval_bindings"][
            "independent_control"
        ],
        effective_at=parsed.to_dict()["effective_at"],
        expires_at=parsed.to_dict()["expires_at"],
    )
    if parsed.to_dict() != expected.to_dict():
        raise CollaborationPlanError("Execution channel policy binding is stale")
    document = parsed.to_dict()
    if document["policy_version"] == 1:
        if previous_policy is not None:
            raise CollaborationPlanError("Initial execution channel policy cannot replace one")
    else:
        if previous_policy is None:
            raise CollaborationPlanError("Execution channel policy predecessor is required")
        predecessor = CollaborationExecutionChannelPolicy.from_dict(previous_policy.to_dict())
        prior = predecessor.to_dict()
        if (
            document["policy_version"] != prior["policy_version"] + 1
            or document["previous_channel_policy_sha256"]
            != predecessor.channel_policy_sha256
            or document["mission_id"] != prior["mission_id"]
            or document["collaboration_plan_id"] != prior["collaboration_plan_id"]
            or document["collaboration_plan_sha256"]
            != prior["collaboration_plan_sha256"]
        ):
            raise CollaborationPlanError("Execution channel policy predecessor is stale")
        if _timestamp_value(document["effective_at"]) <= _timestamp_value(
            prior["effective_at"]
        ):
            raise CollaborationPlanError("Execution channel policy version is not monotonic")
    return parsed


def _optional_session_predecessor(raw: Any) -> dict[str, str | None]:
    value = _mapping(raw, "worker session predecessor")
    fields = {
        "session_id",
        "session_sha256",
        "credential_reference_id",
        "credential_sha256",
        "revocation_reference_id",
        "revocation_sha256",
    }
    _exact_fields(value, fields, "worker session predecessor")
    result = {
        "session_id": _optional_identifier(value.get("session_id"), "predecessor.session_id"),
        "session_sha256": _optional_sha256(
            value.get("session_sha256"), "predecessor.session_sha256"
        ),
        "credential_reference_id": _optional_identifier(
            value.get("credential_reference_id"), "predecessor.credential_reference_id"
        ),
        "credential_sha256": _optional_sha256(
            value.get("credential_sha256"), "predecessor.credential_sha256"
        ),
        "revocation_reference_id": _optional_identifier(
            value.get("revocation_reference_id"), "predecessor.revocation_reference_id"
        ),
        "revocation_sha256": _optional_sha256(
            value.get("revocation_sha256"), "predecessor.revocation_sha256"
        ),
    }
    present = {key for key, item in result.items() if item is not None}
    if present and present != fields:
        raise CollaborationPlanError("Worker session predecessor proof is incomplete")
    if result["session_id"] is not None and re.fullmatch(
        r"ECS-[0-9A-F]{32}", result["session_id"]
    ) is None:
        raise CollaborationPlanError("predecessor.session_id is invalid")
    return result


@dataclass(frozen=True)
class CollaborationFencedWorkerSession:
    """An inactive worker session bound to one exact ownership fence."""

    session_id: str
    session_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationFencedWorkerSession:
        value = _mapping(raw, "collaboration fenced worker session")
        fields = {
            "schema_version",
            "session_id",
            "session_sha256",
            "channel_policy",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "work_item_id",
            "work_item_objective_sha256",
            "ownership_chain_id",
            "ownership_entry_id",
            "ownership_entry_sha256",
            "owner_profile_id",
            "owner_epoch",
            "worker_principal_id",
            "fence_generation",
            "credential_reference_id",
            "credential_sha256",
            "predecessor",
            "prepared_at",
            "expires_at",
            "session_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration fenced worker session")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Worker session schema is invalid")
        session_id = value.get("session_id")
        session_sha256 = value.get("session_sha256")
        if not isinstance(session_id, str) or re.fullmatch(
            r"ECS-[0-9A-F]{32}", session_id
        ) is None:
            raise CollaborationPlanError("Worker session identity is invalid")
        _sha256(session_sha256, "session_sha256")
        channel_policy = _binding(
            value.get("channel_policy"),
            "channel_policy",
            "channel_policy_id",
            r"ECP-[0-9A-F]{32}",
        )
        for field in (
            "mission_id",
            "collaboration_plan_id",
            "work_item_id",
            "owner_profile_id",
            "worker_principal_id",
            "credential_reference_id",
        ):
            _identifier(value.get(field), field)
        for field in (
            "collaboration_plan_sha256",
            "work_item_objective_sha256",
            "ownership_entry_sha256",
            "credential_sha256",
        ):
            _sha256(value.get(field), field)
        if not isinstance(value.get("ownership_chain_id"), str) or re.fullmatch(
            r"OCN-[0-9A-F]{32}", value["ownership_chain_id"]
        ) is None:
            raise CollaborationPlanError("ownership_chain_id is invalid")
        if not isinstance(value.get("ownership_entry_id"), str) or re.fullmatch(
            r"OCE-[0-9A-F]{32}", value["ownership_entry_id"]
        ) is None:
            raise CollaborationPlanError("ownership_entry_id is invalid")
        _positive_integer(value.get("owner_epoch"), "owner_epoch")
        _positive_integer(value.get("fence_generation"), "fence_generation")
        predecessor = _optional_session_predecessor(value.get("predecessor"))
        prepared_at = _timestamp(value.get("prepared_at"), "prepared_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(prepared_at):
            raise CollaborationPlanError("Worker session window is invalid")
        if value.get("session_status") != "prepared_pending_channel_activation":
            raise CollaborationPlanError("Worker session status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Worker session runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"session_id", "session_sha256"}
        }
        digest = _canonical_sha256({"domain": SESSION_DOMAIN, "session": body})
        expected_id = "ECS-" + digest.removeprefix("sha256:")[:32].upper()
        if session_sha256 != digest or session_id != expected_id:
            raise CollaborationPlanError("Worker session hash is invalid")
        return cls(
            session_id,
            session_sha256,
            _canonical_json(
                {**value, "channel_policy": channel_policy, "predecessor": predecessor}
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Worker session is invalid")
        return value


def build_collaboration_fenced_worker_session(
    *,
    channel_policy: CollaborationExecutionChannelPolicy,
    work_item_id: str,
    work_item_objective_sha256: str,
    ownership_chain_id: str,
    ownership_entry_id: str,
    ownership_entry_sha256: str,
    owner_profile_id: str,
    owner_epoch: int,
    worker_principal_id: str,
    fence_generation: int,
    credential_reference_id: str,
    credential_sha256: str,
    predecessor: dict[str, str | None] | None,
    prepared_at: str,
    expires_at: str,
) -> CollaborationFencedWorkerSession:
    """Build one inert session fence with mandatory predecessor revocation proof."""

    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    policy_document = policy.to_dict()
    if _timestamp_value(expires_at) > _timestamp_value(policy_document["expires_at"]):
        raise CollaborationPlanError("Worker session exceeds the channel policy window")
    body = {
        "schema_version": SCHEMA_VERSION,
        "channel_policy": {
            "channel_policy_id": policy.channel_policy_id,
            "channel_policy_sha256": policy.channel_policy_sha256,
        },
        "mission_id": policy_document["mission_id"],
        "collaboration_plan_id": policy_document["collaboration_plan_id"],
        "collaboration_plan_sha256": policy_document["collaboration_plan_sha256"],
        "work_item_id": work_item_id,
        "work_item_objective_sha256": work_item_objective_sha256,
        "ownership_chain_id": ownership_chain_id,
        "ownership_entry_id": ownership_entry_id,
        "ownership_entry_sha256": ownership_entry_sha256,
        "owner_profile_id": owner_profile_id,
        "owner_epoch": owner_epoch,
        "worker_principal_id": worker_principal_id,
        "fence_generation": fence_generation,
        "credential_reference_id": credential_reference_id,
        "credential_sha256": credential_sha256,
        "predecessor": predecessor
        or {
            "session_id": None,
            "session_sha256": None,
            "credential_reference_id": None,
            "credential_sha256": None,
            "revocation_reference_id": None,
            "revocation_sha256": None,
        },
        "prepared_at": prepared_at,
        "expires_at": expires_at,
        "session_status": "prepared_pending_channel_activation",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": SESSION_DOMAIN, "session": body})
    return CollaborationFencedWorkerSession.from_dict(
        {
            **body,
            "session_id": "ECS-" + digest.removeprefix("sha256:")[:32].upper(),
            "session_sha256": digest,
        }
    )


def validate_collaboration_fenced_worker_session(
    session: CollaborationFencedWorkerSession,
    *,
    channel_policy: CollaborationExecutionChannelPolicy,
    previous_session: CollaborationFencedWorkerSession | None = None,
) -> CollaborationFencedWorkerSession:
    """Validate channel, mission, predecessor, generation, and revocation fences."""

    parsed = CollaborationFencedWorkerSession.from_dict(session.to_dict())
    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    document = parsed.to_dict()
    policy_document = policy.to_dict()
    if document["channel_policy"] != {
        "channel_policy_id": policy.channel_policy_id,
        "channel_policy_sha256": policy.channel_policy_sha256,
    }:
        raise CollaborationPlanError("Worker session channel policy is stale")
    for field in ("mission_id", "collaboration_plan_id", "collaboration_plan_sha256"):
        if document[field] != policy_document[field]:
            raise CollaborationPlanError("Worker session mission binding is stale")
    predecessor = document["predecessor"]
    if previous_session is None:
        if any(item is not None for item in predecessor.values()):
            raise CollaborationPlanError("Initial worker session cannot bind a predecessor")
        if document["fence_generation"] != 1:
            raise CollaborationPlanError("Initial worker session fence generation must be one")
    else:
        previous = CollaborationFencedWorkerSession.from_dict(previous_session.to_dict())
        prior = previous.to_dict()
        expected = {
            "session_id": previous.session_id,
            "session_sha256": previous.session_sha256,
            "credential_reference_id": prior["credential_reference_id"],
            "credential_sha256": prior["credential_sha256"],
        }
        if any(predecessor[key] != item for key, item in expected.items()):
            raise CollaborationPlanError("Worker session predecessor is stale")
        if document["fence_generation"] != prior["fence_generation"] + 1:
            raise CollaborationPlanError("Worker session fence generation is stale")
        anchor_fields = (
            "channel_policy",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "work_item_id",
            "work_item_objective_sha256",
            "ownership_chain_id",
        )
        if any(document[field] != prior[field] for field in anchor_fields):
            raise CollaborationPlanError("Worker session predecessor anchor changed")
        if document["credential_reference_id"] == prior["credential_reference_id"]:
            raise CollaborationPlanError("Successor worker session must rotate credentials")
        if _timestamp_value(document["prepared_at"]) <= _timestamp_value(prior["prepared_at"]):
            raise CollaborationPlanError("Worker session successor is not monotonic")
    return parsed


def load_collaboration_execution_channel_policy(
    path: str | Path,
) -> CollaborationExecutionChannelPolicy:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution channel policy: {resolved}"
        ) from exc
    return CollaborationExecutionChannelPolicy.from_dict(raw)


def load_collaboration_fenced_worker_session(
    path: str | Path,
) -> CollaborationFencedWorkerSession:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load worker session: {resolved}") from exc
    return CollaborationFencedWorkerSession.from_dict(raw)


__all__ = [
    "CollaborationExecutionChannelPolicy",
    "CollaborationFencedWorkerSession",
    "build_collaboration_execution_channel_policy",
    "build_collaboration_fenced_worker_session",
    "collaboration_execution_channel_selection_sha256",
    "load_collaboration_execution_channel_policy",
    "load_collaboration_fenced_worker_session",
    "validate_collaboration_execution_channel_policy",
    "validate_collaboration_fenced_worker_session",
]
