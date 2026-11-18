"""Atomic custody preflight for terminal execution transfer outcomes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_timeout import (
    validate_collaboration_execution_timeout_resolution,
)
from .collaboration_execution_timeout_authentication import (
    AuthenticatedCollaborationExecutionTimeoutResolution,
    validate_authenticated_collaboration_execution_timeout_resolution,
)
from .collaboration_execution_transfer_authentication import (
    AuthenticatedCollaborationExecutionAcknowledgement,
    AuthenticatedCollaborationExecutionTransferRequest,
    validate_authenticated_collaboration_execution_acknowledgement,
    validate_authenticated_collaboration_execution_transfer_request,
)
from .collaboration_execution_transfer_completion import (
    CollaborationExecutionTransferCompletion,
    validate_collaboration_execution_transfer_completion,
)
from .errors import CollaborationPlanError
from .identity import VerifiedPrincipal
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
CUSTODY_PLAN_DOMAIN = "sunderkey.collaboration-execution-terminal-custody-plan.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TERMINAL_KINDS = {"completed", "failed_closed_timeout"}
ROLE_OPERATIONS = {
    "control_plane_requester": "sunderkey.collaboration.execution-transfer.request-authorize.v1",
    "source_worker": "sunderkey.collaboration.execution-transfer.acknowledge.v1",
    "target_worker": "sunderkey.collaboration.execution-transfer.acknowledge.v1",
    "independent_control": "sunderkey.collaboration.execution-transfer.timeout-resolve.v1",
}


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(
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


def _optional_authentication(raw: Any, terminal_kind: str) -> dict[str, str | None]:
    value = _mapping(raw, "outcome_authentication")
    _exact_fields(
        value,
        {"authentication_id", "authentication_sha256"},
        "outcome_authentication",
    )
    if terminal_kind == "completed":
        if value != {"authentication_id": None, "authentication_sha256": None}:
            raise CollaborationPlanError("Completed outcome cannot have separate authentication")
        return {"authentication_id": None, "authentication_sha256": None}
    authentication_id = value.get("authentication_id")
    if (
        not isinstance(authentication_id, str)
        or re.fullmatch(r"ETA-[0-9A-F]{32}", authentication_id) is None
    ):
        raise CollaborationPlanError("Timeout outcome authentication is invalid")
    return {
        "authentication_id": authentication_id,
        "authentication_sha256": _sha256(
            value.get("authentication_sha256"),
            "outcome_authentication.authentication_sha256",
        ),
    }


def _participant(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    fields = {
        "role",
        "authentication_id",
        "authentication_sha256",
        "profile_id",
        "issuer",
        "assertion_id",
        "assertion_sha256",
        "operation",
        "operation_intent_sha256",
        "policy_sha256",
        "scope_grant_id",
        "scope_grant_sha256",
    }
    _exact_fields(value, fields, label)
    role = value.get("role")
    if role not in ROLE_OPERATIONS:
        raise CollaborationPlanError(f"{label}.role is invalid")
    operation = value.get("operation")
    if operation != ROLE_OPERATIONS[role]:
        raise CollaborationPlanError(f"{label}.operation is invalid")
    authentication_id = value.get("authentication_id")
    authentication_pattern = {
        "control_plane_requester": r"ERA-[0-9A-F]{32}",
        "source_worker": r"EAA-[0-9A-F]{32}",
        "target_worker": r"EAA-[0-9A-F]{32}",
        "independent_control": r"ETA-[0-9A-F]{32}",
    }[role]
    if (
        not isinstance(authentication_id, str)
        or re.fullmatch(authentication_pattern, authentication_id) is None
    ):
        raise CollaborationPlanError(f"{label}.authentication_id is invalid")
    assertion_id = value.get("assertion_id")
    if not isinstance(assertion_id, str) or re.fullmatch(r"PAS-[0-9A-F]{32}", assertion_id) is None:
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    scope_grant_id = value.get("scope_grant_id")
    if (
        not isinstance(scope_grant_id, str)
        or re.fullmatch(r"SGR-[0-9A-F]{32}", scope_grant_id) is None
    ):
        raise CollaborationPlanError(f"{label}.scope_grant_id is invalid")
    return {
        "role": role,
        "authentication_id": authentication_id,
        "authentication_sha256": _sha256(
            value.get("authentication_sha256"), f"{label}.authentication_sha256"
        ),
        "profile_id": _identifier(value.get("profile_id"), f"{label}.profile_id"),
        "issuer": _identifier(value.get("issuer"), f"{label}.issuer"),
        "assertion_id": assertion_id,
        "assertion_sha256": _sha256(value.get("assertion_sha256"), f"{label}.assertion_sha256"),
        "operation": operation,
        "operation_intent_sha256": _sha256(
            value.get("operation_intent_sha256"), f"{label}.operation_intent_sha256"
        ),
        "policy_sha256": _sha256(value.get("policy_sha256"), f"{label}.policy_sha256"),
        "scope_grant_id": scope_grant_id,
        "scope_grant_sha256": _sha256(
            value.get("scope_grant_sha256"), f"{label}.scope_grant_sha256"
        ),
    }


def _participant_from_principal(
    role: str,
    authentication_id: str,
    authentication_sha256: str,
    principal: VerifiedPrincipal,
) -> dict[str, str]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("participant must be a verified principal")
    document = principal.to_dict()
    return _participant(
        {
            "role": role,
            "authentication_id": authentication_id,
            "authentication_sha256": authentication_sha256,
            "profile_id": document["profile_id"],
            "issuer": document["issuer"],
            "assertion_id": document["assertion_id"],
            "assertion_sha256": document["assertion_sha256"],
            "operation": document["operation"],
            "operation_intent_sha256": document["operation_intent_sha256"],
            "policy_sha256": document["policy_sha256"],
            "scope_grant_id": document["scope_grant_id"],
            "scope_grant_sha256": document["scope_grant_sha256"],
        },
        role,
    )


@dataclass(frozen=True)
class CollaborationExecutionTerminalCustodyPlan:
    """One no-effect plan for atomically committing a terminal outcome."""

    custody_plan_id: str
    custody_plan_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionTerminalCustodyPlan:
        value = _mapping(raw, "collaboration execution terminal custody plan")
        fields = {
            "schema_version",
            "custody_plan_id",
            "custody_plan_sha256",
            "terminal_kind",
            "terminal_outcome",
            "outcome_authentication",
            "request_authentication",
            "transfer_request",
            "mission_id",
            "work_item_id",
            "transfer_kind",
            "participant_authentications",
            "assertion_consumption_order",
            "source_session_disposition",
            "target_session_disposition",
            "recovery_required",
            "custody_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution terminal custody plan")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution terminal custody schema is invalid")
        plan_id = value.get("custody_plan_id")
        plan_sha256 = value.get("custody_plan_sha256")
        if not isinstance(plan_id, str) or re.fullmatch(r"ECT-[0-9A-F]{32}", plan_id) is None:
            raise CollaborationPlanError("Execution terminal custody identity is invalid")
        _sha256(plan_sha256, "custody_plan_sha256")
        terminal_kind = value.get("terminal_kind")
        if terminal_kind not in TERMINAL_KINDS:
            raise CollaborationPlanError("Execution terminal custody kind is invalid")
        outcome = _binding(
            value.get("terminal_outcome"),
            "terminal_outcome",
            id_field="outcome_id",
            id_pattern=(
                r"ETC-[0-9A-F]{32}" if terminal_kind == "completed" else r"ETD-[0-9A-F]{32}"
            ),
        )
        outcome_authentication = _optional_authentication(
            value.get("outcome_authentication"), terminal_kind
        )
        request_authentication = _binding(
            value.get("request_authentication"),
            "request_authentication",
            id_field="authentication_id",
            id_pattern=r"ERA-[0-9A-F]{32}",
        )
        transfer_request = _binding(
            value.get("transfer_request"),
            "transfer_request",
            id_field="request_id",
            id_pattern=r"ETR-[0-9A-F]{32}",
        )
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("work_item_id"), "work_item_id")
        if value.get("transfer_kind") not in {"ownership_handoff", "work_cancellation"}:
            raise CollaborationPlanError("Execution terminal transfer kind is invalid")
        raw_participants = value.get("participant_authentications")
        if not isinstance(raw_participants, list) or not raw_participants:
            raise CollaborationPlanError("Execution terminal participants are invalid")
        participants = [
            _participant(item, f"participant_authentications[{index}]")
            for index, item in enumerate(raw_participants)
        ]
        roles = [item["role"] for item in participants]
        if roles[0] != "control_plane_requester":
            raise CollaborationPlanError("Execution terminal requester must be first")
        if terminal_kind == "completed" and "independent_control" in roles:
            raise CollaborationPlanError("Completed outcome cannot include timeout Control")
        if terminal_kind == "failed_closed_timeout" and roles[-1] != "independent_control":
            raise CollaborationPlanError("Timeout Control must be last")
        authentication_ids = [item["authentication_id"] for item in participants]
        assertion_identities = [(item["issuer"], item["assertion_id"]) for item in participants]
        if len(set(authentication_ids)) != len(authentication_ids) or len(
            set(assertion_identities)
        ) != len(assertion_identities):
            raise CollaborationPlanError("Execution terminal participants are duplicated")
        if value.get("assertion_consumption_order") != authentication_ids:
            raise CollaborationPlanError("Execution terminal assertion order is invalid")
        expected_source = "revoked_unavailable"
        expected_target = (
            "eligible_after_atomic_commit"
            if terminal_kind == "completed" and value.get("transfer_kind") == "ownership_handoff"
            else (
                "blocked_never_activated"
                if terminal_kind == "failed_closed_timeout"
                and value.get("transfer_kind") == "ownership_handoff"
                else "not_applicable"
            )
        )
        if terminal_kind == "failed_closed_timeout" and value.get(
            "source_session_disposition"
        ) not in {"revoked_unavailable", "fenced_pending_recovery"}:
            raise CollaborationPlanError("Execution terminal source disposition is invalid")
        if (
            terminal_kind == "completed"
            and value.get("source_session_disposition") != expected_source
        ):
            raise CollaborationPlanError("Execution terminal source disposition is invalid")
        if value.get("target_session_disposition") != expected_target:
            raise CollaborationPlanError("Execution terminal target disposition is invalid")
        if value.get("recovery_required") is not (terminal_kind == "failed_closed_timeout"):
            raise CollaborationPlanError("Execution terminal recovery flag is invalid")
        if value.get("custody_status") != "ready_for_atomic_commit":
            raise CollaborationPlanError("Execution terminal custody status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution terminal custody runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"custody_plan_id", "custody_plan_sha256"}
        }
        digest = _canonical_sha256({"domain": CUSTODY_PLAN_DOMAIN, "custody_plan": body})
        expected_id = "ECT-" + digest.removeprefix("sha256:")[:32].upper()
        if plan_sha256 != digest or plan_id != expected_id:
            raise CollaborationPlanError("Execution terminal custody hash is invalid")
        return cls(
            plan_id,
            plan_sha256,
            _canonical_json(
                {
                    **value,
                    "terminal_outcome": outcome,
                    "outcome_authentication": outcome_authentication,
                    "request_authentication": request_authentication,
                    "transfer_request": transfer_request,
                    "participant_authentications": participants,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution terminal custody plan is invalid")
        return value


def _request_participant(
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
) -> dict[str, str]:
    return _participant_from_principal(
        "control_plane_requester",
        authenticated_request.authentication_id,
        authenticated_request.authentication_sha256,
        authenticated_request.control_plane_requester,
    )


def _acknowledgement_participants(
    acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
) -> list[dict[str, str]]:
    request_document = authenticated_request.request.to_dict()
    order = {
        kind: index for index, kind in enumerate(request_document["required_acknowledgement_kinds"])
    }
    parsed: list[tuple[int, dict[str, str]]] = []
    for authentication, session in acknowledgements:
        validated = validate_authenticated_collaboration_execution_acknowledgement(
            authentication,
            authenticated_request=authenticated_request,
            session=session,
        )
        acknowledgement_kind = validated.acknowledgement.to_dict()["acknowledgement_kind"]
        role = "target_worker" if acknowledgement_kind == "target_accepted" else "source_worker"
        parsed.append(
            (
                order[acknowledgement_kind],
                _participant_from_principal(
                    role,
                    validated.authentication_id,
                    validated.authentication_sha256,
                    validated.external_acknowledger,
                ),
            )
        )
    return [item for _, item in sorted(parsed, key=lambda entry: entry[0])]


def build_collaboration_execution_terminal_custody_plan(
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
    completion: CollaborationExecutionTransferCompletion | None = None,
    authenticated_timeout: AuthenticatedCollaborationExecutionTimeoutResolution | None = None,
) -> CollaborationExecutionTerminalCustodyPlan:
    """Prepare one mutually exclusive terminal outcome for atomic custody."""

    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    if (completion is None) == (authenticated_timeout is None):
        raise CollaborationPlanError("Exactly one execution terminal outcome is required")
    request = request_authentication.request
    request_document = request.to_dict()
    participants = [_request_participant(request_authentication)]
    participants.extend(
        _acknowledgement_participants(
            acknowledgements,
            authenticated_request=request_authentication,
        )
    )
    if completion is not None:
        parsed_completion = validate_collaboration_execution_transfer_completion(
            completion,
            authenticated_request=request_authentication,
            acknowledgements=acknowledgements,
        )
        terminal_kind = "completed"
        outcome_id = parsed_completion.completion_id
        outcome_sha256 = parsed_completion.completion_sha256
        outcome_authentication: dict[str, str | None] = {
            "authentication_id": None,
            "authentication_sha256": None,
        }
        outcome_document = parsed_completion.to_dict()
    else:
        timeout_authentication = validate_authenticated_collaboration_execution_timeout_resolution(
            authenticated_timeout
        )
        resolution = validate_collaboration_execution_timeout_resolution(
            timeout_authentication.resolution,
            authenticated_request=request_authentication,
            observed_acknowledgements=acknowledgements,
        )
        terminal_kind = "failed_closed_timeout"
        outcome_id = resolution.resolution_id
        outcome_sha256 = resolution.resolution_sha256
        outcome_authentication = {
            "authentication_id": timeout_authentication.authentication_id,
            "authentication_sha256": timeout_authentication.authentication_sha256,
        }
        participants.append(
            _participant_from_principal(
                "independent_control",
                timeout_authentication.authentication_id,
                timeout_authentication.authentication_sha256,
                timeout_authentication.independent_control,
            )
        )
        outcome_document = resolution.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "terminal_kind": terminal_kind,
        "terminal_outcome": {
            "outcome_id": outcome_id,
            "outcome_sha256": outcome_sha256,
        },
        "outcome_authentication": outcome_authentication,
        "request_authentication": {
            "authentication_id": request_authentication.authentication_id,
            "authentication_sha256": request_authentication.authentication_sha256,
        },
        "transfer_request": {
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
        },
        "mission_id": request_document["mission_id"],
        "work_item_id": request_document["work_item_id"],
        "transfer_kind": request_document["transfer_kind"],
        "participant_authentications": participants,
        "assertion_consumption_order": [item["authentication_id"] for item in participants],
        "source_session_disposition": outcome_document["source_session_disposition"],
        "target_session_disposition": outcome_document["target_session_disposition"],
        "recovery_required": terminal_kind == "failed_closed_timeout",
        "custody_status": "ready_for_atomic_commit",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": CUSTODY_PLAN_DOMAIN, "custody_plan": body})
    return CollaborationExecutionTerminalCustodyPlan.from_dict(
        {
            **body,
            "custody_plan_id": "ECT-" + digest.removeprefix("sha256:")[:32].upper(),
            "custody_plan_sha256": digest,
        }
    )


def load_collaboration_execution_terminal_custody_plan(
    path: str | Path,
) -> CollaborationExecutionTerminalCustodyPlan:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load execution terminal custody plan: {resolved}"
        ) from exc
    return CollaborationExecutionTerminalCustodyPlan.from_dict(raw)


__all__ = [
    "CollaborationExecutionTerminalCustodyPlan",
    "build_collaboration_execution_terminal_custody_plan",
    "load_collaboration_execution_terminal_custody_plan",
]
