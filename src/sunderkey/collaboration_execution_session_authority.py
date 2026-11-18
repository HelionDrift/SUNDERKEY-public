"""Content-addressed worker-session authority and revocation contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration import CollaborationPlan
from .collaboration_execution_channel import (
    CollaborationExecutionChannelPolicy,
    CollaborationFencedWorkerSession,
    validate_collaboration_fenced_worker_session,
)
from .collaboration_execution_terminal_custody import (
    CollaborationExecutionTerminalCustodyPlan,
)
from .collaboration_execution_transfer import (
    CollaborationExecutionTransferRequest,
    collaboration_execution_transfer_request_selection_sha256,
)
from .collaboration_execution_transfer_authentication import (
    REQUEST_AUTHENTICATION_DOMAIN,
    AuthenticatedCollaborationExecutionTransferRequest,
    validate_authenticated_collaboration_execution_transfer_request,
)
from .collaboration_ownership_chain import collaboration_work_item_objective_sha256
from .errors import CollaborationPlanError
from .identity import PrincipalOperation, compute_operation_intent_hash
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
SESSION_AUTHORITY_DOMAIN = "sunderkey.collaboration-execution-session-authority.v1"
SESSION_REVOCATION_DOMAIN = "sunderkey.collaboration-execution-session-revocation.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
AUTHORITY_KINDS = {"initial_activation", "handoff_activation"}
REVOCATION_REASONS = {
    "credential_compromise",
    "health_failure",
    "mission_stop",
    "normal_completion",
    "operator_request",
    "ownership_change",
    "policy_superseded",
    "timeout_recovery",
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


def _binding(
    raw: Any,
    label: str,
    *,
    id_field: str,
    id_pattern: str,
) -> dict[str, str]:
    value = _mapping(raw, label)
    sha_field = id_field.removesuffix("_id") + "_sha256"
    _exact_fields(value, {id_field, sha_field}, label)
    identifier = value.get(id_field)
    if not isinstance(identifier, str) or re.fullmatch(id_pattern, identifier) is None:
        raise CollaborationPlanError(f"{label}.{id_field} is invalid")
    return {
        id_field: identifier,
        sha_field: _sha256(value.get(sha_field), f"{label}.{sha_field}"),
    }


def _assertion_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"profile_id", "assertion_id", "assertion_sha256"}, label)
    assertion_id = value.get("assertion_id")
    if (
        not isinstance(assertion_id, str)
        or re.fullmatch(r"PAS-[0-9A-F]{32}", assertion_id) is None
    ):
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    return {
        "profile_id": _identifier(value.get("profile_id"), f"{label}.profile_id"),
        "assertion_id": assertion_id,
        "assertion_sha256": _sha256(
            value.get("assertion_sha256"),
            f"{label}.assertion_sha256",
        ),
    }


def _load_document(path: str | Path, label: str) -> Any:
    resolved = Path(path).resolve()
    try:
        return loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load {label}: {resolved}") from exc


def _verified_principal_document(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "control_plane_requester")
    fields = {
        "assertion_id",
        "assertion_sha256",
        "subject",
        "profile_id",
        "issuer",
        "key_id",
        "key_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "scope_grant_id",
        "scope_grant_sha256",
        "audience",
        "store_id",
        "mission_id",
        "operation",
        "operation_intent_sha256",
        "authenticated_at",
        "expires_at",
    }
    _exact_fields(value, fields, "control_plane_requester")
    for field in (
        "subject",
        "profile_id",
        "issuer",
        "key_id",
        "policy_id",
        "audience",
        "store_id",
        "mission_id",
    ):
        _identifier(value.get(field), f"control_plane_requester.{field}")
    assertion_id = value.get("assertion_id")
    scope_grant_id = value.get("scope_grant_id")
    if (
        not isinstance(assertion_id, str)
        or re.fullmatch(r"PAS-[0-9A-F]{32}", assertion_id) is None
        or not isinstance(scope_grant_id, str)
        or re.fullmatch(r"SGR-[0-9A-F]{32}", scope_grant_id) is None
    ):
        raise CollaborationPlanError("Execution session requester identity is invalid")
    for field in (
        "assertion_sha256",
        "key_sha256",
        "policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
    ):
        _sha256(value.get(field), f"control_plane_requester.{field}")
    policy_version = value.get("policy_version")
    if (
        not isinstance(policy_version, int)
        or isinstance(policy_version, bool)
        or policy_version < 1
    ):
        raise CollaborationPlanError("Execution session requester policy version is invalid")
    if value.get("operation") != PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE.value:
        raise CollaborationPlanError("Execution session requester operation is invalid")
    authenticated_at = _timestamp(
        value.get("authenticated_at"),
        "control_plane_requester.authenticated_at",
    )
    expires_at = _timestamp(
        value.get("expires_at"),
        "control_plane_requester.expires_at",
    )
    if _timestamp_value(authenticated_at) > _timestamp_value(expires_at):
        raise CollaborationPlanError("Execution session requester time is invalid")
    return dict(value)


def _durable_request_authentication(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "request_authentication")
    fields = {
        "schema_version",
        "transfer_request",
        "control_plane_requester",
        "authenticated_at",
        "authentication_status",
        "runtime_effect",
        "authentication_id",
        "authentication_sha256",
    }
    _exact_fields(value, fields, "request_authentication")
    if value.get("schema_version") != 1:
        raise CollaborationPlanError("Execution session request authentication schema is invalid")
    request = CollaborationExecutionTransferRequest.from_dict(value.get("transfer_request"))
    request_document = request.to_dict()
    principal = _verified_principal_document(value.get("control_plane_requester"))
    authenticated_at = _timestamp(value.get("authenticated_at"), "authenticated_at")
    authentication_id = value.get("authentication_id")
    authentication_sha256 = value.get("authentication_sha256")
    if (
        not isinstance(authentication_id, str)
        or re.fullmatch(r"ERA-[0-9A-F]{32}", authentication_id) is None
    ):
        raise CollaborationPlanError("Execution session request authentication is invalid")
    _sha256(authentication_sha256, "authentication_sha256")
    if (
        value.get("authentication_status") != "authenticated_control_plane_request"
        or value.get("runtime_effect") != "none"
        or authenticated_at != principal["authenticated_at"]
        or principal["mission_id"] != request_document["mission_id"]
        or principal["profile_id"]
        != request_document["control_plane_requester"]["profile_id"]
        or principal["assertion_id"]
        != request_document["control_plane_requester"]["assertion_id"]
        or principal["assertion_sha256"]
        != request_document["control_plane_requester"]["assertion_sha256"]
    ):
        raise CollaborationPlanError("Execution session request authentication is stale")
    operation = PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE
    intent = {
        "mission_id": request_document["mission_id"],
        "principal_profile_id": principal["profile_id"],
        "request_selection_sha256": (
            collaboration_execution_transfer_request_selection_sha256(request)
        ),
    }
    if principal["operation_intent_sha256"] != compute_operation_intent_hash(
        operation,
        intent,
    ):
        raise CollaborationPlanError("Execution session request intent is invalid")
    body = {
        "schema_version": 1,
        "transfer_request": request.to_dict(),
        "control_plane_requester": principal,
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_control_plane_request",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": REQUEST_AUTHENTICATION_DOMAIN, "authentication": body}
    )
    expected_id = "ERA-" + digest.removeprefix("sha256:")[:32].upper()
    if authentication_sha256 != digest or authentication_id != expected_id:
        raise CollaborationPlanError("Execution session request authentication hash is invalid")
    return {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": authentication_sha256,
    }


def _activation_evidence(raw: Any, authority_kind: str) -> dict[str, Any]:
    value = _mapping(raw, "activation_evidence")
    _exact_fields(
        value,
        {"evidence_kind", "request_authentication", "source_session"},
        "activation_evidence",
    )
    if authority_kind == "initial_activation":
        if value != {
            "evidence_kind": "planned_owner",
            "request_authentication": None,
            "source_session": None,
        }:
            raise CollaborationPlanError("Initial execution session evidence is invalid")
        return dict(value)
    if value.get("evidence_kind") != "completed_transfer":
        raise CollaborationPlanError("Handoff execution session evidence is invalid")
    return {
        "evidence_kind": "completed_transfer",
        "request_authentication": _durable_request_authentication(
            value.get("request_authentication")
        ),
        "source_session": CollaborationFencedWorkerSession.from_dict(
            value.get("source_session")
        ).to_dict(),
    }


@dataclass(frozen=True)
class CollaborationExecutionSessionAuthority:
    """One inactive authority record for an exact fenced worker session."""

    session_authority_id: str
    session_authority_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionSessionAuthority:
        value = _mapping(raw, "collaboration execution session authority")
        fields = {
            "schema_version",
            "session_authority_id",
            "session_authority_sha256",
            "authority_kind",
            "authorization_basis",
            "activation_evidence",
            "session",
            "effective_at",
            "expires_at",
            "authority_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution session authority")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution session authority schema is invalid")
        authority_id = value.get("session_authority_id")
        authority_sha256 = value.get("session_authority_sha256")
        if (
            not isinstance(authority_id, str)
            or re.fullmatch(r"ESA-[0-9A-F]{32}", authority_id) is None
        ):
            raise CollaborationPlanError("Execution session authority identity is invalid")
        _sha256(authority_sha256, "session_authority_sha256")
        authority_kind = value.get("authority_kind")
        if authority_kind not in AUTHORITY_KINDS:
            raise CollaborationPlanError("Execution session authority kind is invalid")
        basis = _mapping(value.get("authorization_basis"), "authorization_basis")
        _exact_fields(
            basis,
            {"basis_kind", "basis_id", "basis_sha256"},
            "authorization_basis",
        )
        expected_basis_kind = (
            "activated_plan"
            if authority_kind == "initial_activation"
            else "completed_terminal_custody"
        )
        if basis.get("basis_kind") != expected_basis_kind:
            raise CollaborationPlanError("Execution session authority basis kind is invalid")
        basis_id = basis.get("basis_id")
        basis_pattern = (
            r"CLP-[0-9A-F]{24}"
            if authority_kind == "initial_activation"
            else r"ECT-[0-9A-F]{32}"
        )
        if not isinstance(basis_id, str) or re.fullmatch(basis_pattern, basis_id) is None:
            raise CollaborationPlanError("Execution session authority basis is invalid")
        parsed_basis = {
            "basis_kind": expected_basis_kind,
            "basis_id": basis_id,
            "basis_sha256": _sha256(basis.get("basis_sha256"), "basis_sha256"),
        }
        evidence = _activation_evidence(value.get("activation_evidence"), authority_kind)
        session = CollaborationFencedWorkerSession.from_dict(value.get("session"))
        session_document = session.to_dict()
        effective_at = _timestamp(value.get("effective_at"), "effective_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if expires_at != session_document["expires_at"]:
            raise CollaborationPlanError("Execution session authority expiry is invalid")
        if _timestamp_value(effective_at) < _timestamp_value(session_document["prepared_at"]):
            raise CollaborationPlanError("Execution session authority precedes preparation")
        if _timestamp_value(effective_at) >= _timestamp_value(expires_at):
            raise CollaborationPlanError("Execution session authority window is invalid")
        if value.get("authority_status") != "pending_atomic_commit":
            raise CollaborationPlanError("Execution session authority status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution session authority runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"session_authority_id", "session_authority_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": SESSION_AUTHORITY_DOMAIN, "session_authority": body}
        )
        expected_id = "ESA-" + digest.removeprefix("sha256:")[:32].upper()
        if authority_sha256 != digest or authority_id != expected_id:
            raise CollaborationPlanError("Execution session authority hash is invalid")
        return cls(
            authority_id,
            authority_sha256,
            _canonical_json(
                {
                    **value,
                    "authorization_basis": parsed_basis,
                    "activation_evidence": evidence,
                    "session": session.to_dict(),
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution session authority is invalid")
        return value


@dataclass(frozen=True)
class CollaborationExecutionSessionRevocation:
    """One pending explicit revocation for a session authority."""

    revocation_id: str
    revocation_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionSessionRevocation:
        value = _mapping(raw, "collaboration execution session revocation")
        fields = {
            "schema_version",
            "revocation_id",
            "revocation_sha256",
            "session_authority",
            "mission_id",
            "work_item_id",
            "session",
            "credential",
            "decision_owner",
            "reason_code",
            "revoked_at",
            "revocation_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration execution session revocation")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution session revocation schema is invalid")
        revocation_id = value.get("revocation_id")
        revocation_sha256 = value.get("revocation_sha256")
        if (
            not isinstance(revocation_id, str)
            or re.fullmatch(r"ESR-[0-9A-F]{32}", revocation_id) is None
        ):
            raise CollaborationPlanError("Execution session revocation identity is invalid")
        _sha256(revocation_sha256, "revocation_sha256")
        authority = _binding(
            value.get("session_authority"),
            "session_authority",
            id_field="session_authority_id",
            id_pattern=r"ESA-[0-9A-F]{32}",
        )
        session = _binding(
            value.get("session"),
            "session",
            id_field="session_id",
            id_pattern=r"ECS-[0-9A-F]{32}",
        )
        credential = _mapping(value.get("credential"), "credential")
        _exact_fields(
            credential,
            {"credential_reference_id", "credential_sha256"},
            "credential",
        )
        parsed_credential = {
            "credential_reference_id": _identifier(
                credential.get("credential_reference_id"),
                "credential_reference_id",
            ),
            "credential_sha256": _sha256(
                credential.get("credential_sha256"),
                "credential_sha256",
            ),
        }
        decision_owner = _assertion_binding(value.get("decision_owner"), "decision_owner")
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("work_item_id"), "work_item_id")
        if value.get("reason_code") not in REVOCATION_REASONS:
            raise CollaborationPlanError("Execution session revocation reason is invalid")
        _timestamp(value.get("revoked_at"), "revoked_at")
        if value.get("revocation_status") != "pending_control_authentication":
            raise CollaborationPlanError("Execution session revocation status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Execution session revocation runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"revocation_id", "revocation_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": SESSION_REVOCATION_DOMAIN, "session_revocation": body}
        )
        expected_id = "ESR-" + digest.removeprefix("sha256:")[:32].upper()
        if revocation_sha256 != digest or revocation_id != expected_id:
            raise CollaborationPlanError("Execution session revocation hash is invalid")
        return cls(
            revocation_id,
            revocation_sha256,
            _canonical_json(
                {
                    **value,
                    "session_authority": authority,
                    "session": session,
                    "credential": parsed_credential,
                    "decision_owner": decision_owner,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution session revocation is invalid")
        return value


def _authority(
    *,
    authority_kind: str,
    basis_kind: str,
    basis_id: str,
    basis_sha256: str,
    activation_evidence: dict[str, Any],
    session: CollaborationFencedWorkerSession,
    effective_at: str,
) -> CollaborationExecutionSessionAuthority:
    document = session.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": authority_kind,
        "authorization_basis": {
            "basis_kind": basis_kind,
            "basis_id": basis_id,
            "basis_sha256": basis_sha256,
        },
        "activation_evidence": activation_evidence,
        "session": document,
        "effective_at": effective_at,
        "expires_at": document["expires_at"],
        "authority_status": "pending_atomic_commit",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": SESSION_AUTHORITY_DOMAIN, "session_authority": body}
    )
    return CollaborationExecutionSessionAuthority.from_dict(
        {
            **body,
            "session_authority_id": "ESA-" + digest.removeprefix("sha256:")[:32].upper(),
            "session_authority_sha256": digest,
        }
    )


def build_initial_collaboration_execution_session_authority(
    *,
    collaboration_plan: CollaborationPlan,
    channel_policy: CollaborationExecutionChannelPolicy,
    session: CollaborationFencedWorkerSession,
    effective_at: str,
) -> CollaborationExecutionSessionAuthority:
    """Prepare initial session authority for one planned work owner."""

    plan = CollaborationPlan.from_dict(collaboration_plan.to_dict())
    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    parsed_session = validate_collaboration_fenced_worker_session(
        session,
        channel_policy=policy,
        previous_session=None,
    )
    policy_document = policy.to_dict()
    document = parsed_session.to_dict()
    if (
        policy_document["collaboration_plan_id"] != plan.plan_id
        or policy_document["collaboration_plan_sha256"] != plan.content_sha256
    ):
        raise CollaborationPlanError("Execution session plan is not bound to the policy")
    items = {item.work_item_id: item for item in plan.work_items}
    item = items.get(document["work_item_id"])
    if (
        item is None
        or collaboration_work_item_objective_sha256(item)
        != document["work_item_objective_sha256"]
    ):
        raise CollaborationPlanError("Execution session work item is not in the plan")
    if (
        document["owner_profile_id"] != item.owner_profile_id
        or document["worker_principal_id"] != item.owner_profile_id
        or document["owner_epoch"] != 1
    ):
        raise CollaborationPlanError("Initial execution session owner is invalid")
    return _authority(
        authority_kind="initial_activation",
        basis_kind="activated_plan",
        basis_id=plan.plan_id,
        basis_sha256=plan.content_sha256,
        activation_evidence={
            "evidence_kind": "planned_owner",
            "request_authentication": None,
            "source_session": None,
        },
        session=parsed_session,
        effective_at=effective_at,
    )


def build_handoff_collaboration_execution_session_authority(
    *,
    channel_policy: CollaborationExecutionChannelPolicy,
    source_session: CollaborationFencedWorkerSession,
    target_session: CollaborationFencedWorkerSession,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    custody_plan: CollaborationExecutionTerminalCustodyPlan,
    effective_at: str,
) -> CollaborationExecutionSessionAuthority:
    """Prepare successor authority from completed terminal custody."""

    policy = CollaborationExecutionChannelPolicy.from_dict(channel_policy.to_dict())
    source = CollaborationFencedWorkerSession.from_dict(source_session.to_dict())
    source_document = source.to_dict()
    policy_document = policy.to_dict()
    if source_document["channel_policy"] != {
        "channel_policy_id": policy.channel_policy_id,
        "channel_policy_sha256": policy.channel_policy_sha256,
    } or any(
        source_document[field] != policy_document[field]
        for field in (
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
        )
    ):
        raise CollaborationPlanError("Execution session source channel policy is stale")
    target = validate_collaboration_fenced_worker_session(
        target_session,
        channel_policy=policy,
        previous_session=source,
    )
    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    request = request_authentication.request.to_dict()
    plan = CollaborationExecutionTerminalCustodyPlan.from_dict(custody_plan.to_dict())
    plan_document = plan.to_dict()
    target_document = target.to_dict()
    expected_target = {
        "session_id": target.session_id,
        "session_sha256": target.session_sha256,
        "worker_principal_id": target_document["worker_principal_id"],
        "fence_generation": target_document["fence_generation"],
        "credential_reference_id": target_document["credential_reference_id"],
        "credential_sha256": target_document["credential_sha256"],
    }
    if (
        plan_document["terminal_kind"] != "completed"
        or plan_document["transfer_kind"] != "ownership_handoff"
        or plan_document["target_session_disposition"]
        != "eligible_after_atomic_commit"
        or plan_document["request_authentication"]["authentication_id"]
        != request_authentication.authentication_id
        or plan_document["transfer_request"]["request_id"]
        != request_authentication.request.request_id
        or request["target_session"] != expected_target
    ):
        raise CollaborationPlanError("Execution session terminal custody is not eligible")
    target_participants = [
        item
        for item in plan_document["participant_authentications"]
        if item["role"] == "target_worker"
    ]
    if (
        len(target_participants) != 1
        or target_participants[0]["profile_id"]
        != target_document["worker_principal_id"]
        or target_document["owner_profile_id"]
        != target_document["worker_principal_id"]
    ):
        raise CollaborationPlanError("Execution session target worker custody is invalid")
    return _authority(
        authority_kind="handoff_activation",
        basis_kind="completed_terminal_custody",
        basis_id=plan.custody_plan_id,
        basis_sha256=plan.custody_plan_sha256,
        activation_evidence={
            "evidence_kind": "completed_transfer",
            "request_authentication": request_authentication.to_dict(),
            "source_session": source.to_dict(),
        },
        session=target,
        effective_at=effective_at,
    )


def build_collaboration_execution_session_revocation(
    authority: CollaborationExecutionSessionAuthority,
    *,
    decision_owner: dict[str, str],
    reason_code: str,
    revoked_at: str,
) -> CollaborationExecutionSessionRevocation:
    """Prepare an explicit session revocation for later authentication."""

    parsed_authority = CollaborationExecutionSessionAuthority.from_dict(authority.to_dict())
    authority_document = parsed_authority.to_dict()
    session = CollaborationFencedWorkerSession.from_dict(authority_document["session"])
    session_document = session.to_dict()
    revoked = _timestamp(revoked_at, "revoked_at")
    if _timestamp_value(revoked) < _timestamp_value(authority_document["effective_at"]):
        raise CollaborationPlanError("Execution session revocation precedes authority")
    body = {
        "schema_version": SCHEMA_VERSION,
        "session_authority": {
            "session_authority_id": parsed_authority.session_authority_id,
            "session_authority_sha256": parsed_authority.session_authority_sha256,
        },
        "mission_id": session_document["mission_id"],
        "work_item_id": session_document["work_item_id"],
        "session": {
            "session_id": session.session_id,
            "session_sha256": session.session_sha256,
        },
        "credential": {
            "credential_reference_id": session_document["credential_reference_id"],
            "credential_sha256": session_document["credential_sha256"],
        },
        "decision_owner": _assertion_binding(decision_owner, "decision_owner"),
        "reason_code": reason_code,
        "revoked_at": revoked,
        "revocation_status": "pending_control_authentication",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": SESSION_REVOCATION_DOMAIN, "session_revocation": body}
    )
    return CollaborationExecutionSessionRevocation.from_dict(
        {
            **body,
            "revocation_id": "ESR-" + digest.removeprefix("sha256:")[:32].upper(),
            "revocation_sha256": digest,
        }
    )


def load_collaboration_execution_session_authority(
    path: str | Path,
) -> CollaborationExecutionSessionAuthority:
    return CollaborationExecutionSessionAuthority.from_dict(
        _load_document(path, "execution session authority")
    )


def load_collaboration_execution_session_revocation(
    path: str | Path,
) -> CollaborationExecutionSessionRevocation:
    return CollaborationExecutionSessionRevocation.from_dict(
        _load_document(path, "execution session revocation")
    )


__all__ = [
    "CollaborationExecutionSessionAuthority",
    "CollaborationExecutionSessionRevocation",
    "build_collaboration_execution_session_revocation",
    "build_handoff_collaboration_execution_session_authority",
    "build_initial_collaboration_execution_session_authority",
    "load_collaboration_execution_session_authority",
    "load_collaboration_execution_session_revocation",
]
