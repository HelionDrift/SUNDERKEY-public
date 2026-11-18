"""Authentication contracts for fenced session activation and revocation."""

from __future__ import annotations

import hmac
import json
import re
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
    CollaborationExecutionSessionRevocation,
)
from .errors import CollaborationPlanError, PrincipalAuthenticationError
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    VerifiedScopeGrant,
    VerifiedTrustPolicy,
    compute_operation_intent_hash,
    verify_principal_assertion,
)
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
ACTIVATION_REQUEST_DOMAIN = "sunderkey.execution-session-activation-request.v1"
ACTIVATION_AUTHENTICATION_DOMAIN = (
    "sunderkey.execution-session-activation-authentication.v1"
)
REVOCATION_AUTHENTICATION_DOMAIN = (
    "sunderkey.execution-session-revocation-authentication.v1"
)
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
_PROOF_KEY = secrets.token_bytes(32)


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


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _identifier_binding(
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
    profile_id = value.get("profile_id")
    assertion_id = value.get("assertion_id")
    if not isinstance(profile_id, str) or len(profile_id) < 3:
        raise CollaborationPlanError(f"{label}.profile_id is invalid")
    if (
        not isinstance(assertion_id, str)
        or re.fullmatch(r"PAS-[0-9A-F]{32}", assertion_id) is None
    ):
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    return {
        "profile_id": profile_id,
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


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _proof(domain: str, document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (domain + "\x00" + _canonical_json(document)).encode(),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class CollaborationExecutionSessionActivationRequest:
    """One inert request for dual-principal fenced-session activation."""

    activation_request_id: str
    activation_request_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutionSessionActivationRequest:
        value = _mapping(raw, "execution session activation request")
        fields = {
            "schema_version",
            "activation_request_id",
            "activation_request_sha256",
            "session_authority",
            "mission_id",
            "work_item_id",
            "session",
            "credential",
            "control_plane_requester",
            "worker_acceptor",
            "requested_at",
            "request_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "execution session activation request")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Execution session activation schema is invalid")
        request_id = value.get("activation_request_id")
        request_sha256 = value.get("activation_request_sha256")
        if (
            not isinstance(request_id, str)
            or re.fullmatch(r"EAR-[0-9A-F]{32}", request_id) is None
        ):
            raise CollaborationPlanError("Execution session activation identity is invalid")
        _sha256(request_sha256, "activation_request_sha256")
        authority = _identifier_binding(
            value.get("session_authority"),
            "session_authority",
            id_field="session_authority_id",
            id_pattern=r"ESA-[0-9A-F]{32}",
        )
        session = _identifier_binding(
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
        credential_reference_id = credential.get("credential_reference_id")
        if not isinstance(credential_reference_id, str) or len(credential_reference_id) < 3:
            raise CollaborationPlanError("Execution session credential reference is invalid")
        parsed_credential = {
            "credential_reference_id": credential_reference_id,
            "credential_sha256": _sha256(
                credential.get("credential_sha256"),
                "credential.credential_sha256",
            ),
        }
        requester = _assertion_binding(
            value.get("control_plane_requester"),
            "control_plane_requester",
        )
        worker = _assertion_binding(value.get("worker_acceptor"), "worker_acceptor")
        mission_id = value.get("mission_id")
        work_item_id = value.get("work_item_id")
        if not isinstance(mission_id, str) or len(mission_id) < 3:
            raise CollaborationPlanError("Execution session activation mission is invalid")
        if not isinstance(work_item_id, str) or len(work_item_id) < 3:
            raise CollaborationPlanError("Execution session activation work item is invalid")
        requested_at = _timestamp(value.get("requested_at"), "requested_at")
        if (
            requester["profile_id"] == worker["profile_id"]
            or value.get("request_status") != "pending_dual_authentication"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Execution session activation request is invalid")
        body = {
            "schema_version": SCHEMA_VERSION,
            "session_authority": authority,
            "mission_id": mission_id,
            "work_item_id": work_item_id,
            "session": session,
            "credential": parsed_credential,
            "control_plane_requester": requester,
            "worker_acceptor": worker,
            "requested_at": requested_at,
            "request_status": "pending_dual_authentication",
            "runtime_effect": "none",
        }
        digest = _canonical_sha256(
            {"domain": ACTIVATION_REQUEST_DOMAIN, "activation_request": body}
        )
        expected_id = "EAR-" + digest.removeprefix("sha256:")[:32].upper()
        if request_sha256 != digest or request_id != expected_id:
            raise CollaborationPlanError("Execution session activation hash is invalid")
        return cls(
            request_id,
            request_sha256,
            _canonical_json(
                {
                    **body,
                    "activation_request_id": request_id,
                    "activation_request_sha256": request_sha256,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Execution session activation request is invalid")
        return value


def collaboration_execution_session_activation_selection_sha256(
    request: CollaborationExecutionSessionActivationRequest,
) -> str:
    parsed = CollaborationExecutionSessionActivationRequest.from_dict(request.to_dict())
    document = parsed.to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key
        not in {
            "activation_request_id",
            "activation_request_sha256",
            "control_plane_requester",
            "worker_acceptor",
        }
    }
    selection["control_plane_profile_id"] = document["control_plane_requester"][
        "profile_id"
    ]
    selection["worker_profile_id"] = document["worker_acceptor"]["profile_id"]
    return _canonical_sha256(
        {"domain": ACTIVATION_REQUEST_DOMAIN, "selection": selection}
    )


def collaboration_execution_session_revocation_selection_sha256(
    revocation: CollaborationExecutionSessionRevocation,
) -> str:
    parsed = CollaborationExecutionSessionRevocation.from_dict(revocation.to_dict())
    document = parsed.to_dict()
    selection = {
        key: item
        for key, item in document.items()
        if key not in {"revocation_id", "revocation_sha256", "decision_owner"}
    }
    selection["decision_owner_profile_id"] = document["decision_owner"]["profile_id"]
    return _canonical_sha256(
        {"domain": REVOCATION_AUTHENTICATION_DOMAIN, "selection": selection}
    )


def build_collaboration_execution_session_activation_request(
    authority: CollaborationExecutionSessionAuthority,
    *,
    control_plane_requester: dict[str, str],
    worker_acceptor: dict[str, str],
    requested_at: str,
) -> CollaborationExecutionSessionActivationRequest:
    parsed = CollaborationExecutionSessionAuthority.from_dict(authority.to_dict())
    authority_document = parsed.to_dict()
    session = authority_document["session"]
    requester = _assertion_binding(control_plane_requester, "control_plane_requester")
    worker = _assertion_binding(worker_acceptor, "worker_acceptor")
    requested = _timestamp(requested_at, "requested_at")
    if not (
        _timestamp_value(authority_document["effective_at"])
        <= _timestamp_value(requested)
        < _timestamp_value(authority_document["expires_at"])
    ):
        raise CollaborationPlanError("Execution session activation is outside authority")
    if (
        requester["profile_id"] == worker["profile_id"]
        or worker["profile_id"] != session["worker_principal_id"]
    ):
        raise CollaborationPlanError("Execution session activation roles are invalid")
    body = {
        "schema_version": SCHEMA_VERSION,
        "session_authority": {
            "session_authority_id": parsed.session_authority_id,
            "session_authority_sha256": parsed.session_authority_sha256,
        },
        "mission_id": session["mission_id"],
        "work_item_id": session["work_item_id"],
        "session": {
            "session_id": session["session_id"],
            "session_sha256": session["session_sha256"],
        },
        "credential": {
            "credential_reference_id": session["credential_reference_id"],
            "credential_sha256": session["credential_sha256"],
        },
        "control_plane_requester": requester,
        "worker_acceptor": worker,
        "requested_at": requested,
        "request_status": "pending_dual_authentication",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": ACTIVATION_REQUEST_DOMAIN, "activation_request": body}
    )
    return CollaborationExecutionSessionActivationRequest.from_dict(
        {
            **body,
            "activation_request_id": (
                "EAR-" + digest.removeprefix("sha256:")[:32].upper()
            ),
            "activation_request_sha256": digest,
        }
    )


def _activation_authentication_body(
    request: CollaborationExecutionSessionActivationRequest,
    requester: VerifiedPrincipal,
    worker: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "activation_request": request.to_dict(),
        "control_plane_requester": _principal_document(requester),
        "worker_acceptor": _principal_document(worker),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_dual_principal",
        "runtime_effect": "none",
    }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionSessionActivation:
    authentication_id: str
    authentication_sha256: str
    request: CollaborationExecutionSessionActivationRequest
    control_plane_requester: VerifiedPrincipal
    worker_acceptor: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _activation_authentication_body(
            self.request,
            self.control_plane_requester,
            self.worker_acceptor,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": ACTIVATION_AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "EAS-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated execution session activation identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(ACTIVATION_AUTHENTICATION_DOMAIN, document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutionSessionActivation can be created "
                "only by authenticate_collaboration_execution_session_activation"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _activation_authentication_body(
            self.request,
            self.control_plane_requester,
            self.worker_acceptor,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def _assertion_binding_matches(
    assertion: PrincipalAssertion,
    binding: dict[str, str],
    *,
    label: str,
) -> None:
    if (
        assertion.profile_id != binding["profile_id"]
        or assertion.assertion_id != binding["assertion_id"]
        or assertion.content_sha256 != binding["assertion_sha256"]
    ):
        raise PrincipalAuthenticationError(f"{label} assertion binding does not match")


def _profile_set(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise PrincipalAuthenticationError(f"{label} profiles are invalid")
    profiles = frozenset(values)
    if not profiles or not all(isinstance(item, str) and len(item) >= 3 for item in profiles):
        raise PrincipalAuthenticationError(f"{label} profiles are invalid")
    return profiles


def authenticate_collaboration_execution_session_activation(
    request: CollaborationExecutionSessionActivationRequest,
    *,
    authority: CollaborationExecutionSessionAuthority,
    control_plane_assertion: PrincipalAssertion,
    worker_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    control_plane_scope: VerifiedScopeGrant,
    worker_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_plane_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutionSessionActivation:
    parsed_request = CollaborationExecutionSessionActivationRequest.from_dict(
        request.to_dict()
    )
    parsed_authority = CollaborationExecutionSessionAuthority.from_dict(
        authority.to_dict()
    )
    request_document = parsed_request.to_dict()
    authority_document = parsed_authority.to_dict()
    session = authority_document["session"]
    if (
        request_document["session_authority"]
        != {
            "session_authority_id": parsed_authority.session_authority_id,
            "session_authority_sha256": parsed_authority.session_authority_sha256,
        }
        or request_document["mission_id"] != session["mission_id"]
        or request_document["work_item_id"] != session["work_item_id"]
        or request_document["session"]
        != {
            "session_id": session["session_id"],
            "session_sha256": session["session_sha256"],
        }
        or request_document["credential"]
        != {
            "credential_reference_id": session["credential_reference_id"],
            "credential_sha256": session["credential_sha256"],
        }
    ):
        raise CollaborationPlanError("Execution session activation authority is stale")
    now = _clock_value(clock)
    if not (
        _timestamp_value(request_document["requested_at"])
        <= now
        < _timestamp_value(authority_document["expires_at"])
    ):
        raise PrincipalAuthenticationError(
            "Execution session activation is outside its validity window"
        )
    requester_binding = request_document["control_plane_requester"]
    worker_binding = request_document["worker_acceptor"]
    control_profiles = _profile_set(
        expected_control_plane_profile_ids,
        "Expected control-plane",
    )
    if requester_binding["profile_id"] not in control_profiles:
        raise PrincipalAuthenticationError(
            "Execution session requester is not an allowed control-plane profile"
        )
    if worker_binding["profile_id"] != session["worker_principal_id"]:
        raise PrincipalAuthenticationError("Execution session worker does not match")
    _assertion_binding_matches(
        control_plane_assertion,
        requester_binding,
        label="Control-plane requester",
    )
    _assertion_binding_matches(
        worker_assertion,
        worker_binding,
        label="Worker acceptor",
    )
    selection_sha256 = collaboration_execution_session_activation_selection_sha256(
        parsed_request
    )
    requester_intent = {
        "activation_selection_sha256": selection_sha256,
        "mission_id": session["mission_id"],
        "principal_profile_id": requester_binding["profile_id"],
    }
    worker_intent = {
        "activation_selection_sha256": selection_sha256,
        "mission_id": session["mission_id"],
        "principal_profile_id": worker_binding["profile_id"],
    }
    requester = verify_principal_assertion(
        control_plane_assertion,
        verified_policy,
        control_plane_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=session["mission_id"],
        expected_operation=PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
            requester_intent,
        ),
        clock=lambda: now,
    )
    worker = verify_principal_assertion(
        worker_assertion,
        verified_policy,
        worker_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=session["mission_id"],
        expected_operation=PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
            worker_intent,
        ),
        clock=lambda: now,
    )
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _activation_authentication_body(
        parsed_request,
        requester,
        worker,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": ACTIVATION_AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "EAS-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutionSessionActivation(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        request=parsed_request,
        control_plane_requester=requester,
        worker_acceptor=worker,
        authenticated_at=authenticated_at,
        _proof=_proof(ACTIVATION_AUTHENTICATION_DOMAIN, proof_document),
    )


def _revocation_authentication_body(
    revocation: CollaborationExecutionSessionRevocation,
    independent_control: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "session_revocation": revocation.to_dict(),
        "independent_control": _principal_document(independent_control),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_independent_control",
        "runtime_effect": "none",
    }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionSessionRevocation:
    authentication_id: str
    authentication_sha256: str
    revocation: CollaborationExecutionSessionRevocation
    independent_control: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _revocation_authentication_body(
            self.revocation,
            self.independent_control,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": REVOCATION_AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "ESV-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated execution session revocation identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(REVOCATION_AUTHENTICATION_DOMAIN, document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutionSessionRevocation can be created "
                "only by authenticate_collaboration_execution_session_revocation"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _revocation_authentication_body(
            self.revocation,
            self.independent_control,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def authenticate_collaboration_execution_session_revocation(
    revocation: CollaborationExecutionSessionRevocation,
    *,
    authority: CollaborationExecutionSessionAuthority,
    independent_control_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    independent_control_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutionSessionRevocation:
    parsed_revocation = CollaborationExecutionSessionRevocation.from_dict(
        revocation.to_dict()
    )
    parsed_authority = CollaborationExecutionSessionAuthority.from_dict(
        authority.to_dict()
    )
    document = parsed_revocation.to_dict()
    authority_document = parsed_authority.to_dict()
    session = authority_document["session"]
    if (
        document["session_authority"]
        != {
            "session_authority_id": parsed_authority.session_authority_id,
            "session_authority_sha256": parsed_authority.session_authority_sha256,
        }
        or document["mission_id"] != session["mission_id"]
        or document["work_item_id"] != session["work_item_id"]
        or document["session"]
        != {
            "session_id": session["session_id"],
            "session_sha256": session["session_sha256"],
        }
        or document["credential"]
        != {
            "credential_reference_id": session["credential_reference_id"],
            "credential_sha256": session["credential_sha256"],
        }
    ):
        raise CollaborationPlanError("Execution session revocation authority is stale")
    control_profiles = _profile_set(
        expected_control_profile_ids,
        "Expected independent Control",
    )
    control_binding = document["decision_owner"]
    if control_binding["profile_id"] not in control_profiles:
        raise PrincipalAuthenticationError(
            "Execution session revocation owner is not independent Control"
        )
    _assertion_binding_matches(
        independent_control_assertion,
        control_binding,
        label="Independent Control",
    )
    now = _clock_value(clock)
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    if document["revoked_at"] != authenticated_at:
        raise PrincipalAuthenticationError(
            "Execution session revocation time does not match authentication"
        )
    selection_sha256 = collaboration_execution_session_revocation_selection_sha256(
        parsed_revocation
    )
    intent = {
        "mission_id": session["mission_id"],
        "principal_profile_id": control_binding["profile_id"],
        "revocation_selection_sha256": selection_sha256,
    }
    control = verify_principal_assertion(
        independent_control_assertion,
        verified_policy,
        independent_control_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=session["mission_id"],
        expected_operation=PrincipalOperation.EXECUTION_SESSION_REVOKE,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            PrincipalOperation.EXECUTION_SESSION_REVOKE,
            intent,
        ),
        clock=lambda: now,
    )
    body = _revocation_authentication_body(
        parsed_revocation,
        control,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": REVOCATION_AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "ESV-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutionSessionRevocation(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        revocation=parsed_revocation,
        independent_control=control,
        authenticated_at=authenticated_at,
        _proof=_proof(REVOCATION_AUTHENTICATION_DOMAIN, proof_document),
    )


def load_collaboration_execution_session_activation_request(
    path: str | Path,
) -> CollaborationExecutionSessionActivationRequest:
    return CollaborationExecutionSessionActivationRequest.from_dict(
        _load_document(path, "execution session activation request")
    )


__all__ = [
    "AuthenticatedCollaborationExecutionSessionActivation",
    "AuthenticatedCollaborationExecutionSessionRevocation",
    "CollaborationExecutionSessionActivationRequest",
    "authenticate_collaboration_execution_session_activation",
    "authenticate_collaboration_execution_session_revocation",
    "build_collaboration_execution_session_activation_request",
    "collaboration_execution_session_activation_selection_sha256",
    "collaboration_execution_session_revocation_selection_sha256",
    "load_collaboration_execution_session_activation_request",
]
