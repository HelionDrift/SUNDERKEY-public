"""Signed authentication for external execution transfer documents."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_transfer import (
    CollaborationExecutionAcknowledgement,
    CollaborationExecutionTransferRequest,
    collaboration_execution_acknowledgement_selection_sha256,
    collaboration_execution_transfer_request_selection_sha256,
    validate_collaboration_execution_acknowledgement,
    validate_collaboration_execution_acknowledgement_set,
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
from .qualification import _canonical_json, _canonical_sha256

REQUEST_AUTHENTICATION_DOMAIN = (
    "sunderkey.collaboration-execution-transfer-request-authentication.v1"
)
ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN = (
    "sunderkey.collaboration-execution-acknowledgement-authentication.v1"
)
_PROOF_KEY = secrets.token_bytes(32)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (TypeError, ValueError) as exc:
        raise CollaborationPlanError("Execution transfer timestamp is invalid") from exc


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _request_authentication_body(
    request: CollaborationExecutionTransferRequest,
    requester: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transfer_request": request.to_dict(),
        "control_plane_requester": _principal_document(requester),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_control_plane_request",
        "runtime_effect": "none",
    }


def _acknowledgement_authentication_body(
    acknowledgement: CollaborationExecutionAcknowledgement,
    request_authentication_id: str,
    request_authentication_sha256: str,
    acknowledger: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "acknowledgement": acknowledgement.to_dict(),
        "request_authentication": {
            "authentication_id": request_authentication_id,
            "authentication_sha256": request_authentication_sha256,
        },
        "external_acknowledger": _principal_document(acknowledger),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_external_acknowledgement",
        "runtime_effect": "none",
    }


def _authentication_proof(domain: str, document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (domain + "\x00" + _canonical_json(document)).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionTransferRequest:
    """Ephemeral proof that the control-plane transfer request authenticated."""

    authentication_id: str
    authentication_sha256: str
    request: CollaborationExecutionTransferRequest
    control_plane_requester: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _request_authentication_body(
            self.request,
            self.control_plane_requester,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": REQUEST_AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "ERA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated execution transfer request identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(REQUEST_AUTHENTICATION_DOMAIN, document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutionTransferRequest can be created only "
                "by authenticate_collaboration_execution_transfer_request"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _request_authentication_body(
            self.request,
            self.control_plane_requester,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionAcknowledgement:
    """Ephemeral proof that one external acknowledgement authenticated."""

    authentication_id: str
    authentication_sha256: str
    acknowledgement: CollaborationExecutionAcknowledgement
    request_authentication_id: str
    request_authentication_sha256: str
    external_acknowledger: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _acknowledgement_authentication_body(
            self.acknowledgement,
            self.request_authentication_id,
            self.request_authentication_sha256,
            self.external_acknowledger,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "EAA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated execution acknowledgement identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN, document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutionAcknowledgement can be created only "
                "by authenticate_collaboration_execution_acknowledgement"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _acknowledgement_authentication_body(
            self.acknowledgement,
            self.request_authentication_id,
            self.request_authentication_sha256,
            self.external_acknowledger,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


@dataclass(frozen=True)
class VerifiedAuthenticatedCollaborationExecutionAcknowledgementSet:
    request_authentication_id: str
    acknowledgement_authentication_ids: tuple[str, ...]
    completed_at: str


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


def _validated_request_authentication(
    authenticated: AuthenticatedCollaborationExecutionTransferRequest,
) -> AuthenticatedCollaborationExecutionTransferRequest:
    if not isinstance(authenticated, AuthenticatedCollaborationExecutionTransferRequest):
        raise TypeError("authenticated_request must be an authenticated request")
    return AuthenticatedCollaborationExecutionTransferRequest(
        authentication_id=authenticated.authentication_id,
        authentication_sha256=authenticated.authentication_sha256,
        request=authenticated.request,
        control_plane_requester=authenticated.control_plane_requester,
        authenticated_at=authenticated.authenticated_at,
        _proof=authenticated._proof,
    )


def _validated_acknowledgement_authentication(
    authenticated: AuthenticatedCollaborationExecutionAcknowledgement,
) -> AuthenticatedCollaborationExecutionAcknowledgement:
    if not isinstance(authenticated, AuthenticatedCollaborationExecutionAcknowledgement):
        raise TypeError("authenticated acknowledgement is invalid")
    return AuthenticatedCollaborationExecutionAcknowledgement(
        authentication_id=authenticated.authentication_id,
        authentication_sha256=authenticated.authentication_sha256,
        acknowledgement=authenticated.acknowledgement,
        request_authentication_id=authenticated.request_authentication_id,
        request_authentication_sha256=authenticated.request_authentication_sha256,
        external_acknowledger=authenticated.external_acknowledger,
        authenticated_at=authenticated.authenticated_at,
        _proof=authenticated._proof,
    )


def validate_authenticated_collaboration_execution_transfer_request(
    authenticated: AuthenticatedCollaborationExecutionTransferRequest,
) -> AuthenticatedCollaborationExecutionTransferRequest:
    """Revalidate one process-local request authentication proof."""

    return _validated_request_authentication(authenticated)


def validate_authenticated_collaboration_execution_acknowledgement(
    authenticated: AuthenticatedCollaborationExecutionAcknowledgement,
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    session: CollaborationFencedWorkerSession,
) -> AuthenticatedCollaborationExecutionAcknowledgement:
    """Revalidate one acknowledgement proof and its exact request and session."""

    request_authentication = _validated_request_authentication(authenticated_request)
    parsed = _validated_acknowledgement_authentication(authenticated)
    if (
        parsed.request_authentication_id != request_authentication.authentication_id
        or parsed.request_authentication_sha256 != request_authentication.authentication_sha256
    ):
        raise CollaborationPlanError("Acknowledgement request authentication is stale")
    validate_collaboration_execution_acknowledgement(
        parsed.acknowledgement,
        request=request_authentication.request,
        session=session,
    )
    return parsed


def authenticate_collaboration_execution_transfer_request(
    request: CollaborationExecutionTransferRequest,
    *,
    requester_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    requester_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutionTransferRequest:
    """Authenticate one exact transfer request without consuming its assertion."""

    parsed = CollaborationExecutionTransferRequest.from_dict(request.to_dict())
    assertion = PrincipalAssertion.from_dict(requester_assertion.to_dict())
    document = parsed.to_dict()
    binding = document["control_plane_requester"]
    _assertion_binding_matches(assertion, binding, label="Control-plane requester")
    now = _clock_value(clock)
    if now < _timestamp(document["requested_at"]):
        raise PrincipalAuthenticationError("Execution transfer request is not yet valid")
    if now > _timestamp(document["acknowledgement_deadline"]):
        raise PrincipalAuthenticationError("Execution transfer request deadline has passed")
    operation = PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE
    intent = {
        "mission_id": document["mission_id"],
        "principal_profile_id": binding["profile_id"],
        "request_selection_sha256": (
            collaboration_execution_transfer_request_selection_sha256(parsed)
        ),
    }
    requester = verify_principal_assertion(
        assertion,
        verified_policy,
        requester_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=document["mission_id"],
        expected_operation=operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(operation, intent),
        clock=lambda: now,
    )
    if requester.profile_id != binding["profile_id"]:
        raise PrincipalAuthenticationError("Authenticated control-plane requester does not match")
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _request_authentication_body(parsed, requester, authenticated_at)
    digest = _canonical_sha256({"domain": REQUEST_AUTHENTICATION_DOMAIN, "authentication": body})
    authentication_id = "ERA-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutionTransferRequest(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        request=parsed,
        control_plane_requester=requester,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(REQUEST_AUTHENTICATION_DOMAIN, proof_document),
    )


def authenticate_collaboration_execution_acknowledgement(
    acknowledgement: CollaborationExecutionAcknowledgement,
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    session: CollaborationFencedWorkerSession,
    acknowledger_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    acknowledger_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutionAcknowledgement:
    """Authenticate one exact external acknowledgement without persistence."""

    request_authentication = _validated_request_authentication(authenticated_request)
    request = request_authentication.request
    parsed = validate_collaboration_execution_acknowledgement(
        acknowledgement,
        request=request,
        session=session,
    )
    assertion = PrincipalAssertion.from_dict(acknowledger_assertion.to_dict())
    document = parsed.to_dict()
    request_document = request.to_dict()
    binding = document["external_acknowledger"]
    _assertion_binding_matches(assertion, binding, label="External acknowledger")
    if binding["profile_id"] != document["session"]["worker_principal_id"]:
        raise PrincipalAuthenticationError(
            "External acknowledger must be the fenced worker principal"
        )
    if binding["profile_id"] == request_authentication.control_plane_requester.profile_id:
        raise PrincipalAuthenticationError(
            "External acknowledger must differ from the control-plane requester"
        )
    now = _clock_value(clock)
    if now < _timestamp(document["acknowledged_at"]):
        raise PrincipalAuthenticationError("Execution acknowledgement is not yet valid")
    if now > _timestamp(request_document["acknowledgement_deadline"]):
        raise PrincipalAuthenticationError("Execution acknowledgement deadline has passed")
    operation = PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE
    intent = {
        "acknowledgement_selection_sha256": (
            collaboration_execution_acknowledgement_selection_sha256(parsed)
        ),
        "mission_id": request_document["mission_id"],
        "principal_profile_id": binding["profile_id"],
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
    }
    acknowledger = verify_principal_assertion(
        assertion,
        verified_policy,
        acknowledger_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=request_document["mission_id"],
        expected_operation=operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(operation, intent),
        clock=lambda: now,
    )
    if acknowledger.profile_id != binding["profile_id"]:
        raise PrincipalAuthenticationError("Authenticated external acknowledger does not match")
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _acknowledgement_authentication_body(
        parsed,
        request_authentication.authentication_id,
        request_authentication.authentication_sha256,
        acknowledger,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "EAA-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutionAcknowledgement(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        acknowledgement=parsed,
        request_authentication_id=request_authentication.authentication_id,
        request_authentication_sha256=request_authentication.authentication_sha256,
        external_acknowledger=acknowledger,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(
            ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN,
            proof_document,
        ),
    )


def validate_authenticated_collaboration_execution_acknowledgement_set(
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
) -> VerifiedAuthenticatedCollaborationExecutionAcknowledgementSet:
    """Validate complete authentication custody for every required acknowledgement."""

    request_authentication = _validated_request_authentication(authenticated_request)
    if not isinstance(acknowledgements, list):
        raise CollaborationPlanError("Authenticated acknowledgements must be a list")
    parsed: list[AuthenticatedCollaborationExecutionAcknowledgement] = []
    contract_entries: list[
        tuple[CollaborationExecutionAcknowledgement, CollaborationFencedWorkerSession]
    ] = []
    for item in acknowledgements:
        if not isinstance(item, tuple) or len(item) != 2:
            raise CollaborationPlanError("Authenticated acknowledgement entry is invalid")
        authentication = _validated_acknowledgement_authentication(item[0])
        if (
            authentication.request_authentication_id != request_authentication.authentication_id
            or authentication.request_authentication_sha256
            != request_authentication.authentication_sha256
        ):
            raise CollaborationPlanError("Acknowledgement request authentication is stale")
        parsed.append(authentication)
        contract_entries.append((authentication.acknowledgement, item[1]))
    verified = validate_collaboration_execution_acknowledgement_set(
        request_authentication.request,
        contract_entries,
    )
    return VerifiedAuthenticatedCollaborationExecutionAcknowledgementSet(
        request_authentication_id=request_authentication.authentication_id,
        acknowledgement_authentication_ids=tuple(item.authentication_id for item in parsed),
        completed_at=verified.completed_at,
    )


__all__ = [
    "AuthenticatedCollaborationExecutionAcknowledgement",
    "AuthenticatedCollaborationExecutionTransferRequest",
    "VerifiedAuthenticatedCollaborationExecutionAcknowledgementSet",
    "authenticate_collaboration_execution_acknowledgement",
    "authenticate_collaboration_execution_transfer_request",
    "validate_authenticated_collaboration_execution_acknowledgement",
    "validate_authenticated_collaboration_execution_acknowledgement_set",
    "validate_authenticated_collaboration_execution_transfer_request",
]
