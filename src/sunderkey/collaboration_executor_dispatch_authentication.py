"""Control-plane authentication for provider-neutral executor dispatches."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorDispatchEnvelope,
)
from .errors import PrincipalAuthenticationError
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
from .store import parse_timestamp

SCHEMA_VERSION = 1
SELECTION_DOMAIN = "sunderkey.collaboration-executor-dispatch-selection.v1"
AUTHENTICATION_DOMAIN = "sunderkey.collaboration-executor-dispatch-authentication.v1"
_PROOF_KEY = secrets.token_bytes(32)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _profile_set(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise PrincipalAuthenticationError("Expected dispatch authorizers are invalid")
    profiles = frozenset(values)
    if not profiles or not all(isinstance(item, str) and len(item) >= 3 for item in profiles):
        raise PrincipalAuthenticationError("Expected dispatch authorizers are invalid")
    return profiles


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (AUTHENTICATION_DOMAIN + "\x00" + _canonical_json(document)).encode(),
        "sha256",
    ).digest()


def collaboration_executor_dispatch_selection_sha256(
    dispatch: CollaborationExecutorDispatchEnvelope,
) -> str:
    """Hash the exact dispatch selected for control-plane authorization."""

    parsed = CollaborationExecutorDispatchEnvelope.from_dict(dispatch.to_dict())
    return _canonical_sha256(
        {"domain": SELECTION_DOMAIN, "dispatch": parsed.to_dict()}
    )


def _authentication_body(
    dispatch: CollaborationExecutorDispatchEnvelope,
    control_plane_authorizer: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "dispatch": dispatch.to_dict(),
        "control_plane_authorizer": _principal_document(control_plane_authorizer),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_control_plane_authorizer",
        "runtime_effect": "none",
    }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutorDispatch:
    """One exact dispatch authenticated by an allowed non-worker authority."""

    authentication_id: str
    authentication_sha256: str
    dispatch: CollaborationExecutorDispatchEnvelope
    control_plane_authorizer: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.dispatch,
            self.control_plane_authorizer,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "EDA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated executor dispatch identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutorDispatch can be created only by "
                "authenticate_collaboration_executor_dispatch"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.dispatch,
            self.control_plane_authorizer,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def authenticate_collaboration_executor_dispatch(
    dispatch: CollaborationExecutorDispatchEnvelope,
    *,
    authorizer_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    authorizer_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_authorizer_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutorDispatch:
    """Authenticate ordinary or safety dispatch under separate operations."""

    parsed = CollaborationExecutorDispatchEnvelope.from_dict(dispatch.to_dict())
    document = parsed.to_dict()
    authorizers = _profile_set(expected_authorizer_profile_ids)
    authorizer_profile_id = authorizer_assertion.profile_id
    if authorizer_profile_id not in authorizers:
        raise PrincipalAuthenticationError("Executor dispatch authorizer is not allowed")
    if authorizer_profile_id == document["worker"]["worker_principal_id"]:
        raise PrincipalAuthenticationError("Executor worker cannot authorize its dispatch")
    now = _clock_value(clock)
    issued_at = parse_timestamp(document["issued_at"], "issued_at")
    expires_at = parse_timestamp(document["expires_at"], "expires_at")
    if now < issued_at or now >= expires_at:
        raise PrincipalAuthenticationError(
            "Executor dispatch authentication is outside dispatch time"
        )
    safety_reduction = document["operation"] in SAFETY_REDUCING_OPERATIONS
    expected_operation = (
        PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE
        if safety_reduction
        else PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE
    )
    assertion_issued_at = parse_timestamp(
        authorizer_assertion.issued_at,
        "authorizer_assertion.issued_at",
    )
    if not safety_reduction and assertion_issued_at < issued_at:
        raise PrincipalAuthenticationError(
            "Executor dispatch assertion precedes ordinary dispatch issuance"
        )
    intent = {
        "dispatch_selection_sha256": (
            collaboration_executor_dispatch_selection_sha256(parsed)
        ),
        "mission_id": document["mission"]["mission_id"],
        "principal_profile_id": authorizer_profile_id,
    }
    authorizer = verify_principal_assertion(
        authorizer_assertion,
        verified_policy,
        authorizer_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=document["mission"]["mission_id"],
        expected_operation=expected_operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            expected_operation,
            intent,
        ),
        clock=lambda: now,
    )
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(parsed, authorizer, authenticated_at)
    digest = _canonical_sha256(
        {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "EDA-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutorDispatch(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        dispatch=parsed,
        control_plane_authorizer=authorizer,
        authenticated_at=authenticated_at,
        _proof=_proof(proof_document),
    )


__all__ = [
    "AuthenticatedCollaborationExecutorDispatch",
    "authenticate_collaboration_executor_dispatch",
    "collaboration_executor_dispatch_selection_sha256",
]
