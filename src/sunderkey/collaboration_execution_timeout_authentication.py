"""Independent Control authentication for fail-closed execution timeouts."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_timeout import (
    CollaborationExecutionTimeoutResolution,
    collaboration_execution_timeout_resolution_selection_sha256,
    validate_collaboration_execution_timeout_resolution,
)
from .collaboration_execution_transfer_authentication import (
    AuthenticatedCollaborationExecutionAcknowledgement,
    AuthenticatedCollaborationExecutionTransferRequest,
    validate_authenticated_collaboration_execution_acknowledgement,
    validate_authenticated_collaboration_execution_transfer_request,
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

AUTHENTICATION_DOMAIN = "sunderkey.collaboration-execution-timeout-authentication.v1"
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
        raise PrincipalAuthenticationError("Execution timeout timestamp is invalid") from exc


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _authentication_body(
    resolution: CollaborationExecutionTimeoutResolution,
    independent_control: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "timeout_resolution": resolution.to_dict(),
        "independent_control": _principal_document(independent_control),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_fail_closed_timeout",
        "runtime_effect": "none",
    }


def _authentication_proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        _canonical_json(document).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionTimeoutResolution:
    """Ephemeral proof that independent Control authenticated one timeout."""

    authentication_id: str
    authentication_sha256: str
    resolution: CollaborationExecutionTimeoutResolution
    independent_control: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.resolution,
            self.independent_control,
            self.authenticated_at,
        )
        digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
        expected_id = "ETA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated execution timeout identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutionTimeoutResolution can be created "
                "only by authenticate_collaboration_execution_timeout_resolution"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.resolution,
            self.independent_control,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def validate_authenticated_collaboration_execution_timeout_resolution(
    authenticated: AuthenticatedCollaborationExecutionTimeoutResolution,
) -> AuthenticatedCollaborationExecutionTimeoutResolution:
    """Revalidate one process-local timeout authentication proof."""

    if not isinstance(authenticated, AuthenticatedCollaborationExecutionTimeoutResolution):
        raise TypeError("authenticated timeout resolution is invalid")
    return AuthenticatedCollaborationExecutionTimeoutResolution(
        authentication_id=authenticated.authentication_id,
        authentication_sha256=authenticated.authentication_sha256,
        resolution=authenticated.resolution,
        independent_control=authenticated.independent_control,
        authenticated_at=authenticated.authenticated_at,
        _proof=authenticated._proof,
    )


def authenticate_collaboration_execution_timeout_resolution(
    resolution: CollaborationExecutionTimeoutResolution,
    *,
    authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
    observed_acknowledgements: list[
        tuple[
            AuthenticatedCollaborationExecutionAcknowledgement,
            CollaborationFencedWorkerSession,
        ]
    ],
    independent_control_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    independent_control_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutionTimeoutResolution:
    """Authenticate one fail-closed timeout without persistence or runtime effect."""

    request_authentication = validate_authenticated_collaboration_execution_transfer_request(
        authenticated_request
    )
    parsed = validate_collaboration_execution_timeout_resolution(
        resolution,
        authenticated_request=request_authentication,
        observed_acknowledgements=observed_acknowledgements,
    )
    assertion = PrincipalAssertion.from_dict(independent_control_assertion.to_dict())
    document = parsed.to_dict()
    binding = document["decision_owner"]
    if (
        assertion.profile_id != binding["profile_id"]
        or assertion.assertion_id != binding["assertion_id"]
        or assertion.content_sha256 != binding["assertion_sha256"]
    ):
        raise PrincipalAuthenticationError(
            "Execution timeout Control assertion binding does not match"
        )
    if isinstance(expected_control_profile_ids, (str, bytes)):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    control_profiles = frozenset(expected_control_profile_ids)
    if not control_profiles or not all(
        isinstance(profile_id, str) for profile_id in control_profiles
    ):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    control_profile_id = binding["profile_id"]
    if control_profile_id not in control_profiles:
        raise PrincipalAuthenticationError(
            "Execution timeout decision owner is not an independent Control profile"
        )
    participant_profiles = {request_authentication.control_plane_requester.profile_id}
    participant_policies = {request_authentication.control_plane_requester.policy_sha256}
    for authentication, session in observed_acknowledgements:
        acknowledgement = validate_authenticated_collaboration_execution_acknowledgement(
            authentication,
            authenticated_request=request_authentication,
            session=session,
        )
        participant_profiles.add(acknowledgement.external_acknowledger.profile_id)
        participant_policies.add(acknowledgement.external_acknowledger.policy_sha256)
    if control_profile_id in participant_profiles:
        raise PrincipalAuthenticationError(
            "Execution timeout Control must be distinct from every execution participant"
        )
    if participant_policies != {verified_policy.policy_sha256}:
        raise PrincipalAuthenticationError(
            "Execution timeout participants use a different trust policy"
        )
    now = _clock_value(clock)
    if now < _timestamp(document["resolved_at"]):
        raise PrincipalAuthenticationError("Execution timeout resolution is not yet valid")
    operation = PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE
    intent = {
        "mission_id": document["mission_id"],
        "principal_profile_id": control_profile_id,
        "resolution_selection_sha256": (
            collaboration_execution_timeout_resolution_selection_sha256(parsed)
        ),
    }
    independent_control = verify_principal_assertion(
        assertion,
        verified_policy,
        independent_control_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=document["mission_id"],
        expected_operation=operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(operation, intent),
        clock=lambda: now,
    )
    if independent_control.profile_id != control_profile_id:
        raise PrincipalAuthenticationError("Authenticated execution timeout Control does not match")
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(parsed, independent_control, authenticated_at)
    digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
    authentication_id = "ETA-" + digest.removeprefix("sha256:")[:32].upper()
    proof_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutionTimeoutResolution(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        resolution=parsed,
        independent_control=independent_control,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(proof_document),
    )


__all__ = [
    "AuthenticatedCollaborationExecutionTimeoutResolution",
    "authenticate_collaboration_execution_timeout_resolution",
    "validate_authenticated_collaboration_execution_timeout_resolution",
]
