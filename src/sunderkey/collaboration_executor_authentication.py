"""Worker-principal authentication for provider executor acknowledgements."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorAcknowledgement,
    CollaborationExecutorDispatchEnvelope,
    validate_collaboration_executor_acknowledgement,
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
AUTHENTICATION_DOMAIN = "sunderkey.collaboration-executor-ack-authentication.v1"
SELECTION_DOMAIN = "sunderkey.collaboration-executor-ack-selection.v1"
_PROOF_KEY = secrets.token_bytes(32)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


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


def collaboration_executor_acknowledgement_selection_sha256(
    acknowledgement: CollaborationExecutorAcknowledgement,
) -> str:
    """Bind the exact provider report selected for worker authentication."""

    parsed = CollaborationExecutorAcknowledgement.from_dict(
        acknowledgement.to_dict()
    )
    return _canonical_sha256(
        {
            "domain": SELECTION_DOMAIN,
            "acknowledgement": parsed.to_dict(),
        }
    )


def _authentication_body(
    acknowledgement: CollaborationExecutorAcknowledgement,
    worker_attestor: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "acknowledgement": acknowledgement.to_dict(),
        "worker_attestor": _principal_document(worker_attestor),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_worker_principal",
        "external_effect_status": "authenticated_report_unverified_effect",
        "runtime_effect": "none",
    }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutorAcknowledgement:
    """An exact provider report authenticated by its fenced worker principal."""

    authentication_id: str
    authentication_sha256: str
    acknowledgement: CollaborationExecutorAcknowledgement
    worker_attestor: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.acknowledgement,
            self.worker_attestor,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "EAX-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated executor acknowledgement identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutorAcknowledgement can be created "
                "only by authenticate_collaboration_executor_acknowledgement"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.acknowledgement,
            self.worker_attestor,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }

    def _proof_is_valid(self) -> bool:
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            _proof(self.to_dict()),
        )


def authenticate_collaboration_executor_acknowledgement(
    dispatch: CollaborationExecutorDispatchEnvelope,
    acknowledgement: CollaborationExecutorAcknowledgement,
    *,
    worker_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    worker_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationExecutorAcknowledgement:
    """Authenticate the report signer while leaving external effect unverified."""

    parsed_dispatch = CollaborationExecutorDispatchEnvelope.from_dict(
        dispatch.to_dict()
    )
    parsed_acknowledgement = validate_collaboration_executor_acknowledgement(
        parsed_dispatch,
        acknowledgement,
    )
    dispatch_document = parsed_dispatch.to_dict()
    acknowledgement_document = parsed_acknowledgement.to_dict()
    worker_profile_id = dispatch_document["worker"]["worker_principal_id"]
    if (
        worker_assertion.profile_id != worker_profile_id
        or acknowledgement_document["worker"]["worker_principal_id"]
        != worker_profile_id
    ):
        raise PrincipalAuthenticationError(
            "Executor acknowledgement worker principal does not match"
        )
    now = _clock_value(clock)
    acknowledged_at = parse_timestamp(
        acknowledgement_document["acknowledged_at"],
        "acknowledged_at",
    )
    dispatch_expires = parse_timestamp(
        dispatch_document["expires_at"],
        "expires_at",
    )
    if now < acknowledged_at or now > dispatch_expires:
        raise PrincipalAuthenticationError(
            "Executor acknowledgement authentication is outside dispatch time"
        )
    assertion_issued_at = parse_timestamp(
        worker_assertion.issued_at,
        "worker_assertion.issued_at",
    )
    if assertion_issued_at < acknowledged_at:
        raise PrincipalAuthenticationError(
            "Executor acknowledgement assertion precedes the provider report"
        )
    selection_sha256 = collaboration_executor_acknowledgement_selection_sha256(
        parsed_acknowledgement
    )
    intent = {
        "acknowledgement_selection_sha256": selection_sha256,
        "dispatch_sha256": parsed_dispatch.dispatch_sha256,
        "mission_id": dispatch_document["mission"]["mission_id"],
        "principal_profile_id": worker_profile_id,
    }
    expected_operation = (
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY
        if dispatch_document["operation"] in SAFETY_REDUCING_OPERATIONS
        else PrincipalOperation.EXECUTOR_ACKNOWLEDGE
    )
    worker = verify_principal_assertion(
        worker_assertion,
        verified_policy,
        worker_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=dispatch_document["mission"]["mission_id"],
        expected_operation=expected_operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            expected_operation,
            intent,
        ),
        clock=lambda: now,
    )
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(
        parsed_acknowledgement,
        worker,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "EAX-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutorAcknowledgement(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        acknowledgement=parsed_acknowledgement,
        worker_attestor=worker,
        authenticated_at=authenticated_at,
        _proof=_proof(document),
    )


__all__ = [
    "AuthenticatedCollaborationExecutorAcknowledgement",
    "authenticate_collaboration_executor_acknowledgement",
    "collaboration_executor_acknowledgement_selection_sha256",
]
