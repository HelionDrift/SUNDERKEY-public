"""Three-principal authentication for ownership transition preflights."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_ownership_chain import CollaborationOwnershipChainEntry
from .collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflight,
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

AUTHENTICATION_DOMAIN = "sunderkey.collaboration-ownership-authentication.v1"
_PROOF_KEY = secrets.token_bytes(32)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _timestamp(value: str, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (AttributeError, TypeError, ValueError) as exc:
        raise PrincipalAuthenticationError(f"{label} is invalid") from exc


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _authentication_body(
    preflight: CollaborationOwnershipTransitionPreflight,
    current_owner: VerifiedPrincipal,
    proposed_owner: VerifiedPrincipal,
    independent_control: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "preflight": preflight.to_dict(),
        "current_owner": _principal_document(current_owner),
        "proposed_owner": _principal_document(proposed_owner),
        "independent_control": _principal_document(independent_control),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_three_party",
        "runtime_effect": "none",
    }


def _authentication_proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        _canonical_json(document).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationOwnershipTransition:
    """Ephemeral proof that all three transition principals authenticated."""

    authentication_id: str
    authentication_sha256: str
    preflight: CollaborationOwnershipTransitionPreflight
    current_owner: VerifiedPrincipal
    proposed_owner: VerifiedPrincipal
    independent_control: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.preflight,
            self.current_owner,
            self.proposed_owner,
            self.independent_control,
            self.authenticated_at,
        )
        digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
        expected_id = "OTA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated ownership transition identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationOwnershipTransition can be created only "
                "by authenticate_collaboration_ownership_transition"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.preflight,
            self.current_owner,
            self.proposed_owner,
            self.independent_control,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def _assertion(value: Any, label: str) -> PrincipalAssertion:
    if not isinstance(value, PrincipalAssertion):
        raise PrincipalAuthenticationError(f"{label} must be a PrincipalAssertion")
    return PrincipalAssertion.from_dict(value.to_dict())


def _operation_intent(
    preflight: dict[str, Any],
    entry: CollaborationOwnershipChainEntry,
    principal_profile_id: str,
) -> dict[str, str]:
    entry_document = entry.to_dict()
    return {
        "entry_id": entry.entry_id,
        "entry_sha256": entry.entry_sha256,
        "mission_id": str(entry_document["mission_id"]),
        "preflight_id": str(preflight["preflight_id"]),
        "preflight_sha256": str(preflight["preflight_sha256"]),
        "principal_profile_id": principal_profile_id,
    }


def _verify(
    assertion: PrincipalAssertion,
    policy: VerifiedTrustPolicy,
    scope: VerifiedScopeGrant,
    *,
    operation: PrincipalOperation,
    intent: dict[str, str],
    expected_audience: str,
    expected_store_id: str,
    expected_mission_id: str,
    now: datetime,
) -> VerifiedPrincipal:
    return verify_principal_assertion(
        assertion,
        policy,
        scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=expected_mission_id,
        expected_operation=operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            operation,
            intent,
        ),
        clock=lambda: now,
    )


def authenticate_collaboration_ownership_transition(
    preflight: CollaborationOwnershipTransitionPreflight,
    *,
    current_owner_assertion: PrincipalAssertion,
    proposed_owner_assertion: PrincipalAssertion,
    independent_control_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    current_owner_scope: VerifiedScopeGrant,
    proposed_owner_scope: VerifiedScopeGrant,
    independent_control_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationOwnershipTransition:
    """Authenticate exact three-party consent without consuming authority."""

    if not isinstance(preflight, CollaborationOwnershipTransitionPreflight):
        raise PrincipalAuthenticationError(
            "preflight must be a CollaborationOwnershipTransitionPreflight"
        )
    current_assertion = _assertion(
        current_owner_assertion,
        "current_owner_assertion",
    )
    proposed_assertion = _assertion(
        proposed_owner_assertion,
        "proposed_owner_assertion",
    )
    control_assertion = _assertion(
        independent_control_assertion,
        "independent_control_assertion",
    )
    preflight_document = preflight.to_dict()
    entry = CollaborationOwnershipChainEntry.from_dict(preflight_document["entry"])
    entry_document = entry.to_dict()
    now = _clock_value(clock)
    if now < _timestamp(str(preflight_document["evaluated_at"]), "evaluated_at"):
        raise PrincipalAuthenticationError("Authentication time precedes preflight evaluation")
    if now >= _timestamp(str(entry_document["expires_at"]), "entry expires_at"):
        raise PrincipalAuthenticationError("Ownership transition has expired")
    if preflight_document["store_id"] != expected_store_id:
        raise PrincipalAuthenticationError("Preflight store binding does not match")
    if entry_document["mission_id"] != current_assertion.mission_id:
        raise PrincipalAuthenticationError("Current-owner mission binding does not match")
    mission_id = str(entry_document["mission_id"])
    if preflight_document["candidate_qualification"]["profile_id"] != entry_document["to_owner_id"]:
        raise PrincipalAuthenticationError(
            "Preflight candidate binding does not match the transition"
        )
    projection = preflight_document["chain_projection"]
    active_depth = projection["active_delegation_depth"]
    if (
        projection["chain_id"] != entry_document["chain_id"]
        or projection["head_entry_id"] != entry.entry_id
        or projection["head_sha256"] != entry.entry_sha256
        or projection["current_owner_id"] != entry_document["to_owner_id"]
        or projection["owner_epoch"] != entry_document["owner_epoch"]
        or projection["entry_count"] != entry_document["sequence"]
        or not isinstance(active_depth, int)
        or isinstance(active_depth, bool)
        or active_depth < 0
        or active_depth > preflight_document["policy_binding"][
            "maximum_delegation_depth"
        ]
        or (
            entry_document["transition_kind"] == "return_to_planned_owner"
            and active_depth != 0
        )
        or (
            entry_document["transition_kind"] == "delegation"
            and active_depth < 1
        )
    ):
        raise PrincipalAuthenticationError(
            "Preflight chain projection does not match the transition"
        )

    bindings = entry_document["authority_bindings"]
    if bindings["second_control_or_mission_authority_id"] is not None:
        raise PrincipalAuthenticationError(
            "This authentication boundary does not support a fourth authority"
        )
    expected = (
        (
            current_assertion,
            str(entry_document["from_owner_id"]),
            bindings["current_owner_authorization_id"],
            "Current owner",
        ),
        (
            proposed_assertion,
            str(entry_document["to_owner_id"]),
            bindings["proposed_owner_acceptance_id"],
            "Proposed owner",
        ),
    )
    for assertion_value, profile_id, assertion_id, label in expected:
        if assertion_value.profile_id != profile_id or assertion_value.assertion_id != assertion_id:
            raise PrincipalAuthenticationError(f"{label} assertion binding does not match")
    if control_assertion.assertion_id != bindings["independent_control_approval_id"]:
        raise PrincipalAuthenticationError("Independent Control assertion binding does not match")
    if isinstance(expected_control_profile_ids, (str, bytes)):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    control_profiles = frozenset(expected_control_profile_ids)
    if not control_profiles or not all(
        isinstance(profile_id, str) for profile_id in control_profiles
    ):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    if control_assertion.profile_id not in control_profiles:
        raise PrincipalAuthenticationError("Control approver is not an independent Control profile")
    identities = {
        current_assertion.profile_id,
        proposed_assertion.profile_id,
        control_assertion.profile_id,
    }
    assertion_keys = {
        (current_assertion.issuer, current_assertion.assertion_id),
        (proposed_assertion.issuer, proposed_assertion.assertion_id),
        (control_assertion.issuer, control_assertion.assertion_id),
    }
    if len(identities) != 3 or len(assertion_keys) != 3:
        raise PrincipalAuthenticationError(
            "Ownership transition requires three distinct principals and assertions"
        )

    current_intent = _operation_intent(
        preflight_document,
        entry,
        current_assertion.profile_id,
    )
    proposed_intent = _operation_intent(
        preflight_document,
        entry,
        proposed_assertion.profile_id,
    )
    control_intent = _operation_intent(
        preflight_document,
        entry,
        control_assertion.profile_id,
    )
    current_owner = _verify(
        current_assertion,
        verified_policy,
        current_owner_scope,
        operation=(PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE),
        intent=current_intent,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        now=now,
    )
    proposed_owner = _verify(
        proposed_assertion,
        verified_policy,
        proposed_owner_scope,
        operation=(PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT),
        intent=proposed_intent,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        now=now,
    )
    independent_control = _verify(
        control_assertion,
        verified_policy,
        independent_control_scope,
        operation=PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        intent=control_intent,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        now=now,
    )

    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(
        preflight,
        current_owner,
        proposed_owner,
        independent_control,
        authenticated_at,
    )
    digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
    authentication_id = "OTA-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationOwnershipTransition(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        preflight=preflight,
        current_owner=current_owner,
        proposed_owner=proposed_owner,
        independent_control=independent_control,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(document),
    )


__all__ = [
    "AuthenticatedCollaborationOwnershipTransition",
    "authenticate_collaboration_ownership_transition",
]
