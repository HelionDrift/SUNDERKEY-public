"""Dual-principal authentication for ownership revocation preflights."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .collaboration_ownership_authentication import (
    _assertion,
    _clock_value,
    _operation_intent,
    _principal_document,
    _timestamp,
    _verify,
)
from .collaboration_ownership_chain import (
    CollaborationOwnershipChainEntry,
    CollaborationOwnershipRevocation,
)
from .collaboration_ownership_revocation_preflight import (
    CollaborationOwnershipRevocationPreflight,
)
from .errors import PrincipalAuthenticationError
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    VerifiedScopeGrant,
    VerifiedTrustPolicy,
)
from .qualification import _canonical_json, _canonical_sha256

AUTHENTICATION_DOMAIN = (
    "sunderkey.collaboration-ownership-revocation-authentication.v1"
)
_PROOF_KEY = secrets.token_bytes(32)


def _authentication_body(
    preflight: CollaborationOwnershipRevocationPreflight,
    planned_owner: VerifiedPrincipal,
    independent_control: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "preflight": preflight.to_dict(),
        "planned_owner": _principal_document(planned_owner),
        "independent_control": _principal_document(independent_control),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_dual_party",
        "runtime_effect": "none",
    }


def _authentication_proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        _canonical_json(document).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationOwnershipRevocation:
    """Ephemeral proof of planned-owner and independent Control consent."""

    authentication_id: str
    authentication_sha256: str
    preflight: CollaborationOwnershipRevocationPreflight
    planned_owner: VerifiedPrincipal
    independent_control: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.preflight,
            self.planned_owner,
            self.independent_control,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "ORA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if (
            self.authentication_sha256 != digest
            or self.authentication_id != expected_id
        ):
            raise TypeError("Authenticated ownership revocation identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationOwnershipRevocation can be created "
                "only by authenticate_collaboration_ownership_revocation"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.preflight,
            self.planned_owner,
            self.independent_control,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def authenticate_collaboration_ownership_revocation(
    preflight: CollaborationOwnershipRevocationPreflight,
    *,
    planned_owner_assertion: PrincipalAssertion,
    independent_control_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    planned_owner_scope: VerifiedScopeGrant,
    independent_control_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationOwnershipRevocation:
    """Authenticate exact dual-party revocation consent without consuming it."""

    if not isinstance(preflight, CollaborationOwnershipRevocationPreflight):
        raise PrincipalAuthenticationError(
            "preflight must be a CollaborationOwnershipRevocationPreflight"
        )
    planned_assertion = _assertion(
        planned_owner_assertion,
        "planned_owner_assertion",
    )
    control_assertion = _assertion(
        independent_control_assertion,
        "independent_control_assertion",
    )
    preflight_document = preflight.to_dict()
    entry = CollaborationOwnershipChainEntry.from_dict(
        preflight_document["entry"]
    )
    entry_document = entry.to_dict()
    revocation = CollaborationOwnershipRevocation.from_dict(
        preflight_document["revocation"]
    )
    request = revocation.to_dict()
    now = _clock_value(clock)
    if now < _timestamp(str(preflight_document["evaluated_at"]), "evaluated_at"):
        raise PrincipalAuthenticationError(
            "Authentication time precedes revocation preflight evaluation"
        )
    if now >= _timestamp(str(entry_document["expires_at"]), "entry expires_at"):
        raise PrincipalAuthenticationError("Ownership revocation has expired")
    if preflight_document["store_id"] != expected_store_id:
        raise PrincipalAuthenticationError("Preflight store binding does not match")
    mission_id = str(entry_document["mission_id"])
    if (
        planned_assertion.mission_id != mission_id
        or control_assertion.mission_id != mission_id
    ):
        raise PrincipalAuthenticationError(
            "Ownership revocation mission binding does not match"
        )
    bindings = entry_document["authority_bindings"]
    qualification = preflight_document["planned_owner_qualification"]
    projection = preflight_document["chain_projection"]
    if (
        entry_document["transition_kind"] != "control_revocation"
        or bindings["current_owner_authorization_id"] is not None
        or bindings["second_control_or_mission_authority_id"] is not None
        or entry_document["to_owner_id"] != request["planned_owner_id"]
        or qualification["profile_id"] != request["planned_owner_id"]
        or projection["chain_id"] != entry_document["chain_id"]
        or projection["head_entry_id"] != entry.entry_id
        or projection["head_sha256"] != entry.entry_sha256
        or projection["current_owner_id"] != entry_document["to_owner_id"]
        or projection["owner_epoch"] != entry_document["owner_epoch"]
        or projection["entry_count"] != entry_document["sequence"]
        or projection["active_delegation_depth"] != 0
    ):
        raise PrincipalAuthenticationError(
            "Revocation preflight projection does not match the transition"
        )
    if (
        planned_assertion.profile_id != request["planned_owner_id"]
        or planned_assertion.assertion_id
        != request["planned_owner_acceptance_id"]
        or planned_assertion.assertion_id
        != bindings["proposed_owner_acceptance_id"]
    ):
        raise PrincipalAuthenticationError(
            "Planned-owner assertion binding does not match"
        )
    if (
        control_assertion.profile_id != request["independent_control_id"]
        or control_assertion.assertion_id
        != request["independent_control_approval_id"]
        or control_assertion.assertion_id
        != bindings["independent_control_approval_id"]
    ):
        raise PrincipalAuthenticationError(
            "Independent Control assertion binding does not match"
        )
    if isinstance(expected_control_profile_ids, (str, bytes)):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    control_profiles = frozenset(expected_control_profile_ids)
    if not control_profiles or not all(
        isinstance(profile_id, str) for profile_id in control_profiles
    ):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    if control_assertion.profile_id not in control_profiles:
        raise PrincipalAuthenticationError(
            "Control approver is not an independent Control profile"
        )
    if (
        planned_assertion.profile_id == control_assertion.profile_id
        or (planned_assertion.issuer, planned_assertion.assertion_id)
        == (control_assertion.issuer, control_assertion.assertion_id)
    ):
        raise PrincipalAuthenticationError(
            "Ownership revocation requires two distinct principals and assertions"
        )

    planned_intent = _operation_intent(
        preflight_document,
        entry,
        planned_assertion.profile_id,
    )
    control_intent = _operation_intent(
        preflight_document,
        entry,
        control_assertion.profile_id,
    )
    planned_owner = _verify(
        planned_assertion,
        verified_policy,
        planned_owner_scope,
        operation=PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
        intent=planned_intent,
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
        planned_owner,
        independent_control,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "ORA-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationOwnershipRevocation(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        preflight=preflight,
        planned_owner=planned_owner,
        independent_control=independent_control,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(document),
    )


__all__ = [
    "AuthenticatedCollaborationOwnershipRevocation",
    "authenticate_collaboration_ownership_revocation",
]
