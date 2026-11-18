"""Three-party or four-party authentication for privileged reassignment."""

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
from .collaboration_ownership_chain import CollaborationOwnershipChainEntry
from .collaboration_ownership_privileged_reassignment_preflight import (
    CollaborationOwnershipPrivilegedReassignmentPreflight,
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
    "sunderkey.collaboration-ownership-privileged-reassignment-"
    "authentication.v1"
)
_PROOF_KEY = secrets.token_bytes(32)


def _authentication_body(
    preflight: CollaborationOwnershipPrivilegedReassignmentPreflight,
    current_owner: VerifiedPrincipal,
    proposed_owner: VerifiedPrincipal,
    independent_control: VerifiedPrincipal,
    second_authority: VerifiedPrincipal | None,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "preflight": preflight.to_dict(),
        "current_owner": _principal_document(current_owner),
        "proposed_owner": _principal_document(proposed_owner),
        "independent_control": _principal_document(independent_control),
        "second_control_or_mission_authority": (
            None
            if second_authority is None
            else _principal_document(second_authority)
        ),
        "authenticated_at": authenticated_at,
        "authentication_status": (
            "authenticated_four_party_control_replacement"
            if second_authority is not None
            else "authenticated_three_party_privileged_reassignment"
        ),
        "runtime_effect": "none",
    }


def _authentication_proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        _canonical_json(document).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationOwnershipPrivilegedReassignment:
    """Ephemeral proof of all authorities required by D001."""

    authentication_id: str
    authentication_sha256: str
    preflight: CollaborationOwnershipPrivilegedReassignmentPreflight
    current_owner: VerifiedPrincipal
    proposed_owner: VerifiedPrincipal
    independent_control: VerifiedPrincipal
    second_control_or_mission_authority: VerifiedPrincipal | None
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.preflight,
            self.current_owner,
            self.proposed_owner,
            self.independent_control,
            self.second_control_or_mission_authority,
            self.authenticated_at,
        )
        digest = _canonical_sha256(
            {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
        )
        expected_id = "OPA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if (
            self.authentication_sha256 != digest
            or self.authentication_id != expected_id
        ):
            raise TypeError(
                "Authenticated privileged reassignment identity is invalid"
            )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationOwnershipPrivilegedReassignment "
                "can be created only by its authentication function"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.preflight,
            self.current_owner,
            self.proposed_owner,
            self.independent_control,
            self.second_control_or_mission_authority,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def _profile_set(value: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(value, (str, bytes)):
        raise PrincipalAuthenticationError(f"{label} are invalid")
    profiles = frozenset(value)
    if not profiles or not all(
        isinstance(profile_id, str) and profile_id for profile_id in profiles
    ):
        raise PrincipalAuthenticationError(f"{label} are invalid")
    return profiles


def authenticate_collaboration_ownership_privileged_reassignment(
    preflight: CollaborationOwnershipPrivilegedReassignmentPreflight,
    *,
    current_owner_assertion: PrincipalAssertion,
    proposed_owner_assertion: PrincipalAssertion,
    independent_control_assertion: PrincipalAssertion,
    second_authority_assertion: PrincipalAssertion | None,
    verified_policy: VerifiedTrustPolicy,
    current_owner_scope: VerifiedScopeGrant,
    proposed_owner_scope: VerifiedScopeGrant,
    independent_control_scope: VerifiedScopeGrant,
    second_authority_scope: VerifiedScopeGrant | None,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    expected_second_authority_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
) -> AuthenticatedCollaborationOwnershipPrivilegedReassignment:
    """Authenticate exact D001 consent without consuming any assertion."""

    if not isinstance(
        preflight,
        CollaborationOwnershipPrivilegedReassignmentPreflight,
    ):
        raise PrincipalAuthenticationError(
            "preflight must be a privileged reassignment preflight"
        )
    parsed_preflight = (
        CollaborationOwnershipPrivilegedReassignmentPreflight.from_dict(
            preflight.to_dict()
        )
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
    document = parsed_preflight.to_dict()
    entry = CollaborationOwnershipChainEntry.from_dict(document["entry"])
    entry_document = entry.to_dict()
    now = _clock_value(clock)
    if now < _timestamp(str(document["evaluated_at"]), "evaluated_at"):
        raise PrincipalAuthenticationError(
            "Authentication time precedes preflight evaluation"
        )
    if now >= _timestamp(str(entry_document["expires_at"]), "entry expires_at"):
        raise PrincipalAuthenticationError(
            "Privileged ownership reassignment has expired"
        )
    if document["store_id"] != expected_store_id:
        raise PrincipalAuthenticationError("Preflight store binding does not match")
    mission_id = str(entry_document["mission_id"])
    if any(
        assertion.mission_id != mission_id
        for assertion in (
            current_assertion,
            proposed_assertion,
            control_assertion,
        )
    ):
        raise PrincipalAuthenticationError(
            "Privileged reassignment mission binding does not match"
        )

    bindings = entry_document["authority_bindings"]
    role = document["role_binding"]
    qualification = document["replacement_qualification"]
    projection = document["chain_projection"]
    if (
        entry_document["transition_kind"] != "privileged_reassignment"
        or entry_document["from_owner_id"] != role["current_owner_id"]
        or entry_document["to_owner_id"] != qualification["profile_id"]
        or entry_document["control_role_replacement"]
        != role["control_role_replacement"]
        or projection["chain_id"] != entry_document["chain_id"]
        or projection["head_entry_id"] != entry.entry_id
        or projection["head_sha256"] != entry.entry_sha256
        or projection["current_owner_id"] != entry_document["to_owner_id"]
        or projection["owner_epoch"] != entry_document["owner_epoch"]
        or projection["entry_count"] != entry_document["sequence"]
        or projection["active_delegation_depth"] < 1
        or projection["active_delegation_depth"]
        > document["policy_binding"]["maximum_delegation_depth"]
    ):
        raise PrincipalAuthenticationError(
            "Privileged reassignment projection does not match the transition"
        )

    expected_bindings = (
        (
            current_assertion,
            entry_document["from_owner_id"],
            bindings["current_owner_authorization_id"],
            "Current owner",
        ),
        (
            proposed_assertion,
            entry_document["to_owner_id"],
            bindings["proposed_owner_acceptance_id"],
            "Proposed owner",
        ),
    )
    for assertion, profile_id, assertion_id, label in expected_bindings:
        if (
            assertion.profile_id != profile_id
            or assertion.assertion_id != assertion_id
        ):
            raise PrincipalAuthenticationError(
                f"{label} assertion binding does not match"
            )
    if control_assertion.assertion_id != bindings[
        "independent_control_approval_id"
    ]:
        raise PrincipalAuthenticationError(
            "Independent Control assertion binding does not match"
        )
    control_profiles = _profile_set(
        expected_control_profile_ids,
        "Expected Control profiles",
    )
    if control_assertion.profile_id not in control_profiles:
        raise PrincipalAuthenticationError(
            "Control approver is not an authorized independent Control profile"
        )

    control_replacement = bool(role["control_role_replacement"])
    if control_replacement:
        if second_authority_assertion is None or second_authority_scope is None:
            raise PrincipalAuthenticationError(
                "Control replacement requires a second authority"
            )
        second_assertion = _assertion(
            second_authority_assertion,
            "second_authority_assertion",
        )
        if (
            second_assertion.mission_id != mission_id
            or second_assertion.assertion_id
            != bindings["second_control_or_mission_authority_id"]
        ):
            raise PrincipalAuthenticationError(
                "Second authority assertion binding does not match"
            )
        second_profiles = _profile_set(
            expected_second_authority_profile_ids,
            "Expected second authority profiles",
        )
        if second_assertion.profile_id not in second_profiles:
            raise PrincipalAuthenticationError(
                "Second authority is not an authorized Control or mission authority"
            )
    else:
        if (
            second_authority_assertion is not None
            or second_authority_scope is not None
            or bindings["second_control_or_mission_authority_id"] is not None
        ):
            raise PrincipalAuthenticationError(
                "Non-Control reassignment cannot use a fourth authority"
            )
        second_assertion = None

    assertions = [current_assertion, proposed_assertion, control_assertion]
    if second_assertion is not None:
        assertions.append(second_assertion)
    identities = {assertion.profile_id for assertion in assertions}
    assertion_keys = {
        (assertion.issuer, assertion.assertion_id) for assertion in assertions
    }
    if len(identities) != len(assertions) or len(assertion_keys) != len(
        assertions
    ):
        raise PrincipalAuthenticationError(
            "Privileged reassignment requires distinct principals and assertions"
        )

    current_owner = _verify(
        current_assertion,
        verified_policy,
        current_owner_scope,
        operation=(
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE
        ),
        intent=_operation_intent(
            document,
            entry,
            current_assertion.profile_id,
        ),
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        now=now,
    )
    proposed_owner = _verify(
        proposed_assertion,
        verified_policy,
        proposed_owner_scope,
        operation=(
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
        ),
        intent=_operation_intent(
            document,
            entry,
            proposed_assertion.profile_id,
        ),
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
        intent=_operation_intent(
            document,
            entry,
            control_assertion.profile_id,
        ),
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        now=now,
    )
    second_authority = None
    if second_assertion is not None:
        second_operation = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE
        )
        second_authority = _verify(
            second_assertion,
            verified_policy,
            second_authority_scope,
            operation=second_operation,
            intent=_operation_intent(
                document,
                entry,
                second_assertion.profile_id,
            ),
            expected_audience=expected_audience,
            expected_store_id=expected_store_id,
            expected_mission_id=mission_id,
            now=now,
        )

    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(
        parsed_preflight,
        current_owner,
        proposed_owner,
        independent_control,
        second_authority,
        authenticated_at,
    )
    digest = _canonical_sha256(
        {"domain": AUTHENTICATION_DOMAIN, "authentication": body}
    )
    authentication_id = "OPA-" + digest.removeprefix("sha256:")[:32].upper()
    authentication_document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationOwnershipPrivilegedReassignment(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        preflight=parsed_preflight,
        current_owner=current_owner,
        proposed_owner=proposed_owner,
        independent_control=independent_control,
        second_control_or_mission_authority=second_authority,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(authentication_document),
    )


__all__ = [
    "AuthenticatedCollaborationOwnershipPrivilegedReassignment",
    "authenticate_collaboration_ownership_privileged_reassignment",
]
