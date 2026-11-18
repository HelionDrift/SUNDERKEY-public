"""Dual-principal authentication for mission reconfiguration policies."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration import CollaborationPlan, WorkItemKind
from .collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    VerifiedMissionPolicyPlanAnchorTransition,
    collaboration_mission_reconfiguration_selection_sha256,
    validate_collaboration_mission_reconfiguration_policy,
)
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
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

AUTHENTICATION_DOMAIN = "sunderkey.collaboration-mission-policy-authentication.v1"
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
        raise CollaborationPlanError("Mission policy timestamp is invalid") from exc


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _authentication_body(
    policy: CollaborationMissionReconfigurationPolicy,
    mission_owner: VerifiedPrincipal,
    independent_control: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mission_policy": policy.to_dict(),
        "mission_owner": _principal_document(mission_owner),
        "independent_control": _principal_document(independent_control),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_dual_control",
        "runtime_effect": "none",
    }


def _authentication_proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        _canonical_json(document).encode("utf-8"),
        "sha256",
    ).digest()


@dataclass(frozen=True)
class AuthenticatedCollaborationMissionPolicy:
    """Ephemeral proof that both required policy assertions authenticated."""

    authentication_id: str
    authentication_sha256: str
    policy: CollaborationMissionReconfigurationPolicy
    mission_owner: VerifiedPrincipal
    independent_control: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.policy,
            self.mission_owner,
            self.independent_control,
            self.authenticated_at,
        )
        digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
        expected_id = "MPA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated mission policy identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _authentication_proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationMissionPolicy can be created only by "
                "authenticate_collaboration_mission_reconfiguration_policy"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.policy,
            self.mission_owner,
            self.independent_control,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }


def _readiness_owner(plan: CollaborationPlan) -> str:
    readiness = tuple(item for item in plan.work_items if item.kind is WorkItemKind.READINESS)
    if len(readiness) != 1:
        raise CollaborationPlanError("Collaboration plan must contain one readiness item")
    return readiness[0].owner_profile_id


def _require_assertion_binding(
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


def _operation_intent(
    *,
    mission_id: str,
    selection_sha256: str,
    principal_profile_id: str,
) -> dict[str, str]:
    return {
        "mission_id": mission_id,
        "policy_selection_sha256": selection_sha256,
        "principal_profile_id": principal_profile_id,
    }


def authenticate_collaboration_mission_reconfiguration_policy(
    policy: CollaborationMissionReconfigurationPolicy,
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    collaboration_plan: CollaborationPlan,
    mission_owner_assertion: PrincipalAssertion,
    independent_control_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    mission_owner_scope: VerifiedScopeGrant,
    independent_control_scope: VerifiedScopeGrant,
    expected_audience: str,
    expected_store_id: str,
    expected_control_profile_ids: Iterable[str],
    clock: Callable[[], datetime],
    previous_policy: CollaborationMissionReconfigurationPolicy | None = None,
    plan_anchor_transition: VerifiedMissionPolicyPlanAnchorTransition | None = None,
) -> AuthenticatedCollaborationMissionPolicy:
    """Authenticate both policy approvals without persistence or runtime activation."""

    if not isinstance(collaboration_plan, CollaborationPlan):
        raise CollaborationPlanError("collaboration_plan must be a CollaborationPlan")
    if not isinstance(mission_owner_assertion, PrincipalAssertion):
        raise PrincipalAuthenticationError("mission_owner_assertion must be a PrincipalAssertion")
    if not isinstance(independent_control_assertion, PrincipalAssertion):
        raise PrincipalAuthenticationError(
            "independent_control_assertion must be a PrincipalAssertion"
        )
    plan = CollaborationPlan.from_dict(collaboration_plan.to_dict())
    owner_assertion = PrincipalAssertion.from_dict(mission_owner_assertion.to_dict())
    control_assertion = PrincipalAssertion.from_dict(independent_control_assertion.to_dict())
    parsed = validate_collaboration_mission_reconfiguration_policy(
        policy,
        authority_policy=authority_policy,
        expected_mission_id=plan.mission_id,
        expected_collaboration_plan_id=plan.plan_id,
        expected_collaboration_plan_sha256=plan.content_sha256,
        previous_policy=previous_policy,
        plan_anchor_transition=plan_anchor_transition,
    )
    if (
        plan_anchor_transition is not None
        and plan_anchor_transition.to_dict()["store_id"] != expected_store_id
    ):
        raise PrincipalAuthenticationError("Mission policy anchor lineage store binding is stale")
    document = parsed.to_dict()
    now = _clock_value(clock)
    if now < _timestamp(document["effective_at"]) or now >= _timestamp(document["expires_at"]):
        raise PrincipalAuthenticationError("Mission policy is outside its validity window")

    approvals = document["approval_bindings"]
    owner_profile_id = _readiness_owner(plan)
    if isinstance(expected_control_profile_ids, (str, bytes)):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    control_profile_ids = frozenset(expected_control_profile_ids)
    if not control_profile_ids or not all(
        isinstance(profile_id, str) for profile_id in control_profile_ids
    ):
        raise PrincipalAuthenticationError("Expected Control profiles are invalid")
    if approvals["mission_owner"]["profile_id"] != owner_profile_id:
        raise PrincipalAuthenticationError(
            "Mission policy owner is not the active plan readiness owner"
        )
    control_profile_id = approvals["independent_control"]["profile_id"]
    if control_profile_id not in control_profile_ids:
        raise PrincipalAuthenticationError(
            "Mission policy Control approver is not an independent Control profile"
        )
    if control_profile_id == owner_profile_id:
        raise PrincipalAuthenticationError("Mission owner and Control approver must be distinct")
    _require_assertion_binding(
        owner_assertion,
        approvals["mission_owner"],
        label="Mission owner",
    )
    _require_assertion_binding(
        control_assertion,
        approvals["independent_control"],
        label="Independent Control",
    )

    selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(parsed)
    owner_intent = _operation_intent(
        mission_id=plan.mission_id,
        selection_sha256=selection_sha256,
        principal_profile_id=owner_profile_id,
    )
    control_intent = _operation_intent(
        mission_id=plan.mission_id,
        selection_sha256=selection_sha256,
        principal_profile_id=control_profile_id,
    )
    mission_owner = verify_principal_assertion(
        owner_assertion,
        verified_policy,
        mission_owner_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=plan.mission_id,
        expected_operation=PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            owner_intent,
        ),
        clock=lambda: now,
    )
    independent_control = verify_principal_assertion(
        control_assertion,
        verified_policy,
        independent_control_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=plan.mission_id,
        expected_operation=PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            control_intent,
        ),
        clock=lambda: now,
    )
    if mission_owner.profile_id != owner_profile_id:
        raise PrincipalAuthenticationError("Authenticated mission owner does not match")
    if independent_control.profile_id != control_profile_id:
        raise PrincipalAuthenticationError("Authenticated Control approver does not match")

    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(
        parsed,
        mission_owner,
        independent_control,
        authenticated_at,
    )
    digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
    authentication_id = "MPA-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    return AuthenticatedCollaborationMissionPolicy(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        policy=parsed,
        mission_owner=mission_owner,
        independent_control=independent_control,
        authenticated_at=authenticated_at,
        _proof=_authentication_proof(document),
    )


__all__ = [
    "AuthenticatedCollaborationMissionPolicy",
    "authenticate_collaboration_mission_reconfiguration_policy",
]
