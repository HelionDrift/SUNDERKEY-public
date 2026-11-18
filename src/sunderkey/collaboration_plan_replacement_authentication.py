"""Offline authentication for collaboration plan replacement authority."""

from __future__ import annotations

import hmac
import json
import re
import secrets
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from typing import Any

from .collaboration import MAX_WORK_ITEMS
from .collaboration_plan_replacement_authority import (
    VerifiedCollaborationPlanReplacementAuthorityPlan,
    validate_verified_collaboration_plan_replacement_authority_plan,
)
from .collaboration_plan_replacement_authority_upgrade import (
    CollaborationPlanReplacementAuthorityUpgrade,
    verify_collaboration_plan_replacement_authority_upgrade,
)
from .collaboration_plan_replacement_preflight import (
    CollaborationPlanReplacementPreflight,
)
from .errors import CollaborationPlanError, PrincipalAuthenticationError
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    VerifiedPrincipal,
    VerifiedScopeGrant,
    VerifiedTrustPolicy,
    verify_principal_assertion,
    verify_scope_grant,
)
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry
from .types import ActionTier, MissionEnvironment

# Retained for the immutable legacy fixture, not a runtime authority gate.
EXPECTED_REQUIREMENT_COUNT = 16
# One current and proposed owner per item, two reviews per cross-command mapping,
# and at most four global owner, Control, second Control, and Assurance roles.
MAX_AUTHORITY_REQUIREMENT_COUNT = 4 * MAX_WORK_ITEMS + 4
AUTHENTICATION_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-authentication.v1"
COMPOSITION_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-composition.v2"
REPLAY_KEY_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-replay-key.v2"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SOURCE_REQUIREMENT_ID_PATTERN = re.compile(r"PAR-[0-9A-F]{32}")
_UPGRADED_REQUIREMENT_ID_PATTERN = re.compile(r"PRA-[0-9A-F]{32}")


def validate_plan_replacement_authority_requirement_count(
    value: Any, label: str = "authority requirement count"
) -> int:
    """Require a native bounded count derived from exact validated requirements."""

    if type(value) is not int or not 1 <= value <= MAX_AUTHORITY_REQUIREMENT_COUNT:
        raise PrincipalAuthenticationError(
            f"{label} must be a native integer from 1 to {MAX_AUTHORITY_REQUIREMENT_COUNT}"
        )
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise PrincipalAuthenticationError(f"{label} is invalid")
    return value


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise PrincipalAuthenticationError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise PrincipalAuthenticationError(f"{label} is not canonical")
    return parsed


def _digest_collection(values: Collection[str], label: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Collection):
        raise PrincipalAuthenticationError(f"{label} must be a collection")
    result = tuple(_sha256(value, f"{label}[{index}]") for index, value in enumerate(values))
    if len(result) != len(set(result)):
        raise PrincipalAuthenticationError(f"{label} contains duplicates")
    return frozenset(result)


@dataclass(frozen=True, slots=True)
class CollaborationPlanReplacementAuthorityCredential:
    """One exact requirement binding and its signed identity credentials."""

    source_requirement_id: str
    upgraded_requirement_id: str
    replay_key_sha256: str
    scope_grant: ScopeGrant
    assertion: PrincipalAssertion

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_requirement_id, str)
            or _SOURCE_REQUIREMENT_ID_PATTERN.fullmatch(self.source_requirement_id) is None
        ):
            raise PrincipalAuthenticationError("source_requirement_id is invalid")
        if (
            not isinstance(self.upgraded_requirement_id, str)
            or _UPGRADED_REQUIREMENT_ID_PATTERN.fullmatch(self.upgraded_requirement_id) is None
        ):
            raise PrincipalAuthenticationError("upgraded_requirement_id is invalid")
        _sha256(self.replay_key_sha256, "replay_key_sha256")
        if not isinstance(self.scope_grant, ScopeGrant):
            raise PrincipalAuthenticationError("scope_grant must be a ScopeGrant")
        if not isinstance(self.assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError("assertion must be a PrincipalAssertion")


@dataclass(frozen=True, slots=True)
class AuthenticatedPlanReplacementRequirement:
    """Inspection record that is authoritative only inside its verified bundle."""

    source_requirement_id: str
    upgraded_requirement_id: str
    replay_key_sha256: str
    role: str
    authority_id: str
    work_item_id: str | None
    principal: VerifiedPrincipal

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_requirement_id, str)
            or _SOURCE_REQUIREMENT_ID_PATTERN.fullmatch(self.source_requirement_id) is None
        ):
            raise PrincipalAuthenticationError("source_requirement_id is invalid")
        if (
            not isinstance(self.upgraded_requirement_id, str)
            or _UPGRADED_REQUIREMENT_ID_PATTERN.fullmatch(self.upgraded_requirement_id) is None
        ):
            raise PrincipalAuthenticationError("upgraded_requirement_id is invalid")
        _sha256(self.replay_key_sha256, "replay_key_sha256")
        for value, label in (
            (self.role, "role"),
            (self.authority_id, "authority_id"),
        ):
            if not isinstance(value, str) or not value:
                raise PrincipalAuthenticationError(f"{label} is invalid")
        if self.work_item_id is not None and (
            not isinstance(self.work_item_id, str) or not self.work_item_id
        ):
            raise PrincipalAuthenticationError("work_item_id is invalid")
        if (
            not isinstance(self.principal, VerifiedPrincipal)
            or not self.principal._proof_is_valid()
        ):
            raise PrincipalAuthenticationError(
                "principal must be produced by verify_principal_assertion"
            )


@dataclass(frozen=True, slots=True)
class _ScopeContext:
    audience: str
    store_id: str
    mission_context_hash: str
    scope_reference: str
    scope_document_hash: str
    environment: MissionEnvironment | str
    max_action_tier: ActionTier | str
    constraints_hash: str


def _normalize_credential(
    value: CollaborationPlanReplacementAuthorityCredential,
) -> CollaborationPlanReplacementAuthorityCredential:
    if not isinstance(value, CollaborationPlanReplacementAuthorityCredential):
        raise PrincipalAuthenticationError(
            "credentials must contain CollaborationPlanReplacementAuthorityCredential values"
        )
    return CollaborationPlanReplacementAuthorityCredential(
        source_requirement_id=value.source_requirement_id,
        upgraded_requirement_id=value.upgraded_requirement_id,
        replay_key_sha256=value.replay_key_sha256,
        scope_grant=ScopeGrant.from_dict(value.scope_grant.to_dict()),
        assertion=PrincipalAssertion.from_dict(value.assertion.to_dict()),
    )


def _normalize_credentials(
    values: Iterable[CollaborationPlanReplacementAuthorityCredential],
) -> tuple[CollaborationPlanReplacementAuthorityCredential, ...]:
    if isinstance(values, (str, bytes)):
        raise PrincipalAuthenticationError("credentials must be an iterable")
    try:
        result = tuple(
            _normalize_credential(value)
            for value in islice(values, MAX_AUTHORITY_REQUIREMENT_COUNT + 1)
        )
    except TypeError as exc:
        raise PrincipalAuthenticationError("credentials must be an iterable") from exc
    validate_plan_replacement_authority_requirement_count(len(result), "authority credential count")
    return result


def _validate_source_composition(
    verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
    authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
    *,
    preflight: CollaborationPlanReplacementPreflight,
    army_registry: ExpertRegistry,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, str],
    str,
]:
    try:
        authority_plan = validate_verified_collaboration_plan_replacement_authority_plan(
            verified_authority_plan
        )
    except TypeError as exc:
        raise PrincipalAuthenticationError(
            "verified_authority_plan did not pass point-of-use validation"
        ) from exc
    if not isinstance(authority_upgrade, CollaborationPlanReplacementAuthorityUpgrade):
        raise CollaborationPlanError(
            "authority_upgrade must be a CollaborationPlanReplacementAuthorityUpgrade"
        )
    if not isinstance(preflight, CollaborationPlanReplacementPreflight):
        raise CollaborationPlanError("preflight must be a CollaborationPlanReplacementPreflight")
    if not isinstance(army_registry, ExpertRegistry):
        raise CollaborationPlanError("army_registry must be an ExpertRegistry")
    parsed_upgrade = verify_collaboration_plan_replacement_authority_upgrade(
        authority_upgrade,
        preflight=preflight,
        army_registry=army_registry,
    )
    plan_document = authority_plan.to_dict()
    upgrade_document = parsed_upgrade.to_dict()
    preflight_document = CollaborationPlanReplacementPreflight.from_dict(
        preflight.to_dict()
    ).to_dict()
    if (
        plan_document["source_preflight"]
        != {
            "preflight_id": preflight_document["preflight_id"],
            "preflight_sha256": preflight_document["preflight_sha256"],
            "selection_sha256": preflight_document["selection_sha256"],
        }
        or upgrade_document["source_preflight"]
        != {
            "preflight_id": preflight_document["preflight_id"],
            "preflight_sha256": preflight_document["preflight_sha256"],
        }
        or plan_document["mission_id"] != upgrade_document["mission_id"]
        or plan_document["mission_id"] != preflight_document["mission_id"]
        or upgrade_document["prior_plan"] != preflight_document["prior_plan"]
        or upgrade_document["replacement_plan"] != preflight_document["replacement_plan"]
        or upgrade_document["selection_sha256"] != preflight_document["selection_sha256"]
        or plan_document["source_registry"]["content_sha256"]
        != upgrade_document["army_registry"]["registry_sha256"]
    ):
        raise CollaborationPlanError("Plan replacement authority sources have drifted")

    plan_requirements = plan_document["assertion_requirements"]
    upgrade_requirements = upgrade_document["authority_requirements"]
    requirement_count = validate_plan_replacement_authority_requirement_count(
        len(plan_requirements)
    )
    if len(upgrade_requirements) != requirement_count:
        raise CollaborationPlanError("Authority plan and upgrade requirement counts differ")
    if len({item["requirement_id"] for item in plan_requirements}) != requirement_count:
        raise CollaborationPlanError("Authority plan requirement identities are not unique")
    upgraded_by_source = {item["source_requirement_id"]: item for item in upgrade_requirements}
    if len(upgraded_by_source) != requirement_count:
        raise CollaborationPlanError("Upgraded authority requirement coverage is not one-to-one")
    if set(upgraded_by_source) != {item["requirement_id"] for item in plan_requirements}:
        raise CollaborationPlanError("Authority plan and identity upgrade coverage differ")
    mapping: list[dict[str, Any]] = []
    canonical_replay_keys: dict[str, str] = {}
    for plan_requirement in plan_requirements:
        upgrade_requirement = upgraded_by_source[plan_requirement["requirement_id"]]
        comparisons = (
            ("role", "role"),
            ("authority_id", "authority_id"),
            ("authority_kind", "authority_kind"),
            ("resolved_profile_id", "principal_profile_id"),
            ("operation", "operation"),
            ("work_item_id", "work_item_id"),
            ("preflight_operation_intent_sha256", "authority_intent_sha256"),
        )
        if any(
            plan_requirement[plan_field] != upgrade_requirement[upgrade_field]
            for plan_field, upgrade_field in comparisons
        ):
            raise CollaborationPlanError("Authority requirement source composition is stale")
        if (
            plan_requirement["authority_kind"] == "command"
            and plan_requirement["resolved_profile_id"]
            != upgrade_requirement["principal_profile_id"]
        ):
            raise CollaborationPlanError("Command authority commander resolution has drifted")
        replay_body = {
            "authority_plan_id": plan_document["authority_plan_id"],
            "authority_plan_sha256": plan_document["authority_plan_sha256"],
            "authority_plan_document_sha256": plan_document["document_sha256"],
            "upgrade_id": upgrade_document["upgrade_id"],
            "upgrade_sha256": upgrade_document["upgrade_sha256"],
            "source_requirement_id": plan_requirement["requirement_id"],
            "upgraded_requirement_id": upgrade_requirement["requirement_id"],
            "source_replay_key_sha256": plan_requirement["replay_key_sha256"],
            "principal_profile_id": upgrade_requirement["principal_profile_id"],
            "operation": upgrade_requirement["operation"],
            "principal_operation_intent_sha256": upgrade_requirement[
                "principal_operation_intent_sha256"
            ],
        }
        canonical_replay_key = _canonical_sha256(
            {"domain": REPLAY_KEY_DOMAIN, "replay_key": replay_body}
        )
        canonical_replay_keys[plan_requirement["requirement_id"]] = canonical_replay_key
        mapping.append({**replay_body, "canonical_replay_key_sha256": canonical_replay_key})
    composition_sha256 = _canonical_sha256(
        {
            "domain": COMPOSITION_DOMAIN,
            "composition": {
                "authority_plan_id": plan_document["authority_plan_id"],
                "authority_plan_sha256": plan_document["authority_plan_sha256"],
                "authority_plan_document_sha256": plan_document["document_sha256"],
                "upgrade_id": upgrade_document["upgrade_id"],
                "upgrade_sha256": upgrade_document["upgrade_sha256"],
                "ordered_requirement_mapping": mapping,
            },
        }
    )
    return (
        plan_document,
        upgrade_document,
        upgraded_by_source,
        canonical_replay_keys,
        composition_sha256,
    )


def collaboration_plan_replacement_authority_replay_keys(
    verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
    authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
    *,
    preflight: CollaborationPlanReplacementPreflight,
    army_registry: ExpertRegistry,
) -> dict[str, str]:
    """Derive the only replay keys admissible for the composed v2 authority set."""

    _, _, _, replay_keys, _ = _validate_source_composition(
        verified_authority_plan,
        authority_upgrade,
        preflight=preflight,
        army_registry=army_registry,
    )
    return dict(replay_keys)


def _require_separation(
    requirements: tuple[AuthenticatedPlanReplacementRequirement, ...],
) -> None:
    profiles_by_role: dict[str, set[str]] = {}
    subjects_by_role: dict[str, set[str]] = {}
    for item in requirements:
        profiles_by_role.setdefault(item.role, set()).add(item.principal.profile_id)
        subjects_by_role.setdefault(item.role, set()).add(item.principal.subject)
    required_singletons = (
        "mission_owner",
        "independent_control",
        "independent_assurance",
        "second_control",
    )
    if any(
        len(profiles_by_role.get(role, set())) != 1 or len(subjects_by_role.get(role, set())) != 1
        for role in required_singletons
    ):
        raise PrincipalAuthenticationError(
            "Mission owner, Control, Assurance, and second Control must each resolve "
            "to one profile and authenticated subject"
        )
    owner_profiles = profiles_by_role.get("current_owner", set()) | profiles_by_role.get(
        "proposed_owner", set()
    )
    owner_subjects = subjects_by_role.get("current_owner", set()) | subjects_by_role.get(
        "proposed_owner", set()
    )
    mission_profiles = profiles_by_role["mission_owner"]
    mission_subjects = subjects_by_role["mission_owner"]
    independent_roles = ("independent_control", "independent_assurance", "second_control")
    independent_profiles = [next(iter(profiles_by_role[role])) for role in independent_roles]
    independent_subjects = [next(iter(subjects_by_role[role])) for role in independent_roles]
    if len(set(independent_profiles)) != len(independent_profiles) or len(
        set(independent_subjects)
    ) != len(independent_subjects):
        raise PrincipalAuthenticationError("Independent review authorities must be distinct")
    if set(independent_profiles) & (mission_profiles | owner_profiles) or set(
        independent_subjects
    ) & (mission_subjects | owner_subjects):
        raise PrincipalAuthenticationError(
            "Independent review authority cannot be the mission owner or an affected owner"
        )
    source_profiles = profiles_by_role.get("source_technical_command", set())
    destination_profiles = profiles_by_role.get("destination_technical_command", set())
    source_subjects = subjects_by_role.get("source_technical_command", set())
    destination_subjects = subjects_by_role.get("destination_technical_command", set())
    if source_profiles & destination_profiles or source_subjects & destination_subjects:
        raise PrincipalAuthenticationError(
            "Source and destination command reviewers must be distinct"
        )
    if (source_profiles | destination_profiles) & set(independent_profiles) or (
        source_subjects | destination_subjects
    ) & set(independent_subjects):
        raise PrincipalAuthenticationError(
            "Command reviewers and independent reviewers must be distinct"
        )


def _verify_credentials(
    *,
    plan_document: dict[str, Any],
    upgraded_by_source: dict[str, dict[str, Any]],
    credentials: tuple[CollaborationPlanReplacementAuthorityCredential, ...],
    canonical_replay_keys: dict[str, str],
    verified_policy: VerifiedTrustPolicy,
    scope_context: _ScopeContext,
    revoked_scope_grant_sha256s: frozenset[str],
    consumed_replay_keys: frozenset[str],
    now: datetime,
) -> tuple[AuthenticatedPlanReplacementRequirement, ...]:
    if (
        not isinstance(verified_policy, VerifiedTrustPolicy)
        or not verified_policy._proof_is_valid()
    ):
        raise PrincipalAuthenticationError(
            "verified_policy must be produced by verify_trust_policy"
        )
    if now < _timestamp(verified_policy.verified_at, "trust policy verified_at"):
        raise PrincipalAuthenticationError("Authentication time precedes trust policy verification")
    requirement_count = validate_plan_replacement_authority_requirement_count(
        len(plan_document["assertion_requirements"])
    )
    plan_requirements = {
        item["requirement_id"]: item for item in plan_document["assertion_requirements"]
    }
    if len(plan_requirements) != requirement_count:
        raise CollaborationPlanError("Authority plan requirement identities are not unique")
    if len(credentials) != requirement_count:
        raise PrincipalAuthenticationError(
            f"Exactly {requirement_count} authority credentials are required"
        )
    source_ids = [item.source_requirement_id for item in credentials]
    upgraded_ids = [item.upgraded_requirement_id for item in credentials]
    replay_keys = [item.replay_key_sha256 for item in credentials]
    assertion_ids = [item.assertion.assertion_id for item in credentials]
    assertion_hashes = [item.assertion.content_sha256 for item in credentials]
    for values, label in (
        (source_ids, "source requirement"),
        (upgraded_ids, "upgraded requirement"),
        (replay_keys, "replay key"),
        (assertion_ids, "assertion ID"),
        (assertion_hashes, "assertion digest"),
    ):
        if len(values) != len(set(values)):
            raise PrincipalAuthenticationError(f"Each {label} must satisfy exactly one requirement")
    if set(source_ids) != set(plan_requirements):
        raise PrincipalAuthenticationError("Authority credential coverage is incomplete or extra")
    issued_at = _timestamp(plan_document["issued_at"], "authority plan issued_at")
    expires_at = _timestamp(plan_document["expires_at"], "authority plan expires_at")
    if not issued_at <= now < expires_at:
        raise PrincipalAuthenticationError("Authority plan is outside its validity window")

    authenticated: list[AuthenticatedPlanReplacementRequirement] = []
    for credential in sorted(credentials, key=lambda item: item.source_requirement_id):
        upgrade_requirement = upgraded_by_source[credential.source_requirement_id]
        if credential.upgraded_requirement_id != upgrade_requirement["requirement_id"]:
            raise PrincipalAuthenticationError("Upgraded requirement identity does not match")
        if credential.replay_key_sha256 != canonical_replay_keys[credential.source_requirement_id]:
            raise PrincipalAuthenticationError("Authority replay domain does not match")
        if credential.replay_key_sha256 in consumed_replay_keys:
            raise PrincipalAuthenticationError("Authority replay key was already consumed")
        grant = credential.scope_grant
        assertion = credential.assertion
        if grant.content_sha256 in revoked_scope_grant_sha256s:
            raise PrincipalAuthenticationError("Authority scope grant is revoked")
        if (
            grant.profile_id != upgrade_requirement["principal_profile_id"]
            or assertion.profile_id != upgrade_requirement["principal_profile_id"]
            or assertion.operation.value != upgrade_requirement["operation"]
            or assertion.operation_intent_sha256
            != upgrade_requirement["principal_operation_intent_sha256"]
            or assertion.mission_id != plan_document["mission_id"]
        ):
            raise PrincipalAuthenticationError("Authority credential requirement binding differs")
        assertion_issued = _timestamp(assertion.issued_at, "assertion issued_at")
        assertion_start = _timestamp(assertion.not_before, "assertion not_before")
        assertion_end = _timestamp(assertion.expires_at, "assertion expires_at")
        if (
            assertion_issued < issued_at
            or assertion_start < issued_at
            or assertion_end > expires_at
        ):
            raise PrincipalAuthenticationError(
                "Principal assertion exceeds the authority requirement validity window"
            )
        operation = PrincipalOperation(upgrade_requirement["operation"])
        verified_scope: VerifiedScopeGrant = verify_scope_grant(
            grant,
            verified_policy,
            expected_audience=scope_context.audience,
            expected_store_id=scope_context.store_id,
            expected_mission_id=plan_document["mission_id"],
            expected_mission_context_hash=scope_context.mission_context_hash,
            expected_scope_reference=scope_context.scope_reference,
            expected_scope_document_hash=scope_context.scope_document_hash,
            expected_environment=scope_context.environment,
            expected_max_action_tier=scope_context.max_action_tier,
            expected_constraints_hash=scope_context.constraints_hash,
            expected_operation=operation,
            clock=lambda: now,
        )
        principal = verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=scope_context.audience,
            expected_store_id=scope_context.store_id,
            expected_mission_id=plan_document["mission_id"],
            expected_operation=operation,
            expected_operation_intent_sha256=upgrade_requirement[
                "principal_operation_intent_sha256"
            ],
            clock=lambda: now,
        )
        authenticated.append(
            AuthenticatedPlanReplacementRequirement(
                source_requirement_id=credential.source_requirement_id,
                upgraded_requirement_id=credential.upgraded_requirement_id,
                replay_key_sha256=credential.replay_key_sha256,
                role=upgrade_requirement["role"],
                authority_id=upgrade_requirement["authority_id"],
                work_item_id=upgrade_requirement["work_item_id"],
                principal=principal,
            )
        )
    result = tuple(authenticated)
    _require_separation(result)
    return result


def _credential_material(
    credentials: tuple[CollaborationPlanReplacementAuthorityCredential, ...],
) -> list[dict[str, Any]]:
    return [
        {
            "source_requirement_id": item.source_requirement_id,
            "upgraded_requirement_id": item.upgraded_requirement_id,
            "replay_key_sha256": item.replay_key_sha256,
            "scope_grant": item.scope_grant.to_dict(),
            "assertion": item.assertion.to_dict(),
        }
        for item in credentials
    ]


def _result_material(
    requirements: tuple[AuthenticatedPlanReplacementRequirement, ...],
) -> list[dict[str, Any]]:
    return [
        {
            "source_requirement_id": item.source_requirement_id,
            "upgraded_requirement_id": item.upgraded_requirement_id,
            "replay_key_sha256": item.replay_key_sha256,
            "role": item.role,
            "authority_id": item.authority_id,
            "work_item_id": item.work_item_id,
            "principal": item.principal.to_dict(),
        }
        for item in requirements
    ]


def _build_verified_bundle_boundary() -> tuple[type[Any], Any, Any]:
    proof_key = secrets.token_bytes(32)
    construction_token = object()

    def material(value: Any) -> dict[str, Any]:
        verified_plan = object.__getattribute__(value, "_verified_plan")
        plan = validate_verified_collaboration_plan_replacement_authority_plan(verified_plan)
        upgrade_json = object.__getattribute__(value, "_upgrade_json")
        upgrade = CollaborationPlanReplacementAuthorityUpgrade.from_dict(json.loads(upgrade_json))
        credentials = tuple(
            _normalize_credential(item) for item in object.__getattribute__(value, "_credentials")
        )
        requirements = object.__getattribute__(value, "_requirements")
        requirement_count = validate_plan_replacement_authority_requirement_count(
            len(plan.to_dict()["assertion_requirements"])
        )
        if type(requirements) is not tuple or len(requirements) != requirement_count:
            raise TypeError("verified authority bundle requirements are invalid")
        for item in requirements:
            if (
                not isinstance(item, AuthenticatedPlanReplacementRequirement)
                or not isinstance(item.principal, VerifiedPrincipal)
                or not item.principal._proof_is_valid()
            ):
                raise TypeError("verified authority bundle principal proof is invalid")
        authenticated_at = object.__getattribute__(value, "_authenticated_at")
        _timestamp(authenticated_at, "authenticated_at")
        policy_sha256 = _sha256(
            object.__getattribute__(value, "_policy_sha256"),
            "policy_sha256",
        )
        context = object.__getattribute__(value, "_scope_context")
        if not isinstance(context, _ScopeContext):
            raise TypeError("verified authority bundle scope context is invalid")
        credentials_by_source = {item.source_requirement_id: item for item in credentials}
        upgrade_requirements = upgrade.to_dict()["authority_requirements"]
        upgrade_by_source = {item["source_requirement_id"]: item for item in upgrade_requirements}
        plan_source_ids = {
            item["requirement_id"] for item in plan.to_dict()["assertion_requirements"]
        }
        requirement_source_ids = {item.source_requirement_id for item in requirements}
        if (
            len(credentials) != requirement_count
            or len(credentials_by_source) != requirement_count
            or len(upgrade_requirements) != requirement_count
            or len(upgrade_by_source) != requirement_count
            or len(requirement_source_ids) != requirement_count
            or set(credentials_by_source) != plan_source_ids
            or set(upgrade_by_source) != plan_source_ids
            or requirement_source_ids != plan_source_ids
        ):
            raise TypeError("verified authority bundle coverage is invalid")
        for item in requirements:
            try:
                credential = credentials_by_source[item.source_requirement_id]
                upgraded = upgrade_by_source[item.source_requirement_id]
            except KeyError as exc:
                raise TypeError("verified authority bundle coverage is invalid") from exc
            principal = item.principal
            if (
                item.upgraded_requirement_id != credential.upgraded_requirement_id
                or item.upgraded_requirement_id != upgraded["requirement_id"]
                or item.replay_key_sha256 != credential.replay_key_sha256
                or item.role != upgraded["role"]
                or item.authority_id != upgraded["authority_id"]
                or item.work_item_id != upgraded["work_item_id"]
                or principal.assertion_id != credential.assertion.assertion_id
                or principal.assertion_sha256 != credential.assertion.content_sha256
                or principal.scope_grant_id != credential.scope_grant.grant_id
                or principal.scope_grant_sha256 != credential.scope_grant.content_sha256
                or principal.profile_id != upgraded["principal_profile_id"]
                or principal.operation.value != upgraded["operation"]
                or principal.operation_intent_sha256
                != upgraded["principal_operation_intent_sha256"]
                or principal.policy_sha256 != policy_sha256
                or principal.mission_id != plan.to_dict()["mission_id"]
                or principal.audience != context.audience
                or principal.store_id != context.store_id
            ):
                raise TypeError("verified authority bundle requirement binding is invalid")
        return {
            "domain": AUTHENTICATION_DOMAIN,
            "authority_plan_id": plan.authority_plan_id,
            "authority_plan_sha256": plan.authority_plan_sha256,
            "authority_plan_document_sha256": plan.document_sha256,
            "authority_plan_verified_at": verified_plan.verified_at,
            "upgrade_id": upgrade.upgrade_id,
            "upgrade_sha256": upgrade.upgrade_sha256,
            "upgrade_json": upgrade_json,
            "credentials": _credential_material(credentials),
            "requirements": _result_material(requirements),
            "policy_sha256": policy_sha256,
            "composition_sha256": _sha256(
                object.__getattribute__(value, "_composition_sha256"),
                "composition_sha256",
            ),
            "authenticated_at": authenticated_at,
            "scope_context": {
                "audience": context.audience,
                "store_id": context.store_id,
                "mission_context_hash": context.mission_context_hash,
                "scope_reference": context.scope_reference,
                "scope_document_hash": context.scope_document_hash,
                "environment": (
                    context.environment.value
                    if isinstance(context.environment, MissionEnvironment)
                    else context.environment
                ),
                "max_action_tier": (
                    context.max_action_tier.value
                    if isinstance(context.max_action_tier, ActionTier)
                    else context.max_action_tier
                ),
                "constraints_hash": context.constraints_hash,
            },
        }

    def proof_for(value: Any, body: dict[str, Any]) -> bytes:
        return hmac.new(
            proof_key,
            (_canonical_json({"instance_id": id(value), "bundle": body})).encode("utf-8"),
            "sha256",
        ).digest()

    def validate_instance(value: Any) -> dict[str, Any]:
        if type(value) is not VerifiedBundle:
            raise TypeError("bundle must come from exact replacement authority authentication")
        try:
            body = material(value)
            proof = object.__getattribute__(value, "_proof")
        except (AttributeError, TypeError, ValueError) as exc:
            raise TypeError("verified authority bundle material is invalid") from exc
        if not isinstance(proof, bytes) or not hmac.compare_digest(proof, proof_for(value, body)):
            raise TypeError("verified authority bundle proof is invalid")
        return body

    class VerifiedBundle:
        """Opaque process-local proof of complete replacement authority authentication."""

        __slots__ = (
            "_authenticated_at",
            "_composition_sha256",
            "_credentials",
            "_policy_sha256",
            "_proof",
            "_requirements",
            "_scope_context",
            "_upgrade_json",
            "_verified_plan",
        )

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise TypeError(
                "VerifiedCollaborationPlanReplacementAuthorityBundle can be created only by "
                "authenticate_collaboration_plan_replacement_authority"
            )

        @property
        def authority_plan_id(self) -> str:
            return str(validate_instance(self)["authority_plan_id"])

        @property
        def upgrade_id(self) -> str:
            return str(validate_instance(self)["upgrade_id"])

        @property
        def policy_sha256(self) -> str:
            return str(validate_instance(self)["policy_sha256"])

        @property
        def authenticated_at(self) -> str:
            return str(validate_instance(self)["authenticated_at"])

        @property
        def composition_sha256(self) -> str:
            return str(validate_instance(self)["composition_sha256"])

        @property
        def requirement_count(self) -> int:
            validate_instance(self)
            return len(object.__getattribute__(self, "_requirements"))

        @property
        def replay_keys(self) -> tuple[str, ...]:
            validate_instance(self)
            requirements = object.__getattribute__(self, "_requirements")
            return tuple(item.replay_key_sha256 for item in requirements)

        @property
        def assertion_identities(self) -> tuple[tuple[str, str, str], ...]:
            """Return exact signed assertion identities for atomic consumption."""

            validate_instance(self)
            requirements = object.__getattribute__(self, "_requirements")
            return tuple(
                (
                    item.principal.issuer,
                    item.principal.assertion_id,
                    item.principal.assertion_sha256,
                )
                for item in requirements
            )

        @property
        def requirements(self) -> tuple[AuthenticatedPlanReplacementRequirement, ...]:
            validate_instance(self)
            return tuple(object.__getattribute__(self, "_requirements"))

        def __repr__(self) -> str:
            body = validate_instance(self)
            return (
                "VerifiedCollaborationPlanReplacementAuthorityBundle("
                f"authority_plan_id={body['authority_plan_id']!r}, "
                f"upgrade_id={body['upgrade_id']!r}, "
                f"authenticated_at={body['authenticated_at']!r})"
            )

    def issue(
        *,
        verified_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
        upgrade: CollaborationPlanReplacementAuthorityUpgrade,
        credentials: tuple[CollaborationPlanReplacementAuthorityCredential, ...],
        requirements: tuple[AuthenticatedPlanReplacementRequirement, ...],
        policy_sha256: str,
        composition_sha256: str,
        authenticated_at: str,
        scope_context: _ScopeContext,
        token: object,
    ) -> Any:
        if token is not construction_token:
            raise TypeError("verified authority bundle issuance is unavailable")
        value = object.__new__(VerifiedBundle)
        object.__setattr__(value, "_verified_plan", verified_plan)
        object.__setattr__(value, "_upgrade_json", _canonical_json(upgrade.to_dict()))
        object.__setattr__(value, "_credentials", credentials)
        object.__setattr__(value, "_requirements", requirements)
        object.__setattr__(value, "_policy_sha256", policy_sha256)
        object.__setattr__(value, "_composition_sha256", composition_sha256)
        object.__setattr__(value, "_authenticated_at", authenticated_at)
        object.__setattr__(value, "_scope_context", scope_context)
        object.__setattr__(value, "_proof", b"")
        body = material(value)
        object.__setattr__(value, "_proof", proof_for(value, body))
        validate_instance(value)
        return value

    def authenticate(
        verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
        authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
        *,
        preflight: CollaborationPlanReplacementPreflight,
        army_registry: ExpertRegistry,
        credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
        verified_policy: VerifiedTrustPolicy,
        expected_audience: str,
        expected_store_id: str,
        expected_mission_context_hash: str,
        expected_scope_reference: str,
        expected_scope_document_hash: str,
        expected_environment: MissionEnvironment | str,
        expected_max_action_tier: ActionTier | str,
        expected_constraints_hash: str,
        revoked_scope_grant_sha256s: Collection[str],
        consumed_replay_keys: Collection[str],
        clock: Callable[[], datetime],
    ) -> Any:
        normalized_credentials = _normalize_credentials(credentials)
        revoked = _digest_collection(
            revoked_scope_grant_sha256s,
            "revoked_scope_grant_sha256s",
        )
        consumed = _digest_collection(consumed_replay_keys, "consumed_replay_keys")
        now = _clock_value(clock)
        (
            plan_document,
            _upgrade_document,
            upgraded_by_source,
            canonical_replay_keys,
            composition_sha256,
        ) = _validate_source_composition(
            verified_authority_plan,
            authority_upgrade,
            preflight=preflight,
            army_registry=army_registry,
        )
        if now < _timestamp(
            verified_authority_plan.verified_at,
            "authority plan verified_at",
        ):
            raise PrincipalAuthenticationError(
                "Authentication time precedes authority plan verification"
            )
        scope_context = _ScopeContext(
            audience=expected_audience,
            store_id=expected_store_id,
            mission_context_hash=expected_mission_context_hash,
            scope_reference=expected_scope_reference,
            scope_document_hash=expected_scope_document_hash,
            environment=expected_environment,
            max_action_tier=expected_max_action_tier,
            constraints_hash=expected_constraints_hash,
        )
        requirements = _verify_credentials(
            plan_document=plan_document,
            upgraded_by_source=upgraded_by_source,
            credentials=normalized_credentials,
            canonical_replay_keys=canonical_replay_keys,
            verified_policy=verified_policy,
            scope_context=scope_context,
            revoked_scope_grant_sha256s=revoked,
            consumed_replay_keys=consumed,
            now=now,
        )
        return issue(
            verified_plan=verified_authority_plan,
            upgrade=authority_upgrade,
            credentials=normalized_credentials,
            requirements=requirements,
            policy_sha256=verified_policy.policy_sha256,
            composition_sha256=composition_sha256,
            authenticated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            scope_context=scope_context,
            token=construction_token,
        )

    def validate_at_point_of_use(
        bundle: Any,
        *,
        verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
        authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
        preflight: CollaborationPlanReplacementPreflight,
        army_registry: ExpertRegistry,
        verified_policy: VerifiedTrustPolicy,
        revoked_scope_grant_sha256s: Collection[str],
        consumed_replay_keys: Collection[str],
        clock: Callable[[], datetime],
    ) -> Any:
        prior = validate_instance(bundle)
        now = _clock_value(clock)
        if now < _timestamp(prior["authenticated_at"], "authenticated_at"):
            raise PrincipalAuthenticationError("Point-of-use time precedes bundle authentication")
        context = object.__getattribute__(bundle, "_scope_context")
        credentials = object.__getattribute__(bundle, "_credentials")
        refreshed = authenticate(
            verified_authority_plan,
            authority_upgrade,
            preflight=preflight,
            army_registry=army_registry,
            credentials=credentials,
            verified_policy=verified_policy,
            expected_audience=context.audience,
            expected_store_id=context.store_id,
            expected_mission_context_hash=context.mission_context_hash,
            expected_scope_reference=context.scope_reference,
            expected_scope_document_hash=context.scope_document_hash,
            expected_environment=context.environment,
            expected_max_action_tier=context.max_action_tier,
            expected_constraints_hash=context.constraints_hash,
            revoked_scope_grant_sha256s=revoked_scope_grant_sha256s,
            consumed_replay_keys=consumed_replay_keys,
            clock=lambda: now,
        )
        current = validate_instance(refreshed)
        stable_fields = (
            "authority_plan_id",
            "authority_plan_sha256",
            "authority_plan_document_sha256",
            "upgrade_id",
            "upgrade_sha256",
            "upgrade_json",
            "credentials",
            "policy_sha256",
            "composition_sha256",
            "scope_context",
        )
        if any(prior[field] != current[field] for field in stable_fields):
            raise PrincipalAuthenticationError(
                "Replacement authority bundle source or trust generation has drifted"
            )
        return refreshed

    VerifiedBundle.__name__ = "VerifiedCollaborationPlanReplacementAuthorityBundle"
    VerifiedBundle.__qualname__ = "VerifiedCollaborationPlanReplacementAuthorityBundle"
    authenticate.__name__ = "authenticate_collaboration_plan_replacement_authority"
    validate_at_point_of_use.__name__ = (
        "validate_verified_collaboration_plan_replacement_authority_bundle"
    )
    return VerifiedBundle, authenticate, validate_at_point_of_use


(
    VerifiedCollaborationPlanReplacementAuthorityBundle,
    authenticate_collaboration_plan_replacement_authority,
    validate_verified_collaboration_plan_replacement_authority_bundle,
) = _build_verified_bundle_boundary()
del _build_verified_bundle_boundary


__all__ = [
    "AUTHENTICATION_DOMAIN",
    "COMPOSITION_DOMAIN",
    "EXPECTED_REQUIREMENT_COUNT",
    "MAX_AUTHORITY_REQUIREMENT_COUNT",
    "REPLAY_KEY_DOMAIN",
    "AuthenticatedPlanReplacementRequirement",
    "CollaborationPlanReplacementAuthorityCredential",
    "VerifiedCollaborationPlanReplacementAuthorityBundle",
    "authenticate_collaboration_plan_replacement_authority",
    "collaboration_plan_replacement_authority_replay_keys",
    "validate_verified_collaboration_plan_replacement_authority_bundle",
    "validate_plan_replacement_authority_requirement_count",
]
