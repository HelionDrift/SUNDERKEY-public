"""Atomic signed-principal collaboration plan replacement."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from itertools import islice
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .collaboration import CollaborationPlan
from .collaboration_plan_replacement_authentication import (
    CollaborationPlanReplacementAuthorityCredential,
    VerifiedCollaborationPlanReplacementAuthorityBundle,
    collaboration_plan_replacement_authority_replay_keys,
    validate_plan_replacement_authority_requirement_count,
    validate_verified_collaboration_plan_replacement_authority_bundle,
)
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
from .collaboration_plan_replacement_store import (
    CollaborationPlanReplacementCommitReceipt,
    CollaborationPlanReplacementStoreService,
    ReplacementAuthorityEvidence,
    VerifiedReplacementAuthority,
)
from .errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    TrustKeyUse,
    _verify_ed25519,
    _verify_policy_key,
    compute_operation_intent_hash,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)

AUTHENTICATION_CUSTODY_DOMAIN = "sunderkey.collaboration-plan-replacement-authentication-custody.v1"
AUTHORITY_EVIDENCE_DOMAIN = "sunderkey.collaboration-plan-replacement-signed-authority-evidence.v1"
AUTHORITY_EFFECT_DOMAIN = "sunderkey.collaboration-plan-replacement-signed-authority-effect.v1"
_REVIEWER_ROLES = frozenset({"independent_control", "independent_assurance", "second_control"})


def _canonical_sha256(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _normalize_credentials(
    credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
    *,
    requirement_count: int,
) -> tuple[CollaborationPlanReplacementAuthorityCredential, ...]:
    validate_plan_replacement_authority_requirement_count(requirement_count)
    if isinstance(credentials, (str, bytes)):
        raise PrincipalAuthenticationError("credentials must be an iterable")
    try:
        result = tuple(
            CollaborationPlanReplacementAuthorityCredential(
                source_requirement_id=item.source_requirement_id,
                upgraded_requirement_id=item.upgraded_requirement_id,
                replay_key_sha256=item.replay_key_sha256,
                scope_grant=ScopeGrant.from_dict(item.scope_grant.to_dict()),
                assertion=PrincipalAssertion.from_dict(item.assertion.to_dict()),
            )
            for item in islice(credentials, requirement_count + 1)
        )
    except (AttributeError, TypeError) as exc:
        raise PrincipalAuthenticationError("credentials are invalid") from exc
    if len(result) != requirement_count:
        raise PrincipalAuthenticationError(
            f"Exactly {requirement_count} source-derived authority credentials are required"
        )
    source_ids = [item.source_requirement_id for item in result]
    if len(source_ids) != len(set(source_ids)):
        raise PrincipalAuthenticationError("Authority credentials are duplicated")
    return tuple(sorted(result, key=lambda item: item.source_requirement_id))


def _principal_intent(
    requirement: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> dict[str, Any]:
    intent: dict[str, Any] = {
        "authority_intent_sha256": requirement["authority_intent_sha256"],
        "mission_id": preflight["mission_id"],
        "principal_profile_id": requirement["principal_profile_id"],
        "prior_plan_id": preflight["prior_plan"]["plan_id"],
        "prior_plan_sha256": preflight["prior_plan"]["plan_sha256"],
        "replacement_plan_id": preflight["replacement_plan"]["plan_id"],
        "replacement_plan_sha256": preflight["replacement_plan"]["plan_sha256"],
        "role": requirement["role"],
        "selection_sha256": requirement["selection_sha256"],
        "work_item_id": requirement["work_item_id"],
    }
    command_binding = requirement.get("command_authority_binding_sha256")
    if command_binding is not None:
        intent["command_authority_binding_sha256"] = command_binding
    return intent


def _evidence(
    *,
    credential: CollaborationPlanReplacementAuthorityCredential,
    bundle: VerifiedCollaborationPlanReplacementAuthorityBundle,
) -> ReplacementAuthorityEvidence:
    document = {
        "schema_version": 1,
        "domain": AUTHORITY_EVIDENCE_DOMAIN,
        "authority_plan_id": bundle.authority_plan_id,
        "authority_upgrade_id": bundle.upgrade_id,
        "composition_sha256": bundle.composition_sha256,
        "source_requirement_id": credential.source_requirement_id,
        "upgraded_requirement_id": credential.upgraded_requirement_id,
        "canonical_replay_key_sha256": credential.replay_key_sha256,
        "scope_grant": credential.scope_grant.to_dict(),
        "assertion": credential.assertion.to_dict(),
    }
    return ReplacementAuthorityEvidence.from_dict(
        {
            "requirement_id": credential.source_requirement_id,
            "evidence_id": credential.assertion.assertion_id,
            "evidence_sha256": _canonical_sha256(document),
            "evidence": document,
        }
    )


def _require_current_reviewer_admissions(
    connection: sqlite3.Connection,
    *,
    store: MissionStore,
    registry: ExpertRegistry,
    mission: Any,
    trust_policies: Mapping[str, Any],
    scope_grants: Mapping[str, Any],
    preflight: CollaborationPlanReplacementPreflight,
    credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
    at: datetime,
) -> None:
    from .plan_replacement_reviewer_admission import (
        verify_plan_replacement_reviewer_admission_for_use,
    )

    roles = {
        item["requirement_id"]: item["role"]
        for item in preflight.to_dict()["authority_requirements"]
        if item["role"] in _REVIEWER_ROLES
    }
    if len(roles) != len(_REVIEWER_ROLES) or set(roles.values()) != _REVIEWER_ROLES:
        raise PrincipalAuthenticationError("Replacement requires all three admitted reviewer roles")
    matched = set()
    for credential in credentials:
        role = roles.get(credential.source_requirement_id)
        if role is None:
            continue
        request = verify_plan_replacement_reviewer_admission_for_use(
            connection,
            store=store,
            mission=mission,
            registry=registry,
            trust_policies=trust_policies,
            scope_grants=scope_grants,
            grant=credential.scope_grant,
            role=role,
            at=at,
        )
        reviewer = request.to_dict()["reviewer"]
        assertion = credential.assertion
        if (
            reviewer["issuer"] != assertion.issuer
            or reviewer["subject"] != assertion.subject
            or reviewer["profile_id"] != assertion.profile_id
            or reviewer["role"] != role
            or reviewer["scope_grant_sha256"] != credential.scope_grant.content_sha256
            or canonical_json(reviewer["scope_grant"])
            != canonical_json(credential.scope_grant.to_dict())
        ):
            raise PrincipalAuthenticationError(
                "Replacement reviewer assertion differs from admission"
            )
        matched.add(credential.source_requirement_id)
    if matched != set(roles):
        raise PrincipalAuthenticationError("Replacement admitted reviewer coverage is incomplete")


def _verify_authenticated_replacement_replay_state(
    connection: sqlite3.Connection,
    *,
    store: MissionStore,
    registry: ExpertRegistry,
    preflight: CollaborationPlanReplacementPreflight,
    credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
    at: datetime,
) -> None:
    """Verify historical approval custody and current grant/admission eligibility.

    Assertion validity is verified by the historical ledger at consumption time,
    not renewed here. No new assertion use or replacement effect is produced.
    """
    document = preflight.to_dict()
    source_ids = {item["requirement_id"] for item in document["authority_requirements"]}
    parsed = _normalize_credentials(credentials, requirement_count=len(source_ids))
    if {item.source_requirement_id for item in parsed} != source_ids:
        raise PrincipalAuthenticationError("Replacement replay authority coverage is stale")
    expected = sorted(
        (
            item.source_requirement_id,
            item.upgraded_requirement_id,
            item.replay_key_sha256,
            _canonical_sha256(
                {
                    "source_requirement_id": item.source_requirement_id,
                    "upgraded_requirement_id": item.upgraded_requirement_id,
                    "canonical_replay_key_sha256": item.replay_key_sha256,
                    "scope_grant": item.scope_grant.to_dict(),
                    "assertion": item.assertion.to_dict(),
                }
            ),
        )
        for item in parsed
    )
    durable = [
        tuple(row)
        for row in connection.execute(
            """
            SELECT source_requirement_id, upgraded_requirement_id,
                   canonical_replay_key_sha256, credential_sha256
            FROM collaboration_plan_replacement_authority_consumptions
            WHERE preflight_id = ? ORDER BY source_requirement_id
            """,
            (preflight.preflight_id,),
        ).fetchall()
    ]
    if durable != expected:
        raise PrincipalAuthenticationError(
            "Replacement replay credentials differ from signed custody"
        )
    identity, trust_policies, mission, scope_grants = AuthenticatedMissionControlService(
        store, registry, clock=lambda: at
    )._verified_mission_state(connection, document["mission_id"])
    policy_hash = identity["trust_policy_hash"]
    policy = trust_policies.get(str(policy_hash)) if policy_hash is not None else None
    if policy is None:
        raise StoreIntegrityError("Current replacement replay trust policy is missing")
    if store._trust_policy_high_water_at(trust_policies, at).policy_sha256 != policy.policy_sha256:
        raise PrincipalAuthenticationError("Replacement replay clock precedes current trust policy")
    for credential in parsed:
        accepted = scope_grants.get(credential.scope_grant.content_sha256)
        if accepted is None:
            raise PrincipalAuthenticationError("Replacement replay scope grant is not accepted")
        row, grant = accepted
        if (
            canonical_json(grant.to_dict()) != canonical_json(credential.scope_grant.to_dict())
            or parse_timestamp(str(row["accepted_at"]), "replacement scope accepted_at") > at
            or store._effective_scope_grant_revocation(connection, row) is not None
        ):
            raise PrincipalAuthenticationError("Replacement replay scope grant is stale or revoked")
        assertion = credential.assertion
        key = _verify_policy_key(
            policy,
            key_id=assertion.key_id,
            required_key_use=TrustKeyUse.PRINCIPAL_ASSERTION,
            issuer=assertion.issuer,
            profile_id=assertion.profile_id,
            subject=assertion.subject,
            operations=(assertion.operation,),
            issued_at=assertion.issued_at,
            now=at,
        )
        _verify_ed25519(
            key.ed25519_public_key(),
            assertion.signature,
            assertion.signing_bytes(),
            "Replacement replay principal assertion",
        )
        verify_scope_grant(
            grant,
            policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=document["mission_id"],
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=mission.mission.scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.mission.to_dict()["constraints"])
            ),
            expected_operation=credential.assertion.operation,
            clock=lambda: at,
        )
    _require_current_reviewer_admissions(
        connection,
        store=store,
        registry=registry,
        mission=mission,
        trust_policies=trust_policies,
        scope_grants=scope_grants,
        preflight=preflight,
        credentials=parsed,
        at=at,
    )


class _TransactionScopedReplacementAuthorityVerifier:
    """Ephemeral verifier that owns one replacement transaction only."""

    def __init__(
        self,
        *,
        store: MissionStore,
        registry: ExpertRegistry,
        preflight: CollaborationPlanReplacementPreflight,
        verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
        authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
        bundle: VerifiedCollaborationPlanReplacementAuthorityBundle,
        credentials: tuple[CollaborationPlanReplacementAuthorityCredential, ...],
    ) -> None:
        self._store = store
        self._registry = registry
        self._preflight = preflight
        self._verified_authority_plan = verified_authority_plan
        self._authority_upgrade = authority_upgrade
        self._bundle = bundle
        self._credentials = {item.source_requirement_id: item for item in credentials}
        self._connection_identity: int | None = None
        self._consumed_at: str | None = None
        self._prepared = False
        self._used_requirements: set[str] = set()
        self._requirements_by_source: dict[str, dict[str, Any]] = {}
        self._principals_by_source: dict[str, Any] = {}
        self._mission: Any = None
        self._identity: sqlite3.Row | None = None
        self._trust_policies: dict[str, Any] = {}
        self._scope_grants: dict[str, Any] = {}
        self._requirement_count: int | None = None

    def _require_call_scope(
        self,
        connection: sqlite3.Connection,
        consumed_at: str,
    ) -> None:
        connection_identity = id(connection)
        if self._connection_identity is None:
            self._connection_identity = connection_identity
            self._consumed_at = consumed_at
        elif self._connection_identity != connection_identity or self._consumed_at != consumed_at:
            raise PrincipalAuthenticationError(
                "Replacement authority verifier cannot cross transactions"
            )

    def _prepare(
        self,
        connection: sqlite3.Connection,
        consumed_at: str,
    ) -> None:
        if self._prepared:
            return
        self._require_call_scope(connection, consumed_at)
        now = parse_timestamp(consumed_at, "replacement authority consumed_at")
        mission_id = self._preflight.to_dict()["mission_id"]
        mission_control = AuthenticatedMissionControlService(
            self._store,
            self._registry,
            clock=lambda: now,
        )
        identity, trust_policies, mission, scope_grants = mission_control._verified_mission_state(
            connection, mission_id
        )
        preflight_document = self._preflight.to_dict()
        policy_commit = preflight_document["mission_policy_commit"]
        policy_row = connection.execute(
            """
            SELECT policy.*, owner_use.assertion_hash AS owner_assertion_hash,
                   owner_use.entry_hash AS owner_entry_hash,
                   control_use.assertion_hash AS control_assertion_hash,
                   control_use.entry_hash AS control_entry_hash
            FROM collaboration_mission_policy_commits AS policy
            JOIN principal_assertion_uses AS owner_use
              ON owner_use.issuer = policy.owner_issuer
             AND owner_use.assertion_id = policy.owner_assertion_id
            JOIN principal_assertion_uses AS control_use
              ON control_use.issuer = policy.control_issuer
             AND control_use.assertion_id = policy.control_assertion_id
            WHERE policy.mission_id = ?
            ORDER BY policy.policy_version DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if policy_row is None:
            raise PrincipalAuthenticationError(
                "Replacement mission policy has no durable authenticated commit"
            )
        prior_plan = preflight_document["prior_plan"]
        if (
            policy_row["policy_id"] != policy_commit["policy_id"]
            or policy_row["policy_sha256"] != policy_commit["policy_sha256"]
            or policy_row["selection_sha256"] != policy_commit["policy_selection_sha256"]
            or policy_row["authentication_id"] != policy_commit["authentication_id"]
            or policy_row["authentication_sha256"] != policy_commit["authentication_sha256"]
            or policy_row["committed_at"] != policy_commit["committed_at"]
            or policy_row["owner_assertion_id"] != policy_commit["mission_owner_assertion_id"]
            or policy_row["owner_assertion_hash"] != policy_commit["mission_owner_assertion_sha256"]
            or policy_row["owner_entry_hash"] != policy_commit["mission_owner_ledger_entry_sha256"]
            or policy_row["control_assertion_id"]
            != policy_commit["independent_control_assertion_id"]
            or policy_row["control_assertion_hash"]
            != policy_commit["independent_control_assertion_sha256"]
            or policy_row["control_entry_hash"]
            != policy_commit["independent_control_ledger_entry_sha256"]
            or policy_row["plan_id"] != prior_plan["plan_id"]
            or policy_row["plan_content_sha256"] != prior_plan["plan_sha256"]
            or parse_timestamp(
                str(policy_row["committed_at"]),
                "collaboration_mission_policy_commits.committed_at",
            )
            > now
        ):
            raise PrincipalAuthenticationError(
                "Replacement mission policy commit is not the current durable commit"
            )
        ledger = connection.execute(
            "SELECT updated_at FROM mission_principal_ledgers WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if ledger is None:
            raise StoreIntegrityError("Mission principal ledger is missing")
        if parse_timestamp(str(ledger["updated_at"]), "mission_principal_ledger.updated_at") > now:
            raise PrincipalAuthenticationError("Runtime clock precedes the principal ledger")
        current_policy_hash = identity["trust_policy_hash"]
        if current_policy_hash is None:
            raise StoreConflictError("A current trust policy is required")
        verified_policy = trust_policies.get(str(current_policy_hash))
        if verified_policy is None:
            raise StoreIntegrityError("Current trust policy is missing from history")
        if (
            self._store._trust_policy_high_water_at(trust_policies, now).policy_sha256
            != verified_policy.policy_sha256
        ):
            raise PrincipalAuthenticationError("Runtime clock precedes the current trust policy")

        revoked: set[str] = set()
        for credential in self._credentials.values():
            stored_scope = scope_grants.get(credential.scope_grant.content_sha256)
            if stored_scope is None:
                raise PrincipalAuthenticationError(
                    "Replacement authority scope grant is not durably accepted"
                )
            scope_row, stored_grant = stored_scope
            if (
                canonical_json(stored_grant.to_dict())
                != canonical_json(credential.scope_grant.to_dict())
                or parse_timestamp(str(scope_row["accepted_at"]), "mission_scope_grant.accepted_at")
                > now
            ):
                raise PrincipalAuthenticationError(
                    "Replacement authority scope grant binding is stale"
                )
            effective_revocation = self._store._effective_scope_grant_revocation(
                connection, scope_row
            )
            if effective_revocation is not None:
                revoked.add(credential.scope_grant.content_sha256)

        replay_keys = tuple(item.replay_key_sha256 for item in self._credentials.values())
        placeholders = ", ".join("?" for _ in replay_keys)
        consumed_replays = {
            str(row[0])
            for row in connection.execute(
                f"""
                SELECT canonical_replay_key_sha256
                FROM collaboration_plan_replacement_authority_consumptions
                WHERE canonical_replay_key_sha256 IN ({placeholders})
                """,
                replay_keys,
            ).fetchall()
        }
        for credential in self._credentials.values():
            existing = connection.execute(
                """
                SELECT assertion_hash FROM principal_assertion_uses
                WHERE issuer = ? AND assertion_id = ?
                """,
                (credential.assertion.issuer, credential.assertion.assertion_id),
            ).fetchone()
            if existing is not None:
                raise PrincipalAuthenticationError(
                    "Replacement authority assertion was already consumed"
                )

        refreshed = validate_verified_collaboration_plan_replacement_authority_bundle(
            self._bundle,
            verified_authority_plan=self._verified_authority_plan,
            authority_upgrade=self._authority_upgrade,
            preflight=self._preflight,
            army_registry=self._registry,
            verified_policy=verified_policy,
            revoked_scope_grant_sha256s=revoked,
            consumed_replay_keys=consumed_replays,
            clock=lambda: now,
        )
        principals = {item.source_requirement_id: item for item in refreshed.requirements}
        if set(principals) != set(self._credentials):
            raise PrincipalAuthenticationError("Replacement authority credential coverage changed")
        for source_id, credential in self._credentials.items():
            authenticated = principals[source_id]
            if (
                authenticated.upgraded_requirement_id != credential.upgraded_requirement_id
                or authenticated.replay_key_sha256 != credential.replay_key_sha256
                or authenticated.principal.issuer != credential.assertion.issuer
                or authenticated.principal.assertion_id != credential.assertion.assertion_id
                or authenticated.principal.assertion_sha256 != credential.assertion.content_sha256
                or authenticated.principal.scope_grant_sha256
                != credential.scope_grant.content_sha256
            ):
                raise PrincipalAuthenticationError(
                    "Replacement authority credential differs from the verified bundle"
                )

        plan = validate_verified_collaboration_plan_replacement_authority_plan(
            self._verified_authority_plan
        )
        upgrade = verify_collaboration_plan_replacement_authority_upgrade(
            self._authority_upgrade,
            preflight=self._preflight,
            army_registry=self._registry,
        )
        plan_document = plan.to_dict()
        upgrade_document = upgrade.to_dict()
        canonical_replays = collaboration_plan_replacement_authority_replay_keys(
            self._verified_authority_plan,
            upgrade,
            preflight=self._preflight,
            army_registry=self._registry,
        )
        requirement_count = validate_plan_replacement_authority_requirement_count(
            len(canonical_replays)
        )
        if (
            refreshed.requirement_count != requirement_count
            or len(principals) != requirement_count
            or set(self._credentials) != set(canonical_replays)
            or any(
                credential.replay_key_sha256 != canonical_replays[source_id]
                for source_id, credential in self._credentials.items()
            )
        ):
            raise PrincipalAuthenticationError(
                "Replacement source-derived authority coverage changed"
            )
        _require_current_reviewer_admissions(
            connection,
            store=self._store,
            registry=self._registry,
            mission=mission,
            trust_policies=trust_policies,
            scope_grants=scope_grants,
            preflight=self._preflight,
            credentials=self._credentials.values(),
            at=now,
        )
        self._requirements_by_source = {
            str(item["source_requirement_id"]): item
            for item in upgrade_document["authority_requirements"]
        }
        authentication_body = {
            "schema_version": 1,
            "domain": AUTHENTICATION_CUSTODY_DOMAIN,
            "preflight_id": self._preflight.preflight_id,
            "mission_id": mission_id,
            "authority_plan_id": plan.authority_plan_id,
            "authority_plan_sha256": plan.authority_plan_sha256,
            "authority_plan_document_sha256": plan.document_sha256,
            "authority_upgrade_id": upgrade.upgrade_id,
            "authority_upgrade_sha256": upgrade.upgrade_sha256,
            "composition_sha256": refreshed.composition_sha256,
            "trust_policy_id": verified_policy.policy.policy_id,
            "trust_policy_version": verified_policy.policy.policy_version,
            "trust_policy_sha256": verified_policy.policy_sha256,
            "authenticated_at": refreshed.authenticated_at,
            "consumed_at": consumed_at,
            "requirement_count": requirement_count,
        }
        connection.execute(
            """
            INSERT INTO collaboration_plan_replacement_authentications(
                preflight_id, mission_id, authority_plan_id,
                authority_plan_sha256, authority_plan_json,
                authority_upgrade_id, authority_upgrade_sha256,
                authority_upgrade_json, composition_sha256,
                trust_policy_id, trust_policy_version, trust_policy_sha256,
                authenticated_at, consumed_at, requirement_count,
                authentication_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._preflight.preflight_id,
                mission_id,
                plan.authority_plan_id,
                plan.authority_plan_sha256,
                canonical_json(plan_document),
                upgrade.upgrade_id,
                upgrade.upgrade_sha256,
                canonical_json(upgrade_document),
                refreshed.composition_sha256,
                verified_policy.policy.policy_id,
                verified_policy.policy.policy_version,
                verified_policy.policy_sha256,
                refreshed.authenticated_at,
                consumed_at,
                requirement_count,
                _canonical_sha256(authentication_body),
            ),
        )
        self._bundle = refreshed
        self._principals_by_source = principals
        self._mission = mission
        self._identity = identity
        self._trust_policies = trust_policies
        self._scope_grants = scope_grants
        self._requirement_count = requirement_count
        self._prepared = True

    def verify(
        self,
        connection: sqlite3.Connection,
        *,
        requirement: Mapping[str, Any],
        evidence: ReplacementAuthorityEvidence,
        consumed_at: str,
    ) -> VerifiedReplacementAuthority:
        self._require_call_scope(connection, consumed_at)
        self._prepare(connection, consumed_at)
        source_id = str(requirement.get("requirement_id"))
        if source_id in self._used_requirements:
            raise PrincipalAuthenticationError(
                "Replacement authority requirement was verified twice"
            )
        credential = self._credentials.get(source_id)
        upgraded = self._requirements_by_source.get(source_id)
        authenticated = self._principals_by_source.get(source_id)
        if credential is None or upgraded is None or authenticated is None:
            raise PrincipalAuthenticationError(
                "Replacement authority requirement is not authenticated"
            )
        expected_evidence = _evidence(credential=credential, bundle=self._bundle)
        if expected_evidence.to_dict() != evidence.to_dict():
            raise PrincipalAuthenticationError(
                "Replacement authority evidence does not match signed credentials"
            )
        assertion = credential.assertion
        principal = authenticated.principal
        operation = PrincipalOperation(str(upgraded["operation"]))
        preflight_document = self._preflight.to_dict()
        operation_intent = _principal_intent(upgraded, preflight_document)
        operation_intent_json = canonical_json(operation_intent)
        signed_intent_hash = compute_operation_intent_hash(operation, operation_intent)
        if signed_intent_hash != assertion.operation_intent_sha256:
            raise PrincipalAuthenticationError("Replacement authority operation intent is stale")
        effect = {
            "schema_version": 1,
            "effect_id": credential.upgraded_requirement_id,
            "effect_kind": operation.value,
            "payload": {
                "domain": AUTHORITY_EFFECT_DOMAIN,
                "preflight_id": self._preflight.preflight_id,
                "source_requirement_id": source_id,
                "upgraded_requirement_id": credential.upgraded_requirement_id,
                "canonical_replay_key_sha256": credential.replay_key_sha256,
                "composition_sha256": self._bundle.composition_sha256,
            },
            "recorded_at": consumed_at,
        }
        effect_json = canonical_json(effect)
        effect_hash = sha256_text(effect_json)
        ledger = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (assertion.mission_id,),
        ).fetchone()
        if ledger is None:
            raise StoreIntegrityError("Mission principal ledger is missing")
        use_sequence = int(ledger["assertion_count"]) + 1
        previous_hash = str(ledger["head_hash"])
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)
        entry = {
            "mission_id": assertion.mission_id,
            "use_sequence": use_sequence,
            "issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_hash": assertion_hash,
            "subject": assertion.subject,
            "principal_profile_id": assertion.profile_id,
            "key_id": assertion.key_id,
            "key_hash": principal.key_sha256,
            "audience": assertion.audience,
            "store_id": assertion.store_id,
            "operation": operation.value,
            "operation_intent_json": operation_intent_json,
            "signed_intent_hash": signed_intent_hash,
            "domain_request_hash": sha256_text(operation_intent_json),
            "idempotency_key_hash": None,
            "scope_grant_hash": assertion.scope_grant_sha256,
            "trust_policy_id": assertion.policy_id,
            "trust_policy_version": assertion.policy_version,
            "trust_policy_hash": principal.policy_sha256,
            "issued_at": assertion.issued_at,
            "not_before": assertion.not_before,
            "expires_at": assertion.expires_at,
            "consumed_at": consumed_at,
            "effects_hash": principal_assertion_effects_hash((effect_hash,)),
            "previous_hash": previous_hash,
        }
        entry_hash = principal_assertion_entry_hash(entry)
        AuthenticatedMissionControlService._insert_assertion_use(
            connection,
            assertion_json=assertion_json,
            entry=entry,
            entry_hash=entry_hash,
        )
        connection.execute(
            """
            INSERT INTO principal_assertion_effects(
                issuer, assertion_id, mission_id, effect_index,
                effect_kind, effect_id, effect_json, effect_hash, recorded_at
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                assertion.issuer,
                assertion.assertion_id,
                assertion.mission_id,
                operation.value,
                credential.upgraded_requirement_id,
                effect_json,
                effect_hash,
                consumed_at,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE mission_principal_ledgers
            SET head_hash = ?, assertion_count = assertion_count + 1,
                effect_count = effect_count + 1, updated_at = ?
            WHERE mission_id = ? AND assertion_count = ? AND head_hash = ?
            """,
            (
                entry_hash,
                consumed_at,
                assertion.mission_id,
                use_sequence - 1,
                previous_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError("Mission principal ledger changed during plan replacement")
        credential_document = {
            "source_requirement_id": credential.source_requirement_id,
            "upgraded_requirement_id": credential.upgraded_requirement_id,
            "canonical_replay_key_sha256": credential.replay_key_sha256,
            "scope_grant": credential.scope_grant.to_dict(),
            "assertion": credential.assertion.to_dict(),
        }
        connection.execute(
            """
            INSERT INTO collaboration_plan_replacement_authority_consumptions(
                preflight_id, source_requirement_id, upgraded_requirement_id,
                canonical_replay_key_sha256, issuer, assertion_id,
                assertion_sha256, scope_grant_sha256, operation, effect_id,
                credential_sha256, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._preflight.preflight_id,
                source_id,
                credential.upgraded_requirement_id,
                credential.replay_key_sha256,
                assertion.issuer,
                assertion.assertion_id,
                assertion_hash,
                assertion.scope_grant_sha256,
                operation.value,
                credential.upgraded_requirement_id,
                _canonical_sha256(credential_document),
                consumed_at,
            ),
        )
        self._used_requirements.add(source_id)
        if len(self._used_requirements) == self._requirement_count:
            assert self._identity is not None
            self._store._verify_principal_ledger(
                connection,
                self._mission,
                store_id=str(self._identity["store_id"]),
                scope_grants=self._scope_grants,
                trust_policies=self._trust_policies,
                registry=self._registry,
            )
        return VerifiedReplacementAuthority(
            requirement_id=source_id,
            role=str(requirement["role"]),
            authority_id=str(requirement["authority_id"]),
            authority_kind=str(requirement["authority_kind"]),
            operation=str(requirement["operation"]),
            work_item_id=requirement.get("work_item_id"),
            operation_intent_sha256=str(requirement["operation_intent_sha256"]),
            evidence_id=evidence.evidence_id,
            evidence_sha256=evidence.evidence_sha256,
        )


def _require_transaction_scoped_replacement_verifier(
    verifier: Any,
    *,
    store: MissionStore,
    registry: ExpertRegistry,
    preflight: CollaborationPlanReplacementPreflight,
) -> None:
    """Bind the runtime kernel to a fresh authenticated adapter, not a protocol hook.

    This is a runtime composition check, not protection against arbitrary code in
    the process. The transaction and durable signed-custody guards remain fences.
    """

    if type(verifier) is not _TransactionScopedReplacementAuthorityVerifier:
        raise PrincipalAuthenticationError(
            "Runtime replacement requires the authenticated transaction verifier"
        )
    try:
        verify = verifier.verify
        if (
            verifier._store is not store
            or verifier._registry is not registry
            or getattr(verify, "__self__", None) is not verifier
            or getattr(verify, "__func__", None)
            is not _TransactionScopedReplacementAuthorityVerifier.verify
            or verifier._connection_identity is not None
            or verifier._consumed_at is not None
            or verifier._prepared is not False
            or type(verifier._used_requirements) is not set
            or verifier._used_requirements
            or verifier._requirement_count is not None
        ):
            raise PrincipalAuthenticationError(
                "Runtime replacement verifier bindings or transaction state are invalid"
            )
        bound = CollaborationPlanReplacementPreflight.from_dict(verifier._preflight.to_dict())
        requested = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
        if canonical_json(bound.to_dict()) != canonical_json(requested.to_dict()):
            raise PrincipalAuthenticationError("Runtime replacement verifier preflight is stale")
    except PrincipalAuthenticationError:
        raise
    except (AttributeError, TypeError, ValueError, CollaborationPlanError) as exc:
        raise PrincipalAuthenticationError(
            "Runtime replacement verifier bindings are invalid"
        ) from exc


class AuthenticatedCollaborationPlanReplacementStoreService:
    """Commit a fully authenticated replacement in one store transaction."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        self._store = store
        self._registry = registry
        self._clock = clock or store._clock

    def replace(
        self,
        *,
        preflight: CollaborationPlanReplacementPreflight,
        prior_plan: CollaborationPlan,
        replacement_plan: CollaborationPlan,
        verified_authority_plan: VerifiedCollaborationPlanReplacementAuthorityPlan,
        authority_upgrade: CollaborationPlanReplacementAuthorityUpgrade,
        authenticated_bundle: VerifiedCollaborationPlanReplacementAuthorityBundle,
        credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
        expected_plan_version: int,
    ) -> CollaborationPlanReplacementCommitReceipt:
        parsed_preflight = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
        canonical_replays = collaboration_plan_replacement_authority_replay_keys(
            verified_authority_plan,
            authority_upgrade,
            preflight=parsed_preflight,
            army_registry=self._registry,
        )
        requirement_count = validate_plan_replacement_authority_requirement_count(
            len(canonical_replays)
        )
        parsed_credentials = _normalize_credentials(
            credentials, requirement_count=requirement_count
        )
        if {item.source_requirement_id for item in parsed_credentials} != set(
            canonical_replays
        ) or any(
            item.replay_key_sha256 != canonical_replays[item.source_requirement_id]
            for item in parsed_credentials
        ):
            raise PrincipalAuthenticationError("Replacement authority credential coverage is stale")
        evidence = tuple(
            _evidence(credential=item, bundle=authenticated_bundle) for item in parsed_credentials
        )
        verifier = _TransactionScopedReplacementAuthorityVerifier(
            store=self._store,
            registry=self._registry,
            preflight=parsed_preflight,
            verified_authority_plan=verified_authority_plan,
            authority_upgrade=authority_upgrade,
            bundle=authenticated_bundle,
            credentials=parsed_credentials,
        )
        service = CollaborationPlanReplacementStoreService(
            self._store,
            self._registry,
            verifier,
            clock=self._clock,
        )
        return service.replace(
            preflight=parsed_preflight,
            prior_plan=prior_plan,
            replacement_plan=replacement_plan,
            authority_evidence=evidence,
            expected_plan_version=expected_plan_version,
        )


__all__ = [
    "AUTHENTICATION_CUSTODY_DOMAIN",
    "AUTHORITY_EFFECT_DOMAIN",
    "AUTHORITY_EVIDENCE_DOMAIN",
    "AuthenticatedCollaborationPlanReplacementStoreService",
]
