"""Authenticated mission-creation boundary for the SUNDERKEY runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .mission import MissionRequest
from .registry import ExpertRegistry
from .store import (
    MISSION_CREATE_EFFECT_KIND,
    MISSION_CREATION_AUTHENTICATION_SCHEMA_VERSION,
    MissionStore,
    StoredMission,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)


@dataclass(frozen=True)
class AuthenticatedMissionCreationReceipt:
    """Immutable mission-creation result and authenticated provenance."""

    mission: StoredMission
    scope_grant_accepted_at: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    subject: str
    principal_profile_id: str
    key_id: str
    key_sha256: str
    scope_grant_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    operation_intent_sha256: str
    consumed_at: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mission": self.mission.to_dict(),
            "scope_grant_accepted_at": self.scope_grant_accepted_at,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "subject": self.subject,
            "principal_profile_id": self.principal_profile_id,
            "key_id": self.key_id,
            "key_sha256": self.key_sha256,
            "scope_grant_sha256": self.scope_grant_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "operation": PrincipalOperation.MISSION_CREATE.value,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "consumed_at": self.consumed_at,
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedMissionCreationService:
    """Verify and create one mission with its scope atomically."""

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

    def create(
        self,
        assertion: PrincipalAssertion,
        scope_grant: ScopeGrant,
        mission: MissionRequest,
    ) -> AuthenticatedMissionCreationReceipt:
        """Authenticate mission creation or return its exact receipt."""

        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        if not isinstance(scope_grant, ScopeGrant):
            raise PrincipalAuthenticationError(
                "scope_grant must be a ScopeGrant"
            )
        if not isinstance(mission, MissionRequest):
            raise StoreError(
                "mission must be a validated MissionRequest"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        scope_grant = ScopeGrant.from_dict(scope_grant.to_dict())
        mission = MissionRequest.from_dict(mission.to_dict())
        context = self._store._build_context(
            self._registry,
            mission,
        )
        context_json = canonical_json(context)
        context_hash = sha256_text(context_json)
        operation_intent = {
            "mission_context_sha256": context_hash,
            "mission_id": mission.mission_id,
            "principal_profile_id": assertion.profile_id,
        }
        operation_intent_json = canonical_json(operation_intent)
        signed_intent_hash = compute_operation_intent_hash(
            PrincipalOperation.MISSION_CREATE,
            operation_intent,
        )
        domain_request_hash = sha256_text(operation_intent_json)
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)
        grant_json = canonical_json(scope_grant.to_dict())
        grant_hash = sha256_text(grant_json)

        try:
            with self._store._write_connection() as connection:
                identity = self._store._verify_store_identity(
                    connection,
                    verify_history=False,
                )
                trust_policies = (
                    self._store._verify_trust_policy_history(
                        connection,
                        identity,
                    )
                )
                existing_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing_use is not None:
                    self._require_exact_replay(
                        existing_use,
                        mission_id=mission.mission_id,
                        principal_profile_id=assertion.profile_id,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=(
                            assertion.policy_version
                        ),
                        assertion_json=assertion_json,
                        assertion_hash=assertion_hash,
                        operation_intent_json=operation_intent_json,
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        scope_grant_hash=grant_hash,
                    )
                    self._require_exact_grant(
                        connection,
                        scope_grant=scope_grant,
                        grant_json=grant_json,
                        grant_hash=grant_hash,
                    )
                    stored = self._verified_mission_state(
                        connection,
                        mission.mission_id,
                        identity=identity,
                        trust_policies=trust_policies,
                    )
                    if stored.context_hash != context_hash:
                        raise StoreConflictError(
                            "Mission creation replay has different "
                            "context"
                        )
                    return self._receipt_from_row(
                        connection,
                        existing_use,
                        stored,
                    )

                existing_mission = connection.execute(
                    """
                    SELECT context_hash
                    FROM missions
                    WHERE mission_id = ?
                    """,
                    (mission.mission_id,),
                ).fetchone()
                if existing_mission is not None:
                    raise StoreConflictError(
                        "Mission ID already has creation provenance"
                    )
                current_policy_hash = identity["trust_policy_hash"]
                if current_policy_hash is None:
                    raise StoreConflictError(
                        "A current trust policy is required"
                    )
                verified_policy = trust_policies.get(
                    str(current_policy_hash)
                )
                if verified_policy is None:
                    raise StoreIntegrityError(
                        "Current trust policy is missing from history"
                    )
                if (
                    assertion.scope_grant_sha256 != grant_hash
                    or assertion.scope_grant_id
                    != scope_grant.grant_id
                ):
                    raise PrincipalAuthenticationError(
                        "Principal assertion scope grant does not "
                        "match the supplied grant"
                    )
                if (
                    assertion.profile_id
                    not in context["allowed_profile_ids"]
                ):
                    raise PrincipalAuthenticationError(
                        "Mission creator is not assigned to the "
                        "mission"
                    )
                scope_document_hash = mission.scope_document_hash
                if scope_document_hash is None:
                    raise PrincipalAuthenticationError(
                        "Mission has no authenticated scope document "
                        "hash"
                    )
                grant_collision = connection.execute(
                    """
                    SELECT grant_hash, grant_json
                    FROM mission_scope_grants
                    WHERE grant_hash = ?
                       OR (issuer = ? AND grant_id = ?)
                    LIMIT 1
                    """,
                    (
                        grant_hash,
                        scope_grant.issuer,
                        scope_grant.grant_id,
                    ),
                ).fetchone()
                if grant_collision is not None:
                    raise StoreConflictError(
                        "Mission creation scope grant is already "
                        "stored"
                    )
                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated mission creation consumed_at",
                )
                policy_high_water = (
                    self._store._trust_policy_high_water_at(
                        trust_policies,
                        consumed_time,
                    )
                )
                if (
                    policy_high_water.policy_sha256
                    != verified_policy.policy_sha256
                ):
                    raise PrincipalAuthenticationError(
                        "Runtime clock precedes the current trust policy"
                    )
                constraints_hash = sha256_text(
                    canonical_json(
                        mission.to_dict()["constraints"]
                    )
                )
                verified_scope = verify_scope_grant(
                    scope_grant,
                    verified_policy,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_mission_id=mission.mission_id,
                    expected_mission_context_hash=context_hash,
                    expected_scope_reference=(
                        mission.scope_reference
                    ),
                    expected_scope_document_hash=(
                        scope_document_hash
                    ),
                    expected_environment=mission.environment,
                    expected_max_action_tier=(
                        mission.max_action_tier
                    ),
                    expected_constraints_hash=constraints_hash,
                    expected_operation=(
                        PrincipalOperation.MISSION_CREATE
                    ),
                    clock=lambda: now,
                )
                principal = verify_principal_assertion(
                    assertion,
                    verified_policy,
                    verified_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_mission_id=mission.mission_id,
                    expected_operation=(
                        PrincipalOperation.MISSION_CREATE
                    ),
                    expected_operation_intent_sha256=(
                        signed_intent_hash
                    ),
                    clock=lambda: now,
                )

                stored = self._store._create_mission_in_connection(
                    connection,
                    self._registry,
                    mission,
                    now,
                    authenticated_principal=True,
                )
                self._insert_scope_grant(
                    connection,
                    scope_grant=scope_grant,
                    grant_json=grant_json,
                    verified_scope=verified_scope,
                    accepted_at=consumed_at,
                )
                ledger = connection.execute(
                    """
                    SELECT *
                    FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (mission.mission_id,),
                ).fetchone()
                if ledger is None:
                    raise StoreIntegrityError(
                        "Mission principal ledger is missing"
                    )
                effect = self._mission_creation_effect(
                    mission_id=mission.mission_id,
                    context=context,
                    context_hash=context_hash,
                    store_id=str(identity["store_id"]),
                    scope_grant_hash=grant_hash,
                    accepted_at=consumed_at,
                )
                effect_json = canonical_json(effect)
                effect_hash = sha256_text(effect_json)
                effects_hash = principal_assertion_effects_hash(
                    (effect_hash,)
                )
                use_sequence = int(ledger["assertion_count"]) + 1
                previous_hash = str(ledger["head_hash"])
                entry = (
                    AuthenticatedMissionControlService._assertion_entry(
                        principal=principal,
                        assertion=assertion,
                        mission_id=mission.mission_id,
                        use_sequence=use_sequence,
                        assertion_hash=assertion_hash,
                        operation_intent_json=(
                            operation_intent_json
                        ),
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        idempotency_key_hash=None,
                        consumed_at=consumed_at,
                        effects_hash=effects_hash,
                        previous_hash=previous_hash,
                    )
                )
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
                        issuer,
                        assertion_id,
                        mission_id,
                        effect_index,
                        effect_kind,
                        effect_id,
                        effect_json,
                        effect_hash,
                        recorded_at
                    ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                        mission.mission_id,
                        MISSION_CREATE_EFFECT_KIND,
                        mission.mission_id,
                        effect_json,
                        effect_hash,
                        consumed_at,
                    ),
                )
                cursor = connection.execute(
                    """
                    UPDATE mission_principal_ledgers
                    SET
                        head_hash = ?,
                        assertion_count = 1,
                        effect_count = 1,
                        updated_at = ?
                    WHERE mission_id = ?
                      AND assertion_count = 0
                      AND effect_count = 0
                      AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        consumed_at,
                        mission.mission_id,
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during "
                        "creation"
                    )
                self._store._insert_mission_creation_provenance(
                    connection,
                    mission_id=mission.mission_id,
                    store_id=str(identity["store_id"]),
                    mission_context_hash=context_hash,
                    provenance_kind="authenticated",
                    source_schema_version=(
                        MISSION_CREATION_AUTHENTICATION_SCHEMA_VERSION
                    ),
                    recorded_at=consumed_at,
                    issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    principal_profile_id=assertion.profile_id,
                    scope_grant_hash=grant_hash,
                    operation_intent_hash=signed_intent_hash,
                    effect_hash=effect_hash,
                )
                stored = self._verified_mission_state(
                    connection,
                    mission.mission_id,
                    identity=identity,
                    trust_policies=trust_policies,
                )
                stored_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if stored_use is None:
                    raise StoreIntegrityError(
                        "Authenticated assertion use was not stored"
                    )
                return self._receipt_from_row(
                    connection,
                    stored_use,
                    stored,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated mission creation conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated mission creation"
            ) from exc

    def _verified_mission_state(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
        *,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
    ) -> StoredMission:
        row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Authenticated mission creation is missing its mission"
            )
        mission = self._store._stored_mission_from_row(
            connection,
            self._registry,
            row,
        )
        ledger, _ = self._store._load_verified_ledger(
            connection,
            mission,
        )
        self._store._verify_auxiliary_state(
            connection,
            mission,
            ledger,
        )
        scope_grants, _ = self._store._verify_scope_grants(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            trust_policies=trust_policies,
            registry=self._registry,
        )
        self._store._verify_scope_revocation_state(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            trust_policies=trust_policies,
            scope_grants=scope_grants,
        )
        self._store._verify_principal_ledger(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            scope_grants=scope_grants,
            trust_policies=trust_policies,
            registry=self._registry,
        )
        return mission

    @staticmethod
    def _require_exact_replay(
        row: sqlite3.Row,
        *,
        mission_id: str,
        principal_profile_id: str,
        trust_policy_id: str,
        trust_policy_version: int,
        assertion_json: str,
        assertion_hash: str,
        operation_intent_json: str,
        signed_intent_hash: str,
        domain_request_hash: str,
        scope_grant_hash: str,
    ) -> None:
        if (
            row["mission_id"] != mission_id
            or row["principal_profile_id"] != principal_profile_id
            or row["trust_policy_id"] != trust_policy_id
            or row["trust_policy_version"] != trust_policy_version
            or row["assertion_json"] != assertion_json
            or row["assertion_hash"] != assertion_hash
            or row["operation"] != MISSION_CREATE_EFFECT_KIND
            or row["operation_intent_json"]
            != operation_intent_json
            or row["signed_intent_hash"] != signed_intent_hash
            or row["domain_request_hash"] != domain_request_hash
            or row["idempotency_key_hash"] is not None
            or row["scope_grant_hash"] != scope_grant_hash
        ):
            raise StoreConflictError(
                "Principal assertion replay has different content"
            )

    @staticmethod
    def _require_exact_grant(
        connection: sqlite3.Connection,
        *,
        scope_grant: ScopeGrant,
        grant_json: str,
        grant_hash: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT *
            FROM mission_scope_grants
            WHERE grant_hash = ?
            """,
            (grant_hash,),
        ).fetchone()
        if (
            row is None
            or row["grant_id"] != scope_grant.grant_id
            or row["issuer"] != scope_grant.issuer
            or row["grant_json"] != grant_json
        ):
            raise StoreConflictError(
                "Mission creation replay has different scope grant"
            )

    @staticmethod
    def _insert_scope_grant(
        connection: sqlite3.Connection,
        *,
        scope_grant: ScopeGrant,
        grant_json: str,
        verified_scope: Any,
        accepted_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO mission_scope_grants(
                grant_hash,
                grant_id,
                grant_json,
                issuer,
                key_id,
                key_hash,
                audience,
                store_id,
                mission_id,
                mission_context_hash,
                scope_document_hash,
                environment,
                max_action_tier,
                constraints_hash,
                issued_at,
                not_before,
                expires_at,
                accepted_at,
                revoked_at,
                revocation_reason,
                trust_policy_id,
                trust_policy_version,
                trust_policy_hash
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, NULL, NULL, ?, ?, ?
            )
            """,
            (
                verified_scope.grant_sha256,
                scope_grant.grant_id,
                grant_json,
                scope_grant.issuer,
                scope_grant.key_id,
                verified_scope.key_sha256,
                scope_grant.audience,
                scope_grant.store_id,
                scope_grant.mission_id,
                scope_grant.mission_context_hash,
                scope_grant.scope_document_hash,
                scope_grant.environment.value,
                scope_grant.max_action_tier.value,
                scope_grant.constraints_hash,
                scope_grant.issued_at,
                scope_grant.not_before,
                scope_grant.expires_at,
                accepted_at,
                scope_grant.policy_id,
                scope_grant.policy_version,
                verified_scope.policy_sha256,
            ),
        )

    @staticmethod
    def _mission_creation_effect(
        *,
        mission_id: str,
        context: dict[str, Any],
        context_hash: str,
        store_id: str,
        scope_grant_hash: str,
        accepted_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": mission_id,
            "effect_kind": MISSION_CREATE_EFFECT_KIND,
            "payload": {
                "mission_context": context,
                "mission_context_sha256": context_hash,
                "scope_grant_sha256": scope_grant_hash,
                "scope_grant_accepted_at": accepted_at,
                "store_id": store_id,
            },
            "recorded_at": accepted_at,
            "schema_version": 1,
        }

    @staticmethod
    def _receipt_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        mission: StoredMission,
    ) -> AuthenticatedMissionCreationReceipt:
        try:
            assertion = PrincipalAssertion.from_dict(
                json.loads(str(row["assertion_json"]))
            )
        except (
            json.JSONDecodeError,
            PrincipalAuthenticationError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored principal assertion is invalid"
            ) from exc
        effects = connection.execute(
            """
            SELECT *
            FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ?
            ORDER BY effect_index
            """,
            (row["issuer"], row["assertion_id"]),
        ).fetchall()
        grant = connection.execute(
            """
            SELECT accepted_at
            FROM mission_scope_grants
            WHERE grant_hash = ?
            """,
            (row["scope_grant_hash"],),
        ).fetchone()
        if (
            len(effects) != 1
            or grant is None
            or row["operation"] != MISSION_CREATE_EFFECT_KIND
            or effects[0]["effect_kind"]
            != MISSION_CREATE_EFFECT_KIND
            or effects[0]["effect_id"]
            != mission.mission.mission_id
        ):
            raise StoreIntegrityError(
                "Stored mission creation effect binding is invalid"
            )
        return AuthenticatedMissionCreationReceipt(
            mission=mission,
            scope_grant_accepted_at=str(grant["accepted_at"]),
            issuer=str(row["issuer"]),
            assertion_id=str(row["assertion_id"]),
            assertion_sha256=str(row["assertion_hash"]),
            subject=str(row["subject"]),
            principal_profile_id=str(
                row["principal_profile_id"]
            ),
            key_id=str(row["key_id"]),
            key_sha256=str(row["key_hash"]),
            scope_grant_sha256=str(row["scope_grant_hash"]),
            policy_id=str(row["trust_policy_id"]),
            policy_version=int(row["trust_policy_version"]),
            policy_sha256=str(row["trust_policy_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            consumed_at=str(row["consumed_at"]),
            effects_sha256=str(row["effects_hash"]),
            ledger_entry_sha256=str(row["entry_hash"]),
        )


__all__ = [
    "AuthenticatedMissionCreationReceipt",
    "AuthenticatedMissionCreationService",
]
