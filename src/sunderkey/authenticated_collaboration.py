"""Authenticated durable collaboration-plan activation for SUNDERKEY."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .collaboration import (
    CollaborationPlan,
    WorkItemKind,
    validate_collaboration_plan,
)
from .errors import (
    CollaborationPlanError,
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .events import MISSION_ID_PATTERN
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    COLLABORATION_ACTIVATE_EFFECT_KIND,
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
class AuthenticatedCollaborationActivationReceipt:
    """Immutable activated plan and principal provenance."""

    plan: CollaborationPlan
    plan_sha256: str
    activated_at: str
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
            "plan": self.plan.to_dict(),
            "plan_sha256": self.plan_sha256,
            "activated_at": self.activated_at,
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
            "operation": (
                PrincipalOperation.COLLABORATION_ACTIVATE.value
            ),
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "consumed_at": self.consumed_at,
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedCollaborationActivationService:
    """Verify and durably activate one exact plan per mission."""

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

    def activate(
        self,
        assertion: PrincipalAssertion,
        plan: CollaborationPlan,
    ) -> AuthenticatedCollaborationActivationReceipt:
        """Authenticate activation or return the exact durable result."""

        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        if not isinstance(plan, CollaborationPlan):
            raise CollaborationPlanError(
                "plan must be a CollaborationPlan"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        plan = CollaborationPlan.from_dict(plan.to_dict())
        plan_json = canonical_json(plan.to_dict())
        plan_hash = sha256_text(plan_json)
        readiness_owner = self._readiness_owner(plan)
        operation = PrincipalOperation.COLLABORATION_ACTIVATE
        operation_intent = {
            "mission_id": plan.mission_id,
            "plan_content_sha256": plan.content_sha256,
            "plan_id": plan.plan_id,
            "principal_profile_id": readiness_owner,
        }
        operation_intent_json = canonical_json(operation_intent)
        signed_intent_hash = compute_operation_intent_hash(
            operation,
            operation_intent,
        )
        domain_request_hash = sha256_text(operation_intent_json)
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)

        try:
            with self._store._write_connection() as connection:
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                    principal_ledger,
                ) = self._verified_mission_state(
                    connection,
                    plan.mission_id,
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
                        mission_id=plan.mission_id,
                        principal_profile_id=readiness_owner,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=(
                            assertion.policy_version
                        ),
                        assertion_json=assertion_json,
                        assertion_hash=assertion_hash,
                        operation_intent_json=operation_intent_json,
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        scope_grant_hash=(
                            assertion.scope_grant_sha256
                        ),
                    )
                    activation = self._require_exact_activation(
                        connection,
                        plan=plan,
                        plan_json=plan_json,
                        plan_hash=plan_hash,
                        assertion=assertion,
                    )
                    return self._receipt_from_rows(
                        connection,
                        existing_use,
                        activation,
                    )

                collision = connection.execute(
                    """
                    SELECT plan_id, mission_id
                    FROM collaboration_plan_activations
                    WHERE plan_id = ? OR mission_id = ?
                    LIMIT 1
                    """,
                    (plan.plan_id, plan.mission_id),
                ).fetchone()
                if collision is not None:
                    raise StoreConflictError(
                        "Mission already has a different activated "
                        "collaboration plan"
                    )
                validate_collaboration_plan(
                    self._registry,
                    mission.mission,
                    plan,
                )
                if assertion.profile_id != readiness_owner:
                    raise PrincipalAuthenticationError(
                        "Collaboration activation requires the plan "
                        "readiness owner"
                    )
                control = connection.execute(
                    """
                    SELECT state
                    FROM mission_controls
                    WHERE mission_id = ?
                    """,
                    (plan.mission_id,),
                ).fetchone()
                if control is None:
                    raise StoreIntegrityError(
                        "Mission control state is missing"
                    )
                if control["state"] != "active":
                    raise MissionStoppedError(
                        "Stopped mission cannot activate a "
                        "collaboration plan"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "collaboration activation consumed_at",
                )
                self._require_runtime_not_before_state(
                    connection,
                    mission,
                    principal_ledger,
                    consumed_time,
                )
                principal = self._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    signed_intent_hash=signed_intent_hash,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=consumed_time,
                )
                effect = self._activation_effect(
                    plan=plan,
                    plan_hash=plan_hash,
                    mission_context_hash=mission.context_hash,
                    store_id=str(identity["store_id"]),
                    activated_at=consumed_at,
                )
                effect_json = canonical_json(effect)
                effect_hash = sha256_text(effect_json)
                effects_hash = principal_assertion_effects_hash(
                    (effect_hash,)
                )
                use_sequence = (
                    int(principal_ledger["assertion_count"]) + 1
                )
                previous_hash = str(principal_ledger["head_hash"])
                entry = (
                    AuthenticatedMissionControlService._assertion_entry(
                        principal=principal,
                        assertion=assertion,
                        mission_id=plan.mission_id,
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
                        plan.mission_id,
                        COLLABORATION_ACTIVATE_EFFECT_KIND,
                        plan.plan_id,
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
                        assertion_count = assertion_count + 1,
                        effect_count = effect_count + 1,
                        updated_at = ?
                    WHERE mission_id = ?
                      AND assertion_count = ?
                      AND effect_count = ?
                      AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        consumed_at,
                        plan.mission_id,
                        use_sequence - 1,
                        int(principal_ledger["effect_count"]),
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during "
                        "collaboration activation"
                    )
                connection.execute(
                    """
                    INSERT INTO collaboration_plan_activations(
                        plan_id,
                        mission_id,
                        store_id,
                        plan_json,
                        plan_sha256,
                        plan_content_sha256,
                        registry_sha256,
                        mission_sha256,
                        joint_mission_cell_sha256,
                        readiness_owner_profile_id,
                        activated_at,
                        issuer,
                        assertion_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.mission_id,
                        str(identity["store_id"]),
                        plan_json,
                        plan_hash,
                        plan.content_sha256,
                        plan.registry_sha256,
                        plan.mission_sha256,
                        plan.joint_mission_cell_sha256,
                        readiness_owner,
                        consumed_at,
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_plan_active_heads(
                        mission_id,
                        active_plan_id,
                        plan_version,
                        replacement_commit_id,
                        updated_at
                    ) VALUES (?, ?, 1, NULL, ?)
                    """,
                    (
                        plan.mission_id,
                        plan.plan_id,
                        consumed_at,
                    ),
                )
                (
                    _,
                    _,
                    _,
                    _,
                    activation_count,
                ) = self._store._verify_phase4_mission_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    registry=self._registry,
                )
                if activation_count != 1:
                    raise StoreIntegrityError(
                        "Collaboration plan activation was not stored"
                    )
                stored_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                activation = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_plan_activations
                    WHERE plan_id = ?
                    """,
                    (plan.plan_id,),
                ).fetchone()
                if stored_use is None or activation is None:
                    raise StoreIntegrityError(
                        "Collaboration activation durable state is "
                        "incomplete"
                    )
                return self._receipt_from_rows(
                    connection,
                    stored_use,
                    activation,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated collaboration activation conflicts "
                "with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated collaboration "
                "activation"
            ) from exc

    def get(
        self,
        mission_id: str,
    ) -> AuthenticatedCollaborationActivationReceipt:
        """Return the verified durable activation for one mission."""

        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is not a valid mission ID")
        try:
            with self._store._read_connection() as connection:
                self._verified_mission_state(
                    connection,
                    mission_id,
                )
                activation = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_plan_activations
                    WHERE mission_id = ? AND activation_kind = 'initial'
                    """,
                    (mission_id,),
                ).fetchone()
                if activation is None:
                    raise StoreError(
                        "Mission has no activated collaboration plan"
                    )
                use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (
                        activation["issuer"],
                        activation["assertion_id"],
                    ),
                ).fetchone()
                if use is None:
                    raise StoreIntegrityError(
                        "Collaboration activation assertion is "
                        "missing"
                    )
                return self._receipt_from_rows(
                    connection,
                    use,
                    activation,
                )
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read authenticated collaboration "
                "activation"
            ) from exc

    def _verified_mission_state(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[
        sqlite3.Row,
        dict[str, Any],
        StoredMission,
        dict[str, Any],
        sqlite3.Row,
    ]:
        identity = self._store._verify_store_identity(
            connection,
            verify_history=False,
        )
        trust_policies = self._store._verify_trust_policy_history(
            connection,
            identity,
        )
        row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreError(f"Unknown stored mission: {mission_id}")
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
        principal_ledger = connection.execute(
            """
            SELECT *
            FROM mission_principal_ledgers
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()
        if principal_ledger is None:
            raise StoreIntegrityError(
                "Mission principal ledger is missing"
            )
        return (
            identity,
            trust_policies,
            mission,
            scope_grants,
            principal_ledger,
        )

    @staticmethod
    def _readiness_owner(plan: CollaborationPlan) -> str:
        readiness = tuple(
            item
            for item in plan.work_items
            if item.kind is WorkItemKind.READINESS
        )
        if len(readiness) != 1:
            raise CollaborationPlanError(
                "collaboration plan must contain one readiness item"
            )
        return readiness[0].owner_profile_id

    @staticmethod
    def _require_runtime_not_before_state(
        connection: sqlite3.Connection,
        mission: StoredMission,
        principal_ledger: sqlite3.Row,
        consumed_time: datetime,
    ) -> None:
        if parse_timestamp(
            str(principal_ledger["updated_at"]),
            "mission_principal_ledger.updated_at",
        ) > consumed_time:
            raise PrincipalAuthenticationError(
                "Runtime clock precedes the principal ledger"
            )
        if parse_timestamp(
            mission.updated_at,
            "mission.updated_at",
        ) > consumed_time:
            raise PrincipalAuthenticationError(
                "Runtime clock precedes the mission ledger"
            )
        revocation = connection.execute(
            """
            SELECT updated_at
            FROM mission_scope_revocation_baselines
            WHERE mission_id = ?
            """,
            (mission.mission.mission_id,),
        ).fetchone()
        if (
            revocation is None
            or parse_timestamp(
                str(revocation["updated_at"]),
                "scope_revocation_baseline.updated_at",
            )
            > consumed_time
        ):
            raise PrincipalAuthenticationError(
                "Runtime clock precedes scope revocation state"
            )

    def _authenticate_current_authority(
        self,
        connection: sqlite3.Connection,
        *,
        assertion: PrincipalAssertion,
        signed_intent_hash: str,
        mission: StoredMission,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
        scope_grants: dict[str, Any],
        now: datetime,
        consumed_time: datetime,
    ) -> Any:
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
        policy_high_water = self._store._trust_policy_high_water_at(
            trust_policies,
            consumed_time,
        )
        if (
            policy_high_water.policy_sha256
            != verified_policy.policy_sha256
        ):
            raise PrincipalAuthenticationError(
                "Runtime clock precedes the current trust policy"
            )
        scope_entry = scope_grants.get(
            assertion.scope_grant_sha256
        )
        if scope_entry is None:
            raise PrincipalAuthenticationError(
                "Principal assertion scope grant is not accepted"
            )
        scope_row, scope_grant = scope_entry
        if parse_timestamp(
            str(scope_row["accepted_at"]),
            "mission_scope_grant.accepted_at",
        ) > consumed_time:
            raise PrincipalAuthenticationError(
                "Scope grant was accepted after assertion use"
            )
        if (
            self._store._effective_scope_grant_revocation(
                connection,
                scope_row,
            )
            is not None
        ):
            raise PrincipalAuthenticationError(
                "Scope grant is revoked"
            )
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError(
                "Mission has no authenticated scope document hash"
            )
        constraints_hash = sha256_text(
            canonical_json(
                mission.mission.to_dict()["constraints"]
            )
        )
        verified_scope = verify_scope_grant(
            scope_grant,
            verified_policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=mission.mission.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=(
                mission.mission.scope_reference
            ),
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=(
                mission.mission.max_action_tier
            ),
            expected_constraints_hash=constraints_hash,
            expected_operation=(
                PrincipalOperation.COLLABORATION_ACTIVATE
            ),
            allow_expired_for_safety_reduction=False,
            clock=lambda: now,
        )
        return verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=mission.mission.mission_id,
            expected_operation=(
                PrincipalOperation.COLLABORATION_ACTIVATE
            ),
            expected_operation_intent_sha256=signed_intent_hash,
            clock=lambda: now,
        )

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
            or row["principal_profile_id"]
            != principal_profile_id
            or row["trust_policy_id"] != trust_policy_id
            or row["trust_policy_version"]
            != trust_policy_version
            or row["assertion_json"] != assertion_json
            or row["assertion_hash"] != assertion_hash
            or row["operation"]
            != COLLABORATION_ACTIVATE_EFFECT_KIND
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
    def _require_exact_activation(
        connection: sqlite3.Connection,
        *,
        plan: CollaborationPlan,
        plan_json: str,
        plan_hash: str,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM collaboration_plan_activations
            WHERE mission_id = ? AND plan_id = ?
            """,
            (plan.mission_id, plan.plan_id),
        ).fetchone()
        if (
            row is None
            or row["plan_id"] != plan.plan_id
            or row["plan_json"] != plan_json
            or row["plan_sha256"] != plan_hash
            or row["plan_content_sha256"]
            != plan.content_sha256
            or row["issuer"] != assertion.issuer
            or row["assertion_id"] != assertion.assertion_id
        ):
            raise StoreConflictError(
                "Collaboration activation replay has different "
                "content"
            )
        return row

    @staticmethod
    def _activation_effect(
        *,
        plan: CollaborationPlan,
        plan_hash: str,
        mission_context_hash: str,
        store_id: str,
        activated_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": plan.plan_id,
            "effect_kind": COLLABORATION_ACTIVATE_EFFECT_KIND,
            "payload": {
                "mission_context_sha256": mission_context_hash,
                "plan_content_sha256": plan.content_sha256,
                "plan_sha256": plan_hash,
                "store_id": store_id,
            },
            "recorded_at": activated_at,
            "schema_version": 1,
        }

    @staticmethod
    def _receipt_from_rows(
        connection: sqlite3.Connection,
        use: sqlite3.Row,
        activation: sqlite3.Row,
    ) -> AuthenticatedCollaborationActivationReceipt:
        try:
            assertion = PrincipalAssertion.from_dict(
                json.loads(str(use["assertion_json"]))
            )
            plan = CollaborationPlan.from_dict(
                json.loads(str(activation["plan_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            PrincipalAuthenticationError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored collaboration activation is invalid"
            ) from exc
        effects = connection.execute(
            """
            SELECT *
            FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ?
            ORDER BY effect_index
            """,
            (use["issuer"], use["assertion_id"]),
        ).fetchall()
        if (
            len(effects) != 1
            or effects[0]["effect_kind"]
            != COLLABORATION_ACTIVATE_EFFECT_KIND
            or effects[0]["effect_id"] != plan.plan_id
            or activation["issuer"] != use["issuer"]
            or activation["assertion_id"] != use["assertion_id"]
        ):
            raise StoreIntegrityError(
                "Stored collaboration activation effect is invalid"
            )
        return AuthenticatedCollaborationActivationReceipt(
            plan=plan,
            plan_sha256=str(activation["plan_sha256"]),
            activated_at=str(activation["activated_at"]),
            issuer=str(use["issuer"]),
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            subject=str(use["subject"]),
            principal_profile_id=str(
                use["principal_profile_id"]
            ),
            key_id=str(use["key_id"]),
            key_sha256=str(use["key_hash"]),
            scope_grant_sha256=str(use["scope_grant_hash"]),
            policy_id=str(use["trust_policy_id"]),
            policy_version=int(use["trust_policy_version"]),
            policy_sha256=str(use["trust_policy_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            consumed_at=str(use["consumed_at"]),
            effects_sha256=str(use["effects_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )


__all__ = [
    "AuthenticatedCollaborationActivationReceipt",
    "AuthenticatedCollaborationActivationService",
]
