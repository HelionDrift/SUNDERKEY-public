"""Authenticated durable commit for mission reconfiguration policies."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authenticated_collaboration import AuthenticatedCollaborationActivationService
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from .collaboration_mission_policy_authentication import (
    authenticate_collaboration_mission_reconfiguration_policy,
)
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import (
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
    VerifiedScopeGrant,
    VerifiedTrustPolicy,
    compute_operation_intent_hash,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
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
class AuthenticatedCollaborationMissionPolicyCommitReceipt:
    """Immutable durable policy and dual-principal provenance."""

    policy: CollaborationMissionReconfigurationPolicy
    selection_sha256: str
    authentication_id: str
    authentication_sha256: str
    committed_at: str
    owner_assertion_id: str
    owner_assertion_sha256: str
    owner_ledger_entry_sha256: str
    control_assertion_id: str
    control_assertion_sha256: str
    control_ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "policy": self.policy.to_dict(),
            "selection_sha256": self.selection_sha256,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
            "committed_at": self.committed_at,
            "mission_owner": {
                "assertion_id": self.owner_assertion_id,
                "assertion_sha256": self.owner_assertion_sha256,
                "ledger_entry_sha256": self.owner_ledger_entry_sha256,
            },
            "independent_control": {
                "assertion_id": self.control_assertion_id,
                "assertion_sha256": self.control_assertion_sha256,
                "ledger_entry_sha256": self.control_ledger_entry_sha256,
            },
            "commit_status": "committed_inactive",
            "runtime_effect": "none",
        }


class AuthenticatedCollaborationMissionPolicyService:
    """Authenticate, consume, and atomically commit one mission policy."""

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
        self._activation = AuthenticatedCollaborationActivationService(
            store,
            registry,
            clock=self._clock,
        )
        self._work = AuthenticatedWorkItemLeaseService(
            store,
            registry,
            clock=self._clock,
        )

    def get(
        self,
        mission_id: str,
        *,
        policy_version: int | None = None,
    ) -> AuthenticatedCollaborationMissionPolicyCommitReceipt:
        """Return one verified durable policy without consuming authority."""

        if not isinstance(mission_id, str) or MISSION_ID_PATTERN.fullmatch(mission_id) is None:
            raise StoreError("mission_id is not a valid mission ID")
        if policy_version is not None and (
            not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
        ):
            raise StoreError("policy_version must be a positive integer")
        try:
            with self._store._read_connection() as connection:
                self._activation._verified_mission_state(connection, mission_id)
                if policy_version is None:
                    row = connection.execute(
                        """
                        SELECT * FROM collaboration_mission_policy_commits
                        WHERE mission_id = ?
                        ORDER BY policy_version DESC
                        LIMIT 1
                        """,
                        (mission_id,),
                    ).fetchone()
                else:
                    row = connection.execute(
                        """
                        SELECT * FROM collaboration_mission_policy_commits
                        WHERE mission_id = ? AND policy_version = ?
                        """,
                        (mission_id, policy_version),
                    ).fetchone()
                if row is None:
                    raise StoreConflictError(
                        "Mission has no matching committed reconfiguration policy"
                    )
                owner_use = connection.execute(
                    """
                    SELECT * FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (row["owner_issuer"], row["owner_assertion_id"]),
                ).fetchone()
                control_use = connection.execute(
                    """
                    SELECT * FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (row["control_issuer"], row["control_assertion_id"]),
                ).fetchone()
                if owner_use is None or control_use is None:
                    raise StoreIntegrityError("Mission policy principal provenance is missing")
                return self._receipt(row, owner_use, control_use)
        except sqlite3.Error as exc:
            raise StoreError("Could not read collaboration mission policy") from exc

    def commit(
        self,
        policy: CollaborationMissionReconfigurationPolicy,
        *,
        authority_policy: CollaborationReconfigurationAuthorityPolicy,
        mission_owner_assertion: PrincipalAssertion,
        independent_control_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationMissionPolicyCommitReceipt:
        """Commit one exact authenticated policy or replay its durable result."""

        if not isinstance(policy, CollaborationMissionReconfigurationPolicy):
            raise TypeError("policy must be a CollaborationMissionReconfigurationPolicy")
        if not isinstance(
            authority_policy,
            CollaborationReconfigurationAuthorityPolicy,
        ):
            raise TypeError(
                "authority_policy must be a CollaborationReconfigurationAuthorityPolicy"
            )
        owner_assertion = self._assertion(
            mission_owner_assertion,
            "mission_owner_assertion",
        )
        control_assertion = self._assertion(
            independent_control_assertion,
            "independent_control_assertion",
        )
        if (
            owner_assertion.issuer == control_assertion.issuer
            and owner_assertion.assertion_id == control_assertion.assertion_id
        ):
            raise PrincipalAuthenticationError(
                "Mission policy commit requires two distinct assertions"
            )
        parsed_policy = CollaborationMissionReconfigurationPolicy.from_dict(policy.to_dict())
        parsed_authority = CollaborationReconfigurationAuthorityPolicy.from_dict(
            authority_policy.to_dict()
        )
        document = parsed_policy.to_dict()
        mission_id = document["mission_id"]
        selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(parsed_policy)
        owner_intent = self._operation_intent(
            mission_id,
            selection_sha256,
            owner_assertion.profile_id,
        )
        control_intent = self._operation_intent(
            mission_id,
            selection_sha256,
            control_assertion.profile_id,
        )
        owner_material = self._assertion_material(
            owner_assertion,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            owner_intent,
        )
        control_material = self._assertion_material(
            control_assertion,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            control_intent,
        )
        policy_json = canonical_json(document)
        authority_json = canonical_json(parsed_authority.to_dict())

        try:
            with self._store._write_connection() as connection:
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                    ledger,
                ) = self._activation._verified_mission_state(connection, mission_id)
                _, plan = self._work._load_activation(connection, mission_id)
                owner_use = self._existing_use(connection, owner_assertion)
                control_use = self._existing_use(connection, control_assertion)
                if owner_use is not None or control_use is not None:
                    if owner_use is None or control_use is None:
                        raise StoreConflictError(
                            "Mission policy replay has incomplete assertion use"
                        )
                    self._require_exact_replay(
                        owner_use,
                        assertion=owner_assertion,
                        mission_id=mission_id,
                        operation=(PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE),
                        material=owner_material,
                    )
                    self._require_exact_replay(
                        control_use,
                        assertion=control_assertion,
                        mission_id=mission_id,
                        operation=(PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE),
                        material=control_material,
                    )
                    row = self._row_for_assertions(
                        connection,
                        owner_assertion,
                        control_assertion,
                    )
                    self._require_exact_commit(
                        row,
                        policy_json=policy_json,
                        authority_policy_json=authority_json,
                        selection_sha256=selection_sha256,
                    )
                    return self._receipt(row, owner_use, control_use)

                self._require_active(connection, mission_id)
                previous_policy = self._latest_policy(connection, mission_id)
                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "collaboration mission policy committed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                verified_policy, owner_scope = self._verified_scope(
                    connection,
                    assertion=owner_assertion,
                    operation=(PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE),
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                )
                control_verified_policy, control_scope = self._verified_scope(
                    connection,
                    assertion=control_assertion,
                    operation=(PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE),
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                )
                if control_verified_policy.policy_sha256 != verified_policy.policy_sha256:
                    raise PrincipalAuthenticationError(
                        "Mission policy approvals use different trust policies"
                    )
                plan_anchor_transition = self._store._mission_policy_signed_plan_anchor_transition(
                    connection,
                    policy=parsed_policy,
                    previous_policy=previous_policy,
                    store_id=str(identity["store_id"]),
                    registry=self._registry,
                    owner_use_sequence=int(ledger["assertion_count"]) + 1,
                    committed_at=committed_at,
                )
                authenticated = authenticate_collaboration_mission_reconfiguration_policy(
                    parsed_policy,
                    authority_policy=parsed_authority,
                    collaboration_plan=plan,
                    mission_owner_assertion=owner_assertion,
                    independent_control_assertion=control_assertion,
                    verified_policy=verified_policy,
                    mission_owner_scope=owner_scope,
                    independent_control_scope=control_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_control_profile_ids=(mission.control_profile_ids),
                    clock=lambda: now,
                    previous_policy=previous_policy,
                    plan_anchor_transition=plan_anchor_transition,
                )
                common_payload = {
                    "authentication_id": authenticated.authentication_id,
                    "authentication_sha256": authenticated.authentication_sha256,
                    "mission_context_sha256": mission.context_hash,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "policy_sha256": parsed_policy.policy_sha256,
                    "selection_sha256": selection_sha256,
                    "store_id": str(identity["store_id"]),
                }
                owner_effect = self._effect(
                    parsed_policy.policy_id,
                    PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
                    {**common_payload, "policy_role": "mission_owner"},
                    committed_at,
                )
                control_effect = self._effect(
                    parsed_policy.policy_id,
                    PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
                    {
                        **common_payload,
                        "policy_role": "independent_control",
                    },
                    committed_at,
                )
                self._record_assertion(
                    connection,
                    principal=authenticated.mission_owner,
                    assertion=owner_assertion,
                    mission_id=mission_id,
                    operation=(PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE),
                    material=owner_material,
                    effect=owner_effect,
                    ledger=ledger,
                    consumed_at=committed_at,
                )
                next_ledger = connection.execute(
                    """
                    SELECT * FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (mission_id,),
                ).fetchone()
                if next_ledger is None:
                    raise StoreIntegrityError("Mission principal ledger disappeared")
                self._record_assertion(
                    connection,
                    principal=authenticated.independent_control,
                    assertion=control_assertion,
                    mission_id=mission_id,
                    operation=(PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE),
                    material=control_material,
                    effect=control_effect,
                    ledger=next_ledger,
                    consumed_at=committed_at,
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_mission_policy_commits(
                        policy_id,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        policy_version,
                        previous_policy_sha256,
                        policy_json,
                        policy_sha256,
                        authority_policy_json,
                        authority_policy_sha256,
                        selection_sha256,
                        authentication_id,
                        authentication_sha256,
                        committed_at,
                        owner_issuer,
                        owner_assertion_id,
                        control_issuer,
                        control_assertion_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed_policy.policy_id,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        document["policy_version"],
                        document["previous_policy_sha256"],
                        policy_json,
                        parsed_policy.policy_sha256,
                        authority_json,
                        parsed_authority.policy_sha256,
                        selection_sha256,
                        authenticated.authentication_id,
                        authenticated.authentication_sha256,
                        committed_at,
                        owner_assertion.issuer,
                        owner_assertion.assertion_id,
                        control_assertion.issuer,
                        control_assertion.assertion_id,
                    ),
                )
                row = self._row_for_assertions(
                    connection,
                    owner_assertion,
                    control_assertion,
                )
                owner_use = self._existing_use(connection, owner_assertion)
                control_use = self._existing_use(connection, control_assertion)
                if owner_use is None or control_use is None:
                    raise StoreIntegrityError("Mission policy assertion use disappeared")
                return self._receipt(row, owner_use, control_use)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Could not commit collaboration mission policy") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit collaboration mission policy") from exc

    @staticmethod
    def _assertion(value: Any, label: str) -> PrincipalAssertion:
        if not isinstance(value, PrincipalAssertion):
            raise PrincipalAuthenticationError(f"{label} must be a PrincipalAssertion")
        return PrincipalAssertion.from_dict(value.to_dict())

    @staticmethod
    def _operation_intent(
        mission_id: str,
        selection_sha256: str,
        principal_profile_id: str,
    ) -> dict[str, str]:
        return {
            "mission_id": mission_id,
            "policy_selection_sha256": selection_sha256,
            "principal_profile_id": principal_profile_id,
        }

    @staticmethod
    def _assertion_material(
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        intent: dict[str, str],
    ) -> dict[str, str]:
        assertion_json = canonical_json(assertion.to_dict())
        intent_json = canonical_json(intent)
        return {
            "assertion_json": assertion_json,
            "assertion_hash": sha256_text(assertion_json),
            "intent_json": intent_json,
            "signed_hash": compute_operation_intent_hash(operation, intent),
            "domain_hash": sha256_text(intent_json),
        }

    @staticmethod
    def _existing_use(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()

    def _require_exact_replay(
        self,
        row: sqlite3.Row,
        *,
        assertion: PrincipalAssertion,
        mission_id: str,
        operation: PrincipalOperation,
        material: dict[str, str],
    ) -> None:
        self._work._require_exact_replay(
            row,
            mission_id=mission_id,
            principal_profile_id=assertion.profile_id,
            operation=operation,
            trust_policy_id=assertion.policy_id,
            trust_policy_version=assertion.policy_version,
            assertion_json=material["assertion_json"],
            assertion_hash=material["assertion_hash"],
            operation_intent_json=material["intent_json"],
            signed_intent_hash=material["signed_hash"],
            domain_request_hash=material["domain_hash"],
            scope_grant_hash=assertion.scope_grant_sha256,
        )

    @staticmethod
    def _require_active(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> None:
        row = connection.execute(
            "SELECT state FROM mission_controls WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Mission control state is missing")
        if row["state"] != "active":
            raise MissionStoppedError("Stopped mission cannot commit a reconfiguration policy")

    @staticmethod
    def _latest_policy(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> CollaborationMissionReconfigurationPolicy | None:
        row = connection.execute(
            """
            SELECT policy_json
            FROM collaboration_mission_policy_commits
            WHERE mission_id = ?
            ORDER BY policy_version DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            return CollaborationMissionReconfigurationPolicy.from_dict(
                json.loads(str(row["policy_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored collaboration mission policy is invalid") from exc

    def _verified_scope(
        self,
        connection: sqlite3.Connection,
        *,
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        mission: StoredMission,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
        scope_grants: dict[str, Any],
        now: datetime,
        consumed_time: datetime,
        allow_expired_for_safety_reduction: bool = False,
    ) -> tuple[VerifiedTrustPolicy, VerifiedScopeGrant]:
        current_policy_hash = identity["trust_policy_hash"]
        if current_policy_hash is None:
            raise StoreConflictError("A current trust policy is required")
        verified_policy = trust_policies.get(str(current_policy_hash))
        if verified_policy is None:
            raise StoreIntegrityError("Current trust policy is missing from history")
        policy_high_water = self._store._trust_policy_high_water_at(
            trust_policies,
            consumed_time,
        )
        if policy_high_water.policy_sha256 != verified_policy.policy_sha256:
            raise PrincipalAuthenticationError("Runtime clock precedes the current trust policy")
        scope_entry = scope_grants.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Principal assertion scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        if (
            parse_timestamp(
                str(scope_row["accepted_at"]),
                "mission_scope_grant.accepted_at",
            )
            > consumed_time
        ):
            raise PrincipalAuthenticationError("Scope grant was accepted after assertion use")
        if (
            self._store._effective_scope_grant_revocation(
                connection,
                scope_row,
            )
            is not None
        ):
            raise PrincipalAuthenticationError("Scope grant is revoked")
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError("Mission has no authenticated scope document hash")
        constraints_hash = sha256_text(canonical_json(mission.mission.to_dict()["constraints"]))
        verified_scope = verify_scope_grant(
            scope_grant,
            verified_policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=mission.mission.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            expected_operation=operation,
            allow_expired_for_safety_reduction=(allow_expired_for_safety_reduction),
            clock=lambda: now,
        )
        return verified_policy, verified_scope

    @staticmethod
    def _effect(
        policy_id: str,
        operation: PrincipalOperation,
        payload: dict[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": policy_id,
            "effect_kind": operation.value,
            "payload": payload,
            "recorded_at": recorded_at,
            "schema_version": 1,
        }

    @staticmethod
    def _record_assertion(
        connection: sqlite3.Connection,
        *,
        principal: Any,
        assertion: PrincipalAssertion,
        mission_id: str,
        operation: PrincipalOperation,
        material: dict[str, str],
        effect: dict[str, Any],
        ledger: sqlite3.Row,
        consumed_at: str,
    ) -> str:
        effect_json = canonical_json(effect)
        effect_hash = sha256_text(effect_json)
        effects_hash = principal_assertion_effects_hash((effect_hash,))
        use_sequence = int(ledger["assertion_count"]) + 1
        previous_hash = str(ledger["head_hash"])
        entry = AuthenticatedMissionControlService._assertion_entry(
            principal=principal,
            assertion=assertion,
            mission_id=mission_id,
            use_sequence=use_sequence,
            assertion_hash=material["assertion_hash"],
            operation_intent_json=material["intent_json"],
            signed_intent_hash=material["signed_hash"],
            domain_request_hash=material["domain_hash"],
            idempotency_key_hash=None,
            consumed_at=consumed_at,
            effects_hash=effects_hash,
            previous_hash=previous_hash,
        )
        entry_hash = principal_assertion_entry_hash(entry)
        AuthenticatedMissionControlService._insert_assertion_use(
            connection,
            assertion_json=material["assertion_json"],
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
                mission_id,
                operation.value,
                effect["effect_id"],
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
                mission_id,
                use_sequence - 1,
                int(ledger["effect_count"]),
                previous_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError("Mission principal ledger changed during policy commit")
        return entry_hash

    @staticmethod
    def _row_for_assertions(
        connection: sqlite3.Connection,
        owner_assertion: PrincipalAssertion,
        control_assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM collaboration_mission_policy_commits
            WHERE owner_issuer = ?
              AND owner_assertion_id = ?
              AND control_issuer = ?
              AND control_assertion_id = ?
            """,
            (
                owner_assertion.issuer,
                owner_assertion.assertion_id,
                control_assertion.issuer,
                control_assertion.assertion_id,
            ),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Mission policy assertions have no durable commit")
        return row

    @staticmethod
    def _require_exact_commit(
        row: sqlite3.Row,
        *,
        policy_json: str,
        authority_policy_json: str,
        selection_sha256: str,
    ) -> None:
        if (
            row["policy_json"] != policy_json
            or row["authority_policy_json"] != authority_policy_json
            or row["selection_sha256"] != selection_sha256
        ):
            raise StoreConflictError("Mission policy replay has different content")

    @staticmethod
    def _receipt(
        row: sqlite3.Row,
        owner_use: sqlite3.Row,
        control_use: sqlite3.Row,
    ) -> AuthenticatedCollaborationMissionPolicyCommitReceipt:
        try:
            policy = CollaborationMissionReconfigurationPolicy.from_dict(
                json.loads(str(row["policy_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored collaboration mission policy is invalid") from exc
        return AuthenticatedCollaborationMissionPolicyCommitReceipt(
            policy=policy,
            selection_sha256=str(row["selection_sha256"]),
            authentication_id=str(row["authentication_id"]),
            authentication_sha256=str(row["authentication_sha256"]),
            committed_at=str(row["committed_at"]),
            owner_assertion_id=str(owner_use["assertion_id"]),
            owner_assertion_sha256=str(owner_use["assertion_hash"]),
            owner_ledger_entry_sha256=str(owner_use["entry_hash"]),
            control_assertion_id=str(control_use["assertion_id"]),
            control_assertion_sha256=str(control_use["assertion_hash"]),
            control_ledger_entry_sha256=str(control_use["entry_hash"]),
        )


__all__ = [
    "AuthenticatedCollaborationMissionPolicyCommitReceipt",
    "AuthenticatedCollaborationMissionPolicyService",
]
