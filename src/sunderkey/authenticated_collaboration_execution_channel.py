"""Authenticated durable commit for execution-channel policies."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .collaboration_execution_channel import (
    CollaborationExecutionChannelPolicy,
    collaboration_execution_channel_selection_sha256,
)
from .collaboration_execution_channel_authentication import (
    authenticate_collaboration_execution_channel_policy,
)
from .collaboration_mission_policy import CollaborationMissionReconfigurationPolicy
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .events import MISSION_ID_PATTERN
from .identity import PrincipalAssertion, PrincipalOperation
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt:
    """Immutable execution-channel policy and dual-principal provenance."""

    policy: CollaborationExecutionChannelPolicy
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


class AuthenticatedCollaborationExecutionChannelPolicyService:
    """Authenticate, consume, and atomically commit one channel policy."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy_service = AuthenticatedCollaborationMissionPolicyService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._policy_service._store
        self._registry = self._policy_service._registry
        self._clock = self._policy_service._clock
        self._activation = self._policy_service._activation
        self._work = self._policy_service._work

    def get(
        self,
        mission_id: str,
        *,
        policy_version: int | None = None,
    ) -> AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt:
        """Return one verified durable channel policy without consuming authority."""

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
                        SELECT * FROM execution_channel_policy_commits
                        WHERE mission_id = ?
                        ORDER BY policy_version DESC
                        LIMIT 1
                        """,
                        (mission_id,),
                    ).fetchone()
                else:
                    row = connection.execute(
                        """
                        SELECT * FROM execution_channel_policy_commits
                        WHERE mission_id = ? AND policy_version = ?
                        """,
                        (mission_id, policy_version),
                    ).fetchone()
                if row is None:
                    raise StoreConflictError(
                        "Mission has no matching committed execution channel policy"
                    )
                owner_use = self._assertion_use(
                    connection,
                    str(row["owner_issuer"]),
                    str(row["owner_assertion_id"]),
                )
                control_use = self._assertion_use(
                    connection,
                    str(row["control_issuer"]),
                    str(row["control_assertion_id"]),
                )
                return self._receipt(row, owner_use, control_use)
        except sqlite3.Error as exc:
            raise StoreError("Could not read execution channel policy") from exc

    def commit(
        self,
        policy: CollaborationExecutionChannelPolicy,
        *,
        authority_policy: CollaborationReconfigurationAuthorityPolicy,
        mission_owner_assertion: PrincipalAssertion,
        independent_control_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt:
        """Commit one authenticated channel policy or replay its durable result."""

        if not isinstance(policy, CollaborationExecutionChannelPolicy):
            raise TypeError("policy must be a CollaborationExecutionChannelPolicy")
        if not isinstance(
            authority_policy,
            CollaborationReconfigurationAuthorityPolicy,
        ):
            raise TypeError(
                "authority_policy must be a CollaborationReconfigurationAuthorityPolicy"
            )
        owner_assertion = self._policy_service._assertion(
            mission_owner_assertion,
            "mission_owner_assertion",
        )
        control_assertion = self._policy_service._assertion(
            independent_control_assertion,
            "independent_control_assertion",
        )
        if (
            owner_assertion.issuer == control_assertion.issuer
            and owner_assertion.assertion_id == control_assertion.assertion_id
        ):
            raise PrincipalAuthenticationError(
                "Execution channel policy commit requires two distinct assertions"
            )
        parsed_policy = CollaborationExecutionChannelPolicy.from_dict(policy.to_dict())
        parsed_authority = CollaborationReconfigurationAuthorityPolicy.from_dict(
            authority_policy.to_dict()
        )
        document = parsed_policy.to_dict()
        mission_id = document["mission_id"]
        selection_sha256 = collaboration_execution_channel_selection_sha256(parsed_policy)
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
        owner_operation = PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE
        control_operation = PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE
        owner_material = self._policy_service._assertion_material(
            owner_assertion,
            owner_operation,
            owner_intent,
        )
        control_material = self._policy_service._assertion_material(
            control_assertion,
            control_operation,
            control_intent,
        )
        policy_json = canonical_json(document)
        authority_json = canonical_json(parsed_authority.to_dict())

        try:
            with self._store._write_connection() as connection:
                identity, trust_policies, mission, scope_grants, ledger = (
                    self._activation._verified_mission_state(connection, mission_id)
                )
                _, plan = self._work._load_activation(connection, mission_id)
                mission_policy = self._committed_mission_policy(
                    connection,
                    document["mission_policy"]["policy_id"],
                    document["mission_policy"]["policy_sha256"],
                    mission_id,
                )
                owner_use = self._policy_service._existing_use(connection, owner_assertion)
                control_use = self._policy_service._existing_use(connection, control_assertion)
                if owner_use is not None or control_use is not None:
                    if owner_use is None or control_use is None:
                        raise StoreConflictError(
                            "Execution channel replay has incomplete assertion use"
                        )
                    self._policy_service._require_exact_replay(
                        owner_use,
                        assertion=owner_assertion,
                        mission_id=mission_id,
                        operation=owner_operation,
                        material=owner_material,
                    )
                    self._policy_service._require_exact_replay(
                        control_use,
                        assertion=control_assertion,
                        mission_id=mission_id,
                        operation=control_operation,
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

                self._policy_service._require_active(connection, mission_id)
                previous_policy = self._latest_policy(connection, mission_id)
                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "execution channel policy committed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                verified_policy, owner_scope = self._policy_service._verified_scope(
                    connection,
                    assertion=owner_assertion,
                    operation=owner_operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                )
                control_verified_policy, control_scope = (
                    self._policy_service._verified_scope(
                        connection,
                        assertion=control_assertion,
                        operation=control_operation,
                        mission=mission,
                        identity=identity,
                        trust_policies=trust_policies,
                        scope_grants=scope_grants,
                        now=now,
                        consumed_time=committed_time,
                    )
                )
                if control_verified_policy.policy_sha256 != verified_policy.policy_sha256:
                    raise PrincipalAuthenticationError(
                        "Execution channel approvals use different trust policies"
                    )
                authenticated = authenticate_collaboration_execution_channel_policy(
                    parsed_policy,
                    authority_policy=parsed_authority,
                    mission_policy=mission_policy,
                    collaboration_plan=plan,
                    mission_owner_assertion=owner_assertion,
                    independent_control_assertion=control_assertion,
                    verified_policy=verified_policy,
                    mission_owner_scope=owner_scope,
                    independent_control_scope=control_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_control_profile_ids=mission.control_profile_ids,
                    clock=lambda: now,
                    previous_policy=previous_policy,
                )
                common_payload = {
                    "authentication_id": authenticated.authentication_id,
                    "authentication_sha256": authenticated.authentication_sha256,
                    "mission_context_sha256": mission.context_hash,
                    "mission_policy_id": mission_policy.policy_id,
                    "mission_policy_sha256": mission_policy.policy_sha256,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "channel_policy_sha256": parsed_policy.channel_policy_sha256,
                    "selection_sha256": selection_sha256,
                    "store_id": str(identity["store_id"]),
                }
                owner_effect = self._policy_service._effect(
                    parsed_policy.channel_policy_id,
                    owner_operation,
                    {**common_payload, "policy_role": "mission_owner"},
                    committed_at,
                )
                control_effect = self._policy_service._effect(
                    parsed_policy.channel_policy_id,
                    control_operation,
                    {**common_payload, "policy_role": "independent_control"},
                    committed_at,
                )
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.mission_owner,
                    assertion=owner_assertion,
                    mission_id=mission_id,
                    operation=owner_operation,
                    material=owner_material,
                    effect=owner_effect,
                    ledger=ledger,
                    consumed_at=committed_at,
                )
                next_ledger = connection.execute(
                    "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
                    (mission_id,),
                ).fetchone()
                if next_ledger is None:
                    raise StoreIntegrityError("Mission principal ledger disappeared")
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.independent_control,
                    assertion=control_assertion,
                    mission_id=mission_id,
                    operation=control_operation,
                    material=control_material,
                    effect=control_effect,
                    ledger=next_ledger,
                    consumed_at=committed_at,
                )
                connection.execute(
                    """
                    INSERT INTO execution_channel_policy_commits(
                        channel_policy_id,
                        channel_policy_sha256,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        mission_policy_id,
                        mission_policy_sha256,
                        policy_version,
                        previous_channel_policy_sha256,
                        channel_policy_json,
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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed_policy.channel_policy_id,
                        parsed_policy.channel_policy_sha256,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        mission_policy.policy_id,
                        mission_policy.policy_sha256,
                        document["policy_version"],
                        document["previous_channel_policy_sha256"],
                        policy_json,
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
                owner_use = self._policy_service._existing_use(connection, owner_assertion)
                control_use = self._policy_service._existing_use(connection, control_assertion)
                if owner_use is None or control_use is None:
                    raise StoreIntegrityError("Execution channel assertion use disappeared")
                return self._receipt(row, owner_use, control_use)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Could not commit execution channel policy") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit execution channel policy") from exc

    @staticmethod
    def _operation_intent(
        mission_id: str,
        selection_sha256: str,
        principal_profile_id: str,
    ) -> dict[str, str]:
        return {
            "channel_policy_selection_sha256": selection_sha256,
            "mission_id": mission_id,
            "principal_profile_id": principal_profile_id,
        }

    @staticmethod
    def _committed_mission_policy(
        connection: sqlite3.Connection,
        policy_id: str,
        policy_sha256: str,
        mission_id: str,
    ) -> CollaborationMissionReconfigurationPolicy:
        row = connection.execute(
            """
            SELECT policy_id, policy_sha256, policy_json
            FROM collaboration_mission_policy_commits
            WHERE mission_id = ?
            ORDER BY policy_version DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("A committed mission policy is required")
        if row["policy_id"] != policy_id or row["policy_sha256"] != policy_sha256:
            raise StoreConflictError("Execution channel mission policy is not current")
        try:
            return CollaborationMissionReconfigurationPolicy.from_dict(
                json.loads(str(row["policy_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored mission policy is invalid") from exc

    @staticmethod
    def _latest_policy(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> CollaborationExecutionChannelPolicy | None:
        row = connection.execute(
            """
            SELECT channel_policy_json
            FROM execution_channel_policy_commits
            WHERE mission_id = ?
            ORDER BY policy_version DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            return CollaborationExecutionChannelPolicy.from_dict(
                json.loads(str(row["channel_policy_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored execution channel policy is invalid") from exc

    @staticmethod
    def _assertion_use(
        connection: sqlite3.Connection,
        issuer: str,
        assertion_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (issuer, assertion_id),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Execution channel principal provenance is missing")
        return row

    @staticmethod
    def _row_for_assertions(
        connection: sqlite3.Connection,
        owner_assertion: PrincipalAssertion,
        control_assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_channel_policy_commits
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
            raise StoreConflictError("Execution channel assertions have no durable commit")
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
            row["channel_policy_json"] != policy_json
            or row["authority_policy_json"] != authority_policy_json
            or row["selection_sha256"] != selection_sha256
        ):
            raise StoreConflictError("Execution channel replay has different content")

    @staticmethod
    def _receipt(
        row: sqlite3.Row,
        owner_use: sqlite3.Row,
        control_use: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt:
        try:
            policy = CollaborationExecutionChannelPolicy.from_dict(
                json.loads(str(row["channel_policy_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored execution channel policy is invalid") from exc
        return AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt(
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
    "AuthenticatedCollaborationExecutionChannelPolicyCommitReceipt",
    "AuthenticatedCollaborationExecutionChannelPolicyService",
]
