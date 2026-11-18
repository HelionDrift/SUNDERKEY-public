"""Atomic authenticated commit for privileged ownership reassignment."""

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
from .authenticated_collaboration_ownership import (
    AuthenticatedCollaborationOwnershipService,
)
from .collaboration_ownership_chain import CollaborationOwnershipChainEntry
from .collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflightService,
)
from .collaboration_ownership_privileged_reassignment_authentication import (
    authenticate_collaboration_ownership_privileged_reassignment,
)
from .collaboration_ownership_privileged_reassignment_preflight import (
    CollaborationOwnershipPrivilegedReassignmentPreflight,
    CollaborationOwnershipPrivilegedReassignmentPreflightService,
)
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import PrincipalAssertion, PrincipalOperation
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp
from .types import ProfileKind


@dataclass(frozen=True)
class AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt:
    """Durable privileged reassignment and complete authority custody."""

    entry: CollaborationOwnershipChainEntry
    preflight_id: str
    preflight_sha256: str
    authentication_id: str
    authentication_sha256: str
    committed_at: str
    current_owner_assertion_id: str
    current_owner_assertion_sha256: str
    current_owner_ledger_entry_sha256: str
    proposed_owner_assertion_id: str
    proposed_owner_assertion_sha256: str
    proposed_owner_ledger_entry_sha256: str
    control_assertion_id: str
    control_assertion_sha256: str
    control_ledger_entry_sha256: str
    second_authority_assertion_id: str | None
    second_authority_assertion_sha256: str | None
    second_authority_ledger_entry_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        entry = self.entry.to_dict()
        second_authority = (
            None
            if self.second_authority_assertion_id is None
            else {
                "assertion_id": self.second_authority_assertion_id,
                "assertion_sha256": self.second_authority_assertion_sha256,
                "ledger_entry_sha256": (
                    self.second_authority_ledger_entry_sha256
                ),
            }
        )
        return {
            "schema_version": 1,
            "entry": entry,
            "preflight_id": self.preflight_id,
            "preflight_sha256": self.preflight_sha256,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
            "committed_at": self.committed_at,
            "effective_owner": {
                "profile_id": entry["to_owner_id"],
                "owner_epoch": entry["owner_epoch"],
            },
            "current_owner": {
                "assertion_id": self.current_owner_assertion_id,
                "assertion_sha256": self.current_owner_assertion_sha256,
                "ledger_entry_sha256": self.current_owner_ledger_entry_sha256,
            },
            "proposed_owner": {
                "assertion_id": self.proposed_owner_assertion_id,
                "assertion_sha256": self.proposed_owner_assertion_sha256,
                "ledger_entry_sha256": self.proposed_owner_ledger_entry_sha256,
            },
            "independent_control": {
                "assertion_id": self.control_assertion_id,
                "assertion_sha256": self.control_assertion_sha256,
                "ledger_entry_sha256": self.control_ledger_entry_sha256,
            },
            "second_control_or_mission_authority": second_authority,
            "commit_status": "committed_active",
            "runtime_effect": "privileged_ownership_projection_updated",
        }


class AuthenticatedCollaborationOwnershipPrivilegedReassignmentService:
    """Revalidate, consume, and atomically commit one D001 reassignment."""

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
        self._preflights = (
            CollaborationOwnershipPrivilegedReassignmentPreflightService(
                store,
                registry,
                clock=self._clock,
            )
        )
        self._policies = AuthenticatedCollaborationMissionPolicyService(
            store,
            registry,
            clock=self._clock,
        )

    def get(
        self,
        mission_id: str,
        work_item_id: str,
        *,
        entry_id: str | None = None,
    ) -> AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt:
        """Return one verified privileged reassignment without a write."""

        if not isinstance(mission_id, str) or not mission_id:
            raise StoreError("mission_id is invalid")
        if not isinstance(work_item_id, str) or not work_item_id:
            raise StoreError("work_item_id is invalid")
        if entry_id is not None and (
            not isinstance(entry_id, str) or not entry_id
        ):
            raise StoreError("entry_id is invalid")
        try:
            with self._store._read_connection() as connection:
                self._preflights._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                query = (
                    "SELECT * FROM collaboration_ownership_chain_entries "
                    "WHERE mission_id = ? AND work_item_id = ? "
                    "AND transition_kind = 'privileged_reassignment' "
                    + (
                        "ORDER BY sequence DESC LIMIT 1"
                        if entry_id is None
                        else "AND entry_id = ?"
                    )
                )
                parameters = (
                    (mission_id, work_item_id)
                    if entry_id is None
                    else (mission_id, work_item_id, entry_id)
                )
                row = connection.execute(query, parameters).fetchone()
                if row is None:
                    raise StoreConflictError(
                        "Work item has no matching privileged reassignment"
                    )
                return self._receipt_for_row(connection, row)
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read privileged ownership reassignment"
            ) from exc

    def commit(
        self,
        preflight: CollaborationOwnershipPrivilegedReassignmentPreflight,
        *,
        current_owner_assertion: PrincipalAssertion,
        proposed_owner_assertion: PrincipalAssertion,
        independent_control_assertion: PrincipalAssertion,
        second_authority_assertion: PrincipalAssertion | None = None,
    ) -> AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt:
        """Commit exact three-party or four-party D001 authority."""

        if not isinstance(
            preflight,
            CollaborationOwnershipPrivilegedReassignmentPreflight,
        ):
            raise TypeError(
                "preflight must be a privileged reassignment preflight"
            )
        current_assertion = AuthenticatedCollaborationOwnershipService._assertion(
            current_owner_assertion,
            "current_owner_assertion",
        )
        proposed_assertion = AuthenticatedCollaborationOwnershipService._assertion(
            proposed_owner_assertion,
            "proposed_owner_assertion",
        )
        control_assertion = AuthenticatedCollaborationOwnershipService._assertion(
            independent_control_assertion,
            "independent_control_assertion",
        )
        second_assertion = (
            None
            if second_authority_assertion is None
            else AuthenticatedCollaborationOwnershipService._assertion(
                second_authority_assertion,
                "second_authority_assertion",
            )
        )
        if preflight.second_authority_required != (second_assertion is not None):
            raise PrincipalAuthenticationError(
                "Privileged reassignment authority count does not match the role"
            )
        assertions = (
            (current_assertion, proposed_assertion, control_assertion)
            if second_assertion is None
            else (
                current_assertion,
                proposed_assertion,
                control_assertion,
                second_assertion,
            )
        )
        if (
            len({(item.issuer, item.assertion_id) for item in assertions})
            != len(assertions)
            or len({item.profile_id for item in assertions}) != len(assertions)
        ):
            raise PrincipalAuthenticationError(
                "Privileged reassignment requires distinct authorities"
            )
        operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
            *(
                ()
                if second_assertion is None
                else (
                    PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE,
                )
            ),
        )
        parsed_entry = CollaborationOwnershipChainEntry.from_dict(
            preflight.entry.to_dict()
        )
        entry_document = parsed_entry.to_dict()
        preflight_document = preflight.to_dict()
        mission_id = str(entry_document["mission_id"])
        materials = tuple(
            AuthenticatedCollaborationOwnershipService._assertion_material(
                assertion,
                operation,
                AuthenticatedCollaborationOwnershipService._operation_intent(
                    preflight_document,
                    parsed_entry,
                    assertion.profile_id,
                ),
            )
            for assertion, operation in zip(
                assertions,
                operations,
                strict=True,
            )
        )
        entry_json = canonical_json(entry_document)
        preflight_json = canonical_json(preflight_document)
        try:
            with self._store._write_connection() as connection:
                existing = tuple(
                    AuthenticatedCollaborationOwnershipService._existing_use(
                        connection,
                        assertion,
                    )
                    for assertion in assertions
                )
                if any(row is not None for row in existing):
                    if any(row is None for row in existing):
                        raise StoreConflictError(
                            "Privileged reassignment replay has incomplete authority use"
                        )
                    for row, assertion, operation, material in zip(
                        existing,
                        assertions,
                        operations,
                        materials,
                        strict=True,
                    ):
                        assert row is not None
                        self._require_exact_replay(
                            row,
                            assertion=assertion,
                            mission_id=mission_id,
                            operation=operation,
                            material=material,
                        )
                    row = self._row_for_assertions(connection, assertions)
                    if (
                        row["entry_json"] != entry_json
                        or row["preflight_json"] != preflight_json
                    ):
                        raise StoreConflictError(
                            "Privileged reassignment replay has different content"
                        )
                    return self._receipt_for_row(connection, row)

                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "privileged ownership reassignment committed_at",
                )
                evaluated_time = parse_timestamp(
                    str(preflight_document["evaluated_at"]),
                    "privileged ownership reassignment preflight evaluated_at",
                )
                if committed_time < evaluated_time:
                    raise StoreConflictError(
                        "Privileged reassignment commit precedes preflight"
                    )
                live_preflight = self._preflights._evaluate(
                    connection,
                    parsed_entry,
                    evaluated_at=str(preflight_document["evaluated_at"]),
                    evaluated_time=evaluated_time,
                )
                if live_preflight.to_dict() != preflight_document:
                    raise StoreConflictError(
                        "Privileged reassignment preflight no longer matches live state"
                    )
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                    ledger,
                ) = self._preflights._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                self._preflights._work._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                _, plan = self._preflights._work._load_activation(
                    connection,
                    mission_id,
                )
                policy = self._policies._latest_policy(connection, mission_id)
                if policy is None:
                    raise StoreConflictError(
                        "Mission has no committed reconfiguration policy"
                    )
                policy_document = policy.to_dict()
                self._preflights._require_active_policy(
                    policy_document,
                    plan.plan_id,
                    plan.content_sha256,
                    committed_time,
                )
                CollaborationOwnershipTransitionPreflightService._require_transition_window(
                    entry_document,
                    policy_document,
                    committed_time,
                )
                verified = tuple(
                    self._policies._verified_scope(
                        connection,
                        assertion=assertion,
                        operation=operation,
                        mission=mission,
                        identity=identity,
                        trust_policies=trust_policies,
                        scope_grants=scope_grants,
                        now=now,
                        consumed_time=committed_time,
                    )
                    for assertion, operation in zip(
                        assertions,
                        operations,
                        strict=True,
                    )
                )
                if len({item[0].policy_sha256 for item in verified}) != 1:
                    raise PrincipalAuthenticationError(
                        "Privileged reassignment authorities use different trust policies"
                    )
                control_profiles = self._independent_control_profiles()
                authenticated = (
                    authenticate_collaboration_ownership_privileged_reassignment(
                        preflight,
                        current_owner_assertion=current_assertion,
                        proposed_owner_assertion=proposed_assertion,
                        independent_control_assertion=control_assertion,
                        second_authority_assertion=second_assertion,
                        verified_policy=verified[0][0],
                        current_owner_scope=verified[0][1],
                        proposed_owner_scope=verified[1][1],
                        independent_control_scope=verified[2][1],
                        second_authority_scope=(
                            None if second_assertion is None else verified[3][1]
                        ),
                        expected_audience=str(identity["audience"]),
                        expected_store_id=str(identity["store_id"]),
                        expected_control_profile_ids=control_profiles,
                        expected_second_authority_profile_ids=(
                            [] if second_assertion is None else control_profiles
                        ),
                        clock=lambda: now,
                    )
                )
                principals = [
                    authenticated.current_owner,
                    authenticated.proposed_owner,
                    authenticated.independent_control,
                ]
                roles = [
                    "current_owner",
                    "proposed_owner",
                    "independent_control",
                ]
                if authenticated.second_control_or_mission_authority is not None:
                    principals.append(
                        authenticated.second_control_or_mission_authority
                    )
                    roles.append("second_control_or_mission_authority")
                common_payload = {
                    "authentication_id": authenticated.authentication_id,
                    "authentication_sha256": authenticated.authentication_sha256,
                    "chain_id": str(entry_document["chain_id"]),
                    "entry_sha256": parsed_entry.entry_sha256,
                    "mission_context_sha256": mission.context_hash,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "policy_id": policy.policy_id,
                    "policy_sha256": policy.policy_sha256,
                    "preflight_id": str(preflight_document["preflight_id"]),
                    "preflight_sha256": str(
                        preflight_document["preflight_sha256"]
                    ),
                    "store_id": str(identity["store_id"]),
                    "work_item_id": str(entry_document["work_item_id"]),
                }
                current_ledger = ledger
                for principal, assertion, operation, material, role in zip(
                    principals,
                    assertions,
                    operations,
                    materials,
                    roles,
                    strict=True,
                ):
                    effect = AuthenticatedCollaborationOwnershipService._effect(
                        parsed_entry.entry_id,
                        operation,
                        {**common_payload, "ownership_role": role},
                        committed_at,
                    )
                    self._policies._record_assertion(
                        connection,
                        principal=principal,
                        assertion=assertion,
                        mission_id=mission_id,
                        operation=operation,
                        material=material,
                        effect=effect,
                        ledger=current_ledger,
                        consumed_at=committed_at,
                    )
                    current_ledger = connection.execute(
                        "SELECT * FROM mission_principal_ledgers "
                        "WHERE mission_id = ?",
                        (mission_id,),
                    ).fetchone()
                    if current_ledger is None:
                        raise StoreIntegrityError(
                            "Mission principal ledger disappeared"
                        )
                connection.execute(
                    """
                    INSERT INTO collaboration_ownership_chain_entries(
                        entry_id, entry_sha256, chain_id, mission_id, plan_id,
                        plan_content_sha256, work_item_id,
                        work_item_objective_sha256, sequence, owner_epoch,
                        previous_entry_sha256, transition_kind, from_owner_id,
                        to_owner_id, entry_json, preflight_id,
                        preflight_sha256, preflight_json, authentication_id,
                        authentication_sha256, revocation_id,
                        revocation_sha256, revocation_json, committed_at,
                        current_owner_issuer, current_owner_assertion_id,
                        proposed_owner_issuer, proposed_owner_assertion_id,
                        control_issuer, control_assertion_id,
                        second_authority_issuer,
                        second_authority_assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        parsed_entry.entry_id,
                        parsed_entry.entry_sha256,
                        entry_document["chain_id"],
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        entry_document["work_item_id"],
                        entry_document["work_item_objective_sha256"],
                        entry_document["sequence"],
                        entry_document["owner_epoch"],
                        entry_document["previous_entry_sha256"],
                        entry_document["transition_kind"],
                        entry_document["from_owner_id"],
                        entry_document["to_owner_id"],
                        entry_json,
                        preflight_document["preflight_id"],
                        preflight_document["preflight_sha256"],
                        preflight_json,
                        authenticated.authentication_id,
                        authenticated.authentication_sha256,
                        committed_at,
                        current_assertion.issuer,
                        current_assertion.assertion_id,
                        proposed_assertion.issuer,
                        proposed_assertion.assertion_id,
                        control_assertion.issuer,
                        control_assertion.assertion_id,
                        None if second_assertion is None else second_assertion.issuer,
                        (
                            None
                            if second_assertion is None
                            else second_assertion.assertion_id
                        ),
                    ),
                )
                row = self._row_for_assertions(connection, assertions)
                return self._receipt_for_row(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit privileged ownership reassignment"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not commit privileged ownership reassignment"
            ) from exc

    def _independent_control_profiles(self) -> tuple[str, ...]:
        return tuple(
            profile.id
            for profile in self._registry.profiles
            if profile.kind is ProfileKind.SHARED
            and profile.category == "independent control"
            and profile.status in {"defined", "qualified"}
        )

    def _require_exact_replay(
        self,
        row: sqlite3.Row,
        *,
        assertion: PrincipalAssertion,
        mission_id: str,
        operation: PrincipalOperation,
        material: dict[str, str],
    ) -> None:
        self._preflights._work._require_exact_replay(
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
    def _row_for_assertions(
        connection: sqlite3.Connection,
        assertions: tuple[PrincipalAssertion, ...],
    ) -> sqlite3.Row:
        current, proposed, control, *remaining = assertions
        second = None if not remaining else remaining[0]
        row = connection.execute(
            """
            SELECT * FROM collaboration_ownership_chain_entries
            WHERE transition_kind = 'privileged_reassignment'
              AND current_owner_issuer = ?
              AND current_owner_assertion_id = ?
              AND proposed_owner_issuer = ?
              AND proposed_owner_assertion_id = ?
              AND control_issuer = ?
              AND control_assertion_id = ?
              AND second_authority_issuer IS ?
              AND second_authority_assertion_id IS ?
            """,
            (
                current.issuer,
                current.assertion_id,
                proposed.issuer,
                proposed.assertion_id,
                control.issuer,
                control.assertion_id,
                None if second is None else second.issuer,
                None if second is None else second.assertion_id,
            ),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Privileged reassignment assertions have no durable entry"
            )
        return row

    @classmethod
    def _receipt_for_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt:
        uses: list[sqlite3.Row] = []
        role_fields = [
            ("current_owner_issuer", "current_owner_assertion_id"),
            ("proposed_owner_issuer", "proposed_owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
        ]
        if row["second_authority_issuer"] is not None:
            role_fields.append(
                (
                    "second_authority_issuer",
                    "second_authority_assertion_id",
                )
            )
        for issuer_field, assertion_field in role_fields:
            use = connection.execute(
                "SELECT * FROM principal_assertion_uses "
                "WHERE issuer = ? AND assertion_id = ?",
                (row[issuer_field], row[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError(
                    "Privileged reassignment provenance is missing"
                )
            uses.append(use)
        try:
            entry = CollaborationOwnershipChainEntry.from_dict(
                json.loads(str(row["entry_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError(
                "Stored privileged reassignment is invalid"
            ) from exc
        second = None if len(uses) == 3 else uses[3]
        return AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt(
            entry=entry,
            preflight_id=str(row["preflight_id"]),
            preflight_sha256=str(row["preflight_sha256"]),
            authentication_id=str(row["authentication_id"]),
            authentication_sha256=str(row["authentication_sha256"]),
            committed_at=str(row["committed_at"]),
            current_owner_assertion_id=str(uses[0]["assertion_id"]),
            current_owner_assertion_sha256=str(uses[0]["assertion_hash"]),
            current_owner_ledger_entry_sha256=str(uses[0]["entry_hash"]),
            proposed_owner_assertion_id=str(uses[1]["assertion_id"]),
            proposed_owner_assertion_sha256=str(uses[1]["assertion_hash"]),
            proposed_owner_ledger_entry_sha256=str(uses[1]["entry_hash"]),
            control_assertion_id=str(uses[2]["assertion_id"]),
            control_assertion_sha256=str(uses[2]["assertion_hash"]),
            control_ledger_entry_sha256=str(uses[2]["entry_hash"]),
            second_authority_assertion_id=(
                None if second is None else str(second["assertion_id"])
            ),
            second_authority_assertion_sha256=(
                None if second is None else str(second["assertion_hash"])
            ),
            second_authority_ledger_entry_sha256=(
                None if second is None else str(second["entry_hash"])
            ),
        )


__all__ = [
    "AuthenticatedCollaborationOwnershipPrivilegedReassignmentCommitReceipt",
    "AuthenticatedCollaborationOwnershipPrivilegedReassignmentService",
]
