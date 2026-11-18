"""Authenticated durable commit for independent Control ownership revocation."""

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
from .collaboration_ownership_chain import (
    CollaborationOwnershipChainEntry,
    CollaborationOwnershipRevocation,
)
from .collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflightService,
)
from .collaboration_ownership_revocation_authentication import (
    authenticate_collaboration_ownership_revocation,
)
from .collaboration_ownership_revocation_preflight import (
    CollaborationOwnershipRevocationPreflight,
    CollaborationOwnershipRevocationPreflightService,
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


@dataclass(frozen=True)
class AuthenticatedCollaborationOwnershipRevocationCommitReceipt:
    """Durable revocation entry and its two-principal provenance."""

    entry: CollaborationOwnershipChainEntry
    revocation: CollaborationOwnershipRevocation
    preflight_id: str
    preflight_sha256: str
    authentication_id: str
    authentication_sha256: str
    committed_at: str
    planned_owner_assertion_id: str
    planned_owner_assertion_sha256: str
    planned_owner_ledger_entry_sha256: str
    control_assertion_id: str
    control_assertion_sha256: str
    control_ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        entry = self.entry.to_dict()
        return {
            "schema_version": 1,
            "revocation": self.revocation.to_dict(),
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
            "planned_owner": {
                "assertion_id": self.planned_owner_assertion_id,
                "assertion_sha256": self.planned_owner_assertion_sha256,
                "ledger_entry_sha256": self.planned_owner_ledger_entry_sha256,
            },
            "independent_control": {
                "assertion_id": self.control_assertion_id,
                "assertion_sha256": self.control_assertion_sha256,
                "ledger_entry_sha256": self.control_ledger_entry_sha256,
            },
            "commit_status": "committed_active",
            "runtime_effect": "ownership_projection_updated",
        }


class AuthenticatedCollaborationOwnershipRevocationService:
    """Revalidate, consume, and commit one exact Control revocation."""

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
        self._preflights = CollaborationOwnershipRevocationPreflightService(
            store,
            registry,
            clock=self._clock,
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
    ) -> AuthenticatedCollaborationOwnershipRevocationCommitReceipt:
        """Return a verified revocation commit without consuming authority."""

        if not isinstance(mission_id, str) or not mission_id:
            raise StoreError("mission_id is invalid")
        if not isinstance(work_item_id, str) or not work_item_id:
            raise StoreError("work_item_id is invalid")
        if entry_id is not None and (not isinstance(entry_id, str) or not entry_id):
            raise StoreError("entry_id is invalid")
        try:
            with self._store._read_connection() as connection:
                self._preflights._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                parameters: tuple[str, ...]
                if entry_id is None:
                    query = """
                        SELECT * FROM collaboration_ownership_chain_entries
                        WHERE mission_id = ? AND work_item_id = ?
                          AND transition_kind = 'control_revocation'
                        ORDER BY sequence DESC
                        LIMIT 1
                    """
                    parameters = (mission_id, work_item_id)
                else:
                    query = """
                        SELECT * FROM collaboration_ownership_chain_entries
                        WHERE mission_id = ? AND work_item_id = ?
                          AND entry_id = ?
                          AND transition_kind = 'control_revocation'
                    """
                    parameters = (mission_id, work_item_id, entry_id)
                row = connection.execute(query, parameters).fetchone()
                if row is None:
                    raise StoreConflictError(
                        "Work item has no matching ownership revocation"
                    )
                return self._receipt_for_row(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read collaboration ownership revocation") from exc

    def commit(
        self,
        preflight: CollaborationOwnershipRevocationPreflight,
        *,
        planned_owner_assertion: PrincipalAssertion,
        independent_control_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationOwnershipRevocationCommitReceipt:
        """Commit one exact authenticated revocation or replay its result."""

        if not isinstance(preflight, CollaborationOwnershipRevocationPreflight):
            raise TypeError(
                "preflight must be a CollaborationOwnershipRevocationPreflight"
            )
        planned_assertion = AuthenticatedCollaborationOwnershipService._assertion(
            planned_owner_assertion,
            "planned_owner_assertion",
        )
        control_assertion = AuthenticatedCollaborationOwnershipService._assertion(
            independent_control_assertion,
            "independent_control_assertion",
        )
        assertions = (planned_assertion, control_assertion)
        if len({(item.issuer, item.assertion_id) for item in assertions}) != 2:
            raise PrincipalAuthenticationError(
                "Ownership revocation commit requires two distinct assertions"
            )
        parsed_entry = CollaborationOwnershipChainEntry.from_dict(
            preflight.entry.to_dict()
        )
        parsed_revocation = CollaborationOwnershipRevocation.from_dict(
            preflight.revocation.to_dict()
        )
        entry_document = parsed_entry.to_dict()
        revocation_document = parsed_revocation.to_dict()
        preflight_document = preflight.to_dict()
        mission_id = str(entry_document["mission_id"])
        operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        )
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
            for assertion, operation in zip(assertions, operations, strict=True)
        )
        entry_json = canonical_json(entry_document)
        revocation_json = canonical_json(revocation_document)
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
                            "Ownership revocation replay has incomplete assertion use"
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
                    row = self._row_for_assertions(
                        connection,
                        planned_assertion,
                        control_assertion,
                    )
                    self._require_exact_commit(
                        row,
                        entry_json=entry_json,
                        revocation_json=revocation_json,
                        preflight_json=preflight_json,
                    )
                    return self._receipt_for_row(connection, row)

                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "collaboration ownership revocation committed_at",
                )
                evaluated_time = parse_timestamp(
                    str(preflight_document["evaluated_at"]),
                    "collaboration ownership revocation preflight evaluated_at",
                )
                if committed_time < evaluated_time:
                    raise StoreConflictError(
                        "Ownership revocation commit time precedes preflight evaluation"
                    )
                live_preflight = self._preflights._evaluate(
                    connection,
                    parsed_revocation,
                    evaluated_at=str(preflight_document["evaluated_at"]),
                    evaluated_time=evaluated_time,
                )
                if live_preflight.to_dict() != preflight_document:
                    raise StoreConflictError(
                        "Ownership revocation preflight no longer matches verified live state"
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
                CollaborationOwnershipTransitionPreflightService._require_active_policy(
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
                        "Ownership revocation approvals use different trust policies"
                    )
                authenticated = authenticate_collaboration_ownership_revocation(
                    preflight,
                    planned_owner_assertion=planned_assertion,
                    independent_control_assertion=control_assertion,
                    verified_policy=verified[0][0],
                    planned_owner_scope=verified[0][1],
                    independent_control_scope=verified[1][1],
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_control_profile_ids=mission.control_profile_ids,
                    clock=lambda: now,
                )
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
                    "preflight_sha256": str(preflight_document["preflight_sha256"]),
                    "revocation_id": parsed_revocation.revocation_id,
                    "revocation_sha256": parsed_revocation.revocation_sha256,
                    "store_id": str(identity["store_id"]),
                    "work_item_id": str(entry_document["work_item_id"]),
                }
                principals = (
                    authenticated.planned_owner,
                    authenticated.independent_control,
                )
                roles = ("planned_owner", "independent_control")
                current_ledger = ledger
                ledger_hashes: list[str] = []
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
                    ledger_hashes.append(
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
                        control_issuer, control_assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?
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
                        parsed_revocation.revocation_id,
                        parsed_revocation.revocation_sha256,
                        revocation_json,
                        committed_at,
                        planned_assertion.issuer,
                        planned_assertion.assertion_id,
                        control_assertion.issuer,
                        control_assertion.assertion_id,
                    ),
                )
                row = self._row_for_assertions(
                    connection,
                    planned_assertion,
                    control_assertion,
                )
                return self._receipt_for_row(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit collaboration ownership revocation"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not commit collaboration ownership revocation"
            ) from exc

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
        planned_assertion: PrincipalAssertion,
        control_assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM collaboration_ownership_chain_entries
            WHERE transition_kind = 'control_revocation'
              AND current_owner_issuer IS NULL
              AND current_owner_assertion_id IS NULL
              AND proposed_owner_issuer = ?
              AND proposed_owner_assertion_id = ?
              AND control_issuer = ?
              AND control_assertion_id = ?
            """,
            (
                planned_assertion.issuer,
                planned_assertion.assertion_id,
                control_assertion.issuer,
                control_assertion.assertion_id,
            ),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Ownership revocation assertions have no durable chain entry"
            )
        return row

    @staticmethod
    def _require_exact_commit(
        row: sqlite3.Row,
        *,
        entry_json: str,
        revocation_json: str,
        preflight_json: str,
    ) -> None:
        if (
            row["entry_json"] != entry_json
            or row["revocation_json"] != revocation_json
            or row["preflight_json"] != preflight_json
        ):
            raise StoreConflictError(
                "Ownership revocation replay has different content"
            )

    @classmethod
    def _receipt_for_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationOwnershipRevocationCommitReceipt:
        uses = []
        for issuer_field, assertion_field in (
            ("proposed_owner_issuer", "proposed_owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
        ):
            use = connection.execute(
                "SELECT * FROM principal_assertion_uses "
                "WHERE issuer = ? AND assertion_id = ?",
                (row[issuer_field], row[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError(
                    "Ownership revocation principal provenance is missing"
                )
            uses.append(use)
        try:
            entry = CollaborationOwnershipChainEntry.from_dict(
                json.loads(str(row["entry_json"]))
            )
            revocation = CollaborationOwnershipRevocation.from_dict(
                json.loads(str(row["revocation_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError(
                "Stored ownership revocation is invalid"
            ) from exc
        return AuthenticatedCollaborationOwnershipRevocationCommitReceipt(
            entry=entry,
            revocation=revocation,
            preflight_id=str(row["preflight_id"]),
            preflight_sha256=str(row["preflight_sha256"]),
            authentication_id=str(row["authentication_id"]),
            authentication_sha256=str(row["authentication_sha256"]),
            committed_at=str(row["committed_at"]),
            planned_owner_assertion_id=str(uses[0]["assertion_id"]),
            planned_owner_assertion_sha256=str(uses[0]["assertion_hash"]),
            planned_owner_ledger_entry_sha256=str(uses[0]["entry_hash"]),
            control_assertion_id=str(uses[1]["assertion_id"]),
            control_assertion_sha256=str(uses[1]["assertion_hash"]),
            control_ledger_entry_sha256=str(uses[1]["entry_hash"]),
        )


__all__ = [
    "AuthenticatedCollaborationOwnershipRevocationCommitReceipt",
    "AuthenticatedCollaborationOwnershipRevocationService",
]
