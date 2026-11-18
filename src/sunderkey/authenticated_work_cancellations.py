"""Authenticated work item cancellation for SUNDERKEY."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .collaboration import (
    WORK_ITEM_ID_PATTERN,
    CollaborationPlan,
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
    compute_operation_intent_hash,
)
from .registry import ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
    work_cancellation_id,
)

CANCELLATION_SCOPE = "item_and_descendants"


@dataclass(frozen=True)
class AuthenticatedWorkCancellationReceipt:
    """Immutable independent Control work cancellation provenance."""

    cancellation_id: str
    cancellation_sha256: str
    mission_id: str
    plan_id: str
    plan_content_sha256: str
    work_item_id: str
    owner_profile_id: str
    control_profile_id: str
    expected_generation: int
    previous_transition_id: str | None
    expected_lease_expires_at: str | None
    cancellation_scope: str
    affected_work_item_ids: tuple[str, ...]
    reason_code: str
    reason: str
    risk: str
    decision_owner: str
    cancelled_at: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    operation_intent_sha256: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "cancellation_id": self.cancellation_id,
            "cancellation_sha256": self.cancellation_sha256,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "work_item_id": self.work_item_id,
            "owner_profile_id": self.owner_profile_id,
            "control_profile_id": self.control_profile_id,
            "expected_generation": self.expected_generation,
            "previous_transition_id": self.previous_transition_id,
            "expected_lease_expires_at": (
                self.expected_lease_expires_at
            ),
            "cancellation_scope": self.cancellation_scope,
            "affected_work_item_ids": list(
                self.affected_work_item_ids
            ),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "risk": self.risk,
            "decision_owner": self.decision_owner,
            "cancelled_at": self.cancelled_at,
            "operation": PrincipalOperation.WORK_CANCEL.value,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedWorkCancellationService:
    """Cancel one work item and its descendants as independent Control."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._work = AuthenticatedWorkItemLeaseService(
            store,
            registry,
            clock=clock,
        )
        self._store = store
        self._registry = registry
        self._clock = clock or store._clock

    def cancel(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        expected_generation: int,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
    ) -> AuthenticatedWorkCancellationReceipt:
        """Record one fenced terminal cancellation."""

        self._validate_target(mission_id, work_item_id)
        assertion = self._assertion(assertion)
        operation = PrincipalOperation.WORK_CANCEL
        cancellation_id = work_cancellation_id(
            assertion.issuer,
            assertion.assertion_id,
        )
        try:
            with self._store._write_connection() as connection:
                (
                    identity,
                    policies,
                    mission,
                    grants,
                    ledger,
                ) = self._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                _, plan = self._work._load_activation(
                    connection,
                    mission_id,
                )
                item = self._work._work_item(plan, work_item_id)
                handoff = self._work._handoff_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                owner_profile_id = (
                    self._work._effective_owner_profile_id(
                        item,
                        handoff,
                    )
                )
                affected_ids = self.affected_work_item_ids(
                    plan,
                    work_item_id,
                )
                intent = {
                    "affected_work_item_ids": list(affected_ids),
                    "cancellation_scope": CANCELLATION_SCOPE,
                    "decision_owner": decision_owner,
                    "expected_generation": expected_generation,
                    "expected_lease_expires_at": (
                        expected_lease_expires_at
                    ),
                    "mission_id": mission_id,
                    "owner_profile_id": owner_profile_id,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "previous_transition_id": previous_transition_id,
                    "principal_profile_id": assertion.profile_id,
                    "reason": reason,
                    "reason_code": reason_code,
                    "risk": risk,
                    "work_item_id": work_item_id,
                }
                material = self._assertion_material(
                    assertion,
                    operation,
                    intent,
                )
                existing = self._existing_use(connection, assertion)
                if existing is not None:
                    self._work._require_exact_replay(
                        existing,
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
                    return self._receipt(
                        connection,
                        existing,
                        self._for_assertion(connection, assertion),
                    )
                if assertion.profile_id not in mission.control_profile_ids:
                    raise PrincipalAuthenticationError(
                        "Work cancellation requires an assigned "
                        "independent Control profile"
                    )
                if assertion.profile_id == owner_profile_id:
                    raise PrincipalAuthenticationError(
                        "Work owner cannot cancel its own work item"
                    )
                self._require_active(connection, mission_id)
                latest = self._work._latest_transition(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                generation = (
                    0 if latest is None else int(latest["generation"])
                )
                durable_previous = (
                    None
                    if latest is None
                    else str(latest["transition_id"])
                )
                durable_expiry = (
                    None
                    if latest is None
                    else str(latest["lease_expires_at"])
                )
                if (
                    expected_generation != generation
                    or previous_transition_id != durable_previous
                    or expected_lease_expires_at != durable_expiry
                ):
                    raise StoreConflictError(
                        "Work cancellation fence changed"
                    )
                if (
                    latest is not None
                    and latest["transition_kind"] == "complete"
                ):
                    raise StoreConflictError(
                        "Completed work item cannot be cancelled"
                    )
                if self._cancellation_ids_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ):
                    raise StoreConflictError(
                        "Work item is already cancelled"
                    )
                now = self._clock()
                cancelled_at = format_timestamp(now)
                cancelled_time = parse_timestamp(
                    cancelled_at,
                    "work cancellation cancelled_at",
                )
                self._work._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    cancelled_time,
                )
                principal = self._work._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    signed_intent_hash=material["signed_hash"],
                    mission=mission,
                    identity=identity,
                    trust_policies=policies,
                    scope_grants=grants,
                    now=now,
                    consumed_time=cancelled_time,
                )
                cancellation_hash = sha256_text(
                    canonical_json(
                        {
                            "cancellation_id": cancellation_id,
                            "cancelled_at": cancelled_at,
                            "domain": "sunderkey.work-cancellation.v1",
                            "intent": intent,
                            "mission_context_sha256": (
                                mission.context_hash
                            ),
                            "schema_version": 1,
                            "store_id": str(identity["store_id"]),
                        }
                    )
                )
                effect = {
                    "effect_id": cancellation_id,
                    "effect_kind": operation.value,
                    "payload": {
                        "affected_work_item_ids": list(affected_ids),
                        "cancellation_scope": CANCELLATION_SCOPE,
                        "cancellation_sha256": cancellation_hash,
                        "mission_context_sha256": mission.context_hash,
                        "owner_profile_id": owner_profile_id,
                        "plan_content_sha256": plan.content_sha256,
                        "plan_id": plan.plan_id,
                        "store_id": str(identity["store_id"]),
                        "work_item_id": work_item_id,
                    },
                    "recorded_at": cancelled_at,
                    "schema_version": 1,
                }
                self._record_assertion(
                    connection,
                    principal=principal,
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=cancelled_at,
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_work_item_cancellations(
                        cancellation_id,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        work_item_id,
                        owner_profile_id,
                        control_profile_id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        cancellation_scope,
                        affected_work_item_ids_json,
                        reason_code,
                        reason,
                        risk,
                        decision_owner,
                        cancellation_sha256,
                        cancelled_at,
                        issuer,
                        assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        cancellation_id,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        work_item_id,
                        owner_profile_id,
                        assertion.profile_id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        CANCELLATION_SCOPE,
                        canonical_json(list(affected_ids)),
                        reason_code,
                        reason,
                        risk,
                        decision_owner,
                        cancellation_hash,
                        cancelled_at,
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                )
                self._store._verify_phase4_mission_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=policies,
                    registry=self._registry,
                )
                use = self._existing_use(connection, assertion)
                if use is None:
                    raise StoreIntegrityError(
                        "Work cancellation durable state is incomplete"
                    )
                receipt = self._receipt(
                    connection,
                    use,
                    self._for_assertion(connection, assertion),
                )
                connection.commit()
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated work cancellation conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated work cancellation"
            ) from exc

    def get(
        self,
        cancellation_id: str,
    ) -> AuthenticatedWorkCancellationReceipt:
        """Return one verified cancellation receipt."""

        try:
            with self._store._read_connection() as connection:
                row = connection.execute(
                    """
                    SELECT cancellation.*, use.*
                    FROM collaboration_work_item_cancellations AS cancellation
                    JOIN principal_assertion_uses AS use
                      ON use.issuer = cancellation.issuer
                     AND use.assertion_id = cancellation.assertion_id
                    WHERE cancellation.cancellation_id = ?
                    """,
                    (cancellation_id,),
                ).fetchone()
                if row is None:
                    raise StoreError(
                        "Unknown work cancellation: " + cancellation_id
                    )
                self._store.verify_store(self._registry)
                cancellation = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_work_item_cancellations
                    WHERE cancellation_id = ?
                    """,
                    (cancellation_id,),
                ).fetchone()
                if cancellation is None:
                    raise StoreIntegrityError(
                        "Work cancellation disappeared during read"
                    )
                return self._receipt(
                    connection,
                    row,
                    cancellation,
                )
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read authenticated work cancellation"
            ) from exc

    @staticmethod
    def affected_work_item_ids(
        plan: CollaborationPlan,
        work_item_id: str,
    ) -> tuple[str, ...]:
        """Return a target and every transitive graph descendant."""

        affected = {work_item_id}
        changed = True
        while changed:
            changed = False
            for item in plan.work_items:
                if (
                    item.work_item_id not in affected
                    and affected.intersection(item.dependency_ids)
                ):
                    affected.add(item.work_item_id)
                    changed = True
        return tuple(sorted(affected))

    @staticmethod
    def _assertion(
        assertion: PrincipalAssertion,
    ) -> PrincipalAssertion:
        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        return PrincipalAssertion.from_dict(assertion.to_dict())

    @staticmethod
    def _validate_target(
        mission_id: str,
        work_item_id: str,
    ) -> None:
        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is not a valid mission ID")
        if (
            not isinstance(work_item_id, str)
            or WORK_ITEM_ID_PATTERN.fullmatch(work_item_id) is None
        ):
            raise StoreError(
                "work_item_id is not a valid collaboration work item ID"
            )

    @staticmethod
    def _assertion_material(
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        intent: dict[str, Any],
    ) -> dict[str, str]:
        assertion_json = canonical_json(assertion.to_dict())
        intent_json = canonical_json(intent)
        return {
            "assertion_json": assertion_json,
            "assertion_hash": sha256_text(assertion_json),
            "intent_json": intent_json,
            "signed_hash": compute_operation_intent_hash(
                operation,
                intent,
            ),
            "domain_hash": sha256_text(intent_json),
        }

    @staticmethod
    def _existing_use(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT *
            FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()

    @staticmethod
    def _require_active(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT state
            FROM mission_controls
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Mission control state is missing"
            )
        if row["state"] != "active":
            raise MissionStoppedError(
                "Stopped mission cannot cancel work"
            )

    @staticmethod
    def _cancellation_ids_for_item(
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> tuple[str, ...]:
        rows = connection.execute(
            """
            SELECT cancellation_id, affected_work_item_ids_json
            FROM collaboration_work_item_cancellations
            WHERE plan_id = ?
            ORDER BY cancellation_id
            """,
            (plan_id,),
        ).fetchall()
        return tuple(
            str(row["cancellation_id"])
            for row in rows
            if work_item_id
            in json.loads(str(row["affected_work_item_ids_json"]))
        )

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
            raise StoreConflictError(
                "Mission principal ledger changed during work cancellation"
            )
        return entry_hash

    @staticmethod
    def _for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_cancellations
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Work cancellation assertion has no durable cancellation"
            )
        return row

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection,
        use: sqlite3.Row,
        row: sqlite3.Row,
    ) -> AuthenticatedWorkCancellationReceipt:
        assertion = PrincipalAssertion.from_dict(
            json.loads(str(use["assertion_json"]))
        )
        affected = tuple(
            json.loads(str(row["affected_work_item_ids_json"]))
        )
        return AuthenticatedWorkCancellationReceipt(
            cancellation_id=str(row["cancellation_id"]),
            cancellation_sha256=str(row["cancellation_sha256"]),
            mission_id=str(row["mission_id"]),
            plan_id=str(row["plan_id"]),
            plan_content_sha256=str(row["plan_content_sha256"]),
            work_item_id=str(row["work_item_id"]),
            owner_profile_id=str(row["owner_profile_id"]),
            control_profile_id=str(row["control_profile_id"]),
            expected_generation=int(row["expected_generation"]),
            previous_transition_id=(
                None
                if row["previous_transition_id"] is None
                else str(row["previous_transition_id"])
            ),
            expected_lease_expires_at=(
                None
                if row["expected_lease_expires_at"] is None
                else str(row["expected_lease_expires_at"])
            ),
            cancellation_scope=str(row["cancellation_scope"]),
            affected_work_item_ids=affected,
            reason_code=str(row["reason_code"]),
            reason=str(row["reason"]),
            risk=str(row["risk"]),
            decision_owner=str(row["decision_owner"]),
            cancelled_at=str(row["cancelled_at"]),
            issuer=str(use["issuer"]),
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            effects_sha256=str(use["effects_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )


__all__ = [
    "AuthenticatedWorkCancellationReceipt",
    "AuthenticatedWorkCancellationService",
    "CANCELLATION_SCOPE",
]
