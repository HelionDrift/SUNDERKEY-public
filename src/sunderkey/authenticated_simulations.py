"""Authenticated plan-only simulation boundary for the SUNDERKEY runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .approvals import ApprovalRecord
from .authenticated import AuthenticatedMissionControlService
from .authenticated_approvals import (
    AuthenticatedApprovalDecisionService,
)
from .errors import (
    PrincipalAuthenticationError,
    SimulationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
)
from .registry import ExpertRegistry
from .simulation import (
    SimulationReceipt,
    SimulationService,
    _simulation_command,
    _SimulationCommand,
)
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)


@dataclass(frozen=True)
class AuthenticatedSimulationReceipt:
    """Immutable simulation result and authenticated provenance."""

    simulation: SimulationReceipt
    approval: ApprovalRecord
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
    operation: PrincipalOperation
    operation_intent_sha256: str
    consumed_at: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "simulation": self.simulation.to_dict(),
            "approval": self.approval.to_dict(),
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
            "operation": self.operation.value,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "consumed_at": self.consumed_at,
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedSimulationService(
    AuthenticatedApprovalDecisionService
):
    """Verify and consume one simulation approval atomically."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(
            store,
            registry,
            clock=clock,
        )
        self._simulations = SimulationService(
            store,
            registry,
            clock=self._clock,
        )

    def simulate(
        self,
        assertion: PrincipalAssertion,
        approval_id: str,
        *,
        idempotency_key: str,
    ) -> AuthenticatedSimulationReceipt:
        """Authenticate and simulate, or return the exact durable retry."""

        checked_assertion = self._checked_assertion(assertion)
        command = _simulation_command(
            approval_id,
            idempotency_key=idempotency_key,
            principal_profile_id=checked_assertion.profile_id,
        )
        return self._simulate(checked_assertion, command)

    def _simulate(
        self,
        assertion: PrincipalAssertion,
        command: _SimulationCommand,
    ) -> AuthenticatedSimulationReceipt:
        operation = PrincipalOperation.SIMULATION_RUN
        operation_intent = command.operation_intent()
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
                raw_approval = self._approvals._approval_row(
                    connection,
                    command.approval_id,
                )
                mission_id = str(raw_approval["mission_id"])
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                ) = self._verified_mission_state(
                    connection,
                    mission_id,
                )

                existing = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing is not None:
                    self._require_exact_replay(
                        existing,
                        operation=operation,
                        mission_id=mission_id,
                        principal_profile_id=assertion.profile_id,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=assertion.policy_version,
                        assertion_json=assertion_json,
                        assertion_hash=assertion_hash,
                        operation_intent_json=operation_intent_json,
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        idempotency_key_hash=(
                            command.idempotency_key_hash
                        ),
                        scope_grant_hash=(
                            assertion.scope_grant_sha256
                        ),
                    )
                    return self._receipt_from_row(
                        connection,
                        existing,
                    )

                conflict = connection.execute(
                    """
                    SELECT issuer, assertion_id
                    FROM principal_assertion_uses
                    WHERE mission_id = ?
                      AND operation = ?
                      AND (
                          domain_request_hash = ?
                          OR idempotency_key_hash = ?
                      )
                    LIMIT 1
                    """,
                    (
                        mission_id,
                        operation.value,
                        domain_request_hash,
                        command.idempotency_key_hash,
                    ),
                ).fetchone()
                if conflict is not None:
                    raise StoreConflictError(
                        "Simulation intent or idempotency key is "
                        "already bound to another assertion"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated simulation consumed_at",
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
                self._require_runtime_not_before_state(
                    connection,
                    mission,
                    principal_ledger,
                    consumed_time,
                )
                principal = self._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    signed_intent_hash=signed_intent_hash,
                    mission_id=mission_id,
                    identity=identity,
                    trust_policies=trust_policies,
                    mission=mission,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=consumed_time,
                )

                applied = self._simulations._simulate_in_connection(
                    connection,
                    command,
                    now,
                    authenticated_principal=True,
                )
                effect = self._simulation_effect(
                    applied=applied,
                    consumed_at=consumed_at,
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
                        mission_id=mission_id,
                        use_sequence=use_sequence,
                        assertion_hash=assertion_hash,
                        operation_intent_json=operation_intent_json,
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        idempotency_key_hash=(
                            command.idempotency_key_hash
                        ),
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
                      AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        consumed_at,
                        mission_id,
                        use_sequence - 1,
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during "
                        "simulation"
                    )

                self._verified_mission_state(
                    connection,
                    mission_id,
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
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated simulation conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated simulation"
            ) from exc

    @staticmethod
    def _simulation_effect(
        *,
        applied: Any,
        consumed_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": applied.receipt.simulation_id,
            "effect_kind": PrincipalOperation.SIMULATION_RUN.value,
            "payload": {
                "approval_id": applied.approval.approval_id,
                "simulation_id": applied.receipt.simulation_id,
                "approval_record": applied.approval.to_dict(),
                "simulation_receipt": applied.receipt.to_dict(),
                "simulation_request_sha256": (
                    applied.request_hash
                ),
                "idempotency_key_sha256": (
                    applied.idempotency_key_hash
                ),
                "pre_approval_version": (
                    applied.pre_approval_version
                ),
                "pre_approval_state": (
                    applied.pre_approval_state.value
                ),
                "final_approval_version": (
                    applied.final_approval_version
                ),
                "final_approval_state": (
                    applied.final_approval_state.value
                ),
                "pre_mission_revision": (
                    applied.mission_revision
                ),
                "pre_mission_head_hash": (
                    applied.mission_head_hash
                ),
                "final_mission_revision": (
                    applied.mission_revision
                ),
                "final_mission_head_hash": (
                    applied.mission_head_hash
                ),
            },
            "recorded_at": consumed_at,
            "schema_version": 1,
        }

    @staticmethod
    def _receipt_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedSimulationReceipt:
        try:
            assertion = PrincipalAssertion.from_dict(
                json.loads(str(row["assertion_json"]))
            )
            operation = PrincipalOperation(str(row["operation"]))
        except (
            json.JSONDecodeError,
            PrincipalAuthenticationError,
            ValueError,
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
        if len(effects) != 1:
            raise StoreIntegrityError(
                "Stored authenticated simulation must have one effect"
            )
        try:
            effect = json.loads(str(effects[0]["effect_json"]))
            payload = effect["payload"]
            approval = (
                AuthenticatedApprovalDecisionService
                ._approval_record_from_dict(
                    payload["approval_record"]
                )
            )
            simulation = SimulationReceipt.from_dict(
                payload["simulation_receipt"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            SimulationError,
            json.JSONDecodeError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored authenticated simulation effect is invalid"
            ) from exc
        if (
            operation is not PrincipalOperation.SIMULATION_RUN
            or effects[0]["effect_kind"] != operation.value
            or effects[0]["effect_id"] != simulation.simulation_id
            or approval.approval_id != simulation.approval_id
            or approval.mission_id != simulation.mission_id
            or approval.state.value != "consumed"
            or approval.version != 3
            or approval.simulation_id != simulation.simulation_id
        ):
            raise StoreIntegrityError(
                "Stored simulation effect binding is invalid"
            )
        return AuthenticatedSimulationReceipt(
            simulation=simulation,
            approval=approval,
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
            operation=operation,
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            consumed_at=str(row["consumed_at"]),
            effects_sha256=str(row["effects_hash"]),
            ledger_entry_sha256=str(row["entry_hash"]),
        )


__all__ = [
    "AuthenticatedSimulationReceipt",
    "AuthenticatedSimulationService",
]
