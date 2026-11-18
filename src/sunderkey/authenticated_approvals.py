"""Authenticated approval decision boundary for the SUNDERKEY runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .approvals import (
    ApprovalPurpose,
    ApprovalRecord,
    ApprovalService,
    ApprovalState,
    _ApprovalDecisionCommand,
    _approve_command,
    _deny_command,
)
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
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
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
)
from .types import ActionTier


@dataclass(frozen=True)
class AuthenticatedApprovalDecisionReceipt:
    """Immutable result and provenance for one approval decision."""

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


class AuthenticatedApprovalDecisionService:
    """Verify and commit approval decisions in one transaction."""

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
        self._approvals = ApprovalService(
            store,
            registry,
            clock=self._clock,
        )

    def approve(
        self,
        assertion: PrincipalAssertion,
        approval_id: str,
        *,
        authority: str,
        constraints: Iterable[str],
        authorization_expires_at: str,
        idempotency_key: str,
        expected_version: int,
    ) -> AuthenticatedApprovalDecisionReceipt:
        """Authenticate and approve, or return the exact durable retry."""

        checked_assertion = self._checked_assertion(assertion)
        command = _approve_command(
            approval_id,
            authority=authority,
            constraints=constraints,
            authorization_expires_at=authorization_expires_at,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=checked_assertion.profile_id,
        )
        return self._decide(
            checked_assertion,
            command,
            PrincipalOperation.APPROVAL_APPROVE,
        )

    def deny(
        self,
        assertion: PrincipalAssertion,
        approval_id: str,
        *,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
        idempotency_key: str,
        expected_version: int,
    ) -> AuthenticatedApprovalDecisionReceipt:
        """Authenticate and deny, or return the exact durable retry."""

        checked_assertion = self._checked_assertion(assertion)
        command = _deny_command(
            approval_id,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
            decision_owner=decision_owner,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=checked_assertion.profile_id,
        )
        return self._decide(
            checked_assertion,
            command,
            PrincipalOperation.APPROVAL_DENY,
        )

    @staticmethod
    def _checked_assertion(
        assertion: PrincipalAssertion,
    ) -> PrincipalAssertion:
        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        return PrincipalAssertion.from_dict(assertion.to_dict())

    def _decide(
        self,
        assertion: PrincipalAssertion,
        command: _ApprovalDecisionCommand,
        operation: PrincipalOperation,
    ) -> AuthenticatedApprovalDecisionReceipt:
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
                    SELECT * FROM principal_assertion_uses
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
                        "Approval decision intent or idempotency key is "
                        "already bound to another assertion"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated approval decision consumed_at",
                )
                principal_ledger = connection.execute(
                    """
                    SELECT * FROM mission_principal_ledgers
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

                if operation is PrincipalOperation.APPROVAL_APPROVE:
                    applied = self._approvals._approve_in_connection(
                        connection,
                        command,
                        now,
                        allow_exact_replay=False,
                        authenticated_principal=True,
                    )
                else:
                    applied = self._approvals._deny_in_connection(
                        connection,
                        command,
                        now,
                        allow_exact_replay=False,
                        authenticated_principal=True,
                    )

                effect = self._approval_decision_effect(
                    applied=applied,
                    operation=operation,
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
                        "approval decision"
                    )

                self._verified_mission_state(
                    connection,
                    mission_id,
                )
                stored_use = connection.execute(
                    """
                    SELECT * FROM principal_assertion_uses
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
                "Authenticated approval decision conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated approval decision"
            ) from exc

    def _verified_mission_state(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[sqlite3.Row, dict[str, Any], Any, dict[str, Any]]:
        identity = self._store._verify_store_identity(
            connection,
            verify_history=False,
        )
        trust_policies = self._store._verify_trust_policy_history(
            connection,
            identity,
        )
        mission, ledger = self._approvals._mission_and_ledger(
            connection,
            mission_id,
        )
        self._store._verify_auxiliary_state(
            connection,
            mission,
            ledger,
        )
        self._store._verify_phase4_mission_state(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            trust_policies=trust_policies,
            registry=self._registry,
        )
        scope_grants, _ = self._store._verify_scope_grants(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            trust_policies=trust_policies,
            registry=self._registry,
        )
        return identity, trust_policies, mission, scope_grants

    @staticmethod
    def _require_runtime_not_before_state(
        connection: sqlite3.Connection,
        mission: Any,
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
        revocation_ledger = connection.execute(
            """
            SELECT updated_at
            FROM mission_scope_revocation_baselines
            WHERE mission_id = ?
            """,
            (mission.mission.mission_id,),
        ).fetchone()
        if (
            revocation_ledger is None
            or parse_timestamp(
                str(revocation_ledger["updated_at"]),
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
        operation: PrincipalOperation,
        signed_intent_hash: str,
        mission_id: str,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
        mission: Any,
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
            expected_mission_id=mission_id,
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
            expected_operation=operation,
            allow_expired_for_safety_reduction=False,
            clock=lambda: now,
        )
        return verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=mission_id,
            expected_operation=operation,
            expected_operation_intent_sha256=signed_intent_hash,
            clock=lambda: now,
        )

    @staticmethod
    def _require_exact_replay(
        row: sqlite3.Row,
        *,
        operation: PrincipalOperation,
        mission_id: str,
        principal_profile_id: str,
        trust_policy_id: str,
        trust_policy_version: int,
        assertion_json: str,
        assertion_hash: str,
        operation_intent_json: str,
        signed_intent_hash: str,
        domain_request_hash: str,
        idempotency_key_hash: str,
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
            or row["operation"] != operation.value
            or row["operation_intent_json"]
            != operation_intent_json
            or row["signed_intent_hash"] != signed_intent_hash
            or row["domain_request_hash"] != domain_request_hash
            or row["idempotency_key_hash"]
            != idempotency_key_hash
            or row["scope_grant_hash"] != scope_grant_hash
        ):
            raise StoreConflictError(
                "Principal assertion replay has different content"
            )

    @staticmethod
    def _approval_decision_effect(
        *,
        applied: Any,
        operation: PrincipalOperation,
        consumed_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": applied.event.event_id,
            "effect_kind": operation.value,
            "payload": {
                "approval_id": applied.record.approval_id,
                "approval_record": applied.record.to_dict(),
                "decision_event": applied.event.to_dict(),
                "append_receipt": applied.append_receipt.to_dict(),
                "decision_request_sha256": applied.request_hash,
                "idempotency_key_sha256": (
                    applied.idempotency_key_hash
                ),
                "expected_approval_version": (
                    applied.expected_approval_version
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
                    applied.pre_mission_revision
                ),
                "pre_mission_head_hash": (
                    applied.pre_mission_head_hash
                ),
                "final_mission_revision": (
                    applied.final_mission_revision
                ),
                "final_mission_head_hash": (
                    applied.final_mission_head_hash
                ),
                "event_sequence": applied.event_sequence,
                "event_previous_hash": (
                    applied.event_previous_hash
                ),
                "event_entry_hash": applied.event_entry_hash,
                "event_stored_at": applied.event_stored_at,
            },
            "recorded_at": consumed_at,
            "schema_version": 1,
        }

    @staticmethod
    def _receipt_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedApprovalDecisionReceipt:
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
            SELECT * FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ?
            ORDER BY effect_index
            """,
            (row["issuer"], row["assertion_id"]),
        ).fetchall()
        if len(effects) != 1:
            raise StoreIntegrityError(
                "Stored authenticated approval decision must have one effect"
            )
        try:
            effect = json.loads(str(effects[0]["effect_json"]))
            approval = (
                AuthenticatedApprovalDecisionService
                ._approval_record_from_dict(
                    effect["payload"]["approval_record"]
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored authenticated approval effect is invalid"
            ) from exc
        if operation not in {
            PrincipalOperation.APPROVAL_APPROVE,
            PrincipalOperation.APPROVAL_DENY,
        }:
            raise StoreIntegrityError(
                "Stored approval decision operation is invalid"
            )
        if effects[0]["effect_kind"] != operation.value:
            raise StoreIntegrityError(
                "Stored approval decision effect kind is invalid"
            )
        return AuthenticatedApprovalDecisionReceipt(
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

    @staticmethod
    def _approval_record_from_dict(
        value: Any,
    ) -> ApprovalRecord:
        if not isinstance(value, dict):
            raise ValueError("approval record must be an object")
        expected = {
            "schema_version",
            "approval_id",
            "mission_id",
            "proposal_id",
            "proposal_hash",
            "proposer_profile_id",
            "executor_profile_id",
            "action_tier",
            "scope_reference",
            "purpose",
            "state",
            "submitted_at",
            "review_expires_at",
            "version",
            "decision_actor_profile_id",
            "decision_at",
            "decision_code",
            "decision_reason",
            "decision_event_id",
            "authorization_event_id",
            "authorization_expires_at",
            "simulation_id",
        }
        if set(value) != expected:
            raise ValueError(
                "approval record has unexpected fields"
            )
        return ApprovalRecord(
            schema_version=int(value["schema_version"]),
            approval_id=str(value["approval_id"]),
            mission_id=str(value["mission_id"]),
            proposal_id=str(value["proposal_id"]),
            proposal_hash=str(value["proposal_hash"]),
            proposer_profile_id=str(
                value["proposer_profile_id"]
            ),
            executor_profile_id=str(
                value["executor_profile_id"]
            ),
            action_tier=ActionTier(str(value["action_tier"])),
            scope_reference=str(value["scope_reference"]),
            purpose=ApprovalPurpose(str(value["purpose"])),
            state=ApprovalState(str(value["state"])),
            submitted_at=str(value["submitted_at"]),
            review_expires_at=str(value["review_expires_at"]),
            version=int(value["version"]),
            decision_actor_profile_id=(
                None
                if value["decision_actor_profile_id"] is None
                else str(value["decision_actor_profile_id"])
            ),
            decision_at=(
                None
                if value["decision_at"] is None
                else str(value["decision_at"])
            ),
            decision_code=(
                None
                if value["decision_code"] is None
                else str(value["decision_code"])
            ),
            decision_reason=(
                None
                if value["decision_reason"] is None
                else str(value["decision_reason"])
            ),
            decision_event_id=(
                None
                if value["decision_event_id"] is None
                else str(value["decision_event_id"])
            ),
            authorization_event_id=(
                None
                if value["authorization_event_id"] is None
                else str(value["authorization_event_id"])
            ),
            authorization_expires_at=(
                None
                if value["authorization_expires_at"] is None
                else str(value["authorization_expires_at"])
            ),
            simulation_id=(
                None
                if value["simulation_id"] is None
                else str(value["simulation_id"])
            ),
        )


__all__ = [
    "AuthenticatedApprovalDecisionReceipt",
    "AuthenticatedApprovalDecisionService",
]
