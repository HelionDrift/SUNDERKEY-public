"""Authenticated approval revocation boundary for the SUNDERKEY runtime."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .approvals import (
    ApprovalRecord,
    ApprovalRevocationRecord,
    _ApprovalDecisionCommand,
    _revoke_command,
)
from .authenticated import AuthenticatedMissionControlService
from .authenticated_approvals import (
    AuthenticatedApprovalDecisionService,
)
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
)
from .store import (
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)


@dataclass(frozen=True)
class AuthenticatedApprovalRevocationReceipt:
    """Immutable result and provenance for one approval revocation."""

    approval: ApprovalRecord
    revocation: ApprovalRevocationRecord
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
            "revocation": self.revocation.to_dict(),
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


class AuthenticatedApprovalRevocationService(
    AuthenticatedApprovalDecisionService
):
    """Verify and commit approval revocation in one transaction."""

    def revoke(
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
    ) -> AuthenticatedApprovalRevocationReceipt:
        """Authenticate and revoke, or return the exact durable retry."""

        checked_assertion = self._checked_assertion(assertion)
        command = _revoke_command(
            approval_id,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
            decision_owner=decision_owner,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=checked_assertion.profile_id,
        )
        return self._revoke(checked_assertion, command)

    def _revoke(
        self,
        assertion: PrincipalAssertion,
        command: _ApprovalDecisionCommand,
    ) -> AuthenticatedApprovalRevocationReceipt:
        operation = PrincipalOperation.APPROVAL_REVOKE
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
                        "Approval revocation intent or idempotency key is "
                        "already bound to another assertion"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated approval revocation consumed_at",
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

                applied = self._approvals._revoke_in_connection(
                    connection,
                    command,
                    now,
                    allow_exact_replay=False,
                    authenticated_principal=True,
                )
                effect = self._approval_revocation_effect(
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
                        "approval revocation"
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
                "Authenticated approval revocation conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated approval revocation"
            ) from exc

    @staticmethod
    def _approval_revocation_effect(
        *,
        applied: Any,
        consumed_at: str,
    ) -> dict[str, Any]:
        operation = PrincipalOperation.APPROVAL_REVOKE
        return {
            "effect_id": applied.event.event_id,
            "effect_kind": operation.value,
            "payload": {
                "approval_id": applied.record.approval_id,
                "approval_record": applied.record.to_dict(),
                "revocation_record": applied.revocation.to_dict(),
                "revocation_event": applied.event.to_dict(),
                "append_receipt": applied.append_receipt.to_dict(),
                "revocation_request_sha256": applied.request_hash,
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
    ) -> AuthenticatedApprovalRevocationReceipt:
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
                "Stored authenticated approval revocation must have "
                "one effect"
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
            revocation = (
                AuthenticatedApprovalRevocationService
                ._revocation_record_from_dict(
                    payload["revocation_record"]
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored authenticated approval revocation effect is invalid"
            ) from exc
        if (
            operation is not PrincipalOperation.APPROVAL_REVOKE
            or effects[0]["effect_kind"] != operation.value
            or approval.approval_id != revocation.approval_id
            or approval.mission_id != revocation.mission_id
            or approval.state.value != "revoked"
            or approval.version != 3
            or revocation.revocation_event_id
            != effects[0]["effect_id"]
        ):
            raise StoreIntegrityError(
                "Stored approval revocation effect binding is invalid"
            )
        return AuthenticatedApprovalRevocationReceipt(
            approval=approval,
            revocation=revocation,
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
    def _revocation_record_from_dict(
        value: Any,
    ) -> ApprovalRevocationRecord:
        if not isinstance(value, dict):
            raise ValueError("revocation record must be an object")
        expected = {
            "schema_version",
            "approval_id",
            "mission_id",
            "authorization_event_id",
            "revocation_event_id",
            "actor_profile_id",
            "revoked_at",
            "reason_code",
            "reason",
            "risk",
            "decision_owner",
            "expected_version",
        }
        if set(value) != expected:
            raise ValueError(
                "revocation record has unexpected fields"
            )
        return ApprovalRevocationRecord(
            schema_version=int(value["schema_version"]),
            approval_id=str(value["approval_id"]),
            mission_id=str(value["mission_id"]),
            authorization_event_id=str(
                value["authorization_event_id"]
            ),
            revocation_event_id=str(
                value["revocation_event_id"]
            ),
            actor_profile_id=str(value["actor_profile_id"]),
            revoked_at=str(value["revoked_at"]),
            reason_code=str(value["reason_code"]),
            reason=str(value["reason"]),
            risk=str(value["risk"]),
            decision_owner=str(value["decision_owner"]),
            expected_version=int(value["expected_version"]),
        )


__all__ = [
    "AuthenticatedApprovalRevocationReceipt",
    "AuthenticatedApprovalRevocationService",
]
