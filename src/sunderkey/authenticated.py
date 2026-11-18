"""Authenticated mutation boundaries for the SUNDERKEY mission runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .mission_control import (
    MissionControlRecord,
    MissionControlService,
    _mission_stop_command,
)
from .registry import ExpertRegistry
from .store import (
    MISSION_STOP_EFFECT_KIND,
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)


@dataclass(frozen=True)
class AuthenticatedMissionStopReceipt:
    """Durable receipt for an authenticated terminal mission stop."""

    mission_control: MissionControlRecord
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
            "mission_control": self.mission_control.to_dict(),
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
            "operation": PrincipalOperation.MISSION_STOP.value,
            "operation_intent_sha256": self.operation_intent_sha256,
            "consumed_at": self.consumed_at,
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedMissionControlService:
    """Verify and commit an authenticated mission stop in one transaction."""

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
        self._mission_control = MissionControlService(
            store,
            registry,
            clock=self._clock,
        )

    def stop(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        *,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
        idempotency_key: str,
        expected_version: int,
    ) -> AuthenticatedMissionStopReceipt:
        """Authenticate, stop, record effects, or return an exact retry."""

        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        command = _mission_stop_command(
            mission_id,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
            decision_owner=decision_owner,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=assertion.profile_id,
        )
        operation_intent = command.operation_intent()
        operation_intent_json = canonical_json(operation_intent)
        signed_intent_hash = compute_operation_intent_hash(
            PrincipalOperation.MISSION_STOP,
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
                ) = self._verified_mission_state(
                    connection,
                    command.mission_id,
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
                        mission_id=command.mission_id,
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
                    control = self._mission_control._record_from_row(
                        self._mission_control._control_row(
                            connection,
                            command.mission_id,
                        )
                    )
                    return self._receipt_from_row(
                        existing,
                        control,
                    )

                conflicting_request = connection.execute(
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
                        command.mission_id,
                        PrincipalOperation.MISSION_STOP.value,
                        domain_request_hash,
                        command.idempotency_key_hash,
                    ),
                ).fetchone()
                if conflicting_request is not None:
                    raise StoreConflictError(
                        "Mission stop intent or idempotency key is already "
                        "bound to another assertion"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated mission stop consumed_at",
                )
                principal_ledger = connection.execute(
                    """
                    SELECT updated_at FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (command.mission_id,),
                ).fetchone()
                if principal_ledger is None:
                    raise StoreIntegrityError(
                        "Mission principal ledger is missing"
                    )
                if parse_timestamp(
                    str(principal_ledger["updated_at"]),
                    "mission_principal_ledger.updated_at",
                ) > consumed_time:
                    raise PrincipalAuthenticationError(
                        "Runtime clock precedes the principal ledger"
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

                scope_entry = scope_grants.get(
                    assertion.scope_grant_sha256
                )
                if scope_entry is None:
                    raise PrincipalAuthenticationError(
                        "Principal assertion scope grant is not accepted"
                    )
                scope_row, scope_grant = scope_entry
                accepted_at = parse_timestamp(
                    str(scope_row["accepted_at"]),
                    "mission_scope_grant.accepted_at",
                )
                if accepted_at > consumed_time:
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
                scope_document_hash = (
                    mission.mission.scope_document_hash
                )
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
                    expected_mission_id=command.mission_id,
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
                    expected_operation=PrincipalOperation.MISSION_STOP,
                    allow_expired_for_safety_reduction=True,
                    clock=lambda: now,
                )
                principal = verify_principal_assertion(
                    assertion,
                    verified_policy,
                    verified_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_mission_id=command.mission_id,
                    expected_operation=PrincipalOperation.MISSION_STOP,
                    expected_operation_intent_sha256=(
                        signed_intent_hash
                    ),
                    clock=lambda: now,
                )

                applied = self._mission_control._stop_in_connection(
                    connection,
                    command,
                    now,
                    allow_exact_replay=False,
                    authenticated_principal=True,
                )
                ledger = connection.execute(
                    """
                    SELECT * FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (command.mission_id,),
                ).fetchone()
                if ledger is None:
                    raise StoreIntegrityError(
                        "Mission principal ledger is missing"
                    )
                effect = self._mission_stop_effect(
                    applied=applied,
                    command=command,
                    consumed_at=consumed_at,
                )
                effect_json = canonical_json(effect)
                effect_hash = sha256_text(effect_json)
                effects_hash = principal_assertion_effects_hash(
                    (effect_hash,)
                )
                use_sequence = int(ledger["assertion_count"]) + 1
                previous_hash = str(ledger["head_hash"])
                entry = self._assertion_entry(
                    principal=principal,
                    assertion=assertion,
                    mission_id=command.mission_id,
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
                entry_hash = principal_assertion_entry_hash(entry)
                self._insert_assertion_use(
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
                        command.mission_id,
                        MISSION_STOP_EFFECT_KIND,
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
                        command.mission_id,
                        use_sequence - 1,
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during stop"
                    )
                updated_mission, updated_ledger = (
                    self._mission_control._mission_and_ledger(
                        connection,
                        command.mission_id,
                    )
                )
                self._store._verify_auxiliary_state(
                    connection,
                    updated_mission,
                    updated_ledger,
                )
                updated_scope_grants, _ = (
                    self._store._verify_scope_grants(
                        connection,
                        updated_mission,
                        store_id=str(identity["store_id"]),
                        trust_policies=trust_policies,
                        registry=self._registry,
                    )
                )
                self._store._verify_scope_revocation_state(
                    connection,
                    updated_mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    scope_grants=updated_scope_grants,
                )
                self._store._verify_principal_ledger(
                    connection,
                    updated_mission,
                    store_id=str(identity["store_id"]),
                    scope_grants=updated_scope_grants,
                    trust_policies=trust_policies,
                    registry=self._registry,
                )
                row = connection.execute(
                    """
                    SELECT * FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if row is None:
                    raise StoreIntegrityError(
                        "Authenticated assertion use was not stored"
                    )
                return self._receipt_from_row(
                    row,
                    applied.record,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated mission stop conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated mission stop"
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
        mission, ledger = self._mission_control._mission_and_ledger(
            connection,
            mission_id,
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
        return identity, trust_policies, mission, scope_grants

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
        idempotency_key_hash: str,
        scope_grant_hash: str,
    ) -> None:
        if (
            row["mission_id"] != mission_id
            or row["principal_profile_id"] != principal_profile_id
            or row["trust_policy_id"] != trust_policy_id
            or row["trust_policy_version"] != trust_policy_version
            or row["assertion_json"] != assertion_json
            or row["assertion_hash"] != assertion_hash
            or row["operation"]
            != PrincipalOperation.MISSION_STOP.value
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
    def _mission_stop_effect(
        *,
        applied: Any,
        command: Any,
        consumed_at: str,
    ) -> dict[str, Any]:
        record = applied.record
        if record.stop_event_id is None:
            raise StoreIntegrityError(
                "Authenticated stop has no blocker event"
            )
        return {
            "effect_id": record.stop_event_id,
            "effect_kind": MISSION_STOP_EFFECT_KIND,
            "payload": {
                "blocker_event": applied.blocker_event.to_dict(),
                "event_entry_hash": applied.event_entry_hash,
                "event_sequence": applied.event_sequence,
                "mission_control": record.to_dict(),
                "mission_revision": applied.mission_revision,
                "stop_key_hash": command.idempotency_key_hash,
                "stop_request_hash": command.request_hash,
            },
            "recorded_at": consumed_at,
            "schema_version": 1,
        }

    @staticmethod
    def _assertion_entry(
        *,
        principal: VerifiedPrincipal,
        assertion: PrincipalAssertion,
        mission_id: str,
        use_sequence: int,
        assertion_hash: str,
        operation_intent_json: str,
        signed_intent_hash: str,
        domain_request_hash: str,
        idempotency_key_hash: str,
        consumed_at: str,
        effects_hash: str,
        previous_hash: str,
    ) -> dict[str, Any]:
        return {
            "mission_id": mission_id,
            "use_sequence": use_sequence,
            "issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_hash": assertion_hash,
            "subject": assertion.subject,
            "principal_profile_id": assertion.profile_id,
            "key_id": assertion.key_id,
            "key_hash": principal.key_sha256,
            "audience": assertion.audience,
            "store_id": assertion.store_id,
            "operation": assertion.operation.value,
            "operation_intent_json": operation_intent_json,
            "signed_intent_hash": signed_intent_hash,
            "domain_request_hash": domain_request_hash,
            "idempotency_key_hash": idempotency_key_hash,
            "scope_grant_hash": assertion.scope_grant_sha256,
            "trust_policy_id": assertion.policy_id,
            "trust_policy_version": assertion.policy_version,
            "trust_policy_hash": principal.policy_sha256,
            "issued_at": assertion.issued_at,
            "not_before": assertion.not_before,
            "expires_at": assertion.expires_at,
            "consumed_at": consumed_at,
            "effects_hash": effects_hash,
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _insert_assertion_use(
        connection: sqlite3.Connection,
        *,
        assertion_json: str,
        entry: dict[str, Any],
        entry_hash: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO principal_assertion_uses(
                mission_id,
                use_sequence,
                issuer,
                assertion_id,
                assertion_json,
                assertion_hash,
                subject,
                principal_profile_id,
                key_id,
                key_hash,
                audience,
                store_id,
                operation,
                operation_intent_json,
                signed_intent_hash,
                domain_request_hash,
                idempotency_key_hash,
                scope_grant_hash,
                trust_policy_id,
                trust_policy_version,
                trust_policy_hash,
                issued_at,
                not_before,
                expires_at,
                consumed_at,
                effects_hash,
                previous_hash,
                entry_hash
            ) VALUES (
                :mission_id,
                :use_sequence,
                :issuer,
                :assertion_id,
                :assertion_json,
                :assertion_hash,
                :subject,
                :principal_profile_id,
                :key_id,
                :key_hash,
                :audience,
                :store_id,
                :operation,
                :operation_intent_json,
                :signed_intent_hash,
                :domain_request_hash,
                :idempotency_key_hash,
                :scope_grant_hash,
                :trust_policy_id,
                :trust_policy_version,
                :trust_policy_hash,
                :issued_at,
                :not_before,
                :expires_at,
                :consumed_at,
                :effects_hash,
                :previous_hash,
                :entry_hash
            )
            """,
            {
                **entry,
                "assertion_json": assertion_json,
                "entry_hash": entry_hash,
            },
        )

    @staticmethod
    def _receipt_from_row(
        row: sqlite3.Row,
        control: MissionControlRecord,
    ) -> AuthenticatedMissionStopReceipt:
        try:
            raw_assertion = json.loads(str(row["assertion_json"]))
            assertion = PrincipalAssertion.from_dict(raw_assertion)
        except (
            json.JSONDecodeError,
            PrincipalAuthenticationError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored principal assertion is invalid"
            ) from exc
        return AuthenticatedMissionStopReceipt(
            mission_control=control,
            issuer=str(row["issuer"]),
            assertion_id=str(row["assertion_id"]),
            assertion_sha256=str(row["assertion_hash"]),
            subject=str(row["subject"]),
            principal_profile_id=str(row["principal_profile_id"]),
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
    "AuthenticatedMissionControlService",
    "AuthenticatedMissionStopReceipt",
]
