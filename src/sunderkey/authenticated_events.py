"""Authenticated event append boundary for the SUNDERKEY mission runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .events import MissionEvent
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    EVENT_APPEND_EFFECT_KIND,
    AppendReceipt,
    MissionStore,
    canonical_json,
    event_append_batch_hash,
    format_timestamp,
    is_service_event_id,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from .types import EventType


def compute_event_batch_hash(
    events: Iterable[MissionEvent],
) -> str:
    """Hash one exact, ordered event batch with a protocol domain."""

    pending = tuple(events)
    if not pending:
        raise StoreError("At least one event is required")
    if any(not isinstance(event, MissionEvent) for event in pending):
        raise StoreError(
            "events must contain only validated MissionEvent objects"
        )
    return event_append_batch_hash(pending)


@dataclass(frozen=True)
class AuthenticatedEventAppendReceipt:
    """Durable receipt for one authenticated event batch append."""

    receipts: tuple[AppendReceipt, ...]
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
    event_batch_sha256: str
    expected_revision: int
    operation_intent_sha256: str
    consumed_at: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        mission_id = (
            self.receipts[0].mission_id
            if self.receipts
            else None
        )
        return {
            "schema_version": 1,
            "mission_id": mission_id,
            "receipts": [
                receipt.to_dict()
                for receipt in self.receipts
            ],
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
            "operation": PrincipalOperation.EVENT_APPEND.value,
            "event_batch_sha256": self.event_batch_sha256,
            "expected_revision": self.expected_revision,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "consumed_at": self.consumed_at,
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedEventAppendService:
    """Verify and append an authenticated event batch in one transaction."""

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

    def append(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        events: Iterable[MissionEvent],
        *,
        expected_revision: int,
    ) -> AuthenticatedEventAppendReceipt:
        """Authenticate, append, record effects, or return an exact retry."""

        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise StoreError(
                "expected_revision must be a non-negative integer"
            )
        pending = tuple(events)
        if not pending:
            raise StoreError("At least one event is required")
        if len(pending) > 1000:
            raise StoreError(
                "Authenticated event batches cannot exceed 1000 events"
            )
        if any(not isinstance(event, MissionEvent) for event in pending):
            raise StoreError(
                "events must contain only validated MissionEvent objects"
            )
        pending = tuple(
            MissionEvent.from_dict(event.to_dict())
            for event in pending
        )
        if any(event.mission_id != mission_id for event in pending):
            raise StoreError(
                "Every event must match the requested mission ID"
            )
        if any(
            event.actor_profile_id != assertion.profile_id
            for event in pending
        ):
            raise PrincipalAuthenticationError(
                "Every event actor must match the authenticated profile"
            )
        if len({event.event_id for event in pending}) != len(pending):
            raise StoreConflictError(
                "Event batch contains duplicate event IDs"
            )
        if any(
            event.event_type is EventType.AUTHORIZATION
            and event.payload.get("purpose") == "simulation"
            for event in pending
        ):
            raise StoreError(
                "Simulation authorizations must be created through "
                "ApprovalService"
            )
        if any(
            is_service_event_id(event.event_id)
            for event in pending
        ):
            raise StoreError(
                "Service-owned events must be created through their services"
            )

        event_batch_hash = compute_event_batch_hash(pending)
        operation_intent = {
            "event_batch_sha256": event_batch_hash,
            "expected_revision": expected_revision,
            "mission_id": mission_id,
            "principal_profile_id": assertion.profile_id,
        }
        operation_intent_json = canonical_json(operation_intent)
        signed_intent_hash = compute_operation_intent_hash(
            PrincipalOperation.EVENT_APPEND,
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
                        mission_id=mission_id,
                        principal_profile_id=assertion.profile_id,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=assertion.policy_version,
                        assertion_json=assertion_json,
                        assertion_hash=assertion_hash,
                        operation_intent_json=operation_intent_json,
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
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
                      AND domain_request_hash = ?
                    LIMIT 1
                    """,
                    (
                        mission_id,
                        PrincipalOperation.EVENT_APPEND.value,
                        domain_request_hash,
                    ),
                ).fetchone()
                if conflict is not None:
                    raise StoreConflictError(
                        "Event append intent is already "
                        "bound to another assertion"
                    )

                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "authenticated event append consumed_at",
                )
                if any(
                    parse_timestamp(
                        event.timestamp,
                        "authenticated event timestamp",
                    )
                    > consumed_time
                    for event in pending
                ):
                    raise StoreConflictError(
                        "Authenticated events cannot be timestamped "
                        "after credential consumption"
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
                    (mission_id,),
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
                    expected_mission_id=mission_id,
                    expected_mission_context_hash=(
                        mission.context_hash
                    ),
                    expected_scope_reference=(
                        mission.mission.scope_reference
                    ),
                    expected_scope_document_hash=(
                        scope_document_hash
                    ),
                    expected_environment=(
                        mission.mission.environment
                    ),
                    expected_max_action_tier=(
                        mission.mission.max_action_tier
                    ),
                    expected_constraints_hash=constraints_hash,
                    expected_operation=(
                        PrincipalOperation.EVENT_APPEND
                    ),
                    allow_expired_for_safety_reduction=False,
                    clock=lambda: now,
                )
                principal = verify_principal_assertion(
                    assertion,
                    verified_policy,
                    verified_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_mission_id=mission_id,
                    expected_operation=(
                        PrincipalOperation.EVENT_APPEND
                    ),
                    expected_operation_intent_sha256=(
                        signed_intent_hash
                    ),
                    clock=lambda: now,
                )

                self._store._require_mission_active(
                    connection,
                    mission_id,
                )
                if mission.revision != expected_revision:
                    raise StoreConflictError(
                        f"Expected revision {expected_revision} does not "
                        f"match stored revision {mission.revision}"
                    )
                for event in pending:
                    existing_event = connection.execute(
                        """
                        SELECT 1 FROM mission_events
                        WHERE mission_id = ? AND event_id = ?
                        """,
                        (mission_id, event.event_id),
                    ).fetchone()
                    if existing_event is not None:
                        raise StoreConflictError(
                            "Authenticated event append cannot reuse event "
                            f"ID: {event.event_id}"
                        )

                pre_revision = mission.revision
                pre_head_hash = mission.head_hash
                append_receipts = (
                    self._store._append_events_in_connection(
                        connection,
                        self._registry,
                        mission_id,
                        pending,
                        expected_revision=expected_revision,
                        stored_at=consumed_at,
                    )
                )
                effects = self._event_effects(
                    connection,
                    pending=pending,
                    append_receipts=append_receipts,
                    event_batch_hash=event_batch_hash,
                    expected_revision=expected_revision,
                    pre_revision=pre_revision,
                    pre_head_hash=pre_head_hash,
                    consumed_at=consumed_at,
                )
                effect_hashes = tuple(
                    sha256_text(canonical_json(effect))
                    for effect in effects
                )
                effects_hash = principal_assertion_effects_hash(
                    effect_hashes
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
                for effect_index, (
                    effect,
                    effect_hash,
                ) in enumerate(
                    zip(effects, effect_hashes, strict=True),
                    start=1,
                ):
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
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            assertion.issuer,
                            assertion.assertion_id,
                            mission_id,
                            effect_index,
                            EVENT_APPEND_EFFECT_KIND,
                            effect["effect_id"],
                            canonical_json(effect),
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
                        effect_count = effect_count + ?,
                        updated_at = ?
                    WHERE mission_id = ?
                      AND assertion_count = ?
                      AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        len(effects),
                        consumed_at,
                        mission_id,
                        use_sequence - 1,
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during event append"
                    )

                updated_mission = self._mission_from_connection(
                    connection,
                    mission_id,
                )
                updated_ledger, _ = (
                    self._store._load_verified_ledger(
                        connection,
                        updated_mission,
                    )
                )
                self._store._verify_auxiliary_state(
                    connection,
                    updated_mission,
                    updated_ledger,
                )
                self._store._verify_phase4_mission_state(
                    connection,
                    updated_mission,
                    store_id=str(identity["store_id"]),
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
                return self._receipt_from_row(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated event append conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated event append"
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
        mission = self._mission_from_connection(
            connection,
            mission_id,
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

    def _mission_from_connection(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> Any:
        row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreError(f"Unknown stored mission: {mission_id}")
        return self._store._stored_mission_from_row(
            connection,
            self._registry,
            row,
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
            != PrincipalOperation.EVENT_APPEND.value
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
    def _event_effects(
        connection: sqlite3.Connection,
        *,
        pending: tuple[MissionEvent, ...],
        append_receipts: tuple[AppendReceipt, ...],
        event_batch_hash: str,
        expected_revision: int,
        pre_revision: int,
        pre_head_hash: str,
        consumed_at: str,
    ) -> tuple[dict[str, Any], ...]:
        if not append_receipts:
            raise StoreIntegrityError(
                "Authenticated event append produced no receipts"
            )
        final_revision = append_receipts[-1].revision
        final_row = connection.execute(
            """
            SELECT head_hash FROM missions
            WHERE mission_id = ?
            """,
            (pending[0].mission_id,),
        ).fetchone()
        if final_row is None:
            raise StoreIntegrityError(
                "Authenticated event append mission is missing"
            )
        final_head_hash = str(final_row["head_hash"])
        effects: list[dict[str, Any]] = []
        for event_index, (
            event,
            receipt,
        ) in enumerate(
            zip(pending, append_receipts, strict=True),
            start=1,
        ):
            row = connection.execute(
                """
                SELECT * FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (event.mission_id, event.event_id),
            ).fetchone()
            if row is None:
                raise StoreIntegrityError(
                    "Authenticated event append row is missing"
                )
            effects.append(
                {
                    "effect_id": event.event_id,
                    "effect_kind": EVENT_APPEND_EFFECT_KIND,
                    "payload": {
                        "append_receipt": receipt.to_dict(),
                        "event": event.to_dict(),
                        "event_batch_count": len(pending),
                        "event_batch_index": event_index,
                        "event_batch_sha256": event_batch_hash,
                        "event_entry_hash": str(row["entry_hash"]),
                        "event_previous_hash": str(
                            row["previous_hash"]
                        ),
                        "event_sequence": int(row["sequence"]),
                        "event_stored_at": str(row["stored_at"]),
                        "expected_revision": expected_revision,
                        "final_head_hash": final_head_hash,
                        "final_revision": final_revision,
                        "pre_head_hash": pre_head_hash,
                        "pre_revision": pre_revision,
                    },
                    "recorded_at": consumed_at,
                    "schema_version": 1,
                }
            )
        return tuple(effects)

    @staticmethod
    def _receipt_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedEventAppendReceipt:
        try:
            raw_assertion = json.loads(str(row["assertion_json"]))
            assertion = PrincipalAssertion.from_dict(raw_assertion)
            raw_intent = json.loads(
                str(row["operation_intent_json"])
            )
        except (
            json.JSONDecodeError,
            PrincipalAuthenticationError,
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
        receipts: list[AppendReceipt] = []
        for effect in effects:
            try:
                raw_effect = json.loads(str(effect["effect_json"]))
                raw_receipt = raw_effect["payload"][
                    "append_receipt"
                ]
                receipts.append(
                    AppendReceipt(
                        mission_id=str(raw_receipt["mission_id"]),
                        event_id=str(raw_receipt["event_id"]),
                        sequence=int(raw_receipt["sequence"]),
                        revision=int(raw_receipt["revision"]),
                        entry_hash=str(raw_receipt["entry_hash"]),
                        idempotent=bool(
                            raw_receipt["idempotent"]
                        ),
                    )
                )
            except (
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise StoreIntegrityError(
                    "Stored authenticated event effect is invalid"
                ) from exc
        if not receipts:
            raise StoreIntegrityError(
                "Stored authenticated event append has no effects"
            )
        expected_revision = raw_intent.get("expected_revision")
        event_batch_hash = raw_intent.get(
            "event_batch_sha256"
        )
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or not isinstance(event_batch_hash, str)
        ):
            raise StoreIntegrityError(
                "Stored event append intent is invalid"
            )
        if row["idempotency_key_hash"] is not None:
            raise StoreIntegrityError(
                "Stored event append idempotency identity is invalid"
            )
        return AuthenticatedEventAppendReceipt(
            receipts=tuple(receipts),
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
            event_batch_sha256=event_batch_hash,
            expected_revision=expected_revision,
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            consumed_at=str(row["consumed_at"]),
            effects_sha256=str(row["effects_hash"]),
            ledger_entry_sha256=str(row["entry_hash"]),
        )


__all__ = [
    "AuthenticatedEventAppendReceipt",
    "AuthenticatedEventAppendService",
    "compute_event_batch_hash",
]
