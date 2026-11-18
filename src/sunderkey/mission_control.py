"""Terminal mission stop controls for the local SUNDERKEY runtime."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .errors import (
    MissionControlError,
    MissionStoppedError,
    StoreConflictError,
    StoreError,
)
from .events import MISSION_ID_PATTERN, PROFILE_ID_PATTERN, MissionEvent
from .identity import PrincipalOperation, validate_operation_intent
from .registry import ExpertRegistry
from .store import (
    AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION,
    MissionStore,
    allocate_control_event_id,
    format_timestamp,
    mission_stop_request_hash,
    parse_timestamp,
    sha256_text,
    utc_now,
)
from .types import EventType
from .validation import is_ascii_text


class MissionControlState(StrEnum):
    ACTIVE = "active"
    STOPPED = "stopped"


class MissionStopReason(StrEnum):
    OPERATOR_REQUEST = "operator_request"
    SCOPE_AMBIGUITY = "scope_ambiguity"
    AUTHORIZATION_WITHDRAWN = "authorization_withdrawn"
    INTEGRITY_FAILURE = "integrity_failure"
    SAFETY_THRESHOLD = "safety_threshold"
    DECONFLICTION_CONFLICT = "deconfliction_conflict"
    EXTERNAL_STOP_SIGNAL = "external_stop_signal"


@dataclass(frozen=True)
class MissionControlRecord:
    schema_version: int
    mission_id: str
    state: MissionControlState
    version: int
    stopped_at: str | None
    stop_actor_profile_id: str | None
    stop_reason_code: str | None
    stop_reason: str | None
    stop_risk: str | None
    stop_decision_owner: str | None
    stop_event_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "state": self.state.value,
            "version": self.version,
            "stopped_at": self.stopped_at,
            "stop_actor_profile_id": self.stop_actor_profile_id,
            "stop_reason_code": self.stop_reason_code,
            "stop_reason": self.stop_reason,
            "stop_risk": self.stop_risk,
            "stop_decision_owner": self.stop_decision_owner,
            "stop_event_id": self.stop_event_id,
        }


@dataclass(frozen=True)
class _MissionStopCommand:
    mission_id: str
    reason_code: str
    reason: str
    risk: str
    decision_owner: str
    idempotency_key_hash: str
    expected_version: int
    principal_profile_id: str
    request_hash: str

    def operation_intent(self) -> dict[str, Any]:
        return {
            "decision_owner": self.decision_owner,
            "expected_version": self.expected_version,
            "idempotency_key_sha256": self.idempotency_key_hash,
            "mission_id": self.mission_id,
            "principal_profile_id": self.principal_profile_id,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class _AppliedMissionStop:
    record: MissionControlRecord
    blocker_event: MissionEvent
    event_sequence: int
    event_entry_hash: str
    mission_revision: int


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not is_ascii_text(value):
        raise MissionControlError(f"{label} must be non-empty ASCII text")
    if len(value) > maximum:
        raise MissionControlError(f"{label} exceeds the maximum length of {maximum}")
    return value


def _key_hash(value: str) -> str:
    return sha256_text(_text(value, "idempotency_key", maximum=256))


def _mission_stop_command(
    mission_id: str,
    *,
    reason_code: str,
    reason: str,
    risk: str,
    decision_owner: str,
    idempotency_key: str,
    expected_version: int,
    principal_profile_id: str,
) -> _MissionStopCommand:
    parsed_mission_id = _text(
        mission_id,
        "mission_id",
        maximum=64,
    )
    if MISSION_ID_PATTERN.fullmatch(parsed_mission_id) is None:
        raise MissionControlError(f"Invalid mission_id: {parsed_mission_id}")
    try:
        parsed_reason_code = MissionStopReason(
            _text(reason_code, "reason_code", maximum=64)
        ).value
    except ValueError as exc:
        raise MissionControlError(
            f"Unsupported mission stop reason: {reason_code}"
        ) from exc
    parsed_profile_id = _text(
        principal_profile_id,
        "principal_profile_id",
        maximum=64,
    )
    if PROFILE_ID_PATTERN.fullmatch(parsed_profile_id) is None:
        raise MissionControlError(
            f"Invalid principal_profile_id: {parsed_profile_id}"
        )
    if (
        not isinstance(expected_version, int)
        or isinstance(expected_version, bool)
        or expected_version < 1
    ):
        raise MissionControlError(
            "expected_version must be a positive integer"
        )
    intent = validate_operation_intent(
        PrincipalOperation.MISSION_STOP,
        {
            "decision_owner": _text(
                decision_owner,
                "decision_owner",
            ),
            "expected_version": expected_version,
            "idempotency_key_sha256": _key_hash(idempotency_key),
            "mission_id": parsed_mission_id,
            "principal_profile_id": parsed_profile_id,
            "reason": _text(reason, "reason"),
            "reason_code": parsed_reason_code,
            "risk": _text(risk, "risk"),
        },
    )
    return _MissionStopCommand(
        mission_id=str(intent["mission_id"]),
        reason_code=str(intent["reason_code"]),
        reason=str(intent["reason"]),
        risk=str(intent["risk"]),
        decision_owner=str(intent["decision_owner"]),
        idempotency_key_hash=str(
            intent["idempotency_key_sha256"]
        ),
        expected_version=int(intent["expected_version"]),
        principal_profile_id=str(intent["principal_profile_id"]),
        request_hash=mission_stop_request_hash(intent),
    )


class MissionControlService:
    """Reads and applies terminal mission stop state."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.store = store
        self.registry = registry
        self._clock = clock

    def get(self, mission_id: str) -> MissionControlRecord:
        mission_id = _text(mission_id, "mission_id", maximum=64)
        if MISSION_ID_PATTERN.fullmatch(mission_id) is None:
            raise MissionControlError(f"Invalid mission_id: {mission_id}")
        try:
            with self.store._read_connection() as connection:
                schema_version = self.store._require_schema(
                    connection
                )
                stored_mission, ledger = self._mission_and_ledger(
                    connection,
                    mission_id,
                )
                self.store._verify_auxiliary_state(
                    connection,
                    stored_mission,
                    ledger,
                )
                if (
                    schema_version
                    >= AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION
                ):
                    identity = self.store._verify_store_identity(
                        connection,
                        verify_history=False,
                    )
                    trust_policies = (
                        self.store._verify_trust_policy_history(
                            connection,
                            identity,
                        )
                    )
                    self.store._verify_phase4_mission_state(
                        connection,
                        stored_mission,
                        store_id=str(identity["store_id"]),
                        trust_policies=trust_policies,
                        registry=self.registry,
                    )
                return self._record_from_row(self._control_row(connection, mission_id))
        except sqlite3.Error as exc:
            raise StoreError("Could not read mission control state") from exc

    def stop(
        self,
        mission_id: str,
        *,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
        idempotency_key: str,
        expected_version: int,
        principal_profile_id: str,
    ) -> MissionControlRecord:
        command = _mission_stop_command(
            mission_id,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
            decision_owner=decision_owner,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=principal_profile_id,
        )
        try:
            with self.store._write_connection() as connection:
                return self._stop_in_connection(
                    connection,
                    command,
                    self._clock(),
                    allow_exact_replay=True,
                ).record
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Could not record mission stop") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist mission stop") from exc

    def _stop_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _MissionStopCommand,
        now: datetime,
        *,
        allow_exact_replay: bool,
        authenticated_principal: bool = False,
    ) -> _AppliedMissionStop:
        stopped_at = format_timestamp(now)
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if (
            schema_version
            >= AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION
        ):
            identity = connection.execute(
                """
                SELECT trust_policy_hash FROM store_identity
                WHERE singleton_id = 1
                """
            ).fetchone()
            if identity is None:
                raise MissionControlError(
                    "Mission store identity is missing"
                )
            if (
                identity["trust_policy_hash"] is not None
                and not authenticated_principal
            ):
                raise MissionControlError(
                    "Authenticated mission stop is required after trust "
                    "policy enrollment"
                )
        stored_mission, ledger = self._mission_and_ledger(
            connection,
            command.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        row = self._control_row(
            connection,
            command.mission_id,
        )
        record = self._record_from_row(row)
        if row["stop_key_hash"] is not None:
            exact_replay = (
                row["stop_key_hash"]
                == command.idempotency_key_hash
                and row["stop_request_hash"] == command.request_hash
            )
            if exact_replay and allow_exact_replay:
                return self._applied_stop(
                    connection,
                    stored_mission.revision,
                    record,
                )
            if exact_replay:
                raise StoreConflictError(
                    "Mission stop already exists outside this assertion"
                )
            raise StoreConflictError(
                "Mission already has a different stop request"
            )
        if record.version != command.expected_version:
            raise StoreConflictError(
                f"Expected mission control version "
                f"{command.expected_version} does not match stored "
                f"version {record.version}"
            )
        if record.state is MissionControlState.STOPPED:
            raise MissionStoppedError(
                f"Mission is stopped: {command.mission_id}"
            )
        if (
            command.principal_profile_id
            not in stored_mission.control_profile_ids
        ):
            raise MissionControlError(
                "Only assigned independent Control can stop a mission"
            )
        event_id = allocate_control_event_id(
            ledger,
            kind="STOP",
            subject_id=command.mission_id,
            key_hash=command.idempotency_key_hash,
            request_hash=command.request_hash,
        )
        blocker = MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": command.mission_id,
                "event_type": EventType.BLOCKER.value,
                "actor_profile_id": command.principal_profile_id,
                "timestamp": stopped_at,
                "payload": {
                    "reason": (
                        f"{command.reason_code}: {command.reason}"
                    ),
                    "risk": command.risk,
                    "decision_owner": command.decision_owner,
                },
                "references": [],
            }
        )
        self.store._append_events_in_connection(
            connection,
            self.registry,
            command.mission_id,
            (blocker,),
            expected_revision=stored_mission.revision,
            allow_control_events=True,
            stored_at=stopped_at,
        )
        cursor = connection.execute(
            """
            UPDATE mission_controls
            SET state = 'stopped',
                version = version + 1,
                stopped_at = ?,
                stop_actor_profile_id = ?,
                stop_reason_code = ?,
                stop_reason = ?,
                stop_risk = ?,
                stop_decision_owner = ?,
                stop_key_hash = ?,
                stop_request_hash = ?,
                stop_event_id = ?
            WHERE mission_id = ?
              AND state = 'active'
              AND version = ?
            """,
            (
                stopped_at,
                command.principal_profile_id,
                command.reason_code,
                command.reason,
                command.risk,
                command.decision_owner,
                command.idempotency_key_hash,
                command.request_hash,
                event_id,
                command.mission_id,
                command.expected_version,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError(
                "Mission control state changed during stop"
            )
        updated_mission, updated_ledger = self._mission_and_ledger(
            connection,
            command.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            updated_mission,
            updated_ledger,
        )
        return self._applied_stop(
            connection,
            updated_mission.revision,
            self._record_from_row(
                self._control_row(connection, command.mission_id)
            ),
        )

    def _applied_stop(
        self,
        connection: sqlite3.Connection,
        mission_revision: int,
        record: MissionControlRecord,
    ) -> _AppliedMissionStop:
        if record.stop_event_id is None:
            raise MissionControlError(
                "Stored mission stop has no blocker event"
            )
        event = connection.execute(
            """
            SELECT event_json, sequence, entry_hash
            FROM mission_events
            WHERE mission_id = ? AND event_id = ?
            """,
            (record.mission_id, record.stop_event_id),
        ).fetchone()
        if event is None:
            raise MissionControlError(
                "Stored mission stop blocker event is missing"
            )
        try:
            raw_event = json.loads(str(event["event_json"]))
            blocker_event = MissionEvent.from_dict(raw_event)
        except (json.JSONDecodeError, ValueError) as exc:
            raise MissionControlError(
                "Stored mission stop blocker event is invalid"
            ) from exc
        return _AppliedMissionStop(
            record=record,
            blocker_event=blocker_event,
            event_sequence=int(event["sequence"]),
            event_entry_hash=str(event["entry_hash"]),
            mission_revision=mission_revision,
        )

    def _mission_and_ledger(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[Any, Any]:
        row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise MissionControlError(f"Unknown stored mission: {mission_id}")
        stored = self.store._stored_mission_from_row(
            connection,
            self.registry,
            row,
        )
        ledger, _ = self.store._load_verified_ledger(connection, stored)
        return stored, ledger

    def _control_row(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM mission_controls WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise MissionControlError(f"Mission control state is missing: {mission_id}")
        return row

    def _record_from_row(
        self,
        row: sqlite3.Row,
    ) -> MissionControlRecord:
        try:
            record = MissionControlRecord(
                schema_version=2,
                mission_id=str(row["mission_id"]),
                state=MissionControlState(str(row["state"])),
                version=int(row["version"]),
                stopped_at=row["stopped_at"],
                stop_actor_profile_id=row["stop_actor_profile_id"],
                stop_reason_code=row["stop_reason_code"],
                stop_reason=row["stop_reason"],
                stop_risk=row["stop_risk"],
                stop_decision_owner=row["stop_decision_owner"],
                stop_event_id=row["stop_event_id"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionControlError("Stored mission control state is invalid") from exc
        stop_values = (
            record.stopped_at,
            record.stop_actor_profile_id,
            record.stop_reason_code,
            record.stop_reason,
            record.stop_risk,
            record.stop_decision_owner,
            record.stop_event_id,
        )
        if record.state is MissionControlState.ACTIVE:
            if record.version != 1 or any(value is not None for value in stop_values):
                raise MissionControlError("Stored active mission control state is invalid")
        else:
            if record.version != 2 or not all(is_ascii_text(value) for value in stop_values):
                raise MissionControlError("Stored stopped mission control state is invalid")
            assert record.stopped_at is not None
            parse_timestamp(record.stopped_at, "mission_control.stopped_at")
        return record
