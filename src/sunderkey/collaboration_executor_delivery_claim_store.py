"""Atomic SQLite custody for provider-neutral executor delivery claims."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .authenticated_collaboration_executor_dispatch import (
    AuthenticatedCollaborationExecutorDispatchService,
)
from .collaboration_executor_delivery_claim import (
    MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS,
    CollaborationExecutorDeliveryClaim,
    build_collaboration_executor_delivery_claim,
)
from .errors import (
    CollaborationPlanError,
    MissionStoppedError,
    QualificationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp
from .validation import is_ascii_text

_AUTHENTICATION_ID_PATTERN = re.compile(r"EDA-[0-9A-F]{32}")
_INSTANCE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")


@dataclass(frozen=True)
class CollaborationExecutorDeliveryClaimCommitReceipt:
    """Durable custody receipt for one claim generation."""

    claim_json: str

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    @property
    def claim(self) -> CollaborationExecutorDeliveryClaim:
        try:
            raw = json.loads(self.claim_json)
            return CollaborationExecutorDeliveryClaim.from_dict(raw)
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor delivery claim is invalid"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "delivery_claim": self.claim.to_dict(),
            "custody_status": "durable_delivery_claim",
            "external_effect_status": "not_started",
            "runtime_effect": "none",
        }


class CollaborationExecutorDeliveryClaimService:
    """Claim reserved dispatch delivery without invoking its adapter."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._reservations = AuthenticatedCollaborationExecutorDispatchService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._reservations._store
        self._registry = self._reservations._registry
        self._clock = self._reservations._clock
        self._activation = self._reservations._activation

    def get_latest(
        self,
        authentication_id: str,
    ) -> CollaborationExecutorDeliveryClaimCommitReceipt | None:
        selected = self._authentication_id(authentication_id)
        try:
            with self._store._read_connection() as connection:
                reservation = self._reservations._row(connection, selected)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(reservation["mission_id"]),
                )
                self._store._verify_executor_dispatch_reservations(
                    connection,
                    mission,
                )
                self._store._verify_executor_dispatch_delivery_claims(
                    connection,
                    mission,
                )
                row = self._latest(connection, selected)
                return None if row is None else self._receipt(row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read executor delivery claim") from exc

    def claim(
        self,
        authentication_id: str,
        *,
        claimant_instance_id: str,
        lease_seconds: int,
    ) -> CollaborationExecutorDeliveryClaimCommitReceipt:
        selected = self._authentication_id(authentication_id)
        claimant = self._claimant_instance_id(claimant_instance_id)
        lease = self._lease_seconds(lease_seconds)
        try:
            with self._store._write_connection() as connection:
                reservation = self._reservations._row(connection, selected)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(reservation["mission_id"]),
                )
                self._store._verify_executor_dispatch_reservations(
                    connection,
                    mission,
                )
                self._store._verify_executor_dispatch_delivery_claims(
                    connection,
                    mission,
                )
                now = self._clock_value()
                latest = self._latest(connection, selected)
                if latest is not None and parse_timestamp(
                    str(latest["lease_expires_at"]),
                    "executor_delivery_claim.lease_expires_at",
                ) > now:
                    if latest["claimant_instance_id"] != claimant:
                        raise StoreConflictError(
                            "Executor delivery reservation has an active claimant"
                        )
                    return self._receipt(latest)
                claimed_at = format_timestamp(now)
                self._require_current_authority(
                    connection,
                    reservation,
                    claimed_at=claimed_at,
                )
                reservation_receipt = self._reservations._receipt(
                    connection,
                    reservation,
                )
                previous_claim = None if latest is None else self._claim(latest)
                claim = build_collaboration_executor_delivery_claim(
                    reservation_receipt,
                    claimant_instance_id=claimant,
                    claimed_at=claimed_at,
                    lease_expires_at=format_timestamp(
                        now + timedelta(seconds=lease)
                    ),
                    previous_claim=previous_claim,
                )
                self._insert(connection, claim)
                self._store._verify_executor_dispatch_delivery_claims(
                    connection,
                    mission,
                )
                return self._receipt(self._row(connection, claim.claim_id))
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit executor delivery claim"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit executor delivery claim") from exc

    def _clock_value(self) -> datetime:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise StoreError("clock must return a timezone-aware datetime")
        return now.astimezone(UTC).replace(microsecond=0)

    @staticmethod
    def _authentication_id(value: str) -> str:
        if (
            not isinstance(value, str)
            or _AUTHENTICATION_ID_PATTERN.fullmatch(value) is None
        ):
            raise StoreError("authentication_id is invalid")
        return value

    @staticmethod
    def _claimant_instance_id(value: str) -> str:
        if (
            not isinstance(value, str)
            or _INSTANCE_ID_PATTERN.fullmatch(value) is None
            or not is_ascii_text(value)
        ):
            raise StoreError("claimant_instance_id is invalid")
        return value

    @staticmethod
    def _lease_seconds(value: int) -> int:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS
        ):
            raise StoreError(
                "lease_seconds must be between 1 and "
                f"{MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS}"
            )
        return value

    @staticmethod
    def _require_current_authority(
        connection: sqlite3.Connection,
        reservation: sqlite3.Row,
        *,
        claimed_at: str,
    ) -> None:
        if parse_timestamp(
            claimed_at,
            "executor_delivery_claim.claimed_at",
        ) >= parse_timestamp(
            str(reservation["expires_at"]),
            "executor_dispatch_reservation.expires_at",
        ):
            raise StoreConflictError("Executor dispatch expired before delivery claim")
        if bool(reservation["safety_reduction"]):
            return
        control = connection.execute(
            "SELECT state FROM mission_controls WHERE mission_id = ?",
            (reservation["mission_id"],),
        ).fetchone()
        if control is None or control["state"] != "active":
            raise MissionStoppedError(
                "Stopped mission cannot claim ordinary executor delivery"
            )
        revocation = connection.execute(
            """
            SELECT 1 FROM execution_session_revocation_commits
            WHERE session_authority_id = ? AND revoked_at <= ?
            """,
            (reservation["session_authority_id"], claimed_at),
        ).fetchone()
        if revocation is not None:
            raise StoreConflictError(
                "Revoked authority cannot claim ordinary executor delivery"
            )

    @staticmethod
    def _latest(
        connection: sqlite3.Connection,
        authentication_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM executor_dispatch_delivery_claims
            WHERE authentication_id = ?
            ORDER BY claim_generation DESC
            LIMIT 1
            """,
            (authentication_id,),
        ).fetchone()

    @staticmethod
    def _row(
        connection: sqlite3.Connection,
        claim_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM executor_dispatch_delivery_claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Executor delivery claim is missing")
        return row

    @staticmethod
    def _claim(row: sqlite3.Row) -> CollaborationExecutorDeliveryClaim:
        try:
            return CollaborationExecutorDeliveryClaim.from_dict(
                json.loads(str(row["claim_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor delivery claim is invalid"
            ) from exc

    @staticmethod
    def _receipt(
        row: sqlite3.Row,
    ) -> CollaborationExecutorDeliveryClaimCommitReceipt:
        return CollaborationExecutorDeliveryClaimCommitReceipt(
            claim_json=str(row["claim_json"]),
        )

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        claim: CollaborationExecutorDeliveryClaim,
    ) -> None:
        document = claim.to_dict()
        predecessor = document["predecessor"]
        connection.execute(
            """
            INSERT INTO executor_dispatch_delivery_claims(
                claim_id,
                claim_sha256,
                authentication_id,
                authentication_sha256,
                dispatch_id,
                dispatch_sha256,
                mission_id,
                collaboration_plan_id,
                session_id,
                session_sha256,
                fence_generation,
                operation,
                operation_sequence,
                operation_input_sha256,
                claimant_instance_id,
                claim_generation,
                predecessor_claim_id,
                predecessor_claim_sha256,
                predecessor_lease_expires_at,
                claimed_at,
                lease_expires_at,
                claim_json,
                claim_status,
                claimant_identity_status,
                external_effect_status,
                runtime_effect
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                document["claim_id"],
                document["claim_sha256"],
                document["reservation"]["authentication_id"],
                document["reservation"]["authentication_sha256"],
                document["reservation"]["dispatch_id"],
                document["reservation"]["dispatch_sha256"],
                document["mission"]["mission_id"],
                document["mission"]["collaboration_plan_id"],
                document["session"]["session_id"],
                document["session"]["session_sha256"],
                document["session"]["fence_generation"],
                document["operation"]["name"],
                document["operation"]["sequence"],
                document["operation"]["operation_input_sha256"],
                document["claimant"]["instance_id"],
                document["claim_generation"],
                None if predecessor is None else predecessor["claim_id"],
                None if predecessor is None else predecessor["claim_sha256"],
                None if predecessor is None else predecessor["lease_expires_at"],
                document["claimed_at"],
                document["lease_expires_at"],
                canonical_json(document),
                document["claim_status"],
                document["claimant_identity_status"],
                document["external_effect_status"],
                document["runtime_effect"],
            ),
        )


__all__ = [
    "CollaborationExecutorDeliveryClaimCommitReceipt",
    "CollaborationExecutorDeliveryClaimService",
]
