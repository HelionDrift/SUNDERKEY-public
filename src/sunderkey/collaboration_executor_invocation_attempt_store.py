"""Atomic SQLite custody for executor invocation attempts."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .collaboration_executor import CollaborationExecutorAcknowledgement
from .collaboration_executor_delivery_claim_store import (
    CollaborationExecutorDeliveryClaimCommitReceipt,
    CollaborationExecutorDeliveryClaimService,
)
from .collaboration_executor_invocation_attempt import (
    CollaborationExecutorInvocationPreparation,
    CollaborationExecutorInvocationResolution,
    build_collaboration_executor_invocation_preparation,
    build_collaboration_executor_invocation_resolution,
)
from .errors import (
    CollaborationPlanError,
    QualificationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp

_ATTEMPT_ID_PATTERN = re.compile(r"EIP-[0-9A-F]{32}")


@dataclass(frozen=True)
class CollaborationExecutorInvocationPreparationCommitReceipt:
    """Receipt for durable-before-invocation preparation custody."""

    preparation_json: str

    @property
    def preparation(self) -> CollaborationExecutorInvocationPreparation:
        try:
            return CollaborationExecutorInvocationPreparation.from_dict(
                json.loads(self.preparation_json)
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor invocation preparation is invalid"
            ) from exc

    @property
    def attempt_id(self) -> str:
        return self.preparation.attempt_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "invocation_preparation": self.preparation.to_dict(),
            "custody_status": "durable_before_invocation",
            "unresolved_recovery_disposition": "treat_as_outcome_uncertain",
            "external_effect_status": "not_started",
            "runtime_effect": "none",
        }


@dataclass(frozen=True)
class CollaborationExecutorInvocationResolutionCommitReceipt:
    """Receipt for one durable terminal local resolution."""

    resolution_json: str

    @property
    def resolution(self) -> CollaborationExecutorInvocationResolution:
        try:
            return CollaborationExecutorInvocationResolution.from_dict(
                json.loads(self.resolution_json)
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor invocation resolution is invalid"
            ) from exc

    @property
    def attempt_id(self) -> str:
        return str(
            self.resolution.to_dict()["invocation_preparation"]["attempt_id"]
        )

    def to_dict(self) -> dict[str, Any]:
        document = self.resolution.to_dict()
        return {
            "schema_version": 1,
            "invocation_resolution": document,
            "custody_status": "durable_terminal_local_resolution",
            "retry_disposition": document["retry_disposition"],
            "external_effect_status": document["external_effect_status"],
            "runtime_effect": "none",
        }


class CollaborationExecutorInvocationAttemptService:
    """Commit preparation and terminal knowledge without invoking an adapter."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._claims = CollaborationExecutorDeliveryClaimService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._claims._store
        self._registry = self._claims._registry
        self._clock = self._claims._clock
        self._activation = self._claims._activation

    def get_preparation(
        self,
        attempt_id: str,
    ) -> CollaborationExecutorInvocationPreparationCommitReceipt | None:
        selected = self._attempt_id(attempt_id)
        try:
            with self._store._read_connection() as connection:
                row = self._preparation_row(connection, selected, required=False)
                if row is None:
                    return None
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._verify(connection, mission)
                return self._preparation_receipt(row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read executor invocation preparation") from exc

    def get_resolution(
        self,
        attempt_id: str,
    ) -> CollaborationExecutorInvocationResolutionCommitReceipt | None:
        selected = self._attempt_id(attempt_id)
        try:
            with self._store._read_connection() as connection:
                preparation = self._preparation_row(
                    connection,
                    selected,
                    required=False,
                )
                if preparation is None:
                    return None
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(preparation["mission_id"]),
                )
                self._verify(connection, mission)
                row = self._resolution_row(connection, selected)
                return None if row is None else self._resolution_receipt(row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read executor invocation resolution") from exc

    def prepare(
        self,
        claim_receipt: CollaborationExecutorDeliveryClaimCommitReceipt,
        operation_input: bytes,
        *,
        adapter_id: str,
        adapter_version: str,
        adapter_build_sha256: str,
        deployment_binding_sha256: str,
        idempotency_status: str,
        idempotency_key_sha256: str | None,
    ) -> CollaborationExecutorInvocationPreparationCommitReceipt:
        if not isinstance(
            claim_receipt,
            CollaborationExecutorDeliveryClaimCommitReceipt,
        ):
            raise TypeError("claim_receipt must be a durable delivery claim receipt")
        claim = claim_receipt.claim
        try:
            with self._store._write_connection() as connection:
                row = self._claims._row(connection, claim.claim_id)
                if str(row["claim_json"]) != claim_receipt.claim_json:
                    raise StoreConflictError(
                        "Executor delivery claim receipt does not match custody"
                    )
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._verify(connection, mission)
                existing = self._preparation_for_claim(connection, claim.claim_id)
                if existing is not None:
                    replay = self._build_preparation(
                        claim_receipt,
                        operation_input,
                        adapter_id=adapter_id,
                        adapter_version=adapter_version,
                        adapter_build_sha256=adapter_build_sha256,
                        deployment_binding_sha256=deployment_binding_sha256,
                        idempotency_status=idempotency_status,
                        idempotency_key_sha256=idempotency_key_sha256,
                        prepared_at=str(existing["prepared_at"]),
                    )
                    if (
                        replay.attempt_id != existing["attempt_id"]
                        or replay.attempt_sha256 != existing["attempt_sha256"]
                    ):
                        raise StoreConflictError(
                            "Executor delivery claim already has another preparation"
                        )
                    return self._preparation_receipt(existing)
                now = self._clock_value()
                prepared_at = format_timestamp(now)
                latest = self._claims._latest(
                    connection,
                    str(row["authentication_id"]),
                )
                if latest is None or latest["claim_id"] != claim.claim_id:
                    raise StoreConflictError(
                        "Executor delivery claim is no longer current"
                    )
                if parse_timestamp(
                    str(row["lease_expires_at"]),
                    "executor_delivery_claim.lease_expires_at",
                ) <= now:
                    raise StoreConflictError(
                        "Executor delivery claim expired before preparation"
                    )
                reservation = self._claims._reservations._row(
                    connection,
                    str(row["authentication_id"]),
                )
                self._claims._require_current_authority(
                    connection,
                    reservation,
                    claimed_at=prepared_at,
                )
                preparation = self._build_preparation(
                    claim_receipt,
                    operation_input,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    adapter_build_sha256=adapter_build_sha256,
                    deployment_binding_sha256=deployment_binding_sha256,
                    idempotency_status=idempotency_status,
                    idempotency_key_sha256=idempotency_key_sha256,
                    prepared_at=prepared_at,
                )
                self._insert_preparation(connection, preparation, row)
                self._store._verify_executor_dispatch_invocation_attempts(
                    connection,
                    mission,
                )
                return self._preparation_receipt(
                    self._preparation_row(
                        connection,
                        preparation.attempt_id,
                        required=True,
                    )
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit executor invocation preparation"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not commit executor invocation preparation"
            ) from exc

    def resolve(
        self,
        attempt_id: str,
        *,
        outcome: str,
        provider_acknowledgement: CollaborationExecutorAcknowledgement | None = None,
        failure_code: str | None = None,
    ) -> CollaborationExecutorInvocationResolutionCommitReceipt:
        selected = self._attempt_id(attempt_id)
        if outcome == "provider_report_received":
            raise StoreConflictError(
                "Provider report custody is required before resolution commit"
            )
        try:
            with self._store._write_connection() as connection:
                preparation_row = self._preparation_row(
                    connection,
                    selected,
                    required=True,
                )
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(preparation_row["mission_id"]),
                )
                self._verify(connection, mission)
                preparation = self._preparation_receipt(
                    preparation_row
                ).preparation
                existing = self._resolution_row(connection, selected)
                resolved_at = (
                    format_timestamp(self._clock_value())
                    if existing is None
                    else str(existing["resolved_at"])
                )
                resolution = build_collaboration_executor_invocation_resolution(
                    preparation,
                    outcome=outcome,
                    provider_acknowledgement=provider_acknowledgement,
                    failure_code=failure_code,
                    resolved_at=resolved_at,
                )
                if existing is not None:
                    if (
                        resolution.resolution_id != existing["resolution_id"]
                        or resolution.resolution_sha256
                        != existing["resolution_sha256"]
                    ):
                        raise StoreConflictError(
                            "Executor invocation attempt already has another resolution"
                        )
                    return self._resolution_receipt(existing)
                self._insert_resolution(
                    connection,
                    resolution,
                    preparation_row,
                )
                self._store._verify_executor_dispatch_invocation_attempts(
                    connection,
                    mission,
                )
                committed = self._resolution_row(connection, selected)
                if committed is None:
                    raise StoreIntegrityError(
                        "Executor invocation resolution is missing after commit"
                    )
                return self._resolution_receipt(committed)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit executor invocation resolution"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not commit executor invocation resolution"
            ) from exc

    def _verify(self, connection: sqlite3.Connection, mission: Any) -> None:
        self._store._verify_executor_dispatch_reservations(connection, mission)
        self._store._verify_executor_dispatch_delivery_claims(connection, mission)
        self._store._verify_executor_dispatch_invocation_attempts(connection, mission)

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
    def _attempt_id(value: str) -> str:
        if (
            not isinstance(value, str)
            or _ATTEMPT_ID_PATTERN.fullmatch(value) is None
        ):
            raise StoreError("attempt_id is invalid")
        return value

    @staticmethod
    def _build_preparation(
        claim_receipt: CollaborationExecutorDeliveryClaimCommitReceipt,
        operation_input: bytes,
        **kwargs: Any,
    ) -> CollaborationExecutorInvocationPreparation:
        return build_collaboration_executor_invocation_preparation(
            claim_receipt,
            operation_input,
            **kwargs,
        )

    @staticmethod
    def _preparation_for_claim(
        connection: sqlite3.Connection,
        claim_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM executor_dispatch_invocation_preparations
            WHERE claim_id = ?
            """,
            (claim_id,),
        ).fetchone()

    @staticmethod
    def _preparation_row(
        connection: sqlite3.Connection,
        attempt_id: str,
        *,
        required: bool,
    ) -> sqlite3.Row | None:
        row = connection.execute(
            """
            SELECT * FROM executor_dispatch_invocation_preparations
            WHERE attempt_id = ?
            """,
            (attempt_id,),
        ).fetchone()
        if required and row is None:
            raise StoreConflictError("Executor invocation preparation is missing")
        return row

    @staticmethod
    def _resolution_row(
        connection: sqlite3.Connection,
        attempt_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM executor_dispatch_invocation_resolutions
            WHERE attempt_id = ?
            """,
            (attempt_id,),
        ).fetchone()

    @staticmethod
    def _preparation_receipt(
        row: sqlite3.Row,
    ) -> CollaborationExecutorInvocationPreparationCommitReceipt:
        return CollaborationExecutorInvocationPreparationCommitReceipt(
            preparation_json=str(row["preparation_json"]),
        )

    @staticmethod
    def _resolution_receipt(
        row: sqlite3.Row,
    ) -> CollaborationExecutorInvocationResolutionCommitReceipt:
        return CollaborationExecutorInvocationResolutionCommitReceipt(
            resolution_json=str(row["resolution_json"]),
        )

    @staticmethod
    def _insert_preparation(
        connection: sqlite3.Connection,
        preparation: CollaborationExecutorInvocationPreparation,
        claim_row: sqlite3.Row,
    ) -> None:
        document = preparation.to_dict()
        connection.execute(
            """
            INSERT INTO executor_dispatch_invocation_preparations(
                attempt_id, attempt_sha256, claim_id, claim_sha256,
                authentication_id, authentication_sha256,
                dispatch_id, dispatch_sha256, mission_id,
                collaboration_plan_id, session_id, session_sha256,
                fence_generation, operation, operation_sequence,
                operation_input_sha256, adapter_id, adapter_version,
                adapter_build_sha256, deployment_binding_sha256,
                idempotency_status, idempotency_key_sha256, prepared_at,
                preparation_json, attempt_status, external_effect_status,
                runtime_effect
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                document["attempt_id"],
                document["attempt_sha256"],
                document["delivery_claim"]["claim_id"],
                document["delivery_claim"]["claim_sha256"],
                document["reservation"]["authentication_id"],
                document["reservation"]["authentication_sha256"],
                document["reservation"]["dispatch_id"],
                document["reservation"]["dispatch_sha256"],
                claim_row["mission_id"],
                claim_row["collaboration_plan_id"],
                document["session"]["session_id"],
                document["session"]["session_sha256"],
                document["session"]["fence_generation"],
                document["operation"]["name"],
                document["operation"]["sequence"],
                document["operation"]["operation_input_sha256"],
                document["adapter"]["adapter_id"],
                document["adapter"]["adapter_version"],
                document["adapter"]["adapter_build_sha256"],
                document["adapter"]["deployment_binding_sha256"],
                document["idempotency"]["status"],
                document["idempotency"]["key_sha256"],
                document["prepared_at"],
                canonical_json(document),
                document["attempt_status"],
                document["external_effect_status"],
                document["runtime_effect"],
            ),
        )

    @staticmethod
    def _insert_resolution(
        connection: sqlite3.Connection,
        resolution: CollaborationExecutorInvocationResolution,
        preparation_row: sqlite3.Row,
    ) -> None:
        document = resolution.to_dict()
        acknowledgement = document["provider_acknowledgement"]
        connection.execute(
            """
            INSERT INTO executor_dispatch_invocation_resolutions(
                resolution_id, resolution_sha256, attempt_id, attempt_sha256,
                mission_id, authentication_id, idempotency_status, outcome,
                acknowledgement_id, acknowledgement_sha256, failure_code,
                resolved_at, retry_disposition, external_effect_status,
                resolution_json, runtime_effect
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document["resolution_id"],
                document["resolution_sha256"],
                document["invocation_preparation"]["attempt_id"],
                document["invocation_preparation"]["attempt_sha256"],
                preparation_row["mission_id"],
                preparation_row["authentication_id"],
                document["invocation_preparation"]["idempotency_status"],
                document["outcome"],
                None if acknowledgement is None else acknowledgement[
                    "acknowledgement_id"
                ],
                None if acknowledgement is None else acknowledgement[
                    "acknowledgement_sha256"
                ],
                document["failure_code"],
                document["resolved_at"],
                document["retry_disposition"],
                document["external_effect_status"],
                canonical_json(document),
                document["runtime_effect"],
            ),
        )


__all__ = [
    "CollaborationExecutorInvocationAttemptService",
    "CollaborationExecutorInvocationPreparationCommitReceipt",
    "CollaborationExecutorInvocationResolutionCommitReceipt",
]
