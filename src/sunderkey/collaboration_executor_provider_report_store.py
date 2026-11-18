"""Atomic custody for complete provider reports and matching resolutions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .collaboration_executor import CollaborationExecutorAcknowledgement
from .collaboration_executor_invocation_attempt import (
    CollaborationExecutorInvocationResolution,
    build_collaboration_executor_invocation_resolution,
)
from .collaboration_executor_invocation_attempt_store import (
    CollaborationExecutorInvocationAttemptService,
)
from .collaboration_executor_provider_report import (
    CollaborationExecutorProviderReport,
    build_collaboration_executor_provider_report,
)
from .errors import (
    CollaborationPlanError,
    QualificationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp


@dataclass(frozen=True)
class CollaborationExecutorProviderReportCommitReceipt:
    """Atomic receipt for full report and terminal local resolution custody."""

    report_json: str
    resolution_json: str

    @property
    def provider_report(self) -> CollaborationExecutorProviderReport:
        try:
            return CollaborationExecutorProviderReport.from_dict(
                json.loads(self.report_json)
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError("Stored executor provider report is invalid") from exc

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
                "Stored executor provider report resolution is invalid"
            ) from exc

    @property
    def attempt_id(self) -> str:
        return str(
            self.provider_report.to_dict()["invocation_preparation"]["attempt_id"]
        )

    def to_dict(self) -> dict[str, Any]:
        report = self.provider_report.to_dict()
        resolution = self.resolution.to_dict()
        acknowledgement = report["provider_acknowledgement"]
        binding = resolution["provider_acknowledgement"]
        if binding != {
            "acknowledgement_id": acknowledgement["acknowledgement_id"],
            "acknowledgement_sha256": acknowledgement["acknowledgement_sha256"],
        }:
            raise StoreIntegrityError(
                "Provider report resolution does not reconcile with report custody"
            )
        return {
            "schema_version": 1,
            "provider_report": report,
            "invocation_resolution": resolution,
            "custody_status": "durable_complete_report_and_resolution",
            "authentication_status": "not_authenticated",
            "external_effect_status": "provider_report_pending_authentication",
            "runtime_effect": "none",
        }


class CollaborationExecutorProviderReportService:
    """Atomically retain a complete report and matching local resolution."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._attempts = CollaborationExecutorInvocationAttemptService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._attempts._store
        self._clock = self._attempts._clock
        self._activation = self._attempts._activation

    def get(
        self,
        attempt_id: str,
    ) -> CollaborationExecutorProviderReportCommitReceipt | None:
        selected = self._attempts._attempt_id(attempt_id)
        try:
            with self._store._read_connection() as connection:
                preparation = self._attempts._preparation_row(
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
                report = self._report_row(connection, selected)
                if report is None:
                    return None
                resolution = self._attempts._resolution_row(connection, selected)
                if resolution is None:
                    raise StoreIntegrityError(
                        "Provider report has no terminal local resolution"
                    )
                return self._receipt(report, resolution)
        except sqlite3.Error as exc:
            raise StoreError("Could not read executor provider report") from exc

    def commit(
        self,
        attempt_id: str,
        provider_acknowledgement: CollaborationExecutorAcknowledgement,
    ) -> CollaborationExecutorProviderReportCommitReceipt:
        selected = self._attempts._attempt_id(attempt_id)
        if not isinstance(provider_acknowledgement, CollaborationExecutorAcknowledgement):
            raise TypeError("provider_acknowledgement must be an executor acknowledgement")
        try:
            with self._store._write_connection() as connection:
                preparation_row = self._attempts._preparation_row(
                    connection,
                    selected,
                    required=True,
                )
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(preparation_row["mission_id"]),
                )
                self._verify(connection, mission)
                preparation = self._attempts._preparation_receipt(
                    preparation_row
                ).preparation
                existing_report = self._report_row(connection, selected)
                existing_resolution = self._attempts._resolution_row(
                    connection,
                    selected,
                )
                received_at = (
                    format_timestamp(self._attempts._clock_value())
                    if existing_report is None
                    else str(existing_report["received_at"])
                )
                report = build_collaboration_executor_provider_report(
                    preparation,
                    provider_acknowledgement,
                    received_at=received_at,
                )
                if existing_report is not None:
                    if (
                        report.report_custody_id
                        != existing_report["report_custody_id"]
                        or report.report_custody_sha256
                        != existing_report["report_custody_sha256"]
                    ):
                        raise StoreConflictError(
                            "Executor invocation already has another provider report"
                        )
                    if existing_resolution is None:
                        raise StoreIntegrityError(
                            "Provider report has no terminal local resolution"
                        )
                    expected_resolution = (
                        build_collaboration_executor_invocation_resolution(
                            preparation,
                            outcome="provider_report_received",
                            provider_acknowledgement=(
                                report.provider_acknowledgement
                            ),
                            resolved_at=str(existing_resolution["resolved_at"]),
                        )
                    )
                    if (
                        expected_resolution.resolution_id
                        != existing_resolution["resolution_id"]
                        or expected_resolution.resolution_sha256
                        != existing_resolution["resolution_sha256"]
                    ):
                        raise StoreIntegrityError(
                            "Provider report terminal resolution is inconsistent"
                        )
                    return self._receipt(existing_report, existing_resolution)
                if existing_resolution is not None:
                    raise StoreConflictError(
                        "Executor invocation already has another terminal resolution"
                    )
                resolution = build_collaboration_executor_invocation_resolution(
                    preparation,
                    outcome="provider_report_received",
                    provider_acknowledgement=report.provider_acknowledgement,
                    resolved_at=received_at,
                )
                self._insert_report(connection, report, preparation_row)
                self._attempts._insert_resolution(
                    connection,
                    resolution,
                    preparation_row,
                )
                self._verify(connection, mission)
                committed_report = self._report_row(connection, selected)
                committed_resolution = self._attempts._resolution_row(
                    connection,
                    selected,
                )
                if committed_report is None or committed_resolution is None:
                    raise StoreIntegrityError(
                        "Provider report atomic custody is incomplete"
                    )
                return self._receipt(committed_report, committed_resolution)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit executor provider report"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit executor provider report") from exc

    def _verify(self, connection: sqlite3.Connection, mission: Any) -> None:
        self._attempts._verify(connection, mission)
        self._store._verify_executor_invocation_provider_reports(
            connection,
            mission,
        )

    @staticmethod
    def _report_row(
        connection: sqlite3.Connection,
        attempt_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM executor_invocation_provider_reports
            WHERE attempt_id = ?
            """,
            (attempt_id,),
        ).fetchone()

    @staticmethod
    def _receipt(
        report_row: sqlite3.Row,
        resolution_row: sqlite3.Row,
    ) -> CollaborationExecutorProviderReportCommitReceipt:
        return CollaborationExecutorProviderReportCommitReceipt(
            report_json=str(report_row["report_json"]),
            resolution_json=str(resolution_row["resolution_json"]),
        )

    @staticmethod
    def _insert_report(
        connection: sqlite3.Connection,
        report: CollaborationExecutorProviderReport,
        preparation_row: sqlite3.Row,
    ) -> None:
        document = report.to_dict()
        acknowledgement = document["provider_acknowledgement"]
        connection.execute(
            """
            INSERT INTO executor_invocation_provider_reports(
                report_custody_id, report_custody_sha256,
                attempt_id, attempt_sha256, mission_id, authentication_id,
                acknowledgement_id, acknowledgement_sha256,
                dispatch_id, dispatch_sha256, operation, operation_sequence,
                adapter_id, adapter_version, adapter_build_sha256,
                session_id, session_sha256, fence_generation,
                worker_principal_id, runtime_instance_id,
                credential_reference_id, credential_sha256,
                outcome, provider_worker_state, provider_evidence_sha256,
                acknowledged_at, received_at, report_json, report_status,
                authentication_status, external_effect_status, runtime_effect
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                document["report_custody_id"],
                document["report_custody_sha256"],
                document["invocation_preparation"]["attempt_id"],
                document["invocation_preparation"]["attempt_sha256"],
                preparation_row["mission_id"],
                preparation_row["authentication_id"],
                acknowledgement["acknowledgement_id"],
                acknowledgement["acknowledgement_sha256"],
                acknowledgement["dispatch"]["dispatch_id"],
                acknowledgement["dispatch"]["dispatch_sha256"],
                acknowledgement["dispatch"]["operation"],
                acknowledgement["dispatch"]["operation_sequence"],
                acknowledgement["provider"]["adapter_id"],
                acknowledgement["provider"]["adapter_version"],
                acknowledgement["provider"]["adapter_build_sha256"],
                acknowledgement["session"]["session_id"],
                acknowledgement["session"]["session_sha256"],
                acknowledgement["worker"]["fence_generation"],
                acknowledgement["worker"]["worker_principal_id"],
                acknowledgement["worker"]["runtime_instance_id"],
                acknowledgement["credential"]["credential_reference_id"],
                acknowledgement["credential"]["credential_sha256"],
                acknowledgement["outcome"],
                acknowledgement["provider_worker_state"],
                acknowledgement["provider_evidence_sha256"],
                acknowledgement["acknowledged_at"],
                document["received_at"],
                canonical_json(document),
                document["report_status"],
                document["authentication_status"],
                document["external_effect_status"],
                document["runtime_effect"],
            ),
        )


__all__ = [
    "CollaborationExecutorProviderReportCommitReceipt",
    "CollaborationExecutorProviderReportService",
]
