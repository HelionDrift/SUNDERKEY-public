"""Atomic custody for authenticated executor provider reports."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorDispatchEnvelope,
)
from .collaboration_executor_authentication import (
    authenticate_collaboration_executor_acknowledgement,
    collaboration_executor_acknowledgement_selection_sha256,
)
from .collaboration_executor_provider_report import (
    CollaborationExecutorProviderReport,
)
from .collaboration_executor_provider_report_authentication import (
    AuthenticatedCollaborationExecutorProviderReport,
    bind_authenticated_collaboration_executor_provider_report,
    collaboration_executor_provider_report_authentication_effect_payload,
    validate_authenticated_collaboration_executor_provider_report_document,
)
from .collaboration_executor_provider_report_store import (
    CollaborationExecutorProviderReportService,
)
from .errors import (
    CollaborationPlanError,
    QualificationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import PrincipalAssertion, PrincipalOperation
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp

_REPORT_AUTHENTICATION_ID_PATTERN = re.compile(r"EPA-[0-9A-F]{32}")


@dataclass(frozen=True)
class ExecutorProviderReportPrincipalCommit:
    """Durable worker assertion and principal-ledger provenance."""

    assertion_id: str
    assertion_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutorProviderReportCommitReceipt:
    """Durable custody receipt for one authenticated retained report."""

    authentication_json: str
    authenticated_at: str
    worker_attestor: ExecutorProviderReportPrincipalCommit

    @property
    def report_authentication_id(self) -> str:
        return str(
            self.to_dict()["provider_report_authentication"][
                "report_authentication_id"
            ]
        )

    @property
    def attempt_id(self) -> str:
        return str(
            self.to_dict()["provider_report_authentication"][
                "provider_report"
            ]["invocation_preparation"]["attempt_id"]
        )

    def to_dict(self) -> dict[str, Any]:
        try:
            authentication = (
                validate_authenticated_collaboration_executor_provider_report_document(
                    json.loads(self.authentication_json)
                )
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor provider report authentication is invalid"
            ) from exc
        if (
            authentication["acknowledgement_authentication"][
                "authenticated_at"
            ]
            != self.authenticated_at
        ):
            raise StoreIntegrityError(
                "Executor provider report authentication time does not reconcile"
            )
        return {
            "schema_version": 1,
            "provider_report_authentication": authentication,
            "authenticated_at": self.authenticated_at,
            "worker_attestor": self.worker_attestor.to_dict(),
            "custody_status": "durable_authenticated_provider_report",
            "evidence_verification_status": (
                "provider_evidence_digest_unverified"
            ),
            "external_effect_status": (
                "authenticated_report_unverified_effect"
            ),
            "runtime_effect": "none",
        }


class AuthenticatedCollaborationExecutorProviderReportService:
    """Authenticate and retain one provider report without target activity."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._reports = CollaborationExecutorProviderReportService(
            store,
            registry,
            clock=clock,
        )
        self._policy = AuthenticatedCollaborationMissionPolicyService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._reports._store
        self._activation = self._reports._activation

    def get(
        self,
        report_authentication_id: str,
    ) -> AuthenticatedCollaborationExecutorProviderReportCommitReceipt:
        if (
            not isinstance(report_authentication_id, str)
            or _REPORT_AUTHENTICATION_ID_PATTERN.fullmatch(
                report_authentication_id
            )
            is None
        ):
            raise StoreError("report_authentication_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = self._row(connection, report_authentication_id)
                _, _, mission, _, _ = (
                    self._activation._verified_mission_state(
                        connection,
                        str(row["mission_id"]),
                    )
                )
                self._verify(connection, mission)
                return self._receipt(connection, row)
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read executor provider report authentication"
            ) from exc

    def authenticate(
        self,
        attempt_id: str,
        *,
        worker_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationExecutorProviderReportCommitReceipt:
        selected = self._reports._attempts._attempt_id(attempt_id)
        assertion = self._policy._assertion(
            worker_assertion,
            "worker_assertion",
        )
        try:
            with self._store._write_connection() as connection:
                report_row = self._reports._report_row(connection, selected)
                if report_row is None:
                    raise StoreConflictError(
                        "Executor provider report is not committed"
                    )
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                    ledger,
                ) = self._activation._verified_mission_state(
                    connection,
                    str(report_row["mission_id"]),
                )
                self._verify(connection, mission)
                report = self._provider_report(report_row)
                dispatch = self._dispatch(connection, report_row)
                report_document = report.to_dict()
                acknowledgement = report.provider_acknowledgement
                acknowledgement_document = acknowledgement.to_dict()
                mission_id = str(report_row["mission_id"])
                operation = (
                    PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY
                    if acknowledgement_document["dispatch"]["operation"]
                    in SAFETY_REDUCING_OPERATIONS
                    else PrincipalOperation.EXECUTOR_ACKNOWLEDGE
                )
                selection_sha256 = (
                    collaboration_executor_acknowledgement_selection_sha256(
                        acknowledgement
                    )
                )
                intent = {
                    "acknowledgement_selection_sha256": selection_sha256,
                    "dispatch_sha256": acknowledgement_document["dispatch"][
                        "dispatch_sha256"
                    ],
                    "mission_id": mission_id,
                    "principal_profile_id": assertion.profile_id,
                }
                material = self._policy._assertion_material(
                    assertion,
                    operation,
                    intent,
                )
                existing_use = self._policy._existing_use(
                    connection,
                    assertion,
                )
                if existing_use is not None:
                    self._policy._require_exact_replay(
                        existing_use,
                        assertion=assertion,
                        mission_id=mission_id,
                        operation=operation,
                        material=material,
                    )
                    row = self._row_for_assertion(connection, assertion)
                    self._require_exact_authentication(
                        row,
                        report_document,
                        assertion,
                    )
                    self._verify(connection, mission)
                    return self._receipt(connection, row)

                now = self._reports._attempts._clock_value()
                authenticated_at = format_timestamp(now)
                authenticated_time = parse_timestamp(
                    authenticated_at,
                    "executor provider report authenticated_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    authenticated_time,
                )
                verified_policy, worker_scope = self._policy._verified_scope(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=authenticated_time,
                    allow_expired_for_safety_reduction=(
                        operation
                        is PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY
                    ),
                )
                acknowledgement_authentication = (
                    authenticate_collaboration_executor_acknowledgement(
                        dispatch,
                        acknowledgement,
                        worker_assertion=assertion,
                        verified_policy=verified_policy,
                        worker_scope=worker_scope,
                        expected_audience=str(identity["audience"]),
                        expected_store_id=str(identity["store_id"]),
                        clock=lambda: now,
                    )
                )
                authenticated = (
                    bind_authenticated_collaboration_executor_provider_report(
                        report,
                        acknowledgement_authentication,
                    )
                )
                effect = self._policy._effect(
                    authenticated.report_authentication_id,
                    operation,
                    collaboration_executor_provider_report_authentication_effect_payload(
                        authenticated
                    ),
                    authenticated_at,
                )
                self._policy._record_assertion(
                    connection,
                    principal=(
                        authenticated.acknowledgement_authentication.worker_attestor
                    ),
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=authenticated_at,
                )
                self._insert_authentication(
                    connection,
                    authenticated,
                    report_row,
                    assertion,
                )
                self._verify(connection, mission)
                row = self._row_for_assertion(connection, assertion)
                return self._receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not authenticate executor provider report"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not authenticate executor provider report"
            ) from exc

    def _verify(self, connection: sqlite3.Connection, mission: Any) -> None:
        self._reports._verify(connection, mission)
        self._store._verify_executor_invocation_provider_report_authentications(
            connection,
            mission,
        )

    @staticmethod
    def _provider_report(
        row: sqlite3.Row,
    ) -> CollaborationExecutorProviderReport:
        try:
            return CollaborationExecutorProviderReport.from_dict(
                json.loads(str(row["report_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor provider report is invalid"
            ) from exc

    @staticmethod
    def _dispatch(
        connection: sqlite3.Connection,
        report_row: sqlite3.Row,
    ) -> CollaborationExecutorDispatchEnvelope:
        reservation = connection.execute(
            """
            SELECT authentication_json FROM executor_dispatch_reservations
            WHERE authentication_id = ?
            """,
            (report_row["authentication_id"],),
        ).fetchone()
        if reservation is None:
            raise StoreIntegrityError(
                "Executor provider report reservation is missing"
            )
        try:
            authentication = json.loads(
                str(reservation["authentication_json"])
            )
            return CollaborationExecutorDispatchEnvelope.from_dict(
                authentication["dispatch"]
            )
        except (
            KeyError,
            json.JSONDecodeError,
            CollaborationPlanError,
            QualificationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor provider report dispatch is invalid"
            ) from exc

    @staticmethod
    def _insert_authentication(
        connection: sqlite3.Connection,
        authenticated: AuthenticatedCollaborationExecutorProviderReport,
        report_row: sqlite3.Row,
        assertion: PrincipalAssertion,
    ) -> None:
        document = authenticated.to_dict()
        report = document["provider_report"]
        acknowledgement = report["provider_acknowledgement"]
        authentication = document["acknowledgement_authentication"]
        worker = authentication["worker_attestor"]
        connection.execute(
            """
            INSERT INTO executor_invocation_provider_report_authentications(
                report_authentication_id, report_authentication_sha256,
                report_custody_id, report_custody_sha256, attempt_id,
                mission_id, acknowledgement_authentication_id,
                acknowledgement_authentication_sha256, acknowledgement_id,
                acknowledgement_sha256, operation, worker_principal_id,
                worker_issuer, worker_assertion_id, worker_assertion_sha256,
                authenticated_at, authentication_json,
                authentication_status, evidence_verification_status,
                external_effect_status, runtime_effect
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                document["report_authentication_id"],
                document["report_authentication_sha256"],
                report["report_custody_id"],
                report["report_custody_sha256"],
                report["invocation_preparation"]["attempt_id"],
                report_row["mission_id"],
                authentication["authentication_id"],
                authentication["authentication_sha256"],
                acknowledgement["acknowledgement_id"],
                acknowledgement["acknowledgement_sha256"],
                acknowledgement["dispatch"]["operation"],
                acknowledgement["worker"]["worker_principal_id"],
                assertion.issuer,
                assertion.assertion_id,
                worker["assertion_sha256"],
                authentication["authenticated_at"],
                canonical_json(document),
                document["authentication_status"],
                document["evidence_verification_status"],
                document["external_effect_status"],
                document["runtime_effect"],
            ),
        )

    @staticmethod
    def _row(
        connection: sqlite3.Connection,
        report_authentication_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM executor_invocation_provider_report_authentications
            WHERE report_authentication_id = ?
            """,
            (report_authentication_id,),
        ).fetchone()
        if row is None:
            raise StoreError(
                "Executor provider report authentication is not committed"
            )
        return row

    @staticmethod
    def _row_for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM executor_invocation_provider_report_authentications
            WHERE worker_issuer = ? AND worker_assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Executor provider report assertion has no authentication"
            )
        return row

    @staticmethod
    def _require_exact_authentication(
        row: sqlite3.Row,
        report: dict[str, Any],
        assertion: PrincipalAssertion,
    ) -> None:
        acknowledgement = report["provider_acknowledgement"]
        if (
            row["report_custody_id"] != report["report_custody_id"]
            or row["report_custody_sha256"]
            != report["report_custody_sha256"]
            or row["attempt_id"]
            != report["invocation_preparation"]["attempt_id"]
            or row["acknowledgement_id"]
            != acknowledgement["acknowledgement_id"]
            or row["acknowledgement_sha256"]
            != acknowledgement["acknowledgement_sha256"]
            or row["worker_principal_id"] != assertion.profile_id
            or row["worker_issuer"] != assertion.issuer
            or row["worker_assertion_id"] != assertion.assertion_id
        ):
            raise StoreConflictError(
                "Executor provider report assertion was used for another authentication"
            )

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutorProviderReportCommitReceipt:
        use = connection.execute(
            """
            SELECT assertion_hash, entry_hash
            FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (row["worker_issuer"], row["worker_assertion_id"]),
        ).fetchone()
        if use is None:
            raise StoreIntegrityError(
                "Executor provider report worker custody is missing"
            )
        return AuthenticatedCollaborationExecutorProviderReportCommitReceipt(
            authentication_json=str(row["authentication_json"]),
            authenticated_at=str(row["authenticated_at"]),
            worker_attestor=ExecutorProviderReportPrincipalCommit(
                assertion_id=str(row["worker_assertion_id"]),
                assertion_sha256=str(use["assertion_hash"]),
                ledger_entry_sha256=str(use["entry_hash"]),
            ),
        )


__all__ = [
    "AuthenticatedCollaborationExecutorProviderReportCommitReceipt",
    "AuthenticatedCollaborationExecutorProviderReportService",
    "ExecutorProviderReportPrincipalCommit",
]
