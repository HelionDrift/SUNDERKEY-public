"""Atomic custody for authenticated executor dispatch reservations."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .collaboration import CollaborationPlan
from .collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
)
from .collaboration_execution_session_status import _build_status
from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorDispatchEnvelope,
    build_collaboration_executor_dispatch,
    validate_collaboration_executor_operation_input,
)
from .collaboration_executor_dispatch_authentication import (
    AuthenticatedCollaborationExecutorDispatch,
    authenticate_collaboration_executor_dispatch,
    collaboration_executor_dispatch_selection_sha256,
)
from .errors import (
    CollaborationPlanError,
    MissionStoppedError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import PrincipalAssertion, PrincipalOperation
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp

_AUTHENTICATION_ID_PATTERN = re.compile(r"EDA-[0-9A-F]{32}")


@dataclass(frozen=True)
class ExecutorDispatchPrincipalCommit:
    """Durable principal assertion and ledger provenance."""

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
class AuthenticatedCollaborationExecutorDispatchReservationReceipt:
    """Durable pre-invocation reservation for one exact dispatch."""

    authentication_json: str
    reserved_at: str
    control_plane_authorizer: ExecutorDispatchPrincipalCommit

    @property
    def authentication_id(self) -> str:
        return str(self.to_dict()["dispatch_authentication"]["authentication_id"])

    @property
    def dispatch_id(self) -> str:
        return str(
            self.to_dict()["dispatch_authentication"]["dispatch"]["dispatch_id"]
        )

    def to_dict(self) -> dict[str, Any]:
        authentication = json.loads(self.authentication_json)
        if not isinstance(authentication, dict):
            raise StoreIntegrityError(
                "Stored executor dispatch authentication is invalid"
            )
        return {
            "schema_version": 1,
            "dispatch_authentication": authentication,
            "reserved_at": self.reserved_at,
            "control_plane_authorizer": self.control_plane_authorizer.to_dict(),
            "reservation_status": "reserved_pending_adapter",
            "runtime_effect": "none",
        }


class AuthenticatedCollaborationExecutorDispatchService:
    """Authenticate and reserve one dispatch without invoking its adapter."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy_service = AuthenticatedCollaborationMissionPolicyService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._policy_service._store
        self._registry = self._policy_service._registry
        self._clock = self._policy_service._clock
        self._activation = self._policy_service._activation

    def get(
        self,
        authentication_id: str,
    ) -> AuthenticatedCollaborationExecutorDispatchReservationReceipt:
        if (
            not isinstance(authentication_id, str)
            or _AUTHENTICATION_ID_PATTERN.fullmatch(authentication_id) is None
        ):
            raise StoreError("authentication_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = self._row(connection, authentication_id)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._store._verify_executor_dispatch_reservations(
                    connection,
                    mission,
                )
                return self._receipt(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read executor dispatch reservation") from exc

    def reserve(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
        *,
        authorizer_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationExecutorDispatchReservationReceipt:
        parsed_dispatch = self._dispatch(dispatch)
        validate_collaboration_executor_operation_input(
            parsed_dispatch,
            operation_input,
        )
        assertion = self._policy_service._assertion(
            authorizer_assertion,
            "authorizer_assertion",
        )
        dispatch_document = parsed_dispatch.to_dict()
        mission_id = str(dispatch_document["mission"]["mission_id"])
        safety_reduction = (
            dispatch_document["operation"] in SAFETY_REDUCING_OPERATIONS
        )
        operation = (
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE
            if safety_reduction
            else PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE
        )
        selection_sha256 = collaboration_executor_dispatch_selection_sha256(
            parsed_dispatch
        )
        intent = {
            "dispatch_selection_sha256": selection_sha256,
            "mission_id": mission_id,
            "principal_profile_id": assertion.profile_id,
        }
        material = self._policy_service._assertion_material(
            assertion,
            operation,
            intent,
        )
        try:
            with self._store._write_connection() as connection:
                identity, trust_policies, mission, scope_grants, ledger = (
                    self._activation._verified_mission_state(
                        connection,
                        mission_id,
                    )
                )
                existing_use = self._policy_service._existing_use(
                    connection,
                    assertion,
                )
                if existing_use is not None:
                    self._policy_service._require_exact_replay(
                        existing_use,
                        assertion=assertion,
                        mission_id=mission_id,
                        operation=operation,
                        material=material,
                    )
                    row = self._row_for_assertion(connection, assertion)
                    self._require_exact_reservation(
                        row,
                        parsed_dispatch,
                        selection_sha256,
                    )
                    self._store._verify_executor_dispatch_reservations(
                        connection,
                        mission,
                    )
                    return self._receipt(connection, row)

                now = self._clock_value()
                reserved_at = format_timestamp(now)
                reserved_time = parse_timestamp(
                    reserved_at,
                    "executor dispatch reserved_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    reserved_time,
                )
                if not safety_reduction:
                    self._require_active(connection, mission_id)
                verified_policy, authorizer_scope = (
                    self._policy_service._verified_scope(
                        connection,
                        assertion=assertion,
                        operation=operation,
                        mission=mission,
                        identity=identity,
                        trust_policies=trust_policies,
                        scope_grants=scope_grants,
                        now=now,
                        consumed_time=reserved_time,
                        allow_expired_for_safety_reduction=safety_reduction,
                    )
                )
                authority_row = self._authority_row(
                    connection,
                    str(
                        dispatch_document["session_authority"][
                            "session_authority_id"
                        ]
                    ),
                )
                authority = self._authority(authority_row)
                activation_row = self._activation_row(
                    connection,
                    authority.session_authority_id,
                )
                self._require_current_dispatch(
                    connection,
                    parsed_dispatch,
                    authority,
                    authority_row,
                    activation_row,
                    safety_reduction=safety_reduction,
                    observed_at=str(
                        dispatch_document["authority_status"]["observed_at"]
                    ),
                    reserved_at=reserved_at,
                )
                self._require_next_sequence(connection, dispatch_document)
                authenticated = authenticate_collaboration_executor_dispatch(
                    parsed_dispatch,
                    authorizer_assertion=assertion,
                    verified_policy=verified_policy,
                    authorizer_scope=authorizer_scope,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_authorizer_profile_ids=mission.control_profile_ids,
                    clock=lambda: now,
                )
                effect = self._policy_service._effect(
                    authenticated.authentication_id,
                    operation,
                    self._effect_payload(
                        authenticated,
                        selection_sha256,
                    ),
                    reserved_at,
                )
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.control_plane_authorizer,
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=reserved_at,
                )
                self._insert_reservation(
                    connection,
                    authenticated,
                    selection_sha256,
                    str(activation_row["authentication_id"]),
                    reserved_at,
                    assertion,
                )
                row = self._row_for_assertion(connection, assertion)
                self._store._verify_executor_dispatch_reservations(
                    connection,
                    mission,
                )
                return self._receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not reserve executor dispatch"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not reserve executor dispatch") from exc

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
    def _dispatch(
        value: Any,
    ) -> CollaborationExecutorDispatchEnvelope:
        if not isinstance(value, CollaborationExecutorDispatchEnvelope):
            raise TypeError(
                "dispatch must be a CollaborationExecutorDispatchEnvelope"
            )
        return CollaborationExecutorDispatchEnvelope.from_dict(value.to_dict())

    @staticmethod
    def _require_active(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> None:
        row = connection.execute(
            "SELECT state FROM mission_controls WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Mission control state is missing")
        if row["state"] != "active":
            raise MissionStoppedError(
                "Stopped mission cannot reserve ordinary executor work"
            )

    @staticmethod
    def _authority_row(
        connection: sqlite3.Connection,
        session_authority_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_authority_commits
            WHERE session_authority_id = ?
            """,
            (session_authority_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Executor dispatch authority is not committed")
        return row

    @staticmethod
    def _activation_row(
        connection: sqlite3.Connection,
        session_authority_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_activation_commits
            WHERE session_authority_id = ?
            """,
            (session_authority_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Executor dispatch authority is not activated")
        return row

    @staticmethod
    def _authority(
        row: sqlite3.Row,
    ) -> CollaborationExecutionSessionAuthority:
        try:
            return CollaborationExecutionSessionAuthority.from_dict(
                json.loads(str(row["authority_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored executor dispatch authority is invalid"
            ) from exc

    @staticmethod
    def _plan(
        connection: sqlite3.Connection,
        mission_id: str,
        plan_id: str,
    ) -> CollaborationPlan:
        row = connection.execute(
            """
            SELECT plan_json FROM collaboration_plan_activations
            WHERE mission_id = ? AND plan_id = ?
            """,
            (mission_id, plan_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Executor dispatch plan is not activated")
        try:
            return CollaborationPlan.from_dict(json.loads(str(row["plan_json"])))
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError("Stored executor dispatch plan is invalid") from exc

    def _require_current_dispatch(
        self,
        connection: sqlite3.Connection,
        dispatch: CollaborationExecutorDispatchEnvelope,
        authority: CollaborationExecutionSessionAuthority,
        authority_row: sqlite3.Row,
        activation_row: sqlite3.Row,
        *,
        safety_reduction: bool,
        observed_at: str,
        reserved_at: str,
    ) -> None:
        document = dispatch.to_dict()
        revocation_at_observation = connection.execute(
            """
            SELECT authentication_id, authentication_sha256, reason_code, committed_at
            FROM execution_session_revocation_commits
            WHERE session_authority_id = ? AND committed_at <= ?
            """,
            (authority.session_authority_id, observed_at),
        ).fetchone()
        status = _build_status(
            authority,
            activation=activation_row,
            revocation=revocation_at_observation,
            observed_at=observed_at,
        )
        plan = self._plan(
            connection,
            str(authority_row["mission_id"]),
            str(authority_row["collaboration_plan_id"]),
        )
        rebuilt = build_collaboration_executor_dispatch(
            status=status,
            authority=authority,
            collaboration_plan=plan,
            operation=str(document["operation"]),
            operation_sequence=int(document["operation_sequence"]),
            tool_policy_sha256=str(document["policy"]["tool_policy_sha256"]),
            operation_input_sha256=str(
                document["policy"]["operation_input_sha256"]
            ),
            issued_at=str(document["issued_at"]),
            expires_at=str(document["expires_at"]),
        )
        if rebuilt != dispatch:
            raise StoreConflictError(
                "Executor dispatch is stale against durable session state"
            )
        effective_revocation = connection.execute(
            """
            SELECT 1 FROM execution_session_revocation_commits
            WHERE session_authority_id = ? AND committed_at <= ?
            """,
            (authority.session_authority_id, reserved_at),
        ).fetchone()
        if not safety_reduction and effective_revocation is not None:
            raise StoreConflictError(
                "Revoked authority cannot reserve ordinary executor work"
            )

    @staticmethod
    def _require_next_sequence(
        connection: sqlite3.Connection,
        dispatch_document: dict[str, Any],
    ) -> None:
        row = connection.execute(
            """
            SELECT COALESCE(MAX(operation_sequence), 0) AS last_sequence
            FROM executor_dispatch_reservations
            WHERE session_id = ?
            """,
            (dispatch_document["session"]["session_id"],),
        ).fetchone()
        expected = int(row["last_sequence"]) + 1
        if dispatch_document["operation_sequence"] != expected:
            raise StoreConflictError(
                f"Executor dispatch operation sequence must be {expected}"
            )

    @staticmethod
    def _effect_payload(
        authenticated: AuthenticatedCollaborationExecutorDispatch,
        selection_sha256: str,
    ) -> dict[str, Any]:
        document = authenticated.to_dict()
        dispatch = document["dispatch"]
        return {
            "authentication_id": authenticated.authentication_id,
            "authentication_sha256": authenticated.authentication_sha256,
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_sha256": dispatch["dispatch_sha256"],
            "dispatch_selection_sha256": selection_sha256,
            "mission_id": dispatch["mission"]["mission_id"],
            "operation": dispatch["operation"],
            "operation_sequence": dispatch["operation_sequence"],
            "reservation_status": "reserved_pending_adapter",
            "runtime_effect": "none",
            "session_authority_id": dispatch["session_authority"][
                "session_authority_id"
            ],
            "session_authority_sha256": dispatch["session_authority"][
                "session_authority_sha256"
            ],
            "session_id": dispatch["session"]["session_id"],
            "session_sha256": dispatch["session"]["session_sha256"],
        }

    @staticmethod
    def _insert_reservation(
        connection: sqlite3.Connection,
        authenticated: AuthenticatedCollaborationExecutorDispatch,
        selection_sha256: str,
        activation_authentication_id: str,
        reserved_at: str,
        assertion: PrincipalAssertion,
    ) -> None:
        authentication = authenticated.to_dict()
        dispatch = authentication["dispatch"]
        mission = dispatch["mission"]
        authority = dispatch["session_authority"]
        session = dispatch["session"]
        credential = dispatch["credential"]
        worker = dispatch["worker"]
        policy = dispatch["policy"]
        connection.execute(
            """
            INSERT INTO executor_dispatch_reservations(
                authentication_id,
                authentication_sha256,
                dispatch_id,
                dispatch_sha256,
                dispatch_selection_sha256,
                mission_id,
                collaboration_plan_id,
                collaboration_plan_sha256,
                work_item_id,
                session_authority_id,
                session_authority_sha256,
                session_activation_authentication_id,
                session_id,
                session_sha256,
                credential_reference_id,
                credential_sha256,
                worker_principal_id,
                owner_epoch,
                fence_generation,
                operation,
                operation_sequence,
                safety_reduction,
                tool_policy_sha256,
                operation_input_sha256,
                issued_at,
                expires_at,
                authenticated_at,
                reserved_at,
                authorizer_issuer,
                authorizer_assertion_id,
                authentication_json,
                reservation_status,
                runtime_effect
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                authenticated.authentication_id,
                authenticated.authentication_sha256,
                dispatch["dispatch_id"],
                dispatch["dispatch_sha256"],
                selection_sha256,
                mission["mission_id"],
                mission["collaboration_plan_id"],
                mission["collaboration_plan_sha256"],
                dispatch["work_item"]["work_item_id"],
                authority["session_authority_id"],
                authority["session_authority_sha256"],
                activation_authentication_id,
                session["session_id"],
                session["session_sha256"],
                credential["credential_reference_id"],
                credential["credential_sha256"],
                worker["worker_principal_id"],
                worker["owner_epoch"],
                worker["fence_generation"],
                dispatch["operation"],
                dispatch["operation_sequence"],
                int(dispatch["operation"] in SAFETY_REDUCING_OPERATIONS),
                policy["tool_policy_sha256"],
                policy["operation_input_sha256"],
                dispatch["issued_at"],
                dispatch["expires_at"],
                authentication["authenticated_at"],
                reserved_at,
                assertion.issuer,
                assertion.assertion_id,
                canonical_json(authentication),
                "reserved_pending_adapter",
                "none",
            ),
        )

    @staticmethod
    def _row(
        connection: sqlite3.Connection,
        authentication_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM executor_dispatch_reservations
            WHERE authentication_id = ?
            """,
            (authentication_id,),
        ).fetchone()
        if row is None:
            raise StoreError("Executor dispatch reservation is not committed")
        return row

    @staticmethod
    def _row_for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM executor_dispatch_reservations
            WHERE authorizer_issuer = ? AND authorizer_assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Executor dispatch assertion has no reservation"
            )
        return row

    @staticmethod
    def _require_exact_reservation(
        row: sqlite3.Row,
        dispatch: CollaborationExecutorDispatchEnvelope,
        selection_sha256: str,
    ) -> None:
        if (
            row["dispatch_id"] != dispatch.dispatch_id
            or row["dispatch_sha256"] != dispatch.dispatch_sha256
            or row["dispatch_selection_sha256"] != selection_sha256
        ):
            raise StoreConflictError(
                "Executor dispatch assertion was used for a different reservation"
            )

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutorDispatchReservationReceipt:
        use = connection.execute(
            """
            SELECT assertion_hash, entry_hash
            FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (row["authorizer_issuer"], row["authorizer_assertion_id"]),
        ).fetchone()
        if use is None:
            raise StoreIntegrityError(
                "Executor dispatch reservation authorizer custody is missing"
            )
        return AuthenticatedCollaborationExecutorDispatchReservationReceipt(
            authentication_json=str(row["authentication_json"]),
            reserved_at=str(row["reserved_at"]),
            control_plane_authorizer=ExecutorDispatchPrincipalCommit(
                assertion_id=str(row["authorizer_assertion_id"]),
                assertion_sha256=str(use["assertion_hash"]),
                ledger_entry_sha256=str(use["entry_hash"]),
            ),
        )


__all__ = [
    "AuthenticatedCollaborationExecutorDispatchReservationReceipt",
    "AuthenticatedCollaborationExecutorDispatchService",
    "ExecutorDispatchPrincipalCommit",
]
