"""Atomic authenticated commit for terminal execution-transfer custody."""

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
from .collaboration_execution_channel import CollaborationFencedWorkerSession
from .collaboration_execution_terminal_custody import (
    CollaborationExecutionTerminalCustodyPlan,
    build_collaboration_execution_terminal_custody_plan,
)
from .collaboration_execution_timeout import (
    collaboration_execution_timeout_resolution_selection_sha256,
)
from .collaboration_execution_timeout_authentication import (
    AuthenticatedCollaborationExecutionTimeoutResolution,
)
from .collaboration_execution_transfer import (
    collaboration_execution_acknowledgement_selection_sha256,
    collaboration_execution_transfer_request_selection_sha256,
)
from .collaboration_execution_transfer_authentication import (
    AuthenticatedCollaborationExecutionAcknowledgement,
    AuthenticatedCollaborationExecutionTransferRequest,
)
from .collaboration_execution_transfer_completion import (
    CollaborationExecutionTransferCompletion,
)
from .collaboration_ownership_chain import collaboration_work_item_objective_sha256
from .errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    verify_principal_assertion,
)
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp

_PLAN_ID_PATTERN = re.compile(r"ECT-[0-9A-F]{32}")


@dataclass(frozen=True)
class ExecutionTerminalCustodyParticipantCommit:
    """Durable ledger provenance for one terminal-custody participant."""

    participant_index: int
    role: str
    authentication_id: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "participant_index": self.participant_index,
            "role": self.role,
            "authentication_id": self.authentication_id,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt:
    """Immutable terminal outcome and ordered assertion provenance."""

    plan: CollaborationExecutionTerminalCustodyPlan
    committed_at: str
    participant_commits: tuple[ExecutionTerminalCustodyParticipantCommit, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "custody_plan": self.plan.to_dict(),
            "committed_at": self.committed_at,
            "participant_commits": [item.to_dict() for item in self.participant_commits],
            "commit_status": "committed_terminal_custody",
            "runtime_effect": "none",
        }


@dataclass(frozen=True)
class _ParticipantInput:
    expected: dict[str, str]
    assertion: PrincipalAssertion
    operation: PrincipalOperation
    intent: dict[str, str]
    material: dict[str, str]


class AuthenticatedCollaborationExecutionTerminalCustodyService:
    """Consume every terminal participant assertion in one transaction."""

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
        self._work = self._policy_service._work

    def get(
        self,
        custody_plan_id: str,
    ) -> AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt:
        """Return one verified durable terminal custody result."""

        if (
            not isinstance(custody_plan_id, str)
            or _PLAN_ID_PATTERN.fullmatch(custody_plan_id) is None
        ):
            raise StoreError("custody_plan_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = self._row_for_plan(connection, custody_plan_id)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._store._verify_execution_terminal_custody_commits(
                    connection,
                    mission,
                )
                return self._receipt(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read execution terminal custody") from exc

    def commit(
        self,
        plan: CollaborationExecutionTerminalCustodyPlan,
        *,
        authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
        acknowledgements: list[
            tuple[
                AuthenticatedCollaborationExecutionAcknowledgement,
                CollaborationFencedWorkerSession,
            ]
        ],
        participant_assertions: list[PrincipalAssertion],
        completion: CollaborationExecutionTransferCompletion | None = None,
        authenticated_timeout: (
            AuthenticatedCollaborationExecutionTimeoutResolution | None
        ) = None,
    ) -> AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt:
        """Commit one exact terminal plan or replay its durable result."""

        parsed_plan = self._validated_plan(
            plan,
            authenticated_request=authenticated_request,
            acknowledgements=acknowledgements,
            completion=completion,
            authenticated_timeout=authenticated_timeout,
        )
        inputs = self._participant_inputs(
            parsed_plan,
            authenticated_request=authenticated_request,
            acknowledgements=acknowledgements,
            participant_assertions=participant_assertions,
            authenticated_timeout=authenticated_timeout,
        )
        document = parsed_plan.to_dict()
        mission_id = document["mission_id"]
        plan_json = canonical_json(document)

        try:
            with self._store._write_connection() as connection:
                identity, trust_policies, mission, scope_grants, ledger = (
                    self._activation._verified_mission_state(connection, mission_id)
                )
                existing_uses = [
                    self._policy_service._existing_use(connection, item.assertion)
                    for item in inputs
                ]
                if any(item is not None for item in existing_uses):
                    if any(item is None for item in existing_uses):
                        raise StoreConflictError(
                            "Execution terminal replay has incomplete assertion use"
                        )
                    for item, use in zip(inputs, existing_uses, strict=True):
                        assert use is not None
                        self._policy_service._require_exact_replay(
                            use,
                            assertion=item.assertion,
                            mission_id=mission_id,
                            operation=item.operation,
                            material=item.material,
                        )
                    row = self._row_for_plan(connection, parsed_plan.custody_plan_id)
                    self._require_exact_commit(row, parsed_plan, plan_json)
                    self._store._verify_execution_terminal_custody_commits(
                        connection,
                        mission,
                    )
                    return self._receipt(connection, row)

                self._policy_service._require_active(connection, mission_id)
                self._require_execution_basis(
                    connection,
                    authenticated_request,
                    document,
                )
                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "execution terminal custody committed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                verified_principals: list[Any] = []
                policy_sha256: str | None = None
                for item in inputs:
                    verified_policy, verified_scope = self._policy_service._verified_scope(
                        connection,
                        assertion=item.assertion,
                        operation=item.operation,
                        mission=mission,
                        identity=identity,
                        trust_policies=trust_policies,
                        scope_grants=scope_grants,
                        now=now,
                        consumed_time=committed_time,
                    )
                    if policy_sha256 is None:
                        policy_sha256 = verified_policy.policy_sha256
                    elif policy_sha256 != verified_policy.policy_sha256:
                        raise PrincipalAuthenticationError(
                            "Execution terminal participants use different trust policies"
                        )
                    principal = verify_principal_assertion(
                        item.assertion,
                        verified_policy,
                        verified_scope,
                        expected_audience=str(identity["audience"]),
                        expected_store_id=str(identity["store_id"]),
                        expected_mission_id=mission_id,
                        expected_operation=item.operation,
                        expected_operation_intent_sha256=item.material["signed_hash"],
                        clock=lambda: now,
                    )
                    self._require_principal_binding(principal.to_dict(), item.expected)
                    verified_principals.append(principal)

                for index, (item, principal) in enumerate(
                    zip(inputs, verified_principals, strict=True)
                ):
                    effect = self._policy_service._effect(
                        item.expected["authentication_id"],
                        item.operation,
                        {
                            "custody_plan_id": parsed_plan.custody_plan_id,
                            "custody_plan_sha256": parsed_plan.custody_plan_sha256,
                            "outcome_id": document["terminal_outcome"]["outcome_id"],
                            "participant_index": index,
                            "role": item.expected["role"],
                            "terminal_kind": document["terminal_kind"],
                        },
                        committed_at,
                    )
                    current_ledger = connection.execute(
                        "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
                        (mission_id,),
                    ).fetchone()
                    if current_ledger is None:
                        raise StoreIntegrityError("Mission principal ledger disappeared")
                    self._policy_service._record_assertion(
                        connection,
                        principal=principal,
                        assertion=item.assertion,
                        mission_id=mission_id,
                        operation=item.operation,
                        material=item.material,
                        effect=effect,
                        ledger=current_ledger,
                        consumed_at=committed_at,
                    )

                self._insert_commit(
                    connection,
                    parsed_plan,
                    plan_json,
                    committed_at,
                )
                self._insert_participants(
                    connection,
                    parsed_plan,
                    committed_at,
                )
                row = self._row_for_plan(connection, parsed_plan.custody_plan_id)
                return self._receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Could not commit execution terminal custody") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit execution terminal custody") from exc

    @staticmethod
    def _validated_plan(
        plan: CollaborationExecutionTerminalCustodyPlan,
        *,
        authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
        acknowledgements: list[
            tuple[
                AuthenticatedCollaborationExecutionAcknowledgement,
                CollaborationFencedWorkerSession,
            ]
        ],
        completion: CollaborationExecutionTransferCompletion | None,
        authenticated_timeout: AuthenticatedCollaborationExecutionTimeoutResolution | None,
    ) -> CollaborationExecutionTerminalCustodyPlan:
        if not isinstance(plan, CollaborationExecutionTerminalCustodyPlan):
            raise TypeError("plan must be a CollaborationExecutionTerminalCustodyPlan")
        parsed = CollaborationExecutionTerminalCustodyPlan.from_dict(plan.to_dict())
        rebuilt = build_collaboration_execution_terminal_custody_plan(
            authenticated_request=authenticated_request,
            acknowledgements=acknowledgements,
            completion=completion,
            authenticated_timeout=authenticated_timeout,
        )
        if canonical_json(parsed.to_dict()) != canonical_json(rebuilt.to_dict()):
            raise StoreConflictError("Execution terminal custody inputs do not match the plan")
        return parsed

    def _participant_inputs(
        self,
        plan: CollaborationExecutionTerminalCustodyPlan,
        *,
        authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
        acknowledgements: list[
            tuple[
                AuthenticatedCollaborationExecutionAcknowledgement,
                CollaborationFencedWorkerSession,
            ]
        ],
        participant_assertions: list[PrincipalAssertion],
        authenticated_timeout: AuthenticatedCollaborationExecutionTimeoutResolution | None,
    ) -> tuple[_ParticipantInput, ...]:
        if not isinstance(participant_assertions, list):
            raise PrincipalAuthenticationError("participant_assertions must be a list")
        document = plan.to_dict()
        expected = document["participant_authentications"]
        if len(participant_assertions) != len(expected):
            raise PrincipalAuthenticationError(
                "Execution terminal participant assertion count does not match"
            )
        acknowledgement_by_id = {
            authentication.authentication_id: authentication
            for authentication, _ in acknowledgements
        }
        result: list[_ParticipantInput] = []
        for participant, raw_assertion in zip(
            expected,
            participant_assertions,
            strict=True,
        ):
            assertion = self._policy_service._assertion(
                raw_assertion,
                f"{participant['role']}_assertion",
            )
            try:
                operation = PrincipalOperation(participant["operation"])
            except ValueError as exc:
                raise PrincipalAuthenticationError(
                    "Execution terminal participant operation is invalid"
                ) from exc
            intent = self._participant_intent(
                participant,
                authenticated_request=authenticated_request,
                acknowledgement_by_id=acknowledgement_by_id,
                authenticated_timeout=authenticated_timeout,
            )
            material = self._policy_service._assertion_material(
                assertion,
                operation,
                intent,
            )
            if (
                assertion.profile_id != participant["profile_id"]
                or assertion.issuer != participant["issuer"]
                or assertion.assertion_id != participant["assertion_id"]
                or material["assertion_hash"] != participant["assertion_sha256"]
                or assertion.scope_grant_id != participant["scope_grant_id"]
                or assertion.scope_grant_sha256 != participant["scope_grant_sha256"]
                or assertion.operation.value != participant["operation"]
                or material["signed_hash"] != participant["operation_intent_sha256"]
            ):
                raise PrincipalAuthenticationError(
                    "Execution terminal participant assertion does not match the plan"
                )
            result.append(
                _ParticipantInput(
                    expected=participant,
                    assertion=assertion,
                    operation=operation,
                    intent=intent,
                    material=material,
                )
            )
        identities = {(item.assertion.issuer, item.assertion.assertion_id) for item in result}
        if len(identities) != len(result):
            raise PrincipalAuthenticationError(
                "Execution terminal participant assertions must be distinct"
            )
        return tuple(result)

    @staticmethod
    def _participant_intent(
        participant: dict[str, str],
        *,
        authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
        acknowledgement_by_id: dict[
            str,
            AuthenticatedCollaborationExecutionAcknowledgement,
        ],
        authenticated_timeout: AuthenticatedCollaborationExecutionTimeoutResolution | None,
    ) -> dict[str, str]:
        request = authenticated_request.request
        request_document = request.to_dict()
        role = participant["role"]
        if role == "control_plane_requester":
            return {
                "mission_id": request_document["mission_id"],
                "principal_profile_id": participant["profile_id"],
                "request_selection_sha256": (
                    collaboration_execution_transfer_request_selection_sha256(request)
                ),
            }
        if role in {"source_worker", "target_worker"}:
            authentication = acknowledgement_by_id.get(participant["authentication_id"])
            if authentication is None:
                raise PrincipalAuthenticationError(
                    "Execution terminal acknowledgement authentication is missing"
                )
            return {
                "acknowledgement_selection_sha256": (
                    collaboration_execution_acknowledgement_selection_sha256(
                        authentication.acknowledgement
                    )
                ),
                "mission_id": request_document["mission_id"],
                "principal_profile_id": participant["profile_id"],
                "request_id": request.request_id,
                "request_sha256": request.request_sha256,
            }
        if role == "independent_control" and authenticated_timeout is not None:
            return {
                "mission_id": request_document["mission_id"],
                "principal_profile_id": participant["profile_id"],
                "resolution_selection_sha256": (
                    collaboration_execution_timeout_resolution_selection_sha256(
                        authenticated_timeout.resolution
                    )
                ),
            }
        raise PrincipalAuthenticationError(
            "Execution terminal participant authentication is missing"
        )

    def _require_execution_basis(
        self,
        connection: sqlite3.Connection,
        authenticated_request: AuthenticatedCollaborationExecutionTransferRequest,
        plan_document: dict[str, Any],
    ) -> None:
        request = authenticated_request.request.to_dict()
        mission_id = plan_document["mission_id"]
        _, collaboration_plan = self._work._load_activation(connection, mission_id)
        if (
            request["collaboration_plan_id"] != collaboration_plan.plan_id
            or request["collaboration_plan_sha256"] != collaboration_plan.content_sha256
        ):
            raise StoreConflictError("Execution terminal collaboration plan is not active")
        work_items = {
            item.work_item_id: item for item in collaboration_plan.work_items
        }
        work_item = work_items.get(plan_document["work_item_id"])
        if (
            work_item is None
            or collaboration_work_item_objective_sha256(work_item)
            != request["work_item_objective_sha256"]
        ):
            raise StoreConflictError("Execution terminal work item is not in the active plan")
        row = connection.execute(
            """
            SELECT channel_policy_id, channel_policy_sha256
            FROM execution_channel_policy_commits
            WHERE mission_id = ?
            ORDER BY policy_version DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("A committed execution channel policy is required")
        if request["channel_policy"] != {
            "channel_policy_id": row["channel_policy_id"],
            "channel_policy_sha256": row["channel_policy_sha256"],
        }:
            raise StoreConflictError("Execution terminal channel policy is not current")

    @staticmethod
    def _require_principal_binding(
        principal: dict[str, Any],
        expected: dict[str, str],
    ) -> None:
        fields = {
            "profile_id": "profile_id",
            "issuer": "issuer",
            "assertion_id": "assertion_id",
            "assertion_sha256": "assertion_sha256",
            "operation": "operation",
            "operation_intent_sha256": "operation_intent_sha256",
            "policy_sha256": "policy_sha256",
            "scope_grant_id": "scope_grant_id",
            "scope_grant_sha256": "scope_grant_sha256",
        }
        if any(principal[left] != expected[right] for left, right in fields.items()):
            raise PrincipalAuthenticationError(
                "Execution terminal verified principal does not match the plan"
            )

    @staticmethod
    def _insert_commit(
        connection: sqlite3.Connection,
        plan: CollaborationExecutionTerminalCustodyPlan,
        plan_json: str,
        committed_at: str,
    ) -> None:
        document = plan.to_dict()
        connection.execute(
            """
            INSERT INTO execution_terminal_custody_commits(
                custody_plan_id, custody_plan_sha256, mission_id, work_item_id,
                transfer_kind, terminal_kind, outcome_id, outcome_sha256,
                outcome_authentication_id, outcome_authentication_sha256,
                request_authentication_id, request_authentication_sha256,
                transfer_request_id, transfer_request_sha256,
                source_session_disposition, target_session_disposition,
                recovery_required, participant_count, custody_plan_json, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                plan.custody_plan_id,
                plan.custody_plan_sha256,
                document["mission_id"],
                document["work_item_id"],
                document["transfer_kind"],
                document["terminal_kind"],
                document["terminal_outcome"]["outcome_id"],
                document["terminal_outcome"]["outcome_sha256"],
                document["outcome_authentication"]["authentication_id"],
                document["outcome_authentication"]["authentication_sha256"],
                document["request_authentication"]["authentication_id"],
                document["request_authentication"]["authentication_sha256"],
                document["transfer_request"]["request_id"],
                document["transfer_request"]["request_sha256"],
                document["source_session_disposition"],
                document["target_session_disposition"],
                int(document["recovery_required"]),
                len(document["participant_authentications"]),
                plan_json,
                committed_at,
            ),
        )

    @staticmethod
    def _insert_participants(
        connection: sqlite3.Connection,
        plan: CollaborationExecutionTerminalCustodyPlan,
        committed_at: str,
    ) -> None:
        document = plan.to_dict()
        for index, participant in enumerate(document["participant_authentications"]):
            connection.execute(
                """
                INSERT INTO execution_terminal_custody_participants(
                    custody_plan_id, participant_index, mission_id, role,
                    authentication_id, authentication_sha256, profile_id, issuer,
                    assertion_id, assertion_sha256, operation,
                    operation_intent_sha256, policy_sha256, scope_grant_id,
                    scope_grant_sha256, committed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.custody_plan_id,
                    index,
                    document["mission_id"],
                    participant["role"],
                    participant["authentication_id"],
                    participant["authentication_sha256"],
                    participant["profile_id"],
                    participant["issuer"],
                    participant["assertion_id"],
                    participant["assertion_sha256"],
                    participant["operation"],
                    participant["operation_intent_sha256"],
                    participant["policy_sha256"],
                    participant["scope_grant_id"],
                    participant["scope_grant_sha256"],
                    committed_at,
                ),
            )

    @staticmethod
    def _row_for_plan(
        connection: sqlite3.Connection,
        custody_plan_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM execution_terminal_custody_commits WHERE custody_plan_id = ?",
            (custody_plan_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Execution terminal custody plan is not committed")
        return row

    @staticmethod
    def _require_exact_commit(
        row: sqlite3.Row,
        plan: CollaborationExecutionTerminalCustodyPlan,
        plan_json: str,
    ) -> None:
        if (
            row["custody_plan_sha256"] != plan.custody_plan_sha256
            or row["custody_plan_json"] != plan_json
        ):
            raise StoreConflictError("Execution terminal replay has different content")

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt:
        try:
            plan = CollaborationExecutionTerminalCustodyPlan.from_dict(
                json.loads(str(row["custody_plan_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError("Stored execution terminal custody is invalid") from exc
        participant_rows = connection.execute(
            """
            SELECT
                participant.participant_index, participant.role,
                participant.authentication_id, participant.issuer,
                participant.assertion_id, participant.assertion_sha256,
                assertion_use.entry_hash
            FROM execution_terminal_custody_participants AS participant
            JOIN principal_assertion_uses AS assertion_use
              ON assertion_use.issuer = participant.issuer
             AND assertion_use.assertion_id = participant.assertion_id
             AND assertion_use.mission_id = participant.mission_id
            WHERE participant.custody_plan_id = ?
            ORDER BY participant.participant_index
            """,
            (plan.custody_plan_id,),
        ).fetchall()
        expected = plan.to_dict()["participant_authentications"]
        if len(participant_rows) != len(expected):
            raise StoreIntegrityError("Execution terminal custody provenance is incomplete")
        commits: list[ExecutionTerminalCustodyParticipantCommit] = []
        for index, (participant, expected_participant) in enumerate(
            zip(participant_rows, expected, strict=True)
        ):
            if (
                int(participant["participant_index"]) != index
                or participant["role"] != expected_participant["role"]
                or participant["authentication_id"]
                != expected_participant["authentication_id"]
                or participant["issuer"] != expected_participant["issuer"]
                or participant["assertion_id"] != expected_participant["assertion_id"]
                or participant["assertion_sha256"]
                != expected_participant["assertion_sha256"]
            ):
                raise StoreIntegrityError(
                    "Execution terminal custody provenance does not match"
                )
            commits.append(
                ExecutionTerminalCustodyParticipantCommit(
                    participant_index=index,
                    role=str(participant["role"]),
                    authentication_id=str(participant["authentication_id"]),
                    issuer=str(participant["issuer"]),
                    assertion_id=str(participant["assertion_id"]),
                    assertion_sha256=str(participant["assertion_sha256"]),
                    ledger_entry_sha256=str(participant["entry_hash"]),
                )
            )
        return AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt(
            plan=plan,
            committed_at=str(row["committed_at"]),
            participant_commits=tuple(commits),
        )


__all__ = [
    "AuthenticatedCollaborationExecutionTerminalCustodyCommitReceipt",
    "AuthenticatedCollaborationExecutionTerminalCustodyService",
    "ExecutionTerminalCustodyParticipantCommit",
]
