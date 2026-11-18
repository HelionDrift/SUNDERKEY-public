"""Atomic custody for authenticated execution session state changes."""

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
from .collaboration_execution_session_authentication import (
    CollaborationExecutionSessionActivationRequest,
    authenticate_collaboration_execution_session_activation,
    authenticate_collaboration_execution_session_revocation,
    collaboration_execution_session_activation_selection_sha256,
    collaboration_execution_session_revocation_selection_sha256,
)
from .collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
    CollaborationExecutionSessionRevocation,
)
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import PrincipalAssertion, PrincipalOperation
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, parse_timestamp

_ACTIVATION_ID_PATTERN = re.compile(r"EAS-[0-9A-F]{32}")
_REVOCATION_ID_PATTERN = re.compile(r"ESV-[0-9A-F]{32}")


@dataclass(frozen=True)
class ExecutionSessionPrincipalCommit:
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
class AuthenticatedCollaborationExecutionSessionActivationCommitReceipt:
    """Durable control-plane availability for one fenced session."""

    authority: CollaborationExecutionSessionAuthority
    request: CollaborationExecutionSessionActivationRequest
    authentication_id: str
    authentication_sha256: str
    activation_selection_sha256: str
    authenticated_at: str
    committed_at: str
    control_plane_requester: ExecutionSessionPrincipalCommit
    worker_acceptor: ExecutionSessionPrincipalCommit

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_authority": self.authority.to_dict(),
            "activation_request": self.request.to_dict(),
            "activation_authentication": {
                "authentication_id": self.authentication_id,
                "authentication_sha256": self.authentication_sha256,
                "activation_selection_sha256": self.activation_selection_sha256,
                "authenticated_at": self.authenticated_at,
            },
            "committed_at": self.committed_at,
            "control_plane_requester": self.control_plane_requester.to_dict(),
            "worker_acceptor": self.worker_acceptor.to_dict(),
            "authority_state": "committed_available_for_executor",
            "runtime_effect": "none",
        }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt:
    """Durable independent-Control revocation for one fenced session."""

    authority: CollaborationExecutionSessionAuthority
    revocation: CollaborationExecutionSessionRevocation
    authentication_id: str
    authentication_sha256: str
    revocation_selection_sha256: str
    authenticated_at: str
    committed_at: str
    independent_control: ExecutionSessionPrincipalCommit

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_authority": self.authority.to_dict(),
            "session_revocation": self.revocation.to_dict(),
            "revocation_authentication": {
                "authentication_id": self.authentication_id,
                "authentication_sha256": self.authentication_sha256,
                "revocation_selection_sha256": self.revocation_selection_sha256,
                "authenticated_at": self.authenticated_at,
            },
            "committed_at": self.committed_at,
            "independent_control": self.independent_control.to_dict(),
            "authority_state": "revoked",
            "runtime_effect": "none",
        }


class AuthenticatedCollaborationExecutionSessionAuthorityService:
    """Atomically commit session authority activation and revocation."""

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

    def get_activation(
        self,
        authentication_id: str,
    ) -> AuthenticatedCollaborationExecutionSessionActivationCommitReceipt:
        if (
            not isinstance(authentication_id, str)
            or _ACTIVATION_ID_PATTERN.fullmatch(authentication_id) is None
        ):
            raise StoreError("authentication_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = self._activation_row(connection, authentication_id)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._store._verify_execution_session_authority_commits(
                    connection,
                    mission,
                )
                self._store._verify_execution_session_state_commits(
                    connection,
                    mission,
                )
                return self._activation_receipt(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read execution session activation") from exc

    def get_revocation(
        self,
        authentication_id: str,
    ) -> AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt:
        if (
            not isinstance(authentication_id, str)
            or _REVOCATION_ID_PATTERN.fullmatch(authentication_id) is None
        ):
            raise StoreError("authentication_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = self._revocation_row(connection, authentication_id)
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(row["mission_id"]),
                )
                self._store._verify_execution_session_authority_commits(
                    connection,
                    mission,
                )
                self._store._verify_execution_session_state_commits(
                    connection,
                    mission,
                )
                return self._revocation_receipt(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read execution session revocation") from exc

    def activate(
        self,
        authority: CollaborationExecutionSessionAuthority,
        request: CollaborationExecutionSessionActivationRequest,
        *,
        control_plane_assertion: PrincipalAssertion,
        worker_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationExecutionSessionActivationCommitReceipt:
        parsed_authority = self._authority(authority)
        parsed_request = self._request(request)
        control = self._policy_service._assertion(
            control_plane_assertion,
            "control_plane_assertion",
        )
        worker = self._policy_service._assertion(
            worker_assertion,
            "worker_assertion",
        )
        if (control.issuer, control.assertion_id) == (
            worker.issuer,
            worker.assertion_id,
        ):
            raise PrincipalAuthenticationError(
                "Execution session activation requires two distinct assertions"
            )
        authority_document = parsed_authority.to_dict()
        session = authority_document["session"]
        mission_id = session["mission_id"]
        selection_sha256 = (
            collaboration_execution_session_activation_selection_sha256(
                parsed_request
            )
        )
        control_operation = PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE
        worker_operation = PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT
        control_intent = self._activation_intent(
            mission_id,
            selection_sha256,
            control.profile_id,
        )
        worker_intent = self._activation_intent(
            mission_id,
            selection_sha256,
            worker.profile_id,
        )
        control_material = self._policy_service._assertion_material(
            control,
            control_operation,
            control_intent,
        )
        worker_material = self._policy_service._assertion_material(
            worker,
            worker_operation,
            worker_intent,
        )
        try:
            with self._store._write_connection() as connection:
                identity, trust_policies, mission, scope_grants, ledger = (
                    self._activation._verified_mission_state(
                        connection,
                        mission_id,
                    )
                )
                control_use = self._policy_service._existing_use(connection, control)
                worker_use = self._policy_service._existing_use(connection, worker)
                if control_use is not None or worker_use is not None:
                    if control_use is None or worker_use is None:
                        raise StoreConflictError(
                            "Execution session activation replay has incomplete "
                            "assertion use"
                        )
                    self._policy_service._require_exact_replay(
                        control_use,
                        assertion=control,
                        mission_id=mission_id,
                        operation=control_operation,
                        material=control_material,
                    )
                    self._policy_service._require_exact_replay(
                        worker_use,
                        assertion=worker,
                        mission_id=mission_id,
                        operation=worker_operation,
                        material=worker_material,
                    )
                    row = self._activation_row_for_assertions(
                        connection,
                        control,
                        worker,
                    )
                    self._require_exact_activation(
                        row,
                        parsed_authority,
                        parsed_request,
                        selection_sha256,
                    )
                    self._store._verify_execution_session_state_commits(
                        connection,
                        mission,
                    )
                    return self._activation_receipt(connection, row)

                self._policy_service._require_active(connection, mission_id)
                if connection.execute(
                    """
                    SELECT 1 FROM execution_session_revocation_commits
                    WHERE session_authority_id = ?
                    """,
                    (parsed_authority.session_authority_id,),
                ).fetchone() is not None:
                    raise StoreConflictError(
                        "Revoked execution session authority cannot be activated"
                    )
                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "execution session activation committed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                verified_policy, control_scope = self._policy_service._verified_scope(
                    connection,
                    assertion=control,
                    operation=control_operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                )
                worker_policy, worker_scope = self._policy_service._verified_scope(
                    connection,
                    assertion=worker,
                    operation=worker_operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                )
                if worker_policy.policy_sha256 != verified_policy.policy_sha256:
                    raise PrincipalAuthenticationError(
                        "Execution session activation uses different trust policies"
                    )
                authenticated = (
                    authenticate_collaboration_execution_session_activation(
                        parsed_request,
                        authority=parsed_authority,
                        control_plane_assertion=control,
                        worker_assertion=worker,
                        verified_policy=verified_policy,
                        control_plane_scope=control_scope,
                        worker_scope=worker_scope,
                        expected_audience=str(identity["audience"]),
                        expected_store_id=str(identity["store_id"]),
                        expected_control_plane_profile_ids=(
                            mission.control_profile_ids
                        ),
                        clock=lambda: now,
                    )
                )
                self._insert_or_require_authority(
                    connection,
                    parsed_authority,
                )
                common_payload = self._activation_effect_payload(
                    authenticated.authentication_id,
                    authenticated.authentication_sha256,
                    parsed_request,
                    selection_sha256,
                    parsed_authority,
                )
                control_effect = self._policy_service._effect(
                    authenticated.authentication_id,
                    control_operation,
                    {
                        **common_payload,
                        "participant_role": "control_plane_requester",
                    },
                    committed_at,
                )
                worker_effect = self._policy_service._effect(
                    authenticated.authentication_id,
                    worker_operation,
                    {
                        **common_payload,
                        "participant_role": "worker_acceptor",
                    },
                    committed_at,
                )
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.control_plane_requester,
                    assertion=control,
                    mission_id=mission_id,
                    operation=control_operation,
                    material=control_material,
                    effect=control_effect,
                    ledger=ledger,
                    consumed_at=committed_at,
                )
                next_ledger = self._ledger(connection, mission_id)
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.worker_acceptor,
                    assertion=worker,
                    mission_id=mission_id,
                    operation=worker_operation,
                    material=worker_material,
                    effect=worker_effect,
                    ledger=next_ledger,
                    consumed_at=committed_at,
                )
                self._insert_activation(
                    connection,
                    parsed_authority,
                    parsed_request,
                    authenticated.to_dict(),
                    selection_sha256,
                    committed_at,
                    control,
                    worker,
                )
                row = self._activation_row_for_assertions(
                    connection,
                    control,
                    worker,
                )
                self._store._verify_execution_session_authority_commits(
                    connection,
                    mission,
                )
                self._store._verify_execution_session_state_commits(
                    connection,
                    mission,
                )
                return self._activation_receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit execution session activation"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit execution session activation") from exc

    def revoke(
        self,
        authority: CollaborationExecutionSessionAuthority,
        revocation: CollaborationExecutionSessionRevocation,
        *,
        independent_control_assertion: PrincipalAssertion,
    ) -> AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt:
        parsed_authority = self._authority(authority)
        parsed_revocation = self._revocation(revocation)
        control = self._policy_service._assertion(
            independent_control_assertion,
            "independent_control_assertion",
        )
        authority_document = parsed_authority.to_dict()
        session = authority_document["session"]
        mission_id = session["mission_id"]
        selection_sha256 = (
            collaboration_execution_session_revocation_selection_sha256(
                parsed_revocation
            )
        )
        operation = PrincipalOperation.EXECUTION_SESSION_REVOKE
        intent = {
            "mission_id": mission_id,
            "principal_profile_id": control.profile_id,
            "revocation_selection_sha256": selection_sha256,
        }
        material = self._policy_service._assertion_material(
            control,
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
                    control,
                )
                if existing_use is not None:
                    self._policy_service._require_exact_replay(
                        existing_use,
                        assertion=control,
                        mission_id=mission_id,
                        operation=operation,
                        material=material,
                    )
                    row = self._revocation_row_for_assertion(connection, control)
                    self._require_exact_revocation(
                        row,
                        parsed_authority,
                        parsed_revocation,
                        selection_sha256,
                    )
                    self._store._verify_execution_session_state_commits(
                        connection,
                        mission,
                    )
                    return self._revocation_receipt(connection, row)

                existing_revocation = connection.execute(
                    """
                    SELECT 1 FROM execution_session_revocation_commits
                    WHERE session_authority_id = ?
                    """,
                    (parsed_authority.session_authority_id,),
                ).fetchone()
                if existing_revocation is not None:
                    raise StoreConflictError(
                        "Execution session authority is already revoked"
                    )
                now = self._clock()
                committed_at = format_timestamp(now)
                committed_time = parse_timestamp(
                    committed_at,
                    "execution session revocation committed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    committed_time,
                )
                verified_policy, control_scope = self._policy_service._verified_scope(
                    connection,
                    assertion=control,
                    operation=operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=committed_time,
                    allow_expired_for_safety_reduction=True,
                )
                authenticated = (
                    authenticate_collaboration_execution_session_revocation(
                        parsed_revocation,
                        authority=parsed_authority,
                        independent_control_assertion=control,
                        verified_policy=verified_policy,
                        independent_control_scope=control_scope,
                        expected_audience=str(identity["audience"]),
                        expected_store_id=str(identity["store_id"]),
                        expected_control_profile_ids=mission.control_profile_ids,
                        clock=lambda: now,
                    )
                )
                self._insert_or_require_authority(
                    connection,
                    parsed_authority,
                )
                effect = self._policy_service._effect(
                    authenticated.authentication_id,
                    operation,
                    self._revocation_effect_payload(
                        authenticated.authentication_id,
                        authenticated.authentication_sha256,
                        parsed_revocation,
                        selection_sha256,
                        parsed_authority,
                    ),
                    committed_at,
                )
                self._policy_service._record_assertion(
                    connection,
                    principal=authenticated.independent_control,
                    assertion=control,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=committed_at,
                )
                self._insert_revocation(
                    connection,
                    parsed_authority,
                    parsed_revocation,
                    authenticated.to_dict(),
                    selection_sha256,
                    committed_at,
                    control,
                )
                row = self._revocation_row_for_assertion(connection, control)
                self._store._verify_execution_session_authority_commits(
                    connection,
                    mission,
                )
                self._store._verify_execution_session_state_commits(
                    connection,
                    mission,
                )
                return self._revocation_receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not commit execution session revocation"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not commit execution session revocation") from exc

    @staticmethod
    def _authority(
        value: Any,
    ) -> CollaborationExecutionSessionAuthority:
        if not isinstance(value, CollaborationExecutionSessionAuthority):
            raise TypeError(
                "authority must be a CollaborationExecutionSessionAuthority"
            )
        return CollaborationExecutionSessionAuthority.from_dict(value.to_dict())

    @staticmethod
    def _request(
        value: Any,
    ) -> CollaborationExecutionSessionActivationRequest:
        if not isinstance(value, CollaborationExecutionSessionActivationRequest):
            raise TypeError(
                "request must be a CollaborationExecutionSessionActivationRequest"
            )
        return CollaborationExecutionSessionActivationRequest.from_dict(
            value.to_dict()
        )

    @staticmethod
    def _revocation(
        value: Any,
    ) -> CollaborationExecutionSessionRevocation:
        if not isinstance(value, CollaborationExecutionSessionRevocation):
            raise TypeError(
                "revocation must be a CollaborationExecutionSessionRevocation"
            )
        return CollaborationExecutionSessionRevocation.from_dict(value.to_dict())

    @staticmethod
    def _activation_intent(
        mission_id: str,
        selection_sha256: str,
        profile_id: str,
    ) -> dict[str, str]:
        return {
            "activation_selection_sha256": selection_sha256,
            "mission_id": mission_id,
            "principal_profile_id": profile_id,
        }

    @staticmethod
    def _activation_effect_payload(
        authentication_id: str,
        authentication_sha256: str,
        request: CollaborationExecutionSessionActivationRequest,
        selection_sha256: str,
        authority: CollaborationExecutionSessionAuthority,
    ) -> dict[str, Any]:
        request_document = request.to_dict()
        return {
            "authentication_id": authentication_id,
            "authentication_sha256": authentication_sha256,
            "activation_request_id": request.activation_request_id,
            "activation_request_sha256": request.activation_request_sha256,
            "activation_selection_sha256": selection_sha256,
            "session_authority_id": authority.session_authority_id,
            "session_authority_sha256": authority.session_authority_sha256,
            "session_id": request_document["session"]["session_id"],
            "session_sha256": request_document["session"]["session_sha256"],
            "credential_reference_id": request_document["credential"][
                "credential_reference_id"
            ],
            "credential_sha256": request_document["credential"][
                "credential_sha256"
            ],
            "mission_id": request_document["mission_id"],
            "work_item_id": request_document["work_item_id"],
            "runtime_effect": "none",
        }

    @staticmethod
    def _revocation_effect_payload(
        authentication_id: str,
        authentication_sha256: str,
        revocation: CollaborationExecutionSessionRevocation,
        selection_sha256: str,
        authority: CollaborationExecutionSessionAuthority,
    ) -> dict[str, Any]:
        document = revocation.to_dict()
        return {
            "authentication_id": authentication_id,
            "authentication_sha256": authentication_sha256,
            "revocation_id": revocation.revocation_id,
            "revocation_sha256": revocation.revocation_sha256,
            "revocation_selection_sha256": selection_sha256,
            "session_authority_id": authority.session_authority_id,
            "session_authority_sha256": authority.session_authority_sha256,
            "session_id": document["session"]["session_id"],
            "session_sha256": document["session"]["session_sha256"],
            "credential_reference_id": document["credential"][
                "credential_reference_id"
            ],
            "credential_sha256": document["credential"]["credential_sha256"],
            "mission_id": document["mission_id"],
            "work_item_id": document["work_item_id"],
            "reason_code": document["reason_code"],
            "runtime_effect": "none",
        }

    @staticmethod
    def _ledger(connection: sqlite3.Connection, mission_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Mission principal ledger disappeared")
        return row

    @staticmethod
    def _insert_or_require_authority(
        connection: sqlite3.Connection,
        authority: CollaborationExecutionSessionAuthority,
    ) -> None:
        existing = connection.execute(
            """
            SELECT * FROM execution_session_authority_commits
            WHERE session_authority_id = ?
            """,
            (authority.session_authority_id,),
        ).fetchone()
        document = authority.to_dict()
        session = document["session"]
        basis = document["authorization_basis"]
        authority_json = canonical_json(document)
        if existing is not None:
            if (
                existing["session_authority_sha256"]
                != authority.session_authority_sha256
                or existing["authority_json"] != authority_json
            ):
                raise StoreConflictError(
                    "Stored execution session authority has different content"
                )
            return
        connection.execute(
            """
            INSERT INTO execution_session_authority_commits(
                session_authority_id,
                session_authority_sha256,
                mission_id,
                collaboration_plan_id,
                collaboration_plan_sha256,
                work_item_id,
                authority_kind,
                basis_kind,
                basis_id,
                basis_sha256,
                channel_policy_id,
                channel_policy_sha256,
                session_id,
                session_sha256,
                owner_profile_id,
                owner_epoch,
                worker_principal_id,
                fence_generation,
                credential_reference_id,
                credential_sha256,
                effective_at,
                expires_at,
                authority_json,
                committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authority.session_authority_id,
                authority.session_authority_sha256,
                session["mission_id"],
                session["collaboration_plan_id"],
                session["collaboration_plan_sha256"],
                session["work_item_id"],
                document["authority_kind"],
                basis["basis_kind"],
                basis["basis_id"],
                basis["basis_sha256"],
                session["channel_policy"]["channel_policy_id"],
                session["channel_policy"]["channel_policy_sha256"],
                session["session_id"],
                session["session_sha256"],
                session["owner_profile_id"],
                session["owner_epoch"],
                session["worker_principal_id"],
                session["fence_generation"],
                session["credential_reference_id"],
                session["credential_sha256"],
                document["effective_at"],
                document["expires_at"],
                authority_json,
                document["effective_at"],
            ),
        )

    @staticmethod
    def _insert_activation(
        connection: sqlite3.Connection,
        authority: CollaborationExecutionSessionAuthority,
        request: CollaborationExecutionSessionActivationRequest,
        authenticated: dict[str, Any],
        selection_sha256: str,
        committed_at: str,
        control: PrincipalAssertion,
        worker: PrincipalAssertion,
    ) -> None:
        document = request.to_dict()
        connection.execute(
            """
            INSERT INTO execution_session_activation_commits(
                authentication_id,
                authentication_sha256,
                activation_request_id,
                activation_request_sha256,
                activation_selection_sha256,
                session_authority_id,
                session_authority_sha256,
                mission_id,
                work_item_id,
                session_id,
                session_sha256,
                credential_reference_id,
                credential_sha256,
                activation_json,
                authenticated_at,
                committed_at,
                control_issuer,
                control_assertion_id,
                worker_issuer,
                worker_assertion_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authenticated["authentication_id"],
                authenticated["authentication_sha256"],
                request.activation_request_id,
                request.activation_request_sha256,
                selection_sha256,
                authority.session_authority_id,
                authority.session_authority_sha256,
                document["mission_id"],
                document["work_item_id"],
                document["session"]["session_id"],
                document["session"]["session_sha256"],
                document["credential"]["credential_reference_id"],
                document["credential"]["credential_sha256"],
                canonical_json(authenticated),
                authenticated["authenticated_at"],
                committed_at,
                control.issuer,
                control.assertion_id,
                worker.issuer,
                worker.assertion_id,
            ),
        )

    @staticmethod
    def _insert_revocation(
        connection: sqlite3.Connection,
        authority: CollaborationExecutionSessionAuthority,
        revocation: CollaborationExecutionSessionRevocation,
        authenticated: dict[str, Any],
        selection_sha256: str,
        committed_at: str,
        control: PrincipalAssertion,
    ) -> None:
        document = revocation.to_dict()
        connection.execute(
            """
            INSERT INTO execution_session_revocation_commits(
                authentication_id,
                authentication_sha256,
                revocation_id,
                revocation_sha256,
                revocation_selection_sha256,
                session_authority_id,
                session_authority_sha256,
                mission_id,
                work_item_id,
                session_id,
                session_sha256,
                credential_reference_id,
                credential_sha256,
                reason_code,
                revocation_json,
                authenticated_at,
                revoked_at,
                committed_at,
                control_issuer,
                control_assertion_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authenticated["authentication_id"],
                authenticated["authentication_sha256"],
                revocation.revocation_id,
                revocation.revocation_sha256,
                selection_sha256,
                authority.session_authority_id,
                authority.session_authority_sha256,
                document["mission_id"],
                document["work_item_id"],
                document["session"]["session_id"],
                document["session"]["session_sha256"],
                document["credential"]["credential_reference_id"],
                document["credential"]["credential_sha256"],
                document["reason_code"],
                canonical_json(authenticated),
                authenticated["authenticated_at"],
                document["revoked_at"],
                committed_at,
                control.issuer,
                control.assertion_id,
            ),
        )

    @staticmethod
    def _activation_row(
        connection: sqlite3.Connection,
        authentication_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_activation_commits
            WHERE authentication_id = ?
            """,
            (authentication_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Execution session activation is not committed")
        return row

    @staticmethod
    def _revocation_row(
        connection: sqlite3.Connection,
        authentication_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_revocation_commits
            WHERE authentication_id = ?
            """,
            (authentication_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Execution session revocation is not committed")
        return row

    @staticmethod
    def _activation_row_for_assertions(
        connection: sqlite3.Connection,
        control: PrincipalAssertion,
        worker: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_activation_commits
            WHERE control_issuer = ? AND control_assertion_id = ?
              AND worker_issuer = ? AND worker_assertion_id = ?
            """,
            (
                control.issuer,
                control.assertion_id,
                worker.issuer,
                worker.assertion_id,
            ),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Execution session assertions have no durable activation"
            )
        return row

    @staticmethod
    def _revocation_row_for_assertion(
        connection: sqlite3.Connection,
        control: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM execution_session_revocation_commits
            WHERE control_issuer = ? AND control_assertion_id = ?
            """,
            (control.issuer, control.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Execution session assertion has no durable revocation"
            )
        return row

    @staticmethod
    def _require_exact_activation(
        row: sqlite3.Row,
        authority: CollaborationExecutionSessionAuthority,
        request: CollaborationExecutionSessionActivationRequest,
        selection_sha256: str,
    ) -> None:
        try:
            document = json.loads(str(row["activation_json"]))
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError(
                "Stored execution session activation is invalid"
            ) from exc
        if (
            row["session_authority_id"] != authority.session_authority_id
            or row["session_authority_sha256"]
            != authority.session_authority_sha256
            or row["activation_request_id"] != request.activation_request_id
            or row["activation_request_sha256"]
            != request.activation_request_sha256
            or row["activation_selection_sha256"] != selection_sha256
            or not isinstance(document, dict)
            or document.get("activation_request") != request.to_dict()
        ):
            raise StoreConflictError(
                "Execution session activation replay has different content"
            )

    @staticmethod
    def _require_exact_revocation(
        row: sqlite3.Row,
        authority: CollaborationExecutionSessionAuthority,
        revocation: CollaborationExecutionSessionRevocation,
        selection_sha256: str,
    ) -> None:
        try:
            document = json.loads(str(row["revocation_json"]))
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError(
                "Stored execution session revocation is invalid"
            ) from exc
        if (
            row["session_authority_id"] != authority.session_authority_id
            or row["session_authority_sha256"]
            != authority.session_authority_sha256
            or row["revocation_id"] != revocation.revocation_id
            or row["revocation_sha256"] != revocation.revocation_sha256
            or row["revocation_selection_sha256"] != selection_sha256
            or not isinstance(document, dict)
            or document.get("session_revocation") != revocation.to_dict()
        ):
            raise StoreConflictError(
                "Execution session revocation replay has different content"
            )

    @staticmethod
    def _assertion_use(
        connection: sqlite3.Connection,
        issuer: str,
        assertion_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (issuer, assertion_id),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Execution session principal provenance is missing"
            )
        return row

    @classmethod
    def _principal_commit(
        cls,
        connection: sqlite3.Connection,
        issuer: str,
        assertion_id: str,
    ) -> ExecutionSessionPrincipalCommit:
        use = cls._assertion_use(connection, issuer, assertion_id)
        return ExecutionSessionPrincipalCommit(
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )

    @classmethod
    def _activation_receipt(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutionSessionActivationCommitReceipt:
        authority_row = connection.execute(
            """
            SELECT authority_json FROM execution_session_authority_commits
            WHERE session_authority_id = ?
            """,
            (row["session_authority_id"],),
        ).fetchone()
        if authority_row is None:
            raise StoreIntegrityError("Execution session authority disappeared")
        try:
            authority = CollaborationExecutionSessionAuthority.from_dict(
                json.loads(str(authority_row["authority_json"]))
            )
            authenticated = json.loads(str(row["activation_json"]))
            request = CollaborationExecutionSessionActivationRequest.from_dict(
                authenticated["activation_request"]
            )
        except (
            KeyError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored execution session activation is invalid"
            ) from exc
        return AuthenticatedCollaborationExecutionSessionActivationCommitReceipt(
            authority=authority,
            request=request,
            authentication_id=str(row["authentication_id"]),
            authentication_sha256=str(row["authentication_sha256"]),
            activation_selection_sha256=str(row["activation_selection_sha256"]),
            authenticated_at=str(row["authenticated_at"]),
            committed_at=str(row["committed_at"]),
            control_plane_requester=cls._principal_commit(
                connection,
                str(row["control_issuer"]),
                str(row["control_assertion_id"]),
            ),
            worker_acceptor=cls._principal_commit(
                connection,
                str(row["worker_issuer"]),
                str(row["worker_assertion_id"]),
            ),
        )

    @classmethod
    def _revocation_receipt(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt:
        authority_row = connection.execute(
            """
            SELECT authority_json FROM execution_session_authority_commits
            WHERE session_authority_id = ?
            """,
            (row["session_authority_id"],),
        ).fetchone()
        if authority_row is None:
            raise StoreIntegrityError("Execution session authority disappeared")
        try:
            authority = CollaborationExecutionSessionAuthority.from_dict(
                json.loads(str(authority_row["authority_json"]))
            )
            authenticated = json.loads(str(row["revocation_json"]))
            revocation = CollaborationExecutionSessionRevocation.from_dict(
                authenticated["session_revocation"]
            )
        except (
            KeyError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored execution session revocation is invalid"
            ) from exc
        return AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt(
            authority=authority,
            revocation=revocation,
            authentication_id=str(row["authentication_id"]),
            authentication_sha256=str(row["authentication_sha256"]),
            revocation_selection_sha256=str(row["revocation_selection_sha256"]),
            authenticated_at=str(row["authenticated_at"]),
            committed_at=str(row["committed_at"]),
            independent_control=cls._principal_commit(
                connection,
                str(row["control_issuer"]),
                str(row["control_assertion_id"]),
            ),
        )


__all__ = [
    "AuthenticatedCollaborationExecutionSessionActivationCommitReceipt",
    "AuthenticatedCollaborationExecutionSessionAuthorityService",
    "AuthenticatedCollaborationExecutionSessionRevocationCommitReceipt",
    "ExecutionSessionPrincipalCommit",
]
