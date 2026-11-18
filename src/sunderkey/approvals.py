"""Mission-bound approval queue with independent Control decisions."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .errors import (
    ApprovalConflictError,
    ApprovalDeniedError,
    ApprovalError,
    ApprovalExpiredError,
    StoreError,
)
from .events import MissionEvent, compute_proposal_action_hash
from .registry import ExpertRegistry
from .store import (
    APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
    APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION,
    APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
    AppendReceipt,
    MissionStore,
    allocate_control_event_id,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
    utc_now,
)
from .types import ActionTier, EventType
from .validation import is_ascii_text

APPROVAL_ID_PATTERN = re.compile(r"APR-[A-Z0-9][A-Z0-9._-]{2,59}")


class ApprovalPurpose(StrEnum):
    SIMULATION = "simulation"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRecord:
    schema_version: int
    approval_id: str
    mission_id: str
    proposal_id: str
    proposal_hash: str
    proposer_profile_id: str
    executor_profile_id: str
    action_tier: ActionTier
    scope_reference: str
    purpose: ApprovalPurpose
    state: ApprovalState
    submitted_at: str
    review_expires_at: str
    version: int
    decision_actor_profile_id: str | None
    decision_at: str | None
    decision_code: str | None
    decision_reason: str | None
    decision_event_id: str | None
    authorization_event_id: str | None
    authorization_expires_at: str | None
    simulation_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "mission_id": self.mission_id,
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "proposer_profile_id": self.proposer_profile_id,
            "executor_profile_id": self.executor_profile_id,
            "action_tier": self.action_tier.value,
            "scope_reference": self.scope_reference,
            "purpose": self.purpose.value,
            "state": self.state.value,
            "submitted_at": self.submitted_at,
            "review_expires_at": self.review_expires_at,
            "version": self.version,
            "decision_actor_profile_id": self.decision_actor_profile_id,
            "decision_at": self.decision_at,
            "decision_code": self.decision_code,
            "decision_reason": self.decision_reason,
            "decision_event_id": self.decision_event_id,
            "authorization_event_id": self.authorization_event_id,
            "authorization_expires_at": self.authorization_expires_at,
            "simulation_id": self.simulation_id,
        }


@dataclass(frozen=True)
class ApprovalRevocationRecord:
    schema_version: int
    approval_id: str
    mission_id: str
    authorization_event_id: str
    revocation_event_id: str
    actor_profile_id: str
    revoked_at: str
    reason_code: str
    reason: str
    risk: str
    decision_owner: str
    expected_version: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "mission_id": self.mission_id,
            "authorization_event_id": self.authorization_event_id,
            "revocation_event_id": self.revocation_event_id,
            "actor_profile_id": self.actor_profile_id,
            "revoked_at": self.revoked_at,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "risk": self.risk,
            "decision_owner": self.decision_owner,
            "expected_version": self.expected_version,
        }


@dataclass(frozen=True)
class _ApprovalDecisionCommand:
    operation: str
    approval_id: str
    principal_profile_id: str
    idempotency_key_hash: str
    expected_version: int
    request_hash: str
    authority: str | None = None
    constraints: tuple[str, ...] = ()
    authorization_expires_at: str | None = None
    authorization_expiry: datetime | None = None
    reason_code: str | None = None
    reason: str | None = None
    risk: str | None = None
    decision_owner: str | None = None

    def operation_intent(self) -> dict[str, Any]:
        if self.operation == "sunderkey.approval.approve.v1":
            assert self.authority is not None
            assert self.authorization_expires_at is not None
            return {
                "approval_id": self.approval_id,
                "authority": self.authority,
                "authorization_expires_at": (
                    self.authorization_expires_at
                ),
                "constraints": list(self.constraints),
                "expected_version": self.expected_version,
                "idempotency_key_sha256": (
                    self.idempotency_key_hash
                ),
                "principal_profile_id": self.principal_profile_id,
            }
        assert self.reason_code is not None
        assert self.reason is not None
        assert self.risk is not None
        assert self.decision_owner is not None
        return {
            "approval_id": self.approval_id,
            "decision_owner": self.decision_owner,
            "expected_version": self.expected_version,
            "idempotency_key_sha256": self.idempotency_key_hash,
            "principal_profile_id": self.principal_profile_id,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class _AppliedApprovalDecision:
    record: ApprovalRecord
    event: MissionEvent
    append_receipt: AppendReceipt
    request_hash: str
    idempotency_key_hash: str
    expected_approval_version: int
    pre_approval_version: int
    pre_approval_state: ApprovalState
    final_approval_version: int
    final_approval_state: ApprovalState
    pre_mission_revision: int
    pre_mission_head_hash: str
    final_mission_revision: int
    final_mission_head_hash: str
    event_sequence: int
    event_previous_hash: str
    event_entry_hash: str
    event_stored_at: str


@dataclass(frozen=True)
class _AppliedApprovalRevocation:
    record: ApprovalRecord
    revocation: ApprovalRevocationRecord
    event: MissionEvent
    append_receipt: AppendReceipt
    request_hash: str
    idempotency_key_hash: str
    expected_approval_version: int
    pre_approval_version: int
    pre_approval_state: ApprovalState
    final_approval_version: int
    final_approval_state: ApprovalState
    pre_mission_revision: int
    pre_mission_head_hash: str
    final_mission_revision: int
    final_mission_head_hash: str
    event_sequence: int
    event_previous_hash: str
    event_entry_hash: str
    event_stored_at: str


@dataclass(frozen=True)
class _ApprovalSubmissionCommand:
    mission_id: str
    proposal_id: str
    executor_profile_id: str
    review_expires_at: str
    review_expiry: datetime
    principal_profile_id: str
    idempotency_key_hash: str
    request_hash: str

    def operation_intent(self) -> dict[str, Any]:
        return {
            "executor_profile_id": self.executor_profile_id,
            "idempotency_key_sha256": self.idempotency_key_hash,
            "mission_id": self.mission_id,
            "principal_profile_id": self.principal_profile_id,
            "proposal_id": self.proposal_id,
            "review_expires_at": self.review_expires_at,
        }


@dataclass(frozen=True)
class _AppliedApprovalSubmission:
    record: ApprovalRecord
    proposal: MissionEvent
    request_hash: str
    idempotency_key_hash: str
    proposal_sequence: int
    proposal_entry_hash: str
    proposal_stored_at: str
    mission_revision: int
    mission_head_hash: str


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not is_ascii_text(value):
        raise ApprovalError(f"{label} must be non-empty ASCII text")
    if len(value) > maximum:
        raise ApprovalError(f"{label} exceeds the maximum length of {maximum}")
    return value


def _text_tuple(values: Iterable[str], label: str) -> tuple[str, ...]:
    result = tuple(_text(value, label) for value in values)
    if not result:
        raise ApprovalError(f"{label} must contain at least one value")
    if len(result) != len(set(result)):
        raise ApprovalError(f"{label} contains duplicate values")
    return result


def _key_hash(value: str) -> str:
    key = _text(value, "idempotency_key", maximum=256)
    return sha256_text(key)


def _approval_id(mission_id: str, proposal_id: str) -> str:
    digest = hashlib.sha256(
        f"{mission_id}\n{proposal_id}".encode("ascii")
    ).hexdigest()[:24].upper()
    return f"APR-{digest}"


def _expected_approval_version(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
    ):
        raise ApprovalError("expected_version must be a positive integer")
    return value


def _submit_command(
    *,
    mission_id: str,
    proposal_id: str,
    executor_profile_id: str,
    review_expires_at: str,
    idempotency_key: str,
    principal_profile_id: str,
) -> _ApprovalSubmissionCommand:
    normalized_mission_id = _text(
        mission_id,
        "mission_id",
        maximum=64,
    )
    normalized_proposal_id = _text(
        proposal_id,
        "proposal_id",
        maximum=96,
    )
    normalized_executor_profile_id = _text(
        executor_profile_id,
        "executor_profile_id",
        maximum=64,
    )
    normalized_principal_profile_id = _text(
        principal_profile_id,
        "principal_profile_id",
        maximum=64,
    )
    normalized_review_expires_at = _text(
        review_expires_at,
        "review_expires_at",
        maximum=64,
    )
    review_expiry = parse_timestamp(
        normalized_review_expires_at,
        "review_expires_at",
    )
    idempotency_key_hash = _key_hash(idempotency_key)
    request = {
        "mission_id": normalized_mission_id,
        "proposal_id": normalized_proposal_id,
        "executor_profile_id": normalized_executor_profile_id,
        "review_expires_at": normalized_review_expires_at,
        "principal_profile_id": normalized_principal_profile_id,
        "purpose": ApprovalPurpose.SIMULATION.value,
    }
    return _ApprovalSubmissionCommand(
        mission_id=normalized_mission_id,
        proposal_id=normalized_proposal_id,
        executor_profile_id=normalized_executor_profile_id,
        review_expires_at=normalized_review_expires_at,
        review_expiry=review_expiry,
        principal_profile_id=normalized_principal_profile_id,
        idempotency_key_hash=idempotency_key_hash,
        request_hash=sha256_text(canonical_json(request)),
    )


def _approve_command(
    approval_id: str,
    *,
    authority: str,
    constraints: Iterable[str],
    authorization_expires_at: str,
    idempotency_key: str,
    expected_version: int,
    principal_profile_id: str,
) -> _ApprovalDecisionCommand:
    normalized_approval_id = _text(
        approval_id,
        "approval_id",
        maximum=64,
    )
    if APPROVAL_ID_PATTERN.fullmatch(normalized_approval_id) is None:
        raise ApprovalError(
            f"Invalid approval_id: {normalized_approval_id}"
        )
    normalized_authority = _text(authority, "authority")
    normalized_constraints = _text_tuple(
        constraints,
        "constraints",
    )
    normalized_profile_id = _text(
        principal_profile_id,
        "principal_profile_id",
        maximum=64,
    )
    normalized_expires_at = _text(
        authorization_expires_at,
        "authorization_expires_at",
        maximum=64,
    )
    authorization_expiry = parse_timestamp(
        normalized_expires_at,
        "authorization_expires_at",
    )
    normalized_version = _expected_approval_version(
        expected_version
    )
    idempotency_key_hash = _key_hash(idempotency_key)
    request = {
        "approval_id": normalized_approval_id,
        "authority": normalized_authority,
        "constraints": list(normalized_constraints),
        "authorization_expires_at": normalized_expires_at,
        "principal_profile_id": normalized_profile_id,
        "expected_version": normalized_version,
    }
    return _ApprovalDecisionCommand(
        operation="sunderkey.approval.approve.v1",
        approval_id=normalized_approval_id,
        principal_profile_id=normalized_profile_id,
        idempotency_key_hash=idempotency_key_hash,
        expected_version=normalized_version,
        request_hash=sha256_text(canonical_json(request)),
        authority=normalized_authority,
        constraints=normalized_constraints,
        authorization_expires_at=normalized_expires_at,
        authorization_expiry=authorization_expiry,
    )


def _deny_command(
    approval_id: str,
    *,
    reason_code: str,
    reason: str,
    risk: str,
    decision_owner: str,
    idempotency_key: str,
    expected_version: int,
    principal_profile_id: str,
) -> _ApprovalDecisionCommand:
    normalized_approval_id = _text(
        approval_id,
        "approval_id",
        maximum=64,
    )
    if APPROVAL_ID_PATTERN.fullmatch(normalized_approval_id) is None:
        raise ApprovalError(
            f"Invalid approval_id: {normalized_approval_id}"
        )
    normalized_reason_code = _text(
        reason_code,
        "reason_code",
        maximum=64,
    )
    normalized_reason = _text(reason, "reason")
    normalized_risk = _text(risk, "risk")
    normalized_owner = _text(decision_owner, "decision_owner")
    normalized_profile_id = _text(
        principal_profile_id,
        "principal_profile_id",
        maximum=64,
    )
    normalized_version = _expected_approval_version(
        expected_version
    )
    idempotency_key_hash = _key_hash(idempotency_key)
    request = {
        "approval_id": normalized_approval_id,
        "reason_code": normalized_reason_code,
        "reason": normalized_reason,
        "risk": normalized_risk,
        "decision_owner": normalized_owner,
        "principal_profile_id": normalized_profile_id,
        "expected_version": normalized_version,
    }
    return _ApprovalDecisionCommand(
        operation="sunderkey.approval.deny.v1",
        approval_id=normalized_approval_id,
        principal_profile_id=normalized_profile_id,
        idempotency_key_hash=idempotency_key_hash,
        expected_version=normalized_version,
        request_hash=sha256_text(canonical_json(request)),
        reason_code=normalized_reason_code,
        reason=normalized_reason,
        risk=normalized_risk,
        decision_owner=normalized_owner,
    )


def _revoke_command(
    approval_id: str,
    *,
    reason_code: str,
    reason: str,
    risk: str,
    decision_owner: str,
    idempotency_key: str,
    expected_version: int,
    principal_profile_id: str,
) -> _ApprovalDecisionCommand:
    command = _deny_command(
        approval_id,
        reason_code=reason_code,
        reason=reason,
        risk=risk,
        decision_owner=decision_owner,
        idempotency_key=idempotency_key,
        expected_version=expected_version,
        principal_profile_id=principal_profile_id,
    )
    return _ApprovalDecisionCommand(
        operation="sunderkey.approval.revoke.v1",
        approval_id=command.approval_id,
        principal_profile_id=command.principal_profile_id,
        idempotency_key_hash=command.idempotency_key_hash,
        expected_version=command.expected_version,
        request_hash=command.request_hash,
        reason_code=command.reason_code,
        reason=command.reason,
        risk=command.risk,
        decision_owner=command.decision_owner,
    )


class ApprovalService:
    """Coordinates proposal review and creates ledger-bound decisions."""

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

    def submit(
        self,
        *,
        mission_id: str,
        proposal_id: str,
        executor_profile_id: str,
        review_expires_at: str,
        idempotency_key: str,
        principal_profile_id: str,
    ) -> ApprovalRecord:
        command = _submit_command(
            mission_id=mission_id,
            proposal_id=proposal_id,
            executor_profile_id=executor_profile_id,
            review_expires_at=review_expires_at,
            idempotency_key=idempotency_key,
            principal_profile_id=principal_profile_id,
        )
        try:
            with self.store._write_connection() as connection:
                return self._submit_in_connection(
                    connection,
                    command,
                    self._clock(),
                    allow_exact_replay=True,
                ).record
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError("Could not submit approval request") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist approval request") from exc

    def _submit_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _ApprovalSubmissionCommand,
        now: datetime,
        *,
        allow_exact_replay: bool,
        authenticated_principal: bool = False,
    ) -> _AppliedApprovalSubmission:
        self._require_authenticated_submission_path(
            connection,
            authenticated_principal=authenticated_principal,
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
        try:
            proposal = ledger.get(command.proposal_id)
        except Exception as exc:
            raise ApprovalError(
                f"Unknown stored proposal: {command.proposal_id}"
            ) from exc
        if proposal.event_type is not EventType.PROPOSAL:
            raise ApprovalError(
                "proposal_id must reference a proposal event"
            )
        if proposal.actor_profile_id != command.principal_profile_id:
            raise ApprovalError(
                "Only the stored proposal actor can submit it for review"
            )
        if (
            command.executor_profile_id
            not in stored_mission.allowed_profile_ids
        ):
            raise ApprovalError(
                "Requested executor is not assigned to the mission"
            )
        if (
            command.executor_profile_id
            in stored_mission.control_profile_ids
        ):
            raise ApprovalError(
                "Independent Control profiles cannot be executors"
            )

        approval_id = _approval_id(
            command.mission_id,
            command.proposal_id,
        )
        existing = connection.execute(
            "SELECT * FROM approval_queue WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if existing is not None:
            exact_replay = (
                existing["submit_key_hash"]
                == command.idempotency_key_hash
                and existing["submit_request_hash"]
                == command.request_hash
            )
            if exact_replay and allow_exact_replay:
                return self._applied_submission(
                    connection,
                    self._record_from_row(existing, now),
                    proposal,
                    stored_mission,
                    command,
                )
            if exact_replay:
                raise ApprovalConflictError(
                    "Approval submission already exists outside this "
                    "assertion"
                )
            raise ApprovalConflictError(
                "The proposal already has a different approval request"
            )

        submitted_at = format_timestamp(now)
        if command.review_expiry <= now:
            raise ApprovalExpiredError(
                "Approval review expiry must be later than submission time"
            )
        self.store._require_mission_active(
            connection,
            command.mission_id,
        )
        proposal_hash = compute_proposal_action_hash(
            proposal.payload
        )
        connection.execute(
            """
            INSERT INTO approval_queue(
                approval_id,
                mission_id,
                proposal_id,
                proposal_hash,
                proposer_profile_id,
                executor_profile_id,
                action_tier,
                scope_reference,
                purpose,
                submitted_at,
                review_expires_at,
                status,
                version,
                submit_key_hash,
                submit_request_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?)
            """,
            (
                approval_id,
                command.mission_id,
                command.proposal_id,
                proposal_hash,
                proposal.actor_profile_id,
                command.executor_profile_id,
                str(proposal.payload["action_tier"]),
                stored_mission.mission.scope_reference,
                ApprovalPurpose.SIMULATION.value,
                submitted_at,
                command.review_expires_at,
                command.idempotency_key_hash,
                command.request_hash,
            ),
        )
        row = connection.execute(
            "SELECT * FROM approval_queue WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise ApprovalError(
                "Stored approval submission is missing"
            )
        record = self._record_from_row(row, now)
        applied = self._applied_submission(
            connection,
            record,
            proposal,
            stored_mission,
            command,
        )
        if not authenticated_principal:
            self.store._verify_auxiliary_state(
                connection,
                stored_mission,
                ledger,
            )
        return applied

    def approve(
        self,
        approval_id: str,
        *,
        authority: str,
        constraints: Iterable[str],
        authorization_expires_at: str,
        idempotency_key: str,
        expected_version: int,
        principal_profile_id: str,
    ) -> ApprovalRecord:
        command = _approve_command(
            approval_id,
            authority=authority,
            constraints=constraints,
            authorization_expires_at=authorization_expires_at,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            principal_profile_id=principal_profile_id,
        )
        try:
            with self.store._write_connection() as connection:
                return self._approve_in_connection(
                    connection,
                    command,
                    self._clock(),
                    allow_exact_replay=True,
                ).record
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError("Could not record approval decision") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist approval decision") from exc

    def deny(
        self,
        approval_id: str,
        *,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
        idempotency_key: str,
        expected_version: int,
        principal_profile_id: str,
    ) -> ApprovalRecord:
        command = _deny_command(
            approval_id,
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
                return self._deny_in_connection(
                    connection,
                    command,
                    self._clock(),
                    allow_exact_replay=True,
                ).record
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError("Could not record approval denial") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist approval denial") from exc

    def _approve_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _ApprovalDecisionCommand,
        now: datetime,
        *,
        allow_exact_replay: bool,
        authenticated_principal: bool = False,
    ) -> _AppliedApprovalDecision:
        self._require_authenticated_decision_path(
            connection,
            authenticated_principal=authenticated_principal,
        )
        row = self._approval_row(
            connection,
            command.approval_id,
        )
        record = self._record_from_row(row, now)
        stored_mission, ledger = self._mission_and_ledger(
            connection,
            record.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        if row["decision_key_hash"] is not None:
            exact_replay = (
                row["decision_key_hash"]
                == command.idempotency_key_hash
                and row["decision_request_hash"]
                == command.request_hash
            )
            if exact_replay and allow_exact_replay:
                return self._applied_existing_decision(
                    connection,
                    record,
                    command,
                )
            if exact_replay:
                raise ApprovalConflictError(
                    "Approval decision already exists outside this assertion"
                )
            raise ApprovalConflictError(
                "Approval already has a different decision"
            )
        if command.authorization_expiry is None:
            raise ApprovalError(
                "Approval command has no authorization expiry"
            )
        if command.authorization_expiry <= now:
            raise ApprovalExpiredError(
                "Authorization expiry must be later than the decision time"
            )
        self.store._require_mission_active(
            connection,
            record.mission_id,
        )
        self._require_pending(record, command.expected_version)
        if (
            command.principal_profile_id
            not in stored_mission.control_profile_ids
        ):
            raise ApprovalError(
                "Only an assigned independent Control profile can approve"
            )
        if (
            command.principal_profile_id
            == record.proposer_profile_id
        ):
            raise ApprovalError(
                "A proposer cannot approve its own proposal"
            )
        if (
            command.principal_profile_id
            == record.executor_profile_id
        ):
            raise ApprovalError(
                "An approver cannot be the bound executor"
            )
        assert command.authority is not None
        assert command.authorization_expires_at is not None
        decision_at = format_timestamp(now)
        authorization_id = allocate_control_event_id(
            ledger,
            kind="AUTH",
            subject_id=command.approval_id,
            key_hash=command.idempotency_key_hash,
            request_hash=command.request_hash,
        )
        authorization = MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": authorization_id,
                "mission_id": record.mission_id,
                "event_type": EventType.AUTHORIZATION.value,
                "actor_profile_id": command.principal_profile_id,
                "timestamp": decision_at,
                "payload": {
                    "proposal_id": record.proposal_id,
                    "executor_profile_id": (
                        record.executor_profile_id
                    ),
                    "authority": command.authority,
                    "scope_token": record.scope_reference,
                    "action_hash": record.proposal_hash,
                    "action_tier": record.action_tier.value,
                    "expires_at": (
                        command.authorization_expires_at
                    ),
                    "constraints": list(command.constraints),
                    "approval_id": command.approval_id,
                    "purpose": ApprovalPurpose.SIMULATION.value,
                },
                "references": [record.proposal_id],
            }
        )
        receipts = self.store._append_events_in_connection(
            connection,
            self.registry,
            record.mission_id,
            (authorization,),
            expected_revision=stored_mission.revision,
            allow_control_events=True,
            stored_at=decision_at,
        )
        if len(receipts) != 1 or receipts[0].idempotent:
            raise ApprovalConflictError(
                "Approval authorization event was not newly appended"
            )
        cursor = connection.execute(
            """
            UPDATE approval_queue
            SET status = 'approved',
                version = version + 1,
                decision_actor_profile_id = ?,
                decision_at = ?,
                decision_code = 'approved',
                decision_reason = 'Approved for plan-only simulation',
                decision_key_hash = ?,
                decision_request_hash = ?,
                decision_event_id = ?,
                authorization_event_id = ?,
                authorization_expires_at = ?
            WHERE approval_id = ?
              AND status = 'pending'
              AND version = ?
            """,
            (
                command.principal_profile_id,
                decision_at,
                command.idempotency_key_hash,
                command.request_hash,
                authorization_id,
                authorization_id,
                command.authorization_expires_at,
                command.approval_id,
                command.expected_version,
            ),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError(
                "Approval changed during the decision"
            )
        return self._applied_new_decision(
            connection,
            record,
            stored_mission,
            authorization,
            receipts[0],
            command,
            now,
        )

    def _deny_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _ApprovalDecisionCommand,
        now: datetime,
        *,
        allow_exact_replay: bool,
        authenticated_principal: bool = False,
    ) -> _AppliedApprovalDecision:
        self._require_authenticated_decision_path(
            connection,
            authenticated_principal=authenticated_principal,
        )
        row = self._approval_row(
            connection,
            command.approval_id,
        )
        record = self._record_from_row(row, now)
        stored_mission, ledger = self._mission_and_ledger(
            connection,
            record.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        if row["decision_key_hash"] is not None:
            exact_replay = (
                row["decision_key_hash"]
                == command.idempotency_key_hash
                and row["decision_request_hash"]
                == command.request_hash
            )
            if exact_replay and allow_exact_replay:
                return self._applied_existing_decision(
                    connection,
                    record,
                    command,
                )
            if exact_replay:
                raise ApprovalConflictError(
                    "Approval decision already exists outside this assertion"
                )
            raise ApprovalConflictError(
                "Approval already has a different decision"
            )
        self.store._require_mission_active(
            connection,
            record.mission_id,
        )
        self._require_pending(record, command.expected_version)
        if (
            command.principal_profile_id
            not in stored_mission.control_profile_ids
        ):
            raise ApprovalError(
                "Only an assigned independent Control profile can deny"
            )
        if authenticated_principal and (
            command.principal_profile_id
            in {
                record.proposer_profile_id,
                record.executor_profile_id,
            }
        ):
            raise ApprovalError(
                "An authenticated denial requires an independent "
                "Control decision"
            )
        assert command.reason_code is not None
        assert command.reason is not None
        assert command.risk is not None
        assert command.decision_owner is not None
        decision_at = format_timestamp(now)
        blocker_id = allocate_control_event_id(
            ledger,
            kind="BLOCK",
            subject_id=command.approval_id,
            key_hash=command.idempotency_key_hash,
            request_hash=command.request_hash,
        )
        blocker = MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": blocker_id,
                "mission_id": record.mission_id,
                "event_type": EventType.BLOCKER.value,
                "actor_profile_id": command.principal_profile_id,
                "timestamp": decision_at,
                "payload": {
                    "reason": (
                        f"{command.reason_code}: {command.reason}"
                    ),
                    "risk": command.risk,
                    "decision_owner": command.decision_owner,
                },
                "references": [record.proposal_id],
            }
        )
        receipts = self.store._append_events_in_connection(
            connection,
            self.registry,
            record.mission_id,
            (blocker,),
            expected_revision=stored_mission.revision,
            allow_control_events=True,
            stored_at=decision_at,
        )
        if len(receipts) != 1 or receipts[0].idempotent:
            raise ApprovalConflictError(
                "Approval blocker event was not newly appended"
            )
        cursor = connection.execute(
            """
            UPDATE approval_queue
            SET status = 'denied',
                version = version + 1,
                decision_actor_profile_id = ?,
                decision_at = ?,
                decision_code = ?,
                decision_reason = ?,
                decision_key_hash = ?,
                decision_request_hash = ?,
                decision_event_id = ?
            WHERE approval_id = ?
              AND status = 'pending'
              AND version = ?
            """,
            (
                command.principal_profile_id,
                decision_at,
                command.reason_code,
                command.reason,
                command.idempotency_key_hash,
                command.request_hash,
                blocker_id,
                command.approval_id,
                command.expected_version,
            ),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError(
                "Approval changed during the decision"
            )
        return self._applied_new_decision(
            connection,
            record,
            stored_mission,
            blocker,
            receipts[0],
            command,
            now,
        )

    def revoke(
        self,
        approval_id: str,
        *,
        reason_code: str,
        reason: str,
        risk: str,
        decision_owner: str,
        idempotency_key: str,
        expected_version: int,
        principal_profile_id: str,
    ) -> ApprovalRevocationRecord:
        command = _revoke_command(
            approval_id,
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
                return self._revoke_in_connection(
                    connection,
                    command,
                    self._clock(),
                    allow_exact_replay=True,
                ).revocation
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError(
                "Could not record approval revocation"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist approval revocation"
            ) from exc

    def _revoke_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _ApprovalDecisionCommand,
        now: datetime,
        *,
        allow_exact_replay: bool,
        authenticated_principal: bool = False,
    ) -> _AppliedApprovalRevocation:
        self._require_authenticated_revocation_path(
            connection,
            authenticated_principal=authenticated_principal,
        )
        row = self._approval_row(
            connection,
            command.approval_id,
        )
        record = self._record_from_row(row, now)
        stored_mission, ledger = self._mission_and_ledger(
            connection,
            record.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        existing = connection.execute(
            """
            SELECT * FROM approval_revocations
            WHERE approval_id = ?
            """,
            (command.approval_id,),
        ).fetchone()
        if existing is not None:
            exact_replay = (
                existing["key_hash"]
                == command.idempotency_key_hash
                and existing["request_hash"] == command.request_hash
            )
            if exact_replay and allow_exact_replay:
                return self._applied_existing_revocation(
                    connection,
                    record,
                    existing,
                    command,
                )
            if exact_replay:
                raise ApprovalConflictError(
                    "Approval revocation already exists outside this assertion"
                )
            raise ApprovalConflictError(
                "Approval already has a different revocation"
            )

        revoked_at = format_timestamp(now)
        record = self._record_from_row(row, now)
        self.store._require_mission_active(
            connection,
            record.mission_id,
        )
        if record.version != command.expected_version:
            raise ApprovalConflictError(
                f"Expected approval version {command.expected_version} "
                f"does not match stored version {record.version}"
            )
        if record.state is ApprovalState.EXPIRED:
            raise ApprovalExpiredError(
                "Simulation authorization has expired"
            )
        if record.state is not ApprovalState.APPROVED:
            raise ApprovalConflictError(
                "Only an approved, unconsumed approval can be revoked"
            )
        if command.expected_version != 2:
            raise ApprovalConflictError(
                "Approved revocation requires version 2"
            )
        if (
            command.principal_profile_id
            not in stored_mission.control_profile_ids
        ):
            raise ApprovalError(
                "Only assigned independent Control can revoke"
            )
        if (
            command.principal_profile_id
            == record.proposer_profile_id
        ):
            raise ApprovalError(
                "A proposer cannot revoke its own proposal"
            )
        if (
            command.principal_profile_id
            == record.executor_profile_id
        ):
            raise ApprovalError(
                "The bound executor cannot revoke its approval"
            )
        authorization_id = record.authorization_event_id
        if authorization_id is None:
            raise ApprovalError(
                "Approved record is missing authorization"
            )
        issued_at = record.decision_at
        expires_at = record.authorization_expires_at
        if issued_at is None or expires_at is None:
            raise ApprovalError(
                "Approved record has incomplete authorization time"
            )
        issued = parse_timestamp(
            issued_at,
            "approval.decision_at",
        )
        expires = parse_timestamp(
            expires_at,
            "approval.authorization_expires_at",
        )
        if now < issued:
            raise ApprovalError(
                "Revocation time precedes authorization issuance"
            )
        if now >= expires:
            raise ApprovalExpiredError(
                "Simulation authorization has expired"
            )
        assert command.reason_code is not None
        assert command.reason is not None
        assert command.risk is not None
        assert command.decision_owner is not None
        event_id = allocate_control_event_id(
            ledger,
            kind="REVOKE",
            subject_id=command.approval_id,
            key_hash=command.idempotency_key_hash,
            request_hash=command.request_hash,
        )
        blocker = MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": record.mission_id,
                "event_type": EventType.BLOCKER.value,
                "actor_profile_id": command.principal_profile_id,
                "timestamp": revoked_at,
                "payload": {
                    "reason": (
                        f"{command.reason_code}: {command.reason}"
                    ),
                    "risk": command.risk,
                    "decision_owner": command.decision_owner,
                },
                "references": [
                    record.proposal_id,
                    authorization_id,
                ],
            }
        )
        receipts = self.store._append_events_in_connection(
            connection,
            self.registry,
            record.mission_id,
            (blocker,),
            expected_revision=stored_mission.revision,
            allow_control_events=True,
            stored_at=revoked_at,
        )
        if len(receipts) != 1 or receipts[0].idempotent:
            raise ApprovalConflictError(
                "Approval revocation event was not newly appended"
            )
        connection.execute(
            """
            INSERT INTO approval_revocations(
                approval_id,
                mission_id,
                authorization_event_id,
                revocation_event_id,
                actor_profile_id,
                revoked_at,
                reason_code,
                reason,
                risk,
                decision_owner,
                expected_version,
                key_hash,
                request_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                command.approval_id,
                record.mission_id,
                authorization_id,
                event_id,
                command.principal_profile_id,
                revoked_at,
                command.reason_code,
                command.reason,
                command.risk,
                command.decision_owner,
                command.expected_version,
                command.idempotency_key_hash,
                command.request_hash,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE approval_queue
            SET status = 'revoked',
                version = version + 1
            WHERE approval_id = ?
              AND status = 'approved'
              AND version = 2
              AND simulation_key_hash IS NULL
              AND simulation_id IS NULL
            """,
            (command.approval_id,),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError(
                "Approval changed during revocation"
            )
        return self._applied_new_revocation(
            connection,
            record,
            stored_mission,
            blocker,
            receipts[0],
            command,
            now,
        )

    def get_revocation(
        self,
        approval_id: str,
    ) -> ApprovalRevocationRecord:
        approval_id = _text(approval_id, "approval_id", maximum=64)
        try:
            with self.store._read_connection() as connection:
                self.store._require_schema(connection)
                approval = self._approval_row(connection, approval_id)
                stored_mission, ledger = self._mission_and_ledger(
                    connection,
                    str(approval["mission_id"]),
                )
                self.store._verify_auxiliary_state(
                    connection,
                    stored_mission,
                    ledger,
                )
                row = connection.execute(
                    """
                    SELECT * FROM approval_revocations
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                ).fetchone()
                if row is None:
                    raise ApprovalError(
                        f"Approval has not been revoked: {approval_id}"
                    )
                return self._revocation_from_row(row)
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read approval revocation"
            ) from exc

    def get(self, approval_id: str) -> ApprovalRecord:
        approval_id = _text(approval_id, "approval_id", maximum=64)
        now = self._clock()
        try:
            with self.store._read_connection() as connection:
                row = self._approval_row(connection, approval_id)
                record = self._record_from_row(row, now)
                stored_mission, ledger = self._mission_and_ledger(
                    connection,
                    record.mission_id,
                )
                self.store._verify_auxiliary_state(
                    connection,
                    stored_mission,
                    ledger,
                )
                return record
        except sqlite3.Error as exc:
            raise StoreError("Could not read approval") from exc

    def list(
        self,
        mission_id: str,
        *,
        state: ApprovalState | None = None,
    ) -> tuple[ApprovalRecord, ...]:
        mission_id = _text(mission_id, "mission_id", maximum=64)
        if state is not None and not isinstance(state, ApprovalState):
            raise ApprovalError("state must be an ApprovalState")
        now = self._clock()
        try:
            with self.store._read_connection() as connection:
                stored_mission, ledger = self._mission_and_ledger(
                    connection,
                    mission_id,
                )
                self.store._verify_auxiliary_state(
                    connection,
                    stored_mission,
                    ledger,
                )
                rows = connection.execute(
                    """
                    SELECT * FROM approval_queue
                    WHERE mission_id = ?
                    ORDER BY submitted_at, approval_id
                    """,
                    (mission_id,),
                ).fetchall()
                records: list[ApprovalRecord] = []
                for row in rows:
                    records.append(self._record_from_row(row, now))
                if state is None:
                    return tuple(records)
                return tuple(
                    record
                    for record in records
                    if record.state is state
                )
        except sqlite3.Error as exc:
            raise StoreError("Could not list approvals") from exc

    def _mission_and_ledger(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[Any, Any]:
        mission_row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if mission_row is None:
            raise ApprovalError(f"Unknown stored mission: {mission_id}")
        stored_mission = self.store._stored_mission_from_row(
            connection,
            self.registry,
            mission_row,
        )
        ledger, _ = self.store._load_verified_ledger(
            connection,
            stored_mission,
        )
        return stored_mission, ledger

    def _approval_row(
        self,
        connection: sqlite3.Connection,
        approval_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM approval_queue WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise ApprovalError(f"Unknown approval: {approval_id}")
        return row

    def _validate_submission_binding(
        self,
        row: sqlite3.Row,
        record: ApprovalRecord,
        stored_mission: Any,
        ledger: Any,
    ) -> None:
        if record.approval_id != _approval_id(
            record.mission_id,
            record.proposal_id,
        ):
            raise ApprovalError("Stored approval ID is invalid")
        try:
            proposal = ledger.get(record.proposal_id)
        except Exception as exc:
            raise ApprovalError("Stored approval proposal does not exist") from exc
        if proposal.event_type is not EventType.PROPOSAL:
            raise ApprovalError("Stored approval does not reference a proposal")
        if proposal.actor_profile_id != record.proposer_profile_id:
            raise ApprovalError("Stored approval proposer binding is invalid")
        if compute_proposal_action_hash(proposal.payload) != record.proposal_hash:
            raise ApprovalError("Stored proposal hash no longer matches approval")
        if proposal.payload["action_tier"] != record.action_tier.value:
            raise ApprovalError("Stored approval action tier is invalid")
        if record.scope_reference != stored_mission.mission.scope_reference:
            raise ApprovalError("Stored approval scope binding is invalid")
        if record.purpose is not ApprovalPurpose.SIMULATION:
            raise ApprovalError("Stored approval purpose is invalid")
        if (
            record.executor_profile_id not in stored_mission.allowed_profile_ids
            or record.executor_profile_id in stored_mission.control_profile_ids
        ):
            raise ApprovalError("Stored approval executor binding is invalid")
        submit_request = {
            "mission_id": record.mission_id,
            "proposal_id": record.proposal_id,
            "executor_profile_id": record.executor_profile_id,
            "review_expires_at": record.review_expires_at,
            "principal_profile_id": record.proposer_profile_id,
            "purpose": record.purpose.value,
        }
        if row["submit_request_hash"] != sha256_text(
            canonical_json(submit_request)
        ):
            raise ApprovalError("Stored approval request hash is invalid")

    def _record_from_row(
        self,
        row: sqlite3.Row,
        now: datetime,
    ) -> ApprovalRecord:
        try:
            stored_state = ApprovalState(str(row["status"]))
            state = stored_state
            if stored_state is ApprovalState.PENDING:
                if parse_timestamp(
                    str(row["review_expires_at"]),
                    "review_expires_at",
                ) <= now:
                    state = ApprovalState.EXPIRED
            elif stored_state is ApprovalState.APPROVED:
                expires_at = row["authorization_expires_at"]
                if expires_at is None:
                    raise ApprovalError(
                        "Approved record is missing authorization expiry"
                    )
                if parse_timestamp(
                    str(expires_at),
                    "authorization_expires_at",
                ) <= now:
                    state = ApprovalState.EXPIRED
            return ApprovalRecord(
                schema_version=1,
                approval_id=str(row["approval_id"]),
                mission_id=str(row["mission_id"]),
                proposal_id=str(row["proposal_id"]),
                proposal_hash=str(row["proposal_hash"]),
                proposer_profile_id=str(row["proposer_profile_id"]),
                executor_profile_id=str(row["executor_profile_id"]),
                action_tier=ActionTier(str(row["action_tier"])),
                scope_reference=str(row["scope_reference"]),
                purpose=ApprovalPurpose(str(row["purpose"])),
                state=state,
                submitted_at=str(row["submitted_at"]),
                review_expires_at=str(row["review_expires_at"]),
                version=int(row["version"]),
                decision_actor_profile_id=row["decision_actor_profile_id"],
                decision_at=row["decision_at"],
                decision_code=row["decision_code"],
                decision_reason=row["decision_reason"],
                decision_event_id=row["decision_event_id"],
                authorization_event_id=row["authorization_event_id"],
                authorization_expires_at=row["authorization_expires_at"],
                simulation_id=row["simulation_id"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalError("Stored approval record is invalid") from exc

    def _revocation_from_row(
        self,
        row: sqlite3.Row,
    ) -> ApprovalRevocationRecord:
        try:
            record = ApprovalRevocationRecord(
                schema_version=1,
                approval_id=str(row["approval_id"]),
                mission_id=str(row["mission_id"]),
                authorization_event_id=str(
                    row["authorization_event_id"]
                ),
                revocation_event_id=str(row["revocation_event_id"]),
                actor_profile_id=str(row["actor_profile_id"]),
                revoked_at=str(row["revoked_at"]),
                reason_code=str(row["reason_code"]),
                reason=str(row["reason"]),
                risk=str(row["risk"]),
                decision_owner=str(row["decision_owner"]),
                expected_version=int(row["expected_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalError(
                "Stored approval revocation is invalid"
            ) from exc
        text_values = (
            record.approval_id,
            record.mission_id,
            record.authorization_event_id,
            record.revocation_event_id,
            record.actor_profile_id,
            record.revoked_at,
            record.reason_code,
            record.reason,
            record.risk,
            record.decision_owner,
        )
        if not all(is_ascii_text(value) for value in text_values):
            raise ApprovalError(
                "Stored approval revocation text is invalid"
            )
        if (
            APPROVAL_ID_PATTERN.fullmatch(record.approval_id) is None
            or record.expected_version != 2
        ):
            raise ApprovalError(
                "Stored approval revocation binding is invalid"
            )
        parse_timestamp(record.revoked_at, "revocation.revoked_at")
        return record

    def _require_authenticated_submission_path(
        self,
        connection: sqlite3.Connection,
        *,
        authenticated_principal: bool,
    ) -> None:
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if (
            schema_version
            < APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION
        ):
            return
        identity = connection.execute(
            """
            SELECT trust_policy_hash FROM store_identity
            WHERE singleton_id = 1
            """
        ).fetchone()
        if identity is None:
            raise ApprovalError("Mission store identity is missing")
        if (
            identity["trust_policy_hash"] is not None
            and not authenticated_principal
        ):
            raise ApprovalError(
                "Authenticated approval submissions are required after "
                "trust policy enrollment"
            )

    def _require_authenticated_decision_path(
        self,
        connection: sqlite3.Connection,
        *,
        authenticated_principal: bool,
    ) -> None:
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if (
            schema_version
            < APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION
        ):
            return
        identity = connection.execute(
            """
            SELECT trust_policy_hash FROM store_identity
            WHERE singleton_id = 1
            """
        ).fetchone()
        if identity is None:
            raise ApprovalError("Mission store identity is missing")
        if (
            identity["trust_policy_hash"] is not None
            and not authenticated_principal
        ):
            raise ApprovalError(
                "Authenticated approval decisions are required after "
                "trust policy enrollment"
            )

    def _require_authenticated_revocation_path(
        self,
        connection: sqlite3.Connection,
        *,
        authenticated_principal: bool,
    ) -> None:
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if (
            schema_version
            < APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION
        ):
            return
        identity = connection.execute(
            """
            SELECT trust_policy_hash FROM store_identity
            WHERE singleton_id = 1
            """
        ).fetchone()
        if identity is None:
            raise ApprovalError("Mission store identity is missing")
        if (
            identity["trust_policy_hash"] is not None
            and not authenticated_principal
        ):
            raise ApprovalError(
                "Authenticated approval revocations are required after "
                "trust policy enrollment"
            )

    def _applied_submission(
        self,
        connection: sqlite3.Connection,
        record: ApprovalRecord,
        proposal: MissionEvent,
        mission: Any,
        command: _ApprovalSubmissionCommand,
    ) -> _AppliedApprovalSubmission:
        event_row = connection.execute(
            """
            SELECT * FROM mission_events
            WHERE mission_id = ? AND event_id = ?
            """,
            (command.mission_id, command.proposal_id),
        ).fetchone()
        if event_row is None:
            raise ApprovalError(
                "Stored approval proposal event is missing"
            )
        if (
            str(event_row["event_json"])
            != canonical_json(proposal.to_dict())
        ):
            raise ApprovalError(
                "Stored approval proposal event is inconsistent"
            )
        if (
            record.approval_id
            != _approval_id(
                command.mission_id,
                command.proposal_id,
            )
            or record.mission_id != command.mission_id
            or record.proposal_id != command.proposal_id
            or record.executor_profile_id
            != command.executor_profile_id
            or record.proposer_profile_id
            != command.principal_profile_id
            or record.review_expires_at
            != command.review_expires_at
        ):
            raise ApprovalError(
                "Stored approval submission is inconsistent"
            )
        return _AppliedApprovalSubmission(
            record=record,
            proposal=proposal,
            request_hash=command.request_hash,
            idempotency_key_hash=command.idempotency_key_hash,
            proposal_sequence=int(event_row["sequence"]),
            proposal_entry_hash=str(event_row["entry_hash"]),
            proposal_stored_at=str(event_row["stored_at"]),
            mission_revision=mission.revision,
            mission_head_hash=mission.head_hash,
        )

    def _applied_new_decision(
        self,
        connection: sqlite3.Connection,
        previous_record: ApprovalRecord,
        previous_mission: Any,
        event: MissionEvent,
        append_receipt: AppendReceipt,
        command: _ApprovalDecisionCommand,
        now: datetime,
    ) -> _AppliedApprovalDecision:
        updated_row = self._approval_row(
            connection,
            command.approval_id,
        )
        updated_record = self._record_from_row(updated_row, now)
        updated_mission, updated_ledger = self._mission_and_ledger(
            connection,
            updated_record.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            updated_mission,
            updated_ledger,
        )
        event_row = self._decision_event_row(
            connection,
            updated_record.mission_id,
            event.event_id,
        )
        if (
            str(event_row["event_json"])
            != canonical_json(event.to_dict())
            or int(event_row["sequence"]) != append_receipt.sequence
            or str(event_row["entry_hash"])
            != append_receipt.entry_hash
        ):
            raise ApprovalError(
                "Stored approval decision event is inconsistent"
            )
        return _AppliedApprovalDecision(
            record=updated_record,
            event=event,
            append_receipt=append_receipt,
            request_hash=command.request_hash,
            idempotency_key_hash=command.idempotency_key_hash,
            expected_approval_version=command.expected_version,
            pre_approval_version=previous_record.version,
            pre_approval_state=previous_record.state,
            final_approval_version=updated_record.version,
            final_approval_state=updated_record.state,
            pre_mission_revision=previous_mission.revision,
            pre_mission_head_hash=previous_mission.head_hash,
            final_mission_revision=updated_mission.revision,
            final_mission_head_hash=updated_mission.head_hash,
            event_sequence=int(event_row["sequence"]),
            event_previous_hash=str(event_row["previous_hash"]),
            event_entry_hash=str(event_row["entry_hash"]),
            event_stored_at=str(event_row["stored_at"]),
        )

    def _applied_new_revocation(
        self,
        connection: sqlite3.Connection,
        previous_record: ApprovalRecord,
        previous_mission: Any,
        event: MissionEvent,
        append_receipt: AppendReceipt,
        command: _ApprovalDecisionCommand,
        now: datetime,
    ) -> _AppliedApprovalRevocation:
        updated_row = self._approval_row(
            connection,
            command.approval_id,
        )
        updated_record = self._record_from_row(updated_row, now)
        updated_mission, updated_ledger = self._mission_and_ledger(
            connection,
            updated_record.mission_id,
        )
        self.store._verify_auxiliary_state(
            connection,
            updated_mission,
            updated_ledger,
        )
        event_row = self._decision_event_row(
            connection,
            updated_record.mission_id,
            event.event_id,
        )
        revocation_row = connection.execute(
            """
            SELECT * FROM approval_revocations
            WHERE approval_id = ?
            """,
            (command.approval_id,),
        ).fetchone()
        if revocation_row is None:
            raise ApprovalError(
                "Stored approval revocation is missing"
            )
        revocation = self._revocation_from_row(revocation_row)
        if (
            str(event_row["event_json"])
            != canonical_json(event.to_dict())
            or int(event_row["sequence"]) != append_receipt.sequence
            or str(event_row["entry_hash"])
            != append_receipt.entry_hash
            or revocation.revocation_event_id != event.event_id
            or revocation.approval_id != command.approval_id
            or revocation.actor_profile_id
            != command.principal_profile_id
            or revocation.revoked_at != event.timestamp
            or revocation.expected_version
            != command.expected_version
            or updated_record.state is not ApprovalState.REVOKED
            or updated_record.version != 3
            or updated_record.simulation_id is not None
        ):
            raise ApprovalError(
                "Stored approval revocation is inconsistent"
            )
        return _AppliedApprovalRevocation(
            record=updated_record,
            revocation=revocation,
            event=event,
            append_receipt=append_receipt,
            request_hash=command.request_hash,
            idempotency_key_hash=command.idempotency_key_hash,
            expected_approval_version=command.expected_version,
            pre_approval_version=previous_record.version,
            pre_approval_state=previous_record.state,
            final_approval_version=updated_record.version,
            final_approval_state=updated_record.state,
            pre_mission_revision=previous_mission.revision,
            pre_mission_head_hash=previous_mission.head_hash,
            final_mission_revision=updated_mission.revision,
            final_mission_head_hash=updated_mission.head_hash,
            event_sequence=int(event_row["sequence"]),
            event_previous_hash=str(event_row["previous_hash"]),
            event_entry_hash=str(event_row["entry_hash"]),
            event_stored_at=str(event_row["stored_at"]),
        )

    def _applied_existing_decision(
        self,
        connection: sqlite3.Connection,
        record: ApprovalRecord,
        command: _ApprovalDecisionCommand,
    ) -> _AppliedApprovalDecision:
        if record.decision_event_id is None:
            raise ApprovalError(
                "Stored approval decision has no event"
            )
        event_row = self._decision_event_row(
            connection,
            record.mission_id,
            record.decision_event_id,
        )
        try:
            event = MissionEvent.from_dict(
                json.loads(str(event_row["event_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ApprovalError(
                "Stored approval decision event is invalid"
            ) from exc
        mission, _ = self._mission_and_ledger(
            connection,
            record.mission_id,
        )
        event_sequence = int(event_row["sequence"])
        append_receipt = AppendReceipt(
            mission_id=record.mission_id,
            event_id=record.decision_event_id,
            sequence=event_sequence,
            revision=event_sequence,
            entry_hash=str(event_row["entry_hash"]),
            idempotent=True,
        )
        return _AppliedApprovalDecision(
            record=record,
            event=event,
            append_receipt=append_receipt,
            request_hash=command.request_hash,
            idempotency_key_hash=command.idempotency_key_hash,
            expected_approval_version=command.expected_version,
            pre_approval_version=command.expected_version,
            pre_approval_state=ApprovalState.PENDING,
            final_approval_version=record.version,
            final_approval_state=record.state,
            pre_mission_revision=max(event_sequence - 1, 0),
            pre_mission_head_hash=str(
                event_row["previous_hash"]
            ),
            final_mission_revision=mission.revision,
            final_mission_head_hash=mission.head_hash,
            event_sequence=event_sequence,
            event_previous_hash=str(event_row["previous_hash"]),
            event_entry_hash=str(event_row["entry_hash"]),
            event_stored_at=str(event_row["stored_at"]),
        )

    def _applied_existing_revocation(
        self,
        connection: sqlite3.Connection,
        record: ApprovalRecord,
        revocation_row: sqlite3.Row,
        command: _ApprovalDecisionCommand,
    ) -> _AppliedApprovalRevocation:
        revocation = self._revocation_from_row(revocation_row)
        event_row = self._decision_event_row(
            connection,
            record.mission_id,
            revocation.revocation_event_id,
        )
        try:
            event = MissionEvent.from_dict(
                json.loads(str(event_row["event_json"]))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ApprovalError(
                "Stored approval revocation event is invalid"
            ) from exc
        event_sequence = int(event_row["sequence"])
        append_receipt = AppendReceipt(
            mission_id=record.mission_id,
            event_id=revocation.revocation_event_id,
            sequence=event_sequence,
            revision=event_sequence,
            entry_hash=str(event_row["entry_hash"]),
            idempotent=True,
        )
        return _AppliedApprovalRevocation(
            record=record,
            revocation=revocation,
            event=event,
            append_receipt=append_receipt,
            request_hash=command.request_hash,
            idempotency_key_hash=command.idempotency_key_hash,
            expected_approval_version=command.expected_version,
            pre_approval_version=command.expected_version,
            pre_approval_state=ApprovalState.APPROVED,
            final_approval_version=record.version,
            final_approval_state=record.state,
            pre_mission_revision=max(event_sequence - 1, 0),
            pre_mission_head_hash=str(event_row["previous_hash"]),
            final_mission_revision=event_sequence,
            final_mission_head_hash=str(event_row["entry_hash"]),
            event_sequence=event_sequence,
            event_previous_hash=str(event_row["previous_hash"]),
            event_entry_hash=str(event_row["entry_hash"]),
            event_stored_at=str(event_row["stored_at"]),
        )

    def _decision_event_row(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
        event_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM mission_events
            WHERE mission_id = ? AND event_id = ?
            """,
            (mission_id, event_id),
        ).fetchone()
        if row is None:
            raise ApprovalError(
                "Stored approval decision event is missing"
            )
        return row

    def _require_pending(
        self,
        record: ApprovalRecord,
        expected_version: int,
    ) -> None:
        if record.version != expected_version:
            raise ApprovalConflictError(
                f"Expected approval version {expected_version} does not match "
                f"stored version {record.version}"
            )
        if record.state is ApprovalState.EXPIRED:
            raise ApprovalExpiredError("Approval review window has expired")
        if record.state is ApprovalState.DENIED:
            raise ApprovalDeniedError("Approval has already been denied")
        if record.state is not ApprovalState.PENDING:
            raise ApprovalConflictError(
                f"Approval is not pending: {record.state.value}"
            )
