"""Authenticated owner-only work item leases for SUNDERKEY."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from .collaboration import (
    WORK_ITEM_ID_PATTERN,
    CollaborationPlan,
    WorkItem,
)
from .errors import (
    CollaborationPlanError,
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .events import MISSION_ID_PATTERN
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    COLLABORATION_OWNERSHIP_SCHEMA_VERSION,
    WORK_ITEM_ABSOLUTE_MAX_GENERATION,
    WORK_ITEM_HANDOFF_SCHEMA_VERSION,
    WORK_ITEM_LEASE_SECONDS,
    WORK_ITEM_MAX_CLAIM_ATTEMPTS,
    WORK_ITEM_MAX_RECOVERY_EPOCHS,
    WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS,
    MissionStore,
    StoredMission,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
    work_item_transition_id,
)


class WorkItemTransitionKind(StrEnum):
    """One authenticated owner lease transition."""

    CLAIM = "claim"
    RENEW = "renew"
    RELEASE = "release"
    COMPLETE = "complete"


class WorkItemRuntimeState(StrEnum):
    """Effective work item state derived from immutable transitions."""

    BLOCKED = "blocked"
    READY = "ready"
    LEASED = "leased"
    NEEDS_REVIEW = "needs_review"
    RECOVERY_PENDING = "recovery_pending"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CANCELLED_DEPENDENCY = "cancelled_dependency"
    STOPPED = "stopped"


_OPERATION_BY_KIND = {
    WorkItemTransitionKind.CLAIM: PrincipalOperation.WORK_CLAIM,
    WorkItemTransitionKind.RENEW: PrincipalOperation.WORK_RENEW,
    WorkItemTransitionKind.RELEASE: PrincipalOperation.WORK_RELEASE,
    WorkItemTransitionKind.COMPLETE: PrincipalOperation.WORK_COMPLETE,
}


@dataclass(frozen=True)
class AuthenticatedWorkItemTransitionReceipt:
    """Immutable lease transition and authentication provenance."""

    mission_id: str
    plan_id: str
    plan_content_sha256: str
    work_item_id: str
    owner_profile_id: str
    generation: int
    transition_id: str
    transition_kind: WorkItemTransitionKind
    previous_transition_id: str | None
    previous_lease_expires_at: str | None
    lease_started_at: str
    lease_expires_at: str
    result_id: str | None
    result_sha256: str | None
    evidence_manifest_sha256: str | None
    release_reason_code: str | None
    release_reason: str | None
    recorded_at: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    subject: str
    key_id: str
    key_sha256: str
    scope_grant_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    operation_intent_sha256: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "work_item_id": self.work_item_id,
            "owner_profile_id": self.owner_profile_id,
            "generation": self.generation,
            "transition_id": self.transition_id,
            "transition_kind": self.transition_kind.value,
            "previous_transition_id": self.previous_transition_id,
            "previous_lease_expires_at": (
                self.previous_lease_expires_at
            ),
            "lease_started_at": self.lease_started_at,
            "lease_expires_at": self.lease_expires_at,
            "result_id": self.result_id,
            "result_sha256": self.result_sha256,
            "evidence_manifest_sha256": (
                self.evidence_manifest_sha256
            ),
            "release_reason_code": self.release_reason_code,
            "release_reason": self.release_reason,
            "recorded_at": self.recorded_at,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "subject": self.subject,
            "key_id": self.key_id,
            "key_sha256": self.key_sha256,
            "scope_grant_sha256": self.scope_grant_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "operation": _OPERATION_BY_KIND[
                self.transition_kind
            ].value,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


@dataclass(frozen=True)
class WorkItemRuntimeStatus:
    """Effective status for one activated collaboration work item."""

    work_item_id: str
    owner_profile_id: str
    planned_owner_profile_id: str
    handoff_id: str | None
    handoff_transferred_at: str | None
    dependency_ids: tuple[str, ...]
    state: WorkItemRuntimeState
    generation: int
    attempts_remaining: int
    current_transition_id: str | None
    current_transition_kind: WorkItemTransitionKind | None
    lease_started_at: str | None
    lease_expires_at: str | None
    result_id: str | None
    result_sha256: str | None
    evidence_manifest_sha256: str | None
    recovery_request_id: str | None
    recovery_decision_id: str | None
    recovery_decision: str | None
    recovery_epoch: int | None
    cancellation_ids: tuple[str, ...]
    cancellation_source_work_item_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_item_id": self.work_item_id,
            "owner_profile_id": self.owner_profile_id,
            "planned_owner_profile_id": (
                self.planned_owner_profile_id
            ),
            "handoff_id": self.handoff_id,
            "handoff_transferred_at": self.handoff_transferred_at,
            "dependency_ids": list(self.dependency_ids),
            "state": self.state.value,
            "generation": self.generation,
            "attempts_remaining": self.attempts_remaining,
            "current_transition_id": self.current_transition_id,
            "current_transition_kind": (
                None
                if self.current_transition_kind is None
                else self.current_transition_kind.value
            ),
            "lease_started_at": self.lease_started_at,
            "lease_expires_at": self.lease_expires_at,
            "result_id": self.result_id,
            "result_sha256": self.result_sha256,
            "evidence_manifest_sha256": (
                self.evidence_manifest_sha256
            ),
            "recovery_request_id": self.recovery_request_id,
            "recovery_decision_id": self.recovery_decision_id,
            "recovery_decision": self.recovery_decision,
            "recovery_epoch": self.recovery_epoch,
            "cancellation_ids": list(self.cancellation_ids),
            "cancellation_source_work_item_ids": list(
                self.cancellation_source_work_item_ids
            ),
        }


@dataclass(frozen=True)
class AuthenticatedWorkItemStatusReceipt:
    """Verified effective status for an activated plan."""

    mission_id: str
    plan_id: str
    plan_content_sha256: str
    evaluated_at: str
    lease_duration_seconds: int
    maximum_claim_attempts: int
    recovery_claim_attempts: int
    maximum_recovery_epochs: int
    absolute_maximum_generation: int
    work_items: tuple[WorkItemRuntimeStatus, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 4,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "evaluated_at": self.evaluated_at,
            "lease_duration_seconds": self.lease_duration_seconds,
            "maximum_claim_attempts": self.maximum_claim_attempts,
            "recovery_claim_attempts": self.recovery_claim_attempts,
            "maximum_recovery_epochs": self.maximum_recovery_epochs,
            "absolute_maximum_generation": (
                self.absolute_maximum_generation
            ),
            "work_items": [
                item.to_dict() for item in self.work_items
            ],
        }


class AuthenticatedWorkItemLeaseService:
    """Persist owner-only, fenced work item lease transitions."""

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
        self._activation = (
            AuthenticatedCollaborationActivationService(
                store,
                registry,
                clock=self._clock,
            )
        )

    def claim(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        expected_generation: int,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        """Acquire the next owner-only lease generation."""

        return self._transition(
            WorkItemTransitionKind.CLAIM,
            assertion,
            mission_id,
            work_item_id,
            expected_generation=expected_generation,
        )

    def renew(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        claim_generation: int,
        previous_transition_id: str,
        expected_lease_expires_at: str,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        """Renew one active owner lease."""

        return self._transition(
            WorkItemTransitionKind.RENEW,
            assertion,
            mission_id,
            work_item_id,
            claim_generation=claim_generation,
            previous_transition_id=previous_transition_id,
            expected_lease_expires_at=(
                expected_lease_expires_at
            ),
        )

    def release(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        claim_generation: int,
        previous_transition_id: str,
        expected_lease_expires_at: str,
        reason_code: str,
        reason: str,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        """Release one active owner lease with a signed reason."""

        return self._transition(
            WorkItemTransitionKind.RELEASE,
            assertion,
            mission_id,
            work_item_id,
            claim_generation=claim_generation,
            previous_transition_id=previous_transition_id,
            expected_lease_expires_at=(
                expected_lease_expires_at
            ),
            reason_code=reason_code,
            reason=reason,
        )

    def complete(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        claim_generation: int,
        previous_transition_id: str,
        expected_lease_expires_at: str,
        result_id: str,
        result_sha256: str,
        evidence_manifest_sha256: str,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        """Complete one active lease with result and evidence hashes."""

        return self._transition(
            WorkItemTransitionKind.COMPLETE,
            assertion,
            mission_id,
            work_item_id,
            claim_generation=claim_generation,
            previous_transition_id=previous_transition_id,
            expected_lease_expires_at=(
                expected_lease_expires_at
            ),
            result_id=result_id,
            result_sha256=result_sha256,
            evidence_manifest_sha256=(
                evidence_manifest_sha256
            ),
        )

    def status(
        self,
        mission_id: str,
        *,
        work_item_id: str | None = None,
    ) -> AuthenticatedWorkItemStatusReceipt:
        """Return verified effective state without consuming authority."""

        self._validate_target(
            mission_id,
            work_item_id,
            allow_all=True,
        )
        try:
            with self._store._read_connection() as connection:
                (
                    _,
                    _,
                    mission,
                    _,
                    principal_ledger,
                ) = self._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                _, plan = self._load_activation(
                    connection,
                    mission_id,
                )
                now = self._clock()
                evaluated_at = format_timestamp(now)
                evaluated_time = parse_timestamp(
                    evaluated_at,
                    "work item status evaluated_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    principal_ledger,
                    evaluated_time,
                )
                control = connection.execute(
                    """
                    SELECT state
                    FROM mission_controls
                    WHERE mission_id = ?
                    """,
                    (mission_id,),
                ).fetchone()
                if control is None:
                    raise StoreIntegrityError(
                        "Mission control state is missing"
                    )
                latest = self._latest_transitions(
                    connection,
                    plan.plan_id,
                )
                cancellations = self._cancellations_for_plan(
                    connection,
                    plan.plan_id,
                )
                handoffs = self._handoffs_for_plan(
                    connection,
                    plan.plan_id,
                )
                ownerships = self._ownerships_for_plan(
                    connection,
                    plan.plan_id,
                )
                carried_completed = self._carried_completed_for_plan(
                    connection,
                    plan.plan_id,
                )
                completed = {
                    identifier
                    for identifier, row in latest.items()
                    if row["transition_kind"] == "complete"
                } | set(carried_completed)
                selected = tuple(
                    item
                    for item in plan.work_items
                    if (
                        work_item_id is None
                        or item.work_item_id == work_item_id
                    )
                )
                if not selected:
                    raise StoreError(
                        f"Unknown collaboration work item: "
                        f"{work_item_id}"
                    )
                statuses = tuple(
                    self._status_for_item(
                        item,
                        latest.get(item.work_item_id),
                        self._recovery_for_item(
                            connection,
                            plan.plan_id,
                            item.work_item_id,
                        ),
                        cancellations.get(item.work_item_id, ()),
                        handoffs.get(item.work_item_id),
                        ownerships.get(item.work_item_id),
                        completed,
                        evaluated_time,
                        carried_result_sha256=carried_completed.get(
                            item.work_item_id
                        ),
                        mission_active=(
                            control["state"] == "active"
                        ),
                    )
                    for item in selected
                )
                return AuthenticatedWorkItemStatusReceipt(
                    mission_id=mission_id,
                    plan_id=plan.plan_id,
                    plan_content_sha256=plan.content_sha256,
                    evaluated_at=evaluated_at,
                    lease_duration_seconds=(
                        WORK_ITEM_LEASE_SECONDS
                    ),
                    maximum_claim_attempts=(
                        WORK_ITEM_MAX_CLAIM_ATTEMPTS
                    ),
                    recovery_claim_attempts=(
                        WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS
                    ),
                    maximum_recovery_epochs=(
                        WORK_ITEM_MAX_RECOVERY_EPOCHS
                    ),
                    absolute_maximum_generation=(
                        WORK_ITEM_ABSOLUTE_MAX_GENERATION
                    ),
                    work_items=statuses,
                )
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read authenticated work item status"
            ) from exc

    def _transition(
        self,
        kind: WorkItemTransitionKind,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        expected_generation: int | None = None,
        claim_generation: int | None = None,
        previous_transition_id: str | None = None,
        expected_lease_expires_at: str | None = None,
        reason_code: str | None = None,
        reason: str | None = None,
        result_id: str | None = None,
        result_sha256: str | None = None,
        evidence_manifest_sha256: str | None = None,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        self._validate_target(mission_id, work_item_id)
        assertion = PrincipalAssertion.from_dict(
            assertion.to_dict()
        )
        operation = _OPERATION_BY_KIND[kind]
        transition_id = work_item_transition_id(
            assertion.issuer,
            assertion.assertion_id,
        )
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)

        try:
            with self._store._write_connection() as connection:
                (
                    identity,
                    trust_policies,
                    mission,
                    scope_grants,
                    principal_ledger,
                ) = self._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                _, plan = self._load_activation(
                    connection,
                    mission_id,
                )
                item = self._work_item(plan, work_item_id)
                existing_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                ).fetchone()
                handoff = self._handoff_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                ownership = self._ownership_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                owner_profile_id = (
                    str(existing_use["principal_profile_id"])
                    if existing_use is not None
                    else self._effective_owner_profile_id(
                        item,
                        handoff,
                        ownership,
                    )
                )
                operation_intent = self._operation_intent(
                    kind,
                    plan,
                    item,
                    owner_profile_id=owner_profile_id,
                    expected_generation=expected_generation,
                    claim_generation=claim_generation,
                    previous_transition_id=(
                        previous_transition_id
                    ),
                    expected_lease_expires_at=(
                        expected_lease_expires_at
                    ),
                    reason_code=reason_code,
                    reason=reason,
                    result_id=result_id,
                    result_sha256=result_sha256,
                    evidence_manifest_sha256=(
                        evidence_manifest_sha256
                    ),
                )
                operation_intent_json = canonical_json(
                    operation_intent
                )
                signed_intent_hash = (
                    compute_operation_intent_hash(
                        operation,
                        operation_intent,
                    )
                )
                domain_request_hash = sha256_text(
                    operation_intent_json
                )
                if existing_use is not None:
                    self._require_exact_replay(
                        existing_use,
                        mission_id=mission_id,
                        principal_profile_id=owner_profile_id,
                        operation=operation,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=(
                            assertion.policy_version
                        ),
                        assertion_json=assertion_json,
                        assertion_hash=assertion_hash,
                        operation_intent_json=(
                            operation_intent_json
                        ),
                        signed_intent_hash=signed_intent_hash,
                        domain_request_hash=domain_request_hash,
                        scope_grant_hash=(
                            assertion.scope_grant_sha256
                        ),
                    )
                    row = self._transition_for_assertion(
                        connection,
                        assertion,
                    )
                    if (
                        row["transition_id"] != transition_id
                        or row["mission_id"] != mission_id
                        or row["plan_id"] != plan.plan_id
                        or row["work_item_id"] != work_item_id
                        or row["transition_kind"] != kind.value
                    ):
                        raise StoreConflictError(
                            "Work item transition replay has "
                            "different content"
                        )
                    return self._receipt_from_rows(
                        connection,
                        existing_use,
                        row,
                    )

                if assertion.profile_id != owner_profile_id:
                    raise PrincipalAuthenticationError(
                        "Work item claim and lease transitions require "
                        "the planned owner or effective handoff owner"
                    )
                control = connection.execute(
                    """
                    SELECT state
                    FROM mission_controls
                    WHERE mission_id = ?
                    """,
                    (mission_id,),
                ).fetchone()
                if control is None:
                    raise StoreIntegrityError(
                        "Mission control state is missing"
                    )
                if control["state"] != "active":
                    raise MissionStoppedError(
                        "Stopped mission cannot mutate work item "
                        "leases"
                    )
                now = self._clock()
                consumed_at = format_timestamp(now)
                consumed_time = parse_timestamp(
                    consumed_at,
                    "work item transition consumed_at",
                )
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    principal_ledger,
                    consumed_time,
                )
                latest = self._latest_transition(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                recovery = self._recovery_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                cancellation_ids = self._cancellation_ids_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                if cancellation_ids:
                    raise StoreConflictError(
                        "Cancelled work item cannot mutate its lease"
                    )
                carried_completed = self._carried_completed_for_plan(
                    connection,
                    plan.plan_id,
                )
                if work_item_id in carried_completed:
                    raise StoreConflictError(
                        "Completed carried-forward work item cannot mutate its lease"
                    )
                completed = {
                    str(row["work_item_id"])
                    for row in connection.execute(
                        """
                        SELECT work_item_id
                        FROM collaboration_work_item_transitions
                        WHERE plan_id = ?
                          AND transition_kind = 'complete'
                        UNION ALL
                        SELECT work_item_id
                        FROM collaboration_work_item_recovery_transitions
                        WHERE plan_id = ?
                          AND transition_kind = 'complete'
                        """,
                        (plan.plan_id, plan.plan_id),
                    ).fetchall()
                } | set(carried_completed)
                transition = self._derive_transition(
                    kind,
                    item,
                    latest,
                    recovery,
                    completed,
                    consumed_time,
                    expected_generation=expected_generation,
                    claim_generation=claim_generation,
                    previous_transition_id=(
                        previous_transition_id
                    ),
                    expected_lease_expires_at=(
                        expected_lease_expires_at
                    ),
                )
                principal = self._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    signed_intent_hash=signed_intent_hash,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=consumed_time,
                )
                effect = self._transition_effect(
                    transition_id=transition_id,
                    operation=operation,
                    kind=kind,
                    mission=mission,
                    plan=plan,
                    item=item,
                    owner_profile_id=owner_profile_id,
                    transition=transition,
                    store_id=str(identity["store_id"]),
                    result_id=result_id,
                    result_sha256=result_sha256,
                    evidence_manifest_sha256=(
                        evidence_manifest_sha256
                    ),
                    reason_code=reason_code,
                    reason=reason,
                    recorded_at=consumed_at,
                )
                effect_json = canonical_json(effect)
                effect_hash = sha256_text(effect_json)
                effects_hash = principal_assertion_effects_hash(
                    (effect_hash,)
                )
                use_sequence = (
                    int(principal_ledger["assertion_count"]) + 1
                )
                previous_hash = str(
                    principal_ledger["head_hash"]
                )
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
                    ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                        mission_id,
                        operation.value,
                        transition_id,
                        effect_json,
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
                        effect_count = effect_count + 1,
                        updated_at = ?
                    WHERE mission_id = ?
                      AND assertion_count = ?
                      AND effect_count = ?
                      AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        consumed_at,
                        mission_id,
                        use_sequence - 1,
                        int(principal_ledger["effect_count"]),
                        previous_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError(
                        "Mission principal ledger changed during "
                        "work item transition"
                    )
                transition_values = (
                    transition_id,
                    mission_id,
                    plan.plan_id,
                    plan.content_sha256,
                    work_item_id,
                    transition["generation"],
                    kind.value,
                    owner_profile_id,
                    transition["previous_transition_id"],
                    transition["previous_lease_expires_at"],
                    transition["lease_started_at"],
                    transition["lease_expires_at"],
                    result_id,
                    result_sha256,
                    evidence_manifest_sha256,
                    reason_code,
                    reason,
                    consumed_at,
                    assertion.issuer,
                    assertion.assertion_id,
                )
                if int(transition["generation"]) <= 3:
                    connection.execute(
                        """
                        INSERT INTO collaboration_work_item_transitions(
                            transition_id,
                            mission_id,
                            plan_id,
                            plan_content_sha256,
                            work_item_id,
                            generation,
                            transition_kind,
                            owner_profile_id,
                            previous_transition_id,
                            previous_lease_expires_at,
                            lease_started_at,
                            lease_expires_at,
                            result_id,
                            result_sha256,
                            evidence_manifest_sha256,
                            release_reason_code,
                            release_reason,
                            recorded_at,
                            issuer,
                            assertion_id
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        transition_values,
                    )
                else:
                    if (
                        recovery is None
                        or recovery["decision"] != "approve"
                        or recovery["recovery_decision_id"] is None
                    ):
                        raise StoreConflictError(
                            "Approved work recovery is required"
                        )
                    connection.execute(
                        """
                        INSERT INTO
                            collaboration_work_item_recovery_transitions(
                                transition_id,
                                recovery_decision_id,
                                recovery_epoch,
                                epoch_attempt,
                                mission_id,
                                plan_id,
                                plan_content_sha256,
                                work_item_id,
                                generation,
                                transition_kind,
                                owner_profile_id,
                                previous_transition_id,
                                previous_lease_expires_at,
                                lease_started_at,
                                lease_expires_at,
                                result_id,
                                result_sha256,
                                evidence_manifest_sha256,
                                release_reason_code,
                                release_reason,
                                recorded_at,
                                issuer,
                                assertion_id
                            ) VALUES (
                                ?1, ?2, 1, ?3, ?4, ?5, ?6, ?7,
                                ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                                ?15, ?16, ?17, ?18, ?19, ?20,
                                ?21, ?22
                            )
                        """,
                        (
                            transition_id,
                            str(recovery["recovery_decision_id"]),
                            int(transition["generation"]) - 3,
                            mission_id,
                            plan.plan_id,
                            plan.content_sha256,
                            work_item_id,
                            transition["generation"],
                            kind.value,
                            owner_profile_id,
                            transition["previous_transition_id"],
                            transition[
                                "previous_lease_expires_at"
                            ],
                            transition["lease_started_at"],
                            transition["lease_expires_at"],
                            result_id,
                            result_sha256,
                            evidence_manifest_sha256,
                            reason_code,
                            reason,
                            consumed_at,
                            assertion.issuer,
                            assertion.assertion_id,
                        ),
                    )
                self._store._verify_phase4_mission_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    registry=self._registry,
                )
                stored_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                ).fetchone()
                row = self._transition_for_assertion(
                    connection,
                    assertion,
                )
                if stored_use is None:
                    raise StoreIntegrityError(
                        "Work item transition durable state is "
                        "incomplete"
                    )
                return self._receipt_from_rows(
                    connection,
                    stored_use,
                    row,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated work item transition conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated work item "
                "transition"
            ) from exc

    @staticmethod
    def _validate_target(
        mission_id: str,
        work_item_id: str | None,
        *,
        allow_all: bool = False,
    ) -> None:
        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is not a valid mission ID")
        if work_item_id is None and allow_all:
            return
        if (
            not isinstance(work_item_id, str)
            or WORK_ITEM_ID_PATTERN.fullmatch(work_item_id) is None
        ):
            raise StoreError(
                "work_item_id is not a valid collaboration work "
                "item ID"
            )

    @staticmethod
    def _load_activation(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[sqlite3.Row, CollaborationPlan]:
        activation = connection.execute(
            """
            SELECT activation.*
            FROM collaboration_plan_active_heads AS head
            JOIN collaboration_plan_activations AS activation
              ON activation.plan_id = head.active_plan_id
            WHERE head.mission_id = ?
            """,
            (mission_id,),
        ).fetchone()
        if activation is None:
            raise StoreConflictError(
                "Mission has no activated collaboration plan"
            )
        try:
            plan = CollaborationPlan.from_dict(
                json.loads(str(activation["plan_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
        ) as exc:
            raise StoreIntegrityError(
                "Activated collaboration plan is invalid"
            ) from exc
        return activation, plan

    @staticmethod
    def _work_item(
        plan: CollaborationPlan,
        work_item_id: str,
    ) -> WorkItem:
        for item in plan.work_items:
            if item.work_item_id == work_item_id:
                return item
        raise StoreError(
            f"Unknown collaboration work item: {work_item_id}"
        )

    @staticmethod
    def _latest_transition(
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            WITH transitions AS (
                SELECT *
                FROM collaboration_work_item_transitions
                UNION ALL
                SELECT
                    transition_id,
                    mission_id,
                    plan_id,
                    plan_content_sha256,
                    work_item_id,
                    generation,
                    transition_kind,
                    owner_profile_id,
                    previous_transition_id,
                    previous_lease_expires_at,
                    lease_started_at,
                    lease_expires_at,
                    result_id,
                    result_sha256,
                    evidence_manifest_sha256,
                    release_reason_code,
                    release_reason,
                    recorded_at,
                    issuer,
                    assertion_id
                FROM collaboration_work_item_recovery_transitions
            )
            SELECT transition.*
            FROM transitions AS transition
            JOIN principal_assertion_uses AS principal_use
              ON principal_use.issuer = transition.issuer
             AND principal_use.assertion_id
                 = transition.assertion_id
            WHERE transition.plan_id = ?
              AND transition.work_item_id = ?
            ORDER BY principal_use.use_sequence DESC
            LIMIT 1
            """,
            (plan_id, work_item_id),
        ).fetchone()

    @staticmethod
    def _latest_transitions(
        connection: sqlite3.Connection,
        plan_id: str,
    ) -> dict[str, sqlite3.Row]:
        rows = connection.execute(
            """
            WITH transitions AS (
                SELECT *
                FROM collaboration_work_item_transitions
                UNION ALL
                SELECT
                    transition_id,
                    mission_id,
                    plan_id,
                    plan_content_sha256,
                    work_item_id,
                    generation,
                    transition_kind,
                    owner_profile_id,
                    previous_transition_id,
                    previous_lease_expires_at,
                    lease_started_at,
                    lease_expires_at,
                    result_id,
                    result_sha256,
                    evidence_manifest_sha256,
                    release_reason_code,
                    release_reason,
                    recorded_at,
                    issuer,
                    assertion_id
                FROM collaboration_work_item_recovery_transitions
            )
            SELECT transition.*
            FROM transitions AS transition
            JOIN principal_assertion_uses AS principal_use
              ON principal_use.issuer = transition.issuer
             AND principal_use.assertion_id
                 = transition.assertion_id
            WHERE transition.plan_id = ?
            ORDER BY principal_use.use_sequence
            """,
            (plan_id,),
        ).fetchall()
        return {
            str(row["work_item_id"]): row
            for row in rows
        }

    @staticmethod
    def _carried_completed_for_plan(
        connection: sqlite3.Connection,
        plan_id: str,
    ) -> dict[str, str]:
        rows = connection.execute(
            """
            SELECT initialization.replacement_work_item_id,
                   initialization.completed_result_sha256
            FROM collaboration_plan_activations AS activation
            JOIN collaboration_plan_work_initializations AS initialization
              ON initialization.replacement_commit_id
                 = activation.replacement_commit_id
            WHERE activation.plan_id = ?
              AND initialization.initial_state = 'completed_carried_forward'
            ORDER BY initialization.replacement_work_item_id
            """,
            (plan_id,),
        ).fetchall()
        return {
            str(row["replacement_work_item_id"]): str(
                row["completed_result_sha256"]
            )
            for row in rows
        }

    @staticmethod
    def _recovery_for_item(
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT
                request.recovery_request_id,
                request.request_sha256,
                decision.recovery_decision_id,
                decision.decision,
                decision.recovery_epoch,
                decision.additional_attempts,
                decision.control_profile_id
            FROM collaboration_work_item_recovery_requests AS request
            LEFT JOIN collaboration_work_item_recovery_decisions AS decision
              ON decision.recovery_request_id
                 = request.recovery_request_id
            WHERE request.plan_id = ?
              AND request.work_item_id = ?
            """,
            (plan_id, work_item_id),
        ).fetchone()

    @staticmethod
    def _cancellations_for_plan(
        connection: sqlite3.Connection,
        plan_id: str,
    ) -> dict[str, tuple[tuple[str, str], ...]]:
        rows = connection.execute(
            """
            SELECT
                cancellation_id,
                work_item_id,
                affected_work_item_ids_json
            FROM collaboration_work_item_cancellations
            WHERE plan_id = ?
            ORDER BY cancellation_id
            """,
            (plan_id,),
        ).fetchall()
        pending: dict[str, list[tuple[str, str]]] = {}
        for row in rows:
            cancellation_id = str(row["cancellation_id"])
            source_id = str(row["work_item_id"])
            affected = json.loads(
                str(row["affected_work_item_ids_json"])
            )
            for affected_id in affected:
                pending.setdefault(str(affected_id), []).append(
                    (cancellation_id, source_id)
                )
        return {
            work_item_id: tuple(sorted(values))
            for work_item_id, values in pending.items()
        }

    @classmethod
    def _cancellation_ids_for_item(
        cls,
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> tuple[str, ...]:
        return tuple(
            cancellation_id
            for cancellation_id, _ in cls._cancellations_for_plan(
                connection,
                plan_id,
            ).get(work_item_id, ())
        )

    @staticmethod
    def _handoffs_for_plan(
        connection: sqlite3.Connection,
        plan_id: str,
    ) -> dict[str, sqlite3.Row]:
        if int(
            connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
        ) < WORK_ITEM_HANDOFF_SCHEMA_VERSION:
            return {}
        rows = connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_handoffs
            WHERE plan_id = ?
            ORDER BY work_item_id
            """,
            (plan_id,),
        ).fetchall()
        return {
            str(row["work_item_id"]): row
            for row in rows
        }

    @classmethod
    def _handoff_for_item(
        cls,
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> sqlite3.Row | None:
        return cls._handoffs_for_plan(
            connection,
            plan_id,
        ).get(work_item_id)

    @staticmethod
    def _ownerships_for_plan(
        connection: sqlite3.Connection,
        plan_id: str,
    ) -> dict[str, sqlite3.Row]:
        if int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        ) < COLLABORATION_OWNERSHIP_SCHEMA_VERSION:
            return {}
        rows = connection.execute(
            """
            SELECT *
            FROM collaboration_ownership_chain_entries
            WHERE plan_id = ?
            ORDER BY work_item_id, sequence
            """,
            (plan_id,),
        ).fetchall()
        return {str(row["work_item_id"]): row for row in rows}

    @classmethod
    def _ownership_for_item(
        cls,
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> sqlite3.Row | None:
        return cls._ownerships_for_plan(connection, plan_id).get(work_item_id)

    @staticmethod
    def _effective_owner_profile_id(
        item: WorkItem,
        handoff: sqlite3.Row | None,
        ownership: sqlite3.Row | None = None,
    ) -> str:
        if handoff is not None and ownership is not None:
            raise StoreIntegrityError(
                "Work item has both legacy handoff and ownership-chain state"
            )
        if ownership is not None:
            return str(ownership["to_owner_id"])
        if handoff is None:
            return item.owner_profile_id
        return str(handoff["candidate_profile_id"])

    @staticmethod
    def _operation_intent(
        kind: WorkItemTransitionKind,
        plan: CollaborationPlan,
        item: WorkItem,
        *,
        owner_profile_id: str | None = None,
        expected_generation: int | None,
        claim_generation: int | None,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
        reason_code: str | None,
        reason: str | None,
        result_id: str | None,
        result_sha256: str | None,
        evidence_manifest_sha256: str | None,
    ) -> dict[str, Any]:
        effective_owner = (
            item.owner_profile_id
            if owner_profile_id is None
            else owner_profile_id
        )
        common = {
            "mission_id": plan.mission_id,
            "plan_content_sha256": plan.content_sha256,
            "plan_id": plan.plan_id,
            "principal_profile_id": effective_owner,
            "work_item_id": item.work_item_id,
        }
        if kind is WorkItemTransitionKind.CLAIM:
            return {
                "expected_generation": expected_generation,
                **common,
            }
        transition = {
            "claim_generation": claim_generation,
            "expected_lease_expires_at": (
                expected_lease_expires_at
            ),
            **common,
            "previous_transition_id": previous_transition_id,
        }
        if kind is WorkItemTransitionKind.RENEW:
            return transition
        if kind is WorkItemTransitionKind.RELEASE:
            return {
                **transition,
                "reason": reason,
                "reason_code": reason_code,
            }
        return {
            **transition,
            "evidence_manifest_sha256": (
                evidence_manifest_sha256
            ),
            "result_id": result_id,
            "result_sha256": result_sha256,
        }

    @staticmethod
    def _derive_transition(
        kind: WorkItemTransitionKind,
        item: WorkItem,
        latest: sqlite3.Row | None,
        recovery: sqlite3.Row | None,
        completed: set[str],
        now: datetime,
        *,
        expected_generation: int | None,
        claim_generation: int | None,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
    ) -> dict[str, Any]:
        if kind is WorkItemTransitionKind.CLAIM:
            if (
                not isinstance(expected_generation, int)
                or isinstance(expected_generation, bool)
                or not 0
                <= expected_generation
                <= WORK_ITEM_ABSOLUTE_MAX_GENERATION
            ):
                raise StoreConflictError(
                    "expected_generation is outside the claim policy"
                )
            current_generation = (
                0 if latest is None else int(latest["generation"])
            )
            if expected_generation != current_generation:
                raise StoreConflictError(
                    "Work item claim generation changed"
                )
            if latest is not None:
                if latest["transition_kind"] == "complete":
                    raise StoreConflictError(
                        "Completed work item cannot be claimed"
                    )
                if (
                    latest["transition_kind"]
                    in {"claim", "renew"}
                    and now
                    < parse_timestamp(
                        str(latest["lease_expires_at"]),
                        "current work item lease_expires_at",
                    )
                ):
                    raise StoreConflictError(
                        "Work item already has an active lease"
                    )
            if current_generation >= WORK_ITEM_ABSOLUTE_MAX_GENERATION:
                raise StoreConflictError(
                    "Work item recovery attempts are exhausted"
                )
            if current_generation >= WORK_ITEM_MAX_CLAIM_ATTEMPTS:
                if recovery is None:
                    raise StoreConflictError(
                        "Work item claim attempts require review"
                    )
                if recovery["decision"] is None:
                    raise StoreConflictError(
                        "Work item recovery awaits Control decision"
                    )
                if recovery["decision"] != "approve":
                    raise StoreConflictError(
                        "Work item recovery was denied"
                    )
            missing = sorted(
                set(item.dependency_ids) - completed
            )
            if missing:
                raise StoreConflictError(
                    "Work item dependencies are not complete: "
                    + ", ".join(missing)
                )
            recorded_at = format_timestamp(now)
            return {
                "generation": current_generation + 1,
                "previous_transition_id": (
                    None
                    if latest is None
                    else str(latest["transition_id"])
                ),
                "previous_lease_expires_at": (
                    None
                    if latest is None
                    else str(latest["lease_expires_at"])
                ),
                "lease_started_at": recorded_at,
                "lease_expires_at": format_timestamp(
                    now
                    + timedelta(
                        seconds=WORK_ITEM_LEASE_SECONDS
                    )
                ),
            }

        if latest is None:
            raise StoreConflictError(
                "Work item has no lease to transition"
            )
        if (
            not isinstance(claim_generation, int)
            or isinstance(claim_generation, bool)
            or claim_generation != int(latest["generation"])
            or previous_transition_id
            != latest["transition_id"]
            or expected_lease_expires_at
            != latest["lease_expires_at"]
        ):
            raise StoreConflictError(
                "Work item lease fence changed"
            )
        if latest["transition_kind"] not in {"claim", "renew"}:
            raise StoreConflictError(
                "Work item has no active lease"
            )
        latest_recorded = parse_timestamp(
            str(latest["recorded_at"]),
            "current work item recorded_at",
        )
        latest_expiry = parse_timestamp(
            str(latest["lease_expires_at"]),
            "current work item lease_expires_at",
        )
        if now < latest_recorded:
            raise PrincipalAuthenticationError(
                "Runtime clock precedes the current work item lease"
            )
        if now >= latest_expiry:
            raise StoreConflictError(
                "Work item lease has expired"
            )
        lease_expires_at = (
            now
            if kind
            in {
                WorkItemTransitionKind.RELEASE,
                WorkItemTransitionKind.COMPLETE,
            }
            else now
            + timedelta(seconds=WORK_ITEM_LEASE_SECONDS)
        )
        if (
            kind is WorkItemTransitionKind.RENEW
            and lease_expires_at <= latest_expiry
        ):
            raise StoreConflictError(
                "Work item renewal must advance the lease"
            )
        return {
            "generation": claim_generation,
            "previous_transition_id": str(
                latest["transition_id"]
            ),
            "previous_lease_expires_at": str(
                latest["lease_expires_at"]
            ),
            "lease_started_at": str(
                latest["lease_started_at"]
            ),
            "lease_expires_at": format_timestamp(
                lease_expires_at
            ),
        }

    def _authenticate_current_authority(
        self,
        connection: sqlite3.Connection,
        *,
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        signed_intent_hash: str,
        mission: StoredMission,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
        scope_grants: dict[str, Any],
        now: datetime,
        consumed_time: datetime,
    ) -> Any:
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
        policy_high_water = self._store._trust_policy_high_water_at(
            trust_policies,
            consumed_time,
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
            expected_mission_id=mission.mission.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=(
                mission.mission.scope_reference
            ),
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=(
                mission.mission.max_action_tier
            ),
            expected_constraints_hash=constraints_hash,
            expected_operation=operation,
            allow_expired_for_safety_reduction=False,
            clock=lambda: now,
        )
        return verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=mission.mission.mission_id,
            expected_operation=operation,
            expected_operation_intent_sha256=signed_intent_hash,
            clock=lambda: now,
        )

    @staticmethod
    def _transition_effect(
        *,
        transition_id: str,
        operation: PrincipalOperation,
        kind: WorkItemTransitionKind,
        mission: StoredMission,
        plan: CollaborationPlan,
        item: WorkItem,
        owner_profile_id: str,
        transition: dict[str, Any],
        store_id: str,
        result_id: str | None,
        result_sha256: str | None,
        evidence_manifest_sha256: str | None,
        reason_code: str | None,
        reason: str | None,
        recorded_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": transition_id,
            "effect_kind": operation.value,
            "payload": {
                "evidence_manifest_sha256": (
                    evidence_manifest_sha256
                ),
                "generation": transition["generation"],
                "lease_expires_at": transition[
                    "lease_expires_at"
                ],
                "lease_started_at": transition[
                    "lease_started_at"
                ],
                "mission_context_sha256": mission.context_hash,
                "owner_profile_id": owner_profile_id,
                "plan_content_sha256": plan.content_sha256,
                "plan_id": plan.plan_id,
                "previous_lease_expires_at": transition[
                    "previous_lease_expires_at"
                ],
                "previous_transition_id": transition[
                    "previous_transition_id"
                ],
                "release_reason": reason,
                "release_reason_code": reason_code,
                "result_id": result_id,
                "result_sha256": result_sha256,
                "store_id": store_id,
                "transition_kind": kind.value,
                "work_item_id": item.work_item_id,
            },
            "recorded_at": recorded_at,
            "schema_version": 1,
        }

    @staticmethod
    def _require_exact_replay(
        row: sqlite3.Row,
        *,
        mission_id: str,
        principal_profile_id: str,
        operation: PrincipalOperation,
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
            or row["operation"] != operation.value
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
    def _transition_for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM (
                SELECT *
                FROM collaboration_work_item_transitions
                UNION ALL
                SELECT
                    transition_id,
                    mission_id,
                    plan_id,
                    plan_content_sha256,
                    work_item_id,
                    generation,
                    transition_kind,
                    owner_profile_id,
                    previous_transition_id,
                    previous_lease_expires_at,
                    lease_started_at,
                    lease_expires_at,
                    result_id,
                    result_sha256,
                    evidence_manifest_sha256,
                    release_reason_code,
                    release_reason,
                    recorded_at,
                    issuer,
                    assertion_id
                FROM collaboration_work_item_recovery_transitions
            )
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Work item assertion has no durable transition"
            )
        return row

    @staticmethod
    def _receipt_from_rows(
        connection: sqlite3.Connection,
        use: sqlite3.Row,
        row: sqlite3.Row,
    ) -> AuthenticatedWorkItemTransitionReceipt:
        try:
            assertion = PrincipalAssertion.from_dict(
                json.loads(str(use["assertion_json"]))
            )
            kind = WorkItemTransitionKind(
                str(row["transition_kind"])
            )
        except (
            ValueError,
            json.JSONDecodeError,
            PrincipalAuthenticationError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored work item transition is invalid"
            ) from exc
        effects = connection.execute(
            """
            SELECT *
            FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ?
            ORDER BY effect_index
            """,
            (use["issuer"], use["assertion_id"]),
        ).fetchall()
        operation = _OPERATION_BY_KIND[kind]
        if (
            len(effects) != 1
            or effects[0]["effect_kind"] != operation.value
            or effects[0]["effect_id"] != row["transition_id"]
            or row["issuer"] != use["issuer"]
            or row["assertion_id"] != use["assertion_id"]
        ):
            raise StoreIntegrityError(
                "Stored work item transition effect is invalid"
            )
        return AuthenticatedWorkItemTransitionReceipt(
            mission_id=str(row["mission_id"]),
            plan_id=str(row["plan_id"]),
            plan_content_sha256=str(
                row["plan_content_sha256"]
            ),
            work_item_id=str(row["work_item_id"]),
            owner_profile_id=str(row["owner_profile_id"]),
            generation=int(row["generation"]),
            transition_id=str(row["transition_id"]),
            transition_kind=kind,
            previous_transition_id=(
                None
                if row["previous_transition_id"] is None
                else str(row["previous_transition_id"])
            ),
            previous_lease_expires_at=(
                None
                if row["previous_lease_expires_at"] is None
                else str(row["previous_lease_expires_at"])
            ),
            lease_started_at=str(row["lease_started_at"]),
            lease_expires_at=str(row["lease_expires_at"]),
            result_id=(
                None
                if row["result_id"] is None
                else str(row["result_id"])
            ),
            result_sha256=(
                None
                if row["result_sha256"] is None
                else str(row["result_sha256"])
            ),
            evidence_manifest_sha256=(
                None
                if row["evidence_manifest_sha256"] is None
                else str(row["evidence_manifest_sha256"])
            ),
            release_reason_code=(
                None
                if row["release_reason_code"] is None
                else str(row["release_reason_code"])
            ),
            release_reason=(
                None
                if row["release_reason"] is None
                else str(row["release_reason"])
            ),
            recorded_at=str(row["recorded_at"]),
            issuer=str(use["issuer"]),
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            subject=str(use["subject"]),
            key_id=str(use["key_id"]),
            key_sha256=str(use["key_hash"]),
            scope_grant_sha256=str(use["scope_grant_hash"]),
            policy_id=str(use["trust_policy_id"]),
            policy_version=int(use["trust_policy_version"]),
            policy_sha256=str(use["trust_policy_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            effects_sha256=str(use["effects_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )

    @staticmethod
    def _status_for_item(
        item: WorkItem,
        latest: sqlite3.Row | None,
        recovery: sqlite3.Row | None,
        cancellations: tuple[tuple[str, str], ...],
        handoff: sqlite3.Row | None,
        ownership: sqlite3.Row | None,
        completed: set[str],
        now: datetime,
        *,
        carried_result_sha256: str | None = None,
        mission_active: bool,
    ) -> WorkItemRuntimeStatus:
        generation = (
            0 if latest is None else int(latest["generation"])
        )
        kind = (
            None
            if latest is None
            else WorkItemTransitionKind(
                str(latest["transition_kind"])
            )
        )
        if (
            kind is WorkItemTransitionKind.COMPLETE
            or carried_result_sha256 is not None
        ):
            state = WorkItemRuntimeState.COMPLETED
        elif not mission_active:
            state = WorkItemRuntimeState.STOPPED
        elif cancellations:
            direct = any(
                source_id == item.work_item_id
                for _, source_id in cancellations
            )
            state = (
                WorkItemRuntimeState.CANCELLED
                if direct
                else WorkItemRuntimeState.CANCELLED_DEPENDENCY
            )
        elif not set(item.dependency_ids) <= completed:
            state = WorkItemRuntimeState.BLOCKED
        elif (
            latest is not None
            and kind
            in {
                WorkItemTransitionKind.CLAIM,
                WorkItemTransitionKind.RENEW,
            }
            and now
            < parse_timestamp(
                str(latest["lease_expires_at"]),
                "current work item lease_expires_at",
            )
        ):
            state = WorkItemRuntimeState.LEASED
        elif (
            recovery is not None
            and recovery["decision"] == "deny"
        ) or generation >= WORK_ITEM_ABSOLUTE_MAX_GENERATION:
            state = WorkItemRuntimeState.FAILED
        elif (
            recovery is not None
            and recovery["decision"] is None
        ):
            state = WorkItemRuntimeState.RECOVERY_PENDING
        elif (
            generation >= WORK_ITEM_MAX_CLAIM_ATTEMPTS
            and recovery is None
        ):
            state = WorkItemRuntimeState.NEEDS_REVIEW
        else:
            state = WorkItemRuntimeState.READY
        attempt_limit = (
            WORK_ITEM_ABSOLUTE_MAX_GENERATION
            if (
                recovery is not None
                and recovery["decision"] == "approve"
            )
            else WORK_ITEM_MAX_CLAIM_ATTEMPTS
        )
        return WorkItemRuntimeStatus(
            work_item_id=item.work_item_id,
            owner_profile_id=AuthenticatedWorkItemLeaseService._effective_owner_profile_id(
                item,
                handoff,
                ownership,
            ),
            planned_owner_profile_id=item.owner_profile_id,
            handoff_id=(
                None
                if handoff is None
                else str(handoff["handoff_id"])
            ),
            handoff_transferred_at=(
                None
                if handoff is None
                else str(handoff["transferred_at"])
            ),
            dependency_ids=item.dependency_ids,
            state=state,
            generation=generation,
            attempts_remaining=max(
                0,
                0
                if cancellations
                else attempt_limit - generation,
            ),
            current_transition_id=(
                None
                if latest is None
                else str(latest["transition_id"])
            ),
            current_transition_kind=kind,
            lease_started_at=(
                None
                if latest is None
                else str(latest["lease_started_at"])
            ),
            lease_expires_at=(
                None
                if latest is None
                else str(latest["lease_expires_at"])
            ),
            result_id=(
                None
                if latest is None or latest["result_id"] is None
                else str(latest["result_id"])
            ),
            result_sha256=(
                carried_result_sha256
                if latest is None
                else (
                    None
                    if latest["result_sha256"] is None
                    else str(latest["result_sha256"])
                )
            ),
            evidence_manifest_sha256=(
                None
                if latest is None
                or latest["evidence_manifest_sha256"] is None
                else str(latest["evidence_manifest_sha256"])
            ),
            recovery_request_id=(
                None
                if recovery is None
                else str(recovery["recovery_request_id"])
            ),
            recovery_decision_id=(
                None
                if recovery is None
                or recovery["recovery_decision_id"] is None
                else str(recovery["recovery_decision_id"])
            ),
            recovery_decision=(
                None
                if recovery is None or recovery["decision"] is None
                else str(recovery["decision"])
            ),
            recovery_epoch=(
                None
                if recovery is None or recovery["recovery_epoch"] is None
                else int(recovery["recovery_epoch"])
            ),
            cancellation_ids=tuple(
                cancellation_id
                for cancellation_id, _ in cancellations
            ),
            cancellation_source_work_item_ids=tuple(
                sorted(
                    {
                        source_id
                        for _, source_id in cancellations
                    }
                )
            ),
        )


__all__ = [
    "AuthenticatedWorkItemLeaseService",
    "AuthenticatedWorkItemStatusReceipt",
    "AuthenticatedWorkItemTransitionReceipt",
    "WorkItemRuntimeState",
    "WorkItemRuntimeStatus",
    "WorkItemTransitionKind",
]
