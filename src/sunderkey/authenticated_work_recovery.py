"""Authenticated same-owner work item recovery for SUNDERKEY."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .collaboration import WORK_ITEM_ID_PATTERN
from .errors import (
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
)
from .registry import ExpertRegistry
from .store import (
    WORK_ITEM_MAX_CLAIM_ATTEMPTS,
    WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS,
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
    work_recovery_decision_id,
    work_recovery_request_id,
)


class WorkRecoveryDecision(StrEnum):
    """Independent Control disposition for one recovery request."""

    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class AuthenticatedWorkRecoveryRequestReceipt:
    """Immutable same-owner recovery request provenance."""

    recovery_request_id: str
    request_sha256: str
    mission_id: str
    plan_id: str
    plan_content_sha256: str
    work_item_id: str
    owner_profile_id: str
    expected_generation: int
    previous_transition_id: str
    expected_lease_expires_at: str
    reason_code: str
    reason: str
    remediation: str
    requested_attempts: int
    requested_at: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    operation_intent_sha256: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "recovery_request_id": self.recovery_request_id,
            "request_sha256": self.request_sha256,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "work_item_id": self.work_item_id,
            "owner_profile_id": self.owner_profile_id,
            "expected_generation": self.expected_generation,
            "previous_transition_id": self.previous_transition_id,
            "expected_lease_expires_at": (
                self.expected_lease_expires_at
            ),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "remediation": self.remediation,
            "requested_attempts": self.requested_attempts,
            "requested_at": self.requested_at,
            "operation": PrincipalOperation.WORK_RECOVERY_REQUEST.value,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


@dataclass(frozen=True)
class AuthenticatedWorkRecoveryDecisionReceipt:
    """Immutable independent Control recovery decision provenance."""

    recovery_decision_id: str
    recovery_request_id: str
    recovery_request_sha256: str
    decision: WorkRecoveryDecision
    mission_id: str
    plan_id: str
    plan_content_sha256: str
    work_item_id: str
    owner_profile_id: str
    control_profile_id: str
    recovery_epoch: int
    additional_attempts: int
    decision_owner: str
    authority: str | None
    constraints: tuple[str, ...]
    reason_code: str | None
    reason: str | None
    risk: str | None
    decided_at: str
    issuer: str
    assertion_id: str
    assertion_sha256: str
    operation_intent_sha256: str
    effects_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        operation = (
            PrincipalOperation.WORK_RECOVERY_APPROVE
            if self.decision is WorkRecoveryDecision.APPROVE
            else PrincipalOperation.WORK_RECOVERY_DENY
        )
        return {
            "schema_version": 1,
            "recovery_decision_id": self.recovery_decision_id,
            "recovery_request_id": self.recovery_request_id,
            "recovery_request_sha256": self.recovery_request_sha256,
            "decision": self.decision.value,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "work_item_id": self.work_item_id,
            "owner_profile_id": self.owner_profile_id,
            "control_profile_id": self.control_profile_id,
            "recovery_epoch": self.recovery_epoch,
            "additional_attempts": self.additional_attempts,
            "decision_owner": self.decision_owner,
            "authority": self.authority,
            "constraints": list(self.constraints),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "risk": self.risk,
            "decided_at": self.decided_at,
            "operation": operation.value,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "operation_intent_sha256": (
                self.operation_intent_sha256
            ),
            "effects_sha256": self.effects_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


class AuthenticatedWorkRecoveryService:
    """Open one independently approved same-owner recovery epoch."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._work = AuthenticatedWorkItemLeaseService(
            store,
            registry,
            clock=clock,
        )
        self._store = store
        self._registry = registry
        self._clock = clock or store._clock

    def request(
        self,
        assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        expected_generation: int,
        previous_transition_id: str,
        expected_lease_expires_at: str,
        reason_code: str,
        reason: str,
        remediation: str,
    ) -> AuthenticatedWorkRecoveryRequestReceipt:
        """Request one recovery epoch as the original work owner."""

        self._validate_target(mission_id, work_item_id)
        assertion = self._assertion(assertion)
        request_id = work_recovery_request_id(
            assertion.issuer,
            assertion.assertion_id,
        )
        operation = PrincipalOperation.WORK_RECOVERY_REQUEST
        try:
            with self._store._write_connection() as connection:
                (
                    identity,
                    policies,
                    mission,
                    grants,
                    ledger,
                ) = self._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                _, plan = self._work._load_activation(
                    connection,
                    mission_id,
                )
                item = self._work._work_item(plan, work_item_id)
                handoff = self._work._handoff_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                owner_profile_id = (
                    self._work._effective_owner_profile_id(
                        item,
                        handoff,
                    )
                )
                intent = {
                    "expected_generation": expected_generation,
                    "expected_lease_expires_at": (
                        expected_lease_expires_at
                    ),
                    "mission_id": mission_id,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "previous_transition_id": previous_transition_id,
                    "principal_profile_id": owner_profile_id,
                    "reason": reason,
                    "reason_code": reason_code,
                    "remediation": remediation,
                    "requested_attempts": (
                        WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS
                    ),
                    "work_item_id": work_item_id,
                }
                material = self._assertion_material(
                    assertion,
                    operation,
                    intent,
                )
                existing = self._existing_use(connection, assertion)
                if existing is not None:
                    self._work._require_exact_replay(
                        existing,
                        mission_id=mission_id,
                        principal_profile_id=owner_profile_id,
                        operation=operation,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=assertion.policy_version,
                        assertion_json=material["assertion_json"],
                        assertion_hash=material["assertion_hash"],
                        operation_intent_json=material["intent_json"],
                        signed_intent_hash=material["signed_hash"],
                        domain_request_hash=material["domain_hash"],
                        scope_grant_hash=assertion.scope_grant_sha256,
                    )
                    return self._request_receipt(
                        connection,
                        existing,
                        self._request_for_assertion(
                            connection,
                            assertion,
                        ),
                    )
                if self._work._cancellation_ids_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ):
                    raise StoreConflictError(
                        "Cancelled work item cannot request recovery"
                    )
                if assertion.profile_id != owner_profile_id:
                    raise PrincipalAuthenticationError(
                        "Work recovery request requires the "
                        "effective owner"
                    )
                self._require_active(connection, mission_id)
                now = self._clock()
                requested_at = format_timestamp(now)
                requested_time = parse_timestamp(
                    requested_at,
                    "work recovery requested_at",
                )
                self._work._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    requested_time,
                )
                latest = self._work._latest_transition(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                if (
                    latest is None
                    or expected_generation
                    != WORK_ITEM_MAX_CLAIM_ATTEMPTS
                    or int(latest["generation"])
                    != WORK_ITEM_MAX_CLAIM_ATTEMPTS
                    or latest["transition_kind"] == "complete"
                    or previous_transition_id
                    != latest["transition_id"]
                    or expected_lease_expires_at
                    != latest["lease_expires_at"]
                ):
                    raise StoreConflictError(
                        "Work recovery requires the exhausted "
                        "generation 3 fence"
                    )
                if (
                    latest["transition_kind"] in {"claim", "renew"}
                    and requested_time
                    < parse_timestamp(
                        str(latest["lease_expires_at"]),
                        "current work item lease_expires_at",
                    )
                ):
                    raise StoreConflictError(
                        "Active work item lease cannot enter recovery"
                    )
                principal = self._work._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    signed_intent_hash=material["signed_hash"],
                    mission=mission,
                    identity=identity,
                    trust_policies=policies,
                    scope_grants=grants,
                    now=now,
                    consumed_time=requested_time,
                )
                request_hash = sha256_text(
                    canonical_json(
                        {
                            "domain": "sunderkey.work-recovery-request.v1",
                            "intent": intent,
                            "mission_context_sha256": (
                                mission.context_hash
                            ),
                            "recovery_request_id": request_id,
                            "requested_at": requested_at,
                            "schema_version": 1,
                            "store_id": str(identity["store_id"]),
                        }
                    )
                )
                effect = {
                    "effect_id": request_id,
                    "effect_kind": operation.value,
                    "payload": {
                        "mission_context_sha256": mission.context_hash,
                        "owner_profile_id": owner_profile_id,
                        "plan_content_sha256": plan.content_sha256,
                        "plan_id": plan.plan_id,
                        "recovery_request_sha256": request_hash,
                        "requested_attempts": (
                            WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS
                        ),
                        "store_id": str(identity["store_id"]),
                        "work_item_id": work_item_id,
                    },
                    "recorded_at": requested_at,
                    "schema_version": 1,
                }
                entry_hash = self._record_assertion(
                    connection,
                    principal=principal,
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=requested_at,
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_work_item_recovery_requests(
                        recovery_request_id,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        work_item_id,
                        owner_profile_id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        reason_code,
                        reason,
                        remediation,
                        requested_attempts,
                        request_sha256,
                        requested_at,
                        issuer,
                        assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?
                    )
                    """,
                    (
                        request_id,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        work_item_id,
                        owner_profile_id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        reason_code,
                        reason,
                        remediation,
                        WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS,
                        request_hash,
                        requested_at,
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                )
                self._verify_after_mutation(
                    connection,
                    mission,
                    identity,
                    policies,
                )
                use = self._existing_use(connection, assertion)
                if use is None:
                    raise StoreIntegrityError(
                        "Work recovery request durable state is "
                        "incomplete"
                    )
                receipt = self._request_receipt(
                    connection,
                    use,
                    self._request_for_assertion(connection, assertion),
                )
                if receipt.ledger_entry_sha256 != entry_hash:
                    raise StoreIntegrityError(
                        "Work recovery request ledger entry changed"
                    )
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated work recovery request conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated work recovery request"
            ) from exc

    def approve(
        self,
        assertion: PrincipalAssertion,
        recovery_request_id: str,
        *,
        decision_owner: str,
        authority: str,
        constraints: Sequence[str],
    ) -> AuthenticatedWorkRecoveryDecisionReceipt:
        """Approve the one recovery epoch as independent Control."""

        return self._decide(
            WorkRecoveryDecision.APPROVE,
            assertion,
            recovery_request_id,
            decision_owner=decision_owner,
            authority=authority,
            constraints=constraints,
        )

    def deny(
        self,
        assertion: PrincipalAssertion,
        recovery_request_id: str,
        *,
        decision_owner: str,
        reason_code: str,
        reason: str,
        risk: str,
    ) -> AuthenticatedWorkRecoveryDecisionReceipt:
        """Deny recovery and record terminal failure."""

        return self._decide(
            WorkRecoveryDecision.DENY,
            assertion,
            recovery_request_id,
            decision_owner=decision_owner,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
        )

    def get(
        self,
        recovery_request_id: str,
    ) -> dict[str, Any]:
        """Return one verified recovery request and optional decision."""

        try:
            with self._store._read_connection() as connection:
                request = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_work_item_recovery_requests
                    WHERE recovery_request_id = ?
                    """,
                    (recovery_request_id,),
                ).fetchone()
                if request is None:
                    raise StoreError(
                        "Unknown work recovery request: "
                        + recovery_request_id
                    )
                self._store.verify_store(self._registry)
                decision = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_work_item_recovery_decisions
                    WHERE recovery_request_id = ?
                    """,
                    (recovery_request_id,),
                ).fetchone()
                return {
                    "schema_version": 1,
                    "request": dict(request),
                    "decision": (
                        None if decision is None else dict(decision)
                    ),
                }
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read authenticated work recovery"
            ) from exc

    def _decide(
        self,
        decision: WorkRecoveryDecision,
        assertion: PrincipalAssertion,
        recovery_request_id: str,
        *,
        decision_owner: str,
        authority: str | None = None,
        constraints: Sequence[str] = (),
        reason_code: str | None = None,
        reason: str | None = None,
        risk: str | None = None,
    ) -> AuthenticatedWorkRecoveryDecisionReceipt:
        assertion = self._assertion(assertion)
        operation = (
            PrincipalOperation.WORK_RECOVERY_APPROVE
            if decision is WorkRecoveryDecision.APPROVE
            else PrincipalOperation.WORK_RECOVERY_DENY
        )
        decision_id = work_recovery_decision_id(
            assertion.issuer,
            assertion.assertion_id,
        )
        try:
            with self._store._write_connection() as connection:
                request = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_work_item_recovery_requests
                    WHERE recovery_request_id = ?
                    """,
                    (recovery_request_id,),
                ).fetchone()
                if request is None:
                    raise StoreConflictError(
                        "Work recovery request does not exist"
                    )
                mission_id = str(request["mission_id"])
                (
                    identity,
                    policies,
                    mission,
                    grants,
                    ledger,
                ) = self._work._activation._verified_mission_state(
                    connection,
                    mission_id,
                )
                _, plan = self._work._load_activation(
                    connection,
                    mission_id,
                )
                if (
                    isinstance(constraints, (str, bytes))
                    or any(
                        not isinstance(value, str)
                        for value in constraints
                    )
                ):
                    raise PrincipalAuthenticationError(
                        "constraints must be a sequence of strings"
                    )
                canonical_constraints = tuple(sorted(constraints))
                if len(canonical_constraints) != len(
                    set(canonical_constraints)
                ):
                    raise PrincipalAuthenticationError(
                        "constraints must not contain duplicate values"
                    )
                common = {
                    "additional_attempts": (
                        WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS
                    ),
                    "decision_owner": decision_owner,
                    "mission_id": mission_id,
                    "owner_profile_id": str(
                        request["owner_profile_id"]
                    ),
                    "plan_content_sha256": str(
                        request["plan_content_sha256"]
                    ),
                    "plan_id": str(request["plan_id"]),
                    "principal_profile_id": assertion.profile_id,
                    "recovery_epoch": 1,
                    "recovery_request_id": recovery_request_id,
                    "recovery_request_sha256": str(
                        request["request_sha256"]
                    ),
                    "work_item_id": str(request["work_item_id"]),
                }
                intent = (
                    {
                        **common,
                        "authority": authority,
                        "constraints": list(canonical_constraints),
                    }
                    if decision is WorkRecoveryDecision.APPROVE
                    else {
                        **common,
                        "reason": reason,
                        "reason_code": reason_code,
                        "risk": risk,
                    }
                )
                material = self._assertion_material(
                    assertion,
                    operation,
                    intent,
                )
                existing = self._existing_use(connection, assertion)
                if existing is not None:
                    self._work._require_exact_replay(
                        existing,
                        mission_id=mission_id,
                        principal_profile_id=assertion.profile_id,
                        operation=operation,
                        trust_policy_id=assertion.policy_id,
                        trust_policy_version=assertion.policy_version,
                        assertion_json=material["assertion_json"],
                        assertion_hash=material["assertion_hash"],
                        operation_intent_json=material["intent_json"],
                        signed_intent_hash=material["signed_hash"],
                        domain_request_hash=material["domain_hash"],
                        scope_grant_hash=assertion.scope_grant_sha256,
                    )
                    return self._decision_receipt(
                        connection,
                        existing,
                        self._decision_for_assertion(
                            connection,
                            assertion,
                        ),
                    )
                if self._work._cancellation_ids_for_item(
                    connection,
                    str(request["plan_id"]),
                    str(request["work_item_id"]),
                ):
                    raise StoreConflictError(
                        "Cancelled work item recovery cannot be decided"
                    )
                if (
                    assertion.profile_id
                    not in mission.control_profile_ids
                ):
                    raise PrincipalAuthenticationError(
                        "Work recovery decision requires an assigned "
                        "independent Control profile"
                    )
                if (
                    assertion.profile_id
                    == request["owner_profile_id"]
                ):
                    raise PrincipalAuthenticationError(
                        "Work owner cannot decide its own recovery "
                        "request"
                    )
                self._require_active(connection, mission_id)
                if connection.execute(
                    """
                    SELECT 1
                    FROM collaboration_work_item_recovery_decisions
                    WHERE recovery_request_id = ?
                    """,
                    (recovery_request_id,),
                ).fetchone() is not None:
                    raise StoreConflictError(
                        "Work recovery request already has a decision"
                    )
                now = self._clock()
                decided_at = format_timestamp(now)
                decided_time = parse_timestamp(
                    decided_at,
                    "work recovery decided_at",
                )
                self._work._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    decided_time,
                )
                principal = self._work._authenticate_current_authority(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    signed_intent_hash=material["signed_hash"],
                    mission=mission,
                    identity=identity,
                    trust_policies=policies,
                    scope_grants=grants,
                    now=now,
                    consumed_time=decided_time,
                )
                effect = {
                    "effect_id": decision_id,
                    "effect_kind": operation.value,
                    "payload": {
                        "additional_attempts": (
                            WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS
                        ),
                        "control_profile_id": assertion.profile_id,
                        "decision": decision.value,
                        "mission_context_sha256": mission.context_hash,
                        "owner_profile_id": str(
                            request["owner_profile_id"]
                        ),
                        "plan_content_sha256": str(
                            request["plan_content_sha256"]
                        ),
                        "plan_id": str(request["plan_id"]),
                        "recovery_epoch": 1,
                        "recovery_request_id": recovery_request_id,
                        "recovery_request_sha256": str(
                            request["request_sha256"]
                        ),
                        "store_id": str(identity["store_id"]),
                        "work_item_id": str(request["work_item_id"]),
                    },
                    "recorded_at": decided_at,
                    "schema_version": 1,
                }
                entry_hash = self._record_assertion(
                    connection,
                    principal=principal,
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=decided_at,
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_work_item_recovery_decisions(
                        recovery_decision_id,
                        recovery_request_id,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        work_item_id,
                        owner_profile_id,
                        decision,
                        control_profile_id,
                        recovery_epoch,
                        additional_attempts,
                        decision_owner,
                        authority,
                        constraints_json,
                        reason_code,
                        reason,
                        risk,
                        decided_at,
                        issuer,
                        assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 3, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        decision_id,
                        recovery_request_id,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        str(request["work_item_id"]),
                        str(request["owner_profile_id"]),
                        decision.value,
                        assertion.profile_id,
                        decision_owner,
                        authority,
                        (
                            canonical_json(list(canonical_constraints))
                            if decision
                            is WorkRecoveryDecision.APPROVE
                            else None
                        ),
                        reason_code,
                        reason,
                        risk,
                        decided_at,
                        assertion.issuer,
                        assertion.assertion_id,
                    ),
                )
                self._verify_after_mutation(
                    connection,
                    mission,
                    identity,
                    policies,
                )
                use = self._existing_use(connection, assertion)
                if use is None:
                    raise StoreIntegrityError(
                        "Work recovery decision durable state is "
                        "incomplete"
                    )
                receipt = self._decision_receipt(
                    connection,
                    use,
                    self._decision_for_assertion(connection, assertion),
                )
                if receipt.ledger_entry_sha256 != entry_hash:
                    raise StoreIntegrityError(
                        "Work recovery decision ledger entry changed"
                    )
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated work recovery decision conflicts with "
                "durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated work recovery decision"
            ) from exc

    @staticmethod
    def _assertion(assertion: PrincipalAssertion) -> PrincipalAssertion:
        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                "assertion must be a PrincipalAssertion"
            )
        return PrincipalAssertion.from_dict(assertion.to_dict())

    @staticmethod
    def _validate_target(mission_id: str, work_item_id: str) -> None:
        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is not a valid mission ID")
        if (
            not isinstance(work_item_id, str)
            or WORK_ITEM_ID_PATTERN.fullmatch(work_item_id) is None
        ):
            raise StoreError(
                "work_item_id is not a valid collaboration work item ID"
            )

    @staticmethod
    def _assertion_material(
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        intent: dict[str, Any],
    ) -> dict[str, str]:
        assertion_json = canonical_json(assertion.to_dict())
        intent_json = canonical_json(intent)
        return {
            "assertion_json": assertion_json,
            "assertion_hash": sha256_text(assertion_json),
            "intent_json": intent_json,
            "signed_hash": compute_operation_intent_hash(
                operation,
                intent,
            ),
            "domain_hash": sha256_text(intent_json),
        }

    @staticmethod
    def _existing_use(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT *
            FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()

    @staticmethod
    def _require_active(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT state
            FROM mission_controls
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "Mission control state is missing"
            )
        if row["state"] != "active":
            raise MissionStoppedError(
                "Stopped mission cannot mutate work recovery"
            )

    @staticmethod
    def _record_assertion(
        connection: sqlite3.Connection,
        *,
        principal: Any,
        assertion: PrincipalAssertion,
        mission_id: str,
        operation: PrincipalOperation,
        material: dict[str, str],
        effect: dict[str, Any],
        ledger: sqlite3.Row,
        consumed_at: str,
    ) -> str:
        effect_json = canonical_json(effect)
        effect_hash = sha256_text(effect_json)
        effects_hash = principal_assertion_effects_hash(
            (effect_hash,)
        )
        use_sequence = int(ledger["assertion_count"]) + 1
        previous_hash = str(ledger["head_hash"])
        entry = AuthenticatedMissionControlService._assertion_entry(
            principal=principal,
            assertion=assertion,
            mission_id=mission_id,
            use_sequence=use_sequence,
            assertion_hash=material["assertion_hash"],
            operation_intent_json=material["intent_json"],
            signed_intent_hash=material["signed_hash"],
            domain_request_hash=material["domain_hash"],
            idempotency_key_hash=None,
            consumed_at=consumed_at,
            effects_hash=effects_hash,
            previous_hash=previous_hash,
        )
        entry_hash = principal_assertion_entry_hash(entry)
        AuthenticatedMissionControlService._insert_assertion_use(
            connection,
            assertion_json=material["assertion_json"],
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
                effect["effect_id"],
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
                int(ledger["effect_count"]),
                previous_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError(
                "Mission principal ledger changed during work recovery"
            )
        return entry_hash

    def _verify_after_mutation(
        self,
        connection: sqlite3.Connection,
        mission: Any,
        identity: sqlite3.Row,
        policies: dict[str, Any],
    ) -> None:
        self._store._verify_phase4_mission_state(
            connection,
            mission,
            store_id=str(identity["store_id"]),
            trust_policies=policies,
            registry=self._registry,
        )

    @staticmethod
    def _request_for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_recovery_requests
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Work recovery assertion has no durable request"
            )
        return row

    @staticmethod
    def _decision_for_assertion(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_recovery_decisions
            WHERE issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Work recovery assertion has no durable decision"
            )
        return row

    @staticmethod
    def _request_receipt(
        connection: sqlite3.Connection,
        use: sqlite3.Row,
        row: sqlite3.Row,
    ) -> AuthenticatedWorkRecoveryRequestReceipt:
        assertion = PrincipalAssertion.from_dict(
            json.loads(str(use["assertion_json"]))
        )
        return AuthenticatedWorkRecoveryRequestReceipt(
            recovery_request_id=str(row["recovery_request_id"]),
            request_sha256=str(row["request_sha256"]),
            mission_id=str(row["mission_id"]),
            plan_id=str(row["plan_id"]),
            plan_content_sha256=str(row["plan_content_sha256"]),
            work_item_id=str(row["work_item_id"]),
            owner_profile_id=str(row["owner_profile_id"]),
            expected_generation=int(row["expected_generation"]),
            previous_transition_id=str(row["previous_transition_id"]),
            expected_lease_expires_at=str(
                row["expected_lease_expires_at"]
            ),
            reason_code=str(row["reason_code"]),
            reason=str(row["reason"]),
            remediation=str(row["remediation"]),
            requested_attempts=int(row["requested_attempts"]),
            requested_at=str(row["requested_at"]),
            issuer=str(use["issuer"]),
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            effects_sha256=str(use["effects_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )

    @staticmethod
    def _decision_receipt(
        connection: sqlite3.Connection,
        use: sqlite3.Row,
        row: sqlite3.Row,
    ) -> AuthenticatedWorkRecoveryDecisionReceipt:
        assertion = PrincipalAssertion.from_dict(
            json.loads(str(use["assertion_json"]))
        )
        request = connection.execute(
            """
            SELECT request_sha256
            FROM collaboration_work_item_recovery_requests
            WHERE recovery_request_id = ?
            """,
            (row["recovery_request_id"],),
        ).fetchone()
        if request is None:
            raise StoreIntegrityError(
                "Work recovery decision request is missing"
            )
        constraints = (
            ()
            if row["constraints_json"] is None
            else tuple(json.loads(str(row["constraints_json"])))
        )
        return AuthenticatedWorkRecoveryDecisionReceipt(
            recovery_decision_id=str(row["recovery_decision_id"]),
            recovery_request_id=str(row["recovery_request_id"]),
            recovery_request_sha256=str(request["request_sha256"]),
            decision=WorkRecoveryDecision(str(row["decision"])),
            mission_id=str(row["mission_id"]),
            plan_id=str(row["plan_id"]),
            plan_content_sha256=str(row["plan_content_sha256"]),
            work_item_id=str(row["work_item_id"]),
            owner_profile_id=str(row["owner_profile_id"]),
            control_profile_id=str(row["control_profile_id"]),
            recovery_epoch=int(row["recovery_epoch"]),
            additional_attempts=int(row["additional_attempts"]),
            decision_owner=str(row["decision_owner"]),
            authority=(
                None
                if row["authority"] is None
                else str(row["authority"])
            ),
            constraints=constraints,
            reason_code=(
                None
                if row["reason_code"] is None
                else str(row["reason_code"])
            ),
            reason=(
                None if row["reason"] is None else str(row["reason"])
            ),
            risk=None if row["risk"] is None else str(row["risk"]),
            decided_at=str(row["decided_at"]),
            issuer=str(use["issuer"]),
            assertion_id=str(use["assertion_id"]),
            assertion_sha256=str(use["assertion_hash"]),
            operation_intent_sha256=(
                assertion.operation_intent_sha256
            ),
            effects_sha256=str(use["effects_hash"]),
            ledger_entry_sha256=str(use["entry_hash"]),
        )


__all__ = [
    "AuthenticatedWorkRecoveryDecisionReceipt",
    "AuthenticatedWorkRecoveryRequestReceipt",
    "AuthenticatedWorkRecoveryService",
    "WorkRecoveryDecision",
]
