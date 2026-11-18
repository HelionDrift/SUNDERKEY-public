"""Authenticated specialist work handoff for SUNDERKEY."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .collaboration import (
    WORK_ITEM_ID_PATTERN,
    CollaborationPlan,
    WorkItem,
    WorkItemKind,
)
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
from .registry import ExpertProfile, ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
    work_handoff_id,
)
from .types import ProfileKind

HANDOFF_SCOPE = "remaining_specialist_work"
QUALIFICATION_BASIS = "assigned_qualified_same_command_v1"


@dataclass(frozen=True)
class AuthenticatedWorkHandoffReceipt:
    """Immutable dual-assertion specialist handoff provenance."""

    handoff_id: str
    handoff_sha256: str
    mission_id: str
    plan_id: str
    plan_content_sha256: str
    work_item_id: str
    planned_owner_profile_id: str
    candidate_profile_id: str
    expected_generation: int
    previous_transition_id: str | None
    expected_lease_expires_at: str | None
    handoff_scope: str
    qualification_basis: str
    qualification_command_id: str
    candidate_profile_version: str
    candidate_registry_status: str
    reason_code: str
    reason: str
    transferred_at: str
    owner_issuer: str
    owner_assertion_id: str
    owner_assertion_sha256: str
    owner_operation_intent_sha256: str
    owner_effects_sha256: str
    owner_ledger_entry_sha256: str
    candidate_issuer: str
    candidate_assertion_id: str
    candidate_assertion_sha256: str
    candidate_operation_intent_sha256: str
    candidate_effects_sha256: str
    candidate_ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "plan_content_sha256": self.plan_content_sha256,
            "work_item_id": self.work_item_id,
            "planned_owner_profile_id": (
                self.planned_owner_profile_id
            ),
            "candidate_profile_id": self.candidate_profile_id,
            "expected_generation": self.expected_generation,
            "previous_transition_id": self.previous_transition_id,
            "expected_lease_expires_at": (
                self.expected_lease_expires_at
            ),
            "handoff_scope": self.handoff_scope,
            "qualification_basis": self.qualification_basis,
            "qualification_command_id": (
                self.qualification_command_id
            ),
            "candidate_profile_version": (
                self.candidate_profile_version
            ),
            "candidate_registry_status": (
                self.candidate_registry_status
            ),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "transferred_at": self.transferred_at,
            "owner_operation": (
                PrincipalOperation.WORK_HANDOFF_AUTHORIZE.value
            ),
            "owner_issuer": self.owner_issuer,
            "owner_assertion_id": self.owner_assertion_id,
            "owner_assertion_sha256": self.owner_assertion_sha256,
            "owner_operation_intent_sha256": (
                self.owner_operation_intent_sha256
            ),
            "owner_effects_sha256": self.owner_effects_sha256,
            "owner_ledger_entry_sha256": (
                self.owner_ledger_entry_sha256
            ),
            "candidate_operation": (
                PrincipalOperation.WORK_HANDOFF_ACCEPT.value
            ),
            "candidate_issuer": self.candidate_issuer,
            "candidate_assertion_id": self.candidate_assertion_id,
            "candidate_assertion_sha256": (
                self.candidate_assertion_sha256
            ),
            "candidate_operation_intent_sha256": (
                self.candidate_operation_intent_sha256
            ),
            "candidate_effects_sha256": (
                self.candidate_effects_sha256
            ),
            "candidate_ledger_entry_sha256": (
                self.candidate_ledger_entry_sha256
            ),
        }


class AuthenticatedWorkHandoffService:
    """Atomically hand one specialist item to a qualified peer."""

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

    def handoff(
        self,
        owner_assertion: PrincipalAssertion,
        candidate_assertion: PrincipalAssertion,
        mission_id: str,
        work_item_id: str,
        *,
        expected_generation: int,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
        reason_code: str,
        reason: str,
    ) -> AuthenticatedWorkHandoffReceipt:
        """Commit one exact owner authorization and peer acceptance."""

        self._validate_target(mission_id, work_item_id)
        owner_assertion = self._assertion(
            owner_assertion,
            "owner_assertion",
        )
        candidate_assertion = self._assertion(
            candidate_assertion,
            "candidate_assertion",
        )
        if (
            owner_assertion.issuer == candidate_assertion.issuer
            and owner_assertion.assertion_id
            == candidate_assertion.assertion_id
        ):
            raise PrincipalAuthenticationError(
                "Work handoff requires two distinct assertions"
            )
        handoff_id = work_handoff_id(
            owner_assertion.issuer,
            owner_assertion.assertion_id,
            candidate_assertion.issuer,
            candidate_assertion.assertion_id,
        )
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
                candidate = self._registry.profile(
                    candidate_assertion.profile_id
                )
                self._require_qualified_candidate(
                    plan,
                    item,
                    candidate,
                    mission.allowed_profile_ids,
                    mission.control_profile_ids,
                    mission.assurance_profile_ids,
                )
                owner_intent = self._operation_intent(
                    plan,
                    item,
                    candidate,
                    owner_assertion,
                    candidate_assertion,
                    principal_profile_id=item.owner_profile_id,
                    expected_generation=expected_generation,
                    previous_transition_id=previous_transition_id,
                    expected_lease_expires_at=(
                        expected_lease_expires_at
                    ),
                    reason_code=reason_code,
                    reason=reason,
                )
                candidate_intent = self._operation_intent(
                    plan,
                    item,
                    candidate,
                    owner_assertion,
                    candidate_assertion,
                    principal_profile_id=candidate.id,
                    expected_generation=expected_generation,
                    previous_transition_id=previous_transition_id,
                    expected_lease_expires_at=(
                        expected_lease_expires_at
                    ),
                    reason_code=reason_code,
                    reason=reason,
                )
                owner_material = self._assertion_material(
                    owner_assertion,
                    PrincipalOperation.WORK_HANDOFF_AUTHORIZE,
                    owner_intent,
                )
                candidate_material = self._assertion_material(
                    candidate_assertion,
                    PrincipalOperation.WORK_HANDOFF_ACCEPT,
                    candidate_intent,
                )
                owner_use = self._existing_use(
                    connection,
                    owner_assertion,
                )
                candidate_use = self._existing_use(
                    connection,
                    candidate_assertion,
                )
                if owner_use is not None or candidate_use is not None:
                    if owner_use is None or candidate_use is None:
                        raise StoreConflictError(
                            "Work handoff replay is incomplete"
                        )
                    self._work._require_exact_replay(
                        owner_use,
                        mission_id=mission_id,
                        principal_profile_id=item.owner_profile_id,
                        operation=(
                            PrincipalOperation.WORK_HANDOFF_AUTHORIZE
                        ),
                        trust_policy_id=owner_assertion.policy_id,
                        trust_policy_version=(
                            owner_assertion.policy_version
                        ),
                        assertion_json=owner_material["assertion_json"],
                        assertion_hash=owner_material["assertion_hash"],
                        operation_intent_json=owner_material["intent_json"],
                        signed_intent_hash=owner_material["signed_hash"],
                        domain_request_hash=owner_material["domain_hash"],
                        scope_grant_hash=(
                            owner_assertion.scope_grant_sha256
                        ),
                    )
                    self._work._require_exact_replay(
                        candidate_use,
                        mission_id=mission_id,
                        principal_profile_id=candidate.id,
                        operation=(
                            PrincipalOperation.WORK_HANDOFF_ACCEPT
                        ),
                        trust_policy_id=candidate_assertion.policy_id,
                        trust_policy_version=(
                            candidate_assertion.policy_version
                        ),
                        assertion_json=(
                            candidate_material["assertion_json"]
                        ),
                        assertion_hash=(
                            candidate_material["assertion_hash"]
                        ),
                        operation_intent_json=(
                            candidate_material["intent_json"]
                        ),
                        signed_intent_hash=(
                            candidate_material["signed_hash"]
                        ),
                        domain_request_hash=(
                            candidate_material["domain_hash"]
                        ),
                        scope_grant_hash=(
                            candidate_assertion.scope_grant_sha256
                        ),
                    )
                    row = self._for_assertions(
                        connection,
                        owner_assertion,
                        candidate_assertion,
                    )
                    if row["handoff_id"] != handoff_id:
                        raise StoreConflictError(
                            "Work handoff replay has different content"
                        )
                    return self._receipt(
                        row,
                        owner_use,
                        candidate_use,
                    )
                if owner_assertion.profile_id != item.owner_profile_id:
                    raise PrincipalAuthenticationError(
                        "Work handoff authorization requires the "
                        "planned owner"
                    )
                self._require_active(connection, mission_id)
                if self._handoff_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ) is not None:
                    raise StoreConflictError(
                        "Work item has already been handed off"
                    )
                if self._work._ownership_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ) is not None:
                    raise StoreConflictError(
                        "Ownership-chained work item cannot use a legacy handoff"
                    )
                if self._work._cancellation_ids_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ):
                    raise StoreConflictError(
                        "Cancelled work item cannot be handed off"
                    )
                if self._work._recovery_for_item(
                    connection,
                    plan.plan_id,
                    work_item_id,
                ) is not None:
                    raise StoreConflictError(
                        "Recovered work item cannot be handed off"
                    )
                now = self._clock()
                transferred_at = format_timestamp(now)
                transferred_time = parse_timestamp(
                    transferred_at,
                    "work handoff transferred_at",
                )
                self._work._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    ledger,
                    transferred_time,
                )
                latest = self._work._latest_transition(
                    connection,
                    plan.plan_id,
                    work_item_id,
                )
                self._require_exact_inactive_fence(
                    latest,
                    now,
                    expected_generation=expected_generation,
                    previous_transition_id=previous_transition_id,
                    expected_lease_expires_at=(
                        expected_lease_expires_at
                    ),
                )
                owner_principal = (
                    self._work._authenticate_current_authority(
                        connection,
                        assertion=owner_assertion,
                        operation=(
                            PrincipalOperation.WORK_HANDOFF_AUTHORIZE
                        ),
                        signed_intent_hash=owner_material["signed_hash"],
                        mission=mission,
                        identity=identity,
                        trust_policies=policies,
                        scope_grants=grants,
                        now=now,
                        consumed_time=transferred_time,
                    )
                )
                candidate_principal = (
                    self._work._authenticate_current_authority(
                        connection,
                        assertion=candidate_assertion,
                        operation=(
                            PrincipalOperation.WORK_HANDOFF_ACCEPT
                        ),
                        signed_intent_hash=(
                            candidate_material["signed_hash"]
                        ),
                        mission=mission,
                        identity=identity,
                        trust_policies=policies,
                        scope_grants=grants,
                        now=now,
                        consumed_time=transferred_time,
                    )
                )
                handoff_hash = sha256_text(
                    canonical_json(
                        {
                            "candidate_intent": candidate_intent,
                            "domain": "sunderkey.work-handoff.v1",
                            "handoff_id": handoff_id,
                            "mission_context_sha256": (
                                mission.context_hash
                            ),
                            "owner_intent": owner_intent,
                            "schema_version": 1,
                            "store_id": str(identity["store_id"]),
                            "transferred_at": transferred_at,
                        }
                    )
                )
                common_payload = {
                    "candidate_profile_id": candidate.id,
                    "handoff_scope": HANDOFF_SCOPE,
                    "handoff_sha256": handoff_hash,
                    "mission_context_sha256": mission.context_hash,
                    "plan_content_sha256": plan.content_sha256,
                    "plan_id": plan.plan_id,
                    "planned_owner_profile_id": item.owner_profile_id,
                    "qualification_basis": QUALIFICATION_BASIS,
                    "qualification_command_id": item.command_id,
                    "store_id": str(identity["store_id"]),
                    "work_item_id": work_item_id,
                }
                owner_effect = self._effect(
                    handoff_id,
                    PrincipalOperation.WORK_HANDOFF_AUTHORIZE,
                    {
                        **common_payload,
                        "handoff_role": "planned_owner_authorization",
                    },
                    transferred_at,
                )
                candidate_effect = self._effect(
                    handoff_id,
                    PrincipalOperation.WORK_HANDOFF_ACCEPT,
                    {
                        **common_payload,
                        "handoff_role": "candidate_acceptance",
                    },
                    transferred_at,
                )
                self._record_assertion(
                    connection,
                    principal=owner_principal,
                    assertion=owner_assertion,
                    mission_id=mission_id,
                    operation=(
                        PrincipalOperation.WORK_HANDOFF_AUTHORIZE
                    ),
                    material=owner_material,
                    effect=owner_effect,
                    ledger=ledger,
                    consumed_at=transferred_at,
                )
                next_ledger = connection.execute(
                    """
                    SELECT *
                    FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (mission_id,),
                ).fetchone()
                if next_ledger is None:
                    raise StoreIntegrityError(
                        "Mission principal ledger disappeared"
                    )
                self._record_assertion(
                    connection,
                    principal=candidate_principal,
                    assertion=candidate_assertion,
                    mission_id=mission_id,
                    operation=PrincipalOperation.WORK_HANDOFF_ACCEPT,
                    material=candidate_material,
                    effect=candidate_effect,
                    ledger=next_ledger,
                    consumed_at=transferred_at,
                )
                connection.execute(
                    """
                    INSERT INTO collaboration_work_item_handoffs(
                        handoff_id,
                        mission_id,
                        plan_id,
                        plan_content_sha256,
                        work_item_id,
                        planned_owner_profile_id,
                        candidate_profile_id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        handoff_scope,
                        qualification_basis,
                        qualification_command_id,
                        candidate_profile_version,
                        candidate_registry_status,
                        reason_code,
                        reason,
                        handoff_sha256,
                        transferred_at,
                        owner_issuer,
                        owner_assertion_id,
                        candidate_issuer,
                        candidate_assertion_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        handoff_id,
                        mission_id,
                        plan.plan_id,
                        plan.content_sha256,
                        work_item_id,
                        item.owner_profile_id,
                        candidate.id,
                        expected_generation,
                        previous_transition_id,
                        expected_lease_expires_at,
                        HANDOFF_SCOPE,
                        QUALIFICATION_BASIS,
                        item.command_id,
                        candidate.version,
                        candidate.status,
                        reason_code,
                        reason,
                        handoff_hash,
                        transferred_at,
                        owner_assertion.issuer,
                        owner_assertion.assertion_id,
                        candidate_assertion.issuer,
                        candidate_assertion.assertion_id,
                    ),
                )
                self._store._verify_phase4_mission_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=policies,
                    registry=self._registry,
                )
                owner_use = self._existing_use(
                    connection,
                    owner_assertion,
                )
                candidate_use = self._existing_use(
                    connection,
                    candidate_assertion,
                )
                if owner_use is None or candidate_use is None:
                    raise StoreIntegrityError(
                        "Work handoff durable state is incomplete"
                    )
                row = self._for_assertions(
                    connection,
                    owner_assertion,
                    candidate_assertion,
                )
                receipt = self._receipt(
                    row,
                    owner_use,
                    candidate_use,
                )
                connection.commit()
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Authenticated work handoff conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist authenticated work handoff"
            ) from exc

    def get(
        self,
        handoff_id: str,
    ) -> AuthenticatedWorkHandoffReceipt:
        """Return one verified specialist handoff receipt."""

        try:
            with self._store._read_connection() as connection:
                row = connection.execute(
                    """
                    SELECT *
                    FROM collaboration_work_item_handoffs
                    WHERE handoff_id = ?
                    """,
                    (handoff_id,),
                ).fetchone()
                if row is None:
                    raise StoreError(
                        "Unknown work handoff: " + handoff_id
                    )
                self._store.verify_store(self._registry)
                owner_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (
                        row["owner_issuer"],
                        row["owner_assertion_id"],
                    ),
                ).fetchone()
                candidate_use = connection.execute(
                    """
                    SELECT *
                    FROM principal_assertion_uses
                    WHERE issuer = ? AND assertion_id = ?
                    """,
                    (
                        row["candidate_issuer"],
                        row["candidate_assertion_id"],
                    ),
                ).fetchone()
                if owner_use is None or candidate_use is None:
                    raise StoreIntegrityError(
                        "Work handoff assertion provenance is missing"
                    )
                return self._receipt(
                    row,
                    owner_use,
                    candidate_use,
                )
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not read authenticated work handoff"
            ) from exc

    @staticmethod
    def _assertion(
        assertion: PrincipalAssertion,
        label: str,
    ) -> PrincipalAssertion:
        if not isinstance(assertion, PrincipalAssertion):
            raise PrincipalAuthenticationError(
                f"{label} must be a PrincipalAssertion"
            )
        return PrincipalAssertion.from_dict(assertion.to_dict())

    @staticmethod
    def _validate_target(
        mission_id: str,
        work_item_id: str,
    ) -> None:
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
    def _require_qualified_candidate(
        plan: CollaborationPlan,
        item: WorkItem,
        candidate: ExpertProfile,
        allowed_profile_ids: tuple[str, ...],
        control_profile_ids: tuple[str, ...],
        assurance_profile_ids: tuple[str, ...],
    ) -> None:
        candidate_item = next(
            (
                candidate_item
                for candidate_item in plan.work_items
                if candidate_item.kind
                is WorkItemKind.SPECIALIST_ANALYSIS
                and candidate_item.owner_profile_id == candidate.id
            ),
            None,
        )
        if (
            item.kind is not WorkItemKind.SPECIALIST_ANALYSIS
            or item.command_id is None
            or item.group_id is None
        ):
            raise StoreConflictError(
                "Only specialist analysis work can be handed off"
            )
        if (
            candidate.id == item.owner_profile_id
            or candidate.id not in allowed_profile_ids
            or candidate.id in control_profile_ids
            or candidate.id in assurance_profile_ids
            or candidate.kind is not ProfileKind.SPECIALIST
            or candidate.status != "qualified"
            or candidate.command_id != item.command_id
            or candidate.group_id != item.group_id
            or candidate_item is None
            or candidate_item.command_id != item.command_id
            or candidate_item.group_id != item.group_id
            or not candidate.max_autonomous_tier.allows(
                item.action_tier_ceiling
            )
        ):
            raise PrincipalAuthenticationError(
                "Work handoff candidate is not an assigned qualified "
                "specialist in the same command"
            )

    @staticmethod
    def _operation_intent(
        plan: CollaborationPlan,
        item: WorkItem,
        candidate: ExpertProfile,
        owner_assertion: PrincipalAssertion,
        candidate_assertion: PrincipalAssertion,
        *,
        principal_profile_id: str,
        expected_generation: int,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
        reason_code: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "candidate_assertion_id": (
                candidate_assertion.assertion_id
            ),
            "candidate_issuer": candidate_assertion.issuer,
            "candidate_profile_id": candidate.id,
            "candidate_profile_version": candidate.version,
            "candidate_registry_status": candidate.status,
            "expected_generation": expected_generation,
            "expected_lease_expires_at": (
                expected_lease_expires_at
            ),
            "handoff_scope": HANDOFF_SCOPE,
            "mission_id": plan.mission_id,
            "owner_assertion_id": owner_assertion.assertion_id,
            "owner_issuer": owner_assertion.issuer,
            "plan_content_sha256": plan.content_sha256,
            "plan_id": plan.plan_id,
            "planned_owner_profile_id": item.owner_profile_id,
            "previous_transition_id": previous_transition_id,
            "principal_profile_id": principal_profile_id,
            "qualification_basis": QUALIFICATION_BASIS,
            "qualification_command_id": item.command_id,
            "reason": reason,
            "reason_code": reason_code,
            "work_item_id": item.work_item_id,
            "work_item_kind": item.kind.value,
        }

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
    def _require_exact_inactive_fence(
        latest: sqlite3.Row | None,
        now: datetime,
        *,
        expected_generation: int,
        previous_transition_id: str | None,
        expected_lease_expires_at: str | None,
    ) -> None:
        generation = 0 if latest is None else int(latest["generation"])
        durable_previous = (
            None
            if latest is None
            else str(latest["transition_id"])
        )
        durable_expiry = (
            None
            if latest is None
            else str(latest["lease_expires_at"])
        )
        if (
            expected_generation != generation
            or previous_transition_id != durable_previous
            or expected_lease_expires_at != durable_expiry
        ):
            raise StoreConflictError("Work handoff fence changed")
        if latest is None:
            return
        if latest["transition_kind"] == "complete":
            raise StoreConflictError(
                "Completed work item cannot be handed off"
            )
        if (
            latest["transition_kind"] in {"claim", "renew"}
            and now
            < parse_timestamp(
                str(latest["lease_expires_at"]),
                "current work item lease_expires_at",
            )
        ):
            raise StoreConflictError(
                "Active work item lease cannot be handed off"
            )

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
                "Stopped mission cannot hand off work"
            )

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
    def _handoff_for_item(
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_handoffs
            WHERE plan_id = ? AND work_item_id = ?
            """,
            (plan_id, work_item_id),
        ).fetchone()

    @staticmethod
    def _for_assertions(
        connection: sqlite3.Connection,
        owner_assertion: PrincipalAssertion,
        candidate_assertion: PrincipalAssertion,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT *
            FROM collaboration_work_item_handoffs
            WHERE owner_issuer = ?
              AND owner_assertion_id = ?
              AND candidate_issuer = ?
              AND candidate_assertion_id = ?
            """,
            (
                owner_assertion.issuer,
                owner_assertion.assertion_id,
                candidate_assertion.issuer,
                candidate_assertion.assertion_id,
            ),
        ).fetchone()
        if row is None:
            raise StoreConflictError(
                "Work handoff assertions have no durable handoff"
            )
        return row

    @staticmethod
    def _effect(
        handoff_id: str,
        operation: PrincipalOperation,
        payload: dict[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": handoff_id,
            "effect_kind": operation.value,
            "payload": payload,
            "recorded_at": recorded_at,
            "schema_version": 1,
        }

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
        effects_hash = principal_assertion_effects_hash((effect_hash,))
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
                "Mission principal ledger changed during work handoff"
            )
        return entry_hash

    @staticmethod
    def _receipt(
        row: sqlite3.Row,
        owner_use: sqlite3.Row,
        candidate_use: sqlite3.Row,
    ) -> AuthenticatedWorkHandoffReceipt:
        owner_assertion = PrincipalAssertion.from_dict(
            json.loads(str(owner_use["assertion_json"]))
        )
        candidate_assertion = PrincipalAssertion.from_dict(
            json.loads(str(candidate_use["assertion_json"]))
        )
        return AuthenticatedWorkHandoffReceipt(
            handoff_id=str(row["handoff_id"]),
            handoff_sha256=str(row["handoff_sha256"]),
            mission_id=str(row["mission_id"]),
            plan_id=str(row["plan_id"]),
            plan_content_sha256=str(row["plan_content_sha256"]),
            work_item_id=str(row["work_item_id"]),
            planned_owner_profile_id=str(
                row["planned_owner_profile_id"]
            ),
            candidate_profile_id=str(row["candidate_profile_id"]),
            expected_generation=int(row["expected_generation"]),
            previous_transition_id=(
                None
                if row["previous_transition_id"] is None
                else str(row["previous_transition_id"])
            ),
            expected_lease_expires_at=(
                None
                if row["expected_lease_expires_at"] is None
                else str(row["expected_lease_expires_at"])
            ),
            handoff_scope=str(row["handoff_scope"]),
            qualification_basis=str(row["qualification_basis"]),
            qualification_command_id=str(
                row["qualification_command_id"]
            ),
            candidate_profile_version=str(
                row["candidate_profile_version"]
            ),
            candidate_registry_status=str(
                row["candidate_registry_status"]
            ),
            reason_code=str(row["reason_code"]),
            reason=str(row["reason"]),
            transferred_at=str(row["transferred_at"]),
            owner_issuer=str(owner_use["issuer"]),
            owner_assertion_id=str(owner_use["assertion_id"]),
            owner_assertion_sha256=str(owner_use["assertion_hash"]),
            owner_operation_intent_sha256=(
                owner_assertion.operation_intent_sha256
            ),
            owner_effects_sha256=str(owner_use["effects_hash"]),
            owner_ledger_entry_sha256=str(owner_use["entry_hash"]),
            candidate_issuer=str(candidate_use["issuer"]),
            candidate_assertion_id=str(
                candidate_use["assertion_id"]
            ),
            candidate_assertion_sha256=str(
                candidate_use["assertion_hash"]
            ),
            candidate_operation_intent_sha256=(
                candidate_assertion.operation_intent_sha256
            ),
            candidate_effects_sha256=str(
                candidate_use["effects_hash"]
            ),
            candidate_ledger_entry_sha256=str(
                candidate_use["entry_hash"]
            ),
        )


__all__ = [
    "AuthenticatedWorkHandoffReceipt",
    "AuthenticatedWorkHandoffService",
    "HANDOFF_SCOPE",
    "QUALIFICATION_BASIS",
]
