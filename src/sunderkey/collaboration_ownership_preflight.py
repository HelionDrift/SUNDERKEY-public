"""Verified policy-backed ownership transition preflight."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .authenticated_work_handoffs import AuthenticatedWorkHandoffService
from .collaboration import WorkItem, WorkItemKind
from .collaboration_ownership_chain import (
    CollaborationOwnershipChainEntry,
    collaboration_work_item_objective_sha256,
    validate_collaboration_ownership_chain,
)
from .errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
)
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

PREFLIGHT_DOMAIN = "sunderkey.collaboration-ownership-transition-preflight.v1"
QUALIFICATION_BASIS = "assigned_qualified_same_command_v1"


@dataclass(frozen=True)
class CollaborationOwnershipTransitionPreflight:
    """Content-addressed read-only admission result for one transition."""

    entry: CollaborationOwnershipChainEntry
    evaluated_at: str
    store_id: str
    mission_context_sha256: str
    policy_id: str
    policy_sha256: str
    policy_version: int
    maximum_delegation_depth: int
    expected_generation: int
    previous_transition_id: str | None
    expected_lease_expires_at: str | None
    candidate_profile_id: str
    candidate_profile_version: str
    candidate_registry_status: str
    qualification_command_id: str
    qualification_group_id: str
    chain_id: str
    head_entry_id: str
    head_sha256: str
    current_owner_id: str
    owner_epoch: int
    active_delegation_depth: int
    entry_count: int

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationOwnershipTransitionPreflight:
        """Parse and verify one content-addressed preflight document."""

        if not isinstance(raw, dict):
            raise CollaborationPlanError("Ownership preflight must be an object")
        fields = {
            "schema_version",
            "entry",
            "evaluated_at",
            "store_id",
            "mission_context_sha256",
            "policy_binding",
            "work_fence",
            "candidate_qualification",
            "chain_projection",
            "admission_status",
            "authentication_status",
            "runtime_effect",
            "preflight_id",
            "preflight_sha256",
        }
        if set(raw) != fields or raw.get("schema_version") != 1:
            raise CollaborationPlanError("Ownership preflight fields are invalid")
        nested_fields = {
            "policy_binding": {
                "policy_id",
                "policy_sha256",
                "policy_version",
                "maximum_delegation_depth",
            },
            "work_fence": {
                "expected_generation",
                "previous_transition_id",
                "expected_lease_expires_at",
            },
            "candidate_qualification": {
                "profile_id",
                "profile_version",
                "registry_status",
                "qualification_basis",
                "command_id",
                "group_id",
            },
            "chain_projection": {
                "chain_id",
                "head_entry_id",
                "head_sha256",
                "current_owner_id",
                "owner_epoch",
                "active_delegation_depth",
                "entry_count",
            },
        }
        for name, expected in nested_fields.items():
            value = raw.get(name)
            if not isinstance(value, dict) or set(value) != expected:
                raise CollaborationPlanError(
                    f"Ownership preflight {name} fields are invalid"
                )
        policy = raw["policy_binding"]
        fence = raw["work_fence"]
        candidate = raw["candidate_qualification"]
        projection = raw["chain_projection"]
        integer_values = (
            policy["policy_version"],
            policy["maximum_delegation_depth"],
            fence["expected_generation"],
            projection["owner_epoch"],
            projection["active_delegation_depth"],
            projection["entry_count"],
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in integer_values
        ):
            raise CollaborationPlanError("Ownership preflight integer is invalid")
        if (
            policy["policy_version"] < 1
            or policy["maximum_delegation_depth"] < 1
            or projection["owner_epoch"] < 1
            or projection["entry_count"] < 1
            or candidate["qualification_basis"] != QUALIFICATION_BASIS
            or raw.get("admission_status")
            != "admissible_pending_authenticated_commit"
            or raw.get("authentication_status") != "not_performed"
            or raw.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Ownership preflight state is invalid")
        try:
            datetime.fromisoformat(
                str(raw["evaluated_at"]).removesuffix("Z") + "+00:00"
            )
            parsed = cls(
                entry=CollaborationOwnershipChainEntry.from_dict(raw["entry"]),
                evaluated_at=str(raw["evaluated_at"]),
                store_id=str(raw["store_id"]),
                mission_context_sha256=str(raw["mission_context_sha256"]),
                policy_id=str(policy["policy_id"]),
                policy_sha256=str(policy["policy_sha256"]),
                policy_version=int(policy["policy_version"]),
                maximum_delegation_depth=int(policy["maximum_delegation_depth"]),
                expected_generation=int(fence["expected_generation"]),
                previous_transition_id=fence["previous_transition_id"],
                expected_lease_expires_at=fence["expected_lease_expires_at"],
                candidate_profile_id=str(candidate["profile_id"]),
                candidate_profile_version=str(candidate["profile_version"]),
                candidate_registry_status=str(candidate["registry_status"]),
                qualification_command_id=str(candidate["command_id"]),
                qualification_group_id=str(candidate["group_id"]),
                chain_id=str(projection["chain_id"]),
                head_entry_id=str(projection["head_entry_id"]),
                head_sha256=str(projection["head_sha256"]),
                current_owner_id=str(projection["current_owner_id"]),
                owner_epoch=int(projection["owner_epoch"]),
                active_delegation_depth=int(
                    projection["active_delegation_depth"]
                ),
                entry_count=int(projection["entry_count"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CollaborationPlanError("Ownership preflight is invalid") from exc
        if parsed.to_dict() != raw:
            raise CollaborationPlanError(
                "Ownership preflight identity or content is invalid"
            )
        return parsed

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": 1,
            "entry": self.entry.to_dict(),
            "evaluated_at": self.evaluated_at,
            "store_id": self.store_id,
            "mission_context_sha256": self.mission_context_sha256,
            "policy_binding": {
                "policy_id": self.policy_id,
                "policy_sha256": self.policy_sha256,
                "policy_version": self.policy_version,
                "maximum_delegation_depth": self.maximum_delegation_depth,
            },
            "work_fence": {
                "expected_generation": self.expected_generation,
                "previous_transition_id": self.previous_transition_id,
                "expected_lease_expires_at": self.expected_lease_expires_at,
            },
            "candidate_qualification": {
                "profile_id": self.candidate_profile_id,
                "profile_version": self.candidate_profile_version,
                "registry_status": self.candidate_registry_status,
                "qualification_basis": QUALIFICATION_BASIS,
                "command_id": self.qualification_command_id,
                "group_id": self.qualification_group_id,
            },
            "chain_projection": {
                "chain_id": self.chain_id,
                "head_entry_id": self.head_entry_id,
                "head_sha256": self.head_sha256,
                "current_owner_id": self.current_owner_id,
                "owner_epoch": self.owner_epoch,
                "active_delegation_depth": self.active_delegation_depth,
                "entry_count": self.entry_count,
            },
            "admission_status": "admissible_pending_authenticated_commit",
            "authentication_status": "not_performed",
            "runtime_effect": "none",
        }
        digest = sha256_text(
            canonical_json(
                {
                    "domain": PREFLIGHT_DOMAIN,
                    "preflight": body,
                }
            )
        )
        return {
            **body,
            "preflight_id": "OTP-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }


class CollaborationOwnershipTransitionPreflightService:
    """Verify a supported D002 ownership transition without changing ownership."""

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
        self._work = AuthenticatedWorkItemLeaseService(
            store,
            registry,
            clock=self._clock,
        )
        self._policies = AuthenticatedCollaborationMissionPolicyService(
            store,
            registry,
            clock=self._clock,
        )

    def preflight(
        self,
        entry: CollaborationOwnershipChainEntry,
    ) -> CollaborationOwnershipTransitionPreflight:
        """Evaluate one exact ownership transition against verified live state."""

        if not isinstance(entry, CollaborationOwnershipChainEntry):
            raise TypeError("entry must be a CollaborationOwnershipChainEntry")
        parsed_entry = CollaborationOwnershipChainEntry.from_dict(entry.to_dict())
        now = self._clock()
        evaluated_at = format_timestamp(now)
        evaluated_time = parse_timestamp(
            evaluated_at,
            "ownership transition preflight evaluated_at",
        )
        try:
            with self._store._read_connection() as connection:
                return self._evaluate(
                    connection,
                    parsed_entry,
                    evaluated_at=evaluated_at,
                    evaluated_time=evaluated_time,
                )
        except sqlite3.Error as exc:
            raise StoreError("Could not evaluate collaboration ownership transition") from exc

    def _evaluate(
        self,
        connection: sqlite3.Connection,
        entry: CollaborationOwnershipChainEntry,
        *,
        evaluated_at: str,
        evaluated_time: datetime,
    ) -> CollaborationOwnershipTransitionPreflight:
        """Evaluate one transition using the caller's active transaction."""

        parsed_entry = CollaborationOwnershipChainEntry.from_dict(entry.to_dict())
        document = parsed_entry.to_dict()
        mission_id = str(document["mission_id"])
        (
            identity,
            _,
            mission,
            _,
            ledger,
        ) = self._work._activation._verified_mission_state(
            connection,
            mission_id,
        )
        AuthenticatedWorkHandoffService._require_active(
            connection,
            mission_id,
        )
        self._work._activation._require_runtime_not_before_state(
            connection,
            mission,
            ledger,
            evaluated_time,
        )
        _, plan = self._work._load_activation(connection, mission_id)
        policy = self._policies._latest_policy(connection, mission_id)
        if policy is None:
            raise StoreConflictError("Mission has no committed reconfiguration policy")
        policy_document = policy.to_dict()
        self._require_active_policy(
            policy_document,
            plan.plan_id,
            plan.content_sha256,
            evaluated_time,
        )
        item = self._work._work_item(
            plan,
            str(document["work_item_id"]),
        )
        maximum_depth = int(
            policy_document["selected_parameters"]["maximum_delegation_depth"]
        )
        existing_entries = self._ownership_entries(
            connection,
            plan.plan_id,
            item.work_item_id,
        )
        self._require_entry_anchor(
            document,
            plan_id=plan.plan_id,
            plan_sha256=plan.content_sha256,
            item_owner_id=item.owner_profile_id,
            item_objective_sha256=(collaboration_work_item_objective_sha256(item)),
            existing_entries=existing_entries,
            maximum_delegation_depth=maximum_depth,
        )
        if (
            self._work._handoff_for_item(
                connection,
                plan.plan_id,
                item.work_item_id,
            )
            is not None
        ):
            raise StoreConflictError(
                "Legacy one-time handoff must be migrated before ownership chaining"
            )
        if self._work._cancellation_ids_for_item(
            connection,
            plan.plan_id,
            item.work_item_id,
        ):
            raise StoreConflictError("Cancelled work item cannot enter an ownership chain")
        if (
            self._work._recovery_for_item(
                connection,
                plan.plan_id,
                item.work_item_id,
            )
            is not None
        ):
            raise StoreConflictError("Recovered work item cannot enter an ownership chain")
        latest = self._work._latest_transition(
            connection,
            plan.plan_id,
            item.work_item_id,
        )
        generation = 0 if latest is None else int(latest["generation"])
        previous_transition_id = None if latest is None else str(latest["transition_id"])
        expected_lease_expires_at = (
            None
            if latest is None or latest["lease_expires_at"] is None
            else str(latest["lease_expires_at"])
        )
        AuthenticatedWorkHandoffService._require_exact_inactive_fence(
            latest,
            evaluated_time,
            expected_generation=generation,
            previous_transition_id=previous_transition_id,
            expected_lease_expires_at=expected_lease_expires_at,
        )
        candidate = self._registry.profile(str(document["to_owner_id"]))
        if document["transition_kind"] == "return_to_planned_owner":
            self._require_qualified_planned_owner(
                item,
                candidate,
                mission.allowed_profile_ids,
                mission.control_profile_ids,
                mission.assurance_profile_ids,
            )
        else:
            AuthenticatedWorkHandoffService._require_qualified_candidate(
                plan,
                item,
                candidate,
                mission.allowed_profile_ids,
                mission.control_profile_ids,
                mission.assurance_profile_ids,
            )
        self._require_transition_window(
            document,
            policy_document,
            evaluated_time,
        )
        projection = validate_collaboration_ownership_chain(
            (*existing_entries, parsed_entry),
            maximum_delegation_depth=maximum_depth,
        )
        if item.command_id is None or item.group_id is None:
            raise StoreIntegrityError("Specialist work item command binding is missing")
        return CollaborationOwnershipTransitionPreflight(
            entry=parsed_entry,
            evaluated_at=evaluated_at,
            store_id=str(identity["store_id"]),
            mission_context_sha256=mission.context_hash,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            policy_version=int(policy_document["policy_version"]),
            maximum_delegation_depth=maximum_depth,
            expected_generation=generation,
            previous_transition_id=previous_transition_id,
            expected_lease_expires_at=expected_lease_expires_at,
            candidate_profile_id=candidate.id,
            candidate_profile_version=candidate.version,
            candidate_registry_status=candidate.status,
            qualification_command_id=item.command_id,
            qualification_group_id=item.group_id,
            chain_id=projection.chain_id,
            head_entry_id=projection.head_entry_id,
            head_sha256=projection.head_sha256,
            current_owner_id=projection.current_owner_id,
            owner_epoch=projection.owner_epoch,
            active_delegation_depth=projection.active_delegation_depth,
            entry_count=projection.entry_count,
        )

    @staticmethod
    def _require_active_policy(
        policy: dict[str, Any],
        plan_id: str,
        plan_sha256: str,
        evaluated_at: datetime,
    ) -> None:
        if (
            policy["collaboration_plan_id"] != plan_id
            or policy["collaboration_plan_sha256"] != plan_sha256
        ):
            raise StoreIntegrityError(
                "Committed policy does not bind the active collaboration plan"
            )
        if not policy["transition_activation"]["delegation_return_and_revocation"]:
            raise StoreConflictError("Committed policy does not activate ownership chaining")
        effective_at = parse_timestamp(
            str(policy["effective_at"]),
            "mission policy effective_at",
        )
        expires_at = parse_timestamp(
            str(policy["expires_at"]),
            "mission policy expires_at",
        )
        if evaluated_at < effective_at or evaluated_at >= expires_at:
            raise StoreConflictError("Committed mission policy is outside its active window")

    @staticmethod
    def _require_entry_anchor(
        entry: dict[str, Any],
        *,
        plan_id: str,
        plan_sha256: str,
        item_owner_id: str,
        item_objective_sha256: str,
        existing_entries: tuple[CollaborationOwnershipChainEntry, ...],
        maximum_delegation_depth: int,
    ) -> None:
        if (
            entry["collaboration_plan_id"] != plan_id
            or entry["collaboration_plan_sha256"] != plan_sha256
            or entry["planned_owner_id"] != item_owner_id
            or entry["work_item_objective_sha256"] != item_objective_sha256
        ):
            raise StoreConflictError("Ownership transition does not bind the active work item")
        if not existing_entries:
            if (
                entry["transition_kind"] != "delegation"
                or entry["sequence"] != 1
                or entry["owner_epoch"] != 1
                or entry["previous_entry_sha256"] is not None
                or entry["from_owner_id"] != item_owner_id
            ):
                raise StoreConflictError(
                    "Preflight requires an initial planned-owner delegation"
                )
            return
        try:
            current = validate_collaboration_ownership_chain(
                existing_entries,
                maximum_delegation_depth=maximum_delegation_depth,
            )
        except CollaborationPlanError as exc:
            raise StoreIntegrityError(
                "Durable ownership chain is invalid"
            ) from exc
        if (
            entry["chain_id"] != current.chain_id
            or entry["sequence"] != current.entry_count + 1
            or entry["owner_epoch"] != current.owner_epoch + 1
            or entry["previous_entry_sha256"] != current.head_sha256
            or entry["from_owner_id"] != current.current_owner_id
        ):
            raise StoreConflictError(
                "Ownership transition does not continue the exact chain head"
            )
        transition_kind = entry["transition_kind"]
        if transition_kind == "return_to_planned_owner":
            if (
                current.current_owner_id == item_owner_id
                or current.active_delegation_depth < 1
                or entry["to_owner_id"] != item_owner_id
            ):
                raise StoreConflictError(
                    "Preflight requires an exact return to the planned owner"
                )
            return
        if transition_kind != "delegation":
            raise StoreConflictError(
                "Preflight supports only delegation or planned-owner return"
            )

    @staticmethod
    def _ownership_entries(
        connection: sqlite3.Connection,
        plan_id: str,
        work_item_id: str,
    ) -> tuple[CollaborationOwnershipChainEntry, ...]:
        rows = connection.execute(
            """
            SELECT entry_json
            FROM collaboration_ownership_chain_entries
            WHERE plan_id = ? AND work_item_id = ?
            ORDER BY sequence
            """,
            (plan_id, work_item_id),
        ).fetchall()
        try:
            entries = tuple(
                CollaborationOwnershipChainEntry.from_dict(
                    loads_json_without_duplicate_keys(str(row["entry_json"]))
                )
                for row in rows
            )
        except (CollaborationPlanError, TypeError, ValueError) as exc:
            raise StoreIntegrityError(
                "Durable ownership chain is invalid"
            ) from exc
        if any(
            canonical_json(entry.to_dict()) != str(row["entry_json"])
            for entry, row in zip(entries, rows, strict=True)
        ):
            raise StoreIntegrityError("Durable ownership chain is not canonical")
        return entries

    @staticmethod
    def _require_qualified_planned_owner(
        item: WorkItem,
        candidate: Any,
        allowed_profile_ids: tuple[str, ...],
        control_profile_ids: tuple[str, ...],
        assurance_profile_ids: tuple[str, ...],
    ) -> None:
        if (
            item.kind is not WorkItemKind.SPECIALIST_ANALYSIS
            or item.command_id is None
            or item.group_id is None
            or candidate.id != item.owner_profile_id
            or candidate.id not in allowed_profile_ids
            or candidate.id in control_profile_ids
            or candidate.id in assurance_profile_ids
            or candidate.kind is not ProfileKind.SPECIALIST
            or candidate.status != "qualified"
            or candidate.command_id != item.command_id
            or candidate.group_id != item.group_id
            or not candidate.max_autonomous_tier.allows(item.action_tier_ceiling)
        ):
            raise PrincipalAuthenticationError(
                "Planned owner is not an assigned qualified specialist "
                "in the original command"
            )

    @staticmethod
    def _require_transition_window(
        entry: dict[str, Any],
        policy: dict[str, Any],
        evaluated_at: datetime,
    ) -> None:
        requested_at = parse_timestamp(
            str(entry["requested_at"]),
            "ownership transition requested_at",
        )
        expires_at = parse_timestamp(
            str(entry["expires_at"]),
            "ownership transition expires_at",
        )
        policy_effective_at = parse_timestamp(
            str(policy["effective_at"]),
            "mission policy effective_at",
        )
        policy_expires_at = parse_timestamp(
            str(policy["expires_at"]),
            "mission policy expires_at",
        )
        validity_seconds = int(policy["selected_parameters"]["reconfiguration_validity_seconds"])
        if (
            requested_at < policy_effective_at
            or expires_at > policy_expires_at
            or requested_at > evaluated_at
            or expires_at <= evaluated_at
            or expires_at - requested_at > timedelta(seconds=validity_seconds)
        ):
            raise StoreConflictError(
                "Ownership transition is outside the committed validity window"
            )


def load_collaboration_ownership_transition_preflight(
    path: str | Path,
) -> CollaborationOwnershipTransitionPreflight:
    """Load and verify one ownership-transition preflight artifact."""

    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load ownership-transition preflight: {resolved}"
        ) from exc
    return CollaborationOwnershipTransitionPreflight.from_dict(raw)


__all__ = [
    "CollaborationOwnershipTransitionPreflight",
    "CollaborationOwnershipTransitionPreflightService",
    "load_collaboration_ownership_transition_preflight",
]
