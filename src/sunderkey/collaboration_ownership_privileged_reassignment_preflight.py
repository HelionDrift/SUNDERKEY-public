"""Verified read-only preflight for privileged ownership reassignment."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
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
from .collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflightService,
)
from .errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertProfile, ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
)
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

PREFLIGHT_DOMAIN = (
    "sunderkey.collaboration-ownership-privileged-reassignment-preflight.v1"
)
QUALIFICATION_BASIS = "registry_equivalent_privileged_role_v1"


@dataclass(frozen=True)
class CollaborationOwnershipPrivilegedReassignmentPreflight:
    """Content-addressed admission result for one privileged reassignment."""

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
    work_item_kind: str
    planned_owner_id: str
    current_owner_id: str
    control_role_replacement: bool
    second_authority_required: bool
    required_authority_count: int
    replacement_profile_id: str
    replacement_profile_version: str
    replacement_registry_status: str
    replacement_profile_kind: str
    replacement_category: str | None
    replacement_command_id: str | None
    replacement_group_id: str | None
    chain_id: str
    head_entry_id: str
    head_sha256: str
    owner_epoch: int
    active_delegation_depth: int
    entry_count: int

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CollaborationOwnershipPrivilegedReassignmentPreflight:
        """Parse and verify one exact privileged reassignment preflight."""

        if not isinstance(raw, dict):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight must be an object"
            )
        fields = {
            "schema_version",
            "entry",
            "evaluated_at",
            "store_id",
            "mission_context_sha256",
            "policy_binding",
            "work_fence",
            "role_binding",
            "replacement_qualification",
            "chain_projection",
            "admission_status",
            "authentication_status",
            "runtime_effect",
            "preflight_id",
            "preflight_sha256",
        }
        if set(raw) != fields or raw.get("schema_version") != 1:
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight fields are invalid"
            )
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
            "role_binding": {
                "work_item_kind",
                "planned_owner_id",
                "current_owner_id",
                "control_role_replacement",
                "second_authority_required",
                "required_authority_count",
            },
            "replacement_qualification": {
                "profile_id",
                "profile_version",
                "registry_status",
                "profile_kind",
                "category",
                "command_id",
                "group_id",
                "qualification_basis",
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
                    f"Privileged ownership reassignment preflight {name} "
                    "fields are invalid"
                )
        policy = raw["policy_binding"]
        fence = raw["work_fence"]
        role = raw["role_binding"]
        qualification = raw["replacement_qualification"]
        projection = raw["chain_projection"]
        required_strings = (
            raw["evaluated_at"],
            raw["store_id"],
            raw["mission_context_sha256"],
            policy["policy_id"],
            policy["policy_sha256"],
            role["work_item_kind"],
            role["planned_owner_id"],
            role["current_owner_id"],
            qualification["profile_id"],
            qualification["profile_version"],
            qualification["registry_status"],
            qualification["profile_kind"],
            qualification["qualification_basis"],
            projection["chain_id"],
            projection["head_entry_id"],
            projection["head_sha256"],
            projection["current_owner_id"],
            raw["preflight_id"],
            raw["preflight_sha256"],
        )
        optional_strings = (
            fence["previous_transition_id"],
            fence["expected_lease_expires_at"],
            qualification["category"],
            qualification["command_id"],
            qualification["group_id"],
        )
        if any(not isinstance(value, str) or not value for value in required_strings):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight text is invalid"
            )
        if any(
            value is not None and (not isinstance(value, str) or not value)
            for value in optional_strings
        ):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight optional text is invalid"
            )
        integers = (
            policy["policy_version"],
            policy["maximum_delegation_depth"],
            fence["expected_generation"],
            role["required_authority_count"],
            projection["owner_epoch"],
            projection["active_delegation_depth"],
            projection["entry_count"],
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in integers
        ):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight integer is invalid"
            )
        if (
            policy["policy_version"] < 1
            or policy["maximum_delegation_depth"] < 1
            or projection["owner_epoch"] < 1
            or projection["entry_count"] < 1
        ):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight bounds are invalid"
            )
        try:
            work_item_kind = WorkItemKind(role["work_item_kind"])
            profile_kind = ProfileKind(qualification["profile_kind"])
        except ValueError as exc:
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight role is invalid"
            ) from exc
        control_replacement = role["control_role_replacement"]
        second_required = role["second_authority_required"]
        if (
            not isinstance(control_replacement, bool)
            or not isinstance(second_required, bool)
            or control_replacement != second_required
            or control_replacement
            != (work_item_kind is WorkItemKind.CONTROL_REVIEW)
            or work_item_kind is WorkItemKind.SPECIALIST_ANALYSIS
            or profile_kind not in {ProfileKind.DOMAIN_COMMANDER, ProfileKind.SHARED}
            or role["required_authority_count"]
            != (4 if control_replacement else 3)
            or qualification["registry_status"] not in {"defined", "qualified"}
            or qualification["qualification_basis"] != QUALIFICATION_BASIS
            or projection["current_owner_id"] != qualification["profile_id"]
            or raw.get("admission_status")
            != "admissible_pending_privileged_authenticated_commit"
            or raw.get("authentication_status") != "not_performed"
            or raw.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight state is invalid"
            )
        try:
            evaluated_at = datetime.fromisoformat(
                raw["evaluated_at"].removesuffix("Z") + "+00:00"
            )
            entry = CollaborationOwnershipChainEntry.from_dict(raw["entry"])
            entry_document = entry.to_dict()
            WorkItemKind(role["work_item_kind"])
            ProfileKind(qualification["profile_kind"])
            if fence["expected_lease_expires_at"] is not None:
                parse_timestamp(
                    fence["expected_lease_expires_at"],
                    "privileged ownership reassignment expected lease expiry",
                )
            parsed = cls(
                entry=entry,
                evaluated_at=raw["evaluated_at"],
                store_id=raw["store_id"],
                mission_context_sha256=raw["mission_context_sha256"],
                policy_id=policy["policy_id"],
                policy_sha256=policy["policy_sha256"],
                policy_version=int(policy["policy_version"]),
                maximum_delegation_depth=int(
                    policy["maximum_delegation_depth"]
                ),
                expected_generation=int(fence["expected_generation"]),
                previous_transition_id=fence["previous_transition_id"],
                expected_lease_expires_at=fence["expected_lease_expires_at"],
                work_item_kind=role["work_item_kind"],
                planned_owner_id=role["planned_owner_id"],
                current_owner_id=role["current_owner_id"],
                control_role_replacement=control_replacement,
                second_authority_required=second_required,
                required_authority_count=int(role["required_authority_count"]),
                replacement_profile_id=qualification["profile_id"],
                replacement_profile_version=qualification["profile_version"],
                replacement_registry_status=qualification["registry_status"],
                replacement_profile_kind=qualification["profile_kind"],
                replacement_category=qualification["category"],
                replacement_command_id=qualification["command_id"],
                replacement_group_id=qualification["group_id"],
                chain_id=projection["chain_id"],
                head_entry_id=projection["head_entry_id"],
                head_sha256=projection["head_sha256"],
                owner_epoch=int(projection["owner_epoch"]),
                active_delegation_depth=int(
                    projection["active_delegation_depth"]
                ),
                entry_count=int(projection["entry_count"]),
            )
        except (KeyError, StoreIntegrityError, TypeError, ValueError) as exc:
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight is invalid"
            ) from exc
        if (
            not raw["evaluated_at"].endswith("Z")
            or evaluated_at.utcoffset() != UTC.utcoffset(evaluated_at)
            or entry_document["transition_kind"] != "privileged_reassignment"
            or entry_document["planned_owner_id"] != role["planned_owner_id"]
            or entry_document["from_owner_id"] != role["current_owner_id"]
            or entry_document["to_owner_id"] != qualification["profile_id"]
            or entry_document["control_role_replacement"] != control_replacement
            or entry_document["chain_id"] != projection["chain_id"]
            or entry_document["entry_id"] != projection["head_entry_id"]
            or entry_document["entry_sha256"] != projection["head_sha256"]
            or entry_document["owner_epoch"] != projection["owner_epoch"]
            or entry_document["sequence"] != projection["entry_count"]
        ):
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight bindings are invalid"
            )
        if parsed.to_dict() != raw:
            raise CollaborationPlanError(
                "Privileged ownership reassignment preflight identity or "
                "content is invalid"
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
            "role_binding": {
                "work_item_kind": self.work_item_kind,
                "planned_owner_id": self.planned_owner_id,
                "current_owner_id": self.current_owner_id,
                "control_role_replacement": self.control_role_replacement,
                "second_authority_required": self.second_authority_required,
                "required_authority_count": self.required_authority_count,
            },
            "replacement_qualification": {
                "profile_id": self.replacement_profile_id,
                "profile_version": self.replacement_profile_version,
                "registry_status": self.replacement_registry_status,
                "profile_kind": self.replacement_profile_kind,
                "category": self.replacement_category,
                "command_id": self.replacement_command_id,
                "group_id": self.replacement_group_id,
                "qualification_basis": QUALIFICATION_BASIS,
            },
            "chain_projection": {
                "chain_id": self.chain_id,
                "head_entry_id": self.head_entry_id,
                "head_sha256": self.head_sha256,
                "current_owner_id": self.replacement_profile_id,
                "owner_epoch": self.owner_epoch,
                "active_delegation_depth": self.active_delegation_depth,
                "entry_count": self.entry_count,
            },
            "admission_status": (
                "admissible_pending_privileged_authenticated_commit"
            ),
            "authentication_status": "not_performed",
            "runtime_effect": "none",
        }
        digest = sha256_text(
            canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        )
        return {
            **body,
            "preflight_id": "OPF-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }


class CollaborationOwnershipPrivilegedReassignmentPreflightService:
    """Verify one exact privileged reassignment without consuming authority."""

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
    ) -> CollaborationOwnershipPrivilegedReassignmentPreflight:
        """Evaluate one reassignment against verified live state."""

        if not isinstance(entry, CollaborationOwnershipChainEntry):
            raise TypeError("entry must be a CollaborationOwnershipChainEntry")
        parsed = CollaborationOwnershipChainEntry.from_dict(entry.to_dict())
        evaluated_at = format_timestamp(self._clock())
        evaluated_time = parse_timestamp(
            evaluated_at,
            "privileged ownership reassignment preflight evaluated_at",
        )
        try:
            with self._store._read_connection() as connection:
                return self._evaluate(
                    connection,
                    parsed,
                    evaluated_at=evaluated_at,
                    evaluated_time=evaluated_time,
                )
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not evaluate privileged ownership reassignment"
            ) from exc

    def _evaluate(
        self,
        connection: sqlite3.Connection,
        entry: CollaborationOwnershipChainEntry,
        *,
        evaluated_at: str,
        evaluated_time: datetime,
    ) -> CollaborationOwnershipPrivilegedReassignmentPreflight:
        parsed = CollaborationOwnershipChainEntry.from_dict(entry.to_dict())
        document = parsed.to_dict()
        if document["transition_kind"] != "privileged_reassignment":
            raise StoreConflictError(
                "Preflight requires a privileged reassignment entry"
            )
        mission_id = str(document["mission_id"])
        identity, _, mission, _, ledger = (
            self._work._activation._verified_mission_state(
                connection,
                mission_id,
            )
        )
        AuthenticatedWorkHandoffService._require_active(connection, mission_id)
        self._work._activation._require_runtime_not_before_state(
            connection,
            mission,
            ledger,
            evaluated_time,
        )
        _, plan = self._work._load_activation(connection, mission_id)
        policy = self._policies._latest_policy(connection, mission_id)
        if policy is None:
            raise StoreConflictError(
                "Mission has no committed reconfiguration policy"
            )
        policy_document = policy.to_dict()
        self._require_active_policy(
            policy_document,
            plan.plan_id,
            plan.content_sha256,
            evaluated_time,
        )
        item = self._work._work_item(plan, str(document["work_item_id"]))
        maximum_depth = int(
            policy_document["selected_parameters"]["maximum_delegation_depth"]
        )
        existing = CollaborationOwnershipTransitionPreflightService._ownership_entries(
            connection,
            plan.plan_id,
            item.work_item_id,
        )
        current_owner_id = self._require_entry_anchor(
            document,
            item=item,
            plan_id=plan.plan_id,
            plan_sha256=plan.content_sha256,
            existing_entries=existing,
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
                "Legacy one-time handoff must be migrated before reassignment"
            )
        if self._work._cancellation_ids_for_item(
            connection,
            plan.plan_id,
            item.work_item_id,
        ):
            raise StoreConflictError("Cancelled work item cannot be reassigned")
        if (
            self._work._recovery_for_item(
                connection,
                plan.plan_id,
                item.work_item_id,
            )
            is not None
        ):
            raise StoreConflictError("Recovered work item cannot be reassigned")
        latest = self._work._latest_transition(
            connection,
            plan.plan_id,
            item.work_item_id,
        )
        generation = 0 if latest is None else int(latest["generation"])
        previous_transition_id = (
            None if latest is None else str(latest["transition_id"])
        )
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
        replacement = self._registry.profile(str(document["to_owner_id"]))
        current_owner = self._registry.profile(current_owner_id)
        self._require_equivalent_replacement(
            item,
            current_owner,
            replacement,
        )
        control_replacement = item.kind is WorkItemKind.CONTROL_REVIEW
        self._require_authority_shape(document, control_replacement)
        CollaborationOwnershipTransitionPreflightService._require_transition_window(
            document,
            policy_document,
            evaluated_time,
        )
        try:
            projection = validate_collaboration_ownership_chain(
                (*existing, parsed),
                maximum_delegation_depth=maximum_depth,
            )
        except CollaborationPlanError as exc:
            raise StoreConflictError(
                "Privileged reassignment does not produce a valid chain"
            ) from exc
        return CollaborationOwnershipPrivilegedReassignmentPreflight(
            entry=parsed,
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
            work_item_kind=item.kind.value,
            planned_owner_id=item.owner_profile_id,
            current_owner_id=current_owner_id,
            control_role_replacement=control_replacement,
            second_authority_required=control_replacement,
            required_authority_count=4 if control_replacement else 3,
            replacement_profile_id=replacement.id,
            replacement_profile_version=replacement.version,
            replacement_registry_status=replacement.status,
            replacement_profile_kind=replacement.kind.value,
            replacement_category=replacement.category,
            replacement_command_id=replacement.command_id,
            replacement_group_id=replacement.group_id,
            chain_id=projection.chain_id,
            head_entry_id=projection.head_entry_id,
            head_sha256=projection.head_sha256,
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
        if not policy["transition_activation"][
            "privileged_role_reassignment"
        ]:
            raise StoreConflictError(
                "Committed policy does not activate privileged reassignment"
            )
        effective_at = parse_timestamp(
            str(policy["effective_at"]),
            "mission policy effective_at",
        )
        expires_at = parse_timestamp(
            str(policy["expires_at"]),
            "mission policy expires_at",
        )
        if evaluated_at < effective_at or evaluated_at >= expires_at:
            raise StoreConflictError(
                "Committed mission policy is outside its active window"
            )

    @staticmethod
    def _require_entry_anchor(
        entry: dict[str, Any],
        *,
        item: WorkItem,
        plan_id: str,
        plan_sha256: str,
        existing_entries: tuple[CollaborationOwnershipChainEntry, ...],
        maximum_delegation_depth: int,
    ) -> str:
        if (
            entry["collaboration_plan_id"] != plan_id
            or entry["collaboration_plan_sha256"] != plan_sha256
            or entry["planned_owner_id"] != item.owner_profile_id
            or entry["work_item_objective_sha256"]
            != collaboration_work_item_objective_sha256(item)
        ):
            raise StoreConflictError(
                "Privileged reassignment does not bind the active work item"
            )
        if not existing_entries:
            if (
                entry["sequence"] != 1
                or entry["owner_epoch"] != 1
                or entry["previous_entry_sha256"] is not None
                or entry["from_owner_id"] != item.owner_profile_id
            ):
                raise StoreConflictError(
                    "Initial privileged reassignment does not bind the planned owner"
                )
            return item.owner_profile_id
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
                "Privileged reassignment does not continue the exact chain head"
            )
        return current.current_owner_id

    @staticmethod
    def _require_equivalent_replacement(
        item: WorkItem,
        current_owner: ExpertProfile,
        replacement: ExpertProfile,
    ) -> None:
        allowed_statuses = {"defined", "qualified"}
        equivalent = False
        if current_owner.kind is ProfileKind.DOMAIN_COMMANDER:
            equivalent = (
                replacement.kind is ProfileKind.DOMAIN_COMMANDER
                and replacement.command_id == item.command_id
                and replacement.group_id == item.group_id
            )
        elif current_owner.kind is ProfileKind.SHARED:
            equivalent = (
                replacement.kind is ProfileKind.SHARED
                and replacement.category == current_owner.category
            )
        if (
            item.kind is WorkItemKind.SPECIALIST_ANALYSIS
            or replacement.id == current_owner.id
            or replacement.status not in allowed_statuses
            or not replacement.max_autonomous_tier.allows(
                item.action_tier_ceiling
            )
            or not equivalent
        ):
            raise PrincipalAuthenticationError(
                "Replacement is not an assigned equivalent privileged role"
            )

    @staticmethod
    def _require_authority_shape(
        entry: dict[str, Any],
        control_replacement: bool,
    ) -> None:
        bindings = entry["authority_bindings"]
        second = bindings["second_control_or_mission_authority_id"]
        if (
            entry["control_role_replacement"] != control_replacement
            or control_replacement != (second is not None)
        ):
            raise StoreConflictError(
                "Privileged reassignment authority shape does not match the role"
            )
        assertion_ids = {
            bindings["current_owner_authorization_id"],
            bindings["proposed_owner_acceptance_id"],
            bindings["independent_control_approval_id"],
        }
        if second is not None:
            assertion_ids.add(second)
        if None in assertion_ids or len(assertion_ids) != (
            4 if control_replacement else 3
        ):
            raise StoreConflictError(
                "Privileged reassignment requires distinct authority assertions"
            )


def load_collaboration_ownership_privileged_reassignment_preflight(
    path: str | Path,
) -> CollaborationOwnershipPrivilegedReassignmentPreflight:
    """Load and verify one privileged reassignment preflight artifact."""

    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            "Could not load privileged ownership reassignment preflight: "
            f"{resolved}"
        ) from exc
    return CollaborationOwnershipPrivilegedReassignmentPreflight.from_dict(raw)


__all__ = [
    "CollaborationOwnershipPrivilegedReassignmentPreflight",
    "CollaborationOwnershipPrivilegedReassignmentPreflightService",
    "load_collaboration_ownership_privileged_reassignment_preflight",
]
