"""Verified read-only preflight for independent Control ownership revocation."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .authenticated_work_handoffs import AuthenticatedWorkHandoffService
from .collaboration_ownership_chain import (
    CollaborationOwnershipChainEntry,
    CollaborationOwnershipRevocation,
    apply_collaboration_ownership_revocation,
    collaboration_work_item_objective_sha256,
    validate_collaboration_ownership_chain,
)
from .collaboration_ownership_preflight import (
    QUALIFICATION_BASIS,
    CollaborationOwnershipTransitionPreflightService,
)
from .errors import (
    CollaborationPlanError,
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
from .validation import loads_json_without_duplicate_keys

PREFLIGHT_DOMAIN = "sunderkey.collaboration-ownership-revocation-preflight.v1"


@dataclass(frozen=True)
class CollaborationOwnershipRevocationPreflight:
    """Content-addressed admission result for one Control revocation."""

    revocation: CollaborationOwnershipRevocation
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
    planned_owner_profile_id: str
    planned_owner_profile_version: str
    planned_owner_registry_status: str
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
    def from_dict(cls, raw: Any) -> CollaborationOwnershipRevocationPreflight:
        """Parse and verify one exact revocation preflight document."""

        if not isinstance(raw, dict):
            raise CollaborationPlanError("Ownership revocation preflight must be an object")
        fields = {
            "schema_version",
            "revocation",
            "entry",
            "evaluated_at",
            "store_id",
            "mission_context_sha256",
            "policy_binding",
            "work_fence",
            "planned_owner_qualification",
            "chain_projection",
            "admission_status",
            "authentication_status",
            "runtime_effect",
            "preflight_id",
            "preflight_sha256",
        }
        if set(raw) != fields or raw.get("schema_version") != 1:
            raise CollaborationPlanError("Ownership revocation preflight fields are invalid")
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
            "planned_owner_qualification": {
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
                    f"Ownership revocation preflight {name} fields are invalid"
                )
        policy = raw["policy_binding"]
        fence = raw["work_fence"]
        qualification = raw["planned_owner_qualification"]
        projection = raw["chain_projection"]
        integers = (
            policy["policy_version"],
            policy["maximum_delegation_depth"],
            fence["expected_generation"],
            projection["owner_epoch"],
            projection["active_delegation_depth"],
            projection["entry_count"],
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in integers
        ):
            raise CollaborationPlanError(
                "Ownership revocation preflight integer is invalid"
            )
        if (
            policy["policy_version"] < 1
            or policy["maximum_delegation_depth"] < 1
            or projection["owner_epoch"] < 2
            or projection["entry_count"] < 2
            or projection["active_delegation_depth"] != 0
            or qualification["qualification_basis"] != QUALIFICATION_BASIS
            or raw.get("admission_status")
            != "admissible_pending_dual_authenticated_commit"
            or raw.get("authentication_status") != "not_performed"
            or raw.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Ownership revocation preflight state is invalid")
        try:
            datetime.fromisoformat(
                str(raw["evaluated_at"]).removesuffix("Z") + "+00:00"
            )
            parsed = cls(
                revocation=CollaborationOwnershipRevocation.from_dict(
                    raw["revocation"]
                ),
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
                planned_owner_profile_id=str(qualification["profile_id"]),
                planned_owner_profile_version=str(qualification["profile_version"]),
                planned_owner_registry_status=str(qualification["registry_status"]),
                qualification_command_id=str(qualification["command_id"]),
                qualification_group_id=str(qualification["group_id"]),
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
            raise CollaborationPlanError(
                "Ownership revocation preflight is invalid"
            ) from exc
        if parsed.to_dict() != raw:
            raise CollaborationPlanError(
                "Ownership revocation preflight identity or content is invalid"
            )
        return parsed

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": 1,
            "revocation": self.revocation.to_dict(),
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
            "planned_owner_qualification": {
                "profile_id": self.planned_owner_profile_id,
                "profile_version": self.planned_owner_profile_version,
                "registry_status": self.planned_owner_registry_status,
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
            "admission_status": "admissible_pending_dual_authenticated_commit",
            "authentication_status": "not_performed",
            "runtime_effect": "none",
        }
        digest = sha256_text(
            canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        )
        return {
            **body,
            "preflight_id": "ORF-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }


class CollaborationOwnershipRevocationPreflightService:
    """Verify one exact Control revocation without consuming authority."""

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
        revocation: CollaborationOwnershipRevocation,
    ) -> CollaborationOwnershipRevocationPreflight:
        """Evaluate one exact revocation request against verified live state."""

        if not isinstance(revocation, CollaborationOwnershipRevocation):
            raise TypeError("revocation must be a CollaborationOwnershipRevocation")
        parsed = CollaborationOwnershipRevocation.from_dict(revocation.to_dict())
        evaluated_at = format_timestamp(self._clock())
        evaluated_time = parse_timestamp(
            evaluated_at,
            "ownership revocation preflight evaluated_at",
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
            raise StoreError("Could not evaluate collaboration ownership revocation") from exc

    def _evaluate(
        self,
        connection: sqlite3.Connection,
        revocation: CollaborationOwnershipRevocation,
        *,
        evaluated_at: str,
        evaluated_time: datetime,
    ) -> CollaborationOwnershipRevocationPreflight:
        request = CollaborationOwnershipRevocation.from_dict(
            revocation.to_dict()
        )
        request_document = request.to_dict()
        entries = self._chain_entries(connection, str(request_document["chain_id"]))
        if not entries:
            raise StoreConflictError("Ownership revocation chain does not exist")
        head_document = entries[-1].to_dict()
        mission_id = str(head_document["mission_id"])
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
            raise StoreConflictError("Mission has no committed reconfiguration policy")
        policy_document = policy.to_dict()
        CollaborationOwnershipTransitionPreflightService._require_active_policy(
            policy_document,
            plan.plan_id,
            plan.content_sha256,
            evaluated_time,
        )
        maximum_depth = int(
            policy_document["selected_parameters"]["maximum_delegation_depth"]
        )
        current = validate_collaboration_ownership_chain(
            entries,
            maximum_delegation_depth=maximum_depth,
        )
        if (
            request_document["current_head_entry_id"] != current.head_entry_id
            or request_document["current_head_sha256"] != current.head_sha256
            or request_document["current_owner_id"] != current.current_owner_id
            or request_document["planned_owner_id"]
            != head_document["planned_owner_id"]
        ):
            raise StoreConflictError("Ownership revocation does not bind the current head")
        control_id = str(request_document["independent_control_id"])
        if (
            control_id not in mission.control_profile_ids
            or control_id == current.current_owner_id
            or control_id == request_document["planned_owner_id"]
        ):
            raise StoreConflictError(
                "Ownership revocation requires an assigned independent Control profile"
            )
        entry, projection = apply_collaboration_ownership_revocation(
            entries,
            request,
            maximum_delegation_depth=maximum_depth,
        )
        entry_document = entry.to_dict()
        if (
            entry_document["mission_id"] != mission_id
            or entry_document["collaboration_plan_id"] != plan.plan_id
            or entry_document["collaboration_plan_sha256"] != plan.content_sha256
        ):
            raise StoreIntegrityError(
                "Ownership revocation does not bind the active plan"
            )
        item = self._work._work_item(plan, str(entry_document["work_item_id"]))
        if (
            entry_document["work_item_objective_sha256"]
            != collaboration_work_item_objective_sha256(item)
            or item.owner_profile_id != request_document["planned_owner_id"]
        ):
            raise StoreIntegrityError(
                "Ownership revocation does not bind the active work item"
            )
        if (
            self._work._handoff_for_item(connection, plan.plan_id, item.work_item_id)
            is not None
        ):
            raise StoreConflictError(
                "Legacy one-time handoff must be migrated before ownership revocation"
            )
        if self._work._cancellation_ids_for_item(
            connection,
            plan.plan_id,
            item.work_item_id,
        ):
            raise StoreConflictError("Cancelled work item cannot be revoked")
        if (
            self._work._recovery_for_item(connection, plan.plan_id, item.work_item_id)
            is not None
        ):
            raise StoreConflictError("Recovered work item cannot be revoked")
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
        planned_owner = self._registry.profile(item.owner_profile_id)
        CollaborationOwnershipTransitionPreflightService._require_qualified_planned_owner(
            item,
            planned_owner,
            mission.allowed_profile_ids,
            mission.control_profile_ids,
            mission.assurance_profile_ids,
        )
        CollaborationOwnershipTransitionPreflightService._require_transition_window(
            entry_document,
            policy_document,
            evaluated_time,
        )
        if item.command_id is None or item.group_id is None:
            raise StoreIntegrityError("Specialist work item command binding is missing")
        return CollaborationOwnershipRevocationPreflight(
            revocation=request,
            entry=entry,
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
            planned_owner_profile_id=planned_owner.id,
            planned_owner_profile_version=planned_owner.version,
            planned_owner_registry_status=planned_owner.status,
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
    def _chain_entries(
        connection: sqlite3.Connection,
        chain_id: str,
    ) -> tuple[CollaborationOwnershipChainEntry, ...]:
        rows = connection.execute(
            """
            SELECT entry_json
            FROM collaboration_ownership_chain_entries
            WHERE chain_id = ?
            ORDER BY sequence
            """,
            (chain_id,),
        ).fetchall()
        try:
            entries = tuple(
                CollaborationOwnershipChainEntry.from_dict(
                    loads_json_without_duplicate_keys(str(row["entry_json"]))
                )
                for row in rows
            )
        except (CollaborationPlanError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Durable ownership chain is invalid") from exc
        if any(
            canonical_json(entry.to_dict()) != str(row["entry_json"])
            for entry, row in zip(entries, rows, strict=True)
        ):
            raise StoreIntegrityError("Durable ownership chain is not canonical")
        return entries


def load_collaboration_ownership_revocation_preflight(
    path: str | Path,
) -> CollaborationOwnershipRevocationPreflight:
    """Load and verify one ownership revocation preflight artifact."""

    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load ownership revocation preflight: {resolved}"
        ) from exc
    return CollaborationOwnershipRevocationPreflight.from_dict(raw)


__all__ = [
    "CollaborationOwnershipRevocationPreflight",
    "CollaborationOwnershipRevocationPreflightService",
    "load_collaboration_ownership_revocation_preflight",
]
