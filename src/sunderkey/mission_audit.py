"""Verified, read-only mission audit snapshots."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .approvals import ApprovalRecord, ApprovalService
from .authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from .authenticated_work import (
    AuthenticatedWorkItemLeaseService,
    AuthenticatedWorkItemStatusReceipt,
)
from .errors import StoreError, StoreIntegrityError
from .events import MISSION_ID_PATTERN
from .mission_control import MissionControlService
from .registry import ExpertRegistry
from .store import (
    SCHEMA_VERSION,
    WORK_ITEM_ABSOLUTE_MAX_GENERATION,
    WORK_ITEM_LEASE_SECONDS,
    WORK_ITEM_MAX_CLAIM_ATTEMPTS,
    WORK_ITEM_MAX_RECOVERY_EPOCHS,
    WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS,
    MissionStore,
    StoredMission,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
)

MISSION_AUDIT_SNAPSHOT_DOMAIN = "sunderkey.mission-audit-snapshot.v1"
MISSION_AUDIT_SNAPSHOT_SCHEMA_VERSION = 1
MISSION_AUDIT_SNAPSHOT_ID_PATTERN = re.compile(r"MAS-[0-9A-F]{32}")


@dataclass(frozen=True)
class MissionAuditSnapshotReceipt:
    """A canonical, self-identifying verified mission snapshot."""

    snapshot_id: str
    snapshot_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> MissionAuditSnapshotReceipt:
        if not isinstance(raw, dict):
            raise StoreIntegrityError(
                "Mission audit snapshot must be an object"
            )
        expected = {
            "schema_version",
            "snapshot_id",
            "snapshot_sha256",
            "evaluated_at",
            "integrity",
            "store",
            "mission",
            "control",
            "events",
            "scope",
            "authentication",
            "approvals",
            "simulations",
            "collaboration",
        }
        if set(raw) != expected:
            raise StoreIntegrityError(
                "Mission audit snapshot fields are invalid"
            )
        if (
            raw["schema_version"]
            != MISSION_AUDIT_SNAPSHOT_SCHEMA_VERSION
        ):
            raise StoreIntegrityError(
                "Mission audit snapshot schema version is invalid"
            )
        snapshot_id = raw["snapshot_id"]
        snapshot_hash = raw["snapshot_sha256"]
        if (
            not isinstance(snapshot_id, str)
            or MISSION_AUDIT_SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id)
            is None
            or not isinstance(snapshot_hash, str)
        ):
            raise StoreIntegrityError(
                "Mission audit snapshot identity is invalid"
            )
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        expected_hash = _snapshot_hash(body)
        expected_id = _snapshot_id(expected_hash)
        if (
            snapshot_hash != expected_hash
            or snapshot_id != expected_id
        ):
            raise StoreIntegrityError(
                "Mission audit snapshot hash is invalid"
            )
        document_json = canonical_json(raw)
        return cls(
            snapshot_id=snapshot_id,
            snapshot_sha256=snapshot_hash,
            document_json=document_json,
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise StoreIntegrityError(
                "Mission audit snapshot document is invalid"
            )
        return value


class MissionAuditSnapshotService:
    """Project one verified mission from one read transaction."""

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
        self._work = AuthenticatedWorkItemLeaseService(
            store,
            registry,
            clock=self._clock,
        )
        self._approvals = ApprovalService(
            store,
            registry,
            clock=self._clock,
        )
        self._control = MissionControlService(
            store,
            registry,
            clock=self._clock,
        )

    def snapshot(
        self,
        mission_id: str,
    ) -> MissionAuditSnapshotReceipt:
        """Verify and return a non-authorizing operational snapshot."""

        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is not a valid mission ID")
        evaluated_at = format_timestamp(self._clock())
        evaluated_time = parse_timestamp(
            evaluated_at,
            "mission audit evaluated_at",
        )
        try:
            with self._store._read_connection() as connection:
                connection.execute("PRAGMA query_only = ON")
                self._store._quick_check(connection)
                self._store._foreign_key_check(connection)
                self._store._require_schema(connection)
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
                self._activation._require_runtime_not_before_state(
                    connection,
                    mission,
                    principal_ledger,
                    evaluated_time,
                )
                _, stored_events = self._store._load_verified_ledger(
                    connection,
                    mission,
                )
                control_row = self._control._control_row(
                    connection,
                    mission_id,
                )
                control = self._control._record_from_row(control_row)
                approvals = self._approval_records(
                    connection,
                    mission_id,
                    evaluated_time,
                )
                body = {
                    "schema_version": (
                        MISSION_AUDIT_SNAPSHOT_SCHEMA_VERSION
                    ),
                    "evaluated_at": evaluated_at,
                    "integrity": {
                        "status": "verified",
                        "sqlite_quick_check": "ok",
                        "sqlite_foreign_key_check": "ok",
                        "sqlite_query_only": True,
                        "transaction_consistency": (
                            "single_read_transaction"
                        ),
                        "authorization_effect": "none",
                    },
                    "store": self._store_summary(
                        connection,
                        identity,
                        trust_policies,
                    ),
                    "mission": self._mission_summary(mission),
                    "control": {
                        "schema_version": control.schema_version,
                        "state": control.state.value,
                        "version": control.version,
                        "stopped_at": control.stopped_at,
                        "stop_actor_profile_id": (
                            control.stop_actor_profile_id
                        ),
                        "stop_reason_code": control.stop_reason_code,
                        "stop_event_id": control.stop_event_id,
                    },
                    "events": self._event_summary(
                        stored_events,
                        mission,
                    ),
                    "scope": self._scope_summary(
                        connection,
                        scope_grants,
                        evaluated_time,
                    ),
                    "authentication": (
                        self._authentication_summary(
                            connection,
                            mission_id,
                            principal_ledger,
                        )
                    ),
                    "approvals": self._approval_summary(approvals),
                    "simulations": self._simulation_summary(
                        connection,
                        mission_id,
                    ),
                    "collaboration": self._collaboration_summary(
                        connection,
                        mission,
                        principal_ledger,
                        evaluated_time,
                        evaluated_at,
                        control.state.value == "active",
                    ),
                }
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not create mission audit snapshot"
            ) from exc
        snapshot_hash = _snapshot_hash(body)
        document = {
            **body,
            "snapshot_id": _snapshot_id(snapshot_hash),
            "snapshot_sha256": snapshot_hash,
        }
        return MissionAuditSnapshotReceipt.from_dict(document)

    @staticmethod
    def _store_summary(
        connection: sqlite3.Connection,
        identity: sqlite3.Row,
        trust_policies: dict[str, Any],
    ) -> dict[str, Any]:
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version != SCHEMA_VERSION:
            raise StoreIntegrityError(
                "Mission audit requires the current store schema"
            )
        return {
            "store_id": str(identity["store_id"]),
            "schema_version": schema_version,
            "created_at": str(identity["created_at"]),
            "audience": identity["audience"],
            "root_key_id": identity["pinned_root_key_id"],
            "root_key_sha256": identity["pinned_root_key_hash"],
            "root_provisioned_at": identity["root_provisioned_at"],
            "policy_id": identity["trust_policy_id"],
            "policy_version": identity["trust_policy_version"],
            "policy_sha256": identity["trust_policy_hash"],
            "policy_applied_at": identity["policy_applied_at"],
            "trust_policy_history_count": len(trust_policies),
        }

    @staticmethod
    def _mission_summary(mission: StoredMission) -> dict[str, Any]:
        request = mission.mission
        return {
            "mission_id": request.mission_id,
            "catalog_id": mission.catalog_id,
            "catalog_version": mission.catalog_version,
            "context_sha256": mission.context_hash,
            "revision": mission.revision,
            "head_sha256": mission.head_hash,
            "created_at": mission.created_at,
            "updated_at": mission.updated_at,
            "scope_reference": request.scope_reference,
            "scope_document_sha256": request.scope_document_hash,
            "environment": request.environment.value,
            "maximum_action_tier": request.max_action_tier.value,
            "required_evidence_level": (
                request.required_evidence_level.value
            ),
            "assigned_profile_count": len(
                mission.allowed_profile_ids
            ),
            "control_profile_count": len(
                mission.control_profile_ids
            ),
            "assurance_profile_count": len(
                mission.assurance_profile_ids
            ),
        }

    @staticmethod
    def _event_summary(
        stored_events: tuple[Any, ...],
        mission: StoredMission,
    ) -> dict[str, Any]:
        type_counts = Counter(
            stored.event.event_type.value
            for stored in stored_events
        )
        return {
            "count": len(stored_events),
            "counts_by_type": dict(sorted(type_counts.items())),
            "last_event_at": (
                None
                if not stored_events
                else stored_events[-1].event.timestamp
            ),
            "revision": mission.revision,
            "head_sha256": mission.head_hash,
        }

    @staticmethod
    def _scope_summary(
        connection: sqlite3.Connection,
        scope_grants: dict[str, Any],
        evaluated_time: datetime,
    ) -> dict[str, Any]:
        accepted = len(scope_grants)
        revoked = 0
        currently_valid = 0
        for row, grant in scope_grants.values():
            signed_revocation = connection.execute(
                """
                SELECT 1
                FROM mission_scope_grant_revocations
                WHERE scope_grant_hash = ?
                """,
                (row["grant_hash"],),
            ).fetchone()
            is_revoked = (
                row["revoked_at"] is not None
                or signed_revocation is not None
            )
            revoked += int(is_revoked)
            if (
                not is_revoked
                and parse_timestamp(
                    grant.not_before,
                    "scope grant not_before",
                )
                <= evaluated_time
                < parse_timestamp(
                    grant.expires_at,
                    "scope grant expires_at",
                )
            ):
                currently_valid += 1
        return {
            "accepted_grant_count": accepted,
            "revoked_grant_count": revoked,
            "currently_valid_grant_count": currently_valid,
            "profile_count": len(
                {
                    grant.profile_id
                    for _, grant in scope_grants.values()
                }
            ),
        }

    @staticmethod
    def _authentication_summary(
        connection: sqlite3.Connection,
        mission_id: str,
        principal_ledger: sqlite3.Row,
    ) -> dict[str, Any]:
        rows = connection.execute(
            """
            SELECT operation, COUNT(*) AS operation_count
            FROM principal_assertion_uses
            WHERE mission_id = ?
            GROUP BY operation
            ORDER BY operation
            """,
            (mission_id,),
        ).fetchall()
        principal_count = int(
            connection.execute(
                """
                SELECT COUNT(DISTINCT principal_profile_id)
                FROM principal_assertion_uses
                WHERE mission_id = ?
                """,
                (mission_id,),
            ).fetchone()[0]
        )
        return {
            "baseline_kind": str(
                principal_ledger["baseline_kind"]
            ),
            "baseline_sha256": str(
                principal_ledger["baseline_hash"]
            ),
            "baseline_root_sha256": str(
                principal_ledger["baseline_root_hash"]
            ),
            "assertion_count": int(
                principal_ledger["assertion_count"]
            ),
            "effect_count": int(principal_ledger["effect_count"]),
            "principal_count": principal_count,
            "counts_by_operation": {
                str(row["operation"]): int(row["operation_count"])
                for row in rows
            },
            "head_sha256": str(principal_ledger["head_hash"]),
            "updated_at": str(principal_ledger["updated_at"]),
        }

    def _approval_records(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
        evaluated_time: datetime,
    ) -> tuple[ApprovalRecord, ...]:
        rows = connection.execute(
            """
            SELECT *
            FROM approval_queue
            WHERE mission_id = ?
            ORDER BY submitted_at, approval_id
            """,
            (mission_id,),
        ).fetchall()
        return tuple(
            self._approvals._record_from_row(row, evaluated_time)
            for row in rows
        )

    @staticmethod
    def _approval_summary(
        approvals: tuple[ApprovalRecord, ...],
    ) -> dict[str, Any]:
        state_counts = Counter(record.state.value for record in approvals)
        return {
            "count": len(approvals),
            "counts_by_state": dict(sorted(state_counts.items())),
            "records": [
                {
                    "approval_id": record.approval_id,
                    "proposal_id": record.proposal_id,
                    "proposer_profile_id": (
                        record.proposer_profile_id
                    ),
                    "executor_profile_id": (
                        record.executor_profile_id
                    ),
                    "action_tier": record.action_tier.value,
                    "state": record.state.value,
                    "submitted_at": record.submitted_at,
                    "review_expires_at": record.review_expires_at,
                    "version": record.version,
                    "decision_actor_profile_id": (
                        record.decision_actor_profile_id
                    ),
                    "decision_at": record.decision_at,
                    "decision_code": record.decision_code,
                    "decision_event_id": record.decision_event_id,
                    "authorization_event_id": (
                        record.authorization_event_id
                    ),
                    "authorization_expires_at": (
                        record.authorization_expires_at
                    ),
                    "simulation_id": record.simulation_id,
                }
                for record in approvals
            ],
        }

    @staticmethod
    def _simulation_summary(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> dict[str, Any]:
        rows = connection.execute(
            """
            SELECT
                simulation_id,
                approval_id,
                proposal_id,
                authorization_id,
                receipt_hash,
                recorded_at
            FROM simulation_receipts
            WHERE mission_id = ?
            ORDER BY recorded_at, simulation_id
            """,
            (mission_id,),
        ).fetchall()
        return {
            "count": len(rows),
            "records": [
                {
                    "simulation_id": str(row["simulation_id"]),
                    "approval_id": str(row["approval_id"]),
                    "proposal_id": str(row["proposal_id"]),
                    "authorization_id": str(
                        row["authorization_id"]
                    ),
                    "receipt_sha256": str(row["receipt_hash"]),
                    "recorded_at": str(row["recorded_at"]),
                }
                for row in rows
            ],
        }

    def _collaboration_summary(
        self,
        connection: sqlite3.Connection,
        mission: StoredMission,
        principal_ledger: sqlite3.Row,
        evaluated_time: datetime,
        evaluated_at: str,
        mission_active: bool,
    ) -> dict[str, Any]:
        activation = connection.execute(
            """
            SELECT activation.*
            FROM collaboration_plan_active_heads AS head
            JOIN collaboration_plan_activations AS activation
              ON activation.plan_id = head.active_plan_id
            WHERE head.mission_id = ?
            """,
            (mission.mission.mission_id,),
        ).fetchone()
        if activation is None:
            return {
                "activated": False,
                "activation": None,
                "work": None,
                "work_state_counts": {},
                "transition_count": 0,
                "recovery_request_count": 0,
                "recovery_decision_count": 0,
                "cancellation_count": 0,
                "handoff_count": 0,
            }
        _, plan = self._work._load_activation(
            connection,
            mission.mission.mission_id,
        )
        self._activation._require_runtime_not_before_state(
            connection,
            mission,
            principal_ledger,
            evaluated_time,
        )
        latest = self._work._latest_transitions(
            connection,
            plan.plan_id,
        )
        cancellations = self._work._cancellations_for_plan(
            connection,
            plan.plan_id,
        )
        handoffs = self._work._handoffs_for_plan(
            connection,
            plan.plan_id,
        )
        ownerships = self._work._ownerships_for_plan(
            connection,
            plan.plan_id,
        )
        carried_completed = self._work._carried_completed_for_plan(
            connection,
            plan.plan_id,
        )
        completed = {
            identifier
            for identifier, row in latest.items()
            if row["transition_kind"] == "complete"
        } | set(carried_completed)
        statuses = tuple(
            self._work._status_for_item(
                item,
                latest.get(item.work_item_id),
                self._work._recovery_for_item(
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
                mission_active=mission_active,
            )
            for item in plan.work_items
        )
        status_receipt = AuthenticatedWorkItemStatusReceipt(
            mission_id=mission.mission.mission_id,
            plan_id=plan.plan_id,
            plan_content_sha256=plan.content_sha256,
            evaluated_at=evaluated_at,
            lease_duration_seconds=WORK_ITEM_LEASE_SECONDS,
            maximum_claim_attempts=WORK_ITEM_MAX_CLAIM_ATTEMPTS,
            recovery_claim_attempts=WORK_ITEM_RECOVERY_CLAIM_ATTEMPTS,
            maximum_recovery_epochs=WORK_ITEM_MAX_RECOVERY_EPOCHS,
            absolute_maximum_generation=(
                WORK_ITEM_ABSOLUTE_MAX_GENERATION
            ),
            work_items=statuses,
        )
        state_counts = Counter(status.state.value for status in statuses)
        transition_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_transitions
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        ) + int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_recovery_transitions
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        )
        recovery_request_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_recovery_requests
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        )
        recovery_decision_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_recovery_decisions
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        )
        cancellation_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_cancellations
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        )
        handoff_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM collaboration_work_item_handoffs
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()[0]
        )
        return {
            "activated": True,
            "activation": {
                "plan_id": str(activation["plan_id"]),
                "plan_sha256": str(activation["plan_sha256"]),
                "plan_content_sha256": str(
                    activation["plan_content_sha256"]
                ),
                "registry_sha256": str(
                    activation["registry_sha256"]
                ),
                "mission_sha256": str(
                    activation["mission_sha256"]
                ),
                "joint_mission_cell_sha256": str(
                    activation["joint_mission_cell_sha256"]
                ),
                "readiness_owner_profile_id": str(
                    activation["readiness_owner_profile_id"]
                ),
                "activated_at": str(activation["activated_at"]),
                "issuer": (
                    None
                    if activation["issuer"] is None
                    else str(activation["issuer"])
                ),
                "assertion_id": (
                    None
                    if activation["assertion_id"] is None
                    else str(activation["assertion_id"])
                ),
            },
            "work": status_receipt.to_dict(),
            "work_state_counts": dict(sorted(state_counts.items())),
            "transition_count": transition_count,
            "recovery_request_count": recovery_request_count,
            "recovery_decision_count": recovery_decision_count,
            "cancellation_count": cancellation_count,
            "handoff_count": handoff_count,
        }


def _snapshot_hash(body: dict[str, Any]) -> str:
    return sha256_text(
        canonical_json(
            {
                "domain": MISSION_AUDIT_SNAPSHOT_DOMAIN,
                "snapshot": body,
            }
        )
    )


def _snapshot_id(snapshot_hash: str) -> str:
    return "MAS-" + snapshot_hash.removeprefix("sha256:")[:32].upper()
