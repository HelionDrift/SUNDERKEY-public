"""Read-only selected action origin link across separately verified stores.

The link is an ephemeral operator observation, not cross-store atomic custody.
"""

from __future__ import annotations

from typing import Any

from .expert_workspace import SQLiteExpertWorkspaceStore
from .mission import MISSION_ID_PATTERN
from .mission_audit import MissionAuditSnapshotService
from .offline_composed_mission_trace import (
    OfflineComposedMissionTrace,
    OfflineComposedMissionTraceError,
    recheck_offline_composed_mission_trace,
)
from .offline_mission_action_custody import (
    OfflineMissionActionCustodyError,
    OfflineMissionActionCustodySnapshot,
    verify_offline_mission_action_custody_snapshot,
)
from .orchestration_journal import SQLiteOrchestrationJournal
from .registry import ExpertRegistry
from .store import MissionStore

_EFFECTS = {
    "action_authority": "none",
    "network_call_performed": False,
    "qualification_effect": "none",
    "target_action_performed": False,
}


class OfflineActionWorkspaceLinkError(ValueError):
    """Raised when one selected action cannot be safely linked for review."""


def _expected(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise OfflineActionWorkspaceLinkError(f"{label} is invalid")
    return value


def link_offline_action_to_workspace(
    *,
    action_snapshot: OfflineMissionActionCustodySnapshot,
    trace: OfflineComposedMissionTrace,
    mission_store: MissionStore,
    mission_audit: MissionAuditSnapshotService,
    workspace_store: SQLiteExpertWorkspaceStore,
    orchestration_journal: SQLiteOrchestrationJournal,
    runtime_catalog: Any,
    expert_registry: ExpertRegistry,
    expected_tenant_id: str,
    expected_mission_id: str,
    expected_workspace_id: str,
    expected_receipt_id: str,
) -> dict[str, Any]:
    """Recheck a saved action and trace, then compare exact selected origin IDs.

    Each source is observed independently. This cannot prove a simultaneous
    cross-store snapshot, present action authority, or current work assignment.
    """

    tenant_id = _expected(expected_tenant_id, "expected_tenant_id")
    mission_id = _expected(expected_mission_id, "expected_mission_id")
    workspace_id = _expected(expected_workspace_id, "expected_workspace_id")
    receipt_id = _expected(expected_receipt_id, "expected_receipt_id")
    if MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        raise OfflineActionWorkspaceLinkError("expected_mission_id is invalid")
    if (
        type(action_snapshot) is not OfflineMissionActionCustodySnapshot
        or type(trace) is not OfflineComposedMissionTrace
        or type(mission_store) is not MissionStore
        or type(mission_audit) is not MissionAuditSnapshotService
        or type(workspace_store) is not SQLiteExpertWorkspaceStore
        or type(orchestration_journal) is not SQLiteOrchestrationJournal
        or type(expert_registry) is not ExpertRegistry
        or mission_audit._store is not mission_store
        or mission_audit._registry is not expert_registry
    ):
        raise OfflineActionWorkspaceLinkError("matching mission sources are required")

    try:
        verify_offline_mission_action_custody_snapshot(
            action_snapshot,
            mission_store,
            expert_registry,
            expected_tenant_id=tenant_id,
        )
    except OfflineMissionActionCustodyError as exc:
        raise OfflineActionWorkspaceLinkError("action custody recheck failed") from exc
    action = action_snapshot.to_dict()
    if action["tenant_id"] != tenant_id or action["mission_id"] != mission_id:
        raise OfflineActionWorkspaceLinkError("selected action origin is unavailable")
    selected = [
        item for item in action["receipts"] if item["receipt_id"] == receipt_id
    ]
    if len(selected) != 1:
        raise OfflineActionWorkspaceLinkError("selected action origin is unavailable")
    receipt = selected[0]

    try:
        recheck = recheck_offline_composed_mission_trace(
            trace,
            mission_audit=mission_audit,
            workspace_store=workspace_store,
            orchestration_journal=orchestration_journal,
            runtime_catalog=runtime_catalog,
            expert_registry=expert_registry,
            expected_tenant_id=tenant_id,
            expected_mission_id=mission_id,
            expected_workspace_id=workspace_id,
        )
    except OfflineComposedMissionTraceError as exc:
        raise OfflineActionWorkspaceLinkError("workspace trace recheck failed") from exc
    if recheck["status"] != "selected_observations_match_at_recheck":
        raise OfflineActionWorkspaceLinkError("workspace trace recheck failed")

    # Reobserve the action after the separate trace read. This detects an
    # observed action-store change, but cannot create an atomic cross-store view.
    try:
        verify_offline_mission_action_custody_snapshot(
            action_snapshot,
            mission_store,
            expert_registry,
            expected_tenant_id=tenant_id,
        )
    except OfflineMissionActionCustodyError as exc:
        raise OfflineActionWorkspaceLinkError("action custody changed during link") from exc

    observation = trace.to_dict()
    mission = observation["mission_observation"]
    workspace = observation["workspace_observation"]
    if (
        observation["tenant_id"] != tenant_id
        or mission["mission_id"] != mission_id
        or mission["revision"] != action["mission_revision"]
        or mission["head_sha256"] != action["mission_head_sha256"]
        or workspace["workspace_id"] != workspace_id
        or workspace["mission_id"] != mission_id
        or workspace["plan_id"] != receipt["origin_plan_id"]
        or receipt["tenant_id"] != tenant_id
        or receipt["origin_workspace_id"] != workspace_id
    ):
        raise OfflineActionWorkspaceLinkError("selected action origin does not match workspace")

    return {
        "schema_version": 1,
        "status": "historical_action_origin_matches_selected_workspace",
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "workspace_id": workspace_id,
        "receipt_id": receipt_id,
        "receipt_sha256": receipt["receipt_sha256"],
        "action_snapshot_sha256": action_snapshot.snapshot_sha256,
        "trace_sha256": trace.trace_sha256,
        "historical_workspace_sha256": receipt["origin_workspace_sha256"],
        "plan_id": receipt["origin_plan_id"],
        "work_id": receipt["origin_work_id"],
        "reviewed_product_id": receipt["proposal_product_id"],
        "reviewed_product_sha256": receipt["proposal_product_sha256"],
        "review_revocation_status": receipt["review_revocation_status"],
        "selected_sources_rechecked": True,
        "current_work_assignment_compared": False,
        "full_mission_audit_state_compared": False,
        "source_identity_authenticated": False,
        "current_authority_verified": False,
        "cross_store_consistency": "not_proven",
        "positive_use_approved": False,
        "effects": dict(_EFFECTS),
    }
