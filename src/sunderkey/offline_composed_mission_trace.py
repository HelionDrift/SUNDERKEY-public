"""Read-only cross-store mission observations without action authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .expert_workspace import (
    ExpertWorkspaceState,
    ExpertWorkspaceVerificationReport,
    SQLiteExpertWorkspaceStore,
)
from .mission_audit import MissionAuditSnapshotReceipt, MissionAuditSnapshotService
from .orchestration_journal import SQLiteOrchestrationJournal
from .registry import ExpertRegistry
from .store import canonical_json


class OfflineComposedMissionTraceError(ValueError):
    """Raised when an offline observation cannot be safely composed."""


KIND = "sunderkey.offline-composed-mission-trace.v1"
MAX_SCANNED_JOBS = 1000
_EFFECTS = {
    "action_authority": "none",
    "cross_store_transaction": False,
    "network_call_performed": False,
    "qualification_effect": "none",
    "target_action_performed": False,
}
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise OfflineComposedMissionTraceError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise OfflineComposedMissionTraceError(f"{label} is invalid")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise OfflineComposedMissionTraceError(f"{label} is invalid")
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OfflineComposedMissionTraceError(f"{label} fields are invalid")
    return value


def _validate_body(body: dict[str, Any]) -> None:
    tenant_id = _text(body["tenant_id"], "tenant_id")
    mission = _exact(
        body["mission_observation"],
        {"mission_id", "snapshot_id", "snapshot_sha256", "revision", "head_sha256"},
        "mission observation",
    )
    mission_id = _text(mission["mission_id"], "mission_id")
    _text(mission["snapshot_id"], "mission snapshot_id")
    _digest(mission["snapshot_sha256"], "mission snapshot_sha256")
    _count(mission["revision"], "mission revision")
    _digest(mission["head_sha256"], "mission head_sha256")

    workspace = _exact(
        body["workspace_observation"],
        {
            "workspace_id", "mission_id", "plan_id", "revision", "status",
            "assignment_count", "completed_assignment_count",
        },
        "workspace observation",
    )
    workspace_id = _text(workspace["workspace_id"], "workspace_id")
    if workspace["mission_id"] != mission_id:
        raise OfflineComposedMissionTraceError("workspace mission binding is invalid")
    _text(workspace["plan_id"], "workspace plan_id")
    _text(workspace["status"], "workspace status")
    _count(workspace["revision"], "workspace revision")
    assignments = _count(workspace["assignment_count"], "workspace assignment_count")
    completed = _count(
        workspace["completed_assignment_count"], "workspace completed_assignment_count"
    )
    if completed > assignments:
        raise OfflineComposedMissionTraceError("workspace completion count is invalid")

    integrity = _exact(
        body["source_integrity"],
        {
            "mission", "workspace", "workspace_store_sha256", "journal",
            "journal_schema_manifest_sha256",
        },
        "source integrity",
    )
    if (
        integrity["mission"] != "mission_audit_single_read_transaction"
        or integrity["workspace"] != "verified_before_workspace_read"
        or integrity["journal"] != "verified_before_job_reads"
    ):
        raise OfflineComposedMissionTraceError("source integrity labels are invalid")
    _digest(integrity["workspace_store_sha256"], "workspace store digest")
    _digest(integrity["journal_schema_manifest_sha256"], "journal schema digest")

    jobs = body["job_observations"]
    if not isinstance(jobs, list) or len(jobs) > MAX_SCANNED_JOBS:
        raise OfflineComposedMissionTraceError("job observations are invalid")
    job_ids: list[str] = []
    for raw_job in jobs:
        job = _exact(
            raw_job,
            {
                "job_id", "job_sha256", "tenant_id", "subject_ref", "kind",
                "state", "revision", "authority_status",
            },
            "job observation",
        )
        job_ids.append(_text(job["job_id"], "job_id"))
        _digest(job["job_sha256"], "job digest")
        if job["tenant_id"] != tenant_id or job["subject_ref"] not in {
            mission_id, workspace_id
        }:
            raise OfflineComposedMissionTraceError("job boundary is invalid")
        _text(job["kind"], "job kind")
        _text(job["state"], "job state")
        _count(job["revision"], "job revision")
        if job["authority_status"] != "not_authoritative":
            raise OfflineComposedMissionTraceError("job authority status is invalid")
    if job_ids != sorted(set(job_ids)):
        raise OfflineComposedMissionTraceError("job observation order is invalid")


def _identity(body: dict[str, Any]) -> tuple[str, str]:
    digest = "sha256:" + hashlib.sha256(
        (KIND + "\n" + canonical_json(body)).encode("utf-8")
    ).hexdigest()
    return "OMT-" + digest[7:39].upper(), digest


def _checked_journal_report(report: Any) -> str:
    if (
        not isinstance(report, dict)
        or report.get("status") != "valid"
        or not isinstance(report.get("counts"), dict)
        or not isinstance(report.get("event_count"), int)
        or type(report["event_count"]) is not int
        or report["event_count"] < 0
        or any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in report["counts"].items()
        )
    ):
        raise OfflineComposedMissionTraceError("orchestration journal is not valid")
    _digest(report.get("schema_manifest_sha256"), "journal schema digest")
    return canonical_json(report)


def _matching_jobs(
    journal: SQLiteOrchestrationJournal,
    *,
    tenant_id: str,
    mission_id: str,
    workspace_id: str,
) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    scanned = 0
    after: str | None = None
    while True:
        page_limit = min(200, MAX_SCANNED_JOBS + 1 - scanned)
        page = journal.list_jobs(tenant_id, after_job_id=after, limit=page_limit)
        if not page:
            break
        scanned += len(page)
        if scanned > MAX_SCANNED_JOBS:
            raise OfflineComposedMissionTraceError("tenant job scan exceeds the trace bound")
        for view in page:
            if view.job.tenant_id != tenant_id:
                raise OfflineComposedMissionTraceError("journal job crosses the tenant boundary")
            if view.job.subject_ref in {mission_id, workspace_id}:
                jobs.append(
                    {
                        "job_id": view.job.job_id,
                        "job_sha256": view.job.job_sha256,
                        "tenant_id": view.job.tenant_id,
                        "subject_ref": view.job.subject_ref,
                        "kind": view.job.job_kind.value,
                        "state": view.state.value,
                        "revision": view.revision,
                        "authority_status": "not_authoritative",
                    }
                )
        after = page[-1].job.job_id
        if len(page) < page_limit:
            break
    jobs.sort(key=lambda item: item["job_id"])
    return jobs


@dataclass(frozen=True, slots=True)
class OfflineComposedMissionTrace:
    """A content-addressed report of separately observed source states."""

    trace_id: str
    trace_sha256: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> OfflineComposedMissionTrace:
        if not isinstance(raw, dict) or set(raw) != {
            "cross_store_consistency",
            "effects",
            "job_observations",
            "kind",
            "mission_observation",
            "schema_version",
            "source_integrity",
            "tenant_id",
            "trace_id",
            "trace_sha256",
            "workspace_observation",
        }:
            raise OfflineComposedMissionTraceError("trace fields are invalid")
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["kind"] != KIND
            or not isinstance(raw["effects"], dict)
            or raw["effects"] != _EFFECTS
            or raw["cross_store_consistency"] != "not_proven"
        ):
            raise OfflineComposedMissionTraceError("trace boundary is invalid")
        body = {key: value for key, value in raw.items() if key not in {"trace_id", "trace_sha256"}}
        _validate_body(body)
        trace_id, digest = _identity(body)
        if raw["trace_id"] != trace_id or raw["trace_sha256"] != digest:
            raise OfflineComposedMissionTraceError("trace content address is invalid")
        return cls(trace_id, digest, canonical_json(raw))

    @classmethod
    def from_json(cls, document: str) -> OfflineComposedMissionTrace:
        if not isinstance(document, str):
            raise OfflineComposedMissionTraceError("trace document must be text")
        try:
            raw = json.loads(document)
        except (TypeError, ValueError) as exc:
            raise OfflineComposedMissionTraceError("trace document is invalid") from exc
        trace = cls.from_dict(raw)
        if trace.document_json != document:
            raise OfflineComposedMissionTraceError("trace document is not canonical")
        return trace


def capture_offline_composed_mission_trace(
    *,
    mission_audit: MissionAuditSnapshotService,
    workspace_store: SQLiteExpertWorkspaceStore,
    orchestration_journal: SQLiteOrchestrationJournal,
    runtime_catalog: Any,
    expert_registry: ExpertRegistry | None,
    tenant_id: str,
    mission_id: str,
    workspace_id: str,
) -> OfflineComposedMissionTrace:
    """Observe three stores, verify their local integrity, and bind matching IDs.

    The reads are not one transaction. This report cannot establish live source
    currentness, authorize a job, or prove that a target action happened.
    """

    mission_receipt = mission_audit.snapshot(mission_id)
    if not isinstance(mission_receipt, MissionAuditSnapshotReceipt):
        raise OfflineComposedMissionTraceError("mission audit receipt is invalid")
    mission_document = MissionAuditSnapshotReceipt.from_dict(mission_receipt.to_dict()).to_dict()
    mission = mission_document["mission"]
    if mission.get("mission_id") != mission_id:
        raise OfflineComposedMissionTraceError("mission audit crosses the requested mission")

    workspace_report = workspace_store.verify_store(
        runtime_catalog, expert_registry=expert_registry
    )
    workspace = workspace_store.get_workspace(workspace_id, tenant_id=tenant_id)
    if (
        not isinstance(workspace_report, ExpertWorkspaceVerificationReport)
        or workspace_report.status != "valid"
        or not isinstance(workspace, ExpertWorkspaceState)
        or workspace.workspace_id != workspace_id
        or workspace.tenant_id != tenant_id
        or workspace.mission_id != mission_id
    ):
        raise OfflineComposedMissionTraceError("workspace does not match the mission boundary")

    journal_report = orchestration_journal.verify()
    journal_report_document = _checked_journal_report(journal_report)
    jobs = _matching_jobs(
        orchestration_journal,
        tenant_id=tenant_id,
        mission_id=mission_id,
        workspace_id=workspace_id,
    )

    # A second read detects observed movement during composition. It cannot
    # make the three independent stores into one atomic snapshot.
    repeated_jobs = _matching_jobs(
        orchestration_journal,
        tenant_id=tenant_id,
        mission_id=mission_id,
        workspace_id=workspace_id,
    )
    repeated_journal_report = orchestration_journal.verify()
    if (
        repeated_jobs != jobs
        or _checked_journal_report(repeated_journal_report) != journal_report_document
    ):
        raise OfflineComposedMissionTraceError("orchestration journal changed during capture")
    repeated_workspace = workspace_store.get_workspace(workspace_id, tenant_id=tenant_id)
    repeated_workspace_report = workspace_store.verify_store(
        runtime_catalog, expert_registry=expert_registry
    )
    if repeated_workspace != workspace or repeated_workspace_report != workspace_report:
        raise OfflineComposedMissionTraceError("workspace changed during capture")
    repeated_mission_receipt = mission_audit.snapshot(mission_id)
    if not isinstance(repeated_mission_receipt, MissionAuditSnapshotReceipt):
        raise OfflineComposedMissionTraceError("mission audit receipt is invalid")
    repeated_mission = MissionAuditSnapshotReceipt.from_dict(
        repeated_mission_receipt.to_dict()
    ).to_dict()["mission"]
    if (
        repeated_mission.get("mission_id") != mission_id
        or repeated_mission.get("revision") != mission["revision"]
        or repeated_mission.get("head_sha256") != mission["head_sha256"]
    ):
        raise OfflineComposedMissionTraceError("mission changed during capture")

    body = {
        "cross_store_consistency": "not_proven",
        "effects": dict(_EFFECTS),
        "job_observations": jobs,
        "kind": KIND,
        "mission_observation": {
            "mission_id": mission_id,
            "snapshot_id": mission_receipt.snapshot_id,
            "snapshot_sha256": mission_receipt.snapshot_sha256,
            "revision": mission["revision"],
            "head_sha256": mission["head_sha256"],
        },
        "schema_version": 1,
        "source_integrity": {
            "mission": "mission_audit_single_read_transaction",
            "workspace": "verified_before_workspace_read",
            "workspace_store_sha256": workspace_report.store_sha256,
            "journal": "verified_before_job_reads",
            "journal_schema_manifest_sha256": journal_report["schema_manifest_sha256"],
        },
        "tenant_id": tenant_id,
        "workspace_observation": {
            "workspace_id": workspace_id,
            "mission_id": workspace.mission_id,
            "plan_id": workspace.plan_id,
            "revision": workspace.revision,
            "status": workspace.status,
            "assignment_count": workspace.assignment_count,
            "completed_assignment_count": workspace.completed_assignment_count,
        },
    }
    trace_id, digest = _identity(body)
    return OfflineComposedMissionTrace.from_dict(
        {**body, "trace_id": trace_id, "trace_sha256": digest}
    )


def recheck_offline_composed_mission_trace(
    trace: OfflineComposedMissionTrace,
    *,
    mission_audit: MissionAuditSnapshotService,
    workspace_store: SQLiteExpertWorkspaceStore,
    orchestration_journal: SQLiteOrchestrationJournal,
    runtime_catalog: Any,
    expert_registry: ExpertRegistry | None,
    expected_tenant_id: str,
    expected_mission_id: str,
    expected_workspace_id: str,
) -> dict[str, Any]:
    """Compare selected saved observations with a fresh read-only capture.

    This is not a full mission-audit comparison or an atomic cross-store read.
    Expected identities must come from the caller, not the unsigned trace.
    """

    if type(trace) is not OfflineComposedMissionTrace:
        raise OfflineComposedMissionTraceError("typed saved trace is required")
    for value, label in (
        (expected_tenant_id, "expected_tenant_id"),
        (expected_mission_id, "expected_mission_id"),
        (expected_workspace_id, "expected_workspace_id"),
    ):
        if type(value) is not str:
            raise OfflineComposedMissionTraceError(f"{label} must be native text")
        _text(value, label)
    parsed = OfflineComposedMissionTrace.from_json(trace.document_json)
    if parsed != trace:
        raise OfflineComposedMissionTraceError("saved trace fields differ from its document")
    saved = parsed.to_dict()
    if (
        saved["tenant_id"] != expected_tenant_id
        or saved["mission_observation"]["mission_id"] != expected_mission_id
        or saved["workspace_observation"]["workspace_id"] != expected_workspace_id
        or saved["workspace_observation"]["mission_id"] != expected_mission_id
    ):
        raise OfflineComposedMissionTraceError("saved trace crosses expected identities")
    current_trace = capture_offline_composed_mission_trace(
        mission_audit=mission_audit,
        workspace_store=workspace_store,
        orchestration_journal=orchestration_journal,
        runtime_catalog=runtime_catalog,
        expert_registry=expert_registry,
        tenant_id=expected_tenant_id,
        mission_id=expected_mission_id,
        workspace_id=expected_workspace_id,
    )
    current = current_trace.to_dict()
    saved_mission = saved["mission_observation"]
    current_mission = current["mission_observation"]
    if (
        saved_mission["mission_id"] != current_mission["mission_id"]
        or saved_mission["revision"] != current_mission["revision"]
        or saved_mission["head_sha256"] != current_mission["head_sha256"]
        or saved["workspace_observation"] != current["workspace_observation"]
        or saved["source_integrity"] != current["source_integrity"]
        or saved["job_observations"] != current["job_observations"]
    ):
        raise OfflineComposedMissionTraceError(
            "selected mission trace observations changed at recheck"
        )
    return {
        "status": "selected_observations_match_at_recheck",
        "saved_trace_sha256": trace.trace_sha256,
        "rechecked_trace_sha256": current_trace.trace_sha256,
        "tenant_id": expected_tenant_id,
        "mission_id": expected_mission_id,
        "workspace_id": expected_workspace_id,
        "mission_audit_snapshot_sha256_changed": (
            saved_mission["snapshot_sha256"] != current_mission["snapshot_sha256"]
        ),
        "full_mission_audit_state_compared": False,
        "source_identity_authenticated": False,
        "current_authority_verified": False,
        "cross_store_consistency": "not_proven",
        "positive_use_approved": False,
        "effects": dict(_EFFECTS),
    }
