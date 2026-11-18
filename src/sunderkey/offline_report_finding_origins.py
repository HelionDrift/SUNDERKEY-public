"""Read-only local origin checks for reported finding lifecycle references."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .assessment_reporting import AssessmentReportingError, PentestReport
from .finding_lifecycle import FindingLifecycleError, FindingSnapshot

SCHEMA_VERSION = 1
MAX_FINDINGS = 200
MAX_TOTAL_SNAPSHOTS = 4096
MAX_EMBEDDED_EVENTS = 2048


class OfflineReportFindingOriginsError(ValueError):
    """Raised when a report cannot be joined to exact local finding originals."""


def verify_report_finding_origins(
    *,
    report: PentestReport,
    snapshot_histories: Mapping[str, Sequence[FindingSnapshot]],
) -> dict[str, Any]:
    """Match a report to complete supplied local snapshot chains, without effects.

    This checks only the supplied originals. It does not establish that a head
    is current in an external store or that any actor, review, or authority is
    authenticated.
    """

    if type(report) is not PentestReport:
        raise OfflineReportFindingOriginsError("report must be a PentestReport")
    if type(snapshot_histories) is not dict:
        raise OfflineReportFindingOriginsError("snapshot histories must be a native dict")
    try:
        original_report = PentestReport.from_dict(report.to_dict())
    except (AssessmentReportingError, TypeError, ValueError, KeyError) as exc:
        raise OfflineReportFindingOriginsError("report original is invalid") from exc

    expected_ids = {finding.finding_id for finding in original_report.findings}
    if len(expected_ids) > MAX_FINDINGS or len(snapshot_histories) != len(expected_ids):
        raise OfflineReportFindingOriginsError(
            "snapshot history keys must exactly match report findings"
        )
    supplied_histories: dict[str, tuple[FindingSnapshot, ...]] = {}
    total_snapshots = 0
    total_embedded_events = 0
    try:
        entries = tuple(snapshot_histories.items())
    except RuntimeError as exc:
        raise OfflineReportFindingOriginsError(
            "snapshot histories changed during capture"
        ) from exc
    for finding_id, supplied in entries:
        if type(finding_id) is not str or finding_id not in expected_ids:
            raise OfflineReportFindingOriginsError(
                "snapshot history keys must exactly match report findings"
            )
        if type(supplied) not in (list, tuple):
            raise OfflineReportFindingOriginsError(
                "snapshot history must be a native list or tuple"
            )
        if total_snapshots + len(supplied) > MAX_TOTAL_SNAPSHOTS:
            raise OfflineReportFindingOriginsError("too many snapshot originals")
        captured = tuple(supplied)
        total_snapshots += len(captured)
        if total_snapshots > MAX_TOTAL_SNAPSHOTS:
            raise OfflineReportFindingOriginsError("too many snapshot originals")
        for original in captured:
            if type(original) is not FindingSnapshot or type(original.events) is not tuple:
                raise OfflineReportFindingOriginsError("snapshot original has invalid type")
            total_embedded_events += len(original.events)
            if total_embedded_events > MAX_EMBEDDED_EVENTS:
                raise OfflineReportFindingOriginsError("too many embedded finding events")
        supplied_histories[finding_id] = captured

    references = {
        reference.finding_id: reference
        for reference in original_report.assessment.finding_lifecycle
    }
    heads: list[dict[str, Any]] = []
    for finding in original_report.findings:
        supplied = supplied_histories[finding.finding_id]
        if not supplied:
            raise OfflineReportFindingOriginsError("snapshot history is empty")

        previous: FindingSnapshot | None = None
        for version, original in enumerate(supplied, start=1):
            if type(original) is not FindingSnapshot:
                raise OfflineReportFindingOriginsError("snapshot original has invalid type")
            try:
                snapshot = FindingSnapshot.from_dict(original.to_dict())
                if snapshot.finding_id != finding.finding_id:
                    raise OfflineReportFindingOriginsError("snapshot finding ID does not match")
                if snapshot.finding_version != version:
                    raise OfflineReportFindingOriginsError("snapshot history is incomplete")
                if previous is None:
                    if snapshot.parent_snapshot_sha256 is not None:
                        raise OfflineReportFindingOriginsError("genesis snapshot has a parent")
                else:
                    snapshot.verify_parent(previous)
            except (FindingLifecycleError, TypeError, ValueError, KeyError) as exc:
                if isinstance(exc, OfflineReportFindingOriginsError):
                    raise
                raise OfflineReportFindingOriginsError(
                    "snapshot original or parent history is invalid"
                ) from exc
            previous = snapshot

        if previous is None:
            raise OfflineReportFindingOriginsError("snapshot history is empty")
        head = previous
        reference = references[finding.finding_id]
        if (
            reference.snapshot_sha256 != head.snapshot_sha256
            or reference.state != head.state.value
            or reference.updated_at != head.updated_at
            or finding.lifecycle_snapshot_sha256 != head.snapshot_sha256
            or finding.status != head.state.value
        ):
            raise OfflineReportFindingOriginsError(
                "report lifecycle reference does not match the supplied head"
            )
        if (
            finding.vulnerability_class != head.identity.vulnerability_class
            or finding.severity != head.classification.severity.value
            or finding.cwe_ref not in head.classification.cwe_refs
            or (
                finding.cvss_vector is not None
                and finding.cvss_vector not in head.classification.cvss_refs
            )
            or not set(finding.evidence_digests).issubset(head.evidence_digests)
        ):
            raise OfflineReportFindingOriginsError(
                "report finding details do not match the supplied head"
            )
        heads.append(
            {
                "finding_id": head.finding_id,
                "finding_version": head.finding_version,
                "snapshot_sha256": head.snapshot_sha256,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "matched_local_originals",
        "report_id": original_report.report_id,
        "report_sha256": original_report.report_sha256,
        "finding_count": len(heads),
        "snapshot_count": total_snapshots,
        "snapshot_heads": heads,
        "asset_operation_identity_binding": "not_proven",
        "live_source_currentness": "not_proven",
        "authenticated_review": "not_proven",
        "external_anti_rollback": "not_proven",
        "authorization_effect": "none",
        "qualification_effect": "none",
        "target_effect": "none",
    }


__all__ = ["OfflineReportFindingOriginsError", "verify_report_finding_origins"]
