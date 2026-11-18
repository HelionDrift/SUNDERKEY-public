"""Bind asserted terminal task outcomes to one immutable coverage schedule."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .coverage_scheduler import CoverageSchedule, CoverageSchedulerError, OutcomeStatus

OUTCOME_DOMAIN = "sunderkey.coverage-outcome-snapshot.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "execution": "none",
    "qualification": "none",
    "source_authentication": "none",
    "target_action": "none",
}


class CoverageOutcomeSnapshotError(ValueError):
    """Raised when asserted outcomes do not bind to the exact schedule."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_coverage_outcome_snapshot(
    schedule: CoverageSchedule,
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive task keys and world identity from the schedule, not the caller."""

    if not isinstance(schedule, CoverageSchedule):
        raise CoverageOutcomeSnapshotError("schedule must be typed")
    try:
        checked = CoverageSchedule.from_dict(schedule.to_dict())
    except CoverageSchedulerError as exc:
        raise CoverageOutcomeSnapshotError("schedule identity is invalid") from exc
    if not isinstance(observations, Mapping) or len(observations) > len(checked.tasks):
        raise CoverageOutcomeSnapshotError("observations must be a bounded mapping")
    tasks = {task.task_id: task for task in checked.tasks}
    outcomes: list[dict[str, Any]] = []
    for task_id, raw in observations.items():
        if task_id not in tasks or not isinstance(raw, Mapping):
            raise CoverageOutcomeSnapshotError("observation names an unknown task")
        if set(raw) != {"status", "evidence_digests"}:
            raise CoverageOutcomeSnapshotError("observation fields are invalid")
        try:
            status = OutcomeStatus(raw["status"])
        except (TypeError, ValueError) as exc:
            raise CoverageOutcomeSnapshotError("observation status is invalid") from exc
        if status in {OutcomeStatus.PENDING, OutcomeStatus.RUNNING}:
            raise CoverageOutcomeSnapshotError("observation must be terminal")
        digests = raw["evidence_digests"]
        if (
            not isinstance(digests, (list, tuple))
            or len(digests) > 64
            or any(
                not isinstance(item, str) or SHA256_RE.fullmatch(item) is None
                for item in digests
            )
        ):
            raise CoverageOutcomeSnapshotError("observation evidence digests are invalid")
        if status is OutcomeStatus.SUCCEEDED and not digests:
            raise CoverageOutcomeSnapshotError("successful observation requires evidence")
        task = tasks[task_id]
        outcomes.append(
            {
                "task_id": task_id,
                "task_key": task.task_key,
                "world_snapshot_sha256": task.world_snapshot_sha256,
                "status": status.value,
                "evidence_digests": sorted(set(digests)),
            }
        )
    body = {
        "schema_version": 1,
        "schedule_id": checked.schedule_id,
        "schedule_sha256": checked.schedule_sha256,
        "world_snapshot_sha256": checked.world_snapshot_sha256,
        "outcomes": sorted(outcomes, key=lambda item: item["task_id"]),
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "snapshot_sha256": _digest({"domain": OUTCOME_DOMAIN, "body": body})}


def verify_coverage_outcome_snapshot(
    schedule: CoverageSchedule, document: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify structural identity only, without authenticating outcome sources."""

    if not isinstance(document, Mapping) or not isinstance(document.get("outcomes"), list):
        raise CoverageOutcomeSnapshotError("outcome snapshot document is invalid")
    try:
        observations = {
            item["task_id"]: {
                "status": item["status"],
                "evidence_digests": item["evidence_digests"],
            }
            for item in document["outcomes"]
        }
        if len(observations) != len(document["outcomes"]):
            raise CoverageOutcomeSnapshotError("outcome snapshot has duplicate task IDs")
        expected = build_coverage_outcome_snapshot(schedule, observations)
        if _canonical(dict(document)) != _canonical(expected):
            raise CoverageOutcomeSnapshotError("outcome snapshot does not match schedule")
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, CoverageOutcomeSnapshotError):
            raise
        raise CoverageOutcomeSnapshotError("outcome snapshot document is invalid") from exc
    return expected


def prior_task_outcomes_from_snapshot(
    schedule: CoverageSchedule, document: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Return only schedule-bound asserted outcomes for offline replanning."""

    checked = verify_coverage_outcome_snapshot(schedule, document)
    return {
        item["task_id"]: {
            "task_key": item["task_key"],
            "world_snapshot_sha256": item["world_snapshot_sha256"],
            "status": item["status"],
            "evidence_digests": list(item["evidence_digests"]),
        }
        for item in checked["outcomes"]
    }


__all__ = [
    "CoverageOutcomeSnapshotError",
    "build_coverage_outcome_snapshot",
    "prior_task_outcomes_from_snapshot",
    "verify_coverage_outcome_snapshot",
]
