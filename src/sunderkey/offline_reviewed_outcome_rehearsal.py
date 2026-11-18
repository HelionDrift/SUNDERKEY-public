"""Bind local review signatures to asserted outcomes for simulation only."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .coverage_outcome_snapshot import (
    CoverageOutcomeSnapshotError,
    build_coverage_outcome_snapshot,
)
from .coverage_scheduler import CoverageSchedule
from .offline_task_review_receipts import (
    OfflineTaskReviewReceiptError,
    ReviewerKeyBinding,
    verify_offline_task_review_packet,
)

DOMAIN = "sunderkey.offline-reviewed-outcome-rehearsal.v1"
NO_EFFECTS = {
    "admission": "none",
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class OfflineReviewedOutcomeRehearsalError(ValueError):
    """Raised when an asserted success lacks matching local review."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _time(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) != 20:
        raise OfflineReviewedOutcomeRehearsalError("rehearsal timestamp is invalid")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineReviewedOutcomeRehearsalError("rehearsal timestamp is invalid") from exc
    return value


def build_offline_reviewed_outcome_rehearsal(
    *,
    schedule: CoverageSchedule,
    observations: Mapping[str, Mapping[str, Any]],
    review_packets: Mapping[str, Mapping[str, Any]],
    reviewer_keys: Mapping[str, ReviewerKeyBinding],
    rehearsed_at: str,
) -> dict[str, Any]:
    """Require two local signatures per asserted success, with no live-use claim."""

    _time(rehearsed_at)
    if not isinstance(schedule, CoverageSchedule) or rehearsed_at < schedule.limits.as_of:
        raise OfflineReviewedOutcomeRehearsalError("rehearsal precedes its schedule")
    try:
        snapshot = build_coverage_outcome_snapshot(schedule, observations)
        if not isinstance(review_packets, Mapping):
            raise OfflineReviewedOutcomeRehearsalError("review packets must be a mapping")
        succeeded = {
            item["task_id"]: item
            for item in snapshot["outcomes"]
            if item["status"] == "succeeded"
        }
        if set(review_packets) != set(succeeded):
            raise OfflineReviewedOutcomeRehearsalError(
                "successful outcomes and review packets differ"
            )
        bindings = []
        for task_id in sorted(succeeded):
            packet = verify_offline_task_review_packet(
                schedule=schedule,
                packet=review_packets[task_id],
                reviewer_keys=reviewer_keys,
            )
            candidate = packet["work_product"]
            if (
                packet["review_state"] != "locally_accepted"
                or candidate["task_id"] != task_id
                or candidate["evidence_sha256s"] != succeeded[task_id]["evidence_digests"]
                or any(item["reviewed_at"] > rehearsed_at for item in packet["attestations"])
            ):
                raise OfflineReviewedOutcomeRehearsalError(
                    "successful outcome lacks matching completed review"
                )
            bindings.append(
                {
                    "task_id": task_id,
                    "work_product_sha256": candidate["work_product_sha256"],
                    "review_packet_sha256": packet["packet_sha256"],
                }
            )
    except OfflineReviewedOutcomeRehearsalError:
        raise
    except (CoverageOutcomeSnapshotError, OfflineTaskReviewReceiptError, TypeError) as exc:
        raise OfflineReviewedOutcomeRehearsalError("outcome sources are invalid") from exc
    body = {
        "schema_version": 1,
        "schedule_sha256": schedule.schedule_sha256,
        "outcome_snapshot": snapshot,
        "review_bindings": bindings,
        "rehearsed_at": rehearsed_at,
        "key_binding_assurance": "caller_provided",
        "source_authentication": "not_verified",
        "simulation_only": True,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "rehearsal_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_reviewed_outcome_rehearsal(
    *,
    document: Mapping[str, Any],
    schedule: CoverageSchedule,
    observations: Mapping[str, Mapping[str, Any]],
    review_packets: Mapping[str, Mapping[str, Any]],
    reviewer_keys: Mapping[str, ReviewerKeyBinding],
    rehearsed_at: str,
) -> dict[str, Any]:
    expected = build_offline_reviewed_outcome_rehearsal(
        schedule=schedule,
        observations=observations,
        review_packets=review_packets,
        reviewer_keys=reviewer_keys,
        rehearsed_at=rehearsed_at,
    )
    try:
        same = isinstance(document, Mapping) and _canonical(dict(document)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineReviewedOutcomeRehearsalError("reviewed outcome does not match sources")
    return expected


__all__ = [
    "OfflineReviewedOutcomeRehearsalError",
    "build_offline_reviewed_outcome_rehearsal",
    "verify_offline_reviewed_outcome_rehearsal",
]
