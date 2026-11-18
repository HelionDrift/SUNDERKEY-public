"""Bind a locally reviewed task to an unpublished, nonfinding report draft."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .coverage_scheduler import CoverageSchedule, CoverageSchedulerError
from .offline_api_reviewer_dossier import (
    OfflineApiReviewerDossierError,
    verify_offline_api_reviewer_dossier,
)
from .offline_task_review_receipts import (
    OfflineTaskReviewReceiptError,
    ReviewerKeyBinding,
    verify_offline_task_review_packet,
)

DOMAIN = "sunderkey.offline-reviewed-report-draft.v1"
NO_EFFECTS = {
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "report_publication": "none",
    "reviewer_enrollment": "none",
}


class OfflineReviewedReportDraftError(ValueError):
    """Raised when a local review and its report lineage disagree."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_reviewed_report_draft(
    *,
    dossier: Mapping[str, Any],
    dossier_options: Mapping[str, Any],
    schedule: CoverageSchedule,
    review_packet: Mapping[str, Any],
    reviewer_keys: Mapping[str, ReviewerKeyBinding],
) -> dict[str, Any]:
    """Replay local sources and index one reviewed task without publishing a finding."""

    try:
        checked_dossier = verify_offline_api_reviewer_dossier(
            document=dossier, **dossier_options
        )
        checked_schedule = CoverageSchedule.from_dict(schedule.to_dict())
        packet = verify_offline_task_review_packet(
            schedule=checked_schedule,
            packet=review_packet,
            reviewer_keys=reviewer_keys,
        )
        work = packet["work_product"]
        if (
            checked_schedule.schedule_sha256 != checked_dossier["schedule_sha256"]
            or checked_schedule.scope_sha256 != checked_dossier["scope_sha256"]
            or work["task_id"] not in checked_dossier["proposed_task_ids"]
            or work["schedule_sha256"] != checked_dossier["schedule_sha256"]
            or packet["review_state"] != "locally_accepted"
        ):
            raise OfflineReviewedReportDraftError("report draft lineage or review differs")
    except OfflineReviewedReportDraftError:
        raise
    except (
        OfflineApiReviewerDossierError,
        OfflineTaskReviewReceiptError,
        CoverageSchedulerError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise OfflineReviewedReportDraftError("report draft sources are invalid") from exc
    body = {
        "schema_version": 1,
        "tenant_id": checked_dossier["tenant_id"],
        "scope_sha256": checked_dossier["scope_sha256"],
        "schedule_sha256": checked_schedule.schedule_sha256,
        "dossier_sha256": checked_dossier["dossier_sha256"],
        "transition_sha256": checked_dossier["transition_sha256"],
        "task_id": work["task_id"],
        "task_sha256": work["task_sha256"],
        "work_product_sha256": work["work_product_sha256"],
        "review_packet_sha256": packet["packet_sha256"],
        "reviewer_key_ids": sorted(item["key_id"] for item in packet["attestations"]),
        "review_state": "locally_accepted_under_caller_provided_keys",
        "finding_count": 0,
        "finding_state": "not_published",
        "report_state": "unpublished_nonfinding_draft",
        "origin_authentication": "not_verified",
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "draft_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_reviewed_report_draft(
    *,
    document: Mapping[str, Any],
    dossier: Mapping[str, Any],
    dossier_options: Mapping[str, Any],
    schedule: CoverageSchedule,
    review_packet: Mapping[str, Any],
    reviewer_keys: Mapping[str, ReviewerKeyBinding],
) -> dict[str, Any]:
    expected = build_offline_reviewed_report_draft(
        dossier=dossier,
        dossier_options=dossier_options,
        schedule=schedule,
        review_packet=review_packet,
        reviewer_keys=reviewer_keys,
    )
    try:
        same = isinstance(document, Mapping) and _canonical(dict(document)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineReviewedReportDraftError("report draft does not match sources")
    return expected


__all__ = [
    "OfflineReviewedReportDraftError",
    "build_offline_reviewed_report_draft",
    "verify_offline_reviewed_report_draft",
]
