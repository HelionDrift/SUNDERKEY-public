"""Bind proposal-only API review to the exact synthetic planning lineage."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .coverage_scheduler import CoverageSchedule
from .offline_api_assessment import OfflineApiAssessmentError, verify_offline_api_batch
from .offline_api_planning_bundle import (
    OfflineApiPlanningError,
    verify_offline_api_planning_bundle,
)
from .offline_api_review_handoff import (
    OfflineApiReviewHandoffError,
    verify_offline_api_review_handoff,
)

BRIDGE_DOMAIN = "sunderkey.offline-api-review-plan-bridge.v1"
NO_EFFECTS = {
    "assignment": "none",
    "execution": "none",
    "finding_publication": "none",
    "notification": "none",
    "review_decision": "none",
}


class OfflineApiReviewPlanBridgeError(ValueError):
    """Raised when review and planning do not share source lineage."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_review_plan_bridge(
    *,
    tenant_id: str,
    planning_bundle: Mapping[str, Any],
    review_handoff: Mapping[str, Any],
    planning_options: Mapping[str, Any],
    review_options: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay both source paths, then bind review candidates to the plan."""

    try:
        planning = verify_offline_api_planning_bundle(
            bundle=planning_bundle, **planning_options
        )
        review = verify_offline_api_review_handoff(
            handoff=review_handoff, **review_options
        )
        if (
            planning["batch_sha256"] != review["batch_sha256"]
            or planning["scope_sha256"] != review_options["scope_binding_sha256"]
        ):
            raise OfflineApiReviewPlanBridgeError("review and planning source context differs")
        batch = verify_offline_api_batch(
            adapter=planning_options["adapter"],
            sources=planning_options["sources"],
            batch=planning_options["batch"],
        )
        if (
            tenant_id != review_options["tenant_id"]
            or tenant_id != review["routing_plan"]["tenant_id"]
        ):
            raise OfflineApiReviewPlanBridgeError("review tenant context differs")
        schedule = CoverageSchedule.from_dict(planning["schedule"])
    except OfflineApiReviewPlanBridgeError:
        raise
    except (
        OfflineApiAssessmentError,
        OfflineApiPlanningError,
        OfflineApiReviewHandoffError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise OfflineApiReviewPlanBridgeError("review planning sources are invalid") from exc
    candidates = set(batch.review_candidate_case_ids)
    cases = [
        {
            "case_id": item.case_id,
            "result_sha256": item.result_sha256,
            "review_status": "pending",
        }
        for item in batch.cases
        if item.case_id in candidates
    ]
    if len(cases) != review["review_case_count"]:
        raise OfflineApiReviewPlanBridgeError("review candidate set differs")
    body = {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "scope_sha256": planning["scope_sha256"],
        "batch_sha256": batch.batch_sha256,
        "planning_bundle_sha256": planning["bundle_sha256"],
        "schedule_sha256": schedule.schedule_sha256,
        "review_handoff_sha256": review["handoff_sha256"],
        "review_cases": cases,
        "plan_tasks": [
            {
                "task_id": item.task_id,
                "task_sha256": item.task_sha256,
                "task_type": item.task_type.value,
            }
            for item in schedule.tasks
        ],
        "review_state": "awaiting_independent_human_review",
        "finding_state": "not_published",
        "origin_authentication": "not_verified",
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "bridge_sha256": _digest({"domain": BRIDGE_DOMAIN, "bridge": body})}


def verify_offline_api_review_plan_bridge(
    *,
    tenant_id: str,
    bridge: Mapping[str, Any],
    planning_bundle: Mapping[str, Any],
    review_handoff: Mapping[str, Any],
    planning_options: Mapping[str, Any],
    review_options: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_offline_api_review_plan_bridge(
        tenant_id=tenant_id,
        planning_bundle=planning_bundle,
        review_handoff=review_handoff,
        planning_options=planning_options,
        review_options=review_options,
    )
    try:
        same = isinstance(bridge, Mapping) and _canonical(dict(bridge)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiReviewPlanBridgeError("review planning bridge does not match sources")
    return expected


__all__ = [
    "OfflineApiReviewPlanBridgeError",
    "build_offline_api_review_plan_bridge",
    "verify_offline_api_review_plan_bridge",
]
