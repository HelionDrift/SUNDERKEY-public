"""Prepare a nonfinding reviewer index from reproduced offline API lineage."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .offline_api_retest_transition_bridge import (
    OfflineApiRetestTransitionError,
    verify_offline_api_retest_transition,
)
from .offline_api_review_plan_bridge import (
    OfflineApiReviewPlanBridgeError,
    verify_offline_api_review_plan_bridge,
)

DOMAIN = "sunderkey.offline-api-reviewer-dossier.v1"
NO_EFFECTS = {
    "assignment": "none",
    "execution": "none",
    "finding_publication": "none",
    "remediation_claim": "none",
    "report_publication": "none",
    "review_decision": "none",
}


class OfflineApiReviewerDossierError(ValueError):
    """Raised when a reviewer index does not match its replayed sources."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_reviewer_dossier(
    *,
    review_bridge: Mapping[str, Any],
    transition: Mapping[str, Any],
    review_bridge_options: Mapping[str, Any],
    transition_options: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay both branches and expose only digests and pending states."""

    try:
        review = verify_offline_api_review_plan_bridge(
            bridge=review_bridge, **review_bridge_options
        )
        retest = verify_offline_api_retest_transition(
            document=transition, **transition_options
        )
        matches = [
            item
            for item in review["review_cases"]
            if item["case_id"] == retest["prior_case_id"]
        ]
        prior_entries = [
            item
            for item in retest["child_lineage"]["source_ledger"]["cases"]
            if item["case_id"] == retest["prior_case_id"]
        ]
        scope = review_bridge_options["planning_options"]["scope"]
        if (
            len(matches) != 1
            or len(prior_entries) != 1
            or matches[0]["result_sha256"]
            != retest["comparison"]["prior_result_sha256"]
            or prior_entries[0]["batch_sha256"] != review["batch_sha256"]
            or retest["child_lineage"]["scope_id"] != scope.scope_id
            or review["scope_sha256"] != scope.content_sha256
            or review["tenant_id"] != review_bridge_options["tenant_id"]
        ):
            raise OfflineApiReviewerDossierError("review and retest source lineage differs")
    except OfflineApiReviewerDossierError:
        raise
    except (
        OfflineApiReviewPlanBridgeError,
        OfflineApiRetestTransitionError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise OfflineApiReviewerDossierError("reviewer dossier sources are invalid") from exc
    body = {
        "schema_version": 1,
        "tenant_id": review["tenant_id"],
        "scope_sha256": review["scope_sha256"],
        "batch_sha256": review["batch_sha256"],
        "planning_bundle_sha256": review["planning_bundle_sha256"],
        "schedule_sha256": review["schedule_sha256"],
        "review_handoff_sha256": review["review_handoff_sha256"],
        "transition_sha256": retest["transition_sha256"],
        "child_world_snapshot_sha256": retest["child_lineage"]["world_snapshot"][
            "snapshot_sha256"
        ],
        "prior_case_id": retest["prior_case_id"],
        "second_case_id": retest["second_case_id"],
        "prior_result_sha256": retest["comparison"]["prior_result_sha256"],
        "second_result_sha256": retest["comparison"]["second_result_sha256"],
        "observation_change": retest["observation_change"],
        "proposed_task_ids": [item["task_id"] for item in review["plan_tasks"]],
        "review_status": "awaiting_independent_human_review",
        "finding_count": 0,
        "finding_state": "not_published",
        "report_state": "nonfinding_reviewer_draft",
        "origin_authentication": "not_verified",
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "dossier_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_reviewer_dossier(
    *,
    document: Mapping[str, Any],
    review_bridge: Mapping[str, Any],
    transition: Mapping[str, Any],
    review_bridge_options: Mapping[str, Any],
    transition_options: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_offline_api_reviewer_dossier(
        review_bridge=review_bridge,
        transition=transition,
        review_bridge_options=review_bridge_options,
        transition_options=transition_options,
    )
    try:
        same = isinstance(document, Mapping) and _canonical(dict(document)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiReviewerDossierError("reviewer dossier does not match sources")
    return expected


__all__ = [
    "OfflineApiReviewerDossierError",
    "build_offline_api_reviewer_dossier",
    "verify_offline_api_reviewer_dossier",
]
