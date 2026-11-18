"""Compare two independently reproduced offline specialist review snapshots."""

from __future__ import annotations

import json
from typing import Any

from .offline_review_handoff import (
    OfflineReviewHandoffError,
    verify_offline_review_handoff,
)
from .traffic_derived_api_inventory import _canonical_sha, _timestamp

SCHEMA_VERSION = 1
MAX_TRANSITION_BYTES = 1_000_000
SOURCE_FIELDS = {
    "credential_exposure": ("signal_sha256", "consent_sha256"),
    "synthetic_scenario": ("request_sha256", "consent_sha256"),
    "decoy_lifecycle": ("approval_sha256", "event_sha256"),
    "restricted_asset": ("case_sha256", "observation_sha256"),
    "inert_resilience": ("scenario_sha256", "observation_sha256"),
    "detection_rule": ("snapshot_sha256", "observation_sha256"),
    "metadata_impact": ("observation_sha256",),
    "email_control": ("approval_sha256", "observation_sha256", "cleanup_sha256"),
}
NO_EFFECTS = {
    "assignment": "none",
    "authority": "none",
    "finding_publication": "none",
    "network": "none",
    "retest_execution": "none",
    "target_interaction": "none",
}


class OfflineReviewTransitionError(ValueError):
    """Snapshot transition is not comparable or reproducible."""


def _source_fingerprint(job: dict[str, Any]) -> str | None:
    fields = SOURCE_FIELDS.get(job["kind"])
    if fields is None:
        return None
    result = job["result"]
    return _canonical_sha(
        "sunderkey.offline-review-declared-sources.v1",
        {"kind": job["kind"], "sources": {name: result[name] for name in fields}},
    )


def _transition_item(
    job_id: str,
    prior_job: dict[str, Any] | None,
    current_job: dict[str, Any] | None,
    prior_handoff: dict[str, Any] | None,
    current_handoff: dict[str, Any] | None,
) -> dict[str, Any]:
    prior_source = _source_fingerprint(prior_job) if prior_job else None
    current_source = _source_fingerprint(current_job) if current_job else None
    if prior_job is None:
        change_type = "added_job"
    elif current_job is None:
        change_type = "removed_job"
    elif prior_job["kind"] != current_job["kind"]:
        change_type = "kind_changed"
    elif prior_source is None or current_source is None:
        change_type = "unmapped_kind"
    else:
        source_relation = (
            "same_declared_sources" if prior_source == current_source
            else "changed_declared_sources"
        )
        review_relation = (
            "same_review" if (
                prior_handoff["review_lane"], prior_handoff["reason_codes"]
            ) == (
                current_handoff["review_lane"], current_handoff["reason_codes"]
            ) else "review_changed"
        )
        change_type = f"{source_relation}_{review_relation}"
    return {
        "job_id": job_id,
        "prior_kind": prior_job["kind"] if prior_job else None,
        "current_kind": current_job["kind"] if current_job else None,
        "prior_declared_sources_sha256": prior_source,
        "current_declared_sources_sha256": current_source,
        "prior_result_sha256": prior_job["result_sha256"] if prior_job else None,
        "current_result_sha256": current_job["result_sha256"] if current_job else None,
        "prior_review_lane": prior_handoff["review_lane"] if prior_handoff else None,
        "current_review_lane": current_handoff["review_lane"] if current_handoff else None,
        "change_type": change_type,
        "verified_fix": False,
        "confirmed_regression": False,
    }


def build_offline_review_transition(
    prior_request: Any,
    prior_bundle: Any,
    prior_handoff: Any,
    current_request: Any,
    current_bundle: Any,
    current_handoff: Any,
) -> dict[str, Any]:
    """Compare declared sources and review lanes, never infer a live outcome."""
    try:
        verify_offline_review_handoff(prior_request, prior_bundle, prior_handoff)
        verify_offline_review_handoff(current_request, current_bundle, current_handoff)
    except OfflineReviewHandoffError as exc:
        raise OfflineReviewTransitionError("source handoff is not reproducible") from exc
    if (
        prior_handoff["tenant_id"] != current_handoff["tenant_id"]
        or prior_handoff["scope_sha256"] != current_handoff["scope_sha256"]
    ):
        raise OfflineReviewTransitionError("snapshots cross tenant or scope")
    if _timestamp(prior_handoff["reviewed_at"], "reviewed_at") >= _timestamp(
        current_handoff["reviewed_at"], "reviewed_at",
    ):
        raise OfflineReviewTransitionError("snapshot times are not strictly ordered")
    prior_jobs = {job["job_id"]: job for job in prior_bundle["jobs"]}
    current_jobs = {job["job_id"]: job for job in current_bundle["jobs"]}
    prior_items = {item["job_id"]: item for item in prior_handoff["items"]}
    current_items = {item["job_id"]: item for item in current_handoff["items"]}
    items = [
        _transition_item(
            job_id, prior_jobs.get(job_id), current_jobs.get(job_id),
            prior_items.get(job_id), current_items.get(job_id),
        )
        for job_id in sorted(prior_jobs.keys() | current_jobs.keys())
    ]
    body = {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": prior_handoff["tenant_id"],
        "scope_sha256": prior_handoff["scope_sha256"],
        "prior_reviewed_at": prior_handoff["reviewed_at"],
        "current_reviewed_at": current_handoff["reviewed_at"],
        "prior_bundle_sha256": prior_bundle["bundle_sha256"],
        "current_bundle_sha256": current_bundle["bundle_sha256"],
        "prior_handoff_sha256": prior_handoff["handoff_sha256"],
        "current_handoff_sha256": current_handoff["handoff_sha256"],
        "items": items,
        "review_status": "comparison_for_independent_human_review",
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "transition_sha256": _canonical_sha("sunderkey.offline-review-transition.v1", body),
    }


def verify_offline_review_transition(
    prior_request: Any,
    prior_bundle: Any,
    prior_handoff: Any,
    current_request: Any,
    current_bundle: Any,
    current_handoff: Any,
    transition: Any,
) -> dict[str, Any]:
    """Reproduce both review snapshots and the complete transition record."""
    expected = build_offline_review_transition(
        prior_request, prior_bundle, prior_handoff,
        current_request, current_bundle, current_handoff,
    )
    try:
        expected_json = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        actual_json = json.dumps(
            transition, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise OfflineReviewTransitionError("transition is not valid JSON data") from exc
    if actual_json != expected_json:
        raise OfflineReviewTransitionError("transition does not reproduce from sources")
    return {
        "status": "valid",
        "transition_sha256": expected["transition_sha256"],
        "item_count": len(expected["items"]),
        "verification_scope": "offline_reproduction_only",
        "origin_authentication": "not_verified",
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
    }
