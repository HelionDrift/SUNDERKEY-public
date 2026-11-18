"""Read-only commander handoff for reproduced offline specialist reviews."""

from __future__ import annotations

import json
from typing import Any

from .offline_review_workflow import (
    MAX_JOBS,
    OfflineReviewWorkflowError,
    verify_offline_review_bundle,
)
from .traffic_derived_api_inventory import _canonical_sha

SCHEMA_VERSION = 1
MAX_HANDOFF_BYTES = 1_000_000
NO_EFFECTS = {
    "assignment": "none",
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "target_interaction": "none",
}


class OfflineReviewHandoffError(ValueError):
    """Handoff could not be derived or reproduced from exact offline inputs."""


def _classify(job: dict[str, Any]) -> tuple[str, list[str]]:
    kind = job["kind"]
    result = job["result"]
    if kind in {"credential_exposure", "synthetic_scenario"}:
        dispositions = sorted({item["disposition"] for item in result["items"]})
        if "human_review_candidate" in dispositions:
            lane = "candidate_for_independent_review"
        elif dispositions in (["stale_signal"], ["expired_request"]):
            lane = "stale"
        else:
            lane = "inconclusive"
        return lane, dispositions or ["no_review_items"]
    if kind == "decoy_lifecycle":
        flags = result["review_flags"]
        if flags:
            return "attention_for_independent_review", list(flags)
        if result["state"] == "awaiting_placement":
            return "inconclusive", ["awaiting_placement"]
        return "candidate_for_independent_review", [result["state"]]
    if kind == "restricted_asset":
        lane = {
            "bounded_inference_for_review": "candidate_for_independent_review",
            "counterevidence_present": "attention_for_independent_review",
            "stale_evidence": "stale",
        }.get(result["status"], "inconclusive")
        return lane, list(result["reasons"])
    if kind == "inert_resilience":
        lane = {
            "readiness_evidence_for_review": "candidate_for_independent_review",
            "gap_requires_review": "attention_for_independent_review",
            "stale_evidence": "stale",
        }.get(result["status"], "inconclusive")
        return lane, list(result["review_reasons"])
    if kind == "detection_rule":
        lane = {
            "metadata_healthy_for_review": "candidate_for_independent_review",
            "attention_required": "attention_for_independent_review",
            "stale_evidence": "stale",
        }.get(result["status"], "inconclusive")
        return lane, list(result["reasons"])
    if kind == "metadata_impact":
        signals = result["signals"]
        statuses = {signal["review_status"] for signal in signals}
        reasons = sorted({
            reason for signal in signals for reason in signal["review_reasons"]
        })
        if statuses.intersection({"review_required", "triage_required"}):
            lane = "attention_for_independent_review"
        elif statuses == {"stale_metadata"}:
            lane = "stale"
        else:
            lane = "inconclusive"
        return lane, reasons or ["no_impact_signals"]
    if kind == "email_control":
        lane = {
            "asserted_prevention_for_review": "candidate_for_independent_review",
            "attention_required": "attention_for_independent_review",
            "stale_evidence": "stale",
        }.get(result["status"], "inconclusive")
        return lane, list(result["review_reasons"])
    return "inconclusive", ["unmapped_review_kind"]


def build_offline_review_handoff(request: Any, bundle: Any) -> dict[str, Any]:
    """Derive a bounded review queue only after exact bundle reproduction."""
    try:
        verify_offline_review_bundle(request, bundle)
    except OfflineReviewWorkflowError as exc:
        raise OfflineReviewHandoffError("source review bundle is not reproducible") from exc
    items = []
    for job in bundle["jobs"]:
        lane, reasons = _classify(job)
        items.append({
            "job_id": job["job_id"],
            "kind": job["kind"],
            "result_sha256": job["result_sha256"],
            "review_lane": lane,
            "reason_codes": sorted(set(reasons)),
            "independent_human_review_required": True,
        })
    if len(items) > MAX_JOBS:
        raise OfflineReviewHandoffError("handoff item count exceeds its limit")
    body = {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": bundle["tenant_id"],
        "scope_sha256": bundle["scope_sha256"],
        "reviewed_at": bundle["reviewed_at"],
        "source_bundle_sha256": bundle["bundle_sha256"],
        "items": items,
        "review_status": "prepared_for_independent_human_review",
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "handoff_sha256": _canonical_sha("sunderkey.offline-review-handoff.v1", body),
    }


def verify_offline_review_handoff(
    request: Any, bundle: Any, handoff: Any,
) -> dict[str, Any]:
    """Reproduce every source review and the exact derived handoff."""
    expected = build_offline_review_handoff(request, bundle)
    try:
        actual_json = json.dumps(
            handoff, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        expected_json = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise OfflineReviewHandoffError("handoff is not valid JSON data") from exc
    if actual_json != expected_json:
        raise OfflineReviewHandoffError("handoff does not reproduce from its sources")
    return {
        "status": "valid",
        "handoff_sha256": expected["handoff_sha256"],
        "source_bundle_sha256": expected["source_bundle_sha256"],
        "item_count": len(expected["items"]),
        "verification_scope": "offline_reproduction_only",
        "origin_authentication": "not_verified",
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
    }
