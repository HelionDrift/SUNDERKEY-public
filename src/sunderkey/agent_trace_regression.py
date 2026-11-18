"""Compare two reproduced, same-policy redacted agent trace reviews."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .agent_trace_review import AgentTraceReviewError, verify_agent_trace_review
from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes

SCHEMA_VERSION = 1
MAX_COMPARISON_BYTES = 1_000_000
DOMAIN = "sunderkey.agent-trace-regression.v1"


class AgentTraceRegressionError(ValueError):
    """Trace reviews cannot be compared or reproduced safely."""


def _sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _issue_counts(review: Mapping[str, Any]) -> Counter[str]:
    return Counter(issue["code"] for issue in review["issues"])


def build_agent_trace_regression(
    prior_trace: Any,
    prior_review: Any,
    current_trace: Any,
    current_review: Any,
) -> dict[str, Any]:
    """Describe observed issue-count changes, not fixes or live regressions."""
    try:
        verify_agent_trace_review(prior_trace, prior_review)
        verify_agent_trace_review(current_trace, current_review)
    except AgentTraceReviewError as exc:
        raise AgentTraceRegressionError("a source trace review is not reproducible") from exc
    if (
        prior_trace["tenant_ref"] != current_trace["tenant_ref"]
        or prior_trace["scope_sha256"] != current_trace["scope_sha256"]
        or prior_trace["case_ref"] != current_trace["case_ref"]
    ):
        raise AgentTraceRegressionError("trace tenant, scope, and case must match")
    if prior_trace["policy"] != current_trace["policy"]:
        raise AgentTraceRegressionError("trace policies must match for comparison")
    if _instant(prior_trace["observed_at"]) >= _instant(current_trace["observed_at"]):
        raise AgentTraceRegressionError("current trace must have a later observed_at")
    if prior_trace["source_trace_sha256"] == current_trace["source_trace_sha256"]:
        raise AgentTraceRegressionError("current trace must assert a distinct source")
    prior_counts = _issue_counts(prior_review)
    current_counts = _issue_counts(current_review)
    codes = sorted(prior_counts.keys() | current_counts.keys())
    newly_observed = [
        {"code": code, "count": current_counts[code] - prior_counts[code]}
        for code in codes if current_counts[code] > prior_counts[code]
    ]
    no_longer_observed = [
        {"code": code, "count": prior_counts[code] - current_counts[code]}
        for code in codes if prior_counts[code] > current_counts[code]
    ]
    if newly_observed and no_longer_observed:
        status = "mixed_observed_change"
    elif newly_observed:
        status = "new_issues_observed"
    elif no_longer_observed:
        status = "issues_no_longer_observed"
    else:
        status = "no_issue_count_change"
    body = {
        "schema_version": SCHEMA_VERSION,
        "tenant_ref": prior_trace["tenant_ref"],
        "scope_sha256": prior_trace["scope_sha256"],
        "case_ref": prior_trace["case_ref"],
        "policy_sha256": _sha(prior_trace["policy"]),
        "prior_trace_sha256": prior_review["trace_sha256"],
        "current_trace_sha256": current_review["trace_sha256"],
        "prior_review_sha256": prior_review["review_sha256"],
        "current_review_sha256": current_review["review_sha256"],
        "prior_source_trace_sha256": prior_trace["source_trace_sha256"],
        "current_source_trace_sha256": current_trace["source_trace_sha256"],
        "prior_review_status": prior_review["review_status"],
        "current_review_status": current_review["review_status"],
        "prior_tool_execution_count": prior_review["tool_execution_count"],
        "current_tool_execution_count": current_review["tool_execution_count"],
        "newly_observed_issues": newly_observed,
        "no_longer_observed_issues": no_longer_observed,
        "comparison_status": status,
        "qualification_effect": "none",
        "interpretation": "trace_metadata_change_only_not_a_verified_fix_or_live_regression",
    }
    digest = _sha({"domain": DOMAIN, "content": body})
    return {
        **body,
        "comparison_id": "ATC-" + digest[7:39].upper(),
        "comparison_sha256": digest,
    }


def verify_agent_trace_regression(
    prior_trace: Any,
    prior_review: Any,
    current_trace: Any,
    current_review: Any,
    comparison: Any,
) -> dict[str, Any]:
    """Reproduce comparison from all four exact source artifacts."""
    expected = build_agent_trace_regression(
        prior_trace, prior_review, current_trace, current_review,
    )
    try:
        supplied = canonical_json_bytes(comparison, max_bytes=MAX_COMPARISON_BYTES)
        reproduced = canonical_json_bytes(expected, max_bytes=MAX_COMPARISON_BYTES)
    except JsonContractIntegrityError as exc:
        raise AgentTraceRegressionError("comparison must be bounded exact JSON") from exc
    if supplied != reproduced:
        raise AgentTraceRegressionError("comparison does not reproduce from sources")
    return {
        "status": "valid",
        "comparison_id": expected["comparison_id"],
        "comparison_sha256": expected["comparison_sha256"],
        "comparison_status": expected["comparison_status"],
        "qualification_effect": "none",
    }
