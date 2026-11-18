"""Bind a synthetic API observation change to source and world lineage."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    compare_offline_api_retest,
    verify_offline_api_case,
)
from .offline_api_retest_lineage import (
    OfflineApiRetestLineageError,
    append_offline_api_retest_lineage,
    verify_offline_api_retest_lineage,
)
from .reference_adapters import OfflineReferenceAdapter

DOMAIN = "sunderkey.offline-api-retest-transition-bridge.v1"
NO_EFFECTS = {
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "remediation_claim": "none",
    "review_decision": "none",
}


class OfflineApiRetestTransitionError(ValueError):
    """Raised when a retest transition cannot be tied to its child lineage."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_retest_transition(
    *,
    prior_lineage: Mapping[str, Any],
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    second_batch: Mapping[str, Any],
    second_projection: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Replay a selected prior case and append one new, distinct retest case."""

    try:
        prior = verify_offline_api_retest_lineage(prior_lineage)
        checked_prior_case = verify_offline_api_case(
            adapter=adapter,
            case_id=prior_source.case_id,
            invocation=prior_source.invocation,
            evidence=prior_source.evidence,
            result=prior_source.result,
        )
        matching = [
            item
            for item in prior["source_ledger"]["cases"]
            if item["case_id"] == checked_prior_case.case_id
        ]
        if len(matching) != 1:
            raise OfflineApiRetestTransitionError("prior case is absent from source lineage")
        entry = matching[0]
        if (
            entry["result_sha256"] != checked_prior_case.result_sha256
            or entry["invocation_id"] != checked_prior_case.invocation_id
            or entry["evidence_sha256s"] != list(checked_prior_case.evidence_sha256s)
        ):
            raise OfflineApiRetestTransitionError("prior case source lineage differs")
        comparison = compare_offline_api_retest(
            adapter=adapter,
            prior_case_id=prior_source.case_id,
            prior_invocation=prior_source.invocation,
            prior_evidence=prior_source.evidence,
            prior_result=prior_source.result,
            second_case_id=second_source.case_id,
            second_invocation=second_source.invocation,
            second_evidence=second_source.evidence,
            second_result=second_source.result,
        )
        child = append_offline_api_retest_lineage(
            prior=prior,
            adapter=adapter,
            sources=(second_source,),
            batch=second_batch,
            projection=second_projection,
            observed_at=observed_at,
            expires_at=expires_at,
        )
    except OfflineApiRetestTransitionError:
        raise
    except (OfflineApiAssessmentError, OfflineApiRetestLineageError) as exc:
        raise OfflineApiRetestTransitionError("API retest transition sources are invalid") from exc
    body = {
        "schema_version": 1,
        "prior_case_id": prior_source.case_id,
        "second_case_id": second_source.case_id,
        "prior_lineage_sha256": prior["lineage_sha256"],
        "child_lineage": child,
        "comparison": comparison.to_dict(),
        "observation_change": comparison.observation_change,
        "review_status": "not_reviewed",
        "remediation_status": "not_claimed",
        "origin_authentication": "not_verified",
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "transition_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_retest_transition(
    *,
    document: Mapping[str, Any],
    prior_lineage: Mapping[str, Any],
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    second_batch: Mapping[str, Any],
    second_projection: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    expected = build_offline_api_retest_transition(
        prior_lineage=prior_lineage,
        prior_source=prior_source,
        second_source=second_source,
        second_batch=second_batch,
        second_projection=second_projection,
        adapter=adapter,
        observed_at=observed_at,
        expires_at=expires_at,
    )
    try:
        same = isinstance(document, Mapping) and _canonical(dict(document)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiRetestTransitionError("API retest transition does not match sources")
    return expected


__all__ = [
    "OfflineApiRetestTransitionError",
    "build_offline_api_retest_transition",
    "verify_offline_api_retest_transition",
]
