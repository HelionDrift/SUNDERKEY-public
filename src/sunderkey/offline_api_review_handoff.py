"""Prepare a non-authoritative human-review proposal from verified API cases."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .expert_review import ReviewerRole
from .human_escalation_routing import (
    HumanEscalationError,
    HumanReviewCase,
    ReviewerRosterEntry,
    plan_human_review,
)
from .offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    verify_offline_api_batch,
)
from .reference_adapters import OfflineReferenceAdapter

HANDOFF_DOMAIN = "sunderkey.offline-api-review-handoff.v1"
NO_EFFECTS = {
    "assignment": "none",
    "authority": "none",
    "evidence_access": "none",
    "finding_publication": "none",
    "notification": "none",
    "review_decision": "none",
}


class OfflineApiReviewHandoffError(ValueError):
    """Raised when the API review proposal cannot be reproduced safely."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_review_handoff(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    tenant_id: str,
    scope_binding_sha256: str,
    originating_principal_id: str,
    originating_team_id: str,
    opened_at: str,
    response_due_at: str,
    planned_at: str,
    roster: tuple[ReviewerRosterEntry, ...] = (),
) -> dict[str, Any]:
    """Reproduce the batch, then propose independent reviewers for nonnegative cases."""

    try:
        checked = verify_offline_api_batch(adapter=adapter, sources=sources, batch=batch)
        if not checked.review_candidate_case_ids:
            raise OfflineApiReviewHandoffError("batch has no review candidates")
        candidates = set(checked.review_candidate_case_ids)
        cases = tuple(
            HumanReviewCase(
                case_id=case.case_id,
                tenant_id=tenant_id,
                subject_kind="synthetic_api_assessment",
                evidence_sha256=case.result_sha256,
                scope_binding_sha256=scope_binding_sha256,
                originating_principal_id=originating_principal_id,
                originating_team_id=originating_team_id,
                required_expertise=("api_authorization",),
                required_roles=(
                    ReviewerRole.TECHNICAL_EVALUATOR,
                    ReviewerRole.INDEPENDENT_CONTROL,
                    ReviewerRole.INDEPENDENT_ASSURANCE,
                ),
                priority="medium",
                opened_at=opened_at,
                response_due_at=response_due_at,
            )
            for case in checked.cases
            if case.case_id in candidates
        )
        plan = plan_human_review(
            tenant_id=tenant_id, planned_at=planned_at, cases=cases, roster=roster
        )
    except (OfflineApiAssessmentError, HumanEscalationError) as exc:
        raise OfflineApiReviewHandoffError("API review sources or roster are invalid") from exc
    body = {
        "schema_version": 1,
        "batch_sha256": checked.batch_sha256,
        "routing_plan": plan.to_dict(),
        "review_case_count": len(cases),
        "origin_authentication": "not_verified",
        "scope_authentication": "not_verified",
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "handoff_sha256": _digest({"domain": HANDOFF_DOMAIN, "handoff": body})}


def verify_offline_api_review_handoff(
    *,
    handoff: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    tenant_id: str,
    scope_binding_sha256: str,
    originating_principal_id: str,
    originating_team_id: str,
    opened_at: str,
    response_due_at: str,
    planned_at: str,
    roster: tuple[ReviewerRosterEntry, ...] = (),
) -> dict[str, Any]:
    """Reproduce all source cases, the batch, and the exact routing proposal."""

    expected = build_offline_api_review_handoff(
        adapter=adapter,
        sources=sources,
        batch=batch,
        tenant_id=tenant_id,
        scope_binding_sha256=scope_binding_sha256,
        originating_principal_id=originating_principal_id,
        originating_team_id=originating_team_id,
        opened_at=opened_at,
        response_due_at=response_due_at,
        planned_at=planned_at,
        roster=roster,
    )
    try:
        same = isinstance(handoff, Mapping) and _canonical(dict(handoff)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiReviewHandoffError("API review handoff does not match sources")
    return expected


__all__ = [
    "OfflineApiReviewHandoffError",
    "build_offline_api_review_handoff",
    "verify_offline_api_review_handoff",
]
