"""Join offline remediation sources without equating a ticket or old review with a fix."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .remediation_validation_contracts import (
    ClosureDecision,
    ContextBinding,
    GateDisposition,
    RemediationPlan,
    RemediationValidationError,
    RetestObservation,
    RetestPlan,
    RiskException,
    _timestamp,
    canonical_json,
    canonical_sha256,
    verify_closure_decision,
    verify_remediation_plan,
    verify_retest_observation,
    verify_retest_plan,
    verify_risk_exception,
)
from .remediation_workflow_visibility import (
    NO_EFFECTS as WORKFLOW_NO_EFFECTS,
)
from .remediation_workflow_visibility import (
    RemediationDeliveryObservation,
    RemediationServiceTarget,
    review_remediation_workflow,
)

NO_EFFECTS = MappingProxyType({**WORKFLOW_NO_EFFECTS, "finding_publication": "none"})
DOMAIN = "sunderkey.remediation-case-review.v1"


class RemediationCaseReviewError(RemediationValidationError):
    """A case has incomplete or substituted source lineage."""


def _checked(record: Any, record_type: type[Any], label: str) -> Any:
    if not isinstance(record, record_type):
        raise RemediationCaseReviewError(f"{label} must be a typed record")
    return record_type.from_dict(record.to_dict())


def build_remediation_case_review(
    context: ContextBinding,
    plan: RemediationPlan,
    *,
    targets: tuple[RemediationServiceTarget, ...],
    delivery_observations: tuple[RemediationDeliveryObservation, ...],
    as_of: str,
    retest: RetestPlan | None = None,
    retest_observation: RetestObservation | None = None,
    closure: ClosureDecision | None = None,
    exception: RiskException | None = None,
    max_delivery_observation_age_seconds: int = 86_400,
) -> dict[str, Any]:
    """Rehearse a complete source join, preserving missing stages and historical review."""

    context = _checked(context, ContextBinding, "context")
    plan = _checked(plan, RemediationPlan, "plan")
    verify_remediation_plan(context, plan)
    workflow = review_remediation_workflow(
        plan,
        targets=targets,
        observations=delivery_observations,
        as_of=as_of,
        max_observation_age_seconds=max_delivery_observation_age_seconds,
    )
    now = _timestamp(as_of, "as_of")
    windows = [context.expires_at, plan.expires_at]
    reasons = {"independent_live_evidence_not_established"}
    stage = "planning_only"
    historical_disposition = "not_supplied"
    gate_summary = None
    exception_summary = None
    if exception is not None:
        exception = _checked(exception, RiskException, "exception")
        try:
            verify_risk_exception(plan, exception)
        except RemediationValidationError as exc:
            raise RemediationCaseReviewError(str(exc)) from exc
        controls = {control.control_ref: control for control in plan.compensating_controls}
        if _timestamp(exception.approved_at, "exception approved_at") > now:
            raise RemediationCaseReviewError("exception approval is after the case review")
        selected_controls = tuple(controls[ref] for ref in exception.control_refs)
        control_windows_open = all(
            now < _timestamp(control.expires_at, "control expires_at")
            for control in selected_controls
        )
        covered = {item_ref for control in selected_controls for item_ref in control.item_refs}
        coverage_complete = set(exception.item_refs) <= covered
        exception_window_open = now < _timestamp(exception.expires_at, "exception expires_at")
        if not exception_window_open:
            reasons.add("declared_exception_window_expired")
        if not control_windows_open:
            reasons.add("declared_compensating_control_window_expired")
        if not coverage_complete:
            reasons.add("asserted_exception_control_coverage_incomplete")
        exception_summary = {
            "exception_sha256": exception.exception_sha256,
            "approved_at": exception.approved_at,
            "expires_at": exception.expires_at,
            "item_refs": list(exception.item_refs),
            "control_refs": list(exception.control_refs),
            "declared_exception_window_open": exception_window_open,
            "declared_control_windows_open": control_windows_open,
            "asserted_control_coverage_complete": coverage_complete,
            "used_by_historical_closure": False,
            "effective_risk_acceptance_verified": False,
        }
    if retest is None:
        if retest_observation is not None or closure is not None:
            raise RemediationCaseReviewError("observation or closure requires its retest source")
        reasons.add("retest_plan_not_supplied")
    else:
        retest = _checked(retest, RetestPlan, "retest")
        verify_retest_plan(plan, retest)
        if _timestamp(retest.created_at, "retest created_at") > now:
            raise RemediationCaseReviewError("retest creation is after the case review")
        windows.append(retest.expires_at)
        stage = "awaiting_retest_observation"
        if retest_observation is None:
            if closure is not None:
                raise RemediationCaseReviewError("closure requires its exact observation source")
            reasons.add("retest_observation_not_supplied")
        else:
            retest_observation = _checked(retest_observation, RetestObservation, "observation")
            verify_retest_observation(plan, retest, retest_observation)
            if _timestamp(retest_observation.observed_at, "observation observed_at") > now:
                raise RemediationCaseReviewError("retest observation is after the case review")
            gate_summary = {
                disposition.value: sum(
                    gate.disposition is disposition for gate in retest_observation.gate_observations
                )
                for disposition in GateDisposition
            }
            observed_gates = {gate.gate_ref: gate for gate in retest_observation.gate_observations}
            evidence_complete = all(
                set(gate.required_evidence_digests)
                <= set(observed_gates[gate.gate_ref].evidence_digests)
                for gate in retest.gates
            )
            restoration_complete = set(retest.rollback_evidence_digests) <= set(
                retest_observation.rollback_evidence_digests
            ) and set(retest.cleanup_evidence_digests) <= set(
                retest_observation.cleanup_evidence_digests
            )
            gate_summary.update(
                required_evidence_complete=evidence_complete,
                restoration_evidence_complete=restoration_complete,
            )
            if not evidence_complete:
                reasons.add("required_retest_evidence_missing")
            if not restoration_complete:
                reasons.add("rollback_cleanup_evidence_missing")
            if gate_summary[GateDisposition.PASS.value] != len(retest.gates):
                reasons.add("regression_gate_not_passed")
            stage = "awaiting_closure_review"
            if closure is None:
                reasons.add("closure_recommendation_not_supplied")
            else:
                closure = _checked(closure, ClosureDecision, "closure")
                if _timestamp(closure.reviewed_at, "closure reviewed_at") > now:
                    raise RemediationCaseReviewError(
                        "closure recommendation is after the case review"
                    )
                verify_closure_decision(
                    plan, retest, retest_observation, closure, exception=exception
                )
                historical_disposition = closure.disposition.value
                stage = "historical_recommendation_replayed"
                if exception_summary is not None:
                    exception_summary["used_by_historical_closure"] = (
                        closure.exception_sha256 == exception.exception_sha256
                    )
    windows_open = all(now < _timestamp(value, "source expires_at") for value in windows)
    if not windows_open:
        reasons.add("declared_source_window_expired")
    body = {
        "schema_version": 1,
        "as_of": as_of,
        "context_id": context.context_id,
        "context_sha256": context.context_sha256,
        "tenant_ref": context.tenant_ref,
        "assessment_ref": context.assessment_ref,
        "scope_sha256": context.scope_sha256,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "retest_plan_sha256": None if retest is None else retest.retest_plan_sha256,
        "retest_observation_sha256": (
            None if retest_observation is None else retest_observation.observation_sha256
        ),
        "closure_decision_sha256": None if closure is None else closure.decision_sha256,
        "exception_sha256": None if exception is None else exception.exception_sha256,
        "case_status": "review_required",
        "review_stage": stage,
        "historical_closure_disposition": historical_disposition,
        "declared_source_windows_open": windows_open,
        "live_source_freshness": "not_established",
        "retest_gate_summary": gate_summary,
        "exception_summary": exception_summary,
        "proposed_risk_points": {
            "inherent": sum(item.inherent_risk_points for item in plan.items),
            "residual": sum(item.residual_risk_points for item in plan.items),
            "reduction": sum(item.risk_reduction_points for item in plan.items),
        },
        "workflow": workflow,
        "reason_codes": sorted(reasons),
        "claims": {
            "identity_authenticated": False,
            "source_provenance_authenticated": False,
            "retest_execution_verified": False,
            "risk_acceptance_verified": False,
            "remediation_verified": False,
        },
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "case_review_sha256": canonical_sha256({"domain": DOMAIN, "content": body}),
    }


def verify_remediation_case_review(
    review: Mapping[str, Any],
    context: ContextBinding,
    plan: RemediationPlan,
    *,
    targets: tuple[RemediationServiceTarget, ...],
    delivery_observations: tuple[RemediationDeliveryObservation, ...],
    as_of: str,
    retest: RetestPlan | None = None,
    retest_observation: RetestObservation | None = None,
    closure: ClosureDecision | None = None,
    exception: RiskException | None = None,
    max_delivery_observation_age_seconds: int = 86_400,
) -> None:
    """Reproduce the entire advisory case from its complete explicit source set."""

    if not isinstance(review, Mapping):
        raise RemediationCaseReviewError("case review must be a mapping")
    expected = build_remediation_case_review(
        context,
        plan,
        targets=targets,
        delivery_observations=delivery_observations,
        as_of=as_of,
        retest=retest,
        retest_observation=retest_observation,
        closure=closure,
        exception=exception,
        max_delivery_observation_age_seconds=max_delivery_observation_age_seconds,
    )
    if canonical_json(dict(review)) != canonical_json(expected):
        raise RemediationCaseReviewError("case review does not replay from its sources")
