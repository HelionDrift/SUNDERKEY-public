"""Bounded, effect-free workflow for repository-only review artifacts."""

from __future__ import annotations

import json
from dataclasses import fields
from enum import StrEnum
from typing import Any

from .credential_exposure_triage import (
    CredentialExposureSignal,
    ExposureReviewConsent,
    plan_credential_exposure_review,
)
from .decoy_lifecycle_review import (
    DecoyLifecycleEvent,
    DecoyPlacementApproval,
    review_decoy_lifecycle,
)
from .detection_rule_hygiene import (
    RedactedRuleSnapshot,
    RuleSourceObservation,
    review_detection_rule_hygiene,
)
from .email_control_review import (
    EmailCleanupAssertion,
    EmailDeliveryObservation,
    EmailTestApproval,
    review_email_control,
)
from .inert_resilience_readiness import (
    InertReadinessObservation,
    InertReadinessScenario,
    review_inert_readiness,
)
from .metadata_impact_review import DataMetadataObservation, review_data_metadata
from .restricted_asset_inference import (
    RestrictedAssetCase,
    RestrictedAssetObservation,
    infer_restricted_asset,
)
from .synthetic_scenario_planning import (
    SyntheticScenarioConsent,
    SyntheticScenarioRequest,
    plan_synthetic_scenarios,
)
from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

SCHEMA_VERSION = 1
MAX_JOBS = 16
MAX_RECORDS_PER_JOB = 1000
MAX_INPUT_BYTES = 1_000_000
MAX_BUNDLE_BYTES = 4_000_000
TUPLE_FIELDS = frozenset({
    "allowed_kinds", "synthetic_principal_refs", "surface_refs",
    "prerequisites", "required_source_refs", "test_mailbox_refs",
    "allowed_artifact_classes",
})
NO_EFFECTS = {
    "authority": "none",
    "credential_access": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
}


class OfflineReviewWorkflowError(ValueError):
    """Offline review request failed closed without partial publication."""


class OfflineReviewKind(StrEnum):
    CREDENTIAL_EXPOSURE = "credential_exposure"
    SYNTHETIC_SCENARIO = "synthetic_scenario"
    DECOY_LIFECYCLE = "decoy_lifecycle"
    RESTRICTED_ASSET = "restricted_asset"
    INERT_RESILIENCE = "inert_resilience"
    DETECTION_RULE = "detection_rule"
    EMAIL_CONTROL = "email_control"
    METADATA_IMPACT = "metadata_impact"


PAYLOAD_FIELDS = {
    OfflineReviewKind.CREDENTIAL_EXPOSURE: frozenset({"signals", "consents"}),
    OfflineReviewKind.SYNTHETIC_SCENARIO: frozenset({"requests", "consents"}),
    OfflineReviewKind.DECOY_LIFECYCLE: frozenset({"approval", "events"}),
    OfflineReviewKind.RESTRICTED_ASSET: frozenset({"case", "observations"}),
    OfflineReviewKind.INERT_RESILIENCE: frozenset({"scenario", "observations"}),
    OfflineReviewKind.DETECTION_RULE: frozenset({"snapshot", "observations"}),
    OfflineReviewKind.EMAIL_CONTROL: frozenset({
        "approval", "observations", "cleanup_assertions",
    }),
    OfflineReviewKind.METADATA_IMPACT: frozenset({"observations"}),
}
RESULT_DIGEST_FIELD = {
    OfflineReviewKind.CREDENTIAL_EXPOSURE: "plan_sha256",
    OfflineReviewKind.SYNTHETIC_SCENARIO: "plan_sha256",
    OfflineReviewKind.DECOY_LIFECYCLE: "review_sha256",
    OfflineReviewKind.RESTRICTED_ASSET: "inference_sha256",
    OfflineReviewKind.INERT_RESILIENCE: "review_sha256",
    OfflineReviewKind.DETECTION_RULE: "review_sha256",
    OfflineReviewKind.EMAIL_CONTROL: "review_sha256",
    OfflineReviewKind.METADATA_IMPACT: "review_sha256",
}


def _exact_mapping(value: Any, required: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise OfflineReviewWorkflowError(f"{label} fields are invalid")
    return value


def _record(record_type: type[Any], value: Any, label: str) -> Any:
    required = frozenset(item.name for item in fields(record_type))
    raw = _exact_mapping(value, required, label)
    prepared = dict(raw)
    for name in required.intersection(TUPLE_FIELDS):
        if not isinstance(prepared[name], list):
            raise OfflineReviewWorkflowError(f"{label} {name} must be a list")
        prepared[name] = tuple(prepared[name])
    try:
        record = record_type(**prepared)
    except (TypeError, ValueError) as exc:
        raise OfflineReviewWorkflowError(f"{label} is invalid") from exc
    digest_fields = [name for name in required if name.endswith("_sha256")]
    if any(name in raw and raw[name] == "" for name in digest_fields):
        raise OfflineReviewWorkflowError(f"{label} must carry content digests")
    return record


def _records(record_type: type[Any], value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list) or len(value) > MAX_RECORDS_PER_JOB:
        raise OfflineReviewWorkflowError(f"{label} must be a bounded list")
    return tuple(_record(record_type, item, label) for item in value)


def _anchor(record: Any, tenant_id: str, scope_sha256: str) -> None:
    if record.tenant_id != tenant_id or record.scope_sha256 != scope_sha256:
        raise OfflineReviewWorkflowError("review anchor crosses tenant or scope")


def _evaluate(
    kind: OfflineReviewKind,
    payload: dict[str, Any],
    tenant_id: str,
    scope_sha256: str,
    reviewed_at: str,
) -> dict[str, Any]:
    try:
        if kind is OfflineReviewKind.CREDENTIAL_EXPOSURE:
            result = plan_credential_exposure_review(
                tenant_id=tenant_id, scope_sha256=scope_sha256,
                reviewed_at=reviewed_at,
                signals=_records(CredentialExposureSignal, payload["signals"], "signal"),
                consents=_records(ExposureReviewConsent, payload["consents"], "consent"),
            )
        elif kind is OfflineReviewKind.SYNTHETIC_SCENARIO:
            result = plan_synthetic_scenarios(
                tenant_id=tenant_id, scope_sha256=scope_sha256,
                planned_at=reviewed_at,
                requests=_records(SyntheticScenarioRequest, payload["requests"], "request"),
                consents=_records(SyntheticScenarioConsent, payload["consents"], "consent"),
            )
        elif kind is OfflineReviewKind.DECOY_LIFECYCLE:
            approval = _record(DecoyPlacementApproval, payload["approval"], "approval")
            _anchor(approval, tenant_id, scope_sha256)
            result = review_decoy_lifecycle(
                approval=approval,
                events=_records(DecoyLifecycleEvent, payload["events"], "event"),
                reviewed_at=reviewed_at,
            )
        elif kind is OfflineReviewKind.RESTRICTED_ASSET:
            case = _record(RestrictedAssetCase, payload["case"], "case")
            _anchor(case, tenant_id, scope_sha256)
            result = infer_restricted_asset(
                case=case,
                observations=_records(
                    RestrictedAssetObservation, payload["observations"], "observation",
                ),
                reviewed_at=reviewed_at,
            )
        elif kind is OfflineReviewKind.INERT_RESILIENCE:
            scenario = _record(InertReadinessScenario, payload["scenario"], "scenario")
            _anchor(scenario, tenant_id, scope_sha256)
            result = review_inert_readiness(
                scenario=scenario,
                observations=_records(
                    InertReadinessObservation, payload["observations"], "observation",
                ),
                reviewed_at=reviewed_at,
            )
        elif kind is OfflineReviewKind.DETECTION_RULE:
            snapshot = _record(RedactedRuleSnapshot, payload["snapshot"], "snapshot")
            _anchor(snapshot, tenant_id, scope_sha256)
            result = review_detection_rule_hygiene(
                snapshot=snapshot,
                observations=_records(
                    RuleSourceObservation, payload["observations"], "observation",
                ),
                reviewed_at=reviewed_at,
            )
        elif kind is OfflineReviewKind.EMAIL_CONTROL:
            approval = _record(EmailTestApproval, payload["approval"], "approval")
            _anchor(approval, tenant_id, scope_sha256)
            result = review_email_control(
                approval=approval,
                observations=_records(
                    EmailDeliveryObservation, payload["observations"], "observation",
                ),
                cleanup_assertions=_records(
                    EmailCleanupAssertion, payload["cleanup_assertions"], "cleanup",
                ),
                reviewed_at=reviewed_at,
            )
        else:
            result = review_data_metadata(
                observations=_records(
                    DataMetadataObservation, payload["observations"], "observation",
                ),
                tenant_id=tenant_id, scope_sha256=scope_sha256,
                reviewed_at=reviewed_at,
            )
    except OfflineReviewWorkflowError:
        raise
    except (TypeError, ValueError) as exc:
        raise OfflineReviewWorkflowError(f"{kind.value} review failed") from exc
    return result.to_dict()


def build_offline_review_bundle(request: Any) -> dict[str, Any]:
    """Evaluate exact same-tenant offline reviews without partial output."""
    raw = _exact_mapping(
        request,
        frozenset({"schema_version", "tenant_id", "scope_sha256", "reviewed_at", "jobs"}),
        "request",
    )
    if type(raw["schema_version"]) is not int or raw["schema_version"] != SCHEMA_VERSION:
        raise OfflineReviewWorkflowError("schema_version is invalid")
    try:
        _identifier(raw["tenant_id"], "tenant_id")
        _digest(raw["scope_sha256"], "scope_sha256")
        _timestamp(raw["reviewed_at"], "reviewed_at")
    except TrafficApiInventoryError as exc:
        raise OfflineReviewWorkflowError("review context is invalid") from exc
    jobs = raw["jobs"]
    if not isinstance(jobs, list) or not jobs or len(jobs) > MAX_JOBS:
        raise OfflineReviewWorkflowError("jobs must be a nonempty bounded list")
    by_id: dict[str, dict[str, Any]] = {}
    for job in jobs:
        item = _exact_mapping(job, frozenset({"job_id", "kind", "payload"}), "job")
        try:
            _identifier(item["job_id"], "job_id")
            kind = OfflineReviewKind(item["kind"])
        except (TrafficApiInventoryError, TypeError, ValueError) as exc:
            raise OfflineReviewWorkflowError("job identity or kind is invalid") from exc
        if item["job_id"] in by_id:
            raise OfflineReviewWorkflowError("job_id is repeated")
        payload = _exact_mapping(item["payload"], PAYLOAD_FIELDS[kind], "job payload")
        result = _evaluate(
            kind, payload, raw["tenant_id"], raw["scope_sha256"], raw["reviewed_at"],
        )
        by_id[item["job_id"]] = {
            "job_id": item["job_id"], "kind": kind.value,
            "result_sha256": result[RESULT_DIGEST_FIELD[kind]],
            "result": result,
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": raw["tenant_id"],
        "scope_sha256": raw["scope_sha256"],
        "reviewed_at": raw["reviewed_at"],
        "jobs": [by_id[key] for key in sorted(by_id)],
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "bundle_sha256": _canonical_sha("sunderkey.offline-review-bundle.v1", body),
    }


def verify_offline_review_bundle(request: Any, bundle: Any) -> dict[str, Any]:
    """Reproduce a bundle from its inputs; make no provenance or authority claim."""
    expected = build_offline_review_bundle(request)
    try:
        expected_json = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        supplied_json = json.dumps(
            bundle, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise OfflineReviewWorkflowError("bundle is not valid JSON data") from exc
    if supplied_json != expected_json:
        raise OfflineReviewWorkflowError("bundle does not reproduce from the request")
    return {
        "status": "valid",
        "bundle_sha256": expected["bundle_sha256"],
        "job_count": len(expected["jobs"]),
        "verification_scope": "offline_reproduction_only",
        "origin_authentication": "not_verified",
        "authority_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
    }
