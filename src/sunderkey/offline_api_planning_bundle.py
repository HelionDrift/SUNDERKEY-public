"""Bind synthetic API evidence to an effect-free Army planning rehearsal."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .attack_world_model import AttackWorldModelError, AttackWorldSnapshot
from .coverage_capacity_rehearsal import (
    CapacityRehearsalError,
    bind_rehearsal_to_army_registry,
    plan_capacity_rehearsal,
    verify_capacity_rehearsal,
    verify_registry_capacity_binding,
)
from .coverage_scheduler import (
    CoverageSchedule,
    CoverageSchedulerError,
    SchedulingLimits,
    compute_coverage_schedule,
)
from .offline_api_assessment import (
    API_TECHNIQUE_ID,
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    verify_offline_api_batch,
)
from .offline_api_world_projection import (
    NO_EFFECTS as PROJECTION_NO_EFFECTS,
)
from .offline_api_world_projection import (
    PROJECTION_DOMAIN,
    OfflineApiWorldProjectionError,
    build_offline_api_world_projection,
)
from .reference_adapters import OfflineReferenceAdapter
from .registry import ExpertRegistry
from .signed_scope_compiler import VerifiedAssessmentScope
from .target_context import TargetContextBundle, TargetContextError

BUNDLE_DOMAIN = "sunderkey.offline-api-planning-bundle.v1"
NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "routing": "none",
    "target_execution": "none",
}
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class OfflineApiPlanningError(ValueError):
    """Raised when the synthetic evidence-to-planning chain is inconsistent."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_planning_bundle(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    scope: VerifiedAssessmentScope,
    observed_at: str,
    expires_at: str,
    capability_availability: Mapping[str, Any],
    validator_availability: Mapping[str, Any],
    limits: SchedulingLimits,
    specialist_capacity: Mapping[str, int],
    commander_capacity: Mapping[str, int],
    validator_capacity: Mapping[str, int],
    registry: ExpertRegistry,
    target_context: TargetContextBundle | None = None,
) -> dict[str, Any]:
    """Replay source cases and bind a planning-only schedule to the Army roster."""

    if not isinstance(scope, VerifiedAssessmentScope):
        raise OfflineApiPlanningError("a verified assessment scope is required")
    try:
        checked = verify_offline_api_batch(adapter=adapter, sources=sources, batch=batch)
        if checked.scope_id != scope.scope_id:
            raise OfflineApiPlanningError("synthetic batch and verified scope differ")
        if any(
            "source_scope_sha256" in record.attributes
            and record.attributes["source_scope_sha256"] != scope.content_sha256
            for source in sources
            for record in source.evidence
        ):
            raise OfflineApiPlanningError("receipt source and verified scope digest differ")
        if API_TECHNIQUE_ID not in scope.to_dict()["allowed_technique_ids"]:
            raise OfflineApiPlanningError("API technique is outside the verified scope")
        context_hash = None
        if target_context is not None:
            if not isinstance(target_context, TargetContextBundle):
                raise OfflineApiPlanningError("target context must be a typed bundle")
            authority_refs = {source.invocation.authority_ref for source in sources}
            if len(authority_refs) != 1:
                raise OfflineApiPlanningError(
                    "target context requires one source authority reference"
                )
            context = TargetContextBundle.from_dict(
                target_context.to_dict(),
                mission_id=checked.mission_id,
                authority_ref=next(iter(authority_refs)),
            )
            if context.status != "accepted":
                raise OfflineApiPlanningError("target context is not accepted")
            context_hash = context.bundle_sha256
        projection = build_offline_api_world_projection(
            adapter=adapter,
            sources=sources,
            batch=batch,
            observed_at=observed_at,
            expires_at=expires_at,
        )
        snapshot = AttackWorldSnapshot.from_dict(projection["snapshot"])
        schedule = compute_coverage_schedule(
            scope,
            snapshot,
            capability_availability,
            validator_availability,
            {},
            limits,
        )
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity=specialist_capacity,
            commander_capacity=commander_capacity,
            validator_capacity=validator_capacity,
        )
        roster_binding = bind_rehearsal_to_army_registry(schedule, rehearsal, registry)
    except OfflineApiPlanningError:
        raise
    except (
        AttackWorldModelError,
        CapacityRehearsalError,
        CoverageSchedulerError,
        OfflineApiAssessmentError,
        OfflineApiWorldProjectionError,
        TargetContextError,
        TypeError,
        ValueError,
        KeyError,
        AttributeError,
    ) as exc:
        raise OfflineApiPlanningError("offline API planning inputs are invalid") from exc
    body = {
        "schema_version": 1,
        "batch_sha256": checked.batch_sha256,
        "scope_sha256": scope.content_sha256,
        "target_context_sha256": context_hash,
        "projection": projection,
        "schedule": schedule.to_dict(),
        "capacity_rehearsal": rehearsal.to_dict(),
        "army_roster_binding": roster_binding.to_dict(),
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "bundle_sha256": _digest({"domain": BUNDLE_DOMAIN, "bundle": body}),
    }


def verify_offline_api_planning_bundle(
    *,
    bundle: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    scope: VerifiedAssessmentScope,
    observed_at: str,
    expires_at: str,
    capability_availability: Mapping[str, Any],
    validator_availability: Mapping[str, Any],
    limits: SchedulingLimits,
    specialist_capacity: Mapping[str, int],
    commander_capacity: Mapping[str, int],
    validator_capacity: Mapping[str, int],
    registry: ExpertRegistry,
    target_context: TargetContextBundle | None = None,
) -> dict[str, Any]:
    """Reproduce the complete local chain before accepting a serialized bundle."""

    expected = build_offline_api_planning_bundle(
        adapter=adapter,
        sources=sources,
        batch=batch,
        scope=scope,
        observed_at=observed_at,
        expires_at=expires_at,
        capability_availability=capability_availability,
        validator_availability=validator_availability,
        limits=limits,
        specialist_capacity=specialist_capacity,
        commander_capacity=commander_capacity,
        validator_capacity=validator_capacity,
        registry=registry,
        target_context=target_context,
    )
    try:
        same = isinstance(bundle, Mapping) and _canonical(dict(bundle)) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiPlanningError("offline API planning bundle does not match sources")
    return expected


def inspect_offline_api_planning_integrity(
    *, bundle: Mapping[str, Any], registry: ExpertRegistry
) -> dict[str, Any]:
    """Check archived container identities without source replay or live-use approval."""

    expected_fields = {
        "schema_version",
        "batch_sha256",
        "scope_sha256",
        "target_context_sha256",
        "projection",
        "schedule",
        "capacity_rehearsal",
        "army_roster_binding",
        "effects",
        "bundle_sha256",
    }
    if not isinstance(bundle, Mapping) or set(bundle) != expected_fields:
        raise OfflineApiPlanningError("planning bundle fields are invalid")
    try:
        body = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
        if (
            type(bundle["schema_version"]) is not int
            or bundle["schema_version"] != 1
            or bundle["effects"] != NO_EFFECTS
        ):
            raise OfflineApiPlanningError("planning bundle policy fields are invalid")
        if bundle["bundle_sha256"] != _digest({"domain": BUNDLE_DOMAIN, "bundle": body}):
            raise OfflineApiPlanningError("planning bundle content identity is invalid")
        for name in ("batch_sha256", "scope_sha256"):
            if not isinstance(bundle[name], str) or SHA256_RE.fullmatch(bundle[name]) is None:
                raise OfflineApiPlanningError(f"planning bundle {name} is invalid")
        context_hash = bundle["target_context_sha256"]
        if context_hash is not None and (
            not isinstance(context_hash, str) or SHA256_RE.fullmatch(context_hash) is None
        ):
            raise OfflineApiPlanningError("planning bundle context digest is invalid")
        projection = bundle["projection"]
        projection_fields = {
            "schema_version",
            "batch_sha256",
            "snapshot",
            "skipped_case_ids",
            "origin_authentication",
            "path_verification",
            "effects",
            "projection_sha256",
        }
        if not isinstance(projection, Mapping) or set(projection) != projection_fields:
            raise OfflineApiPlanningError("planning projection fields are invalid")
        projection_body = {
            key: value for key, value in projection.items() if key != "projection_sha256"
        }
        if (
            type(projection["schema_version"]) is not int
            or projection["schema_version"] != 1
            or projection["batch_sha256"] != bundle["batch_sha256"]
            or projection["origin_authentication"] != "not_verified"
            or projection["path_verification"] != "not_established"
            or projection["effects"] != PROJECTION_NO_EFFECTS
            or projection["projection_sha256"]
            != _digest({"domain": PROJECTION_DOMAIN, "projection": projection_body})
        ):
            raise OfflineApiPlanningError("planning projection identity or policy is invalid")
        snapshot = AttackWorldSnapshot.from_dict(projection["snapshot"])
        schedule = CoverageSchedule.from_dict(bundle["schedule"])
        if (
            schedule.scope_sha256 != bundle["scope_sha256"]
            or schedule.world_snapshot_sha256 != snapshot.snapshot_sha256
        ):
            raise OfflineApiPlanningError("planning schedule source binding is invalid")
        rehearsal = verify_capacity_rehearsal(schedule, bundle["capacity_rehearsal"])
        binding = verify_registry_capacity_binding(
            schedule, rehearsal, registry, bundle["army_roster_binding"]
        )
    except (
        AttackWorldModelError,
        CapacityRehearsalError,
        CoverageSchedulerError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        if isinstance(exc, OfflineApiPlanningError):
            raise
        raise OfflineApiPlanningError("planning bundle historical integrity is invalid") from exc
    return {
        "status": "valid_historical_integrity",
        "bundle_sha256": bundle["bundle_sha256"],
        "schedule_sha256": schedule.schedule_sha256,
        "rehearsal_sha256": rehearsal.rehearsal_sha256,
        "registry_binding_sha256": binding.binding_sha256,
        "source_replay_performed": False,
        "positive_use_approved": False,
        "qualification_effect": "none",
    }


__all__ = [
    "OfflineApiPlanningError",
    "build_offline_api_planning_bundle",
    "inspect_offline_api_planning_integrity",
    "verify_offline_api_planning_bundle",
]
