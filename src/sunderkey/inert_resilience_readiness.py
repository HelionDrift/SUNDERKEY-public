"""Effect-free review of asserted inert ransomware-readiness evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from typing import Any

from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_AGE_SECONDS = 7 * 24 * 60 * 60
ASSET_RE = re.compile(r"synthetic-asset:sha256:[0-9a-f]{64}\Z")
CANARY_RE = re.compile(r"inert-canary:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "data_mutation": "none",
    "encryption": "none",
    "exfiltration": "none",
    "network": "none",
    "restoration": "none",
    "target_interaction": "none",
}


class InertReadinessError(ValueError):
    """Inert resilience evidence failed closed."""


class ReadinessFacet(StrEnum):
    PROPAGATION_BOUNDARY = "propagation_boundary"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    ENCRYPTION_REACH_CANARY = "encryption_reach_canary"
    EGRESS_POLICY = "egress_policy"
    ISOLATED_RESTORATION = "isolated_restoration"


class FacetOutcome(StrEnum):
    PROTECTED_ASSERTED = "protected_asserted"
    GAP_ASSERTED = "gap_asserted"
    NOT_OBSERVED = "not_observed"


class ReadinessStatus(StrEnum):
    GAP_REQUIRES_REVIEW = "gap_requires_review"
    STALE_EVIDENCE = "stale_evidence"
    INCONCLUSIVE = "inconclusive"
    EVIDENCE_FOR_REVIEW = "readiness_evidence_for_review"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise InertReadinessError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise InertReadinessError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise InertReadinessError(f"{label} is invalid") from exc


def _opaque(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise InertReadinessError(f"{label} must be an opaque synthetic reference")


@dataclass(frozen=True, slots=True)
class InertReadinessScenario:
    scenario_id: str
    tenant_id: str
    scope_sha256: str
    synthetic_asset_ref: str
    inert_canary_ref: str
    source_sha256: str
    recorded_at: str
    expires_at: str
    scenario_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.scenario_id, "scenario_id")
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.synthetic_asset_ref, "synthetic_asset_ref", ASSET_RE)
        _opaque(self.inert_canary_ref, "inert_canary_ref", CANARY_RE)
        _sha(self.source_sha256, "source_sha256")
        recorded = _time(self.recorded_at, "recorded_at")
        expires = _time(self.expires_at, "expires_at")
        if not recorded < expires <= recorded + timedelta(seconds=MAX_AGE_SECONDS):
            raise InertReadinessError("scenario expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.inert-readiness-scenario.v1", self._payload())
        if self.scenario_sha256 and self.scenario_sha256 != expected:
            raise InertReadinessError("scenario_sha256 does not match content")
        object.__setattr__(self, "scenario_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id, "tenant_id": self.tenant_id,
            "scope_sha256": self.scope_sha256,
            "synthetic_asset_ref": self.synthetic_asset_ref,
            "inert_canary_ref": self.inert_canary_ref,
            "source_sha256": self.source_sha256,
            "recorded_at": self.recorded_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "scenario_sha256": self.scenario_sha256}


@dataclass(frozen=True, slots=True)
class InertReadinessObservation:
    tenant_id: str
    scope_sha256: str
    scenario_sha256: str
    facet: ReadinessFacet | str
    outcome: FacetOutcome | str
    source_sha256: str
    observed_at: str
    expires_at: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.scenario_sha256, "scenario_sha256")
        try:
            object.__setattr__(self, "facet", ReadinessFacet(self.facet))
            object.__setattr__(self, "outcome", FacetOutcome(self.outcome))
        except (TypeError, ValueError) as exc:
            raise InertReadinessError("observation facet or outcome is invalid") from exc
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_AGE_SECONDS):
            raise InertReadinessError("observation expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.inert-readiness-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise InertReadinessError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "scenario_sha256": self.scenario_sha256,
            "facet": self.facet.value, "outcome": self.outcome.value,
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class InertReadinessReview:
    scenario_sha256: str
    reviewed_at: str
    observation_sha256: tuple[str, ...]
    status: ReadinessStatus | str
    review_reasons: tuple[str, ...]
    review_sha256: str = ""

    def __post_init__(self) -> None:
        _sha(self.scenario_sha256, "scenario_sha256")
        _time(self.reviewed_at, "reviewed_at")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > len(ReadinessFacet)
            or self.observation_sha256 != tuple(sorted(set(self.observation_sha256)))
        ):
            raise InertReadinessError("observation digests are not canonical")
        for value in self.observation_sha256:
            _sha(value, "observation digest")
        try:
            object.__setattr__(self, "status", ReadinessStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise InertReadinessError("review status is invalid") from exc
        allowed = {
            "all_facets_protected_asserted", "facet_gap_asserted",
            "facet_missing_or_not_observed", "facet_stale", "scenario_expired",
        }
        if (
            not isinstance(self.review_reasons, tuple)
            or not self.review_reasons
            or self.review_reasons != tuple(sorted(set(self.review_reasons)))
            or any(reason not in allowed for reason in self.review_reasons)
        ):
            raise InertReadinessError("review reasons are not canonical")
        reasons = set(self.review_reasons)
        if (
            (self.status is ReadinessStatus.EVIDENCE_FOR_REVIEW)
            != (reasons == {"all_facets_protected_asserted"})
            or self.status is ReadinessStatus.GAP_REQUIRES_REVIEW
            and "facet_gap_asserted" not in reasons
            or self.status is ReadinessStatus.STALE_EVIDENCE
            and not reasons.intersection({"scenario_expired", "facet_stale"})
            or self.status is ReadinessStatus.INCONCLUSIVE
            and "facet_missing_or_not_observed" not in reasons
        ):
            raise InertReadinessError("review status conflicts with reasons")
        expected = _canonical_sha("sunderkey.inert-readiness-review.v1", self._payload())
        if self.review_sha256 and self.review_sha256 != expected:
            raise InertReadinessError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "scenario_sha256": self.scenario_sha256,
            "reviewed_at": self.reviewed_at,
            "observation_sha256": list(self.observation_sha256),
            "status": self.status.value,
            "review_reasons": list(self.review_reasons),
            "successful_containment_proven": False,
            "successful_restoration_proven": False,
            "independent_review_required": True,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}


def review_inert_readiness(
    *, scenario: InertReadinessScenario,
    observations: tuple[InertReadinessObservation, ...],
    reviewed_at: str,
) -> InertReadinessReview:
    """Review supplied inert evidence without simulating any target effect."""
    if not isinstance(scenario, InertReadinessScenario):
        raise InertReadinessError("scenario must be typed")
    replace(scenario)
    now = _time(reviewed_at, "reviewed_at")
    if _time(scenario.recorded_at, "recorded_at") > now:
        raise InertReadinessError("scenario is future-dated")
    if (
        not isinstance(observations, tuple)
        or len(observations) > len(ReadinessFacet)
        or any(not isinstance(item, InertReadinessObservation) for item in observations)
    ):
        raise InertReadinessError("observations must be a bounded typed tuple")
    by_facet: dict[ReadinessFacet, InertReadinessObservation] = {}
    for item in observations:
        replace(item)
        if (
            item.tenant_id != scenario.tenant_id
            or item.scope_sha256 != scenario.scope_sha256
            or item.scenario_sha256 != scenario.scenario_sha256
        ):
            raise InertReadinessError("observation crosses scenario binding")
        if _time(item.observed_at, "observed_at") > now:
            raise InertReadinessError("observation is future-dated")
        prior = by_facet.setdefault(item.facet, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise InertReadinessError("facet has conflicting evidence")
    flags: set[str] = set()
    if _time(scenario.expires_at, "expires_at") <= now:
        flags.add("scenario_expired")
    for facet in ReadinessFacet:
        item = by_facet.get(facet)
        if item is None:
            flags.add("facet_missing_or_not_observed")
        elif _time(item.expires_at, "expires_at") <= now:
            flags.add("facet_stale")
        elif item.outcome is FacetOutcome.GAP_ASSERTED:
            flags.add("facet_gap_asserted")
        elif item.outcome is FacetOutcome.NOT_OBSERVED:
            flags.add("facet_missing_or_not_observed")
    if "facet_gap_asserted" in flags:
        status = ReadinessStatus.GAP_REQUIRES_REVIEW
    elif "scenario_expired" in flags or "facet_stale" in flags:
        status = ReadinessStatus.STALE_EVIDENCE
    elif flags:
        status = ReadinessStatus.INCONCLUSIVE
    else:
        status = ReadinessStatus.EVIDENCE_FOR_REVIEW
        flags.add("all_facets_protected_asserted")
    return InertReadinessReview(
        scenario_sha256=scenario.scenario_sha256, reviewed_at=reviewed_at,
        observation_sha256=tuple(sorted({
            item.observation_sha256 for item in by_facet.values()
        })),
        status=status, review_reasons=tuple(sorted(flags)),
    )
