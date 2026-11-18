"""Conservative, non-exploit inference for caller-restricted assets."""

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

MAX_OBSERVATIONS = 16
MAX_CASE_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_OBSERVATION_AGE_SECONDS = 7 * 24 * 60 * 60
ASSET_RE = re.compile(r"asset:sha256:[0-9a-f]{64}\Z")
TECHNIQUE_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
NO_EFFECTS = {
    "authority": "none",
    "execution": "none",
    "exploit_proof": "none",
    "network": "none",
    "target_interaction": "none",
}


class RestrictedAssetInferenceError(ValueError):
    """Restricted-asset inference input failed closed."""


class RestrictionReason(StrEnum):
    UNSAFE_TO_EXPLOIT = "unsafe_to_exploit"
    NO_ACTION_AUTHORITY = "no_action_authority"
    OPERATIONAL_CONSTRAINT = "operational_constraint"


class EvidenceFacet(StrEnum):
    ASSET_REACHABILITY = "asset_reachability"
    IDENTITY_PRECONDITION = "identity_precondition"
    CONFIGURATION_PRECONDITION = "configuration_precondition"
    DEPENDENCY_PRECONDITION = "dependency_precondition"
    CONTROL_OBSERVATION = "control_observation"


class EvidenceState(StrEnum):
    SUPPORTED_ASSERTED = "supported_asserted"
    CONTRADICTED_ASSERTED = "contradicted_asserted"
    UNKNOWN = "unknown"


class InferenceStatus(StrEnum):
    BOUNDED_INFERENCE = "bounded_inference_for_review"
    COUNTEREVIDENCE = "counterevidence_present"
    STALE = "stale_evidence"
    INSUFFICIENT = "insufficient_evidence"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise RestrictedAssetInferenceError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise RestrictedAssetInferenceError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise RestrictedAssetInferenceError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class RestrictedAssetCase:
    tenant_id: str
    scope_sha256: str
    asset_ref: str
    technique_id: str
    restriction_reason: RestrictionReason | str
    prerequisites: tuple[EvidenceFacet | str, ...]
    mapping_source_sha256: str
    restriction_source_sha256: str
    recorded_at: str
    expires_at: str
    case_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        if not isinstance(self.asset_ref, str) or ASSET_RE.fullmatch(self.asset_ref) is None:
            raise RestrictedAssetInferenceError("asset_ref must be opaque")
        if (
            not isinstance(self.technique_id, str)
            or TECHNIQUE_RE.fullmatch(self.technique_id) is None
        ):
            raise RestrictedAssetInferenceError("technique_id is invalid")
        try:
            object.__setattr__(
                self, "restriction_reason", RestrictionReason(self.restriction_reason),
            )
            facets = tuple(EvidenceFacet(value) for value in self.prerequisites)
        except (TypeError, ValueError) as exc:
            raise RestrictedAssetInferenceError("reason or prerequisites are invalid") from exc
        if (
            not facets or EvidenceFacet.CONTROL_OBSERVATION in facets
            or facets != tuple(sorted(set(facets)))
        ):
            raise RestrictedAssetInferenceError("prerequisites must be unique and canonical")
        object.__setattr__(self, "prerequisites", facets)
        _sha(self.mapping_source_sha256, "mapping_source_sha256")
        _sha(self.restriction_source_sha256, "restriction_source_sha256")
        recorded = _time(self.recorded_at, "recorded_at")
        expires = _time(self.expires_at, "expires_at")
        if not recorded < expires <= recorded + timedelta(seconds=MAX_CASE_AGE_SECONDS):
            raise RestrictedAssetInferenceError("case expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.restricted-asset-case.v1", self._payload())
        if self.case_sha256 and self.case_sha256 != expected:
            raise RestrictedAssetInferenceError("case_sha256 does not match content")
        object.__setattr__(self, "case_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "asset_ref": self.asset_ref, "technique_id": self.technique_id,
            "restriction_reason": self.restriction_reason.value,
            "prerequisites": [facet.value for facet in self.prerequisites],
            "mapping_source_sha256": self.mapping_source_sha256,
            "restriction_source_sha256": self.restriction_source_sha256,
            "recorded_at": self.recorded_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "case_sha256": self.case_sha256}


@dataclass(frozen=True, slots=True)
class RestrictedAssetObservation:
    tenant_id: str
    scope_sha256: str
    asset_ref: str
    technique_id: str
    facet: EvidenceFacet | str
    state: EvidenceState | str
    source_sha256: str
    observed_at: str
    expires_at: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        if not isinstance(self.asset_ref, str) or ASSET_RE.fullmatch(self.asset_ref) is None:
            raise RestrictedAssetInferenceError("asset_ref must be opaque")
        if (
            not isinstance(self.technique_id, str)
            or TECHNIQUE_RE.fullmatch(self.technique_id) is None
        ):
            raise RestrictedAssetInferenceError("technique_id is invalid")
        try:
            object.__setattr__(self, "facet", EvidenceFacet(self.facet))
            object.__setattr__(self, "state", EvidenceState(self.state))
        except (TypeError, ValueError) as exc:
            raise RestrictedAssetInferenceError("observation facet or state is invalid") from exc
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS):
            raise RestrictedAssetInferenceError("observation expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.restricted-asset-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise RestrictedAssetInferenceError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "asset_ref": self.asset_ref, "technique_id": self.technique_id,
            "facet": self.facet.value, "state": self.state.value,
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class RestrictedAssetInference:
    case_sha256: str
    reviewed_at: str
    observation_sha256: tuple[str, ...]
    status: InferenceStatus | str
    reasons: tuple[str, ...]
    inference_sha256: str = ""

    def __post_init__(self) -> None:
        _sha(self.case_sha256, "case_sha256")
        _time(self.reviewed_at, "reviewed_at")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > MAX_OBSERVATIONS
            or self.observation_sha256 != tuple(sorted(set(self.observation_sha256)))
        ):
            raise RestrictedAssetInferenceError("observation digests are not canonical")
        for value in self.observation_sha256:
            _sha(value, "observation digest")
        try:
            object.__setattr__(self, "status", InferenceStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise RestrictedAssetInferenceError("inference status is invalid") from exc
        allowed = {
            "case_expired", "control_counterevidence", "control_missing_or_unknown",
            "control_stale", "prerequisite_counterevidence",
            "prerequisite_missing_or_unknown", "prerequisite_stale",
            "prerequisites_and_control_asserted",
        }
        if (
            not isinstance(self.reasons, tuple)
            or not self.reasons or self.reasons != tuple(sorted(set(self.reasons)))
            or any(reason not in allowed for reason in self.reasons)
        ):
            raise RestrictedAssetInferenceError("inference reasons are not canonical")
        expected = _canonical_sha("sunderkey.restricted-asset-inference.v1", self._payload())
        if self.inference_sha256 and self.inference_sha256 != expected:
            raise RestrictedAssetInferenceError("inference_sha256 does not match content")
        object.__setattr__(self, "inference_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "case_sha256": self.case_sha256, "reviewed_at": self.reviewed_at,
            "observation_sha256": list(self.observation_sha256),
            "evidence_class": "restricted_asset_inference",
            "status": self.status.value, "reasons": list(self.reasons),
            "confidence": "low" if self.status is InferenceStatus.BOUNDED_INFERENCE else "none",
            "successful_exploitation": False,
            "independent_review_required": True,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "inference_sha256": self.inference_sha256}


def infer_restricted_asset(
    *, case: RestrictedAssetCase,
    observations: tuple[RestrictedAssetObservation, ...],
    reviewed_at: str,
) -> RestrictedAssetInference:
    """Classify metadata evidence without claiming a live exploit or bypass."""
    if not isinstance(case, RestrictedAssetCase):
        raise RestrictedAssetInferenceError("case must be typed")
    replace(case)
    now = _time(reviewed_at, "reviewed_at")
    if _time(case.recorded_at, "recorded_at") > now:
        raise RestrictedAssetInferenceError("case is future-dated")
    if (
        not isinstance(observations, tuple) or len(observations) > MAX_OBSERVATIONS
        or any(not isinstance(item, RestrictedAssetObservation) for item in observations)
    ):
        raise RestrictedAssetInferenceError("observations must be a bounded typed tuple")
    by_facet: dict[EvidenceFacet, RestrictedAssetObservation] = {}
    for item in observations:
        replace(item)
        if (
            item.tenant_id != case.tenant_id or item.scope_sha256 != case.scope_sha256
            or item.asset_ref != case.asset_ref or item.technique_id != case.technique_id
            or item.facet not in (*case.prerequisites, EvidenceFacet.CONTROL_OBSERVATION)
        ):
            raise RestrictedAssetInferenceError("observation crosses case binding")
        if _time(item.observed_at, "observed_at") > now:
            raise RestrictedAssetInferenceError("observation is future-dated")
        prior = by_facet.setdefault(item.facet, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise RestrictedAssetInferenceError("facet has conflicting evidence")
    flags: set[str] = set()
    if _time(case.expires_at, "expires_at") <= now:
        flags.add("case_expired")
    for facet in case.prerequisites:
        item = by_facet.get(facet)
        if item is None:
            flags.add("prerequisite_missing_or_unknown")
        elif _time(item.expires_at, "expires_at") <= now:
            flags.add("prerequisite_stale")
        elif item.state is EvidenceState.UNKNOWN:
            flags.add("prerequisite_missing_or_unknown")
        elif item.state is EvidenceState.CONTRADICTED_ASSERTED:
            flags.add("prerequisite_counterevidence")
    control = by_facet.get(EvidenceFacet.CONTROL_OBSERVATION)
    if control is None:
        flags.add("control_missing_or_unknown")
    elif _time(control.expires_at, "expires_at") <= now:
        flags.add("control_stale")
    elif control.state is EvidenceState.UNKNOWN:
        flags.add("control_missing_or_unknown")
    elif control.state is EvidenceState.CONTRADICTED_ASSERTED:
        flags.add("control_counterevidence")
    if "prerequisite_counterevidence" in flags or "control_counterevidence" in flags:
        status = InferenceStatus.COUNTEREVIDENCE
    elif "case_expired" in flags or "prerequisite_stale" in flags or "control_stale" in flags:
        status = InferenceStatus.STALE
    elif flags:
        status = InferenceStatus.INSUFFICIENT
    else:
        status = InferenceStatus.BOUNDED_INFERENCE
        flags.add("prerequisites_and_control_asserted")
    return RestrictedAssetInference(
        case_sha256=case.case_sha256, reviewed_at=reviewed_at,
        observation_sha256=tuple(sorted({
            item.observation_sha256 for item in by_facet.values()
        })),
        status=status, reasons=tuple(sorted(flags)),
    )
