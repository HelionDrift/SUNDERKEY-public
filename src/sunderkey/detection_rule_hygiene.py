"""Read-only hygiene review for redacted detection-rule snapshots."""

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

MAX_SOURCES = 32
MAX_AGE_SECONDS = 7 * 24 * 60 * 60
RULE_RE = re.compile(r"rule:sha256:[0-9a-f]{64}\Z")
SOURCE_RE = re.compile(r"source:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "connector_read": "none",
    "network": "none",
    "rule_change": "none",
    "rule_execution": "none",
    "telemetry_collection": "none",
}


class DetectionRuleHygieneError(ValueError):
    """Detection-rule snapshot or source evidence failed closed."""


class QueryHealth(StrEnum):
    VALID_ASSERTED = "valid_asserted"
    ERROR_ASSERTED = "error_asserted"
    UNKNOWN = "unknown"


class MappingState(StrEnum):
    CURRENT_ASSERTED = "current_asserted"
    STALE_ASSERTED = "stale_asserted"
    UNKNOWN = "unknown"


class SourceState(StrEnum):
    AVAILABLE_ASSERTED = "available_asserted"
    MISSING_ASSERTED = "missing_asserted"
    UNKNOWN = "unknown"


class HygieneStatus(StrEnum):
    ATTENTION_REQUIRED = "attention_required"
    STALE_EVIDENCE = "stale_evidence"
    INCONCLUSIVE = "inconclusive"
    METADATA_HEALTHY = "metadata_healthy_for_review"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise DetectionRuleHygieneError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise DetectionRuleHygieneError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise DetectionRuleHygieneError(f"{label} is invalid") from exc


def _opaque(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DetectionRuleHygieneError(f"{label} must be an opaque reference")


@dataclass(frozen=True, slots=True)
class RedactedRuleSnapshot:
    tenant_id: str
    scope_sha256: str
    rule_ref: str
    enabled: bool
    query_health: QueryHealth | str
    mapping_state: MappingState | str
    required_source_refs: tuple[str, ...]
    source_sha256: str
    observed_at: str
    expires_at: str
    snapshot_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.rule_ref, "rule_ref", RULE_RE)
        if not isinstance(self.enabled, bool):
            raise DetectionRuleHygieneError("enabled must be boolean")
        try:
            object.__setattr__(self, "query_health", QueryHealth(self.query_health))
            object.__setattr__(self, "mapping_state", MappingState(self.mapping_state))
        except (TypeError, ValueError) as exc:
            raise DetectionRuleHygieneError("query health or mapping state is invalid") from exc
        if (
            not isinstance(self.required_source_refs, tuple)
            or not self.required_source_refs
            or len(self.required_source_refs) > MAX_SOURCES
            or self.required_source_refs != tuple(sorted(set(self.required_source_refs)))
        ):
            raise DetectionRuleHygieneError("required sources must be bounded and canonical")
        for value in self.required_source_refs:
            _opaque(value, "required source", SOURCE_RE)
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_AGE_SECONDS):
            raise DetectionRuleHygieneError("snapshot expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.redacted-rule-snapshot.v1", self._payload())
        if self.snapshot_sha256 and self.snapshot_sha256 != expected:
            raise DetectionRuleHygieneError("snapshot_sha256 does not match content")
        object.__setattr__(self, "snapshot_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "rule_ref": self.rule_ref, "enabled": self.enabled,
            "query_health": self.query_health.value,
            "mapping_state": self.mapping_state.value,
            "required_source_refs": list(self.required_source_refs),
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "snapshot_sha256": self.snapshot_sha256}


@dataclass(frozen=True, slots=True)
class RuleSourceObservation:
    tenant_id: str
    scope_sha256: str
    rule_ref: str
    source_ref: str
    state: SourceState | str
    evidence_sha256: str
    observed_at: str
    expires_at: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.rule_ref, "rule_ref", RULE_RE)
        _opaque(self.source_ref, "source_ref", SOURCE_RE)
        try:
            object.__setattr__(self, "state", SourceState(self.state))
        except (TypeError, ValueError) as exc:
            raise DetectionRuleHygieneError("source state is invalid") from exc
        _sha(self.evidence_sha256, "evidence_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_AGE_SECONDS):
            raise DetectionRuleHygieneError("source expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.rule-source-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise DetectionRuleHygieneError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "rule_ref": self.rule_ref, "source_ref": self.source_ref,
            "state": self.state.value, "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class DetectionRuleHygieneReview:
    snapshot_sha256: str
    reviewed_at: str
    observation_sha256: tuple[str, ...]
    status: HygieneStatus | str
    reasons: tuple[str, ...]
    review_sha256: str = ""

    def __post_init__(self) -> None:
        _sha(self.snapshot_sha256, "snapshot_sha256")
        _time(self.reviewed_at, "reviewed_at")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > MAX_SOURCES
            or self.observation_sha256 != tuple(sorted(set(self.observation_sha256)))
        ):
            raise DetectionRuleHygieneError("observation digests are not canonical")
        for value in self.observation_sha256:
            _sha(value, "observation digest")
        try:
            object.__setattr__(self, "status", HygieneStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise DetectionRuleHygieneError("review status is invalid") from exc
        allowed = {
            "all_metadata_healthy_asserted", "mapping_stale_asserted",
            "mapping_unknown", "query_error_asserted", "query_unknown",
            "rule_disabled", "snapshot_expired", "source_expired",
            "source_missing_asserted", "source_missing_or_unknown",
        }
        if (
            not isinstance(self.reasons, tuple)
            or not self.reasons or self.reasons != tuple(sorted(set(self.reasons)))
            or any(reason not in allowed for reason in self.reasons)
        ):
            raise DetectionRuleHygieneError("review reasons are not canonical")
        reasons = set(self.reasons)
        if (
            (self.status is HygieneStatus.METADATA_HEALTHY)
            != (reasons == {"all_metadata_healthy_asserted"})
            or self.status is HygieneStatus.ATTENTION_REQUIRED
            and not reasons.intersection({
                "rule_disabled", "query_error_asserted", "mapping_stale_asserted",
                "source_missing_asserted",
            })
            or self.status is HygieneStatus.STALE_EVIDENCE
            and not reasons.intersection({"snapshot_expired", "source_expired"})
            or self.status is HygieneStatus.INCONCLUSIVE
            and not reasons.intersection({
                "query_unknown", "mapping_unknown", "source_missing_or_unknown",
            })
        ):
            raise DetectionRuleHygieneError("review status conflicts with reasons")
        expected = _canonical_sha("sunderkey.detection-rule-hygiene-review.v1", self._payload())
        if self.review_sha256 and self.review_sha256 != expected:
            raise DetectionRuleHygieneError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "snapshot_sha256": self.snapshot_sha256,
            "reviewed_at": self.reviewed_at,
            "observation_sha256": list(self.observation_sha256),
            "status": self.status.value, "reasons": list(self.reasons),
            "detection_effectiveness_proven": False,
            "independent_review_required": True,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}


def review_detection_rule_hygiene(
    *, snapshot: RedactedRuleSnapshot,
    observations: tuple[RuleSourceObservation, ...],
    reviewed_at: str,
) -> DetectionRuleHygieneReview:
    """Classify redacted rule and source metadata without contacting a SIEM."""
    if not isinstance(snapshot, RedactedRuleSnapshot):
        raise DetectionRuleHygieneError("snapshot must be typed")
    replace(snapshot)
    now = _time(reviewed_at, "reviewed_at")
    if _time(snapshot.observed_at, "observed_at") > now:
        raise DetectionRuleHygieneError("snapshot is future-dated")
    if (
        not isinstance(observations, tuple)
        or len(observations) > MAX_SOURCES
        or any(not isinstance(item, RuleSourceObservation) for item in observations)
    ):
        raise DetectionRuleHygieneError("observations must be a bounded typed tuple")
    by_source: dict[str, RuleSourceObservation] = {}
    for item in observations:
        replace(item)
        if (
            item.tenant_id != snapshot.tenant_id
            or item.scope_sha256 != snapshot.scope_sha256
            or item.rule_ref != snapshot.rule_ref
            or item.source_ref not in snapshot.required_source_refs
        ):
            raise DetectionRuleHygieneError("source observation crosses snapshot binding")
        if _time(item.observed_at, "observed_at") > now:
            raise DetectionRuleHygieneError("source observation is future-dated")
        prior = by_source.setdefault(item.source_ref, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise DetectionRuleHygieneError("source has conflicting evidence")
    flags: set[str] = set()
    if _time(snapshot.expires_at, "expires_at") <= now:
        flags.add("snapshot_expired")
    if not snapshot.enabled:
        flags.add("rule_disabled")
    if snapshot.query_health is QueryHealth.ERROR_ASSERTED:
        flags.add("query_error_asserted")
    elif snapshot.query_health is QueryHealth.UNKNOWN:
        flags.add("query_unknown")
    if snapshot.mapping_state is MappingState.STALE_ASSERTED:
        flags.add("mapping_stale_asserted")
    elif snapshot.mapping_state is MappingState.UNKNOWN:
        flags.add("mapping_unknown")
    for ref in snapshot.required_source_refs:
        item = by_source.get(ref)
        if item is None:
            flags.add("source_missing_or_unknown")
        elif _time(item.expires_at, "expires_at") <= now:
            flags.add("source_expired")
        elif item.state is SourceState.MISSING_ASSERTED:
            flags.add("source_missing_asserted")
        elif item.state is SourceState.UNKNOWN:
            flags.add("source_missing_or_unknown")
    if "snapshot_expired" in flags:
        status = HygieneStatus.STALE_EVIDENCE
    elif flags.intersection({
        "rule_disabled", "query_error_asserted", "mapping_stale_asserted",
        "source_missing_asserted",
    }):
        status = HygieneStatus.ATTENTION_REQUIRED
    elif "source_expired" in flags:
        status = HygieneStatus.STALE_EVIDENCE
    elif flags:
        status = HygieneStatus.INCONCLUSIVE
    else:
        status = HygieneStatus.METADATA_HEALTHY
        flags.add("all_metadata_healthy_asserted")
    return DetectionRuleHygieneReview(
        snapshot_sha256=snapshot.snapshot_sha256, reviewed_at=reviewed_at,
        observation_sha256=tuple(sorted({
            item.observation_sha256 for item in by_source.values()
        })),
        status=status, reasons=tuple(sorted(flags)),
    )
