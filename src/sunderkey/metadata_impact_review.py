"""Metadata-only sensitive-data impact triage without content access."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_OBSERVATIONS = 10000
MAX_DATASETS = 2000
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
DATASET_RE = re.compile(r"dataset:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = MappingProxyType({
    "authority": "none",
    "content_access": "none",
    "data_collection": "none",
    "exfiltration_verdict": "none",
    "execution": "none",
    "network": "none",
    "regulatory_verdict": "none",
})


class MetadataImpactError(ValueError):
    """Metadata-only impact input or review failed closed."""


class DataCategory(StrEnum):
    PERSONAL_IDENTIFIER = "personal_identifier"
    FINANCIAL = "financial"
    HEALTH = "health"
    AUTHENTICATION = "authentication"
    BUSINESS_CONFIDENTIAL = "business_confidential"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class Reachability(StrEnum):
    VERIFIED_PATH_ASSERTED = "verified_path_asserted"
    HYPOTHESIS = "hypothesis"
    NOT_ASSESSED = "not_assessed"


class RecordCountBucket(StrEnum):
    UNKNOWN = "unknown"
    ONE_TO_HUNDRED = "1_100"
    HUNDRED_ONE_TO_TEN_THOUSAND = "101_10000"
    OVER_TEN_THOUSAND = "over_10000"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ReviewStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    TRIAGE_REQUIRED = "triage_required"
    INCONCLUSIVE = "inconclusive"
    STALE_METADATA = "stale_metadata"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise MetadataImpactError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise MetadataImpactError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise MetadataImpactError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class DataMetadataObservation:
    tenant_id: str
    scope_sha256: str
    dataset_ref: str
    source_record_id: str
    source_sha256: str
    observed_at: str
    expires_at: str
    category: DataCategory | str
    reachability: Reachability | str
    path_evidence_sha256: str | None
    record_count_bucket: RecordCountBucket | str
    business_criticality: Criticality | str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        if not isinstance(self.dataset_ref, str) or DATASET_RE.fullmatch(
            self.dataset_ref
        ) is None:
            raise MetadataImpactError("dataset_ref must be an opaque digest reference")
        _id(self.source_record_id, "source_record_id")
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_AGE_SECONDS):
            raise MetadataImpactError("metadata expiry is outside retention limit")
        for name, enum_type in (
            ("category", DataCategory),
            ("reachability", Reachability),
            ("record_count_bucket", RecordCountBucket),
            ("business_criticality", Criticality),
        ):
            try:
                object.__setattr__(self, name, enum_type(getattr(self, name)))
            except (TypeError, ValueError) as exc:
                raise MetadataImpactError(f"{name} is invalid") from exc
        if self.reachability is Reachability.NOT_ASSESSED:
            if self.path_evidence_sha256 is not None:
                raise MetadataImpactError("unassessed reachability cannot carry path evidence")
        else:
            _sha(self.path_evidence_sha256, "path_evidence_sha256")
        expected = _canonical_sha("sunderkey.data-metadata-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise MetadataImpactError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "dataset_ref": self.dataset_ref,
            "source_record_id": self.source_record_id,
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
            "category": self.category.value,
            "reachability": self.reachability.value,
            "path_evidence_sha256": self.path_evidence_sha256,
            "record_count_bucket": self.record_count_bucket.value,
            "business_criticality": self.business_criticality.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class DatasetImpactSignal:
    dataset_ref: str
    categories: tuple[str, ...]
    record_count_buckets: tuple[str, ...]
    business_criticalities: tuple[str, ...]
    reachability_states: tuple[str, ...]
    observation_sha256: tuple[str, ...]
    review_reasons: tuple[str, ...]
    review_status: ReviewStatus | str

    def __post_init__(self) -> None:
        if not isinstance(self.dataset_ref, str) or DATASET_RE.fullmatch(
            self.dataset_ref
        ) is None:
            raise MetadataImpactError("signal dataset_ref is invalid")
        for name in (
            "categories", "record_count_buckets", "business_criticalities",
            "reachability_states", "observation_sha256", "review_reasons",
        ):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values or values != tuple(sorted(set(values))):
                raise MetadataImpactError(f"signal {name} is not canonical")
        for name, enum_type in (
            ("categories", DataCategory),
            ("record_count_buckets", RecordCountBucket),
            ("business_criticalities", Criticality),
            ("reachability_states", Reachability),
        ):
            try:
                for value in getattr(self, name):
                    enum_type(value)
            except (TypeError, ValueError) as exc:
                raise MetadataImpactError(f"signal {name} is invalid") from exc
        for value in self.observation_sha256:
            _sha(value, "signal observation digest")
        for value in self.review_reasons:
            _id(value, "review reason")
        try:
            object.__setattr__(self, "review_status", ReviewStatus(self.review_status))
        except (TypeError, ValueError) as exc:
            raise MetadataImpactError("review_status is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_ref": self.dataset_ref,
            "categories": list(self.categories),
            "record_count_buckets": list(self.record_count_buckets),
            "business_criticalities": list(self.business_criticalities),
            "reachability_states": list(self.reachability_states),
            "observation_sha256": list(self.observation_sha256),
            "review_reasons": list(self.review_reasons),
            "review_status": self.review_status.value,
        }


@dataclass(frozen=True, slots=True)
class MetadataImpactReview:
    tenant_id: str
    scope_sha256: str
    reviewed_at: str
    observation_sha256: tuple[str, ...]
    signals: tuple[DatasetImpactSignal, ...]
    review_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _time(self.reviewed_at, "reviewed_at")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > MAX_OBSERVATIONS
            or self.observation_sha256 != tuple(sorted(set(self.observation_sha256)))
        ):
            raise MetadataImpactError("review observations are not canonical")
        for value in self.observation_sha256:
            _sha(value, "review observation digest")
        if (
            not isinstance(self.signals, tuple) or len(self.signals) > MAX_DATASETS
            or any(not isinstance(item, DatasetImpactSignal) for item in self.signals)
            or self.signals != tuple(sorted(self.signals, key=lambda item: item.dataset_ref))
            or len({item.dataset_ref for item in self.signals}) != len(self.signals)
        ):
            raise MetadataImpactError("review signals are not canonical")
        if sum(len(item.observation_sha256) for item in self.signals) != len(
            self.observation_sha256
        ):
            raise MetadataImpactError("review observations are repeated across signals")
        if tuple(sorted({value for item in self.signals for value in item.observation_sha256})) != (
            self.observation_sha256
        ):
            raise MetadataImpactError("signals do not cover observations")
        expected = _canonical_sha("sunderkey.metadata-impact-review.v1", self._payload())
        if self.review_sha256 and self.review_sha256 != expected:
            raise MetadataImpactError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "reviewed_at": self.reviewed_at,
            "observation_sha256": list(self.observation_sha256),
            "signals": [item.to_dict() for item in self.signals],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}


def _signal(
    dataset_ref: str, items: tuple[DataMetadataObservation, ...], at: str,
) -> DatasetImpactSignal:
    now = _time(at, "reviewed_at")
    active = tuple(item for item in items if _time(item.expires_at, "expires_at") > now)
    selected = active or items
    categories = tuple(sorted({item.category.value for item in selected}))
    buckets = tuple(sorted({item.record_count_bucket.value for item in selected}))
    criticalities = tuple(sorted({item.business_criticality.value for item in selected}))
    reachability = tuple(sorted({item.reachability.value for item in selected}))
    sensitive = any(category not in {"public", "unknown"} for category in categories)
    conflicting = "public" in categories and sensitive
    verified = Reachability.VERIFIED_PATH_ASSERTED.value in reachability
    reasons: set[str] = set()
    if not active:
        status = ReviewStatus.STALE_METADATA
        reasons.add("all_metadata_expired")
    elif conflicting:
        status = ReviewStatus.TRIAGE_REQUIRED
        reasons.add("public_sensitive_declaration_conflict")
    elif sensitive and verified:
        status = ReviewStatus.REVIEW_REQUIRED
        reasons.add("sensitive_category_and_path_asserted")
    elif sensitive:
        status = ReviewStatus.TRIAGE_REQUIRED
        reasons.add("sensitive_category_without_verified_path")
    else:
        status = ReviewStatus.INCONCLUSIVE
        reasons.add("no_sensitive_category_established")
    if "high" in criticalities:
        reasons.add("high_criticality_asserted")
    if RecordCountBucket.OVER_TEN_THOUSAND.value in buckets:
        reasons.add("broad_count_bucket_asserted")
    return DatasetImpactSignal(
        dataset_ref=dataset_ref, categories=categories,
        record_count_buckets=buckets, business_criticalities=criticalities,
        reachability_states=reachability,
        observation_sha256=tuple(sorted(item.observation_sha256 for item in items)),
        review_reasons=tuple(sorted(reasons)), review_status=status,
    )


def review_data_metadata(
    *, observations: tuple[DataMetadataObservation, ...],
    tenant_id: str, scope_sha256: str, reviewed_at: str,
) -> MetadataImpactReview:
    """Derive review signals from closed category metadata, never data values."""
    _id(tenant_id, "tenant_id")
    _sha(scope_sha256, "scope_sha256")
    now = _time(reviewed_at, "reviewed_at")
    if not isinstance(observations, tuple) or len(observations) > MAX_OBSERVATIONS:
        raise MetadataImpactError("observations must be a bounded tuple")
    by_source: dict[tuple[str, str], DataMetadataObservation] = {}
    for item in observations:
        if not isinstance(item, DataMetadataObservation):
            raise MetadataImpactError("observation must be typed")
        replace(item)
        if item.tenant_id != tenant_id or item.scope_sha256 != scope_sha256:
            raise MetadataImpactError("observation tenant or scope differs")
        observed = _time(item.observed_at, "observed_at")
        if observed > now or now - observed > timedelta(seconds=MAX_AGE_SECONDS):
            raise MetadataImpactError("observation is future-dated or too old")
        key = (item.dataset_ref, item.source_record_id)
        prior = by_source.setdefault(key, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise MetadataImpactError("one source record has conflicting metadata")
    by_dataset: dict[str, list[DataMetadataObservation]] = defaultdict(list)
    for item in by_source.values():
        by_dataset[item.dataset_ref].append(item)
    if len(by_dataset) > MAX_DATASETS:
        raise MetadataImpactError("dataset count exceeds hard limit")
    signals = tuple(
        _signal(dataset_ref, tuple(items), reviewed_at)
        for dataset_ref, items in sorted(by_dataset.items())
    )
    return MetadataImpactReview(
        tenant_id=tenant_id, scope_sha256=scope_sha256, reviewed_at=reviewed_at,
        observation_sha256=tuple(sorted(
            item.observation_sha256 for item in by_source.values()
        )),
        signals=signals,
    )
