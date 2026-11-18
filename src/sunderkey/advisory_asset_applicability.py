"""Offline advisory and component evidence correlation without target effects."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .asset_reconciliation import (
    AssetReconciliationError,
    AssetReconciliationSnapshot,
    FreshnessState,
)
from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_COMPONENT_OBSERVATIONS = 10000
MAX_AFFECTED_VERSIONS = 1024
MAX_SNAPSHOT_AGE_SECONDS = 7 * 24 * 60 * 60
COMPONENT_RE = re.compile(r"[a-z0-9][a-z0-9._+:/-]{0,127}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}\Z")
ASSET_RE = re.compile(r"AST-[0-9A-F]{32}\Z")
NO_EFFECTS = MappingProxyType({
    "advisory_source_authentication": "none",
    "authority": "none",
    "execution": "none",
    "network": "none",
    "remediation": "none",
    "scheduler": "none",
})


class AdvisoryApplicabilityError(ValueError):
    """Advisory correlation could not be performed safely."""


class ApplicabilityState(StrEnum):
    CANDIDATE_MATCH = "candidate_match"
    VERSION_NOT_LISTED = "version_not_listed"
    STALE_EVIDENCE = "stale_component_evidence"
    ASSET_UNCERTAIN = "asset_identity_or_freshness_uncertain"


def _validate_digest(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise AdvisoryApplicabilityError(f"{label} is invalid") from exc


def _validate_time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise AdvisoryApplicabilityError(f"{label} is invalid") from exc


def _validate_id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise AdvisoryApplicabilityError(f"{label} is invalid") from exc


def _component(value: str) -> None:
    if not isinstance(value, str) or COMPONENT_RE.fullmatch(value) is None:
        raise AdvisoryApplicabilityError("component_ref must be a canonical opaque identifier")


def _version(value: str) -> None:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise AdvisoryApplicabilityError("version must be an exact canonical token")


@dataclass(frozen=True, slots=True, order=True)
class AffectedComponentVersion:
    component_ref: str
    version: str

    def __post_init__(self) -> None:
        _component(self.component_ref)
        _version(self.version)

    def to_dict(self) -> dict[str, str]:
        return {"component_ref": self.component_ref, "version": self.version}


@dataclass(frozen=True, slots=True)
class CuratedThreatAdvisory:
    advisory_id: str
    source_id: str
    source_sha256: str
    published_at: str
    affected_versions: tuple[AffectedComponentVersion, ...]
    advisory_sha256: str = ""

    def __post_init__(self) -> None:
        _validate_id(self.advisory_id, "advisory_id")
        _validate_id(self.source_id, "source_id")
        _validate_digest(self.source_sha256, "source_sha256")
        _validate_time(self.published_at, "published_at")
        if (
            type(self.affected_versions) is not tuple
            or not 1 <= len(self.affected_versions) <= MAX_AFFECTED_VERSIONS
            or any(
                type(item) is not AffectedComponentVersion
                for item in self.affected_versions
            )
            or self.affected_versions != tuple(sorted(set(self.affected_versions)))
        ):
            raise AdvisoryApplicabilityError("affected_versions must be bounded and canonical")
        expected = _canonical_sha("sunderkey.curated-threat-advisory.v1", self._payload())
        if self.advisory_sha256 and self.advisory_sha256 != expected:
            raise AdvisoryApplicabilityError("advisory_sha256 does not match content")
        object.__setattr__(self, "advisory_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id, "source_id": self.source_id,
            "source_sha256": self.source_sha256, "published_at": self.published_at,
            "affected_versions": [item.to_dict() for item in self.affected_versions],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "advisory_sha256": self.advisory_sha256}


@dataclass(frozen=True, slots=True)
class InstalledComponentObservation:
    tenant_id: str
    asset_id: str
    component_ref: str
    version: str
    source_id: str
    source_sha256: str
    observed_at: str
    expires_at: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _validate_id(self.tenant_id, "tenant_id")
        if not isinstance(self.asset_id, str) or ASSET_RE.fullmatch(self.asset_id) is None:
            raise AdvisoryApplicabilityError("asset_id is invalid")
        _component(self.component_ref)
        _version(self.version)
        _validate_id(self.source_id, "source_id")
        _validate_digest(self.source_sha256, "source_sha256")
        if _validate_time(self.expires_at, "expires_at") <= _validate_time(
            self.observed_at, "observed_at"
        ):
            raise AdvisoryApplicabilityError("component expiry must follow observation")
        expected = _canonical_sha("sunderkey.installed-component-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise AdvisoryApplicabilityError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id, "asset_id": self.asset_id,
            "component_ref": self.component_ref, "version": self.version,
            "source_id": self.source_id, "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, str]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class AssetApplicabilityCandidate:
    asset_id: str
    component_ref: str
    observed_versions: tuple[str, ...]
    observation_sha256: tuple[str, ...]
    state: ApplicabilityState | str

    def __post_init__(self) -> None:
        if not isinstance(self.asset_id, str) or ASSET_RE.fullmatch(self.asset_id) is None:
            raise AdvisoryApplicabilityError("candidate asset_id is invalid")
        _component(self.component_ref)
        for values in (self.observed_versions, self.observation_sha256):
            if not isinstance(values, tuple) or not values or values != tuple(sorted(set(values))):
                raise AdvisoryApplicabilityError("candidate evidence is not canonical")
        for version in self.observed_versions:
            _version(version)
        for digest in self.observation_sha256:
            _validate_digest(digest, "candidate observation digest")
        try:
            object.__setattr__(self, "state", ApplicabilityState(self.state))
        except (TypeError, ValueError) as exc:
            raise AdvisoryApplicabilityError("candidate state is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id, "component_ref": self.component_ref,
            "observed_versions": list(self.observed_versions),
            "observation_sha256": list(self.observation_sha256), "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class AdvisoryApplicabilityReport:
    advisory_sha256: str
    asset_snapshot_sha256: str
    tenant_id: str
    as_of: str
    candidates: tuple[AssetApplicabilityCandidate, ...]
    missing_component_evidence_asset_ids: tuple[str, ...]
    report_sha256: str = ""

    def __post_init__(self) -> None:
        _validate_digest(self.advisory_sha256, "advisory_sha256")
        _validate_digest(self.asset_snapshot_sha256, "asset_snapshot_sha256")
        _validate_id(self.tenant_id, "tenant_id")
        _validate_time(self.as_of, "as_of")
        if (
            type(self.candidates) is not tuple
            or any(type(item) is not AssetApplicabilityCandidate for item in self.candidates)
            or self.candidates != tuple(sorted(
                self.candidates, key=lambda item: (item.asset_id, item.component_ref)
            ))
        ):
            raise AdvisoryApplicabilityError("candidates are not canonical")
        gaps = self.missing_component_evidence_asset_ids
        if not isinstance(gaps, tuple) or gaps != tuple(sorted(set(gaps))):
            raise AdvisoryApplicabilityError("missing-evidence assets are not canonical")
        if any(ASSET_RE.fullmatch(value) is None for value in gaps):
            raise AdvisoryApplicabilityError("missing-evidence asset ID is invalid")
        expected = _canonical_sha("sunderkey.advisory-asset-applicability.v1", self._payload())
        if self.report_sha256 and self.report_sha256 != expected:
            raise AdvisoryApplicabilityError("report_sha256 does not match content")
        object.__setattr__(self, "report_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "advisory_sha256": self.advisory_sha256,
            "asset_snapshot_sha256": self.asset_snapshot_sha256,
            "tenant_id": self.tenant_id, "as_of": self.as_of,
            "candidates": [item.to_dict() for item in self.candidates],
            "missing_component_evidence_asset_ids": list(
                self.missing_component_evidence_asset_ids
            ),
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "report_sha256": self.report_sha256}


def correlate_advisory_assets(
    *, advisory: CuratedThreatAdvisory, asset_snapshot: AssetReconciliationSnapshot,
    components: tuple[InstalledComponentObservation, ...], as_of: str,
) -> AdvisoryApplicabilityReport:
    """Match exact component versions while retaining absence and freshness uncertainty."""
    if type(advisory) is not CuratedThreatAdvisory or type(
        asset_snapshot
    ) is not AssetReconciliationSnapshot:
        raise AdvisoryApplicabilityError("typed advisory and asset snapshot are required")
    replace(advisory)
    try:
        AssetReconciliationSnapshot.from_dict(asset_snapshot.to_dict())
    except AssetReconciliationError as exc:
        raise AdvisoryApplicabilityError("asset snapshot integrity is invalid") from exc
    now = _validate_time(as_of, "as_of")
    snapshot_at = _validate_time(asset_snapshot.as_of, "asset snapshot as_of")
    if now < snapshot_at or now - snapshot_at > timedelta(seconds=MAX_SNAPSHOT_AGE_SECONDS):
        raise AdvisoryApplicabilityError("asset snapshot is future-dated or too old")
    if _validate_time(advisory.published_at, "advisory published_at") > now:
        raise AdvisoryApplicabilityError("advisory is future-dated")
    if not isinstance(components, tuple) or len(components) > MAX_COMPONENT_OBSERVATIONS:
        raise AdvisoryApplicabilityError("components must be a bounded tuple")
    asset_by_id = {item.asset_id: item for item in asset_snapshot.assets}
    affected: dict[str, set[str]] = defaultdict(set)
    for item in advisory.affected_versions:
        affected[item.component_ref].add(item.version)
    grouped: dict[tuple[str, str], list[InstalledComponentObservation]] = defaultdict(list)
    seen_sources: dict[tuple[str, str], str] = {}
    for item in components:
        if type(item) is not InstalledComponentObservation:
            raise AdvisoryApplicabilityError("component observation is not typed")
        replace(item)
        if item.tenant_id != asset_snapshot.tenant_id or item.asset_id not in asset_by_id:
            raise AdvisoryApplicabilityError("component tenant or asset is outside snapshot")
        observed = _validate_time(item.observed_at, "component observed_at")
        if observed > snapshot_at:
            raise AdvisoryApplicabilityError("component observation follows asset snapshot")
        source_key = (item.source_id, item.asset_id)
        prior = seen_sources.setdefault(source_key, item.observation_sha256)
        if prior != item.observation_sha256:
            raise AdvisoryApplicabilityError("one source ID conflicts within an asset")
        if item.component_ref in affected:
            grouped[(item.asset_id, item.component_ref)].append(item)
    candidates: list[AssetApplicabilityCandidate] = []
    covered_assets: set[str] = set()
    for (asset_id, component_ref), observations in sorted(grouped.items()):
        covered_assets.add(asset_id)
        asset = asset_by_id[asset_id]
        versions = tuple(sorted({item.version for item in observations}))
        active = tuple(item for item in observations if _validate_time(
            item.expires_at, "component expires_at"
        ) > now)
        if (
            asset.freshness is not FreshnessState.CURRENT
            or asset.confidence_bps < 5000
            or not any(
                _validate_time(provenance.expires_at, "asset provenance expiry") > now
                for provenance in asset.provenance
            )
        ):
            state = ApplicabilityState.ASSET_UNCERTAIN
        elif not active:
            state = ApplicabilityState.STALE_EVIDENCE
        elif any(item.version in affected[component_ref] for item in active):
            state = ApplicabilityState.CANDIDATE_MATCH
        else:
            state = ApplicabilityState.VERSION_NOT_LISTED
        candidates.append(AssetApplicabilityCandidate(
            asset_id=asset_id, component_ref=component_ref,
            observed_versions=versions,
            observation_sha256=tuple(sorted({item.observation_sha256 for item in observations})),
            state=state,
        ))
    return AdvisoryApplicabilityReport(
        advisory_sha256=advisory.advisory_sha256,
        asset_snapshot_sha256=asset_snapshot.snapshot_sha256,
        tenant_id=asset_snapshot.tenant_id, as_of=as_of,
        candidates=tuple(candidates),
        missing_component_evidence_asset_ids=tuple(sorted(set(asset_by_id) - covered_assets)),
    )


def verify_advisory_applicability_report_from_sources(
    *,
    advisory: CuratedThreatAdvisory,
    asset_snapshot: AssetReconciliationSnapshot,
    components: tuple[InstalledComponentObservation, ...],
    report: AdvisoryApplicabilityReport,
) -> AdvisoryApplicabilityReport:
    """Replay a stored report from its supplied advisory, asset, and component evidence."""

    if type(report) is not AdvisoryApplicabilityReport:
        raise AdvisoryApplicabilityError("applicability report has the wrong type")
    replace(report)
    expected = correlate_advisory_assets(
        advisory=advisory,
        asset_snapshot=asset_snapshot,
        components=components,
        as_of=report.as_of,
    )
    if expected != report:
        raise AdvisoryApplicabilityError("applicability report does not match source replay")
    return report
