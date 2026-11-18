"""Replay a closed advisory transition from pinned, caller-supplied raw evidence."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace

from .advisory_asset_applicability import (
    MAX_COMPONENT_OBSERVATIONS,
    AdvisoryApplicabilityError,
    AdvisoryApplicabilityReport,
    CuratedThreatAdvisory,
    InstalledComponentObservation,
    verify_advisory_applicability_report_from_sources,
)
from .advisory_transition_review import (
    AdvisoryTransitionError,
    AdvisoryTransitionReport,
    verify_advisory_transition_report_from_sources,
)
from .asset_reconciliation import (
    MAX_OBSERVATIONS,
    AssetObservation,
    AssetReconciliationError,
    AssetReconciliationSnapshot,
    _digest,
    _sha256,
    verify_asset_reconciliation_snapshot_from_sources,
)

MAX_ANCESTOR_DEPTH = 32
OBSERVATION_DOMAIN = "sunderkey.advisory-source-chain.asset-observations.v1"
COMPONENT_DOMAIN = "sunderkey.advisory-source-chain.component-observations.v1"


class AdvisorySourceChainError(ValueError):
    """Closed source evidence or lineage failed independent replay."""


@dataclass(frozen=True, slots=True)
class AssetSnapshotSources:
    """A snapshot and its pinned complete raw observation set, with optional ancestry."""

    snapshot: AssetReconciliationSnapshot
    observations: tuple[AssetObservation, ...]
    expected_observations_sha256: str
    prior: AssetSnapshotSources | None = None


def _pin(value: str, label: str) -> str:
    try:
        return _sha256(value, label)
    except AssetReconciliationError as exc:
        raise AdvisorySourceChainError(f"{label} is not a canonical digest") from exc


def asset_observation_set_sha256(observations: tuple[AssetObservation, ...]) -> str:
    """Digest a complete canonical raw observation set for external pinning."""

    if type(observations) is not tuple or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise AdvisorySourceChainError("asset observations must be a bounded nonempty tuple")
    if any(type(item) is not AssetObservation for item in observations):
        raise AdvisorySourceChainError("asset observations must remain typed")
    try:
        canonical = tuple(sorted(observations, key=lambda item: item.provenance_key))
        if len({item.provenance_key for item in canonical}) != len(canonical):
            raise AdvisorySourceChainError("asset observation provenance keys repeat")
        for item in canonical:
            if AssetObservation.from_dict(item.to_dict()) != item:
                raise AdvisorySourceChainError("asset observation is not canonical")
        return _digest(OBSERVATION_DOMAIN, [item.to_dict() for item in canonical])
    except (AssetReconciliationError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError("asset observation integrity is invalid") from exc


def component_observation_set_sha256(
    components: tuple[InstalledComponentObservation, ...],
) -> str:
    """Digest all supplied component observations, including repeated entries."""

    if type(components) is not tuple or len(components) > MAX_COMPONENT_OBSERVATIONS:
        raise AdvisorySourceChainError("component observations must be a bounded tuple")
    if any(type(item) is not InstalledComponentObservation for item in components):
        raise AdvisorySourceChainError("component observations must remain typed")
    try:
        for item in components:
            replace(item)
        return _digest(
            COMPONENT_DOMAIN,
            sorted(
                (item.to_dict() for item in components),
                key=lambda item: item["observation_sha256"],
            ),
        )
    except (AdvisoryApplicabilityError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError("component observation integrity is invalid") from exc


def _replay_asset_source(
    source: AssetSnapshotSources,
    *,
    ancestors: frozenset[int] = frozenset(),
) -> AssetReconciliationSnapshot:
    if type(source) is not AssetSnapshotSources:
        raise AdvisorySourceChainError("asset source segment has the wrong type")
    if id(source) in ancestors or len(ancestors) >= MAX_ANCESTOR_DEPTH:
        raise AdvisorySourceChainError("asset source ancestry is cyclic or too deep")
    if type(source.snapshot) is not AssetReconciliationSnapshot:
        raise AdvisorySourceChainError("asset snapshot has the wrong type")
    actual = asset_observation_set_sha256(source.observations)
    if actual != _pin(source.expected_observations_sha256, "asset observation pin"):
        raise AdvisorySourceChainError("asset raw observation pin differs")
    prior = (
        _replay_asset_source(source.prior, ancestors=ancestors | {id(source)})
        if source.prior is not None
        else None
    )
    try:
        return verify_asset_reconciliation_snapshot_from_sources(
            source.snapshot,
            source.observations,
            prior_snapshot=prior,
        )
    except (AssetReconciliationError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError("asset snapshot source replay failed") from exc


def verify_advisory_source_chain(
    *,
    advisory: CuratedThreatAdvisory,
    expected_advisory_sha256: str,
    baseline_source: AssetSnapshotSources,
    expected_baseline_snapshot_sha256: str,
    current_snapshot: AssetReconciliationSnapshot,
    expected_current_snapshot_sha256: str,
    current_observations: tuple[AssetObservation, ...],
    expected_current_observations_sha256: str,
    baseline_components: tuple[InstalledComponentObservation, ...],
    expected_baseline_components_sha256: str,
    current_components: tuple[InstalledComponentObservation, ...],
    expected_current_components_sha256: str,
    baseline_report: AdvisoryApplicabilityReport,
    current_report: AdvisoryApplicabilityReport,
    transition_report: AdvisoryTransitionReport,
) -> AdvisoryTransitionReport:
    """Verify raw pins, asset ancestry, applicability, and transition in that order.

    Expected digests must be retained outside the untrusted evidence bundle.
    This function does not authenticate their origin or grant action authority.
    """

    if type(advisory) is not CuratedThreatAdvisory:
        raise AdvisorySourceChainError("advisory has the wrong type")
    try:
        replace(advisory)
    except (AdvisoryApplicabilityError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError("advisory integrity is invalid") from exc
    if advisory.advisory_sha256 != _pin(expected_advisory_sha256, "advisory pin"):
        raise AdvisorySourceChainError("advisory source pin differs")
    baseline_snapshot = _replay_asset_source(baseline_source)
    if baseline_snapshot.snapshot_sha256 != _pin(
        expected_baseline_snapshot_sha256, "baseline snapshot pin"
    ):
        raise AdvisorySourceChainError("baseline snapshot pin differs")
    if type(current_snapshot) is not AssetReconciliationSnapshot:
        raise AdvisorySourceChainError("current asset snapshot has the wrong type")
    if current_snapshot.snapshot_sha256 != _pin(
        expected_current_snapshot_sha256, "current snapshot pin"
    ):
        raise AdvisorySourceChainError("current snapshot pin differs")
    if asset_observation_set_sha256(current_observations) != _pin(
        expected_current_observations_sha256, "current asset observation pin"
    ):
        raise AdvisorySourceChainError("current asset raw observation pin differs")
    try:
        verify_asset_reconciliation_snapshot_from_sources(
            current_snapshot,
            current_observations,
            prior_snapshot=baseline_snapshot,
        )
    except (AssetReconciliationError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError("current asset snapshot source replay failed") from exc
    if (
        component_observation_set_sha256(baseline_components)
        != _pin(expected_baseline_components_sha256, "baseline component pin")
        or component_observation_set_sha256(current_components)
        != _pin(expected_current_components_sha256, "current component pin")
    ):
        raise AdvisorySourceChainError("component raw observation pin differs")
    for name, value, expected_type in (
        ("baseline report", baseline_report, AdvisoryApplicabilityReport),
        ("current report", current_report, AdvisoryApplicabilityReport),
        ("transition report", transition_report, AdvisoryTransitionReport),
    ):
        if type(value) is not expected_type:
            raise AdvisorySourceChainError(f"{name} has the wrong type")
    try:
        verify_advisory_applicability_report_from_sources(
            advisory=advisory,
            asset_snapshot=baseline_snapshot,
            components=baseline_components,
            report=baseline_report,
        )
        verify_advisory_applicability_report_from_sources(
            advisory=advisory,
            asset_snapshot=current_snapshot,
            components=current_components,
            report=current_report,
        )
        return verify_advisory_transition_report_from_sources(
            advisory=advisory,
            baseline_report=baseline_report,
            current_report=current_report,
            baseline_snapshot=baseline_snapshot,
            current_snapshot=current_snapshot,
            baseline_components=baseline_components,
            current_components=current_components,
            transition_report=transition_report,
        )
    except (AdvisoryApplicabilityError, AdvisoryTransitionError, AttributeError, TypeError) as exc:
        raise AdvisorySourceChainError(
            "advisory applicability or transition replay failed"
        ) from exc
