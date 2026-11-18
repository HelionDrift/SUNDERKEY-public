"""Offline comparison of advisory applicability reports across asset snapshots."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .advisory_asset_applicability import (
    ASSET_RE,
    AdvisoryApplicabilityError,
    AdvisoryApplicabilityReport,
    ApplicabilityState,
    AssetApplicabilityCandidate,
    CuratedThreatAdvisory,
    InstalledComponentObservation,
    _component,
    verify_advisory_applicability_report_from_sources,
)
from .asset_reconciliation import AssetReconciliationError, AssetReconciliationSnapshot
from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

NO_EFFECTS = MappingProxyType(
    {
        "authority": "none",
        "execution": "none",
        "finding_publication": "none",
        "network": "none",
        "remediation_confirmation": "none",
        "scheduler": "none",
    }
)


class AdvisoryTransitionError(ValueError):
    """Applicability reports cannot support a trustworthy transition review."""


class TransitionState(StrEnum):
    NEW_OR_RETURNED_MATCH = "new_or_returned_candidate_match"
    CONTINUING_MATCH = "continuing_candidate_match"
    MATCH_NOT_REOBSERVED = "candidate_match_not_reobserved"
    EVIDENCE_GAP = "current_evidence_gap"
    REVIEW_STATE_CHANGED = "review_state_changed"


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except ValueError as exc:
        raise AdvisoryTransitionError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class AdvisoryTransition:
    asset_id: str
    component_ref: str
    baseline_state: str
    current_state: str
    transition_state: TransitionState | str

    def __post_init__(self) -> None:
        for label in ("baseline_state", "current_state"):
            value = getattr(self, label)
            if value != "missing_evidence":
                try:
                    ApplicabilityState(value)
                except (TypeError, ValueError) as exc:
                    raise AdvisoryTransitionError(f"{label} is invalid") from exc
        try:
            object.__setattr__(self, "transition_state", TransitionState(self.transition_state))
        except (TypeError, ValueError) as exc:
            raise AdvisoryTransitionError("transition_state is invalid") from exc
        if not isinstance(self.asset_id, str) or ASSET_RE.fullmatch(self.asset_id) is None:
            raise AdvisoryTransitionError("transition asset_id is invalid")
        try:
            _component(self.component_ref)
        except AdvisoryApplicabilityError as exc:
            raise AdvisoryTransitionError("transition component_ref is invalid") from exc
        if self.transition_state is not _transition(self.baseline_state, self.current_state):
            raise AdvisoryTransitionError("transition_state does not match observed states")

    def to_dict(self) -> dict[str, str]:
        return {
            "asset_id": self.asset_id,
            "component_ref": self.component_ref,
            "baseline_state": self.baseline_state,
            "current_state": self.current_state,
            "transition_state": self.transition_state.value,
        }


@dataclass(frozen=True, slots=True)
class AdvisoryTransitionReport:
    advisory_sha256: str
    tenant_id: str
    baseline_report_sha256: str
    current_report_sha256: str
    baseline_snapshot_sha256: str
    current_snapshot_sha256: str
    reviewed_at: str
    transitions: tuple[AdvisoryTransition, ...]
    report_sha256: str = ""

    def __post_init__(self) -> None:
        _time(self.reviewed_at, "reviewed_at")
        try:
            _identifier(self.tenant_id, "tenant_id")
        except TrafficApiInventoryError as exc:
            raise AdvisoryTransitionError("tenant_id is invalid") from exc
        if type(self.transitions) is not tuple or any(
            type(item) is not AdvisoryTransition for item in self.transitions
        ):
            raise AdvisoryTransitionError("transitions must be typed")
        if self.transitions != tuple(
            sorted(self.transitions, key=lambda item: (item.asset_id, item.component_ref))
        ):
            raise AdvisoryTransitionError("transitions are not canonical")
        if len({(item.asset_id, item.component_ref) for item in self.transitions}) != len(
            self.transitions
        ):
            raise AdvisoryTransitionError("transition key is repeated")
        for value in (
            self.advisory_sha256,
            self.baseline_report_sha256,
            self.current_report_sha256,
            self.baseline_snapshot_sha256,
            self.current_snapshot_sha256,
        ):
            try:
                _digest(value, "transition lineage digest")
            except TrafficApiInventoryError as exc:
                raise AdvisoryTransitionError("transition lineage digest is invalid") from exc
        expected = _canonical_sha("sunderkey.advisory-transition-report.v1", self._payload())
        if self.report_sha256 and self.report_sha256 != expected:
            raise AdvisoryTransitionError("report_sha256 does not match content")
        object.__setattr__(self, "report_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "advisory_sha256": self.advisory_sha256,
            "tenant_id": self.tenant_id,
            "baseline_report_sha256": self.baseline_report_sha256,
            "current_report_sha256": self.current_report_sha256,
            "baseline_snapshot_sha256": self.baseline_snapshot_sha256,
            "current_snapshot_sha256": self.current_snapshot_sha256,
            "reviewed_at": self.reviewed_at,
            "transitions": [item.to_dict() for item in self.transitions],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "report_sha256": self.report_sha256}


def _candidate_map(
    report: AdvisoryApplicabilityReport,
) -> dict[tuple[str, str], AssetApplicabilityCandidate]:
    keys = [(item.asset_id, item.component_ref) for item in report.candidates]
    if len(set(keys)) != len(keys):
        raise AdvisoryTransitionError("applicability report repeats a candidate key")
    return dict(zip(keys, report.candidates, strict=True))


def _transition(before: str, after: str) -> TransitionState | None:
    match = ApplicabilityState.CANDIDATE_MATCH.value
    if after == match:
        return (
            TransitionState.CONTINUING_MATCH
            if before == match
            else TransitionState.NEW_OR_RETURNED_MATCH
        )
    if before == match:
        return (
            TransitionState.MATCH_NOT_REOBSERVED
            if after == ApplicabilityState.VERSION_NOT_LISTED.value
            else TransitionState.EVIDENCE_GAP
        )
    if before != after:
        return TransitionState.REVIEW_STATE_CHANGED
    return None


def compare_advisory_applicability(
    *,
    advisory: CuratedThreatAdvisory,
    baseline_report: AdvisoryApplicabilityReport,
    current_report: AdvisoryApplicabilityReport,
    baseline_snapshot: AssetReconciliationSnapshot,
    current_snapshot: AssetReconciliationSnapshot,
    reviewed_at: str,
) -> AdvisoryTransitionReport:
    """Describe changed candidate evidence, never infer a confirmed regression or fix."""
    for name, value, kind in (
        ("advisory", advisory, CuratedThreatAdvisory),
        ("baseline_report", baseline_report, AdvisoryApplicabilityReport),
        ("current_report", current_report, AdvisoryApplicabilityReport),
    ):
        if type(value) is not kind:
            raise AdvisoryTransitionError(f"{name} has the wrong type")
        try:
            replace(value)
        except AdvisoryApplicabilityError as exc:
            raise AdvisoryTransitionError(f"{name} integrity is invalid") from exc
    for name, value in (("baseline", baseline_snapshot), ("current", current_snapshot)):
        if type(value) is not AssetReconciliationSnapshot:
            raise AdvisoryTransitionError(f"{name} asset snapshot has the wrong type")
        try:
            AssetReconciliationSnapshot.from_dict(value.to_dict())
        except AssetReconciliationError as exc:
            raise AdvisoryTransitionError(f"{name} asset snapshot integrity is invalid") from exc
    if (
        baseline_report.advisory_sha256 != advisory.advisory_sha256
        or current_report.advisory_sha256 != advisory.advisory_sha256
        or baseline_report.asset_snapshot_sha256 != baseline_snapshot.snapshot_sha256
        or current_report.asset_snapshot_sha256 != current_snapshot.snapshot_sha256
    ):
        raise AdvisoryTransitionError("advisory or snapshot report lineage differs")
    if not (
        baseline_report.tenant_id
        == current_report.tenant_id
        == baseline_snapshot.tenant_id
        == current_snapshot.tenant_id
    ):
        raise AdvisoryTransitionError("tenant lineage differs")
    affected = {(item.component_ref, item.version) for item in advisory.affected_versions}
    advisory_components = {item.component_ref for item in advisory.affected_versions}
    for report, snapshot in (
        (baseline_report, baseline_snapshot),
        (current_report, current_snapshot),
    ):
        asset_ids = {item.asset_id for item in snapshot.assets}
        candidate_assets = {item.asset_id for item in report.candidates}
        gaps = set(report.missing_component_evidence_asset_ids)
        if candidate_assets & gaps or candidate_assets | gaps != asset_ids:
            raise AdvisoryTransitionError("applicability asset coverage differs from snapshot")
        if any(item.component_ref not in advisory_components for item in report.candidates):
            raise AdvisoryTransitionError("applicability component differs from advisory")
        for candidate in report.candidates:
            exact_match = any(
                (candidate.component_ref, version) in affected
                for version in candidate.observed_versions
            )
            if candidate.state is ApplicabilityState.CANDIDATE_MATCH and not exact_match:
                raise AdvisoryTransitionError("applicability state contradicts exact versions")
    if current_snapshot.prior_snapshot_sha256 != baseline_snapshot.snapshot_sha256:
        raise AdvisoryTransitionError("current asset snapshot is not a direct descendant")
    if not (
        _time(baseline_snapshot.as_of, "baseline snapshot")
        <= _time(baseline_report.as_of, "baseline report")
        < _time(current_snapshot.as_of, "current snapshot")
        <= _time(current_report.as_of, "current report")
        <= _time(reviewed_at, "reviewed_at")
    ):
        raise AdvisoryTransitionError("transition chronology is invalid")
    before = _candidate_map(baseline_report)
    after = _candidate_map(current_report)
    transitions: list[AdvisoryTransition] = []
    for asset_id, component_ref in sorted(before.keys() | after.keys()):
        baseline_state = (
            before[(asset_id, component_ref)].state.value
            if (asset_id, component_ref) in before
            else "missing_evidence"
        )
        current_state = (
            after[(asset_id, component_ref)].state.value
            if (asset_id, component_ref) in after
            else "missing_evidence"
        )
        transition = _transition(baseline_state, current_state)
        if transition is not None:
            transitions.append(
                AdvisoryTransition(
                    asset_id=asset_id,
                    component_ref=component_ref,
                    baseline_state=baseline_state,
                    current_state=current_state,
                    transition_state=transition,
                )
            )
    return AdvisoryTransitionReport(
        advisory_sha256=advisory.advisory_sha256,
        tenant_id=baseline_report.tenant_id,
        baseline_report_sha256=baseline_report.report_sha256,
        current_report_sha256=current_report.report_sha256,
        baseline_snapshot_sha256=baseline_snapshot.snapshot_sha256,
        current_snapshot_sha256=current_snapshot.snapshot_sha256,
        reviewed_at=reviewed_at,
        transitions=tuple(transitions),
    )


def verify_advisory_transition_report_from_sources(
    *,
    advisory: CuratedThreatAdvisory,
    baseline_report: AdvisoryApplicabilityReport,
    current_report: AdvisoryApplicabilityReport,
    baseline_snapshot: AssetReconciliationSnapshot,
    current_snapshot: AssetReconciliationSnapshot,
    baseline_components: tuple[InstalledComponentObservation, ...],
    current_components: tuple[InstalledComponentObservation, ...],
    transition_report: AdvisoryTransitionReport,
) -> AdvisoryTransitionReport:
    """Recompute both applicability reports and their transition from supplied sources."""

    if type(transition_report) is not AdvisoryTransitionReport:
        raise AdvisoryTransitionError("transition report has the wrong type")
    if type(baseline_report) is not AdvisoryApplicabilityReport or type(
        current_report
    ) is not AdvisoryApplicabilityReport:
        raise AdvisoryTransitionError("applicability report has the wrong type")
    replace(transition_report)
    try:
        expected_baseline = verify_advisory_applicability_report_from_sources(
            advisory=advisory,
            asset_snapshot=baseline_snapshot,
            components=baseline_components,
            report=baseline_report,
        )
        expected_current = verify_advisory_applicability_report_from_sources(
            advisory=advisory,
            asset_snapshot=current_snapshot,
            components=current_components,
            report=current_report,
        )
    except AdvisoryApplicabilityError as exc:
        raise AdvisoryTransitionError("applicability source replay failed") from exc
    expected_transition = compare_advisory_applicability(
        advisory=advisory,
        baseline_report=expected_baseline,
        current_report=expected_current,
        baseline_snapshot=baseline_snapshot,
        current_snapshot=current_snapshot,
        reviewed_at=transition_report.reviewed_at,
    )
    if expected_transition != transition_report:
        raise AdvisoryTransitionError("transition report does not match source replay")
    return transition_report
