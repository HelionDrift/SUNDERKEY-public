"""Closed advisory transition replay from pinned raw source evidence."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.advisory_asset_applicability import (
    AffectedComponentVersion,
    CuratedThreatAdvisory,
    InstalledComponentObservation,
    correlate_advisory_assets,
)
from sunderkey.advisory_transition_review import compare_advisory_applicability
from sunderkey.asset_reconciliation import (
    AssetIdentifier,
    AssetObservation,
    reconcile_asset_observations,
)
from sunderkey.offline_advisory_source_chain import (
    AdvisorySourceChainError,
    AssetSnapshotSources,
    asset_observation_set_sha256,
    component_observation_set_sha256,
    verify_advisory_source_chain,
)

SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64


def observation(day: int, *, confidence: int = 9000) -> AssetObservation:
    return AssetObservation(
        tenant_id="tenant:one",
        source_kind="cmdb",
        source_system="cmdb_source",
        source_record_id="ci:one",
        observed_at=f"2026-09-{day}T11:00:00Z",
        expires_at=f"2026-09-{day + 1}T16:00:00Z",
        confidence_bps=confidence,
        provenance_sha256=SHA,
        identifiers=(AssetIdentifier("cmdb_ci_id", "cmdb_source", "ci:one"),),
    )


def component(asset_id: str, day: int, version: str) -> InstalledComponentObservation:
    return InstalledComponentObservation(
        tenant_id="tenant:one",
        asset_id=asset_id,
        component_ref="example:library",
        version=version,
        source_id=f"sbom:day-{day}",
        source_sha256=OTHER_SHA,
        observed_at=f"2026-09-{day}T12:15:00Z",
        expires_at=f"2026-09-{day + 1}T16:00:00Z",
    )


class AdvisorySourceChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.advisory = CuratedThreatAdvisory(
            advisory_id="advisory:one",
            source_id="curated:feed",
            source_sha256=SHA,
            published_at="2026-09-22T12:00:00Z",
            affected_versions=(AffectedComponentVersion("example:library", "1.2.3"),),
        )
        prior_observations = (observation(22),)
        prior_snapshot = reconcile_asset_observations(
            "tenant:one", "2026-09-22T12:30:00Z", prior_observations,
        )
        baseline_observations = (observation(23),)
        baseline_snapshot = reconcile_asset_observations(
            "tenant:one", "2026-09-23T12:30:00Z", baseline_observations,
            prior_snapshot=prior_snapshot,
        )
        self.current_observations = (observation(24),)
        self.current_snapshot = reconcile_asset_observations(
            "tenant:one", "2026-09-24T12:30:00Z", self.current_observations,
            prior_snapshot=baseline_snapshot,
        )
        self.baseline_source = AssetSnapshotSources(
            snapshot=baseline_snapshot,
            observations=baseline_observations,
            expected_observations_sha256=asset_observation_set_sha256(baseline_observations),
            prior=AssetSnapshotSources(
                snapshot=prior_snapshot,
                observations=prior_observations,
                expected_observations_sha256=asset_observation_set_sha256(prior_observations),
            ),
        )
        asset_id = baseline_snapshot.assets[0].asset_id
        self.baseline_components = (component(asset_id, 23, "1.2.4"),)
        self.current_components = (component(asset_id, 24, "1.2.3"),)
        self.baseline_report = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=baseline_snapshot,
            components=self.baseline_components,
            as_of="2026-09-23T13:00:00Z",
        )
        self.current_report = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=self.current_snapshot,
            components=self.current_components,
            as_of="2026-09-24T13:00:00Z",
        )
        self.transition_report = compare_advisory_applicability(
            advisory=self.advisory,
            baseline_report=self.baseline_report,
            current_report=self.current_report,
            baseline_snapshot=baseline_snapshot,
            current_snapshot=self.current_snapshot,
            reviewed_at="2026-09-24T13:05:00Z",
        )

    def inputs(self) -> dict:
        return {
            "advisory": self.advisory,
            "expected_advisory_sha256": self.advisory.advisory_sha256,
            "baseline_source": self.baseline_source,
            "expected_baseline_snapshot_sha256": self.baseline_source.snapshot.snapshot_sha256,
            "current_snapshot": self.current_snapshot,
            "expected_current_snapshot_sha256": self.current_snapshot.snapshot_sha256,
            "current_observations": self.current_observations,
            "expected_current_observations_sha256": asset_observation_set_sha256(
                self.current_observations
            ),
            "baseline_components": self.baseline_components,
            "expected_baseline_components_sha256": component_observation_set_sha256(
                self.baseline_components
            ),
            "current_components": self.current_components,
            "expected_current_components_sha256": component_observation_set_sha256(
                self.current_components
            ),
            "baseline_report": self.baseline_report,
            "current_report": self.current_report,
            "transition_report": self.transition_report,
        }

    def test_complete_ancestry_and_reports_replay(self) -> None:
        self.assertEqual(
            verify_advisory_source_chain(**self.inputs()), self.transition_report,
        )

    def test_missing_or_substituted_raw_asset_evidence_fails(self) -> None:
        inputs = self.inputs()
        with self.assertRaisesRegex(AdvisorySourceChainError, "nonempty"):
            verify_advisory_source_chain(**{**inputs, "current_observations": ()})
        alternate_raw = (observation(24, confidence=8000),)
        alternate_snapshot = reconcile_asset_observations(
            "tenant:one", "2026-09-24T12:30:00Z", alternate_raw,
            prior_snapshot=self.baseline_source.snapshot,
        )
        alternate_report = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=alternate_snapshot,
            components=self.current_components,
            as_of=self.current_report.as_of,
        )
        alternate_transition = compare_advisory_applicability(
            advisory=self.advisory,
            baseline_report=self.baseline_report,
            current_report=alternate_report,
            baseline_snapshot=self.baseline_source.snapshot,
            current_snapshot=alternate_snapshot,
            reviewed_at=self.transition_report.reviewed_at,
        )
        with self.assertRaisesRegex(AdvisorySourceChainError, "raw observation pin"):
            verify_advisory_source_chain(**{
                **inputs, "current_observations": alternate_raw,
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "current snapshot pin"):
            verify_advisory_source_chain(**{
                **inputs,
                "current_observations": alternate_raw,
                "current_snapshot": alternate_snapshot,
                "current_report": alternate_report,
                "transition_report": alternate_transition,
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "raw observation pin"):
            verify_advisory_source_chain(**{
                **inputs,
                "baseline_source": replace(
                    self.baseline_source, observations=(observation(23, confidence=8000),),
                ),
            })

    def test_prior_source_and_lineage_changes_fail(self) -> None:
        inputs = self.inputs()
        with self.assertRaisesRegex(AdvisorySourceChainError, "source replay"):
            verify_advisory_source_chain(**{
                **inputs,
                "baseline_source": replace(self.baseline_source, prior=None),
            })
        unlinked = reconcile_asset_observations(
            "tenant:one", self.current_snapshot.as_of, self.current_observations,
        )
        with self.assertRaisesRegex(AdvisorySourceChainError, "current snapshot pin"):
            verify_advisory_source_chain(**{**inputs, "current_snapshot": unlinked})

    def test_coherent_alternate_prior_and_reports_cannot_replace_pinned_lineage(self) -> None:
        alternate_prior_raw = (observation(22, confidence=8000),)
        alternate_prior = reconcile_asset_observations(
            "tenant:one", "2026-09-22T12:30:00Z", alternate_prior_raw,
        )
        alternate_baseline = reconcile_asset_observations(
            "tenant:one", "2026-09-23T12:30:00Z", self.baseline_source.observations,
            prior_snapshot=alternate_prior,
        )
        alternate_current = reconcile_asset_observations(
            "tenant:one", "2026-09-24T12:30:00Z", self.current_observations,
            prior_snapshot=alternate_baseline,
        )
        alternate_baseline_report = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=alternate_baseline,
            components=self.baseline_components,
            as_of=self.baseline_report.as_of,
        )
        alternate_current_report = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=alternate_current,
            components=self.current_components,
            as_of=self.current_report.as_of,
        )
        alternate_transition = compare_advisory_applicability(
            advisory=self.advisory,
            baseline_report=alternate_baseline_report,
            current_report=alternate_current_report,
            baseline_snapshot=alternate_baseline,
            current_snapshot=alternate_current,
            reviewed_at=self.transition_report.reviewed_at,
        )
        alternate_source = AssetSnapshotSources(
            snapshot=alternate_baseline,
            observations=self.baseline_source.observations,
            expected_observations_sha256=self.baseline_source.expected_observations_sha256,
            prior=AssetSnapshotSources(
                snapshot=alternate_prior,
                observations=alternate_prior_raw,
                expected_observations_sha256=asset_observation_set_sha256(
                    alternate_prior_raw
                ),
            ),
        )
        with self.assertRaisesRegex(AdvisorySourceChainError, "baseline snapshot pin"):
            verify_advisory_source_chain(**{
                **self.inputs(),
                "baseline_source": alternate_source,
                "current_snapshot": alternate_current,
                "current_report": alternate_current_report,
                "baseline_report": alternate_baseline_report,
                "transition_report": alternate_transition,
            })

    def test_component_evidence_substitution_and_type_mutation_fail(self) -> None:
        inputs = self.inputs()
        with self.assertRaisesRegex(AdvisorySourceChainError, "component raw observation pin"):
            verify_advisory_source_chain(**{
                **inputs,
                "current_components": (component(
                    self.current_snapshot.assets[0].asset_id, 24, "1.2.4"
                ),),
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "must remain typed"):
            verify_advisory_source_chain(**{
                **inputs, "current_observations": (self.current_observations[0].to_dict(),),
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "wrong type"):
            verify_advisory_source_chain(**{
                **inputs, "baseline_source": self.baseline_source.snapshot,
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "advisory source pin"):
            verify_advisory_source_chain(**{
                **inputs, "expected_advisory_sha256": OTHER_SHA,
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "canonical digest"):
            verify_advisory_source_chain(**{
                **inputs, "expected_advisory_sha256": "sha256:not-a-digest",
            })
        with self.assertRaisesRegex(AdvisorySourceChainError, "wrong type"):
            verify_advisory_source_chain(**{
                **inputs, "current_report": self.current_report.to_dict(),
            })


if __name__ == "__main__":
    unittest.main()
