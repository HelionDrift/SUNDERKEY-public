"""Advisory candidate transitions across direct asset snapshot descendants."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.advisory_asset_applicability import (
    AffectedComponentVersion,
    ApplicabilityState,
    CuratedThreatAdvisory,
    InstalledComponentObservation,
    correlate_advisory_assets,
)
from sunderkey.advisory_transition_review import (
    AdvisoryTransition,
    AdvisoryTransitionError,
    TransitionState,
    compare_advisory_applicability,
    verify_advisory_transition_report_from_sources,
)
from sunderkey.asset_reconciliation import (
    AssetIdentifier,
    AssetObservation,
    reconcile_asset_observations,
)

SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64


def asset_observation(day):
    return AssetObservation(
        tenant_id="tenant:one",
        source_kind="cmdb",
        source_system="cmdb_source",
        source_record_id="ci:one",
        observed_at=f"2026-09-{day}T11:00:00Z",
        expires_at=f"2026-09-{day + 1}T16:00:00Z",
        confidence_bps=9000,
        provenance_sha256=SHA,
        identifiers=(AssetIdentifier("cmdb_ci_id", "cmdb_source", "ci:one"),),
    )


def advisory():
    return CuratedThreatAdvisory(
        advisory_id="advisory:one",
        source_id="curated:feed",
        source_sha256=SHA,
        published_at="2026-09-23T12:00:00Z",
        affected_versions=(AffectedComponentVersion("example:library", "1.2.3"),),
    )


def component(asset_id, day, version):
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


class AdvisoryTransitionReviewTests(unittest.TestCase):
    def setUp(self):
        self.advisory = advisory()
        self.baseline_snapshot = reconcile_asset_observations(
            "tenant:one",
            "2026-09-23T12:30:00Z",
            (asset_observation(23),),
        )
        self.current_snapshot = reconcile_asset_observations(
            "tenant:one",
            "2026-09-24T12:30:00Z",
            (asset_observation(24),),
            prior_snapshot=self.baseline_snapshot,
        )
        self.asset_id = self.baseline_snapshot.assets[0].asset_id

    def reports(self, before_version=None, after_version=None):
        baseline = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=self.baseline_snapshot,
            components=((component(self.asset_id, 23, before_version),) if before_version else ()),
            as_of="2026-09-23T13:00:00Z",
        )
        current = correlate_advisory_assets(
            advisory=self.advisory,
            asset_snapshot=self.current_snapshot,
            components=((component(self.asset_id, 24, after_version),) if after_version else ()),
            as_of="2026-09-24T13:00:00Z",
        )
        return baseline, current

    def compare(self, before_version=None, after_version=None, **changes):
        baseline, current = self.reports(before_version, after_version)
        inputs = {
            "advisory": self.advisory,
            "baseline_report": baseline,
            "current_report": current,
            "baseline_snapshot": self.baseline_snapshot,
            "current_snapshot": self.current_snapshot,
            "reviewed_at": "2026-09-24T13:05:00Z",
        }
        inputs.update(changes)
        return compare_advisory_applicability(**inputs)

    def test_new_or_returned_match_is_not_claimed_as_confirmed_regression(self):
        output = self.compare("1.2.4", "1.2.3")
        self.assertEqual(
            output.transitions[0].transition_state,
            TransitionState.NEW_OR_RETURNED_MATCH,
        )
        self.assertEqual(output.to_dict()["effects"]["remediation_confirmation"], "none")
        self.assertEqual(output.to_dict()["effects"]["authority"], "none")

    def test_nested_transition_subclass_cannot_reuse_report_pin(self):
        output = self.compare("1.2.4", "1.2.3")
        expected_transition = output.transitions[0]

        class MisleadingTransition(AdvisoryTransition):
            def to_dict(self):
                return expected_transition.to_dict()

            def __eq__(self, other):
                return True

        forged_transition = MisleadingTransition(
            expected_transition.asset_id,
            expected_transition.component_ref,
            expected_transition.baseline_state,
            ApplicabilityState.ASSET_UNCERTAIN.value,
            TransitionState.REVIEW_STATE_CHANGED,
        )
        with self.assertRaisesRegex(AdvisoryTransitionError, "typed"):
            replace(output, transitions=(forged_transition,))

    def test_match_not_reobserved_is_not_remediation_proof(self):
        output = self.compare("1.2.3", "1.2.4")
        self.assertEqual(
            output.transitions[0].transition_state,
            TransitionState.MATCH_NOT_REOBSERVED,
        )
        self.assertEqual(output.transitions[0].current_state, "version_not_listed")

    def test_missing_current_evidence_is_an_explicit_gap(self):
        output = self.compare("1.2.3", None)
        self.assertEqual(output.transitions[0].transition_state, TransitionState.EVIDENCE_GAP)
        self.assertEqual(output.transitions[0].current_state, "missing_evidence")

    def test_continuing_match_and_no_observed_change(self):
        self.assertEqual(
            self.compare("1.2.3", "1.2.3").transitions[0].transition_state,
            TransitionState.CONTINUING_MATCH,
        )
        self.assertEqual(self.compare("1.2.4", "1.2.4").transitions, ())

    def test_lineage_time_and_content_tampering_fail_closed(self):
        baseline, current = self.reports("1.2.3", "1.2.4")
        with self.assertRaisesRegex(AdvisoryTransitionError, "direct descendant"):
            self.compare(
                "1.2.3",
                "1.2.4",
                current_snapshot=self.baseline_snapshot,
                current_report=baseline,
            )
        with self.assertRaisesRegex(AdvisoryTransitionError, "chronology"):
            self.compare("1.2.3", "1.2.4", reviewed_at="2026-09-23T13:05:00Z")
        with self.assertRaisesRegex(AdvisoryTransitionError, "lineage"):
            self.compare(
                "1.2.3",
                "1.2.4",
                current_report=replace(
                    current,
                    asset_snapshot_sha256=baseline.asset_snapshot_sha256,
                    report_sha256="",
                ),
            )
        with self.assertRaisesRegex(AdvisoryTransitionError, "asset coverage"):
            self.compare(
                "1.2.3",
                "1.2.4",
                current_report=replace(
                    current,
                    candidates=(),
                    report_sha256="",
                ),
            )
        with self.assertRaisesRegex(AdvisoryTransitionError, "report_sha256"):
            replace(self.compare("1.2.3", "1.2.4"), reviewed_at="2026-09-24T13:06:00Z")

    def test_source_replay_rejects_self_hashed_false_negative_and_transition(self):
        baseline, current = self.reports("1.2.4", "1.2.3")
        baseline_components = (component(self.asset_id, 23, "1.2.4"),)
        current_components = (component(self.asset_id, 24, "1.2.3"),)
        transition = compare_advisory_applicability(
            advisory=self.advisory,
            baseline_report=baseline,
            current_report=current,
            baseline_snapshot=self.baseline_snapshot,
            current_snapshot=self.current_snapshot,
            reviewed_at="2026-09-24T13:05:00Z",
        )
        source = {
            "advisory": self.advisory,
            "baseline_report": baseline,
            "current_report": current,
            "baseline_snapshot": self.baseline_snapshot,
            "current_snapshot": self.current_snapshot,
            "baseline_components": baseline_components,
            "current_components": current_components,
        }
        self.assertEqual(
            verify_advisory_transition_report_from_sources(**source, transition_report=transition),
            transition,
        )
        forged_candidate = replace(
            current.candidates[0], state=ApplicabilityState.VERSION_NOT_LISTED
        )
        forged_current = replace(current, candidates=(forged_candidate,), report_sha256="")
        forged_transition = compare_advisory_applicability(
            advisory=self.advisory,
            baseline_report=baseline,
            current_report=forged_current,
            baseline_snapshot=self.baseline_snapshot,
            current_snapshot=self.current_snapshot,
            reviewed_at=transition.reviewed_at,
        )
        self.assertFalse(forged_transition.transitions)
        with self.assertRaisesRegex(AdvisoryTransitionError, "source replay"):
            verify_advisory_transition_report_from_sources(
                **{**source, "current_report": forged_current},
                transition_report=forged_transition,
            )
        forged_transition = replace(transition, transitions=(), report_sha256="")
        with self.assertRaisesRegex(AdvisoryTransitionError, "transition report"):
            verify_advisory_transition_report_from_sources(
                **source, transition_report=forged_transition
            )


if __name__ == "__main__":
    unittest.main()
