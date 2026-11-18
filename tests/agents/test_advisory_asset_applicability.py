"""Exact advisory-to-asset correlation without exposure claims or effects."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.advisory_asset_applicability import (
    AdvisoryApplicabilityError,
    AffectedComponentVersion,
    ApplicabilityState,
    AssetApplicabilityCandidate,
    CuratedThreatAdvisory,
    InstalledComponentObservation,
    correlate_advisory_assets,
    verify_advisory_applicability_report_from_sources,
)
from sunderkey.asset_reconciliation import (
    AssetIdentifier,
    AssetObservation,
    reconcile_asset_observations,
)

SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64
AT = "2026-09-23T13:00:00Z"


def snapshot():
    observation = AssetObservation(
        tenant_id="tenant:one", source_kind="cmdb", source_system="cmdb_source",
        source_record_id="ci:one", observed_at="2026-09-23T11:00:00Z",
        expires_at="2026-09-24T12:00:00Z", confidence_bps=9000,
        provenance_sha256=SHA,
        identifiers=(AssetIdentifier("cmdb_ci_id", "cmdb_source", "ci:one"),),
    )
    return reconcile_asset_observations(
        "tenant:one", "2026-09-23T12:30:00Z", (observation,),
    )


def advisory():
    return CuratedThreatAdvisory(
        advisory_id="advisory:one", source_id="curated:feed",
        source_sha256=SHA, published_at="2026-09-23T12:00:00Z",
        affected_versions=(AffectedComponentVersion("example:library", "1.2.3"),),
    )


def component(asset_id, *, version="1.2.3", tenant="tenant:one",
              expires_at="2026-09-24T10:00:00Z", source_id="sbom:one"):
    return InstalledComponentObservation(
        tenant_id=tenant, asset_id=asset_id,
        component_ref="example:library", version=version,
        source_id=source_id, source_sha256=OTHER_SHA,
        observed_at="2026-09-23T12:15:00Z", expires_at=expires_at,
    )


def report(items=(), *, at=AT, asset_snapshot=None):
    return correlate_advisory_assets(
        advisory=advisory(), asset_snapshot=asset_snapshot or snapshot(),
        components=tuple(items), as_of=at,
    )


class AdvisoryAssetApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()
        self.asset_id = self.snapshot.assets[0].asset_id

    def test_exact_match_is_only_candidate_not_exploitability_or_authority(self):
        output = report((component(self.asset_id),), asset_snapshot=self.snapshot)
        self.assertEqual(output.candidates[0].state, ApplicabilityState.CANDIDATE_MATCH)
        self.assertEqual(output.candidates[0].observed_versions, ("1.2.3",))
        self.assertEqual(output.advisory_sha256, advisory().advisory_sha256)
        self.assertEqual(output.asset_snapshot_sha256, self.snapshot.snapshot_sha256)
        self.assertEqual(output.to_dict()["effects"]["authority"], "none")
        self.assertEqual(output.to_dict()["effects"]["execution"], "none")
        self.assertEqual(output.missing_component_evidence_asset_ids, ())

    def test_version_not_listed_never_becomes_unaffected_proof(self):
        output = report((component(self.asset_id, version="1.2.4"),))
        self.assertEqual(output.candidates[0].state, ApplicabilityState.VERSION_NOT_LISTED)
        self.assertNotIn("not_affected", output.to_dict()["candidates"][0]["state"])

    def test_stale_and_missing_component_evidence_are_explicit(self):
        stale = report((component(self.asset_id, expires_at="2026-09-23T12:30:00Z"),))
        self.assertEqual(stale.candidates[0].state, ApplicabilityState.STALE_EVIDENCE)
        missing = report(())
        self.assertEqual(missing.candidates, ())
        self.assertEqual(missing.missing_component_evidence_asset_ids, (self.asset_id,))

    def test_asset_evidence_expiry_overrides_component_match(self):
        output = report(
            (component(self.asset_id, expires_at="2026-09-25T12:00:00Z"),),
            at="2026-09-24T13:00:00Z",
        )
        self.assertEqual(output.candidates[0].state, ApplicabilityState.ASSET_UNCERTAIN)

    def test_cross_tenant_unknown_asset_future_and_old_snapshot_fail(self):
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "outside snapshot"):
            report((component(self.asset_id, tenant="tenant:two"),))
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "outside snapshot"):
            report((component("AST-" + "F" * 32),))
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "follows asset snapshot"):
            report((replace(component(self.asset_id), observed_at="2026-09-23T12:45:00Z",
                            observation_sha256=""),))
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "too old"):
            report((), at="2026-10-01T13:00:00Z")

    def test_source_conflict_and_content_tampering_fail(self):
        first = component(self.asset_id)
        second = component(self.asset_id, version="1.2.4")
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "source ID conflicts"):
            report((first, second))
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "observation_sha256"):
            replace(first, version="1.2.4")
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "report_sha256"):
            replace(report((first,)), as_of="2026-09-23T13:05:00Z")

    def test_advisory_version_list_is_exact_and_bounded(self):
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "canonical"):
            replace(advisory(), affected_versions=(
                AffectedComponentVersion("example:library", "1.2.3"),
                AffectedComponentVersion("example:library", "1.2.3"),
            ), advisory_sha256="")
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "exact canonical"):
            AffectedComponentVersion("example:library", ">=1.2.3")

    def test_nested_affected_version_subclass_cannot_reuse_advisory_pin(self):
        class MisleadingVersion(AffectedComponentVersion):
            def to_dict(self):
                return AffectedComponentVersion("example:library", "1.2.3").to_dict()

        trusted = advisory()
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "canonical"):
            replace(
                trusted,
                affected_versions=(MisleadingVersion("example:library", "9.9.9"),),
            )

    def test_nested_candidate_subclass_cannot_reuse_report_pin(self):
        class MisleadingCandidate(AssetApplicabilityCandidate):
            def to_dict(self):
                return expected_candidate.to_dict()

            def __eq__(self, other):
                return True

        output = report((component(self.asset_id),), asset_snapshot=self.snapshot)
        expected_candidate = output.candidates[0]
        forged_candidate = MisleadingCandidate(
            expected_candidate.asset_id,
            expected_candidate.component_ref,
            expected_candidate.observed_versions,
            expected_candidate.observation_sha256,
            ApplicabilityState.VERSION_NOT_LISTED,
        )
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "candidates"):
            replace(output, candidates=(forged_candidate,))

    def test_stored_report_requires_exact_source_replay(self):
        observation = component(self.asset_id)
        output = report((observation,), asset_snapshot=self.snapshot)
        self.assertEqual(
            verify_advisory_applicability_report_from_sources(
                advisory=advisory(),
                asset_snapshot=self.snapshot,
                components=(observation,),
                report=output,
            ),
            output,
        )
        forged_candidate = replace(
            output.candidates[0], state=ApplicabilityState.VERSION_NOT_LISTED
        )
        forged = replace(output, candidates=(forged_candidate,), report_sha256="")
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "source replay"):
            verify_advisory_applicability_report_from_sources(
                advisory=advisory(),
                asset_snapshot=self.snapshot,
                components=(observation,),
                report=forged,
            )
        with self.assertRaisesRegex(AdvisoryApplicabilityError, "source replay"):
            verify_advisory_applicability_report_from_sources(
                advisory=advisory(),
                asset_snapshot=self.snapshot,
                components=(),
                report=output,
            )


if __name__ == "__main__":
    unittest.main()
