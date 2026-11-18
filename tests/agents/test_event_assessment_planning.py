"""Offline event assessment planning and fail-closed boundary tests."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.api_release_delta_review import ApiReleaseDelta
from sunderkey.event_assessment_planning import (
    NO_EFFECTS,
    AssessmentCandidate,
    CandidateDisposition,
    EventAssessmentError,
    event_from_evidence,
    plan_event_assessments,
    verify_assessment_candidate_batch,
)
from sunderkey.surface_drift_detection import (
    SurfaceObservation,
    assess_surface_drift,
    build_surface_snapshot,
)

SCOPE = "sha256:" + "a" * 64
OTHER_SCOPE = "sha256:" + "b" * 64
SHA = "sha256:" + "c" * 64
AT = "2026-09-23T13:30:00Z"


def release_delta(*, release_id: str = "release:17", changed: bool = True) -> ApiReleaseDelta:
    return ApiReleaseDelta(
        release_id=release_id,
        release_artifact_sha256=SHA,
        release_at="2026-09-23T12:00:00Z",
        tenant_id="tenant:one",
        context_id="context:one",
        context_sha256=SHA,
        scope_id="scope:one",
        scope_sha256=SCOPE,
        baseline_inventory_sha256=SHA,
        current_inventory_sha256=OTHER_SCOPE,
        contract_bundle_changed=False,
        new_endpoints=("GET https://api.example.test/new",) if changed else (),
        not_reobserved_endpoints=(),
        expanded_roles=(),
        new_status_codes=(),
        changed_contract_mappings=(),
        review_reasons=("new_endpoint_observed",)
        if changed
        else ("no_difference_observed_without_coverage_proof",),
        gate_status="review_required" if changed else "inconclusive",
        delta_sha256="",
    )


def drift_assessment():
    observation = SurfaceObservation(
        surface_id="endpoint:one",
        surface_kind="endpoint",
        content_sha256=SHA,
        provenance_sha256=OTHER_SCOPE,
        observed_at="2026-09-23T12:05:00Z",
        freshness_expires_at="2026-09-24T12:05:00Z",
        observation_state="verified",
        scope_binding_sha256=SCOPE,
        technique_ids=("technique:http",),
        profile_ids=("profile:web",),
        commander_ids=("commander:application",),
        risk_score=40,
    )
    baseline = build_surface_snapshot(
        (),
        captured_at="2026-09-23T12:00:00Z",
        scope_binding_sha256=SCOPE,
    )
    current = build_surface_snapshot(
        (observation,),
        captured_at="2026-09-23T12:10:00Z",
        scope_binding_sha256=SCOPE,
        parent=baseline,
    )
    return assess_surface_drift(baseline, current, assessed_at="2026-09-23T12:15:00Z")


def event(
    release_id: str = "release:17",
    *,
    changed: bool = True,
    observed_at: str = "2026-09-23T12:10:00Z",
):
    return event_from_evidence(
        release_delta(release_id=release_id, changed=changed),
        observed_at=observed_at,
    )


def plan(events, **changes):
    inputs = {"events": tuple(events), "scope_sha256": SCOPE, "as_of": AT}
    inputs.update(changes)
    return plan_event_assessments(**inputs)


class EventAssessmentPlanningTests(unittest.TestCase):
    def test_release_and_drift_events_preserve_evidence_lineage_without_effects(self):
        release = event()
        drift = event_from_evidence(drift_assessment())
        self.assertTrue(release.change_signal)
        self.assertEqual(release.evidence_sha256, release_delta().delta_sha256)
        self.assertEqual(drift.reason_codes, ("drift_added",))
        self.assertEqual(drift.scope_sha256, SCOPE)
        result = plan((release, drift), cooldown_seconds=1)
        self.assertEqual(len(result.candidates), 2)
        self.assertEqual(result.to_dict()["effects"]["authority"], "none")
        self.assertEqual(result.to_dict()["effects"]["scheduler"], "none")
        self.assertEqual(result.to_dict()["effects"]["execution"], "none")
        self.assertEqual(
            [item.event.event_sha256 for item in result.candidates],
            sorted(item.event.event_sha256 for item in result.candidates),
        )

    def test_no_change_is_not_a_review_candidate(self):
        result = plan((event(changed=False),))
        self.assertEqual(result.candidates[0].disposition, CandidateDisposition.NO_CHANGE_SIGNAL)

    def test_repeated_event_is_deduplicated_in_batch_and_against_prior(self):
        first = event()
        batch = plan((first, first))
        self.assertEqual(
            {item.disposition for item in batch.candidates},
            {CandidateDisposition.REVIEW_CANDIDATE, CandidateDisposition.DUPLICATE},
        )
        prior = (AssessmentCandidate(first, CandidateDisposition.REVIEW_CANDIDATE, AT),)
        self.assertEqual(
            plan((first,), prior_candidates=prior).candidates[0].disposition,
            CandidateDisposition.DUPLICATE,
        )

    def test_suppressed_event_can_be_reviewed_after_condition_clears(self):
        first = event()
        stopped = AssessmentCandidate(first, CandidateDisposition.STOPPED, AT)
        resumed = plan(
            (first,),
            prior_candidates=(stopped,),
            as_of="2026-09-23T14:30:00Z",
        )
        self.assertEqual(
            resumed.candidates[0].disposition,
            CandidateDisposition.REVIEW_CANDIDATE,
        )

        earlier_review = AssessmentCandidate(
            event("release:old"),
            CandidateDisposition.REVIEW_CANDIDATE,
            "2026-09-23T12:30:00Z",
        )
        cooldown = plan(
            (first,),
            prior_candidates=(earlier_review,),
            cooldown_seconds=7200,
        ).candidates[0]
        self.assertEqual(cooldown.disposition, CandidateDisposition.COOLDOWN)
        after_cooldown = plan(
            (first,),
            prior_candidates=(earlier_review, cooldown),
            cooldown_seconds=7200,
            as_of="2026-09-23T16:00:00Z",
        )
        self.assertEqual(
            after_cooldown.candidates[0].disposition,
            CandidateDisposition.REVIEW_CANDIDATE,
        )
        self.assertEqual(
            verify_assessment_candidate_batch(
                after_cooldown,
                events=(first,),
                prior_candidates=(earlier_review, cooldown),
            ),
            after_cooldown,
        )
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(
                after_cooldown,
                events=(first,),
                prior_candidates=(earlier_review,),
            )

        budget = plan(
            (first,),
            prior_candidates=(earlier_review,),
            cooldown_seconds=60,
            daily_candidate_budget=1,
        ).candidates[0]
        self.assertEqual(budget.disposition, CandidateDisposition.BUDGET)
        next_day = plan(
            (first,),
            prior_candidates=(earlier_review, budget),
            as_of="2026-09-24T13:00:00Z",
            max_event_age_seconds=172800,
            cooldown_seconds=60,
            daily_candidate_budget=1,
        )
        self.assertEqual(
            next_day.candidates[0].disposition,
            CandidateDisposition.REVIEW_CANDIDATE,
        )
        self.assertEqual(
            plan(
                (first,),
                prior_candidates=(next_day.candidates[0],),
                as_of="2026-09-24T13:01:00Z",
                max_event_age_seconds=172800,
            )
            .candidates[0]
            .disposition,
            CandidateDisposition.DUPLICATE,
        )

    def test_cooldown_and_daily_budget_are_separate(self):
        prior = (
            AssessmentCandidate(
                event("release:old"),
                CandidateDisposition.REVIEW_CANDIDATE,
                "2026-09-23T12:30:00Z",
            ),
        )
        self.assertEqual(
            plan((event(),), prior_candidates=prior, cooldown_seconds=7200)
            .candidates[0]
            .disposition,
            CandidateDisposition.COOLDOWN,
        )
        self.assertEqual(
            plan((event(),), prior_candidates=prior, cooldown_seconds=60, daily_candidate_budget=1)
            .candidates[0]
            .disposition,
            CandidateDisposition.BUDGET,
        )

    def test_stop_and_stale_are_explicit(self):
        self.assertEqual(
            plan((event(),), intake_stopped=True).candidates[0].disposition,
            CandidateDisposition.STOPPED,
        )
        self.assertEqual(
            plan((event(),), max_event_age_seconds=60).candidates[0].disposition,
            CandidateDisposition.STALE,
        )

    def test_scope_time_and_integrity_conflicts_fail_closed(self):
        with self.assertRaisesRegex(EventAssessmentError, "scope differs"):
            plan((event(),), scope_sha256=OTHER_SCOPE)
        with self.assertRaisesRegex(EventAssessmentError, "future"):
            plan((event(),), as_of="2026-09-23T12:00:00Z")
        evolving_release = plan((event(), event(changed=False)), cooldown_seconds=1)
        self.assertEqual(len(evolving_release.candidates), 2)
        with self.assertRaisesRegex(EventAssessmentError, "event_sha256"):
            replace(event(), source_id="release:tampered")
        with self.assertRaisesRegex(EventAssessmentError, "post-release"):
            event_from_evidence(release_delta(), observed_at="2026-09-23T11:59:00Z")

    def test_bounds_and_batch_digest_fail_closed(self):
        with self.assertRaisesRegex(EventAssessmentError, "hard limit"):
            plan((event(),), daily_candidate_budget=65)
        with self.assertRaisesRegex(EventAssessmentError, "bounded"):
            plan((event(),) * 257)
        with self.assertRaisesRegex(EventAssessmentError, "batch_sha256"):
            replace(plan((event(),)), intake_stopped=True)

    def test_serialized_effects_do_not_mutate_shared_no_effects_contract(self):
        batch = plan((event(),))
        serialized = batch.to_dict()
        serialized["effects"]["authority"] = "granted"
        self.assertEqual(batch.to_dict()["effects"]["authority"], "none")
        self.assertEqual(plan((event(),)).to_dict()["effects"]["authority"], "none")
        with self.assertRaises(TypeError):
            NO_EFFECTS["authority"] = "granted"

    def test_stored_batch_requires_exact_source_replay(self):
        first = event()
        second = event("release:18")
        original = plan((first, second), cooldown_seconds=1)
        self.assertEqual(
            verify_assessment_candidate_batch(original, events=(first, second)),
            original,
        )
        self.assertEqual(
            verify_assessment_candidate_batch(original, events=(second, first)),
            original,
        )
        omitted = plan((first,), cooldown_seconds=1)
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(omitted, events=(first, second))
        stopped = plan((first,), intake_stopped=True)
        forged = replace(
            stopped,
            candidates=(AssessmentCandidate(first, CandidateDisposition.REVIEW_CANDIDATE, AT),),
            batch_sha256="",
        )
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(forged, events=(first,))
        prior = (
            AssessmentCandidate(event("release:old"), CandidateDisposition.REVIEW_CANDIDATE, AT),
        )
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(
                plan((first,)), events=(first,), prior_candidates=prior
            )
        nonreview_prior = (
            AssessmentCandidate(
                event("release:unchanged", changed=False),
                CandidateDisposition.NO_CHANGE_SIGNAL,
                AT,
            ),
        )
        same_disposition = plan((first,), prior_candidates=nonreview_prior)
        self.assertEqual(
            same_disposition.candidates[0].disposition,
            CandidateDisposition.REVIEW_CANDIDATE,
        )
        self.assertNotEqual(
            same_disposition.prior_candidate_set_sha256,
            plan((first,)).prior_candidate_set_sha256,
        )
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(same_disposition, events=(first,))
        with self.assertRaisesRegex(EventAssessmentError, "event set"):
            replace(same_disposition, event_set_sha256=SHA, batch_sha256="")


if __name__ == "__main__":
    unittest.main()
