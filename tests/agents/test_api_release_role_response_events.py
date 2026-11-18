"""Release-review planning controls and pinned legacy event identities."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.api_release_role_response_review import compare_api_release_role_responses
from sunderkey.event_assessment_planning import (
    AssessmentCandidate,
    CandidateDisposition,
    EventAssessmentError,
    event_from_evidence,
    plan_event_assessments,
    verify_assessment_candidate_batch,
)
from tests.agents import test_api_release_role_response_review as review_fixtures
from tests.agents import test_event_assessment_planning as legacy_fixtures


def review():
    before = (
        review_fixtures.observation("event:before-reader", "role:reader", 200),
        review_fixtures.observation("event:before-writer", "role:writer", 403),
    )
    after = (
        review_fixtures.observation("event:after-reader", "role:reader", 403, side="after"),
        review_fixtures.observation("event:after-writer", "role:writer", 200, side="after"),
    )
    return compare_api_release_role_responses(**review_fixtures.sources(before, after))


class ApiReleaseRoleResponseEventTests(unittest.TestCase):
    def test_legacy_release_and_drift_metadata_match_parent_revision(self):
        # These identities were captured from the actual parent implementation.
        # No Git access or replay of an archived implementation occurs in tests.
        release = event_from_evidence(
            legacy_fixtures.release_delta(), observed_at="2026-09-23T12:10:00Z"
        ).to_dict()
        self.assertEqual(
            release,
            {
                "change_signal": True,
                "event_id": "ACE-BA4DDACBF10A1551AADD3C36BE2C875F",
                "event_sha256": "sha256:ba4ddacbf10a1551aadd3c36be2c875f"
                "713a381179627f82fd3913f1846c56ac",
                "evidence_sha256": "sha256:3ddbb3b9214efa22f73efe1debc2be8d"
                "337d29861297a44e21f4e253da04e880",
                "kind": "api_release_delta",
                "occurred_at": "2026-09-23T12:10:00Z",
                "reason_codes": ["new_endpoint_observed"],
                "scope_sha256": legacy_fixtures.SCOPE,
                "source_id": "release:17",
            },
        )
        drift = event_from_evidence(legacy_fixtures.drift_assessment()).to_dict()
        self.assertEqual(
            drift,
            {
                "change_signal": True,
                "event_id": "ACE-7BF8A8FE199E8EFD4BDFBBFD01D273B1",
                "event_sha256": "sha256:7bf8a8fe199e8efd4bdfbbfd01d273b1"
                "ba713093b172b43953fda484affacc72",
                "evidence_sha256": "sha256:e522d7a9475186562c592c37e040635a"
                "42e51d3de7907ac73472aaa456d8c3fa",
                "kind": "surface_drift",
                "occurred_at": "2026-09-23T12:15:00Z",
                "reason_codes": ["drift_added"],
                "scope_sha256": legacy_fixtures.SCOPE,
                "source_id": "SDA-E522D7A9475186562C592C37E040635A",
            },
        )

    def test_review_events_preserve_all_existing_planner_controls(self):
        source = review()
        event = event_from_evidence(source, observed_at=source.current_snapshot_at)
        inputs = {
            "events": (event,),
            "scope_sha256": source.scope_sha256,
            "as_of": "2026-09-23T12:11:00Z",
        }
        accepted = plan_event_assessments(**inputs)
        self.assertEqual(accepted.candidates[0].disposition, CandidateDisposition.REVIEW_CANDIDATE)
        for changes, expected in (
            ({"intake_stopped": True}, CandidateDisposition.STOPPED),
            ({"max_event_age_seconds": 30}, CandidateDisposition.STALE),
            ({"prior_candidates": accepted.candidates}, CandidateDisposition.DUPLICATE),
        ):
            with self.subTest(expected=expected):
                batch = plan_event_assessments(**{**inputs, **changes})
                self.assertEqual(batch.candidates[0].disposition, expected)
        prior_review = replace(source, release_id="release:prior", review_sha256="")
        prior_event = event_from_evidence(
            prior_review, observed_at=prior_review.current_snapshot_at
        )
        prior = (
            AssessmentCandidate(
                prior_event, CandidateDisposition.REVIEW_CANDIDATE, prior_event.occurred_at
            ),
        )
        for changes, expected in (
            ({"cooldown_seconds": 3600}, CandidateDisposition.COOLDOWN),
            (
                {"cooldown_seconds": 1, "daily_candidate_budget": 1},
                CandidateDisposition.BUDGET,
            ),
        ):
            with self.subTest(expected=expected):
                batch = plan_event_assessments(**{**inputs, "prior_candidates": prior, **changes})
                self.assertEqual(batch.candidates[0].disposition, expected)
        with self.assertRaisesRegex(EventAssessmentError, "scope differs"):
            plan_event_assessments(**{**inputs, "scope_sha256": legacy_fixtures.SCOPE})
        self.assertTrue(all(value == "none" for value in accepted.to_dict()["effects"].values()))

    def test_review_event_batch_replay_rejects_rehashed_stop_bypass(self):
        source = review()
        event = event_from_evidence(source, observed_at=source.current_snapshot_at)
        original = plan_event_assessments(
            events=(event,),
            scope_sha256=source.scope_sha256,
            as_of="2026-09-23T12:11:00Z",
            intake_stopped=True,
        )
        self.assertEqual(verify_assessment_candidate_batch(original, events=(event,)), original)
        forged = replace(
            original,
            candidates=(
                AssessmentCandidate(event, CandidateDisposition.REVIEW_CANDIDATE, original.as_of),
            ),
            batch_sha256="",
        )
        with self.assertRaisesRegex(EventAssessmentError, "source replay"):
            verify_assessment_candidate_batch(forged, events=(event,))

    def test_stale_or_malformed_review_cannot_enter_event_intake(self):
        for field, value in (
            ("release_id", "release:substituted"),
            ("review_sha256", "sha256:" + "0" * 64),
            ("gate_status", "approved"),
            ("reobserved_count", True),
        ):
            with self.subTest(field=field):
                source = review()
                object.__setattr__(source, field, value)
                with self.assertRaisesRegex(EventAssessmentError, "integrity"):
                    event_from_evidence(source, observed_at=source.current_snapshot_at)


if __name__ == "__main__":
    unittest.main()
