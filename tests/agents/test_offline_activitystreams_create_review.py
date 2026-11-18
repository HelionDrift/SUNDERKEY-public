"""Synthetic ActivityStreams identifier comparison remains nonqualifying."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_activitystreams_create_review import (
    ActivityStreamsCreateReviewError,
    ActivityStreamsCreateReviewReport,
    analyze_supplied_activitystreams_create,
    component_fixture,
    verify_supplied_activitystreams_create,
)


class ActivityStreamsCreateReviewTests(unittest.TestCase):
    def test_matching_identifiers_do_not_authenticate_account(self) -> None:
        model = component_fixture()
        body = analyze_supplied_activitystreams_create(model).to_dict()
        self.assertTrue(body["actor_matches_supplied_expectation"])
        self.assertTrue(body["actor_matches_object_attribution"])
        self.assertFalse(body["social_account_control_verified"])
        self.assertFalse(body["source_authenticated"])
        self.assertFalse(body["finding_claimed"])
        self.assertNotIn(model["expected_actor_id"], str(body))

    def test_attribution_difference_is_not_a_finding(self) -> None:
        model = component_fixture()
        model["activity"]["object"]["attributedTo"] = (
            "https://social.example.test/actors/jordan"
        )
        body = analyze_supplied_activitystreams_create(model).to_dict()
        self.assertFalse(body["actor_matches_object_attribution"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["disposition"], "unknown")

    def test_unknown_context_http_and_content_reject(self) -> None:
        model = component_fixture()
        model["activity"]["@context"] = "https://example.test/context"
        with self.assertRaises(ActivityStreamsCreateReviewError):
            analyze_supplied_activitystreams_create(model)
        model = component_fixture()
        model["activity"]["actor"] = "http://social.example.test/actors/alex"
        with self.assertRaises(ActivityStreamsCreateReviewError):
            analyze_supplied_activitystreams_create(model)
        model = component_fixture()
        model["activity"]["object"]["content"] = "unneeded private content"
        with self.assertRaises(ValueError):
            analyze_supplied_activitystreams_create(model)

    def test_nonsynthetic_source_rejects(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(ActivityStreamsCreateReviewError):
            analyze_supplied_activitystreams_create(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_activitystreams_create(model)
        self.assertEqual(
            verify_supplied_activitystreams_create(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["activity"]["id"] = "https://social.example.test/activities/two"
        with self.assertRaises(ActivityStreamsCreateReviewError):
            verify_supplied_activitystreams_create(report, model=changed)
        with self.assertRaises(ActivityStreamsCreateReviewError):
            ActivityStreamsCreateReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
