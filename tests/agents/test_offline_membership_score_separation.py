"""Offline aggregate membership-score separation regression tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_membership_score_separation import (
    MembershipScoreSeparationError,
    analyze_supplied_membership_scores,
    component_fixture,
    verify_supplied_membership_scores,
    verify_supplied_membership_scores_bytes,
)


class MembershipScoreSeparationTests(unittest.TestCase):
    def test_exact_rate_advantage_is_nonqualifying(self) -> None:
        model = component_fixture()
        report = analyze_supplied_membership_scores(model)
        body = report.to_dict()
        self.assertEqual(body["member_positive_count"], 3)
        self.assertEqual(body["nonmember_positive_count"], 1)
        self.assertEqual(body["rate_advantage_numerator"], 8)
        self.assertEqual(body["rate_advantage_denominator"], 16)
        self.assertEqual(body["disposition"], "candidate_declared_membership_separation")
        self.assertFalse(body["individual_membership_inferred"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            verify_supplied_membership_scores(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_membership_scores_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_balanced_rates_and_incomplete_conditions(self) -> None:
        model = component_fixture()
        model["nonmember_scores_basis_points"] = [9_000, 8_000, 7_000, 2_000]
        self.assertEqual(analyze_supplied_membership_scores(model).to_dict()["candidate_count"], 0)
        model["same_scoring_conditions"] = False
        self.assertEqual(analyze_supplied_membership_scores(model).to_dict()["unknown_count"], 1)
        model["same_scoring_conditions"] = True
        model["minimum_samples_per_group"] = 5
        self.assertEqual(analyze_supplied_membership_scores(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_scores_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_membership_scores(model)
        changed = copy.deepcopy(model)
        changed["member_scores_basis_points"][0] = 1_000
        with self.assertRaises(MembershipScoreSeparationError):
            verify_supplied_membership_scores(report, model=changed)
        with self.assertRaises(MembershipScoreSeparationError):
            verify_supplied_membership_scores(report.to_dict(), model=model)
        with self.assertRaises(MembershipScoreSeparationError):
            verify_supplied_membership_scores_bytes(b"{}", model=model)

    def test_rejects_fraction_boolean_and_empty_distribution(self) -> None:
        model = component_fixture()
        model["member_scores_basis_points"][0] = 0.5
        with self.assertRaises(ValueError):
            analyze_supplied_membership_scores(model)
        model = component_fixture()
        model["threshold_basis_points"] = True
        with self.assertRaises(MembershipScoreSeparationError):
            analyze_supplied_membership_scores(model)
        model = component_fixture()
        model["nonmember_scores_basis_points"] = []
        with self.assertRaises(MembershipScoreSeparationError):
            analyze_supplied_membership_scores(model)


if __name__ == "__main__":
    unittest.main()
