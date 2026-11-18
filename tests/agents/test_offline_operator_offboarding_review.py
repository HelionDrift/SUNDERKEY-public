"""Synthetic operator chronology cues do not allege insider activity."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_operator_offboarding_review import (
    OperatorOffboardingReviewError,
    OperatorOffboardingReviewReport,
    analyze_supplied_operator_offboarding,
    component_fixture,
    verify_supplied_operator_offboarding,
)


class OperatorOffboardingReviewTests(unittest.TestCase):
    def test_event_between_declared_termination_and_disable_is_only_a_cue(self) -> None:
        model = component_fixture()
        body = analyze_supplied_operator_offboarding(model).to_dict()
        self.assertTrue(body["event_after_declared_termination"])
        self.assertFalse(body["event_after_declared_disable"])
        self.assertEqual(body["record_review_cues"], [
            "privileged_event_after_termination"
        ])
        self.assertFalse(body["insider_activity_verified"])
        self.assertFalse(body["finding_claimed"])
        self.assertNotIn(model["person_ref"], str(body))

    def test_event_after_declared_disable_is_not_proof_of_access(self) -> None:
        model = component_fixture()
        model["privileged_event_time"] = "2026-01-01T02:00:00Z"
        body = analyze_supplied_operator_offboarding(model).to_dict()
        self.assertEqual(len(body["record_review_cues"]), 2)
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["account_control_verified"])

    def test_bad_clock_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["termination_time"] = "2026-13-01T00:00:00Z"
        with self.assertRaises(OperatorOffboardingReviewError):
            analyze_supplied_operator_offboarding(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OperatorOffboardingReviewError):
            analyze_supplied_operator_offboarding(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_operator_offboarding(model)
        self.assertEqual(
            verify_supplied_operator_offboarding(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["privileged_event_time"] = "2025-12-31T23:30:00Z"
        with self.assertRaises(OperatorOffboardingReviewError):
            verify_supplied_operator_offboarding(report, model=changed)
        with self.assertRaises(OperatorOffboardingReviewError):
            OperatorOffboardingReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
