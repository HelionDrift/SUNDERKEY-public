"""Synthetic power recovery cadence review does not claim compliance."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_power_recovery_cadence_review import (
    PowerRecoveryCadenceReviewError,
    PowerRecoveryCadenceReviewReport,
    analyze_supplied_power_recovery_cadence,
    component_fixture,
    verify_supplied_power_recovery_cadence,
)


class PowerRecoveryCadenceReviewTests(unittest.TestCase):
    def test_in_window_dates_do_not_claim_compliance(self) -> None:
        body = analyze_supplied_power_recovery_cadence(component_fixture()).to_dict()
        self.assertEqual(body["fifteen_calendar_month_cutoff"], "2025-07-01")
        self.assertTrue(body["declared_plan_exercise_in_window"])
        self.assertTrue(body["declared_sample_test_in_window"])
        self.assertEqual(body["record_review_cues"], [])
        self.assertFalse(body["standard_compliance_verified"])
        self.assertFalse(body["recovery_test_executed"])
        self.assertFalse(body["finding_claimed"])

    def test_stale_and_incompatible_declarations_are_review_cues_only(self) -> None:
        model = component_fixture()
        model["plan_exercise_date"] = "2025-06-30"
        model["recovery_information_sample_date"] = "2025-06-30"
        model["sample_usable_and_compatible_declared"] = False
        body = analyze_supplied_power_recovery_cadence(model).to_dict()
        self.assertEqual(len(body["record_review_cues"]), 3)
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["disposition"], "unknown")

    def test_boundary_date_is_in_window_and_future_date_rejects(self) -> None:
        model = component_fixture()
        model["plan_exercise_date"] = "2025-07-01"
        self.assertTrue(analyze_supplied_power_recovery_cadence(model).to_dict()[
            "declared_plan_exercise_in_window"
        ])
        model["plan_exercise_date"] = "2026-10-02"
        with self.assertRaises(PowerRecoveryCadenceReviewError):
            analyze_supplied_power_recovery_cadence(model)

    def test_invalid_date_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["as_of_date"] = "2026-02-30"
        with self.assertRaises(PowerRecoveryCadenceReviewError):
            analyze_supplied_power_recovery_cadence(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PowerRecoveryCadenceReviewError):
            analyze_supplied_power_recovery_cadence(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_power_recovery_cadence(model)
        self.assertEqual(
            verify_supplied_power_recovery_cadence(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["recovery_information_sample_date"] = "2025-08-01"
        with self.assertRaises(PowerRecoveryCadenceReviewError):
            verify_supplied_power_recovery_cadence(report, model=changed)
        with self.assertRaises(PowerRecoveryCadenceReviewError):
            PowerRecoveryCadenceReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
