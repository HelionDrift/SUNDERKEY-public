"""Supplied allocation windows do not prove a bot or marketplace defect."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_scalping_window_review import (
    ScalpingWindowReview,
    ScalpingWindowReviewError,
    analyze_supplied_scalping_windows,
    verify_supplied_scalping_windows,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-scalping-window-review-v1",
        "item_ref": "item:sha256:" + "a" * 64,
        "window_seconds": 60,
        "maximum_allowed_per_actor": 1,
        "events": [
            {
                "event_id": "e1",
                "actor_ref": "actor:sha256:" + "b" * 64,
                "second": 1,
                "result": "allowed",
                "declared_allowed_in_window": 1,
            },
            {
                "event_id": "e2",
                "actor_ref": "actor:sha256:" + "b" * 64,
                "second": 2,
                "result": "blocked",
                "declared_allowed_in_window": 1,
            },
            {
                "event_id": "e3",
                "actor_ref": "actor:sha256:" + "b" * 64,
                "second": 3,
                "result": "allowed",
                "declared_allowed_in_window": 1,
            },
        ],
    }


class ScalpingWindowReviewTests(unittest.TestCase):
    def test_window_count_distinguishes_blocked_and_allowed_records(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_scalping_windows(model)
        body = report.to_dict()
        self.assertEqual([row["expected_allowed_in_window"] for row in body["events"]], [1, 1, 2])
        self.assertEqual(body["events"][0]["anomaly_flags"], [])
        self.assertEqual(body["events"][1]["anomaly_flags"], [])
        self.assertEqual(
            body["events"][2]["anomaly_flags"],
            ["allowed_above_supplied_actor_window_limit", "declared_window_count_mismatch"],
        )
        self.assertFalse(body["flags"]["bot_identity_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_scalping_windows(report, model=model).to_json(), report.to_json()
        )

    def test_window_rollover_and_advertised_event_limit(self):
        model = _model()
        model["events"] = [
            {
                **model["events"][0],
                "event_id": "e" + str(index).zfill(127),
                "second": index * 60,
                "declared_allowed_in_window": 1,
            }
            for index in range(512)
        ]
        report = analyze_supplied_scalping_windows(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertTrue(
            all(row["expected_allowed_in_window"] == 1 for row in report.to_dict()["events"])
        )
        self.assertLessEqual(len(report.to_json()), 524_288)

    def test_plain_actor_boolean_out_of_order_and_tamper_are_refused(self):
        model = _model()
        model["events"][0]["actor_ref"] = "real-person"
        with self.assertRaises(ScalpingWindowReviewError):
            analyze_supplied_scalping_windows(model)
        model = _model()
        model["window_seconds"] = True
        with self.assertRaises(ScalpingWindowReviewError):
            analyze_supplied_scalping_windows(model)
        model = _model()
        model["events"][1]["second"] = 0
        with self.assertRaises(ScalpingWindowReviewError):
            analyze_supplied_scalping_windows(model)
        model = _model()
        model["events"][0]["result"] = object()
        with self.assertRaises(ScalpingWindowReviewError):
            analyze_supplied_scalping_windows(model)
        body = analyze_supplied_scalping_windows(_model()).to_dict()
        body["flags"]["bot_identity_proven"] = True
        with self.assertRaises(ScalpingWindowReviewError):
            ScalpingWindowReview(body)
        report = analyze_supplied_scalping_windows(_model())
        changed = _model()
        changed["maximum_allowed_per_actor"] = 2
        with self.assertRaises(ScalpingWindowReviewError):
            verify_supplied_scalping_windows(report, model=changed)


if __name__ == "__main__":
    unittest.main()
