"""Supplied coupon counts are local review arithmetic, not exploitation."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_coupon_redemption_timeline import (
    CouponRedemptionTimeline,
    CouponRedemptionTimelineError,
    analyze_supplied_coupon_redemptions,
    verify_supplied_coupon_redemptions,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _model() -> dict:
    actor_a = _ref("actor", "a")
    actor_b = _ref("actor", "b")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-coupon-redemption-timeline-v1",
        "coupon_ref": _ref("coupon", "c"),
        "global_limit": 2,
        "per_actor_limit": 1,
        "events": [
            {
                "event_id": "e1",
                "actor_ref": actor_a,
                "order_ref": _ref("order", "1"),
                "result": "accepted",
                "declared_global_after": 1,
                "declared_actor_after": 1,
            },
            {
                "event_id": "e2",
                "actor_ref": actor_a,
                "order_ref": _ref("order", "2"),
                "result": "rejected",
                "declared_global_after": 1,
                "declared_actor_after": 1,
            },
            {
                "event_id": "e3",
                "actor_ref": actor_b,
                "order_ref": _ref("order", "3"),
                "result": "accepted",
                "declared_global_after": 2,
                "declared_actor_after": 1,
            },
            {
                "event_id": "e4",
                "actor_ref": actor_a,
                "order_ref": _ref("order", "1"),
                "result": "accepted",
                "declared_global_after": 2,
                "declared_actor_after": 2,
            },
        ],
    }


class CouponRedemptionTimelineTests(unittest.TestCase):
    def test_limits_duplicate_order_and_declared_count_are_separate_signals(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_coupon_redemptions(model)
        body = report.to_dict()
        rows = body["events"]
        self.assertEqual(rows[1]["expected_global_after"], 1)
        self.assertEqual(rows[1]["anomaly_flags"], [])
        self.assertEqual(rows[2]["expected_actor_after"], 1)
        self.assertEqual(
            rows[3]["anomaly_flags"],
            [
                "accepted_beyond_actor_limit",
                "accepted_beyond_global_limit",
                "declared_global_count_mismatch",
                "duplicate_accepted_order_label",
            ],
        )
        self.assertEqual(body["final_expected_global_count"], 3)
        self.assertFalse(body["flags"]["real_redemption_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_coupon_redemptions(report, model=model).to_dict(), body)

    def test_rejected_order_may_later_be_accepted_without_duplicate_flag(self):
        model = _model()
        model["events"][3]["order_ref"] = model["events"][1]["order_ref"]
        rows = analyze_supplied_coupon_redemptions(model).to_dict()["events"]
        self.assertNotIn("duplicate_accepted_order_label", rows[3]["anomaly_flags"])

    def test_maximum_event_count_replays_with_bounded_report(self):
        model = _model()
        model["events"] = [
            {
                **model["events"][0],
                "event_id": "e" + str(index).zfill(127),
                "declared_global_after": index + 1,
                "declared_actor_after": index + 1,
            }
            for index in range(512)
        ]
        report = analyze_supplied_coupon_redemptions(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_coupon_redemptions(report, model=model).to_json(),
            report.to_json(),
        )

    def test_malformed_refs_counts_non_native_and_tamper_are_refused(self):
        for field, value in (
            ("coupon_ref", "SAVE10"),
            ("global_limit", True),
            ("per_actor_limit", 0),
        ):
            with self.subTest(field=field):
                model = _model()
                model[field] = value
                with self.assertRaises(CouponRedemptionTimelineError):
                    analyze_supplied_coupon_redemptions(model)
        model = _model()
        model["events"][0]["actor_ref"] = "customer@example.com"
        with self.assertRaises(CouponRedemptionTimelineError):
            analyze_supplied_coupon_redemptions(model)
        model = _model()
        model["events"][1]["event_id"] = "e1"
        with self.assertRaises(CouponRedemptionTimelineError):
            analyze_supplied_coupon_redemptions(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["events"][0]["result"] = ComparisonTrap()
        with self.assertRaises(CouponRedemptionTimelineError):
            analyze_supplied_coupon_redemptions(model)
        body = analyze_supplied_coupon_redemptions(_model()).to_dict()
        body["flags"]["economic_impact_proven"] = True
        with self.assertRaises(CouponRedemptionTimelineError):
            CouponRedemptionTimeline(body)
        report = analyze_supplied_coupon_redemptions(_model())
        model = _model()
        model["events"][0]["result"] = "rejected"
        with self.assertRaises(CouponRedemptionTimelineError):
            verify_supplied_coupon_redemptions(report, model=model)


if __name__ == "__main__":
    unittest.main()
