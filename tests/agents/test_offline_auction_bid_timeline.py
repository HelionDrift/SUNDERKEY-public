"""Supplied bid ordering does not prove a marketplace defect."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_auction_bid_timeline import (
    AuctionBidTimeline,
    AuctionBidTimelineError,
    analyze_supplied_auction_bids,
    verify_supplied_auction_bids,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _model() -> dict:
    a = _ref("bidder", "a")
    b = _ref("bidder", "b")
    c = _ref("bidder", "c")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-auction-bid-timeline-v1",
        "listing_ref": _ref("listing", "d"),
        "currency_label": "TST",
        "reserve_minor": 100,
        "minimum_increment_minor": 10,
        "events": [
            {
                "event_id": "e1",
                "bidder_ref": a,
                "bid_minor": 100,
                "result": "accepted",
                "declared_leader_ref": a,
                "declared_leading_bid_minor": 100,
            },
            {
                "event_id": "e2",
                "bidder_ref": b,
                "bid_minor": 105,
                "result": "rejected",
                "declared_leader_ref": a,
                "declared_leading_bid_minor": 100,
            },
            {
                "event_id": "e3",
                "bidder_ref": b,
                "bid_minor": 105,
                "result": "accepted",
                "declared_leader_ref": b,
                "declared_leading_bid_minor": 105,
            },
            {
                "event_id": "e4",
                "bidder_ref": c,
                "bid_minor": 120,
                "result": "rejected",
                "declared_leader_ref": b,
                "declared_leading_bid_minor": 105,
            },
            {
                "event_id": "e5",
                "bidder_ref": c,
                "bid_minor": 120,
                "result": "accepted",
                "declared_leader_ref": a,
                "declared_leading_bid_minor": 120,
            },
        ],
    }


class AuctionBidTimelineTests(unittest.TestCase):
    def test_increment_rejection_and_declared_leader_are_separate_signals(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_auction_bids(model)
        body = report.to_dict()
        rows = body["events"]
        self.assertEqual(rows[0]["anomaly_flags"], [])
        self.assertEqual(rows[1]["anomaly_flags"], [])
        self.assertEqual(rows[2]["anomaly_flags"], ["accepted_below_supplied_minimum_increment"])
        self.assertEqual(rows[3]["anomaly_flags"], ["rejected_despite_supplied_increment"])
        self.assertEqual(rows[4]["anomaly_flags"], ["declared_leader_mismatch"])
        self.assertTrue(body["supplied_reserve_met"])
        self.assertFalse(body["flags"]["real_winner_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_auction_bids(report, model=model).to_dict(), body)

    def test_maximum_event_count_has_bounded_report(self):
        model = _model()
        model["events"] = [
            {**model["events"][0], "event_id": "e" + str(index).zfill(127)} for index in range(512)
        ]
        report = analyze_supplied_auction_bids(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_auction_bids(report, model=model).to_json(),
            report.to_json(),
        )

    def test_plain_listing_boolean_inconsistent_leader_and_tamper_are_refused(self):
        model = _model()
        model["listing_ref"] = "real-listing"
        with self.assertRaises(AuctionBidTimelineError):
            analyze_supplied_auction_bids(model)
        model = _model()
        model["minimum_increment_minor"] = True
        with self.assertRaises(AuctionBidTimelineError):
            analyze_supplied_auction_bids(model)
        model = _model()
        model["events"][0]["declared_leader_ref"] = None
        with self.assertRaises(AuctionBidTimelineError):
            analyze_supplied_auction_bids(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["events"][0]["result"] = ComparisonTrap()
        with self.assertRaises(AuctionBidTimelineError):
            analyze_supplied_auction_bids(model)
        body = analyze_supplied_auction_bids(_model()).to_dict()
        body["flags"]["real_winner_proven"] = True
        with self.assertRaises(AuctionBidTimelineError):
            AuctionBidTimeline(body)
        report = analyze_supplied_auction_bids(_model())
        model = _model()
        model["events"][0]["result"] = "rejected"
        with self.assertRaises(AuctionBidTimelineError):
            verify_supplied_auction_bids(report, model=model)


if __name__ == "__main__":
    unittest.main()
