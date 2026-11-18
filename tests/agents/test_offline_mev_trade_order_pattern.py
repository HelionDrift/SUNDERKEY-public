"""Supplied outer-trade ordering pattern and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mev_trade_order_pattern import (
    MevTradeOrderPatternError,
    analyze_supplied_mev_trade_order,
    component_fixture,
    verify_supplied_mev_trade_order,
    verify_supplied_mev_trade_order_bytes,
)


class MevTradeOrderPatternTests(unittest.TestCase):
    def test_outer_trade_order_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mev_trade_order(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["scenario_projections"][0]["witness"],
            {
                "outer_actor_id": "actor-a",
                "front_trade_id": "front-one",
                "victim_trade_id": "victim-one",
                "back_trade_id": "back-one",
            },
        )
        self.assertFalse(body["economic_effect_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_mev_trade_order(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_mev_trade_order_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_wrong_order_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["scenarios"][0]["trades"][2]["direction"] = "buy"
        self.assertEqual(analyze_supplied_mev_trade_order(model).to_dict()["candidate_count"], 0)
        model["scenarios"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_mev_trade_order(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mev_trade_order(model)
        changed = copy.deepcopy(model)
        changed["scenarios"][0]["trades"][0]["actor_id"] = "actor-c"
        with self.assertRaises(MevTradeOrderPatternError):
            verify_supplied_mev_trade_order(report, model=changed)
        with self.assertRaises(MevTradeOrderPatternError):
            verify_supplied_mev_trade_order(report.to_dict(), model=model)
        with self.assertRaises(MevTradeOrderPatternError):
            verify_supplied_mev_trade_order_bytes(b"{}", model=model)

    def test_rejects_duplicate_position_and_absent_victim(self) -> None:
        model = component_fixture()
        model["scenarios"][0]["trades"][1]["position"] = 1
        with self.assertRaises(MevTradeOrderPatternError):
            analyze_supplied_mev_trade_order(model)
        model = component_fixture()
        model["scenarios"][0]["victim_trade_id"] = "absent"
        with self.assertRaises(MevTradeOrderPatternError):
            analyze_supplied_mev_trade_order(model)


if __name__ == "__main__":
    unittest.main()
