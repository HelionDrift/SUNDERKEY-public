"""Offline supplied callback and state-order regression tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_reentrancy_state_order import (
    ReentrancyStateOrderError,
    analyze_supplied_reentrancy_state_order,
    component_fixture,
    verify_supplied_reentrancy_state_order,
    verify_supplied_reentrancy_state_order_bytes,
)


class ReentrancyStateOrderTests(unittest.TestCase):
    def test_callback_before_write_is_an_inert_review_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_reentrancy_state_order(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["trace_projections"][0]["witness_event_ids"],
            {
                "read_event_id": "step-0",
                "external_call_event_id": "step-1",
                "callback_event_id": "step-2",
                "write_event_id": "step-3",
            },
        )
        self.assertFalse(body["reentrant_effect_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            verify_supplied_reentrancy_state_order(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_reentrancy_state_order_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_multiple_read_windows_and_incomplete_trace(self) -> None:
        model = component_fixture()
        first = model["traces"][0]
        first["events"] = [
            {"event_id": f"event-{index}", "kind": kind, "resource_id": "balance"}
            for index, kind in enumerate(
                (
                    "state_read",
                    "external_call",
                    "state_write",
                    "state_read",
                    "external_call",
                    "callback_enter",
                    "state_write",
                )
            )
        ]
        self.assertEqual(
            analyze_supplied_reentrancy_state_order(model).to_dict()["candidate_count"], 1
        )
        first["context_complete"] = False
        self.assertEqual(
            analyze_supplied_reentrancy_state_order(model).to_dict()["unknown_count"], 1
        )
        first["context_complete"] = True
        first["events"] = first["events"][:2]
        self.assertEqual(
            analyze_supplied_reentrancy_state_order(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_event_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_reentrancy_state_order(model)
        changed = copy.deepcopy(model)
        changed["traces"][0]["events"][2]["kind"] = "state_write"
        with self.assertRaises(ReentrancyStateOrderError):
            verify_supplied_reentrancy_state_order(report, model=changed)
        with self.assertRaises(ReentrancyStateOrderError):
            verify_supplied_reentrancy_state_order(report.to_dict(), model=model)
        with self.assertRaises(ReentrancyStateOrderError):
            verify_supplied_reentrancy_state_order_bytes(b"{}", model=model)

    def test_rejects_duplicate_event_and_cross_resource(self) -> None:
        model = component_fixture()
        model["traces"][0]["events"][1]["event_id"] = "step-0"
        with self.assertRaises(ReentrancyStateOrderError):
            analyze_supplied_reentrancy_state_order(model)
        model = component_fixture()
        model["traces"][0]["events"][1]["resource_id"] = "other"
        with self.assertRaises(ReentrancyStateOrderError):
            analyze_supplied_reentrancy_state_order(model)


if __name__ == "__main__":
    unittest.main()
