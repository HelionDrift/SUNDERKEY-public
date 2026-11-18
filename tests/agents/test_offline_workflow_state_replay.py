"""Supplied workflow transitions never establish a deployed workflow defect."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_workflow_state_replay import (
    WorkflowStateReplay,
    WorkflowStateReplayError,
    analyze_supplied_workflow_states,
    verify_supplied_workflow_states,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-workflow-state-replay-v1",
        "workflow_ref": "workflow:sha256:" + "a" * 64,
        "states": ["created", "paid", "fulfilled", "closed"],
        "terminal_states": ["closed"],
        "initial_state": "created",
        "transitions": [
            {
                "transition_id": "pay",
                "from_state": "created",
                "to_state": "paid",
                "guard_label": "payment-approved",
            },
            {
                "transition_id": "fulfill",
                "from_state": "paid",
                "to_state": "fulfilled",
                "guard_label": "inventory-reserved",
            },
            {
                "transition_id": "close",
                "from_state": "fulfilled",
                "to_state": "closed",
                "guard_label": "delivered",
            },
        ],
        "events": [
            {
                "event_id": "e1",
                "transition_id": "pay",
                "declared_before_state": "created",
                "declared_after_state": "paid",
                "guard_outcome": "satisfied",
                "result": "accepted",
            },
            {
                "event_id": "e2",
                "transition_id": "fulfill",
                "declared_before_state": "paid",
                "declared_after_state": "paid",
                "guard_outcome": "unsatisfied",
                "result": "rejected",
            },
            {
                "event_id": "e3",
                "transition_id": "fulfill",
                "declared_before_state": "paid",
                "declared_after_state": "fulfilled",
                "guard_outcome": "unknown",
                "result": "accepted",
            },
            {
                "event_id": "e4",
                "transition_id": "close",
                "declared_before_state": "fulfilled",
                "declared_after_state": "closed",
                "guard_outcome": "satisfied",
                "result": "accepted",
            },
        ],
    }


class WorkflowStateReplayTests(unittest.TestCase):
    def test_rejected_event_does_not_advance_and_unknown_guard_is_review_signal(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_workflow_states(model)
        body = report.to_dict()
        rows = body["events"]
        self.assertEqual(rows[1]["expected_after_state"], "paid")
        self.assertEqual(rows[1]["anomaly_flags"], [])
        self.assertEqual(rows[2]["anomaly_flags"], ["accepted_guard_not_declared_satisfied"])
        self.assertEqual(body["final_expected_state"], "closed")
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["flags"]["deployed_transition_proven"])
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_workflow_states(report, model=model).to_dict(), body)

    def test_unknown_transition_terminal_reentry_and_declared_mismatch_are_distinct(self):
        model = _model()
        model["events"].extend(
            [
                {
                    "event_id": "e5",
                    "transition_id": "unknown",
                    "declared_before_state": "closed",
                    "declared_after_state": "created",
                    "guard_outcome": "satisfied",
                    "result": "accepted",
                },
                {
                    "event_id": "e6",
                    "transition_id": "pay",
                    "declared_before_state": "created",
                    "declared_after_state": "paid",
                    "guard_outcome": "unsatisfied",
                    "result": "accepted",
                },
            ]
        )
        rows = analyze_supplied_workflow_states(model).to_dict()["events"]
        self.assertEqual(
            rows[4]["anomaly_flags"],
            ["accepted_unknown_transition", "declared_after_state_mismatch"],
        )
        self.assertEqual(
            rows[5]["anomaly_flags"],
            [
                "accepted_from_state_mismatch",
                "accepted_from_terminal_state",
                "accepted_guard_not_declared_satisfied",
                "declared_before_state_mismatch",
            ],
        )
        self.assertEqual(rows[5]["expected_after_state"], "paid")

    def test_maximum_event_count_replays_with_bounded_report(self):
        model = _model()
        model["events"] = [
            {**model["events"][0], "event_id": "e" + str(index).zfill(127)} for index in range(512)
        ]
        report = analyze_supplied_workflow_states(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_workflow_states(report, model=model).to_json(),
            report.to_json(),
        )

    def test_malformed_model_non_native_value_and_report_tamper_are_refused(self):
        for field, value in (
            ("workflow_ref", "real-account"),
            ("terminal_states", ["missing"]),
            ("states", ["created", "created"]),
        ):
            with self.subTest(field=field):
                model = _model()
                model[field] = value
                with self.assertRaises(WorkflowStateReplayError):
                    analyze_supplied_workflow_states(model)
        model = _model()
        model["transitions"][1]["from_state"] = "missing"
        with self.assertRaises(WorkflowStateReplayError):
            analyze_supplied_workflow_states(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["events"][0]["result"] = ComparisonTrap()
        with self.assertRaises(WorkflowStateReplayError):
            analyze_supplied_workflow_states(model)
        body = analyze_supplied_workflow_states(_model()).to_dict()
        body["flags"]["exploit_proven"] = True
        with self.assertRaises(WorkflowStateReplayError):
            WorkflowStateReplay(body)
        report = analyze_supplied_workflow_states(_model())
        model = _model()
        model["events"][0]["result"] = "rejected"
        with self.assertRaises(WorkflowStateReplayError):
            verify_supplied_workflow_states(report, model=model)


if __name__ == "__main__":
    unittest.main()
