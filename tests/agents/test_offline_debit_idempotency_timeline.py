"""Supplied debit anomalies are not proof of a real race or double spend."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_debit_idempotency_timeline import (
    DebitIdempotencyTimeline,
    DebitIdempotencyTimelineError,
    analyze_supplied_debit_timeline,
    verify_supplied_debit_timeline,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-debit-idempotency-timeline-v1",
        "account_ref": "account:sha256:" + "a" * 64,
        "currency_label": "TST",
        "initial_balance_minor": 100,
        "events": [
            {
                "event_id": "e1",
                "command_id": "k1",
                "amount_minor": 40,
                "result": "accepted",
                "declared_balance_after_minor": 60,
                "source_id": "fixture-ledger",
            },
            {
                "event_id": "e2",
                "command_id": "k2",
                "amount_minor": 70,
                "result": "rejected",
                "declared_balance_after_minor": 60,
                "source_id": "fixture-ledger",
            },
            {
                "event_id": "e3",
                "command_id": "k1",
                "amount_minor": 20,
                "result": "accepted",
                "declared_balance_after_minor": 40,
                "source_id": "fixture-ledger",
            },
            {
                "event_id": "e4",
                "command_id": "k3",
                "amount_minor": 50,
                "result": "accepted",
                "declared_balance_after_minor": 0,
                "source_id": "fixture-ledger",
            },
        ],
    }


class DebitIdempotencyTimelineTests(unittest.TestCase):
    def test_duplicate_accepted_key_and_overdraw_are_separate_supplied_signals(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_debit_timeline(model)
        body = report.to_dict()
        rows = {row["event_id"]: row for row in body["events"]}
        self.assertEqual(rows["e1"]["expected_balance_after_minor"], 60)
        self.assertEqual(rows["e1"]["anomaly_flags"], [])
        self.assertEqual(rows["e2"]["expected_balance_after_minor"], 60)
        self.assertEqual(rows["e2"]["anomaly_flags"], [])
        self.assertEqual(rows["e3"]["anomaly_flags"], ["duplicate_accepted_command"])
        self.assertEqual(
            rows["e4"]["anomaly_flags"],
            ["accepted_debit_exceeds_declared_available_balance", "declared_balance_mismatch"],
        )
        self.assertEqual(body["final_expected_balance_minor"], -10)
        self.assertFalse(body["flags"]["double_spend_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_debit_timeline(report, model=model).to_dict(), body)

    def test_rejected_key_can_later_be_accepted_without_duplicate_flag(self):
        model = _model()
        model["events"][2]["command_id"] = "k2"
        rows = analyze_supplied_debit_timeline(model).to_dict()["events"]
        self.assertEqual(rows[2]["anomaly_flags"], [])

    def test_plain_account_boolean_duplicate_event_and_tamper_are_refused(self):
        model = _model()
        model["account_ref"] = "customer@example.com"
        with self.assertRaises(DebitIdempotencyTimelineError):
            analyze_supplied_debit_timeline(model)
        model = _model()
        model["events"][0]["amount_minor"] = True
        with self.assertRaises(DebitIdempotencyTimelineError):
            analyze_supplied_debit_timeline(model)
        model = _model()
        model["events"][1]["event_id"] = "e1"
        with self.assertRaises(DebitIdempotencyTimelineError):
            analyze_supplied_debit_timeline(model)
        body = analyze_supplied_debit_timeline(_model()).to_dict()
        body["flags"]["double_spend_proven"] = True
        with self.assertRaises(DebitIdempotencyTimelineError):
            DebitIdempotencyTimeline(body)
        report = analyze_supplied_debit_timeline(_model())
        model = _model()
        model["events"][0]["result"] = "rejected"
        with self.assertRaises(DebitIdempotencyTimelineError):
            verify_supplied_debit_timeline(report, model=model)

    def test_non_native_value_is_rejected_before_comparison(self):
        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["events"][0]["result"] = ComparisonTrap()
        with self.assertRaises(DebitIdempotencyTimelineError):
            analyze_supplied_debit_timeline(model)


if __name__ == "__main__":
    unittest.main()
