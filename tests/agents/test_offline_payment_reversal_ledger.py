"""Supplied reversals are review signals, not payment proof."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_payment_reversal_ledger import (
    PaymentReversalLedger,
    PaymentReversalLedgerError,
    analyze_supplied_payment_reversals,
    verify_supplied_payment_reversals,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-payment-reversal-ledger-v1",
        "payment_ref": "payment:sha256:" + "a" * 64,
        "currency_label": "TST",
        "captured_minor": 100,
        "events": [
            {
                "event_id": "e1",
                "kind": "refund",
                "amount_minor": 40,
                "result": "accepted",
                "declared_remaining_minor": 60,
            },
            {
                "event_id": "e2",
                "kind": "chargeback",
                "amount_minor": 80,
                "result": "rejected",
                "declared_remaining_minor": 60,
            },
            {
                "event_id": "e3",
                "kind": "chargeback",
                "amount_minor": 80,
                "result": "accepted",
                "declared_remaining_minor": 0,
            },
        ],
    }


class PaymentReversalLedgerTests(unittest.TestCase):
    def test_reconcile_accepted_and_rejected_events_separately(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_payment_reversals(model)
        body = report.to_dict()
        self.assertEqual([row["expected_remaining_minor"] for row in body["events"]], [60, 60, -20])
        self.assertEqual(body["events"][0]["anomaly_flags"], [])
        self.assertEqual(body["events"][1]["anomaly_flags"], [])
        self.assertEqual(
            body["events"][2]["anomaly_flags"],
            ["accepted_reversals_exceed_supplied_capture", "declared_remaining_mismatch"],
        )
        self.assertFalse(body["flags"]["capture_or_reversal_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_payment_reversals(report, model=model).to_json(), report.to_json()
        )

    def test_advertised_event_limit_has_bounded_report(self):
        model = _model()
        model["events"] = [
            {**model["events"][1], "event_id": "e" + str(index).zfill(127)} for index in range(512)
        ]
        report = analyze_supplied_payment_reversals(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)

    def test_non_native_plain_reference_boolean_and_tamper_are_refused(self):
        model = _model()
        model["payment_ref"] = "real-payment"
        with self.assertRaises(PaymentReversalLedgerError):
            analyze_supplied_payment_reversals(model)
        model = _model()
        model["events"][0]["amount_minor"] = True
        with self.assertRaises(PaymentReversalLedgerError):
            analyze_supplied_payment_reversals(model)
        model = _model()
        model["events"][1]["event_id"] = "e1"
        with self.assertRaises(PaymentReversalLedgerError):
            analyze_supplied_payment_reversals(model)
        model = _model()
        model["events"][0]["kind"] = object()
        with self.assertRaises(PaymentReversalLedgerError):
            analyze_supplied_payment_reversals(model)
        model = _model()
        model["events"].append(model["events"])
        with self.assertRaises(PaymentReversalLedgerError):
            analyze_supplied_payment_reversals(model)
        body = analyze_supplied_payment_reversals(_model()).to_dict()
        body["flags"]["capture_or_reversal_proven"] = True
        with self.assertRaises(PaymentReversalLedgerError):
            PaymentReversalLedger(body)
        report = analyze_supplied_payment_reversals(_model())
        changed = _model()
        changed["events"][0]["amount_minor"] = 41
        with self.assertRaises(PaymentReversalLedgerError):
            verify_supplied_payment_reversals(report, model=changed)


if __name__ == "__main__":
    unittest.main()
