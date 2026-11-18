"""Supplied channel ordering does not prove an economic defect."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_cross_channel_balance import (
    CrossChannelBalance,
    CrossChannelBalanceError,
    analyze_supplied_cross_channel_balance,
    verify_supplied_cross_channel_balance,
)


def _transaction(letter: str) -> str:
    return "transaction:sha256:" + letter * 64


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-cross-channel-balance-v1",
        "account_ref": "account:sha256:" + "a" * 64,
        "currency_label": "TST",
        "opening_balance_minor": 100,
        "events": [
            {
                "event_id": "e1",
                "channel_id": "web",
                "transaction_ref": _transaction("b"),
                "kind": "debit",
                "amount_minor": 30,
                "result": "accepted",
                "declared_balance_minor": 70,
            },
            {
                "event_id": "e2",
                "channel_id": "mobile",
                "transaction_ref": _transaction("b"),
                "kind": "debit",
                "amount_minor": 30,
                "result": "rejected",
                "declared_balance_minor": 70,
            },
            {
                "event_id": "e3",
                "channel_id": "mobile",
                "transaction_ref": _transaction("b"),
                "kind": "debit",
                "amount_minor": 30,
                "result": "accepted",
                "declared_balance_minor": 70,
            },
        ],
    }


class CrossChannelBalanceTests(unittest.TestCase):
    def test_cross_channel_duplicate_and_balance_mismatch_are_separate(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_cross_channel_balance(model)
        body = report.to_dict()
        self.assertEqual([row["expected_balance_minor"] for row in body["events"]], [70, 70, 40])
        self.assertEqual(body["events"][0]["anomaly_flags"], [])
        self.assertEqual(body["events"][1]["anomaly_flags"], [])
        self.assertEqual(
            body["events"][2]["anomaly_flags"],
            [
                "cross_channel_duplicate_reference",
                "declared_balance_mismatch",
                "duplicate_accepted_transaction_reference",
            ],
        )
        self.assertFalse(body["flags"]["duplicate_economic_effect_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_cross_channel_balance(report, model=model).to_json(), report.to_json()
        )

    def test_advertised_event_limit_has_bounded_report(self):
        model = _model()
        model["events"] = [
            {
                **model["events"][0],
                "event_id": "e" + str(index).zfill(127),
                "transaction_ref": _transaction("b"),
                "result": "rejected",
                "declared_balance_minor": 100,
            }
            for index in range(512)
        ]
        report = analyze_supplied_cross_channel_balance(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)

    def test_plain_account_boolean_duplicate_id_and_tamper_are_refused(self):
        model = _model()
        model["account_ref"] = "customer@example.com"
        with self.assertRaises(CrossChannelBalanceError):
            analyze_supplied_cross_channel_balance(model)
        model = _model()
        model["events"][0]["amount_minor"] = True
        with self.assertRaises(CrossChannelBalanceError):
            analyze_supplied_cross_channel_balance(model)
        model = _model()
        model["events"][1]["event_id"] = "e1"
        with self.assertRaises(CrossChannelBalanceError):
            analyze_supplied_cross_channel_balance(model)
        model = _model()
        model["events"][0]["result"] = object()
        with self.assertRaises(CrossChannelBalanceError):
            analyze_supplied_cross_channel_balance(model)
        body = analyze_supplied_cross_channel_balance(_model()).to_dict()
        body["flags"]["duplicate_economic_effect_proven"] = True
        with self.assertRaises(CrossChannelBalanceError):
            CrossChannelBalance(body)
        report = analyze_supplied_cross_channel_balance(_model())
        changed = _model()
        changed["events"][0]["amount_minor"] = 31
        with self.assertRaises(CrossChannelBalanceError):
            verify_supplied_cross_channel_balance(report, model=changed)


if __name__ == "__main__":
    unittest.main()
