"""Supplied zero-fee token transfer arithmetic and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_token_transfer_arithmetic import (
    TokenTransferArithmeticError,
    analyze_supplied_token_transfers,
    component_fixture,
    verify_supplied_token_transfers,
    verify_supplied_token_transfers_bytes,
)


class TokenTransferArithmeticTests(unittest.TestCase):
    def test_balance_mismatch_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_token_transfers(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertFalse(body["transfer_projections"][0]["sender_matches"])
        self.assertTrue(body["transfer_projections"][1]["sender_matches"])
        self.assertFalse(body["token_contract_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_token_transfers(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_token_transfers_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_reconciled_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["transfers"][0]["sender_after_units"] = 80
        self.assertEqual(analyze_supplied_token_transfers(model).to_dict()["candidate_count"], 0)
        model["transfers"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_token_transfers(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_token_transfers(model)
        changed = copy.deepcopy(model)
        changed["transfers"][0]["amount_units"] = 21
        with self.assertRaises(TokenTransferArithmeticError):
            verify_supplied_token_transfers(report, model=changed)
        with self.assertRaises(TokenTransferArithmeticError):
            verify_supplied_token_transfers(report.to_dict(), model=model)
        with self.assertRaises(TokenTransferArithmeticError):
            verify_supplied_token_transfers_bytes(b"{}", model=model)

    def test_rejects_duplicate_and_self_transfer(self) -> None:
        model = component_fixture()
        model["transfers"][1]["transfer_id"] = "transfer-one"
        with self.assertRaises(TokenTransferArithmeticError):
            analyze_supplied_token_transfers(model)
        model = component_fixture()
        model["transfers"][0]["recipient_id"] = "account-a"
        with self.assertRaises(TokenTransferArithmeticError):
            analyze_supplied_token_transfers(model)


if __name__ == "__main__":
    unittest.main()
