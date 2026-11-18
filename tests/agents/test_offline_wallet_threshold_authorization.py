"""Supplied custody signer threshold and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_wallet_threshold_authorization import (
    WalletThresholdAuthorizationError,
    analyze_supplied_wallet_threshold,
    component_fixture,
    verify_supplied_wallet_threshold,
    verify_supplied_wallet_threshold_bytes,
)


class WalletThresholdAuthorizationTests(unittest.TestCase):
    def test_duplicate_signer_does_not_meet_threshold(self) -> None:
        model = component_fixture()
        report = analyze_supplied_wallet_threshold(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(body["action_projections"][0]["unique_eligible_approval_count"], 1)
        self.assertEqual(body["action_projections"][1]["unique_eligible_approval_count"], 2)
        self.assertFalse(body["signatures_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_wallet_threshold(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_wallet_threshold_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_unknown_signer_and_incomplete_approvals(self) -> None:
        model = component_fixture()
        action = model["policies"][0]["actions"][0]
        action["approval_signer_ids"].append("outsider")
        report = analyze_supplied_wallet_threshold(model).to_dict()
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["action_projections"][0]["unknown_signer_ids"], ["outsider"])
        action["approvals_complete"] = False
        self.assertEqual(analyze_supplied_wallet_threshold(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_wallet_threshold(model)
        changed = copy.deepcopy(model)
        changed["policies"][0]["actions"][0]["approval_signer_ids"].append("signer-b")
        with self.assertRaises(WalletThresholdAuthorizationError):
            verify_supplied_wallet_threshold(report, model=changed)
        with self.assertRaises(WalletThresholdAuthorizationError):
            verify_supplied_wallet_threshold(report.to_dict(), model=model)
        with self.assertRaises(WalletThresholdAuthorizationError):
            verify_supplied_wallet_threshold_bytes(b"{}", model=model)

    def test_rejects_duplicate_signer_policy_and_impossible_threshold(self) -> None:
        model = component_fixture()
        model["policies"][0]["eligible_signer_ids"][1] = "signer-a"
        with self.assertRaises(WalletThresholdAuthorizationError):
            analyze_supplied_wallet_threshold(model)
        model = component_fixture()
        model["policies"][0]["threshold"] = 4
        with self.assertRaises(WalletThresholdAuthorizationError):
            analyze_supplied_wallet_threshold(model)


if __name__ == "__main__":
    unittest.main()
