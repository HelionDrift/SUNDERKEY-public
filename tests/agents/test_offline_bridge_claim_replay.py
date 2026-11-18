"""Offline supplied bridge-claim grouping and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_bridge_claim_replay import (
    BridgeClaimReplayError,
    analyze_supplied_bridge_claims,
    component_fixture,
    verify_supplied_bridge_claims,
    verify_supplied_bridge_claims_bytes,
)


class BridgeClaimReplayTests(unittest.TestCase):
    def test_duplicate_accepted_claims_are_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_bridge_claims(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["message_projections"][0]["duplicate_destination_groups"],
            [{"destination_chain_id": "chain-b", "accepted_claim_ids": ["claim-one", "claim-two"]}],
        )
        self.assertFalse(body["finality_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_bridge_claims(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_bridge_claims_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_uncertainty_and_distinct_destinations(self) -> None:
        model = component_fixture()
        model["messages"][0]["claims"][1]["destination_chain_id"] = "chain-c"
        self.assertEqual(analyze_supplied_bridge_claims(model).to_dict()["candidate_count"], 0)
        model["messages"][0]["finalized"] = None
        self.assertEqual(analyze_supplied_bridge_claims(model).to_dict()["unknown_count"], 1)
        model["messages"][0]["finalized"] = True
        model["messages"][0]["claims"][2]["outcome"] = "unknown"
        self.assertEqual(analyze_supplied_bridge_claims(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_bridge_claims(model)
        changed = copy.deepcopy(model)
        changed["messages"][0]["claims"][1]["outcome"] = "rejected"
        with self.assertRaises(BridgeClaimReplayError):
            verify_supplied_bridge_claims(report, model=changed)
        with self.assertRaises(BridgeClaimReplayError):
            verify_supplied_bridge_claims(report.to_dict(), model=model)
        with self.assertRaises(BridgeClaimReplayError):
            verify_supplied_bridge_claims_bytes(b"{}", model=model)

    def test_rejects_duplicate_message_and_invalid_digest(self) -> None:
        model = component_fixture()
        model["messages"].append(copy.deepcopy(model["messages"][0]))
        with self.assertRaises(BridgeClaimReplayError):
            analyze_supplied_bridge_claims(model)
        model = component_fixture()
        model["messages"][0]["payload_sha256"] = "sha256:wrong"
        with self.assertRaises(BridgeClaimReplayError):
            analyze_supplied_bridge_claims(model)


if __name__ == "__main__":
    unittest.main()
