"""Supplied cross-endpoint RPC response and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_rpc_response_discrepancy import (
    RpcResponseDiscrepancyError,
    analyze_supplied_rpc_responses,
    component_fixture,
    verify_supplied_rpc_responses,
    verify_supplied_rpc_responses_bytes,
)


class RpcResponseDiscrepancyTests(unittest.TestCase):
    def test_different_endpoint_results_are_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rpc_responses(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(len(body["query_projections"][0]["result_groups"]), 2)
        self.assertFalse(body["endpoints_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_rpc_responses(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_rpc_responses_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_same_endpoint_does_not_claim_cross_endpoint_discrepancy(self) -> None:
        model = component_fixture()
        model["observations"][1]["endpoint_id"] = "node-a"
        self.assertEqual(analyze_supplied_rpc_responses(model).to_dict()["candidate_count"], 0)
        model["observations"][1]["block_finalized"] = False
        self.assertEqual(analyze_supplied_rpc_responses(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rpc_responses(model)
        changed = copy.deepcopy(model)
        changed["observations"][1]["result_sha256"] = "sha256:" + "4" * 64
        with self.assertRaises(RpcResponseDiscrepancyError):
            verify_supplied_rpc_responses(report, model=changed)
        with self.assertRaises(RpcResponseDiscrepancyError):
            verify_supplied_rpc_responses(report.to_dict(), model=model)
        with self.assertRaises(RpcResponseDiscrepancyError):
            verify_supplied_rpc_responses_bytes(b"{}", model=model)

    def test_rejects_duplicate_observation_and_invalid_digest(self) -> None:
        model = component_fixture()
        model["observations"][1]["observation_id"] = "observation-one"
        with self.assertRaises(RpcResponseDiscrepancyError):
            analyze_supplied_rpc_responses(model)
        model = component_fixture()
        model["observations"][0]["params_sha256"] = "sha256:wrong"
        with self.assertRaises(RpcResponseDiscrepancyError):
            analyze_supplied_rpc_responses(model)


if __name__ == "__main__":
    unittest.main()
