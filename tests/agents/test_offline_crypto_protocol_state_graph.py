"""Supplied cryptographic protocol state projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_crypto_protocol_state_graph import (
    CryptoProtocolStateGraphError,
    CryptoProtocolStateGraphReport,
    analyze_supplied_crypto_protocol,
    component_fixture,
    verify_supplied_crypto_protocol,
)


class CryptoProtocolStateGraphTests(unittest.TestCase):
    def test_authenticated_projection_has_no_unmarked_path(self) -> None:
        report = analyze_supplied_crypto_protocol(component_fixture()).to_dict()
        self.assertIsNone(report["acceptance_without_supplied_auth_marker_path_ids"])
        self.assertEqual(report["reachable_state_ids"], ["accepted", "authenticated", "start"])
        self.assertFalse(report["authentication_verified"])
        self.assertEqual(report["candidate_count"], 0)

    def test_shortest_unmarked_path_is_only_a_supplied_graph_fact(self) -> None:
        model = component_fixture()
        model["transitions"].append({
            "transition_id": "direct", "from_state_id": "start", "to_state_id": "accepted",
            "asserted_peer_authentication": False,
        })
        report = analyze_supplied_crypto_protocol(model).to_dict()
        self.assertEqual(report["acceptance_without_supplied_auth_marker_path_ids"], ["direct"])
        self.assertFalse(report["finding_claimed"])

    def test_incomplete_inventory_and_unresolved_transition(self) -> None:
        model = component_fixture()
        model["state_inventory_complete"] = False
        report = analyze_supplied_crypto_protocol(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        model = component_fixture()
        model["transitions"][0]["to_state_id"] = "absent"
        with self.assertRaises(CryptoProtocolStateGraphError):
            analyze_supplied_crypto_protocol(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_crypto_protocol(model)
        self.assertEqual(
            verify_supplied_crypto_protocol(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["transitions"][0]["asserted_peer_authentication"] = False
        with self.assertRaises(CryptoProtocolStateGraphError):
            verify_supplied_crypto_protocol(report, model=changed)
        with self.assertRaises(CryptoProtocolStateGraphError):
            CryptoProtocolStateGraphReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
