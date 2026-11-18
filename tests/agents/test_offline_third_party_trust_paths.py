"""Supplied third-party trust-path projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_third_party_trust_paths import (
    ThirdPartyTrustPathsError,
    analyze_supplied_third_party_trust_paths,
    analyze_supplied_third_party_trust_paths_bytes,
    component_fixture,
    verify_supplied_third_party_trust_paths,
    verify_supplied_third_party_trust_paths_bytes,
)


class ThirdPartyTrustPathsTests(unittest.TestCase):
    def test_supplied_msp_mismatch_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_third_party_trust_paths(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], "AOE-GA-D04-S17")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(body["path_observations"][0]["denied_edge_ids"], ["service-delegation"])
        self.assertEqual(
            body["path_observations"][0]["disposition"],
            "candidate_supplied_authority_mismatch",
        )
        self.assertFalse(body["compromise_or_lateral_access_verified"])
        self.assertFalse(body["authority_enforcement_verified"])
        self.assertFalse(body["finding_claimed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_third_party_trust_paths(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_third_party_trust_paths_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analyze_supplied_third_party_trust_paths_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_json(),
            report.to_json(),
        )

    def test_matching_and_unknown_paths_do_not_create_candidates(self) -> None:
        model = component_fixture()
        model["paths"][0]["claimed_authorized"] = False
        body = analyze_supplied_third_party_trust_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["path_observations"][0]["disposition"], "matches_supplied_authority")
        model["edges"][1]["authority_state"] = "unknown"
        body = analyze_supplied_third_party_trust_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["path_observations"][0]["computed_authorized"])
        model["edges"][1]["authority_state"] = "authorized"
        model["inventory_complete"] = False
        body = analyze_supplied_third_party_trust_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        model["inventory_complete"] = True
        model["paths"][0]["context_complete"] = False
        self.assertEqual(
            analyze_supplied_third_party_trust_paths(model).to_dict()["unknown_count"], 1
        )

    def test_disabled_edge_and_inverse_mismatch(self) -> None:
        model = component_fixture()
        model["edges"][1]["authority_state"] = "authorized"
        model["edges"][1]["enabled"] = False
        body = analyze_supplied_third_party_trust_paths(model).to_dict()
        self.assertEqual(body["path_observations"][0]["disabled_edge_ids"], ["service-delegation"])
        self.assertEqual(body["candidate_count"], 1)
        model["edges"][1]["enabled"] = True
        model["paths"][0]["claimed_authorized"] = False
        body = analyze_supplied_third_party_trust_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertTrue(body["path_observations"][0]["computed_authorized"])

    def test_structural_and_closed_schema_rejection(self) -> None:
        model = component_fixture()
        model["paths"][0]["edge_ids"].reverse()
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["paths"][0]["entry_id"] = "first-party-service"
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["edges"][1]["authority_state"] = "inferred"
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["nodes"][0]["surprise"] = "not-allowed"
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["edges"].append(copy.deepcopy(model["edges"][0]))
        with self.assertRaises(ThirdPartyTrustPathsError):
            analyze_supplied_third_party_trust_paths(model)

    def test_original_change_and_forged_export_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_third_party_trust_paths(model)
        changed = copy.deepcopy(model)
        changed["edges"][1]["authority_state"] = "authorized"
        with self.assertRaises(ThirdPartyTrustPathsError):
            verify_supplied_third_party_trust_paths(report, model=changed)
        with self.assertRaises(ThirdPartyTrustPathsError):
            verify_supplied_third_party_trust_paths(report.to_dict(), model=model)
        forged = report.to_dict()
        forged["finding_claimed"] = True
        with self.assertRaises(ThirdPartyTrustPathsError):
            verify_supplied_third_party_trust_paths_bytes(
                json.dumps(forged).encode("ascii"), model=model
            )

    def test_non_native_and_over_budget_input_fail_closed(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["paths"][0]["edge_ids"].append("service-delegation")
        with self.assertRaises(ThirdPartyTrustPathsError):
            analyze_supplied_third_party_trust_paths(model)
        model = component_fixture()
        model["paths"][0]["edge_ids"][0] = {"not": "an-edge-id"}
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths(model)
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths_bytes(model_bytes=b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            analyze_supplied_third_party_trust_paths_bytes(model_bytes=b"x" * 65_537)


if __name__ == "__main__":
    unittest.main()
