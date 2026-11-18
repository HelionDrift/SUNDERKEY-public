"""Bounded AD FS and AD Connect declaration tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_hybrid_identity_mappings import (
    HybridIdentityMappingsError,
    analyze_supplied_hybrid_identity_mappings,
    component_fixture,
    verify_supplied_hybrid_identity_mappings,
    verify_supplied_hybrid_identity_mappings_bytes,
)


class HybridIdentityMappingsTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_mapping_mismatch(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        report = analyze_supplied_hybrid_identity_mappings(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 3)
        self.assertIn(
            "target_anchor_reused_across_enabled_mappings", body["rows"][0]["policy_issues"]
        )
        self.assertIn("issuer_outside_supplied_allowlist", body["rows"][2]["policy_issues"])
        self.assertFalse(body["token_or_claim_validated"])
        self.assertFalse(body["effective_access_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_hybrid_identity_mappings(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_hybrid_identity_mappings_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(), report.to_json()
        )

    def test_clean_and_incomplete_models(self) -> None:
        model = component_fixture()
        model["sync_mappings"][1]["target_anchor_ref"] = "target-anchor:sha256:" + "f" * 64
        model["federation_routes"][0]["issuer_ref"] = model["policy"]["allowed_issuer_refs"][0]
        self.assertEqual(
            analyze_supplied_hybrid_identity_mappings(model).to_dict()["candidate_count"], 0
        )
        model["inventory_complete"] = False
        model["sync_mappings"][1]["target_anchor_ref"] = model["sync_mappings"][0][
            "target_anchor_ref"
        ]
        body = analyze_supplied_hybrid_identity_mappings(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 3)
        self.assertIsNone(body["rows"][0]["policy_issues"])

    def test_disabled_declarations_do_not_report_mappings_match(self) -> None:
        model = component_fixture()
        for mapping in model["sync_mappings"]:
            mapping["enabled"] = False
        model["federation_routes"][0]["enabled"] = False
        body = analyze_supplied_hybrid_identity_mappings(model).to_dict()
        self.assertEqual(body["applicable_declaration_count"], 0)
        self.assertEqual(body["disposition"], "no_applicable_supplied_declarations")
        self.assertTrue(all(row["row_disposition"] == "not_applicable" for row in body["rows"]))

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        model["federation_routes"][0]["issuer_ref"] = "https://issuer.example"
        with self.assertRaises(ValueError):
            analyze_supplied_hybrid_identity_mappings(model)
        model = component_fixture()
        model["sync_mappings"].append(copy.deepcopy(model["sync_mappings"][0]))
        with self.assertRaises(ValueError):
            analyze_supplied_hybrid_identity_mappings(model)
        model = component_fixture()
        model["policy"]["require_unique_source_anchor"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_hybrid_identity_mappings(model)
        model = component_fixture()
        report = analyze_supplied_hybrid_identity_mappings(model)
        changed = copy.deepcopy(model)
        changed["federation_routes"][0]["enabled"] = False
        with self.assertRaises(HybridIdentityMappingsError):
            verify_supplied_hybrid_identity_mappings(report, model=changed)
        with self.assertRaises(HybridIdentityMappingsError):
            verify_supplied_hybrid_identity_mappings(report.to_dict(), model=model)
        with self.assertRaises(HybridIdentityMappingsError):
            verify_supplied_hybrid_identity_mappings_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_hybrid_identity_mappings_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()
