"""Bounded NTLM control-pair declaration tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ntlm_control_pairs import (
    NtlmControlPairsError,
    analyze_supplied_ntlm_control_pairs,
    component_fixture,
    verify_supplied_ntlm_control_pairs,
    verify_supplied_ntlm_control_pairs_bytes,
)


class NtlmControlPairsTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_control_gap(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        report = analyze_supplied_ntlm_control_pairs(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(len(body["rows"][0]["policy_issues"]), 3)
        self.assertFalse(body["coercion_or_relay_attempted"])
        self.assertFalse(body["relay_feasibility_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_ntlm_control_pairs(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_ntlm_control_pairs_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(), report.to_json()
        )

    def test_clean_and_incomplete_models(self) -> None:
        model = component_fixture()
        pair = model["pairs"][0]
        pair["target_signing_required"] = True
        pair["target_epa_required"] = True
        pair["channel_binding_declared"] = True
        self.assertEqual(analyze_supplied_ntlm_control_pairs(model).to_dict()["candidate_count"], 0)
        model["inventory_complete"] = False
        pair["target_signing_required"] = False
        body = analyze_supplied_ntlm_control_pairs(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["rows"][0]["policy_issues"])

    def test_no_applicable_pair_does_not_report_controls_match(self) -> None:
        model = component_fixture()
        model["pairs"][0]["source_ntlm_offered"] = False
        body = analyze_supplied_ntlm_control_pairs(model).to_dict()
        self.assertEqual(body["applicable_pair_count"], 0)
        self.assertEqual(body["disposition"], "no_applicable_supplied_pairs")
        self.assertEqual(body["rows"][0]["row_disposition"], "not_applicable")
        self.assertIsNone(body["rows"][0]["policy_issues"])

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        model["pairs"][0]["target_ref"] = "localhost"
        with self.assertRaises(ValueError):
            analyze_supplied_ntlm_control_pairs(model)
        model = component_fixture()
        model["pairs"].append(copy.deepcopy(model["pairs"][0]))
        with self.assertRaises(ValueError):
            analyze_supplied_ntlm_control_pairs(model)
        model = component_fixture()
        model["policy"]["require_target_signing"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_ntlm_control_pairs(model)
        model = component_fixture()
        report = analyze_supplied_ntlm_control_pairs(model)
        changed = copy.deepcopy(model)
        changed["pairs"][0]["target_epa_required"] = True
        with self.assertRaises(NtlmControlPairsError):
            verify_supplied_ntlm_control_pairs(report, model=changed)
        with self.assertRaises(NtlmControlPairsError):
            verify_supplied_ntlm_control_pairs(report.to_dict(), model=model)
        with self.assertRaises(NtlmControlPairsError):
            verify_supplied_ntlm_control_pairs_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_ntlm_control_pairs_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()
