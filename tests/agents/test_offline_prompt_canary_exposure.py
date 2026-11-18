"""Offline exact protected-canary exposure regression tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_prompt_canary_exposure import (
    PromptCanaryExposureError,
    analyze_supplied_prompt_canaries,
    component_fixture,
    verify_supplied_prompt_canaries,
    verify_supplied_prompt_canaries_bytes,
)


class PromptCanaryExposureTests(unittest.TestCase):
    def test_exact_match_is_source_bound_without_reemitting_content(self) -> None:
        model = component_fixture()
        report = analyze_supplied_prompt_canaries(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(body["output_projections"][0]["matched_canary_ids"], ["canary-one"])
        self.assertEqual(body["output_projections"][1]["disposition"], "no_exact_canary_match")
        self.assertFalse(body["protected_content_reemitted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertNotIn(model["outputs"][0]["content"], report.to_json())
        self.assertNotIn("SYNTHETIC-CANARY-ONLY", report.to_json())
        self.assertEqual(
            verify_supplied_prompt_canaries(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_prompt_canaries_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_missing_context_stays_unknown_even_with_exact_match(self) -> None:
        model = component_fixture()
        model["canary_distribution_known"] = False
        body = analyze_supplied_prompt_canaries(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 2)
        self.assertEqual(body["output_projections"][0]["matched_canary_ids"], ["canary-one"])

    def test_replay_rejects_source_change_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_prompt_canaries(model)
        changed = copy.deepcopy(model)
        changed["outputs"][0]["content"] = "No canary appears"
        with self.assertRaises(PromptCanaryExposureError):
            verify_supplied_prompt_canaries(report, model=changed)
        with self.assertRaises(PromptCanaryExposureError):
            verify_supplied_prompt_canaries(report.to_dict(), model=model)
        with self.assertRaises(PromptCanaryExposureError):
            verify_supplied_prompt_canaries_bytes(b"{}", model=model)

    def test_rejects_duplicate_canary_bad_digest_and_nontext_output(self) -> None:
        model = component_fixture()
        model["protected_canaries"].append(copy.deepcopy(model["protected_canaries"][0]))
        with self.assertRaises(PromptCanaryExposureError):
            analyze_supplied_prompt_canaries(model)
        model = component_fixture()
        model["protected_canaries"][0]["sha256"] = "sha256:BAD"
        with self.assertRaises(PromptCanaryExposureError):
            analyze_supplied_prompt_canaries(model)
        model = component_fixture()
        model["outputs"][0]["content"] = 5
        with self.assertRaises(PromptCanaryExposureError):
            analyze_supplied_prompt_canaries(model)


if __name__ == "__main__":
    unittest.main()
