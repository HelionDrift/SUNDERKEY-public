"""Offline model output similarity regression tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_model_output_similarity import (
    ModelOutputSimilarityError,
    analyze_supplied_model_output_similarity,
    component_fixture,
    verify_supplied_model_output_similarity,
    verify_supplied_model_output_similarity_bytes,
)


class ModelOutputSimilarityTests(unittest.TestCase):
    def test_control_comparison_is_a_nonqualifying_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_model_output_similarity(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_match_count"], 3)
        self.assertEqual(body["control_match_count"], 0)
        self.assertEqual(body["disposition"], "candidate_declared_output_similarity_excess")
        self.assertEqual(body["candidate_count"], 1)
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["model_queried"])
        self.assertNotIn(model["challenge_matches"][0]["reference_output_sha256"], report.to_json())
        self.assertEqual(
            verify_supplied_model_output_similarity(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_model_output_similarity_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_control_match_and_incomplete_conditions_do_not_claim_extraction(self) -> None:
        model = component_fixture()
        for row in model["challenge_matches"]:
            row["control_output_sha256"] = row["reference_output_sha256"]
        self.assertEqual(
            analyze_supplied_model_output_similarity(model).to_dict()["disposition"],
            "no_declared_excess_match",
        )
        model["comparable_conditions"] = False
        self.assertEqual(
            analyze_supplied_model_output_similarity(model).to_dict()["unknown_count"], 1
        )
        model["comparable_conditions"] = True
        model["minimum_challenges"] = 4
        self.assertEqual(
            analyze_supplied_model_output_similarity(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_source_and_forged_report(self) -> None:
        model = component_fixture()
        report = analyze_supplied_model_output_similarity(model)
        changed = copy.deepcopy(model)
        changed["challenge_matches"][0]["candidate_output_sha256"] = changed["challenge_matches"][
            0
        ]["control_output_sha256"]
        with self.assertRaises(ModelOutputSimilarityError):
            verify_supplied_model_output_similarity(report, model=changed)
        with self.assertRaises(ModelOutputSimilarityError):
            verify_supplied_model_output_similarity(report.to_dict(), model=model)
        with self.assertRaises(ModelOutputSimilarityError):
            verify_supplied_model_output_similarity_bytes(b"{}", model=model)

    def test_rejects_invalid_digest_duplicate_and_boolean_integer(self) -> None:
        model = component_fixture()
        model["challenge_matches"][0]["reference_output_sha256"] = "sha256:BAD"
        with self.assertRaises(ModelOutputSimilarityError):
            analyze_supplied_model_output_similarity(model)
        model = component_fixture()
        model["challenge_matches"][1]["challenge_id"] = model["challenge_matches"][0][
            "challenge_id"
        ]
        with self.assertRaises(ModelOutputSimilarityError):
            analyze_supplied_model_output_similarity(model)
        model = component_fixture()
        model["minimum_challenges"] = True
        with self.assertRaises(ModelOutputSimilarityError):
            analyze_supplied_model_output_similarity(model)


if __name__ == "__main__":
    unittest.main()
