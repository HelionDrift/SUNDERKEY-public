"""Trigger selectivity is a supplied count comparison, not a backdoor claim."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_model_trigger_selectivity as analysis

ROOT = Path(__file__).resolve().parents[2]


class ModelTriggerSelectivityTests(unittest.TestCase):
    def test_fixture_separates_selectivity_negative_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_model_trigger_selectivity(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 1)
        self.assertEqual(value["unknown_count"], 2)
        self.assertFalse(value["model_evaluation_performed"])
        self.assertFalse(value["trigger_generation_performed"])
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        rows = {row["comparison_id"]: row for row in value["comparison_projections"]}
        self.assertEqual(rows["large-gap"]["disposition"], "candidate_declared_trigger_selectivity")
        self.assertEqual(rows["small-gap"]["disposition"], "within_declared_rate_gap")
        self.assertEqual(rows["few-samples"]["disposition"], "unknown_insufficient_samples")
        self.assertEqual(rows["unknown"]["disposition"], "unknown")
        self.assertEqual(
            analysis.verify_supplied_model_trigger_selectivity(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_model_trigger_selectivity_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_exact_gap_threshold_is_not_a_candidate(self) -> None:
        model = analysis.component_fixture()
        model["comparisons"] = [copy.deepcopy(model["comparisons"][0])]
        model["comparisons"][0]["clean_target_count"] = 0
        model["comparisons"][0]["trigger_target_count"] = 50
        row = analysis.analyze_supplied_model_trigger_selectivity(model).to_dict()[
            "comparison_projections"
        ][0]
        self.assertFalse(row["exceeds_declared_rate_gap"])
        self.assertEqual(row["disposition"], "within_declared_rate_gap")

    def test_reverse_gap_is_not_selectivity(self) -> None:
        model = analysis.component_fixture()
        model["comparisons"] = [copy.deepcopy(model["comparisons"][0])]
        model["comparisons"][0]["clean_target_count"] = 90
        model["comparisons"][0]["trigger_target_count"] = 10
        row = analysis.analyze_supplied_model_trigger_selectivity(model).to_dict()[
            "comparison_projections"
        ][0]
        self.assertLess(row["signed_rate_gap_numerator_basis_points"], 0)
        self.assertEqual(row["disposition"], "within_declared_rate_gap")

    def test_invalid_counts_and_duplicate_comparisons_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["comparisons"][0].update(clean_trials=True),
            lambda m: m["comparisons"][0].update(clean_trials=0),
            lambda m: m["comparisons"][0].update(clean_target_count=101),
            lambda m: m["comparisons"].append(copy.deepcopy(m["comparisons"][0])),
            lambda m: m.update(minimum_rate_gap_basis_points=10_001),
            lambda m: m["comparisons"][0].update(context_complete="yes"),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_model_trigger_selectivity(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_model_trigger_selectivity(model)
        changed = copy.deepcopy(model)
        changed["comparisons"][0]["trigger_target_count"] = 79
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_model_trigger_selectivity(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_model_trigger_selectivity_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_has_no_trigger_content_or_resources(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-model-trigger-selectivity-component.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(request["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(request["component_id"], analysis.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(request["payload"]["model"], analysis.component_fixture())


if __name__ == "__main__":
    unittest.main()
