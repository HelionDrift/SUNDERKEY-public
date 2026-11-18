"""Supplied evasion trials use exact integer arithmetic without model calls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_evasion_delta_measurement as analysis

ROOT = Path(__file__).resolve().parents[2]


class EvasionDeltaMeasurementTests(unittest.TestCase):
    def test_fixture_distinguishes_within_outside_unchanged_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_evasion_deltas(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 1)
        self.assertEqual(value["unknown_count"], 1)
        self.assertFalse(value["model_evaluation_performed"])
        self.assertFalse(value["input_generation_performed"])
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        rows = {row["trial_id"]: row for row in value["trial_projections"]}
        self.assertEqual(
            rows["within-flip"]["disposition"],
            "candidate_declared_within_budget_label_change",
        )
        self.assertEqual(rows["within-flip"]["linf_delta"], 1)
        self.assertEqual(rows["within-flip"]["l2_squared_delta"], 1)
        self.assertEqual(rows["within-flip"]["changed_coordinate_count"], 1)
        self.assertFalse(rows["outside-flip"]["within_declared_budget"])
        self.assertEqual(rows["no-flip"]["disposition"], "declared_label_unchanged")
        self.assertEqual(rows["unknown"]["disposition"], "unknown")
        self.assertEqual(
            analysis.verify_supplied_evasion_deltas(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_evasion_deltas_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_exact_budget_and_zero_budget_edges(self) -> None:
        model = analysis.component_fixture()
        model["trials"] = [copy.deepcopy(model["trials"][0])]
        row = analysis.analyze_supplied_evasion_deltas(model).to_dict()["trial_projections"][0]
        self.assertTrue(row["within_declared_budget"])
        model["maximum_linf_delta"] = 0
        row = analysis.analyze_supplied_evasion_deltas(model).to_dict()["trial_projections"][0]
        self.assertFalse(row["within_declared_budget"])
        self.assertEqual(row["disposition"], "declared_label_change_outside_budget")
        model["trials"][0]["candidate_vector"] = [0, 0]
        model["maximum_l2_squared"] = 0
        row = analysis.analyze_supplied_evasion_deltas(model).to_dict()["trial_projections"][0]
        self.assertEqual(row["linf_delta"], 0)
        self.assertEqual(row["l2_squared_delta"], 0)
        self.assertEqual(row["disposition"], "unknown_identical_vector_label_conflict")

    def test_incomplete_context_abstains_even_when_labels_change(self) -> None:
        model = analysis.component_fixture()
        model["trials"] = [copy.deepcopy(model["trials"][0])]
        model["trials"][0]["context_complete"] = False
        value = analysis.analyze_supplied_evasion_deltas(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 1)

    def test_invalid_vectors_and_labels_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["trials"][0].update(candidate_vector=[1]),
            lambda m: m["trials"][0].update(candidate_vector=[True, 0]),
            lambda m: m["trials"][0].update(candidate_vector=[10_001, 0]),
            lambda m: m["trials"][0].update(baseline_label=[]),
            lambda m: m.update(maximum_l2_squared=-1),
            lambda m: m["trials"].append(copy.deepcopy(m["trials"][0])),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_evasion_deltas(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_evasion_deltas(model)
        changed = copy.deepcopy(model)
        changed["trials"][0]["candidate_label"] = "class-a"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_evasion_deltas(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_evasion_deltas_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-evasion-delta-measurement-component.json").read_text(
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
