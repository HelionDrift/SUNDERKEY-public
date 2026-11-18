"""Training label-share drift is exact and does not read dataset records."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_training_label_drift as analysis

ROOT = Path(__file__).resolve().parents[2]


class TrainingLabelDriftTests(unittest.TestCase):
    def test_fixture_projects_two_declared_share_drifts(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_training_label_drift(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 2)
        self.assertEqual(value["unknown_count"], 0)
        self.assertEqual(value["baseline_total"], 100)
        self.assertEqual(value["candidate_total"], 100)
        self.assertFalse(value["training_data_read"])
        self.assertFalse(value["model_training_performed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        rows = value["label_projections"]
        self.assertEqual([row["label_id"] for row in rows], ["class-a", "class-b"])
        self.assertTrue(all(row["exceeds_declared_limit"] for row in rows))
        self.assertEqual(
            analysis.verify_supplied_training_label_drift(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_training_label_drift_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_exact_threshold_is_not_a_candidate(self) -> None:
        model = analysis.component_fixture()
        model["candidate_counts"][0]["count"] = 70
        model["candidate_counts"][1]["count"] = 30
        value = analysis.analyze_supplied_training_label_drift(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(
            [row["disposition"] for row in value["label_projections"]],
            ["within_declared_share_limit", "within_declared_share_limit"],
        )

    def test_incomplete_declarations_abstain_from_drift(self) -> None:
        model = analysis.component_fixture()
        model["declaration_complete"] = False
        value = analysis.analyze_supplied_training_label_drift(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 2)

    def test_invalid_counts_and_duplicate_labels_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["baseline_counts"][0].update(count=True),
            lambda m: m["baseline_counts"][0].update(count=-1),
            lambda m: m["baseline_counts"][0].update(count=100_001),
            lambda m: m["baseline_counts"].append(copy.deepcopy(m["baseline_counts"][0])),
            lambda m: m.update(candidate_dataset_id="dataset-before"),
            lambda m: m.update(maximum_share_delta_basis_points=10_001),
            lambda m: m["candidate_counts"][0].update(label_id=[]),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_training_label_drift(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_training_label_drift(model)
        changed = copy.deepcopy(model)
        changed["candidate_counts"][0]["count"] = 70
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_training_label_drift(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_training_label_drift_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-training-label-drift-component.json").read_text(
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
