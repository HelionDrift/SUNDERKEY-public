"""Artifact integrity and serialization risk stay separate in one inert task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


class OfflineAiArtifactTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_matching_digest_does_not_override_pickle_opcode_risk(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.model-artifact-review",
            "jobs": [
                {
                    "job_id": "a-serialization",
                    "request": components.load_offline_specialist_component_request(
                        ROOT / "examples/offline-pickle-opcode-safety-component.json"
                    ),
                },
                {
                    "job_id": "b-artifact-integrity",
                    "request": components.load_offline_specialist_component_request(
                        ROOT / "examples/offline-model-artifact-integrity-component.json"
                    ),
                },
            ],
        }
        original = copy.deepcopy(model)
        analyses = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        for index, result in enumerate(analyses):
            self.assertFalse(result["full_candidate_assembled"])
            self.assertFalse(result["positive_use_approved"])
            self.assertEqual(set(result["operational_effects"].values()), {"none"})
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    result,
                    request=model["jobs"][index]["request"],
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                result,
            )
        opcode_row = next(
            row for row in analyses[0]["analysis"]["artifact_projections"]
            if row["artifact_id"] == "global-allowed"
        )
        integrity_row = next(
            row for row in analyses[1]["analysis"]["artifact_projections"]
            if row["artifact_id"] == "pickle-risky"
        )
        self.assertEqual(opcode_row["artifact_sha256"], integrity_row["artifact_sha256"])
        self.assertEqual(opcode_row["disposition"], "candidate_risky_pickle_opcode")
        self.assertEqual(integrity_row["disposition"], "declared_matching_digest_unverified")
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 2)
        self.assertEqual(result["distinct_profile_count"], 2)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            ["AOE-GD-D20-S07", "AOE-GD-D20-S08"],
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )


if __name__ == "__main__":
    unittest.main()
