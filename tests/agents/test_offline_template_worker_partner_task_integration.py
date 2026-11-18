"""Synthetic template, service-worker and connector models retain distinct owners."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-template", "offline-template-context-component.json"),
    ("b-worker", "offline-service-worker-scope-component.json"),
    ("c-partner", "offline-partner-connector-trust-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.template-worker-partner-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in EXAMPLES
        ],
    }


class OfflineTemplateWorkerPartnerTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_source_bound_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        results = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        self.assertIn(
            "candidate_declared_unescaped_flow",
            {row["disposition"] for row in results[0]["analysis"]["slot_projections"]},
        )
        self.assertGreater(results[1]["analysis"]["summary"]["candidate_control_contradiction"], 0)
        self.assertGreater(results[2]["analysis"]["candidate_count"], 0)
        for job, result in zip(model["jobs"], results, strict=True):
            self.assertFalse(result["full_candidate_assembled"])
            self.assertFalse(result["positive_use_approved"])
            self.assertEqual(set(result["operational_effects"].values()), {"none"})
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    result,
                    request=job["request"],
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                result,
            )
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 3)
        self.assertEqual(result["distinct_component_count"], 3)
        self.assertEqual(result["distinct_profile_count"], 3)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            ["AOE-GB-D05-S09", "AOE-GB-D05-S16", "AOE-GB-D06-S16"],
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["qualification_claimed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_late_resource_grant_denies_all_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["credential"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_invalid_last_model_does_not_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["transfers"][0]["observed_outcome"] = 7
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
