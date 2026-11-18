"""Five supplied API and DOM projections retain distinct specialist owners."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-object", "offline-api-object-authorization-component.json"),
    ("b-function", "offline-api-function-authorization-component.json"),
    ("c-inventory", "offline-api-inventory-drift-component.json"),
    ("d-downstream", "offline-api-downstream-trust-component.json"),
    ("e-dom", "offline-dom-dataflow-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.api-authorization-flow-review",
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


class OfflineApiAuthorizationFlowTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_five_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        results = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        self.assertGreater(results[0]["analysis"]["summary"]["candidate_policy_contradiction"], 0)
        self.assertGreater(results[1]["analysis"]["candidate_contradiction_count"], 0)
        self.assertGreater(len(results[2]["analysis"]["undeclared_route_candidates"]), 0)
        self.assertGreater(len(results[3]["analysis"]["candidate_paths"]), 0)
        self.assertGreater(results[4]["analysis"]["candidate_path_count"], 0)
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
        self.assertEqual(result["job_count"], 5)
        self.assertEqual(result["distinct_component_count"], 5)
        self.assertEqual(result["distinct_profile_count"], 5)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            [
                "AOE-GB-D06-S09",
                "AOE-GB-D06-S10",
                "AOE-GB-D06-S14",
                "AOE-GB-D06-S15",
                "AOE-GB-D05-S13",
            ],
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

    def test_late_resource_grant_is_denied_before_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_late_invalid_model_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["graph_complete"] = "true"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
