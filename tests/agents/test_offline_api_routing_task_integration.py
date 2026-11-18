"""Three synthetic API and URL projections retain independent ownership."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-rate", "offline-api-rate-limit-component.json"),
    ("b-url", "offline-url-navigation-component.json"),
    ("c-gateway", "offline-api-gateway-routes-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.api-routing-review",
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


class OfflineApiRoutingTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        results = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        self.assertEqual(results[0]["analysis"]["summary"]["candidate_admitted_over_limit"], 1)
        self.assertEqual(results[1]["analysis"]["projected_hop_count"], 3)
        self.assertEqual(len(results[2]["analysis"]["selections"]), 3)
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
            ["AOE-GB-D06-S13", "AOE-GB-D05-S05", "AOE-GB-D06-S07"],
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
        model["jobs"][-1]["request"]["resources"]["process"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_invalid_last_route_model_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["route_table"]["rewrite"] = "active"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
