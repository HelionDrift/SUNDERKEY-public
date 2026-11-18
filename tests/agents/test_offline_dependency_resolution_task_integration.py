"""A supplied dependency candidate cannot acquire CI or task authority."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-ci", "offline-ci-workflow-trust-component.json"),
    ("b-dependency", "offline-dependency-resolution-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.supply-chain-review",
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


class OfflineDependencyResolutionTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_dependency_candidate_stays_separate_from_ci_projection(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        results = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        self.assertEqual(len(results[1]["analysis"]["collision_candidates"]), 1)
        self.assertFalse(results[1]["analysis"]["registry_behavior_verified"])
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
        self.assertEqual(result["job_count"], 2)
        self.assertEqual(result["distinct_profile_count"], 2)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            ["AOE-GC-D17-S02", "AOE-GC-D17-S08"],
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_resource_grant_in_last_job_is_denied_before_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_modified_original_invalidates_task_replay(self) -> None:
        model = supplied_task()
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        changed = copy.deepcopy(model)
        changed["jobs"][-1]["request"]["payload"]["model"]["evidence_complete"] = False
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=changed, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
