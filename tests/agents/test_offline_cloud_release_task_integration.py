"""Cloud and release assertions remain inert when combined in one task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-release", "offline-cd-release-provenance-component.json"),
    ("b-admission", "offline-kubernetes-admission-boundary-component.json"),
    ("c-federation", "offline-multicloud-federation-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.cloud-release-review",
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


class OfflineCloudReleaseTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_source_bound_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        for job in model["jobs"]:
            result = components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
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
            ["AOE-GC-D17-S03", "AOE-GC-D15-S08", "AOE-GC-D14-S09"],
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
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_invalid_last_model_does_not_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["unexpected_field"] = True
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
