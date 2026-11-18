"""Three inert web and API projections retain their own source and ownership."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-property", "offline-property-authorization-component.json"),
    ("b-cache", "offline-cache-key-differential-component.json"),
    ("c-content-type", "offline-content-type-differential-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.api-property-cache-review",
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


class OfflineApiPropertyCacheTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_complete_supplied_leaves_preserve_distinct_owners_and_replay(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        component_results = [
            components.run_offline_specialist_component(
                item["request"], catalog=self.catalog, repository_root=ROOT
            )
            for item in model["jobs"]
        ]
        self.assertEqual(component_results[0]["analysis"]["summary"]["declared_prohibited"], 1)
        self.assertEqual(component_results[1]["analysis"]["candidate_signal_count"], 1)
        self.assertGreater(len(component_results[2]["analysis"]["differences"]), 0)
        for job, result in zip(model["jobs"], component_results, strict=True):
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
            ["AOE-GB-D06-S11", "AOE-GB-D05-S04", "AOE-GB-D06-S12"],
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
        changed = copy.deepcopy(original)
        changed["jobs"][0]["request"]["payload"]["model"]["after"]["profile"]["role"] = "member"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_late_resource_grant_is_denied_before_any_leaf_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_last_invalid_content_type_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["form_request"]["body"] = "active=%ZZ"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
