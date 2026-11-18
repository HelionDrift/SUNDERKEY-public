"""Three supplied reconnaissance sources retain one commander and separate claims."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.recon-source-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-dns", "offline-dns-zone-component.json"),
                ("b-prefix", "offline-prefix-origin-component.json"),
                ("c-cloud", "offline-cloud-inventory-drift-component.json"),
            )
        ],
    }


class OfflineCloudInventoryTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_recon_specialists_keep_separate_inputs_under_one_commander(self):
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 3)
        self.assertEqual(body["distinct_component_count"], 3)
        self.assertEqual(body["distinct_profile_count"], 3)
        self.assertEqual(
            [row["profile_id"] for row in body["ownership_index"]],
            ["AOE-GA-D01-S03", "AOE-GA-D01-S04", "AOE-GA-D01-S05"],
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GA-D01-CMD"},
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["qualification_claimed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_late_cloud_resource_grant_or_duplicate_snapshot_prevents_publication(self):
        model = supplied_task()
        model["jobs"][2]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()
        model = supplied_task()
        snapshots = model["jobs"][2]["request"]["payload"]["model"]["snapshots"]
        snapshots[1]["snapshot_id"] = snapshots[0]["snapshot_id"]
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
