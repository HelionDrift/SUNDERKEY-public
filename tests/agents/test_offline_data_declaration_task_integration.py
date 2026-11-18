"""Nine supplied data-system models collaborate without operational inference."""

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
        "task_id": "synthetic.data-declaration-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-relational", "offline-relational-grant-path-component.json"),
                ("b-search", "offline-search-alias-component.json"),
                ("c-backup", "offline-backup-chain-component.json"),
                ("d-stream", "offline-stream-offset-component.json"),
                ("e-etl", "offline-etl-watermark-component.json"),
                ("f-graph", "offline-graph-tenant-routes-component.json"),
                ("g-warehouse", "offline-warehouse-lineage-component.json"),
                ("h-spark", "offline-spark-job-plan-component.json"),
                ("i-analytics", "offline-analytics-sharing-component.json"),
            )
        ],
    }


class DataDeclarationTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_separate_models_share_existing_data_commander(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 9)
        self.assertEqual(body["distinct_profile_count"], 9)
        self.assertEqual(
            {row["profile_id"] for row in body["ownership_index"]},
            {
                "AOE-GB-D07-S01",
                "AOE-GB-D07-S06",
                "AOE-GB-D07-S08",
                "AOE-GB-D07-S11",
                "AOE-GB-D07-S13",
                "AOE-GB-D07-S03",
                "AOE-GB-D07-S09",
                "AOE-GB-D07-S10",
                "AOE-GB-D07-S12",
            },
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GB-D07-CMD"},
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_resource_grant_or_invalid_parent_aborts_whole_task(self) -> None:
        model = supplied_task()
        model["jobs"][1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()
        model = supplied_task()
        model["jobs"][2]["request"]["payload"]["model"]["snapshots"][1]["parent_snapshot_id"] = (
            "missing"
        )
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        model = supplied_task()
        model["jobs"][3]["request"]["payload"]["model"]["history_complete"] = 1
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        model = supplied_task()
        model["jobs"][4]["request"]["payload"]["model"]["dependencies"][0]["upstream_step_ref"] = (
            "unknown"
        )
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
