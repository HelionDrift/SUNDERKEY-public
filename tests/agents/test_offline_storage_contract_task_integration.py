"""Cloud-storage and contract-state specialists retain independent sources."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-s3-controls", "offline-s3-public-grant-controls-component.json"),
    ("b-proxy-layout", "offline-proxy-storage-layout-component.json"),
    ("c-state-order", "offline-reentrancy-state-order-component.json"),
)


class OfflineStorageContractTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_sources_compose_without_shared_authority(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.storage-contract-review",
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
        value = report.to_dict()
        self.assertEqual(value["model"], original)
        self.assertEqual(value["job_count"], 3)
        self.assertEqual(value["distinct_component_count"], 3)
        self.assertEqual(value["distinct_profile_count"], 3)
        self.assertEqual(
            [row["profile_id"] for row in value["ownership_index"]],
            ["AOE-GC-D14-S11", "AOE-GB-D10-S07", "AOE-GB-D10-S08"],
        )
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertFalse(value["qualification_claimed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )


if __name__ == "__main__":
    unittest.main()
