"""Three synthetic record reviewers keep distinct ownership and original models."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.cross-domain-record-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-social", "offline-activitystreams-create-component.json"),
                ("b-power", "offline-power-recovery-cadence-component.json"),
                ("c-operator", "offline-operator-offboarding-component.json"),
            )
        ],
    }


class OfflineCrossDomainRecordReviewTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def test_distinct_ownership_originals_and_no_effects(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 3)
        self.assertEqual(body["distinct_profile_count"], 3)
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GA-D02-CMD", "AOE-GD-D19-CMD"},
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["qualification_claimed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(), report.to_json(),
        )

    def test_nonsynthetic_job_blocks_whole_task(self) -> None:
        model = supplied_task()
        model["jobs"][1]["request"]["payload"]["model"]["synthetic_fixture"] = False
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
