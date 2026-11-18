"""Repository and SaaS metadata stay separate in one inert GA-D01 task."""

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
        "task_id": "synthetic.repo-saas-recon-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-saas", "offline-saas-signal-component.json"),
                ("b-repo", "offline-repository-reference-component.json"),
            )
        ],
    }


class OfflineRepositoryReferenceTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_shared_commander_keeps_original_source_models_separate(self):
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 2)
        self.assertEqual(body["distinct_profile_count"], 2)
        self.assertEqual(
            [row["profile_id"] for row in body["ownership_index"]],
            ["AOE-GA-D01-S06", "AOE-GA-D01-S07"],
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GA-D01-CMD"},
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

    def test_network_grant_or_invalid_selector_aborts_whole_task(self):
        model = supplied_task()
        model["jobs"][1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()
        model = supplied_task()
        references = model["jobs"][1]["request"]["payload"]["model"]["references"]
        references[1]["selector"] = "not-a-commit"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
