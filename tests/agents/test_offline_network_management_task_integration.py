"""Two management specialists retain separate originals in one inert task."""

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
        "task_id": "synthetic.network-management-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-snmp-view", "offline-snmp-view-component.json"),
                ("b-sdwan-overlay", "offline-sdwan-overlay-component.json"),
            )
        ],
    }


class OfflineNetworkManagementTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_with_checked_catalog(self, model: dict) -> task.OfflineSpecialistTaskResult:
        with patch.object(components, "_catalog_document", return_value=self.catalog.to_dict()):
            return task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )

    def test_two_management_specialists_keep_separate_sources_and_commander(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 2)
        self.assertEqual(body["distinct_component_count"], 2)
        self.assertEqual(body["distinct_profile_count"], 2)
        self.assertEqual(
            [row["profile_id"] for row in body["ownership_index"]],
            ["AOE-GC-D13-S15", "AOE-GC-D13-S21"],
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GC-D13-CMD"},
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

    def test_late_network_grant_or_undeclared_secret_blocks_publication(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            self.run_with_checked_catalog(model)
        dispatch.assert_not_called()
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["bindings"][0]["community"] = "forbidden"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.run_with_checked_catalog(model)
        model = supplied_task()
        model["jobs"][1]["request"]["payload"]["model"]["tunnel_key"] = "forbidden"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.run_with_checked_catalog(model)


if __name__ == "__main__":
    unittest.main()
