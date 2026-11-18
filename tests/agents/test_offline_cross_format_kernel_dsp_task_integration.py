"""Supplied binary and minidump specialists retain distinct requests."""

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
        "task_id": "synthetic.binary-artifact-survey",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-macho", "offline-apple-kernel-macho-markers-component.json"),
                ("b-elf32", "offline-hexagon-elf32-layout-component.json"),
                ("c-minidump", "offline-browser-minidump-directory-component.json"),
                ("d-pe-triage", "offline-pe-packing-triage-component.json"),
            )
        ],
    }


class OfflineCrossFormatKernelDspTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def test_four_specialists_preserve_originals_and_no_effects(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 4)
        self.assertEqual(body["distinct_profile_count"], 4)
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GE-D21-CMD"},
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

    def test_late_grant_and_nonsynthetic_source_block_task(self) -> None:
        model = supplied_task()
        model["jobs"][1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )
        dispatch.assert_not_called()
        model = supplied_task()
        model["jobs"][1]["request"]["payload"]["model"]["synthetic_fixture"] = False
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
