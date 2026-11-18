"""Telecom policy specialists preserve separate synthetic originals."""

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
        "task_id": "synthetic.telecom-policy-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-appliance", "offline-telecom-appliance-component.json"),
                ("b-rf", "offline-rf-receive-component.json"),
                ("c-mobile-core", "offline-mobile-core-component.json"),
                ("d-signaling", "offline-signaling-routes-component.json"),
                ("e-oran", "offline-oran-policy-targets-component.json"),
                ("f-esim", "offline-esim-profile-transitions-component.json"),
            )
        ],
    }


class OfflineTelecomPolicyCommonTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def test_six_specialists_preserve_originals_and_no_effects(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 6)
        self.assertEqual(body["distinct_profile_count"], 6)
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

    def test_late_grant_or_invalid_model_blocks_task(self) -> None:
        model = supplied_task()
        model["jobs"][5]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )
        dispatch.assert_not_called()
        model = supplied_task()
        model["jobs"][4]["request"]["payload"]["model"]["synthetic_fixture"] = False
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
