"""Mobile and model-safety specialists preserve distinct synthetic originals."""

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
        "task_id": "synthetic.mobile-model-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-android-instrument", "offline-android-instrumentation-trace-component.json"),
                ("b-android-trust", "offline-android-device-trust-trace-component.json"),
                ("c-ios-instrument", "offline-ios-instrumentation-trace-component.json"),
                ("d-ios-trust", "offline-ios-device-trust-trace-component.json"),
                ("e-instruction", "offline-direct-instruction-boundary-component.json"),
                ("f-media", "offline-multimodal-provenance-component.json"),
            )
        ],
    }


class OfflineMobileModelCommonTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def test_six_specialists_preserve_originals_and_distinct_commanders(self) -> None:
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
            {"AOE-GB-D08-CMD", "AOE-GD-D20-CMD"},
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
