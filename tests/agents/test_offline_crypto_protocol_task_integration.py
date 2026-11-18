"""Four crypto specialists retain separate originals in one inert task."""

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
        "task_id": "synthetic.crypto-protocol-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-protocol", "offline-crypto-protocol-state-component.json"),
                ("b-rng", "offline-rng-sample-component.json"),
                ("c-epochs", "offline-e2ee-epoch-component.json"),
                ("d-framing", "offline-custom-protocol-framing-component.json"),
            )
        ],
    }


class OfflineCryptoProtocolTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def test_four_specialists_replay_separate_sources_under_one_commander(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 4)
        self.assertEqual(body["distinct_component_count"], 4)
        self.assertEqual(body["distinct_profile_count"], 4)
        self.assertEqual(
            [row["profile_id"] for row in body["ownership_index"]],
            [
                "AOE-GE-D22-S01", "AOE-GE-D22-S08",
                "AOE-GE-D22-S13", "AOE-GE-D22-S12",
            ],
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GE-D22-CMD"},
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

    def test_late_resource_grant_or_invalid_framing_prevents_publication(self) -> None:
        model = supplied_task()
        model["jobs"][3]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )
        dispatch.assert_not_called()
        model = supplied_task()
        model["jobs"][3]["request"]["payload"]["model"]["framing"]["length_offset"] = 0
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
