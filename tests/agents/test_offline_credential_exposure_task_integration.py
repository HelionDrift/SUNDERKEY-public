"""Opaque exposure review joins reconnaissance ownership, not credential access."""

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
        "task_id": "synthetic.saas-exposure-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in (
                ("a-saas", "offline-saas-signal-component.json"),
                ("b-exposure", "offline-credential-exposure-component.json"),
            )
        ],
    }


class OfflineCredentialExposureTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_common_task_preserves_distinct_sources_and_no_credential_effect(self):
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        body = report.to_dict()
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 2)
        self.assertEqual(body["distinct_profile_count"], 2)
        self.assertEqual(
            [row["profile_id"] for row in body["ownership_index"]],
            ["AOE-GA-D01-S06", "AOE-GA-D01-S08"],
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

    def test_resource_grant_or_plaintext_reference_aborts_before_publication(self):
        model = supplied_task()
        model["jobs"][1]["request"]["resources"]["credential"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()
        model = supplied_task()
        signal = model["jobs"][1]["request"]["payload"]["model"]["signals"][0]
        signal["credential_ref"] = "password123"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
