"""Three supplied OT declarations compose without operational authority."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_ot_controller_configuration as controller
from sunderkey import offline_ot_engineering_project_provenance as engineering
from sunderkey import offline_ot_hmi_tag_mapping as hmi
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task


ROOT = Path(__file__).resolve().parents[2]
MODULES = (controller, hmi, engineering)
EXAMPLES = (
    ("a-controller", "offline-ot-controller-configuration-component.json"),
    ("b-hmi", "offline-ot-hmi-tag-mapping-component.json"),
    ("c-engineering", "offline-ot-engineering-project-provenance-component.json"),
)


class OfflineOtFoundationTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_module_ownership_matches_bound_catalog(self) -> None:
        by_profile = {
            item["profile_id"]: item for item in self.catalog.to_dict()["components"]
        }
        for module in MODULES:
            with self.subTest(profile_id=module.PROFILE_ID):
                item = by_profile[module.PROFILE_ID]
                self.assertEqual(module.COMPONENT_ID, item["component_id"])
                self.assertEqual(module.CAPABILITY_ID, item["primary_capability_id"])
                self.assertEqual(module.VECTOR_ID, item["vector_id"])
                self.assertEqual(module.WORK_PACKAGE_ID, item["package_id"])
                self.assertEqual(module.COMMANDER_ID, item["commander_profile_id"])
                self.assertEqual(module.INDEPENDENT_VALIDATOR_ID, item["independent_validator_id"])
                self.assertEqual(module.WAVE_ID, item["scheduled_wave_id"])
                self.assertEqual(module.BLUEPRINT_SHA256, item["blueprint_sha256"])

    def test_three_sources_compose_without_shared_authority(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.ot-foundation-review",
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
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        value = report.to_dict()
        self.assertEqual(value["model"], original)
        self.assertEqual(value["job_count"], 3)
        self.assertEqual(value["distinct_component_count"], 3)
        self.assertEqual(value["distinct_profile_count"], 3)
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
