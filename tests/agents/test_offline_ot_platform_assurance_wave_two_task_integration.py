"""Additional OT and platform projections retain independent supplied sources."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_firmware_update_metadata as firmware
from sunderkey import offline_gpu_management_node_permissions as gpu_permissions
from sunderkey import offline_management_engine_state as management
from sunderkey import offline_ot_remote_access_policy as remote_access
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
MODULES = (gpu_permissions, firmware, management, remote_access)
EXAMPLES = (
    ("a-gpu-management", "offline-gpu-management-node-permissions-component.json"),
    ("b-firmware", "offline-firmware-update-metadata-component.json"),
    ("c-management", "offline-management-engine-state-component.json"),
    ("d-remote-access", "offline-ot-remote-access-policy-component.json"),
)


class OfflineOtPlatformAssuranceWaveTwoTaskIntegrationTests(unittest.TestCase):
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

    def test_four_sources_compose_without_shared_authority(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.ot-platform-assurance-wave-two",
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
        self.assertEqual(value["job_count"], 4)
        self.assertEqual(value["distinct_component_count"], 4)
        self.assertEqual(value["distinct_profile_count"], 4)
        self.assertEqual(
            [row["profile_id"] for row in value["ownership_index"]],
            ["AOE-GD-D24-S05", "AOE-GD-D24-S09", "AOE-GD-D24-S10", "AOE-GD-D19-S15"],
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
