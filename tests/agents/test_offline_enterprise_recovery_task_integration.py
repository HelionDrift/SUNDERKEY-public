"""Enterprise virtualization and recovery declarations remain independent."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-hypervisor", "offline-hypervisor-management-posture-component.json"),
    ("b-vdi", "offline-vdi-session-posture-component.json"),
    ("c-backup", "offline-backup-recovery-posture-component.json"),
    ("d-storage", "offline-storage-access-posture-component.json"),
    ("e-server", "offline-enterprise-server-management-component.json"),
    ("f-rmm", "offline-rmm-control-posture-component.json"),
    ("g-hpc", "offline-hpc-queue-posture-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.enterprise-recovery-review",
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


class OfflineEnterpriseRecoveryTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_distinct_source_bound_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 7)
        self.assertEqual(result["distinct_component_count"], 7)
        self.assertEqual(result["distinct_profile_count"], 7)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            [
                "AOE-GC-D16-S06",
                "AOE-GC-D16-S07",
                "AOE-GC-D16-S08",
                "AOE-GC-D16-S09",
                "AOE-GC-D16-S10",
                "AOE-GC-D16-S11",
                "AOE-GC-D16-S12",
            ],
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["qualification_claimed"])
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_late_resource_grant_denies_all_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_invalid_last_model_does_not_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["command"] = "reject"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
