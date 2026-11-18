"""Five software supply-chain leaves compose without authority transfer."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-build", "offline-build-reproducibility-component.json"),
    ("b-secret", "offline-repository-secret-metadata-component.json"),
    ("c-iac", "offline-iac-change-graph-component.json"),
    ("d-devcontainer", "offline-devcontainer-boundary-component.json"),
    ("e-update", "offline-vendor-update-lineage-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.supply-chain-review",
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


class OfflineSupplyChainTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def setUp(self) -> None:
        # The class setup verifies current source bytes once. Composition tests
        # reuse those exact checked bytes instead of rescanning them per leaf.
        captured = self.catalog.to_dict()
        patcher = patch.object(components, "_catalog_document", return_value=captured)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_five_original_sources_and_owners_remain_separate(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 5)
        self.assertEqual(result["distinct_component_count"], 5)
        self.assertEqual(result["distinct_profile_count"], 5)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            [
                "AOE-GC-D17-S09", "AOE-GC-D17-S11", "AOE-GC-D17-S12",
                "AOE-GC-D17-S13", "AOE-GC-D17-S14",
            ],
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in result["ownership_index"]},
            {"AOE-GC-D17-CMD"},
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["qualification_claimed"])
        self.assertFalse(result["positive_use_approved"])
        for row in result["jobs"]:
            self.assertFalse(row["result"]["full_candidate_assembled"])
            self.assertFalse(row["result"]["positive_use_approved"])
            self.assertEqual(set(row["result"]["operational_effects"].values()), {"none"})
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_late_network_grant_denies_before_any_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-permitted"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_changed_final_source_replay_and_invalid_leaf_fail(self) -> None:
        model = supplied_task()
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        changed = copy.deepcopy(model)
        changed["jobs"][-1]["request"]["payload"]["model"]["offers"][0][
            "metadata_version"
        ] = 8
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=changed, catalog=self.catalog, repository_root=ROOT
            )
        invalid = copy.deepcopy(model)
        invalid["jobs"][-1]["request"]["payload"]["model"]["unexpected_field"] = True
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                invalid, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
