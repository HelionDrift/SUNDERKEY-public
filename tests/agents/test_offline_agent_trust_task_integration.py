"""Agent-trust declarations retain separate original sources in one inert task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-tool", "offline-agent-tool-authority-component.json"),
    ("b-output", "offline-agent-output-handling-component.json"),
    ("c-prompt", "offline-indirect-prompt-boundary-component.json"),
    ("d-rag", "offline-rag-provenance-component.json"),
    ("e-memory", "offline-agent-memory-provenance-component.json"),
    ("f-credential", "offline-agent-credential-boundary-component.json"),
    ("g-budget", "offline-agent-resource-budget-component.json"),
    ("h-plan", "offline-agent-plan-integrity-component.json"),
    ("i-coordination", "offline-multi-agent-coordination-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.agent-trust-review",
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


class OfflineAgentTrustTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_nine_source_bound_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
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
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 9)
        self.assertEqual(result["distinct_component_count"], 9)
        self.assertEqual(result["distinct_profile_count"], 9)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            [
                "AOE-GD-D20-S14",
                "AOE-GD-D20-S13",
                "AOE-GD-D20-S10",
                "AOE-GD-D20-S11",
                "AOE-GD-D20-S16",
                "AOE-GD-D20-S15",
                "AOE-GD-D20-S18",
                "AOE-GD-D20-S19",
                "AOE-GD-D20-S20",
            ],
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["qualification_claimed"])
        self.assertFalse(result["positive_use_approved"])
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
        model["jobs"][-1]["request"]["payload"]["model"]["unexpected_field"] = True
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
