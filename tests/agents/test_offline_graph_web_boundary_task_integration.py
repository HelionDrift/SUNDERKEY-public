"""Synthetic graph, web and API boundaries retain independent ownership."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-graph", "offline-attack-graph-model-component.json"),
    ("b-route", "offline-web-route-authorization-component.json"),
    ("c-message", "offline-browser-message-boundary-component.json"),
    ("d-content", "offline-web-content-handling-component.json"),
    ("e-webhook", "offline-webhook-callback-trust-component.json"),
    ("f-mesh", "offline-service-mesh-trust-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.graph-web-boundary-review",
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


class OfflineGraphWebBoundaryTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_six_source_bound_leaves_replay_without_authority_transfer(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        results = [
            components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            for job in model["jobs"]
        ]
        self.assertEqual(
            results[0]["analysis"]["pair_projections"][0]["disposition"],
            "supplied_supported_reachability",
        )
        self.assertGreater(
            results[1]["analysis"]["summary"]["server"]["candidate_policy_contradiction"], 0
        )
        self.assertGreater(results[2]["analysis"]["candidate_count"], 0)
        self.assertIn(
            "candidate_declared_gate_differential",
            {row["disposition"] for row in results[3]["analysis"]["case_projections"]},
        )
        self.assertGreater(results[4]["analysis"]["summary"]["candidate_policy_contradiction"], 0)
        self.assertGreater(results[5]["analysis"]["candidate_count"], 0)
        for job, result in zip(model["jobs"], results, strict=True):
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
        self.assertEqual(result["job_count"], 6)
        self.assertEqual(result["distinct_component_count"], 6)
        self.assertEqual(result["distinct_profile_count"], 6)
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            [
                "AOE-GA-D01-S11",
                "AOE-GB-D05-S12",
                "AOE-GB-D05-S15",
                "AOE-GB-D05-S10",
                "AOE-GB-D06-S06",
                "AOE-GB-D06-S08",
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
        model["jobs"][-1]["request"]["payload"]["model"]["flows"][0]["transport"] = 7
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
