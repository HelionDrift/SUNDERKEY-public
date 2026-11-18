"""Cross-domain unsigned composition with two selections for one existing profile."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


def supplied_task() -> dict:
    selections = (
        ("service", "offline-kubernetes-service-component.json"),
        ("android", "offline-android-component.json"),
        ("nsg", "offline-azure-nsg-component.json"),
        ("network-policy", "offline-kubernetes-network-policy-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.cloud-mobile-declaration-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in selections
        ],
    }


class OfflineDeclarationTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_four_components_share_one_task_without_merging_three_profiles_or_authority(
        self,
    ) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            (
                result["job_count"],
                result["distinct_component_count"],
                result["distinct_profile_count"],
            ),
            (4, 4, 3),
        )
        self.assertEqual(
            [job["job_id"] for job in result["jobs"]],
            ["android", "network-policy", "nsg", "service"],
        )
        requests = {job["job_id"]: job["request"] for job in model["jobs"]}
        actual = {}
        for job, ownership in zip(result["jobs"], result["ownership_index"], strict=True):
            standalone = components.run_offline_specialist_component(
                requests[job["job_id"]], catalog=self.catalog, repository_root=ROOT
            )
            self.assertEqual(job["result"], standalone)
            self.assertTrue(ownership["independent_review_required"])
            self.assertEqual(ownership["component_id"], standalone["component"]["component_id"])
            self.assertEqual(ownership["profile_id"], standalone["component"]["profile_id"])
            actual[job["job_id"]] = ownership
        self.assertEqual(actual["network-policy"]["profile_id"], actual["service"]["profile_id"])
        self.assertNotEqual(
            actual["network-policy"]["component_id"], actual["service"]["component_id"]
        )
        for field in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[field], False)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["coverage"]["pods_complete"] = False
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_cross_domain_resource_denial_precedes_every_leaf(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-authorized"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            self.run_task(model)
        dispatch.assert_not_called()

    def test_service_semantic_failure_is_a_task_error_not_a_partial_result(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["service"]["ports"] = None
        with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
            self.run_task(model)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
