"""Three supplied policy and identity observations remain distinct in one task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("a-aws", "offline-aws-policy-scp-pair-component.json"),
    ("b-saml", "offline-saml-conditions-component.json"),
    ("z-oauth", "offline-oauth-pkce-transcript-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.policy-identity-cross-record-review",
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


class OfflinePolicyFlowTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_three_original_sources_and_owners_replay_without_authority(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            (
                result["job_count"],
                result["distinct_component_count"],
                result["distinct_profile_count"],
            ),
            (3, 3, 3),
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], [item[0] for item in EXAMPLES])
        self.assertEqual(
            [row["profile_id"] for row in result["ownership_index"]],
            ["AOE-GC-D14-S01", "AOE-GA-D03-S03", "AOE-GA-D03-S04"],
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["full_candidate_assembled"])
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["qualification_claimed"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["principal_binding"]["principal_ref"] = (
            "different"
        )
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_grant_denies_before_any_leaf_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()

    def test_last_unsupported_oauth_flow_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["payload"]["model"]["token_request"]["grant_type"] = (
            "client_credentials"
        )
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
