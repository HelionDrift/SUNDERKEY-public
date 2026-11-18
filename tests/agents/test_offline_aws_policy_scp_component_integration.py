"""The supplied AWS two-layer join stays distinct from existing policy checks."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_aws_policy_scp_join as pair
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
JOIN_EXAMPLE = ROOT / "examples" / "offline-aws-policy-scp-pair-component.json"
SCP_EXAMPLE = ROOT / "examples" / "offline-aws-scp-component.json"


class OfflineAwsPolicyScpComponentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_explicit_join_example_replays_both_original_policy_models(self) -> None:
        request = components.load_offline_specialist_component_request(JOIN_EXAMPLE)
        original = copy.deepcopy(request)
        self.assertEqual(request["component_id"], pair.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertTrue(all(value == [] for value in request["resources"].values()))
        result = components.run_offline_specialist_component(
            request, catalog=self.catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["component_id"], pair.COMPONENT_ID)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D14-S01")
        self.assertEqual(
            result["analysis"]["results"][0]["pair_decision"],
            "identity_allow_and_scp_not_blocked",
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["full_candidate_assembled"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            components.verify_offline_specialist_component_result(
                result, request=original, catalog=self.catalog, repository_root=ROOT
            ),
            result,
        )
        self.assertEqual(
            pair.verify_supplied_aws_policy_scp_pair(
                pair.AwsPolicyScpJoin.from_dict(result["analysis"]),
                model=original["payload"]["model"],
            ).to_dict(),
            result["analysis"],
        )
        request["payload"]["model"]["principal_binding"]["principal_ref"] = "other"
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            components.verify_offline_specialist_component_result(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            )

    def test_existing_scp_default_and_two_job_task_keep_distinct_results(self) -> None:
        scp_request = components.load_offline_specialist_component_request(SCP_EXAMPLE)
        join_request = components.load_offline_specialist_component_request(JOIN_EXAMPLE)
        self.assertNotIn("component_id", scp_request)
        self.assertEqual(
            components.PROFILE_DEFAULT_COMPONENTS["AOE-GC-D14-S01"],
            "aws_organizations_supplied_scp_path",
        )
        supplied = {
            "schema_version": 1,
            "task_id": "synthetic.aws-supplied-policy-composition",
            "jobs": [
                {"job_id": "scp", "request": scp_request},
                {"job_id": "pair", "request": join_request},
            ],
        }
        original = copy.deepcopy(supplied)
        report = task.run_offline_specialist_task(
            supplied, catalog=self.catalog, repository_root=ROOT
        )
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(result["job_count"], 2)
        self.assertEqual(result["distinct_component_count"], 2)
        self.assertEqual(result["distinct_profile_count"], 1)
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["pair", "scp"])
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["full_candidate_assembled"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_later_resource_grant_denies_before_any_leaf_dispatch(self) -> None:
        scp_request = components.load_offline_specialist_component_request(SCP_EXAMPLE)
        join_request = components.load_offline_specialist_component_request(JOIN_EXAMPLE)
        join_request["resources"]["network"] = ["forbidden"]
        supplied = {
            "schema_version": 1,
            "task_id": "synthetic.aws-supplied-policy-composition",
            "jobs": [
                {"job_id": "scp", "request": scp_request},
                {"job_id": "pair", "request": join_request},
            ],
        }
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            task.run_offline_specialist_task(supplied, catalog=self.catalog, repository_root=ROOT)
        dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
