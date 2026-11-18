"""Distinct protocol and artifact analyses under one unsigned inert task label."""

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
        ("modbus", "offline-modbus-tcp-component.json"),
        ("dex", "offline-android-dex-component.json"),
        ("csp", "offline-csp-fetch-component.json"),
        ("cors", "offline-cors-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.protocol-artifact-review",
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


class OfflineProtocolArtifactTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_four_components_preserve_three_profiles_and_cors_csp_selector_identity(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            tuple(
                result[field]
                for field in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (4, 4, 3),
        )
        self.assertEqual(
            [job["job_id"] for job in result["jobs"]], ["cors", "csp", "dex", "modbus"]
        )
        expected_ownership = (
            ("AOE-GB-D05-S14", "AOE-GB-D05-CMD", "AOE-HQ-34"),
            ("AOE-GB-D05-S14", "AOE-GB-D05-CMD", "AOE-HQ-34"),
            ("AOE-GB-D08-S01", "AOE-GB-D08-CMD", "AOE-HQ-19"),
            ("AOE-GD-D19-S06", "AOE-GD-D19-CMD", "AOE-HQ-33"),
        )
        requests = {job["job_id"]: job["request"] for job in original["jobs"]}
        for job, ownership, expected in zip(
            result["jobs"], result["ownership_index"], expected_ownership, strict=True
        ):
            self.assertEqual(
                job["result"],
                components.run_offline_specialist_component(
                    requests[job["job_id"]], catalog=self.catalog, repository_root=ROOT
                ),
            )
            self.assertEqual(
                tuple(
                    ownership[field]
                    for field in ("profile_id", "commander_profile_id", "independent_validator_id")
                ),
                expected,
            )
            self.assertTrue(ownership["independent_review_required"])
        self.assertEqual(requests["csp"]["component_id"], "csp_supplied_external_fetch_predicates")
        self.assertNotIn("component_id", requests["cors"])
        self.assertNotEqual(result["jobs"][0]["result"], result["jobs"][1]["result"])
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for field in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[field], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["routing_context"] = "direct"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_grant_denies_before_any_protocol_or_artifact_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["resources"]["process"] = ["not-authorized"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            self.run_task(model)
        dispatch.assert_not_called()

    def test_late_modbus_semantic_denial_returns_no_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["request_base64"] = "not base64"
        with (
            patch.object(
                components,
                "run_offline_specialist_component",
                wraps=components.run_offline_specialist_component,
            ) as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError) as caught,
        ):
            self.run_task(model)
        self.assertEqual(dispatch.call_count, 4)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
