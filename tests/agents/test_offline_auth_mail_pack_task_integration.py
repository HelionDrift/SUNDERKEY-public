"""Distinct assertion, mail and artifact computations under one unsigned task."""

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
        ("pack", "offline-git-pack-component.json"),
        ("dkim", "offline-dkim-component.json"),
        ("auth", "offline-webauthn-assertion-component.json"),
        ("oci", "offline-oci-blob-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.auth-mail-pack-review",
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


class OfflineAuthMailPackTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )

    def test_four_components_retain_original_bytes_and_three_commanders(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            tuple(
                result[name]
                for name in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (4, 4, 4),
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["auth", "dkim", "oci", "pack"])
        expected_owners = (
            ("AOE-GA-D03-S08", "AOE-GA-D03-CMD"),
            ("AOE-GC-D13-S14", "AOE-GC-D13-CMD"),
            ("AOE-GC-D17-S10", "AOE-GC-D17-CMD"),
            ("AOE-GC-D17-S01", "AOE-GC-D17-CMD"),
        )
        self.assertEqual(len({row[1] for row in expected_owners}), 3)
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        for row, owner, expected in zip(
            result["jobs"], result["ownership_index"], expected_owners, strict=True
        ):
            self.assertEqual(
                tuple(owner[name] for name in ("profile_id", "commander_profile_id")),
                expected,
            )
            self.assertEqual(owner["independent_validator_id"], "AOE-HQ-19")
            self.assertIs(owner["independent_review_required"], True)
            self.assertEqual(
                row["result"],
                components.run_offline_specialist_component(
                    requests[row["job_id"]], catalog=self.catalog, repository_root=ROOT
                ),
            )
        assertion, dkim, _, pack = [row["result"]["analysis"] for row in result["jobs"]]
        self.assertTrue(all(assertion["checks"].values()))
        self.assertTrue(all(value is False for value in assertion["claims"].values()))
        self.assertEqual(dkim["analysis_id"], "DCA-F58B5A06975C4D52D03EF747BA432A59")
        self.assertIs(dkim["body_observation"]["body_hash_matches_supplied_bh"], True)
        self.assertTrue(all(value is False for value in dkim["flags"].values()))
        self.assertEqual(pack["analysis_id"], "GPA-BEBB5F5D47375804D82DAB4E0EB7D4F6")
        self.assertIs(pack["pack"]["checksum_matches"], True)
        self.assertTrue(all(value is False for value in pack["claims"].values()))
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][1]["request"]["payload"]["model"]["source_id"] = "different-mail-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_request_denies_every_auth_mail_or_pack_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_last_pack_refusal_cannot_publish_a_partial_auth_mail_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["pack_base64"] = "Tk9UQVBBQ0s="
        with patch.object(
            components,
            "run_offline_specialist_component",
            wraps=components.run_offline_specialist_component,
        ) as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
        self.assertEqual(dispatch.call_count, 4)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
