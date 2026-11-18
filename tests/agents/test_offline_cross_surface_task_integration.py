"""Four cross-surface specialists retain separate sources in one inert task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
JOBS = (
    ("a-archive", "offline-archive-member-paths-component.json"),
    ("b-dns", "offline-dns-scope-timeline-component.json"),
    ("c-pickle", "offline-pickle-opcode-component.json"),
    ("d-json", "offline-json-key-policy-component.json"),
)


def supplied_task() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.cross-surface-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in JOBS
        ],
    }


class CrossSurfaceTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_four_sources_share_ownership_without_cross_source_inference(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(model, original)
        self.assertEqual(body["model"], original)
        self.assertEqual(body["job_count"], 4)
        self.assertEqual(body["distinct_profile_count"], 4)
        self.assertEqual(
            {row["profile_id"] for row in body["ownership_index"]},
            {
                "AOE-GE-D23-S03", "AOE-GE-D23-S04",
                "AOE-GE-D23-S05", "AOE-GE-D23-S06",
            },
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GE-D23-CMD"},
        )
        self.assertEqual(
            {row["independent_validator_id"] for row in body["ownership_index"]},
            {"AOE-HQ-19"},
        )
        sources = {
            job["job_id"]: job["result"]["analysis"]["source_model"]
            for job in body["jobs"]
        }
        self.assertEqual(
            sources,
            {
                job["job_id"]: job["request"]["payload"]["model"]
                for job in original["jobs"]
            },
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_resource_grant_or_late_bad_source_aborts_whole_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["resources"]["network"] = ["forbidden"]
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )
        model = supplied_task()
        model["jobs"][3]["request"]["payload"]["model"]["document_text"] = "{"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )

    def test_twelve_pattern_models_share_task_without_cross_source_inference(self) -> None:
        filenames = (
            "offline-cross-surface-authorization-component.json",
            "offline-cross-channel-session-component.json",
            "offline-request-origin-trust-component.json",
            "offline-toctou-state-schedule-component.json",
            "offline-resource-expansion-budget-component.json",
            "offline-dependency-fail-closed-component.json",
            "offline-configuration-defaults-component.json",
            "offline-confused-deputy-boundary-component.json",
            "offline-integrity-poisoning-component.json",
            "offline-query-input-boundary-component.json",
            "offline-interpreter-input-boundary-component.json",
            "offline-observable-discrepancy-component.json",
        )
        model = {
            "schema_version": 1,
            "task_id": "synthetic.web-boundary-review",
            "jobs": [
                {
                    "job_id": f"job-{index}",
                    "request": components.load_offline_specialist_component_request(
                        ROOT / "examples" / filename
                    ),
                }
                for index, filename in enumerate(filenames, start=1)
            ],
        }
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        body = report.to_dict()
        self.assertEqual(body["job_count"], 12)
        self.assertEqual(body["distinct_profile_count"], 12)
        self.assertEqual(
            {row["profile_id"] for row in body["ownership_index"]},
            {
                "AOE-GE-D23-S07", "AOE-GE-D23-S08",
                "AOE-GE-D23-S09", "AOE-GE-D23-S10",
                "AOE-GE-D23-S11", "AOE-GE-D23-S12",
                "AOE-GE-D23-S13", "AOE-GE-D23-S14",
                "AOE-GE-D23-S15",
                "AOE-GE-D23-S01", "AOE-GE-D23-S02",
                "AOE-GE-D23-S16",
            },
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in body["ownership_index"]},
            {"AOE-GE-D23-CMD"},
        )
        self.assertEqual(
            {row["independent_validator_id"] for row in body["ownership_index"]},
            {"AOE-HQ-19"},
        )
        self.assertEqual(
            {
                job["job_id"]: job["result"]["analysis"]["source_model"]
                for job in body["jobs"]
            },
            {
                job["job_id"]: job["request"]["payload"]["model"]
                for job in model["jobs"]
            },
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        clean_model = copy.deepcopy(model)
        model["jobs"][5]["request"]["payload"]["model"]["observations"][0][
            "dependency_ref"
        ] = "actual-secret"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )
        model = clean_model
        model["jobs"][11]["request"]["payload"]["model"]["comparisons"][0][
            "resource_ref"
        ] = "invalid"
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.run_offline_specialist_task(
                model, catalog=self.catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
