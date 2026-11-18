"""Protocol occurrences, declarations and mobile layout under one inert task label."""

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
        ("wire", "offline-protobuf-wire-component.json"),
        ("macho", "offline-macho-component.json"),
        ("coap", "offline-coap-component.json"),
        ("schema", "offline-protobuf-component.json"),
        ("mqtt", "offline-mqtt-topic-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.wire-mobile-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                ),
            }
            for job_id, name in selections
        ],
    }


class OfflineWireMobileTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_five_components_retain_three_profiles_and_distinct_protocol_defaults(self) -> None:
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
            (5, 5, 3),
        )
        self.assertEqual(
            [row["job_id"] for row in result["jobs"]], ["coap", "macho", "mqtt", "schema", "wire"]
        )
        ownership = (
            ("AOE-GD-D18-S15", "AOE-GD-D18-CMD", "AOE-HQ-33"),
            ("AOE-GB-D08-S05", "AOE-GB-D08-CMD", "AOE-HQ-19"),
            ("AOE-GD-D18-S15", "AOE-GD-D18-CMD", "AOE-HQ-33"),
            ("AOE-GB-D06-S03", "AOE-GB-D06-CMD", "AOE-HQ-34"),
            ("AOE-GB-D06-S03", "AOE-GB-D06-CMD", "AOE-HQ-34"),
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        for row, owner, expected in zip(
            result["jobs"], result["ownership_index"], ownership, strict=True
        ):
            self.assertEqual(
                row["result"],
                components.run_offline_specialist_component(
                    requests[row["job_id"]], catalog=self.catalog, repository_root=ROOT
                ),
            )
            self.assertEqual(
                tuple(
                    owner[name]
                    for name in ("profile_id", "commander_profile_id", "independent_validator_id")
                ),
                expected,
            )
            self.assertIs(owner["independent_review_required"], True)
        self.assertNotIn("component_id", requests["schema"])
        self.assertNotIn("component_id", requests["mqtt"])
        self.assertEqual(requests["wire"]["component_id"], "protobuf_supplied_wire_occurrences")
        self.assertEqual(requests["coap"]["component_id"], "coap_supplied_get_piggyback_structure")
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for name in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[name], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different-wire-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_grant_denies_before_any_wire_or_mobile_analysis(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["credential"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_late_wire_semantic_refusal_returns_no_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["payload_base64"] = "not base64"
        with patch.object(
            components,
            "run_offline_specialist_component",
            wraps=components.run_offline_specialist_component,
        ) as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
        self.assertEqual(dispatch.call_count, 5)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
