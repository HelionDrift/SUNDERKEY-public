"""Supplied Wasm and native binary arithmetic without execution or shared identity."""

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
        ("wasm", "offline-wasm-numeric-stack-component.json"),
        ("elf", "offline-elf64-layout-component.json"),
        ("pe", "offline-pe32-layout-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.wasm-binary-review",
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


class OfflineWasmBinaryTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_three_components_retain_original_bytes_and_two_commanders(self) -> None:
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
            (3, 3, 3),
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["elf", "pe", "wasm"])
        expected_owners = (
            ("AOE-GB-D08-S17", "AOE-GB-D08-CMD"),
            ("AOE-GB-D08-S15", "AOE-GB-D08-CMD"),
            ("AOE-GE-D21-S19", "AOE-GE-D21-CMD"),
        )
        self.assertEqual(len({row[1] for row in expected_owners}), 2)
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
        wasm = result["jobs"][-1]["result"]["analysis"]
        self.assertEqual(wasm["analysis_id"], "WSA-D4337DA9B92BBAFA34E1F4278AAC2294")
        self.assertEqual(wasm["functions"][0]["terminal_result_types"], ["i32"])
        self.assertTrue(all(value is False for value in wasm["flags"].values()))
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different-wasm-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_request_denies_every_binary_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["process"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_last_wasm_refusal_cannot_publish_a_partial_binary_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["module_base64"] = "Tk9UV0FTTQ=="
        with patch.object(
            components,
            "run_offline_specialist_component",
            wraps=components.run_offline_specialist_component,
        ) as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
        self.assertEqual(dispatch.call_count, 3)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
