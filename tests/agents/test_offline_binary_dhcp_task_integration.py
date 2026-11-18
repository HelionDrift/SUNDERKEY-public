"""Separate binary layouts and DHCP/DNS bytes under one unsigned inert task."""

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
        ("pe", "offline-pe32-layout-component.json"),
        ("elf", "offline-elf64-layout-component.json"),
        ("dhcp", "offline-dhcpv4-component.json"),
        ("android", "offline-android-dex-component.json"),
        ("macho", "offline-macho-component.json"),
        ("dns", "offline-dns-message-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.binary-dhcp-review",
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


class OfflineBinaryDhcpTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )

    def test_six_components_retain_five_profiles_and_the_original_dns_default(self) -> None:
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
            (6, 6, 5),
        )
        self.assertEqual(
            [row["job_id"] for row in result["jobs"]],
            ["android", "dhcp", "dns", "elf", "macho", "pe"],
        )
        expected_owners = (
            ("AOE-GB-D08-S01", "AOE-GB-D08-CMD"),
            ("AOE-GC-D13-S03", "AOE-GC-D13-CMD"),
            ("AOE-GC-D13-S03", "AOE-GC-D13-CMD"),
            ("AOE-GB-D08-S17", "AOE-GB-D08-CMD"),
            ("AOE-GB-D08-S05", "AOE-GB-D08-CMD"),
            ("AOE-GB-D08-S15", "AOE-GB-D08-CMD"),
        )
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
        self.assertNotIn("component_id", requests["dns"])
        self.assertEqual(requests["dhcp"]["component_id"], "dhcpv4_supplied_offer_ack_structure")
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different-pe-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_request_denies_before_any_binary_or_dhcp_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_last_pe_refusal_cannot_publish_a_partial_binary_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["pe_file_base64"] = "not base64"
        with patch.object(
            components,
            "run_offline_specialist_component",
            wraps=components.run_offline_specialist_component,
        ) as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
        self.assertEqual(dispatch.call_count, 6)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
