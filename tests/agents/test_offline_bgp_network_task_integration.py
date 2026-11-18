"""Separate supplied BGP, DNS and IPv4 bytes in one unsigned offline task."""

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
        ("z-bgp", "offline-bgp-update-component.json"),
        ("a-dns", "offline-dns-message-component.json"),
        ("m-ipv4", "offline-ipv4-fragment-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.bgp-network-evidence-review",
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


class OfflineBgpNetworkTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_three_original_sources_keep_distinct_network_observations(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            [row["job_id"] for row in result["model"]["jobs"]],
            ["z-bgp", "a-dns", "m-ipv4"],
        )
        self.assertEqual(
            [row["job_id"] for row in result["jobs"]],
            ["a-dns", "m-ipv4", "z-bgp"],
        )
        self.assertEqual(
            tuple(
                result[key]
                for key in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (3, 3, 3),
        )
        expected = (
            ("dns_supplied_wire_structure", "AOE-GC-D13-S03", "IW2-006"),
            (
                "ipv4_supplied_fragment_relations_and_header_checksums",
                "AOE-GC-D13-S01",
                "IW2-004",
            ),
            ("bgp_supplied_update_structure", "AOE-GC-D13-S02", "IW2-005"),
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        for row, owner, (component_id, profile_id, wave_id) in zip(
            result["jobs"], result["ownership_index"], expected, strict=True
        ):
            request = requests[row["job_id"]]
            component_result = row["result"]
            analysis = component_result["analysis"]
            self.assertEqual(
                (owner["component_id"], owner["profile_id"]),
                (component_id, profile_id),
            )
            self.assertEqual(owner["commander_profile_id"], "AOE-GC-D13-CMD")
            self.assertEqual(owner["independent_validator_id"], "AOE-HQ-19")
            self.assertIs(owner["independent_review_required"], True)
            self.assertEqual(component_result["component"]["scheduled_wave_id"], wave_id)
            self.assertEqual(request["action_tier"], "R0")
            self.assertIs(request["dry_run"], True)
            self.assertEqual(request["credential_refs"], [])
            self.assertTrue(all(value == [] for value in request["resources"].values()))
            source_key = "source_model" if "source_model" in analysis else "model"
            self.assertEqual(analysis[source_key], request["payload"]["model"])
            self.assertEqual(component_result["input_provenance"], "operator_supplied_unverified")
            self.assertEqual(set(component_result["operational_effects"].values()), {"none"})
            self.assertIs(component_result["positive_use_approved"], False)
            self.assertIs(component_result["full_candidate_assembled"], False)
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    component_result,
                    request=request,
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                component_result,
            )
        bgp = result["jobs"][-1]["result"]["analysis"]
        self.assertEqual(bgp["analysis_id"], "BGPA-F2A0501B056602E2E5081C3D52955BE9")
        self.assertEqual(bgp["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(bgp["header"]["message_octets"], 45)
        self.assertEqual(bgp["known_contradictions"], [])
        self.assertTrue(all(value is False for value in bgp["claims"].values()))
        self.assertEqual(set(bgp["effects"].values()), {"none"})
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertEqual(result["input_provenance"], "operator_supplied_unverified")
        self.assertIs(result["offline_only"], True)
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "other-bgp"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_bgp_resource_or_authority_change_blocks_all_dispatch(self) -> None:
        for change in ("network_resource", "action_tier"):
            with self.subTest(change=change):
                model = supplied_task()
                request = model["jobs"][0]["request"]
                if change == "network_resource":
                    request["resources"]["network"] = ["unapproved-network"]
                else:
                    request["action_tier"] = "R1"
                with patch.object(components, "run_offline_specialist_component") as dispatch:
                    with self.assertRaises(task.OfflineSpecialistTaskError):
                        self.run_task(model)
                    dispatch.assert_not_called()

    def test_last_malformed_bgp_source_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["update_base64"] = "Tk9UQkdQ"
        with (
            patch.object(
                components,
                "run_offline_specialist_component",
                wraps=components.run_offline_specialist_component,
            ) as dispatch,
            patch.object(task, "_finalize", wraps=task._finalize) as finalize,
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
            self.assertEqual(dispatch.call_count, 3)
            self.assertEqual(
                [call.args[0]["profile_id"] for call in dispatch.call_args_list],
                ["AOE-GC-D13-S03", "AOE-GC-D13-S01", "AOE-GC-D13-S02"],
            )
            finalize.assert_not_called()
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
