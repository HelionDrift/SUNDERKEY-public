"""Independent IPv4, DNS and TLS octets grouped without a shared protocol path."""

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
        ("z-fragments", "offline-ipv4-fragment-component.json"),
        ("tls", "offline-tls-hello-component.json"),
        ("dns", "offline-dns-message-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.ipv4-protocol-review",
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


class OfflineIpv4ProtocolTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_three_original_jobs_replay_without_a_shared_datagram_or_session_claim(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            [row["job_id"] for row in result["model"]["jobs"]],
            ["z-fragments", "tls", "dns"],
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["dns", "tls", "z-fragments"])
        self.assertEqual(
            tuple(
                result[name]
                for name in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (3, 3, 3),
        )
        expected_owners = (
            (
                "dns_supplied_wire_structure",
                "AOE-GC-D13-S03",
                "AOE-GC-D13-CMD",
                "IW2-006",
                "AOE-HQ-05",
            ),
            (
                "tls13_supplied_hello_offer_selection",
                "AOE-GE-D22-S02",
                "AOE-GE-D22-CMD",
                "IW2-015",
                "AOE-HQ-07",
            ),
            (
                "ipv4_supplied_fragment_relations_and_header_checksums",
                "AOE-GC-D13-S01",
                "AOE-GC-D13-CMD",
                "IW2-004",
                "AOE-HQ-05",
            ),
        )
        self.assertEqual(
            {row["commander_profile_id"] for row in result["ownership_index"]},
            {"AOE-GC-D13-CMD", "AOE-GE-D22-CMD"},
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        self.assertNotIn("component_id", requests["dns"])
        for row, owner, expected in zip(
            result["jobs"], result["ownership_index"], expected_owners, strict=True
        ):
            request = requests[row["job_id"]]
            component_result = row["result"]
            descriptor = component_result["component"]
            analysis = component_result["analysis"]
            self.assertEqual(owner["job_id"], row["job_id"])
            self.assertEqual(
                tuple(
                    owner[name] for name in ("component_id", "profile_id", "commander_profile_id")
                ),
                expected[:3],
            )
            self.assertEqual(descriptor["scheduled_wave_id"], expected[3])
            self.assertEqual(analysis["group_commander_profile_id"], expected[4])
            self.assertEqual(owner["independent_validator_id"], "AOE-HQ-19")
            self.assertEqual(analysis["independent_validator_id"], "AOE-HQ-19")
            self.assertIs(owner["independent_review_required"], True)
            self.assertEqual(request["action_tier"], "R0")
            self.assertIs(request["dry_run"], True)
            self.assertEqual(request["credential_refs"], [])
            self.assertTrue(all(value == [] for value in request["resources"].values()))
            source_field = "source_model" if row["job_id"] == "z-fragments" else "model"
            self.assertEqual(analysis[source_field], request["payload"]["model"])
            self.assertEqual(component_result["input_provenance"], "operator_supplied_unverified")
            self.assertEqual(set(component_result["operational_effects"].values()), {"none"})
            self.assertEqual(set(analysis["effects"].values()), {"none"})
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
        dns, tls, fragments = [row["result"]["analysis"] for row in result["jobs"]]
        self.assertEqual(dns["analysis_id"], "DNS-11459030D91AEAC582A266D52F657446")
        self.assertEqual(dns["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertIs(dns["counted_sections_complete"], True)
        self.assertEqual(dns["unconsumed_bytes"], 0)
        self.assertEqual(dns["header"]["question_count"], 1)
        self.assertEqual(dns["header"]["answer_count"], 2)
        self.assertEqual(tls["analysis_id"], "THA-5C4792683DD417BB8537391B63B72DCC")
        self.assertEqual(tls["outcome"], "consistent_with_supported_hello_selection")
        self.assertIs(tls["supported_checks_complete"], True)
        self.assertEqual(set(tls["selection_checks"].values()), {"passes"})
        for analysis in (dns, tls):
            for flag in (
                "message_authenticity_verified",
                "vulnerability_proven",
                "live_use_approved",
                "qualification_claimed",
            ):
                self.assertIs(analysis[flag], False)
        self.assertIs(dns["comprehensive_dns_validity_verified"], False)
        self.assertIs(tls["full_tls_validity_verified"], False)
        self.assertIs(tls["cryptographic_validation_performed"], False)
        self.assertEqual([row["packet_id"] for row in fragments["packets"]], ["first", "last"])
        self.assertTrue(
            all(row["header_checksum_equation_holds"] is True for row in fragments["packets"])
        )
        self.assertEqual(fragments["contradictions"], [])
        relation = fragments["fragment_sets"][0]
        self.assertEqual(relation["merged_supplied_intervals"], [[0, 24]])
        self.assertEqual(relation["union_octets"], 24)
        self.assertEqual(relation["literal_unique_mf_zero_endpoint"], 24)
        self.assertEqual(
            relation["conditional_single_tuple_conclusion"], "consistent_supplied_arithmetic"
        )
        self.assertTrue(all(value is False for value in fragments["claims"].values()))
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertEqual(result["input_provenance"], "operator_supplied_unverified")
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different-fragment-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_fragment_resource_grant_denies_all_protocol_dispatch(self) -> None:
        model = supplied_task()
        # This job is last in the preparation order, despite its original position.
        model["jobs"][0]["request"]["resources"]["network"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_last_malformed_ipv4_source_cannot_finalize_a_partial_protocol_task(self) -> None:
        model = supplied_task()
        fragment_model = model["jobs"][0]["request"]["payload"]["model"]
        fragment_model["fragment_sets"][0]["packets"][0]["packet_base64"] = "Tk9USVBWNA=="
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
                ["AOE-GC-D13-S03", "AOE-GE-D22-S02", "AOE-GC-D13-S01"],
            )
            finalize.assert_not_called()
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
