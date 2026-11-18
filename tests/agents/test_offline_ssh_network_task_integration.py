"""Three supplied computations grouped without an asserted network or SSH session."""

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
        ("ssh", "offline-ssh-kexinit-component.json"),
        ("network", "offline-aws-vpc-flow-component.json"),
        ("dns", "offline-dns-zone-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.ssh-network-review",
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


class OfflineSshNetworkTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_three_original_jobs_replay_with_sorted_ownership_and_no_session_claim(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            [row["job_id"] for row in result["model"]["jobs"]],
            ["ssh", "network", "dns"],
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["dns", "network", "ssh"])
        self.assertEqual(
            tuple(
                result[name]
                for name in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (3, 3, 3),
        )
        expected_owners = (
            (
                "dns_supplied_zone_lookup",
                "AOE-GA-D01-S03",
                "AOE-GA-D01-CMD",
                "IW2-003",
            ),
            (
                "aws_supplied_vpc_flow_predicates",
                "AOE-GC-D14-S03",
                "AOE-GC-D14-CMD",
                "IW2-006",
            ),
            (
                "ssh_supplied_kexinit_selection_arithmetic",
                "AOE-GC-D12-S06",
                "AOE-GC-D12-CMD",
                "IW2-006",
            ),
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        for row, owner, expected in zip(
            result["jobs"], result["ownership_index"], expected_owners, strict=True
        ):
            self.assertEqual(owner["job_id"], row["job_id"])
            self.assertEqual(
                tuple(
                    owner[name] for name in ("component_id", "profile_id", "commander_profile_id")
                ),
                expected[:3],
            )
            self.assertEqual(row["result"]["component"]["scheduled_wave_id"], expected[3])
            self.assertEqual(owner["independent_validator_id"], "AOE-HQ-19")
            self.assertIs(owner["independent_review_required"], True)
            self.assertEqual(row["result"]["input_provenance"], "operator_supplied_unverified")
            request = requests[row["job_id"]]
            self.assertEqual(request["action_tier"], "R0")
            self.assertIs(request["dry_run"], True)
            self.assertEqual(request["credential_refs"], [])
            self.assertTrue(all(value == [] for value in request["resources"].values()))
            self.assertEqual(row["result"]["analysis"]["source_model"], request["payload"]["model"])
            self.assertEqual(set(row["result"]["operational_effects"].values()), {"none"})
            self.assertIs(row["result"]["positive_use_approved"], False)
            self.assertIs(row["result"]["full_candidate_assembled"], False)
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    row["result"],
                    request=requests[row["job_id"]],
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                row["result"],
            )
        dns, network, ssh = [row["result"]["analysis"] for row in result["jobs"]]
        self.assertEqual(dns["group_owner_id"], "AOE-HQ-03")
        dns_queries = {row["query_id"]: row for row in dns["query_results"]}
        self.assertEqual(dns_queries["query:alias"]["rdata"], ["192.0.2.10"])
        self.assertEqual(dns_queries["query:wildcard"]["rdata"], ["192.0.2.20"])
        self.assertEqual(dns_queries["query:cut"]["outcome"], "referral_in_supplied_projection")
        self.assertEqual(dns_queries["query:ordinary"]["outcome"], "no_data_in_supplied_projection")
        self.assertTrue(all(value is False for value in dns["flags"].values()))
        self.assertEqual(network["group_commander_profile_id"], "AOE-HQ-05")
        self.assertEqual(len(network["flow_results"]), 1)
        flow = network["flow_results"][0]
        self.assertEqual(flow["flow"]["protocol"], "TCP")
        self.assertEqual(flow["flow"]["source_port"], 50000)
        self.assertEqual(flow["flow"]["destination_port"], 443)
        self.assertEqual(flow["forward"]["outcome"], "allowed_in_supplied_policy_model")
        self.assertEqual(
            flow["reverse"]["outcome"], "conditionally_allowed_in_supplied_policy_model"
        )
        self.assertIs(flow["reverse"]["conditional"], True)
        for flag in (
            "snapshot_authenticated",
            "snapshot_complete",
            "routing_verified",
            "conntrack_verified",
            "provider_exemptions_verified",
            "reachability_proven",
            "live_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(network[flag], False)
        self.assertEqual(ssh["command_group_id"], "AOE-HQ-05")
        self.assertEqual(ssh["validator_id"], "AOE-HQ-19")
        self.assertEqual(ssh["analysis_id"], "SKA-3CB2321BD41F99BB674FD0CA767537D4")
        self.assertEqual(ssh["outcome"], "consistent_supported_selection_declarations")
        self.assertTrue(all(value is False for value in ssh["claims"].values()))
        for analysis in (dns, network, ssh):
            self.assertEqual(set(analysis["effects"].values()), {"none"})
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
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different-ssh-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_grant_denies_every_dns_tcp_or_ssh_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-authorized"]
        with patch.object(components, "run_offline_specialist_component") as dispatch:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            dispatch.assert_not_called()

    def test_last_malformed_ssh_source_cannot_finalize_a_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["client_payload_base64"] = "Tk9UU1NI"
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
                ["AOE-GA-D01-S03", "AOE-GC-D14-S03", "AOE-GC-D12-S06"],
            )
            finalize.assert_not_called()
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
