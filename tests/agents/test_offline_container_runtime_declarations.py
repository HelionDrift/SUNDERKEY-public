"""Container runtime declaration comparisons remain bounded and inert."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_container_runtime_declarations import (
    ContainerRuntimeDeclarationsError,
    ContainerRuntimeDeclarationsReport,
    analyze_supplied_container_runtime_declarations,
    component_fixture,
    verify_supplied_container_runtime_declarations,
    verify_supplied_container_runtime_declarations_bytes,
)
from sunderkey.offline_specialist_components import load_offline_specialist_component_request


class ContainerRuntimeDeclarationsTests(unittest.TestCase):
    def test_example_envelope_retains_component_fixture(self) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "examples/offline-container-runtime-declarations-component.json"
        )
        request = load_offline_specialist_component_request(path)
        self.assertEqual(request["profile_id"], "AOE-GC-D15-S02")
        self.assertEqual(request["component_id"], "container_supplied_runtime_declarations")
        self.assertEqual(request["payload"]["model"], component_fixture())
        self.assertEqual(request["environment"], "synthetic")
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )

    def test_contradictory_claim_is_only_a_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_container_runtime_declarations(model)
        value = report.to_dict()
        self.assertEqual(value["profile_id"], "AOE-GC-D15-S02")
        self.assertEqual(value["candidate_count"], 1)
        self.assertEqual(value["unknown_count"], 0)
        self.assertEqual(value["rows"][0]["reasons"], ["rootless_requirement_not_declared"])
        self.assertEqual(value["rows"][0]["disposition"], "candidate_claim_conflict")
        self.assertFalse(value["runtime_inspected"])
        self.assertFalse(value["finding_claimed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_container_runtime_declarations(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_container_runtime_declarations_bytes(
                report.to_json().encode("utf-8"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_matching_claim_and_declared_mismatches(self) -> None:
        model = component_fixture()
        model["checks"][0]["claimed_compliant"] = False
        value = analyze_supplied_container_runtime_declarations(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["rows"][0]["disposition"], "supplied_claim_consistent")
        model["runtimes"][0]["rootless"] = True
        model["checks"][0]["claimed_compliant"] = True
        value = analyze_supplied_container_runtime_declarations(model).to_dict()
        self.assertIs(value["rows"][0]["projected_compliant"], True)
        self.assertEqual(value["rows"][0]["disposition"], "supplied_claim_consistent")
        model["runtimes"][0]["rootless"] = False
        model["checks"][0]["claimed_compliant"] = False
        model["runtimes"][0]["engine"] = "docker"
        model["runtimes"][0]["user_namespace_enabled"] = False
        model["runtimes"][0]["remote_api_enabled"] = True
        reasons = analyze_supplied_container_runtime_declarations(model).to_dict()["rows"][0][
            "reasons"
        ]
        self.assertEqual(
            reasons,
            [
                "engine_declaration_mismatch",
                "rootless_requirement_not_declared",
                "user_namespace_requirement_not_declared",
                "remote_api_declared_enabled",
            ],
        )

    def test_incomplete_inventory_and_context_remain_unknown(self) -> None:
        model = component_fixture()
        model["runtimes"] = []
        model["runtime_inventory_complete"] = False
        value = analyze_supplied_container_runtime_declarations(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 1)
        self.assertIsNone(value["rows"][0]["projected_compliant"])
        model["runtime_inventory_complete"] = True
        value = analyze_supplied_container_runtime_declarations(model).to_dict()
        self.assertEqual(value["rows"][0]["reasons"], ["runtime_absent_from_complete_inventory"])
        self.assertEqual(value["candidate_count"], 1)
        model = component_fixture()
        model["checks"][0]["context_complete"] = False
        value = analyze_supplied_container_runtime_declarations(model).to_dict()
        self.assertEqual(value["unknown_count"], 1)
        self.assertEqual(value["candidate_count"], 0)

    def test_malformed_and_non_native_inputs_reject(self) -> None:
        model = component_fixture()
        model["extra"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_container_runtime_declarations(model)
        model = component_fixture()
        model["runtimes"].append(copy.deepcopy(model["runtimes"][0]))
        with self.assertRaises(ContainerRuntimeDeclarationsError):
            analyze_supplied_container_runtime_declarations(model)
        model = component_fixture()
        model["checks"][0]["context_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_container_runtime_declarations(model)
        model = component_fixture()
        model["runtimes"][0]["engine"] = "containerd"
        with self.assertRaises(ValueError):
            analyze_supplied_container_runtime_declarations(model)
        model = component_fixture()
        model["source_id"] = "x" * 129
        with self.assertRaises(ValueError):
            analyze_supplied_container_runtime_declarations(model)
        model = component_fixture()
        model["runtimes"] = tuple(model["runtimes"])
        with self.assertRaises(ValueError):
            analyze_supplied_container_runtime_declarations(model)

    def test_forged_report_and_changed_original_reject(self) -> None:
        model = component_fixture()
        report = analyze_supplied_container_runtime_declarations(model)

        class ForgedWrapper(ContainerRuntimeDeclarationsReport):
            pass

        with self.assertRaises(ContainerRuntimeDeclarationsError):
            ContainerRuntimeDeclarationsReport(report.to_dict())
        with self.assertRaises(ContainerRuntimeDeclarationsError):
            verify_supplied_container_runtime_declarations(report.to_dict(), model=model)
        with self.assertRaises(ContainerRuntimeDeclarationsError):
            verify_supplied_container_runtime_declarations(
                ForgedWrapper._owned(report.to_dict()), model=model
            )
        with self.assertRaises(ValueError):
            verify_supplied_container_runtime_declarations_bytes(b'{"a":1,"a":2}', model=model)
        forged = report.to_dict()
        forged["finding_claimed"] = True
        with self.assertRaises(ContainerRuntimeDeclarationsError):
            verify_supplied_container_runtime_declarations_bytes(
                json.dumps(forged).encode("utf-8"), model=model
            )
        model["runtimes"][0]["rootless"] = True
        with self.assertRaises(ContainerRuntimeDeclarationsError):
            verify_supplied_container_runtime_declarations(report, model=model)


if __name__ == "__main__":
    unittest.main()
