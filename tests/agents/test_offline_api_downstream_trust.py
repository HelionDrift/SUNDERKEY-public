"""Finite supplied downstream data-flow and adversarial replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_downstream_trust as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ApiDownstreamTrustTests(unittest.TestCase):
    def test_fixture_source_addresses_replay_and_no_effects(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_downstream_trust(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S15")
        self.assertEqual(document["capability_id"], "army.gb.d06.s15")
        self.assertEqual(document["vector_id"], "AV-GB-D06-S15-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-downstream-model")
        self.assertEqual(document["source"]["producer"]["source_id"], "synthetic-producer")
        self.assertTrue(document["report_id"].startswith("ADT-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertFalse(document["target_behavior_verified"])
        self.assertIsNone(document["live_vulnerability_verdict"])
        self.assertEqual(
            analysis.ApiDownstreamTrustReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.ApiDownstreamTrustReport.from_dict(document).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_api_downstream_trust(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["flow"]["edges"].clear()
        self.assertNotEqual(model, other)

    def test_fixture_candidate_and_protection_unknowns(self):
        document = analysis.analyze_supplied_api_downstream_trust(
            analysis.component_fixture()
        ).to_dict()
        self.assertEqual(document["analysis_status"], "complete_acyclic_projection")
        self.assertEqual(
            document["candidate_paths"],
            [
                {
                    "field_id": "title-field",
                    "sink_id": "render-sink",
                    "sink_kind": "html_render",
                    "path": ["title-field", "pass-title", "render-sink"],
                }
            ],
        )
        self.assertEqual(
            [(row["field_id"], row["reason"]) for row in document["unknowns"]],
            [
                ("query-field", "declared_protection_unverified"),
                ("token-field", "opaque_transform"),
            ],
        )

    def test_incomplete_graph_withholds_all_candidates(self):
        model = analysis.component_fixture()
        model["graph_complete"] = False
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(document["analysis_status"], "unknown_incomplete_graph")
        self.assertEqual(document["candidate_paths"], [])
        self.assertEqual(len(document["unknowns"]), 3)
        self.assertEqual(
            {row["reason"] for row in document["unknowns"]},
            {"incomplete_graph"},
        )

    def test_empty_incomplete_graph_has_explicit_unknown(self):
        model = analysis.component_fixture()
        model["graph_complete"] = False
        model["flow"]["edges"] = []
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(
            document["unknowns"],
            [{"field_id": None, "sink_id": None, "reason": "incomplete_graph"}],
        )

    def test_cycle_is_unknown_even_with_clear_exit_path(self):
        model = analysis.component_fixture()
        model["flow"]["edges"].append({"from_id": "pass-title", "to_id": "check-query"})
        model["flow"]["edges"].append({"from_id": "check-query", "to_id": "pass-title"})
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(document["analysis_status"], "partial_unsupported_cycle_projection")
        self.assertEqual(document["candidate_paths"], [])
        self.assertEqual(
            {row["reason"] for row in document["unknowns"]},
            {"unsupported_cycle", "opaque_transform"},
        )
        cycle_rows = [row for row in document["unknowns"] if row["reason"] == "unsupported_cycle"]
        self.assertTrue(all("path" in row for row in cycle_rows))

    def test_disconnected_self_cycle_does_not_erase_clear_candidate(self):
        model = analysis.component_fixture()
        model["flow"]["steps"].append(
            {
                "step_id": "isolated-loop",
                "kind": "identity_transform",
                "protected_sink_kinds": [],
            }
        )
        model["flow"]["edges"].append({"from_id": "isolated-loop", "to_id": "isolated-loop"})
        report = analysis.analyze_supplied_api_downstream_trust(model)
        document = report.to_dict()
        self.assertEqual(document["analysis_status"], "partial_unsupported_cycle_projection")
        self.assertEqual(
            document["candidate_paths"][0]["path"], ["title-field", "pass-title", "render-sink"]
        )
        self.assertIn(
            {"field_id": None, "sink_id": None, "reason": "unsupported_cycle"},
            document["unknowns"],
        )
        self.assertEqual(
            analysis.ApiDownstreamTrustReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_api_downstream_trust(report, model=model).to_json(),
            report.to_json(),
        )

    def test_reachable_cycle_unknown_alongside_separate_clear_path(self):
        model = analysis.component_fixture()
        model["flow"]["steps"].append(
            {
                "step_id": "render-loop",
                "kind": "identity_transform",
                "protected_sink_kinds": [],
            }
        )
        model["flow"]["edges"].extend(
            [
                {"from_id": "title-field", "to_id": "render-loop"},
                {"from_id": "render-loop", "to_id": "render-loop"},
                {"from_id": "render-loop", "to_id": "render-sink"},
            ]
        )
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(document["analysis_status"], "partial_unsupported_cycle_projection")
        title = [row for row in document["candidate_paths"] if row["field_id"] == "title-field"]
        self.assertEqual(title[0]["path"], ["title-field", "pass-title", "render-sink"])
        affected = [
            row
            for row in document["unknowns"]
            if row["field_id"] == "title-field"
            and row["sink_id"] == "render-sink"
            and row["reason"] == "unsupported_cycle"
        ]
        self.assertEqual(len(affected), 1)
        self.assertIn("render-loop", affected[0]["path"])

    def test_validation_for_other_sink_is_not_applicable(self):
        model = analysis.component_fixture()
        model["flow"]["steps"][1]["protected_sink_kinds"] = ["html_render"]
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(
            [(row["field_id"], row["sink_id"]) for row in document["candidate_paths"]],
            [("query-field", "sql-sink"), ("title-field", "render-sink")],
        )
        self.assertEqual(
            [row["reason"] for row in document["unknowns"]],
            ["opaque_transform"],
        )

    def test_unprotected_branch_wins_over_separate_protected_branch(self):
        model = analysis.component_fixture()
        model["flow"]["edges"].append({"from_id": "query-field", "to_id": "sql-sink"})
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        query = [row for row in document["candidate_paths"] if row["field_id"] == "query-field"]
        self.assertEqual(len(query), 1)
        self.assertEqual(query[0]["path"], ["query-field", "sql-sink"])
        self.assertNotIn("query-field", [row["field_id"] for row in document["unknowns"]])

    def test_opaque_branch_does_not_mask_clear_branch(self):
        model = analysis.component_fixture()
        model["flow"]["edges"].append({"from_id": "token-field", "to_id": "command-sink"})
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        token = [row for row in document["candidate_paths"] if row["field_id"] == "token-field"]
        self.assertEqual(token[0]["path"], ["token-field", "command-sink"])

    def test_trusted_fields_and_telemetry_are_not_sensitive_candidates(self):
        model = analysis.component_fixture()
        model["flow"]["sinks"].append({"sink_id": "telemetry-sink", "sink_kind": "telemetry"})
        model["flow"]["edges"].append({"from_id": "title-field", "to_id": "telemetry-sink"})
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(len(document["candidate_paths"]), 1)
        self.assertNotIn("stable-field", canonical(document["candidate_paths"]))
        self.assertNotIn("telemetry-sink", canonical(document["candidate_paths"]))

    def test_no_reachable_sensitive_sink_is_narrow_negative(self):
        model = analysis.component_fixture()
        model["flow"]["edges"] = []
        document = analysis.analyze_supplied_api_downstream_trust(model).to_dict()
        self.assertEqual(document["analysis_status"], "complete_acyclic_projection")
        self.assertEqual(document["candidate_paths"], [])
        self.assertEqual(document["unknowns"], [])

    def test_duplicate_json_keys_rejected_nested_and_report(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.analyze_supplied_api_downstream_trust_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"trust":"untrusted"', '"trust":"untrusted","trust":"trusted"', 1
        )
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.analyze_supplied_api_downstream_trust_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_api_downstream_trust(model)
        changed = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.ApiDownstreamTrustReport.from_json(changed)

    def test_duplicate_nodes_edges_and_invalid_references_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["producer"]["response_fields"].append(
            copy.deepcopy(model["producer"]["response_fields"][0])
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["steps"][0]["step_id"] = "title-field"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["sinks"][0]["sink_id"] = "pass-title"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["edges"].append(copy.deepcopy(model["flow"]["edges"][0]))
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["edges"][0]["to_id"] = "missing-step"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["edges"][0]["to_id"] = "query-field"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["edges"][0]["from_id"] = "render-sink"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["source_id"] = model["producer"]["source_id"]
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiDownstreamTrustError):
                    analysis.analyze_supplied_api_downstream_trust(model)

    def test_unsupported_step_semantics_and_native_types_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["flow"]["steps"][0]["kind"] = "custom_eval"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["steps"][0]["protected_sink_kinds"] = ["html_render"]
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["steps"][1]["protected_sink_kinds"] *= 2
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["flow"]["sinks"][0]["sink_kind"] = "filesystem_write"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["graph_complete"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["schema_version"] = True
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["extra"] = "unsupported"
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiDownstreamTrustError):
                    analysis.analyze_supplied_api_downstream_trust(model)

    def test_bounds_and_bad_bytes_rejected(self):
        model = analysis.component_fixture()
        model["producer"]["response_fields"] *= analysis.MAX_FIELDS
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.analyze_supplied_api_downstream_trust(model)
        model = analysis.component_fixture()
        model["flow"]["edges"] *= analysis.MAX_EDGES
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.analyze_supplied_api_downstream_trust(model)
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.analyze_supplied_api_downstream_trust_bytes(model_bytes=b"\xff")

    def test_report_tamper_and_separate_source_mismatch(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_downstream_trust(model)
        changed = report.to_dict()
        changed["live_vulnerability_verdict"] = True
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.ApiDownstreamTrustReport.from_dict(changed)
        changed = report.to_dict()
        changed["candidate_paths"] = []
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.ApiDownstreamTrustReport.from_json(canonical(changed))
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.ApiDownstreamTrustReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["graph_complete"] = False
        with self.assertRaises(analysis.ApiDownstreamTrustError):
            analysis.verify_supplied_api_downstream_trust(report, model=other)

    def test_no_payload_network_process_or_credential_effect(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_api_downstream_trust(analysis.component_fixture())
            effects = report.to_dict()["effects"]
            self.assertEqual(effects["network"], "none")
            self.assertEqual(effects["payload_generation"], "none")
            self.assertEqual(effects["credential_resolution"], "none")


if __name__ == "__main__":
    unittest.main()
