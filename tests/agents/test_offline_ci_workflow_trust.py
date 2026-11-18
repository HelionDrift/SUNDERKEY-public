"""Synthetic CI data-flow witnesses, uncertainty and replay controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_ci_workflow_trust as ci

ERROR = ci.CiWorkflowTrustAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def fixture():
    return ci.component_fixture()


def analyze(source):
    return ci.analyze_supplied_ci_workflow_trust(source).to_dict()


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-ci-workflow-trust.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "CWT-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class CiWorkflowTrustTests(unittest.TestCase):
    def deny_before_hash(self, source):
        with patch.object(ci, "_address") as address:
            with self.assertRaises(ERROR):
                ci.analyze_supplied_ci_workflow_trust(source)
            address.assert_not_called()

    def test_fixture_exact_addresses_path_and_safety_boundary(self):
        source = fixture()
        document = analyze(source)
        self.assertEqual(document["analysis_id"], "CWT-95F340B495ABB6124DF57AB46A019A23")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:95f340b495abb6124df57ab46a019a23508fa41ee77c9b5bed1157b36c0b8305",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:672755d8401cd1c45022ba4e8e433095b56d6e50ccfea44fd38c39318e24c9ca",
        )
        self.assertEqual(document["profile_id"], "AOE-GC-D17-S02")
        self.assertEqual(document["blueprint_sha256"], ci.BLUEPRINT_SHA256)
        self.assertEqual(document["overall_outcome"], "candidate_paths_present")
        self.assertEqual(
            (document["candidate_witness_count"], document["unknown_witness_count"]), (1, 0)
        )
        self.assertEqual(
            document["candidate_witnesses"],
            [
                {
                    "source_id": "pull-request",
                    "target_job_id": "publish",
                    "node_path": [
                        "event:pull-request",
                        "job:build",
                        "artifact:bundle",
                        "job:publish",
                    ],
                    "edge_channels": ["event_input", "artifact_produced", "artifact_consumed"],
                    "hop_count": 3,
                }
            ],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))

    def test_needs_is_scheduling_not_data_flow(self):
        source = fixture()
        source["jobs"][1]["consumes_artifact_ids"] = []
        document = analyze(source)
        self.assertEqual(document["candidate_witness_count"], 0)
        self.assertEqual(document["overall_outcome"], "no_candidate_under_complete_supplied_graph")
        self.assertEqual(source["jobs"][1]["needs_job_ids"], ["build"])
        source["jobs"][1]["uses_job_output_ids"] = ["build"]
        witness = analyze(source)["candidate_witnesses"][0]
        self.assertEqual(witness["node_path"], ["event:pull-request", "job:build", "job:publish"])
        self.assertEqual(witness["edge_channels"], ["event_input", "job_output"])

    def test_direct_untrusted_artifact_source(self):
        source = fixture()
        source["artifacts"][0]["trust"] = "untrusted"
        source["source_ids"] = ["bundle"]
        witness = analyze(source)["candidate_witnesses"][0]
        self.assertEqual(witness["source_id"], "bundle")
        self.assertEqual(witness["node_path"], ["artifact:bundle", "job:publish"])
        self.assertEqual(witness["edge_channels"], ["artifact_consumed"])

    def test_permission_and_source_trust_boundaries(self):
        source = fixture()
        source["jobs"][1]["permissions"] = "read"
        document = analyze(source)
        self.assertEqual(document["overall_outcome"], "no_candidate_under_complete_supplied_graph")
        source["jobs"][1]["permissions"] = "unknown"
        document = analyze(source)
        self.assertEqual(document["overall_outcome"], "unknown")
        self.assertEqual(document["unknown_witnesses"][0]["reason"], "target_permission_unknown")
        source["jobs"][1]["permissions"] = "write"
        source["event"]["trust"] = "unknown"
        document = analyze(source)
        self.assertEqual(document["overall_outcome"], "unknown")
        self.assertEqual(document["unknown_witnesses"][0]["reason"], "source_trust_unknown")
        source["event"]["trust"] = "trusted"
        document = analyze(source)
        self.assertEqual(document["overall_outcome"], "no_candidate_under_complete_supplied_graph")
        self.assertEqual(document["source_observations"][0]["outcome"], "declared_trusted_source")

    def test_incomplete_graph_has_no_negative_claim_but_retains_candidate(self):
        source = fixture()
        source["graph_complete"] = False
        self.assertEqual(analyze(source)["overall_outcome"], "candidate_paths_present")
        source["jobs"][1]["consumes_artifact_ids"] = []
        document = analyze(source)
        self.assertEqual(document["overall_outcome"], "unknown")
        self.assertEqual(document["candidate_witness_count"], 0)
        self.assertEqual(document["source_observations"][0]["outcome"], "unknown")

    def test_shortest_witness_and_deterministic_tie_break(self):
        source = fixture()
        source["jobs"].append(
            {
                "job_id": "alternate",
                "permissions": "read",
                "uses_event_input": True,
                "needs_job_ids": [],
                "uses_job_output_ids": [],
                "consumes_artifact_ids": [],
            }
        )
        source["jobs"][1]["uses_job_output_ids"] = ["alternate", "build"]
        witness = analyze(source)["candidate_witnesses"][0]
        self.assertEqual(witness["hop_count"], 2)
        self.assertEqual(
            witness["node_path"], ["event:pull-request", "job:alternate", "job:publish"]
        )
        source["jobs"][1]["uses_event_input"] = True
        witness = analyze(source)["candidate_witnesses"][0]
        self.assertEqual(witness["node_path"], ["event:pull-request", "job:publish"])

    def test_cycle_is_finite_and_no_phantom_path(self):
        source = fixture()
        source["jobs"][0]["uses_job_output_ids"] = ["publish"]
        witness = analyze(source)["candidate_witnesses"][0]
        self.assertEqual(witness["hop_count"], 3)
        source["jobs"][0]["uses_event_input"] = False
        document = analyze(source)
        self.assertEqual(document["candidate_witness_count"], 0)
        self.assertEqual(document["overall_outcome"], "no_candidate_under_complete_supplied_graph")

    def test_multiple_sources_and_targets_have_stable_order(self):
        source = fixture()
        source["artifacts"][0]["trust"] = "untrusted"
        source["source_ids"] = ["bundle", "pull-request"]
        source["jobs"].append(
            {
                "job_id": "release",
                "permissions": "write",
                "uses_event_input": False,
                "needs_job_ids": [],
                "uses_job_output_ids": ["build"],
                "consumes_artifact_ids": [],
            }
        )
        document = analyze(source)
        self.assertEqual(document["candidate_witness_count"], 3)
        self.assertEqual(
            [(w["source_id"], w["target_job_id"]) for w in document["candidate_witnesses"]],
            [("bundle", "publish"), ("pull-request", "publish"), ("pull-request", "release")],
        )

    def test_roundtrip_detachment_and_separate_originals(self):
        source = fixture()
        original = copy.deepcopy(source)
        report = ci.analyze_supplied_ci_workflow_trust(source)
        expected = report.to_json()
        for rebuilt in (
            ci.CiWorkflowTrustAnalysis.from_dict(report.to_dict()),
            ci.CiWorkflowTrustAnalysis.from_json(expected),
            ci.analyze_supplied_ci_workflow_trust_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            ci.verify_supplied_ci_workflow_trust_analysis(report, model=source),
        ):
            self.assertEqual(rebuilt.to_json(), expected)
        self.assertEqual(report.analysis_id, report.to_dict()["analysis_id"])
        self.assertEqual(report.analysis_sha256, report.to_dict()["analysis_sha256"])
        source["jobs"][1]["permissions"] = "read"
        exported = report.to_dict()
        exported["candidate_witnesses"].clear()
        self.assertEqual(report.to_json(), expected)
        with self.assertRaises(ERROR):
            ci.verify_supplied_ci_workflow_trust_analysis(report, model=source)
        self.assertEqual(
            ci.verify_supplied_ci_workflow_trust_analysis(report, model=original).to_json(),
            expected,
        )

    def test_closed_shapes_aliases_and_references(self):
        source = fixture()
        for version in (True, 1.0, "1", None, 0, 2):
            self.deny_before_hash({**source, "schema_version": version})
        self.deny_before_hash({**source, "extra": None})
        self.deny_before_hash({**source, "jobs": []})
        self.deny_before_hash({**source, "graph_complete": 1})
        for field in source["event"]:
            changed = copy.deepcopy(source)
            changed["event"].pop(field)
            self.deny_before_hash(changed)
        for field in source["jobs"][0]:
            changed = copy.deepcopy(source)
            changed["jobs"][0].pop(field)
            self.deny_before_hash(changed)
        for field in source["artifacts"][0]:
            changed = copy.deepcopy(source)
            changed["artifacts"][0].pop(field)
            self.deny_before_hash(changed)
        for field, value in (
            ("permissions", True),
            ("permissions", "admin"),
            ("uses_event_input", 1),
            ("consumes_artifact_ids", ["missing"]),
            ("needs_job_ids", ["missing"]),
            ("needs_job_ids", ["build"]),
            ("uses_job_output_ids", ["build"]),
        ):
            changed = copy.deepcopy(source)
            changed["jobs"][0][field] = value
            self.deny_before_hash(changed)
        for field, value in (
            ("trust", "maybe"),
            ("producer_job_id", "missing"),
            ("artifact_id", "build"),
        ):
            changed = copy.deepcopy(source)
            changed["artifacts"][0][field] = value
            self.deny_before_hash(changed)
        for sources in ([], ["missing"], ["pull-request", "pull-request"], ["pull-request"] * 9):
            changed = copy.deepcopy(source)
            changed["source_ids"] = sources
            self.deny_before_hash(changed)

        class Mapping(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        self.deny_before_hash(Mapping(source))

    def test_sorted_unique_links_and_global_ids(self):
        source = fixture()
        source["jobs"][1]["needs_job_ids"] = ["build", "build"]
        self.deny_before_hash(source)
        source = fixture()
        source["jobs"].append(
            {
                "job_id": "a",
                "permissions": "read",
                "uses_event_input": False,
                "needs_job_ids": [],
                "uses_job_output_ids": [],
                "consumes_artifact_ids": [],
            }
        )
        source["jobs"][1]["uses_job_output_ids"] = ["build", "a"]
        self.deny_before_hash(source)
        source = fixture()
        source["jobs"][1]["job_id"] = "pull-request"
        self.deny_before_hash(source)
        source = fixture()
        source["artifacts"][0]["artifact_id"] = "publish"
        self.deny_before_hash(source)

    def test_raw_duplicate_keys_lexical_bounds_and_bytes(self):
        source = canonical(fixture())
        for raw in (
            source.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            source.replace('"permissions":"read"', '"permissions":"read","permissions":"write"', 1),
            source.replace('"schema_version":1', '"schema_version":01'),
            source.replace('"schema_version":1', '"schema_version":1.0'),
            '"' + "x" * 257 + '"',
            '"' + "\\u0078" * 257 + '"',
            '"\\u00e4"',
            "[" * 16 + "0" + "]" * 16,
            "9" * 20000,
        ):
            with patch.object(ci, "_address") as address, self.assertRaises(ERROR):
                ci.analyze_supplied_ci_workflow_trust_bytes(model_bytes=raw.encode("ascii"))
            address.assert_not_called()

        class Bytes(bytes):
            pass

        for content in (b"", b"\xff", "{}", bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}")):
            with self.assertRaises(ERROR):
                ci.analyze_supplied_ci_workflow_trust_bytes(model_bytes=content)
        expected = ci.analyze_supplied_ci_workflow_trust(fixture()).to_json()
        for raw in (
            json.dumps(fixture(), indent=2),
            source.replace("synthetic-ci", "\\u0073ynthetic-ci"),
        ):
            self.assertEqual(
                ci.analyze_supplied_ci_workflow_trust_bytes(
                    model_bytes=raw.encode("ascii")
                ).to_json(),
                expected,
            )

    def test_cycles_depth_work_and_family_bounds(self):
        cycle = []
        cycle.append(cycle)
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (cycle, nested, [None] * 32768, ["\\" * 256] * 2100):
            with patch.object(ci.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()
        with patch.object(ci, "MAX_WORK", 1):
            self.deny_before_hash(fixture())
        source = fixture()
        source["jobs"] = [
            {**copy.deepcopy(source["jobs"][0]), "job_id": f"job-{i}"} for i in range(25)
        ]
        self.deny_before_hash(source)
        source = fixture()
        source["artifacts"] = [
            {"artifact_id": f"a-{i}", "trust": "unknown", "producer_job_id": None}
            for i in range(25)
        ]
        self.deny_before_hash(source)

    def test_cohashed_forgery_and_mutated_wrapper_rejected(self):
        document = analyze(fixture())
        for field, value in (
            ("target_job_id", "build"),
            ("hop_count", 1),
            ("node_path", ["event:pull-request", "job:publish"]),
            ("edge_channels", ["needs"]),
        ):
            changed = copy.deepcopy(document)
            changed["candidate_witnesses"][0][field] = value
            with self.assertRaises(ERROR):
                ci.CiWorkflowTrustAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "exploitability_verified", True),
            ("effects", "process", "invoked"),
            ("bounds", "jobs", 25),
        ):
            changed = copy.deepcopy(document)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                ci.CiWorkflowTrustAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(document)
        changed["source_model_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ERROR):
            ci.CiWorkflowTrustAnalysis.from_dict(readdress(changed))
        report = ci.analyze_supplied_ci_workflow_trust(fixture())
        object.__setattr__(report, "_document_json", canonical(readdress(changed)))
        with self.assertRaises(ERROR):
            report.to_dict()
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                ci.verify_supplied_ci_workflow_trust_analysis(foreign, model=fixture())

    def test_no_file_network_process_or_ci_effects(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            self.assertEqual(analyze(fixture())["candidate_witness_count"], 1)


if __name__ == "__main__":
    unittest.main()
