"""Synthetic DOM path protection, uncertainty and replay controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_dom_dataflow as dom

ERROR = dom.DomDataflowAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def fixture():
    return dom.component_fixture()


def analyze(source):
    return dom.analyze_supplied_dom_dataflow(source).to_dict()


def row(source, sink_id="script-sink"):
    return next(item for item in analyze(source)["sink_observations"] if item["sink_id"] == sink_id)


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-dom-dataflow.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "DDF-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class DomDataflowTests(unittest.TestCase):
    def deny_before_hash(self, source):
        with patch.object(dom, "_address") as address:
            with self.assertRaises(ERROR):
                dom.analyze_supplied_dom_dataflow(source)
            address.assert_not_called()

    def test_fixture_exact_addresses_outcomes_and_boundary(self):
        document = analyze(fixture())
        self.assertEqual(document["analysis_id"], "DDF-DD8E82B2658A12730CF94AD53037CA83")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:dd8e82b2658a12730cf94ad53037ca8358eb1d77511450b416e55a2085ee68ea",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:03188627b07f3fd19988817a00f1215c4c8abba4f17553d951ee5271728efb81",
        )
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S13")
        self.assertEqual(document["blueprint_sha256"], dom.BLUEPRINT_SHA256)
        self.assertEqual(
            (
                document["observation_count"],
                document["candidate_path_count"],
                document["unknown_count"],
            ),
            (2, 1, 0),
        )
        self.assertEqual(
            [item["outcome"] for item in document["sink_observations"]],
            ["protected_under_supplied_declarations", "candidate_unprotected_path"],
        )
        self.assertEqual(
            document["sink_observations"][1]["witness_node_ids"],
            ["location-fragment", "passthrough", "script-sink"],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))

    def test_context_match_mismatch_and_declared_protection(self):
        source = fixture()
        source["transforms"][0]["protects_contexts"] = ["javascript_string"]
        self.assertEqual(row(source, "markup-sink")["outcome"], "candidate_unprotected_path")
        source["transforms"][0]["protects_contexts"] = ["html_markup"]
        self.assertEqual(
            row(source, "markup-sink")["outcome"], "protected_under_supplied_declarations"
        )
        source["transforms"][0]["kind"] = "sanitizer"
        self.assertEqual(
            row(source, "markup-sink")["outcome"], "protected_under_supplied_declarations"
        )

    def test_unprotected_parallel_path_overrides_protected_path(self):
        source = fixture()
        source["edges"].append({"from_id": "passthrough", "to_id": "markup-sink"})
        source["edges"].sort(key=lambda edge: (edge["from_id"], edge["to_id"]))
        observed = row(source, "markup-sink")
        self.assertEqual(observed["outcome"], "candidate_unprotected_path")
        self.assertEqual(
            observed["witness_node_ids"],
            ["location-fragment", "passthrough", "markup-sink"],
        )

    def test_protection_preserved_by_declared_passthrough(self):
        source = fixture()
        source["edges"] = [
            {"from_id": "html-encode", "to_id": "passthrough"},
            {"from_id": "location-fragment", "to_id": "html-encode"},
            {"from_id": "passthrough", "to_id": "markup-sink"},
        ]
        self.assertEqual(
            row(source, "markup-sink")["outcome"], "protected_under_supplied_declarations"
        )

    def test_nonmatching_complete_transform_replaces_prior_protection(self):
        for kind in ("encoder", "sanitizer"):
            with self.subTest(kind=kind):
                source = fixture()
                source["transforms"].append(
                    {
                        "transform_id": "later-transform",
                        "kind": kind,
                        "protects_contexts": ["javascript_string"],
                        "semantics_complete": True,
                    }
                )
                source["edges"] = [
                    {"from_id": "html-encode", "to_id": "later-transform"},
                    {"from_id": "later-transform", "to_id": "markup-sink"},
                    {"from_id": "location-fragment", "to_id": "html-encode"},
                ]
                observed = row(source, "markup-sink")
                self.assertEqual(observed["outcome"], "candidate_unprotected_path")
                self.assertEqual(
                    observed["witness_node_ids"],
                    ["location-fragment", "html-encode", "later-transform", "markup-sink"],
                )
                report = dom.analyze_supplied_dom_dataflow(source)
                self.assertEqual(
                    dom.verify_supplied_dom_dataflow_analysis(
                        dom.DomDataflowAnalysis.from_json(report.to_json()), model=source
                    ).to_json(),
                    report.to_json(),
                )
                source["transforms"][-1]["protects_contexts"] = ["html_markup"]
                self.assertEqual(
                    row(source, "markup-sink")["outcome"],
                    "protected_under_supplied_declarations",
                )
                with self.assertRaises(ERROR):
                    dom.verify_supplied_dom_dataflow_analysis(report, model=source)

    def test_incomplete_or_unsupported_semantics_never_candidate(self):
        changes = (
            ("graph_incomplete", lambda x: x.update(graph_complete=False)),
            ("source_trust_unknown", lambda x: x["sources"][0].update(trust="unknown")),
            ("sink_context_unsupported", lambda x: x["sinks"][1].update(context="unsupported")),
            ("sink_semantics_incomplete", lambda x: x["sinks"][1].update(semantics_complete=False)),
            (
                "path_transform_semantics_unknown",
                lambda x: x["transforms"][1].update(semantics_complete=False),
            ),
            (
                "path_transform_semantics_unknown",
                lambda x: x["transforms"][1].update(kind="unsupported"),
            ),
        )
        for reason, change in changes:
            source = fixture()
            change(source)
            observed = row(source)
            self.assertEqual(observed["outcome"], "unknown", reason)
            self.assertIn(reason, observed["uncertainty"])
            self.assertEqual(analyze(source)["candidate_path_count"], 0)

    def test_unknown_parallel_path_does_not_suppress_known_candidate(self):
        source = fixture()
        source["edges"].append({"from_id": "html-encode", "to_id": "script-sink"})
        source["edges"].sort(key=lambda edge: (edge["from_id"], edge["to_id"]))
        source["transforms"][0]["semantics_complete"] = False
        observed = row(source)
        self.assertEqual(observed["outcome"], "candidate_unprotected_path")
        self.assertEqual(
            observed["witness_node_ids"],
            ["location-fragment", "passthrough", "script-sink"],
        )
        self.assertIn("path_transform_semantics_unknown", observed["uncertainty"])
        report = dom.analyze_supplied_dom_dataflow(source)
        self.assertEqual(report.to_dict()["candidate_path_count"], 1)
        self.assertEqual(
            dom.verify_supplied_dom_dataflow_analysis(
                dom.DomDataflowAnalysis.from_json(report.to_json()), model=source
            ).to_json(),
            report.to_json(),
        )

    def test_trusted_nonsensitive_and_unreachable(self):
        source = fixture()
        source["sources"][0]["trust"] = "trusted"
        self.assertEqual(row(source)["outcome"], "declared_trusted_source")
        source = fixture()
        source["sinks"][1]["sensitive"] = False
        self.assertEqual(row(source)["outcome"], "declared_nonsensitive_sink")
        source = fixture()
        source["edges"].pop()
        observed = row(source)
        self.assertEqual(observed["outcome"], "not_reachable_under_supplied_graph")
        self.assertFalse(observed["reachable"])
        self.assertIsNone(observed["witness_node_ids"])

    def test_cycle_finite_and_shortest_witness(self):
        source = fixture()
        source["edges"].append({"from_id": "passthrough", "to_id": "html-encode"})
        source["edges"].append({"from_id": "html-encode", "to_id": "passthrough"})
        source["edges"].sort(key=lambda edge: (edge["from_id"], edge["to_id"]))
        observed = row(source)
        self.assertEqual(observed["outcome"], "candidate_unprotected_path")
        self.assertEqual(
            observed["witness_node_ids"], ["location-fragment", "passthrough", "script-sink"]
        )

    def test_multiple_sources_and_sinks_sorted_stably(self):
        source = fixture()
        source["sources"].append({"source_id": "a-source", "trust": "trusted"})
        source["source_ids"] = ["a-source", "location-fragment"]
        source["edges"].append({"from_id": "a-source", "to_id": "script-sink"})
        source["edges"].sort(key=lambda edge: (edge["from_id"], edge["to_id"]))
        document = analyze(source)
        self.assertEqual(document["observation_count"], 4)
        self.assertEqual(
            [(item["source_id"], item["sink_id"]) for item in document["sink_observations"]],
            [
                ("a-source", "markup-sink"),
                ("a-source", "script-sink"),
                ("location-fragment", "markup-sink"),
                ("location-fragment", "script-sink"),
            ],
        )

    def test_roundtrip_detachment_and_separate_originals(self):
        source = fixture()
        original = copy.deepcopy(source)
        report = dom.analyze_supplied_dom_dataflow(source)
        expected = report.to_json()
        for rebuilt in (
            dom.DomDataflowAnalysis.from_dict(report.to_dict()),
            dom.DomDataflowAnalysis.from_json(expected),
            dom.analyze_supplied_dom_dataflow_bytes(model_bytes=canonical(source).encode("ascii")),
            dom.verify_supplied_dom_dataflow_analysis(report, model=source),
        ):
            self.assertEqual(rebuilt.to_json(), expected)
        self.assertEqual(report.analysis_id, report.to_dict()["analysis_id"])
        self.assertEqual(report.analysis_sha256, report.to_dict()["analysis_sha256"])
        source["sinks"][1]["sensitive"] = False
        exported = report.to_dict()
        exported["sink_observations"].clear()
        self.assertEqual(report.to_json(), expected)
        with self.assertRaises(ERROR):
            dom.verify_supplied_dom_dataflow_analysis(report, model=source)
        self.assertEqual(
            dom.verify_supplied_dom_dataflow_analysis(report, model=original).to_json(), expected
        )

    def test_closed_shapes_aliases_and_references(self):
        source = fixture()
        for version in (True, 1.0, "1", None, 0, 2):
            self.deny_before_hash({**source, "schema_version": version})
        self.deny_before_hash({**source, "extra": None})
        self.deny_before_hash({**source, "graph_complete": 1})
        for section, index in (("sources", 0), ("transforms", 0), ("sinks", 0), ("edges", 0)):
            for field in source[section][index]:
                changed = copy.deepcopy(source)
                changed[section][index].pop(field)
                self.deny_before_hash(changed)
        for trust in (True, 1, None, "maybe"):
            changed = copy.deepcopy(source)
            changed["sources"][0]["trust"] = trust
            self.deny_before_hash(changed)
        for context in (True, None, "css_unknown"):
            changed = copy.deepcopy(source)
            changed["sinks"][0]["context"] = context
            self.deny_before_hash(changed)
        for identity in ("", "bad space", "x" * 129, True):
            changed = copy.deepcopy(source)
            changed["sources"][0]["source_id"] = identity
            self.deny_before_hash(changed)
        for selected in ([], ["missing"], ["location-fragment"] * 2):
            changed = copy.deepcopy(source)
            changed["source_ids"] = selected
            self.deny_before_hash(changed)

        class Mapping(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        self.deny_before_hash(Mapping(source))

    def test_edges_contexts_and_global_id_controls(self):
        source = fixture()
        source["edges"].append(copy.deepcopy(source["edges"][0]))
        self.deny_before_hash(source)
        for start, end in (
            ("missing", "script-sink"),
            ("script-sink", "passthrough"),
            ("passthrough", "location-fragment"),
            ("passthrough", "passthrough"),
        ):
            source = fixture()
            source["edges"] = [{"from_id": start, "to_id": end}]
            self.deny_before_hash(source)
        source = fixture()
        source["edges"].reverse()
        self.deny_before_hash(source)
        source = fixture()
        source["transforms"][0]["protects_contexts"] = ["javascript_string", "html_markup"]
        self.deny_before_hash(source)
        source = fixture()
        source["transforms"][1]["protects_contexts"] = ["html_markup"]
        self.deny_before_hash(source)
        source = fixture()
        source["sinks"][0]["sink_id"] = "passthrough"
        self.deny_before_hash(source)

    def test_raw_duplicate_keys_lexical_bounds_and_bytes(self):
        source = canonical(fixture())
        for raw in (
            source.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            source.replace('"trust":"untrusted"', '"trust":"untrusted","trust":"trusted"'),
            source.replace('"schema_version":1', '"schema_version":01'),
            source.replace('"schema_version":1', '"schema_version":1.0'),
            '"' + "x" * 257 + '"',
            '"' + "\\u0078" * 257 + '"',
            '"\\u00e4"',
            "[" * 16 + "0" + "]" * 16,
            "9" * 20000,
        ):
            with patch.object(dom, "_address") as address, self.assertRaises(ERROR):
                dom.analyze_supplied_dom_dataflow_bytes(model_bytes=raw.encode("ascii"))
            address.assert_not_called()

        class Bytes(bytes):
            pass

        for content in (b"", b"\xff", "{}", bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}")):
            with self.assertRaises(ERROR):
                dom.analyze_supplied_dom_dataflow_bytes(model_bytes=content)
        expected = dom.analyze_supplied_dom_dataflow(fixture()).to_json()
        for raw in (
            json.dumps(fixture(), indent=2),
            source.replace("location-fragment", "\\u006cocation-fragment"),
        ):
            self.assertEqual(
                dom.analyze_supplied_dom_dataflow_bytes(model_bytes=raw.encode("ascii")).to_json(),
                expected,
            )

    def test_cycles_depth_work_and_family_bounds(self):
        cycle = []
        cycle.append(cycle)
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (cycle, nested, [None] * 32768, ["\\" * 256] * 2100):
            with patch.object(dom.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()
        with patch.object(dom, "MAX_WORK", 1):
            self.deny_before_hash(fixture())
        source = fixture()
        source["sources"] = [{"source_id": f"s-{i}", "trust": "untrusted"} for i in range(9)]
        self.deny_before_hash(source)
        source = fixture()
        source["transforms"] = [
            {
                "transform_id": f"t-{i}",
                "kind": "passthrough",
                "protects_contexts": [],
                "semantics_complete": True,
            }
            for i in range(33)
        ]
        self.deny_before_hash(source)
        source = fixture()
        source["sinks"] = [
            {
                "sink_id": f"sink-{i}",
                "context": "html_markup",
                "sensitive": True,
                "semantics_complete": True,
            }
            for i in range(17)
        ]
        self.deny_before_hash(source)

    def test_cohashed_forgery_effect_promotion_and_mutated_wrapper(self):
        document = analyze(fixture())
        for field, value in (
            ("outcome", "verified_xss"),
            ("witness_node_ids", ["location-fragment", "script-sink"]),
            ("reachable", False),
            ("uncertainty", ["none"]),
        ):
            changed = copy.deepcopy(document)
            changed["sink_observations"][1][field] = value
            with self.assertRaises(ERROR):
                dom.DomDataflowAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "xss_verified", True),
            ("effects", "browser", "invoked"),
            ("bounds", "sinks", 17),
        ):
            changed = copy.deepcopy(document)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                dom.DomDataflowAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(document)
        changed["source_model_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ERROR):
            dom.DomDataflowAnalysis.from_dict(readdress(changed))
        report = dom.analyze_supplied_dom_dataflow(fixture())
        object.__setattr__(report, "_document_json", canonical(readdress(changed)))
        with self.assertRaises(ERROR):
            report.to_dict()
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                dom.verify_supplied_dom_dataflow_analysis(foreign, model=fixture())

    def test_no_browser_file_network_process_or_credentials(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            self.assertEqual(analyze(fixture())["candidate_path_count"], 1)


if __name__ == "__main__":
    unittest.main()
