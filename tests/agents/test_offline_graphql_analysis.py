"""Synthetic, source-bound checks for a closed GraphQL query subset."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from sunderkey import offline_graphql_analysis as graphql


def canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def schema_document() -> dict:
    return {
        "query_type": "Query",
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "fields": [
                    {"name": "viewer", "type": "User"},
                    {"name": "users", "type": "[[User!]!]!"},
                    {"name": "ping", "type": "String"},
                ],
            },
            {
                "name": "User",
                "kind": "OBJECT",
                "fields": [
                    {"name": "id", "type": "ID!"},
                    {"name": "name", "type": "String"},
                    {"name": "friends", "type": "[User!]"},
                    {"name": "role", "type": "Role"},
                ],
            },
            {"name": "String", "kind": "SCALAR", "fields": []},
            {"name": "ID", "kind": "SCALAR", "fields": []},
            {"name": "Role", "kind": "ENUM", "fields": []},
        ],
    }


def readdress(document: dict) -> dict:
    result = copy.deepcopy(document)
    body = {
        key: value for key, value in result.items() if key not in {"report_id", "report_sha256"}
    }
    digest = hashlib.sha256(canonical({"domain": graphql.DOMAIN, "analysis": body})).hexdigest()
    result["report_id"] = "GQA-" + digest[:32].upper()
    result["report_sha256"] = "sha256:" + digest
    return result


class StringAlias(str):
    pass


class IntegerAlias(int):
    pass


class BytesAlias(bytes):
    pass


class ListAlias(list):
    def __iter__(self):
        raise AssertionError("Native array intake must not call subclass hooks")


class LimitsAlias(graphql.GraphQLAnalysisLimits):
    pass


class ReportAlias(graphql.GraphQLAnalysisReport):
    pass


class OfflineGraphQLAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = canonical(schema_document())
        self.query = b"query Demo { people: users { ident: id friends { name } } ping }"
        self.limits = graphql.GraphQLAnalysisLimits(65536, 65536, 32, 10000, 10000, 1000000)

    def inputs(self, **changes) -> dict:
        return {
            "schema_content": self.schema,
            "query_content": self.query,
            "schema_source_id": "schema:fixture-v1",
            "query_source_id": "query:demo-v1",
            "operation_name": "Demo",
            "limits": self.limits,
            **changes,
        }

    def analyze(self, **changes) -> graphql.GraphQLAnalysisReport:
        return graphql.analyze_graphql_operation(**self.inputs(**changes))

    def assert_rejected(self, query: bytes, **changes) -> None:
        with self.assertRaises(graphql.GraphQLAnalysisError):
            self.analyze(query_content=query, operation_name=None, **changes)

    def test_nested_fields_list_layers_aliases_and_exact_sources(self) -> None:
        report = self.analyze()
        document = report.to_dict()
        self.assertEqual(
            document["metrics"],
            {
                "schema_type_count": 5,
                "schema_field_count": 7,
                "operation_count": 1,
                "fragment_count": 0,
                "selected_ast_field_count": 5,
                "expanded_field_count": 5,
                "expanded_alias_count": 2,
                "expanded_fragment_spread_count": 0,
                "max_field_depth": 3,
                "max_list_layers_on_path": 3,
                "max_sibling_field_occurrences": 2,
            },
        )
        self.assertEqual(
            document["witnesses"]["deepest_field_path"], ["people:users", "friends", "name"]
        )
        self.assertEqual(
            document["witnesses"]["most_list_layers_path"], ["people:users", "friends", "name"]
        )
        for field, content in (("schema_source", self.schema), ("query_source", self.query)):
            self.assertEqual(
                document[field]["sha256"], "sha256:" + hashlib.sha256(content).hexdigest()
            )
            self.assertEqual(document[field]["byte_count"], len(content))
        self.assertEqual(graphql.verify_graphql_operation_analysis(report, **self.inputs()), report)
        self.assertTrue(document["offline_only"])
        self.assertFalse(document["positive_use_approved"])
        self.assertFalse(document["server_cost_estimated"])
        self.assertFalse(document["qualification_claimed"])
        self.assertEqual(set(document["effects"].values()), {"none"})

    def test_canonical_roundtrip_and_detached_outputs(self) -> None:
        report = self.analyze()
        original = report.to_json()
        detached = report.to_dict()
        detached["metrics"]["expanded_field_count"] = 9
        detached["effects"]["target"] = "other"
        self.assertEqual(report.to_json(), original)
        self.assertEqual(graphql.GraphQLAnalysisReport.from_json("\n" + original + "\n"), report)
        verified = graphql.verify_graphql_operation_analysis(report, **self.inputs())
        self.assertIsNot(verified, report)
        self.assertEqual(verified.to_json(), original)

    def test_literal_report_identity(self) -> None:
        document = self.analyze().to_dict()
        self.assertEqual(document["report_id"], "GQA-1323D07D543183FCCD3EE60F2AD77085")
        self.assertEqual(
            document["report_sha256"],
            "sha256:1323d07d543183fccd3ee60f2ad7708510f6269716cd001ce44bebce35fc7dc0",
        )

    def test_leaf_enum_and_named_or_anonymous_query_controls(self) -> None:
        for query in (
            b"{ viewer { role } }",
            b"query { viewer { role } }",
            b"query One { viewer { role } }",
        ):
            with self.subTest(query=query):
                report = self.analyze(query_content=query, operation_name=None)
                self.assertEqual(report.to_dict()["metrics"]["expanded_field_count"], 2)

    def test_fragment_multiplicity_and_dag_summary(self) -> None:
        definitions = ["fragment F0 on User { ident: id }"]
        definitions.extend(
            f"fragment F{index} on User {{ ...F{index - 1} ...F{index - 1} }}"
            for index in range(1, 19)
        )
        query = ("query Demo { viewer { ...F18 } } " + " ".join(definitions)).encode("ascii")
        report = self.analyze(query_content=query)
        metrics = report.to_dict()["metrics"]
        self.assertEqual(metrics["expanded_field_count"], 1 + 2**18)
        self.assertEqual(metrics["expanded_alias_count"], 2**18)
        self.assertEqual(metrics["expanded_fragment_spread_count"], 2**19 - 1)
        self.assertEqual(metrics["max_sibling_field_occurrences"], 2**18)
        self.assertEqual(metrics["selected_ast_field_count"], 1)
        self.assertEqual(metrics["fragment_count"], 19)
        self.assertEqual(metrics["max_field_depth"], 2)
        self.assertEqual(
            report.to_dict()["witnesses"]["deepest_field_path"], ["viewer", "ident:id"]
        )

    def test_fragment_expansion_ceiling_without_expanded_tree(self) -> None:
        definitions = ["fragment F0 on User { id }"]
        definitions.extend(
            f"fragment F{index} on User {{ ...F{index - 1} ...F{index - 1} }}"
            for index in range(1, 21)
        )
        query = ("{ viewer { ...F20 } } " + " ".join(definitions)).encode("ascii")
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "selection ceiling"):
            self.analyze(query_content=query, operation_name=None)
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "selection ceiling"):
            self.analyze(limits=replace(self.limits, max_expanded_selections=4))

    def test_fragment_definition_permutation_keeps_deterministic_summary(self) -> None:
        first = (
            b"query Demo { viewer { ...A ...B } } "
            b"fragment A on User { name } fragment B on User { id }"
        )
        second = (
            b"fragment B on User { id } fragment A on User { name } "
            b"query Demo { viewer { ...B ...A } }"
        )
        left = self.analyze(query_content=first).to_dict()
        right = self.analyze(query_content=second).to_dict()
        self.assertEqual(left["metrics"], right["metrics"])
        self.assertEqual(left["witnesses"], right["witnesses"])
        self.assertEqual(left["witnesses"]["deepest_field_path"], ["viewer", "id"])
        self.assertNotEqual(left["report_sha256"], right["report_sha256"])

    def test_cycles_including_unused_are_rejected(self) -> None:
        queries = (
            b"{ viewer { ...A } } fragment A on User { ...A }",
            b"{ viewer { ...A } } fragment A on User { ...B } fragment B on User { ...A }",
            b"{ ping } fragment A on User { friends { ...B } } fragment B on User { ...A }",
        )
        for query in queries:
            with (
                self.subTest(query=query),
                self.assertRaisesRegex(graphql.GraphQLAnalysisError, "cycle"),
            ):
                self.analyze(query_content=query, operation_name=None)

    def test_fragment_condition_reachability_and_selection(self) -> None:
        query = b"query One { ping } query Two { viewer { ...F } } fragment F on User { id }"
        report = self.analyze(query_content=query, operation_name="One")
        self.assertEqual(report.to_dict()["metrics"]["fragment_count"], 1)
        self.assertEqual(report.to_dict()["metrics"]["expanded_field_count"], 1)
        for invalid in (
            b"{ ping } fragment F on User { id }",
            b"{ viewer { ...F } } fragment F on Query { ping }",
            b"{ viewer { ...F } } fragment F on ID { id }",
            b"{ viewer { ...F } } fragment F on Missing { id }",
        ):
            with self.subTest(query=invalid):
                self.assert_rejected(invalid)

    def test_multiple_operations_need_exact_selection_and_all_are_checked(self) -> None:
        query = b"query One { ping } query Two { viewer { id } }"
        self.assertEqual(
            self.analyze(query_content=query, operation_name="Two").to_dict()["metrics"][
                "expanded_field_count"
            ],
            2,
        )
        for selected in (None, "Missing"):
            with self.subTest(selected=selected), self.assertRaises(graphql.GraphQLAnalysisError):
                self.analyze(query_content=query, operation_name=selected)
        for query in (
            b"{ ping } query Two { ping }",
            b"query One { ping } query One { ping }",
            b"query One { ping } query Two { unknown }",
        ):
            with self.subTest(query=query), self.assertRaises(graphql.GraphQLAnalysisError):
                self.analyze(query_content=query, operation_name="One")

    def test_undefined_fields_fragments_and_leaf_object_shapes(self) -> None:
        for query in (
            b"{ absent }",
            b"{ viewer { absent } }",
            b"{ viewer { ...Missing } }",
            b"{ viewer }",
            b"{ ping { name } }",
            b"{ viewer { role { name } } }",
        ):
            with self.subTest(query=query):
                self.assert_rejected(query)

    def test_repeated_response_keys_are_conservative_not_resolver_counts(self) -> None:
        report = self.analyze(query_content=b"{ ping ping again: ping }", operation_name=None)
        self.assertEqual(report.to_dict()["metrics"]["expanded_field_count"], 3)
        self.assertEqual(report.to_dict()["metrics"]["max_sibling_field_occurrences"], 3)
        for query in (b"{ x: ping x: viewer { id } }", b"{ viewer { id } viewer { name } }"):
            with (
                self.subTest(query=query),
                self.assertRaisesRegex(graphql.GraphQLAnalysisError, "response-key"),
            ):
                self.analyze(query_content=query, operation_name=None)

    def test_unsupported_constructs_fail_without_partial_result(self) -> None:
        for query in (
            b"mutation M { ping }",
            b"subscription S { ping }",
            b"query Q($x: ID) { ping }",
            b"{ viewer(id: 1) { id } }",
            b"{ ping @skip(if: true) }",
            b"{ viewer { ... on User { id } } }",
            b"type Query { ping: String }",
            b"{ __typename }",
            b'"description" query Q { ping }',
        ):
            with self.subTest(query=query):
                self.assert_rejected(query)

    def test_malformed_queries_names_and_duplicate_definitions(self) -> None:
        for query in (
            b"",
            b"{}",
            b"{",
            b"{ ping",
            b"{ :ping }",
            b"{ ping } }",
            b"{ ... }",
            b"{ ping } fragment F on Query { ping } fragment F on Query { ping }",
            b"{ " + b"a" * 129 + b" }",
            b"{\xff}",
        ):
            with self.subTest(query=query):
                self.assert_rejected(query)

    def test_insignificant_comments_commas_and_bom_are_supported(self) -> None:
        query = (
            "\ufeffquery Demo,# one\n{ people: users { ident: id, friends { name } },ping }".encode(
                "utf-8"
            )
        )
        self.assertEqual(
            self.analyze(query_content=query).to_dict()["metrics"],
            self.analyze().to_dict()["metrics"],
        )

    def test_schema_fields_types_and_root_are_closed_and_unique(self) -> None:
        changes = []
        for transform in (
            lambda d: d.update(query_type="Missing"),
            lambda d: d["types"].append(copy.deepcopy(d["types"][0])),
            lambda d: d["types"][0]["fields"].append(copy.deepcopy(d["types"][0]["fields"][0])),
            lambda d: d["types"][0]["fields"][0].update(type="Missing"),
            lambda d: d["types"][0].update(kind="INTERFACE"),
            lambda d: d["types"][0].update(fields=[]),
            lambda d: d["types"][2].update(fields=[{"name": "x", "type": "String"}]),
            lambda d: d.update(extra=False),
        ):
            document = schema_document()
            transform(document)
            changes.append(document)
        for document in changes:
            with self.subTest(document=document), self.assertRaises(graphql.GraphQLAnalysisError):
                self.analyze(schema_content=canonical(document))
        for field_type in ("", "User!!", "[User", "[User!]!!", "User junk", "[[User]]!x", "[]"):
            document = schema_document()
            document["types"][0]["fields"][0]["type"] = field_type
            with (
                self.subTest(field_type=field_type),
                self.assertRaises(graphql.GraphQLAnalysisError),
            ):
                self.analyze(schema_content=canonical(document))

    def test_json_duplicates_floats_nonfinite_and_large_integers(self) -> None:
        schema = self.schema
        for source in (
            b'{"query_type":"Query",' + schema[1:],
            schema.replace(b'"kind":"OBJECT"', b'"kind":"OBJECT","kind":"OBJECT"', 1),
            b'{"query_type":1.0,"types":[]}',
            b'{"query_type":NaN,"types":[]}',
            b'{"query_type":9223372036854775808,"types":[]}',
            b'{"query_type":true,"types":[]}',
        ):
            with self.subTest(source=source), self.assertRaises(graphql.GraphQLAnalysisError):
                self.analyze(schema_content=source)
        report = self.analyze().to_json()
        for text in (
            report.replace('"schema_version":1', '"schema_version":1.0'),
            report.replace('"schema_version":1', '"schema_version":true'),
            '{"schema_version":1,' + report[1:],
        ):
            with self.subTest(text=text), self.assertRaises(graphql.GraphQLAnalysisError):
                graphql.GraphQLAnalysisReport.from_json(text)

    def test_permutations_keep_metrics_but_change_exact_source_identity(self) -> None:
        report = self.analyze()
        schema = schema_document()
        schema["types"].reverse()
        for definition in schema["types"]:
            definition["fields"].reverse()
        other_schema = canonical(schema)
        other_query = b"query Demo { ping people: users { friends { name } ident: id } }"
        for changes in ({"schema_content": other_schema}, {"query_content": other_query}):
            with self.subTest(changes=changes):
                other = self.analyze(**changes)
                self.assertEqual(other.to_dict()["metrics"], report.to_dict()["metrics"])
                self.assertEqual(other.to_dict()["witnesses"], report.to_dict()["witnesses"])
                self.assertNotEqual(other.to_dict()["report_id"], report.to_dict()["report_id"])
                with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "does not reproduce"):
                    graphql.verify_graphql_operation_analysis(report, **self.inputs(**changes))

    def test_explicit_source_selection_and_limit_substitutions_reject_replay(self) -> None:
        report = self.analyze()
        for changes in (
            {"schema_source_id": "schema:other"},
            {"query_source_id": "query:other"},
            {"operation_name": None},
            {"limits": replace(self.limits, max_tokens=9999)},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(graphql.GraphQLAnalysisError, "does not reproduce"),
            ):
                graphql.verify_graphql_operation_analysis(report, **self.inputs(**changes))

    def test_rehashed_metric_substitution_requires_source_replay(self) -> None:
        report = self.analyze()
        document = report.to_dict()
        document["metrics"]["expanded_field_count"] = 6
        forged = graphql.GraphQLAnalysisReport.from_dict(readdress(document))
        self.assertEqual(forged.to_dict()["metrics"]["expanded_field_count"], 6)
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "does not reproduce"):
            graphql.verify_graphql_operation_analysis(forged, **self.inputs())
        for field in ("schema_source", "query_source"):
            document = report.to_dict()
            document[field]["sha256"] = "sha256:" + "a" * 64
            forged = graphql.GraphQLAnalysisReport.from_dict(readdress(document))
            with self.subTest(field=field), self.assertRaises(graphql.GraphQLAnalysisError):
                graphql.verify_graphql_operation_analysis(forged, **self.inputs())

    def test_rehashed_contradictions_and_positive_claims_fail_integrity(self) -> None:
        report = self.analyze()
        for path, value in (
            (("schema_version",), True),
            (("schema_version",), 1.0),
            (("profile_id",), "AOE-GB-D06-S01"),
            (("positive_use_approved",), True),
            (("qualification_claimed",), True),
            (("server_cost_estimated",), True),
            (("offline_only",), 1),
            (("effects", "execution"), "allowed"),
            (("metrics", "expanded_field_count"), False),
            (("metrics", "expanded_field_count"), 1000001),
            (("metrics", "max_field_depth"), 2),
            (("metrics", "max_list_layers_on_path"), 33),
            (("metrics", "expanded_alias_count"), 6),
            (("metrics", "max_sibling_field_occurrences"), 6),
            (("operation_selection", "selected_name"), "Different"),
            (("query_source", "byte_count"), 65537),
        ):
            document = report.to_dict()
            selected = document
            for key in path[:-1]:
                selected = selected[key]
            selected[path[-1]] = value
            with (
                self.subTest(path=path, value=value),
                self.assertRaises(graphql.GraphQLAnalysisError),
            ):
                graphql.GraphQLAnalysisReport.from_dict(readdress(document))

    def test_bounds_before_hashing_and_native_alias_denial(self) -> None:
        limits_alias = object.__new__(LimitsAlias)
        for key, value in self.limits.to_dict().items():
            object.__setattr__(limits_alias, key, value)
        for changes in (
            {"schema_content": BytesAlias(self.schema)},
            {"query_content": BytesAlias(self.query)},
            {"schema_source_id": StringAlias("schema:fixture-v1")},
            {"operation_name": StringAlias("Demo")},
            {"query_source_id": "x" * 129},
            {"schema_content": self.schema * 2000},
            {"query_content": self.query * 2000},
            {"limits": object.__new__(graphql.GraphQLAnalysisLimits)},
            {"limits": limits_alias},
        ):
            with (
                self.subTest(changes=changes),
                patch.object(
                    graphql.hashlib,
                    "sha256",
                    side_effect=AssertionError("Rejected intake must precede hash work"),
                ),
                self.assertRaises(graphql.GraphQLAnalysisError),
            ):
                self.analyze(**changes)
        for value in (True, 1.0, IntegerAlias(1), 0, -1, 1000001):
            with self.subTest(value=value), self.assertRaises(graphql.GraphQLAnalysisError):
                graphql.GraphQLAnalysisLimits(65536, 65536, 32, 10000, 10000, value)

    def test_each_declared_cost_limit_has_a_real_denial(self) -> None:
        for field, value in (
            ("max_schema_bytes", len(self.schema) - 1),
            ("max_query_bytes", len(self.query) - 1),
            ("max_depth", 2),
            ("max_tokens", 3),
            ("max_nodes", 10),
            ("max_expanded_selections", 4),
        ):
            with self.subTest(field=field), self.assertRaises(graphql.GraphQLAnalysisError):
                self.analyze(limits=replace(self.limits, **{field: value}))
        query = ("{ viewer " + "{ friends " * 7 + "{ id }" + "}" * 8 + "}").encode("ascii")
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "selection depth"):
            self.analyze(
                query_content=query, operation_name=None, limits=replace(self.limits, max_depth=8)
            )
        definitions = ["fragment F0 on Query { ping }"]
        definitions.extend(
            f"fragment F{index} on Query {{ ...F{index - 1} }}" for index in range(1, 33)
        )
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "dependency graph"):
            self.analyze(
                query_content=("{ ...F32 } " + " ".join(definitions)).encode("ascii"),
                operation_name=None,
            )

    def test_shared_graph_and_escaped_byte_budget_precede_serialization(self) -> None:
        chunk = ['\\"' * 2048]
        shared = [chunk] * 500
        for document in (shared, [None] * (graphql.MAX_ITEMS + 1), [[[[None]]]] * 15000):
            with (
                self.subTest(shape=type(document)),
                patch.object(
                    graphql.json,
                    "dumps",
                    side_effect=AssertionError("Over-limit graph must not reach serialization"),
                ),
                self.assertRaises(graphql.GraphQLAnalysisError),
            ):
                graphql.GraphQLAnalysisReport.from_dict(document)

    def test_report_wrapper_forgery_aliases_and_incomplete_slots(self) -> None:
        report = self.analyze()
        for invalid in (
            object.__new__(graphql.GraphQLAnalysisReport),
            ReportAlias(report.to_json()),
            report.to_dict(),
        ):
            with (
                self.subTest(family=type(invalid)),
                self.assertRaises(graphql.GraphQLAnalysisError),
            ):
                graphql.verify_graphql_operation_analysis(invalid, **self.inputs())
        invalid = object.__new__(graphql.GraphQLAnalysisReport)
        with self.assertRaises(graphql.GraphQLAnalysisError):
            invalid.to_dict()
        object.__setattr__(invalid, "document_json", StringAlias(report.to_json()))
        with self.assertRaises(graphql.GraphQLAnalysisError):
            invalid.to_dict()
        for transform in (
            lambda d: d["metrics"].update(expanded_field_count=IntegerAlias(5)),
            lambda d: d["effects"].update(target=StringAlias("none")),
            lambda d: d["witnesses"].update(
                deepest_field_path=ListAlias(["people:users", "friends", "name"])
            ),
        ):
            document = report.to_dict()
            transform(document)
            with self.assertRaises(graphql.GraphQLAnalysisError):
                graphql.GraphQLAnalysisReport.from_dict(document)
        object.__setattr__(
            report, "document_json", self.analyze(query_content=b"query Demo { ping }").to_json()
        )
        with self.assertRaisesRegex(graphql.GraphQLAnalysisError, "does not reproduce"):
            graphql.verify_graphql_operation_analysis(report, **self.inputs())

    def test_input_and_report_bounds_are_revalidated_at_use(self) -> None:
        limits = replace(self.limits)
        object.__setattr__(limits, "max_tokens", True)
        with self.assertRaises(graphql.GraphQLAnalysisError):
            self.analyze(limits=limits)
        report = self.analyze()
        document = report.to_dict()
        document.pop("vector_id")
        for malformed in (document, {**report.to_dict(), "extra": None}):
            with self.assertRaises(graphql.GraphQLAnalysisError):
                graphql.GraphQLAnalysisReport.from_dict(malformed)

    def test_source_bytes_remain_unchanged_and_no_runtime_effect(self) -> None:
        schema = bytes(self.schema)
        query = bytes(self.query)
        report = self.analyze()
        graphql.verify_graphql_operation_analysis(report, **self.inputs())
        self.assertEqual(self.schema, schema)
        self.assertEqual(self.query, query)
        document = report.to_dict()
        self.assertNotIn("query_content", document)
        self.assertNotIn("schema_content", document)
        self.assertFalse(document["qualification_claimed"])


if __name__ == "__main__":
    unittest.main()
