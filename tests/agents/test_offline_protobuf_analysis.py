"""Synthetic public-entry tests for the closed offline Protobuf analyzer."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from sunderkey.offline_protobuf_analysis import (
    ProtobufAnalysisError,
    ProtobufAnalysisLimits,
    ProtobufAnalysisReport,
    analyze_protobuf_schema_evolution,
    verify_protobuf_schema_evolution,
)

PREVIOUS = b"""syntax = "proto3";
package demo;
message Request {
  string key = 1;
  optional int32 limit = 2;
  repeated sint32 values = 3;
  Reply child = 4;
  reserved 8 to 10, 12 to max;
  reserved "retired";
}
message Reply { bytes payload = 1; }
service Catalog {
  rpc Fetch (Request) returns (Reply);
  rpc Watch (stream Request) returns (stream Reply);
}
"""
CURRENT = b"""syntax = "proto3";
package demo;
message Request {
  bytes key = 1;
  optional int32 limit = 5;
  sint32 values = 3;
  optional Reply child = 4;
  uint32 extra = 10;
  string retired = 11;
  reserved 2, 8 to 9, 12 to max;
}
message Reply { fixed64 payload = 1; }
service Catalog {
  rpc Fetch (stream Request) returns (Reply);
  rpc List (Request) returns (stream Reply);
}
"""
LIMITS = ProtobufAnalysisLimits(65_536, 65_536, 4_096, 1_024, 256)
MODULE = "sunderkey.offline_protobuf_analysis"


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def readdress(document: dict) -> dict:
    body = {
        key: value for key, value in document.items() if key not in {"report_id", "report_sha256"}
    }
    digest = hashlib.sha256(
        canonical({"domain": "sunderkey.offline-protobuf-analysis.v1", "analysis": body}).encode(
            "ascii"
        )
    ).hexdigest()
    return {**body, "report_id": "PBA-" + digest[:32].upper(), "report_sha256": "sha256:" + digest}


def source(body: str, *, package: str = "demo") -> bytes:
    declaration = f"package {package};" if package else ""
    return (f'syntax = "proto3"; {declaration} ' + body).encode("utf-8")


class StringAlias(str):
    pass


class IntegerAlias(int):
    pass


class BytesAlias(bytes):
    pass


class ListAlias(list):
    pass


class DictAlias(dict):
    pass


class ProtobufAnalysisTests(unittest.TestCase):
    def analyze(self, previous: bytes = PREVIOUS, current: bytes = CURRENT, **kwargs):
        inputs = {
            "previous_content": previous,
            "current_content": current,
            "previous_source_id": "fixture.previous",
            "current_source_id": "fixture.current",
            "limits": LIMITS,
        }
        inputs.update(kwargs)
        return analyze_protobuf_schema_evolution(**inputs)

    def verify(self, report, previous=PREVIOUS, current=CURRENT, **kwargs):
        inputs = {
            "report": report,
            "previous_content": previous,
            "current_content": current,
            "previous_source_id": "fixture.previous",
            "current_source_id": "fixture.current",
            "limits": LIMITS,
        }
        inputs.update(kwargs)
        return verify_protobuf_schema_evolution(**inputs)

    def test_literal_result_and_source_identities(self):
        report = self.analyze()
        document = report.to_dict()
        self.assertEqual(document["report_id"], "PBA-577A4AFFEFAA98876150F648BB7A2477")
        self.assertEqual(
            document["report_sha256"],
            "sha256:577a4affefaa98876150f648bb7a247720677a6799ddcd7c7448c24205c2f012",
        )
        self.assertEqual(
            document["previous_source"]["sha256"],
            "sha256:8b8ddd969862225b9f668bcbf6f281878b0d15140b3b7630be64c3c6313f83ce",
        )
        self.assertEqual(
            document["current_source"]["sha256"],
            "sha256:f570aa22ff80b1bab909c07b0d1d22b2b4ba6f507dcb286230d3fe3f993a561d",
        )
        self.assertEqual(document["observation_count"], 15)
        self.assertEqual(document["statistics"]["previous_field_count"], 5)
        self.assertEqual(document["statistics"]["current_field_count"], 7)
        self.assertEqual(document["statistics"]["previous_rpc_count"], 2)
        self.assertEqual(document["statistics"]["current_rpc_count"], 2)
        self.assertEqual(self.verify(report).to_json(), report.to_json())

    def test_literal_unchanged_control_and_detached_roundtrip(self):
        report = self.analyze(current=PREVIOUS)
        self.assertEqual(report.to_dict()["report_id"], "PBA-835BBD725EB01C44FA946C726C350438")
        self.assertEqual(
            report.to_dict()["report_sha256"],
            "sha256:835bbd725eb01c44fa946c726c350438c56b6fc8a3b01f5c51910b6b3d896257",
        )
        self.assertEqual(report.to_dict()["observations"], [])
        self.assertEqual(
            ProtobufAnalysisReport.from_dict(report.to_dict()).to_json(), report.to_json()
        )
        self.assertEqual(
            ProtobufAnalysisReport.from_json(" \n" + report.to_json()).to_json(), report.to_json()
        )
        detached = report.to_dict()
        detached["previous_source"]["source_id"] = "changed"
        detached["effects"]["target"] = "enabled"
        self.assertEqual(report.to_dict()["previous_source"]["source_id"], "fixture.previous")
        self.assertEqual(report.to_dict()["effects"]["target"], "none")
        self.assertEqual(self.verify(report, current=PREVIOUS).to_json(), report.to_json())

    def test_field_number_reservations_and_rpc_changes(self):
        observations = self.analyze().to_dict()["observations"]
        changes = {(item["symbol"], item["change"]) for item in observations}
        self.assertIn(("demo.Request.limit", "field_number_changed"), changes)
        self.assertNotIn(("demo.Request.#2", "removed_field_number_not_reserved"), changes)
        self.assertIn(("demo.Request.#10", "reserved_number_reused"), changes)
        self.assertIn(("demo.Request.retired", "reserved_name_reused"), changes)
        self.assertIn(("demo.Catalog.Fetch", "rpc_signature_changed"), changes)
        self.assertIn(("demo.Catalog.Watch", "rpc_removed"), changes)
        self.assertIn(("demo.Catalog.List", "rpc_added"), changes)
        released = [
            item["previous"]
            for item in observations
            if item["change"] == "reserved_numbers_released"
        ]
        self.assertEqual(released, [{"kind": "reserved_range", "start": 10, "end": 10}])

    def test_scalar_encoding_classes_are_not_safety_verdicts(self):
        document = self.analyze().to_dict()
        changes = {
            item["symbol"]: item["change"]
            for item in document["observations"]
            if "wire_type" in item["change"]
        }
        self.assertEqual(
            changes,
            {
                "demo.Reply.payload": "field_base_wire_type_changed",
                "demo.Request.key": "field_type_changed_same_base_wire_type",
            },
        )
        for key in (
            "positive_use_approved",
            "qualification_claimed",
            "wire_compatibility_certified",
            "security_findings_verified",
        ):
            self.assertIs(document[key], False)
        self.assertIs(document["offline_only"], True)
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertNotIn("wire_safe", document)

    def test_optional_message_presence_is_equivalent(self):
        before = source("message Child {} message Root { Child child = 1; }")
        after = source("message Child {} message Root { optional Child child = 1; }")
        self.assertEqual(self.analyze(before, after).to_dict()["observations"], [])
        self.assertNotEqual(
            self.analyze(before, after).to_dict()["previous_source"]["sha256"],
            self.analyze(before, after).to_dict()["current_source"]["sha256"],
        )

    def test_scalar_presence_and_repeated_packability(self):
        before = source("message Root { int32 value = 1; }")
        after = source("message Root { optional int32 value = 1; }")
        changes = self.analyze(before, after).to_dict()["observations"]
        self.assertEqual([item["change"] for item in changes], ["field_presence_changed"])
        numeric = self.analyze(
            source("message Root {}"), source("message Root { repeated sint32 values = 1; }")
        )
        field = numeric.to_dict()["observations"][0]["current"]
        self.assertIs(field["packed_by_default"], True)
        self.assertEqual((field["presence"], field["cardinality"]), ("repeated", "repeated"))
        for field_type in ("string", "bytes", "Root"):
            result = self.analyze(
                source("message Root {}"),
                source(f"message Root {{ repeated {field_type} values = 1; }}"),
            )
            self.assertIs(
                result.to_dict()["observations"][0]["current"]["packed_by_default"], False
            )

    def test_all_builtin_scalars_and_recursive_local_types(self):
        types = (
            "double",
            "float",
            "int32",
            "int64",
            "uint32",
            "uint64",
            "sint32",
            "sint64",
            "fixed32",
            "fixed64",
            "sfixed32",
            "sfixed64",
            "bool",
            "string",
            "bytes",
            "Root",
        )
        body = (
            "message Root { "
            + " ".join(f"{kind} field{index} = {index};" for index, kind in enumerate(types, 1))
            + " }"
        )
        content = source(body)
        document = self.analyze(content, content).to_dict()
        self.assertEqual(document["statistics"]["previous_field_count"], 16)
        self.assertEqual(document["observations"], [])

    def test_absolute_local_type_resolution_and_forward_definitions(self):
        content = source(
            "service Example { rpc Read (.demo.Root) returns (Reply); } "
            "message Root { .demo.Reply reply = 1; } message Reply {}"
        )
        self.assertEqual(self.analyze(content, content).to_dict()["observations"], [])
        no_package = source(
            "message Root {} service Example { rpc Read (.Root) returns (Root); }", package=""
        )
        self.assertEqual(self.analyze(no_package, no_package).to_dict()["observations"], [])

    def test_added_removed_definitions_and_package_renames(self):
        before = source(
            "message Root { string value = 1; } service Example { rpc Read (Root) returns (Root); }"
        )
        after = source(
            "message Root { string value = 1; } "
            "service Example { rpc Read (Root) returns (Root); }",
            package="other",
        )
        changes = self.analyze(before, after).to_dict()["observations"]
        self.assertEqual(
            sorted(item["change"] for item in changes),
            ["message_added", "message_removed", "service_added", "service_removed"],
        )
        removed = next(item for item in changes if item["change"] == "message_removed")
        self.assertEqual(removed["previous"]["field_count"], 1)

    def test_tag_name_change_and_deleted_unreserved_fields(self):
        before = source("message Root { string old = 1; int32 removed = 2; }")
        after = source("message Root { string new = 1; }")
        changes = {
            (item["symbol"], item["change"])
            for item in self.analyze(before, after).to_dict()["observations"]
        }
        self.assertIn(("demo.Root.#1", "field_name_changed_at_number"), changes)
        self.assertNotIn(("demo.Root.#1", "removed_field_number_not_reserved"), changes)
        self.assertIn(("demo.Root.#2", "removed_field_number_not_reserved"), changes)
        self.assertIn(("demo.Root.removed", "removed_field_name_not_reserved"), changes)
        reserved = source('message Root { string new = 1; reserved 2; reserved "old", "removed"; }')
        reserved_changes = self.analyze(before, reserved).to_dict()["observations"]
        self.assertFalse(
            any(item["change"].startswith("removed_field") for item in reserved_changes)
        )

    def test_maximum_reserved_intervals_remain_compact(self):
        before = source("message Root { reserved 1 to max; }")
        after = source("message Root { reserved 2 to 536870910; }")
        result = self.analyze(before, after).to_dict()
        self.assertEqual(result["observation_count"], 2)
        self.assertEqual(
            [item["previous"] for item in result["observations"]],
            [
                {"kind": "reserved_range", "start": 1, "end": 1},
                {"kind": "reserved_range", "start": 536870911, "end": 536870911},
            ],
        )
        self.assertLess(len(canonical(result)), 3_000)
        self.assertEqual(result["statistics"]["previous_ast_node_count"], 4)

    def test_renamed_tag_keeps_type_cardinality_and_presence_joins(self):
        before = source("message Root { string old = 1; }")
        after = source("message Root { repeated int32 new = 1; }")
        changes = {
            (item["symbol"], item["change"])
            for item in self.analyze(before, after).to_dict()["observations"]
        }
        self.assertIn(("demo.Root.#1", "field_name_changed_at_number"), changes)
        self.assertIn(("demo.Root.#1", "field_base_wire_type_changed"), changes)
        self.assertIn(("demo.Root.#1", "field_cardinality_changed"), changes)
        self.assertIn(("demo.Root.#1", "field_presence_changed"), changes)
        self.assertNotIn(("demo.Root.#1", "removed_field_number_not_reserved"), changes)

    def test_report_rpc_booleans_and_reserved_interval_types(self):
        for alias in (0, 1, 1.0):
            document = self.analyze().to_dict()
            rpc = next(
                item["current"]
                for item in document["observations"]
                if item["current"] is not None and item["current"]["kind"] == "rpc"
            )
            rpc["client_streaming"] = alias
            with self.subTest(alias=alias), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(readdress(document))
        for alias in (True, 2.0):
            document = self.analyze().to_dict()
            interval = next(
                item["current"]
                for item in document["observations"]
                if item["current"] is not None and item["current"]["kind"] == "reserved_range"
            )
            interval["start"] = alias
            with self.subTest(alias=alias), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(readdress(document))

    def test_permuted_same_changes_have_deterministic_observation_order(self):
        before = source("message Root { int32 first = 1; string second = 2; }")
        after = source("message Root { sint32 first = 1; bytes second = 2; }")
        reordered_before = source("message Root { string second = 2; int32 first = 1; }")
        reordered_after = source("message Root { bytes second = 2; sint32 first = 1; }")
        original = self.analyze(before, after)
        permuted = self.analyze(reordered_before, reordered_after)
        self.assertEqual(original.to_dict()["observations"], permuted.to_dict()["observations"])
        self.assertNotEqual(original.to_dict()["report_id"], permuted.to_dict()["report_id"])
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(original, reordered_before, reordered_after)

    def test_closed_wrapper_families_and_native_report_graph_are_required(self):
        class LimitsSubclass(ProtobufAnalysisLimits):
            pass

        incomplete = object.__new__(LimitsSubclass)
        with patch(MODULE + "._tokens", side_effect=AssertionError("tokenization")):
            with self.assertRaises(ProtobufAnalysisError):
                self.analyze(limits=incomplete)
        for doc in (DictAlias(self.analyze().to_dict()), self.analyze().to_dict()):
            if type(doc) is dict:
                doc["statistics"]["previous_field_count"] = IntegerAlias(5)
            with patch(MODULE + ".json.dumps", side_effect=AssertionError("serialization")):
                with self.assertRaises(ProtobufAnalysisError):
                    ProtobufAnalysisReport.from_dict(doc)

    def test_interval_subtraction_split_and_adjacent_normalization(self):
        before = source("message Root { reserved 1 to 5, 8 to 12, 20 to 22; }")
        after = source("message Root { reserved 2 to 3, 9 to 10, 13, 14, 21 to 25; }")
        observations = self.analyze(before, after).to_dict()["observations"]
        released = sorted(
            (item["previous"]["start"], item["previous"]["end"])
            for item in observations
            if item["change"] == "reserved_numbers_released"
        )
        added = sorted(
            (item["current"]["start"], item["current"]["end"])
            for item in observations
            if item["change"] == "reserved_numbers_added"
        )
        self.assertEqual(released, [(1, 1), (4, 5), (8, 8), (11, 12), (20, 20)])
        self.assertEqual(added, [(13, 14), (23, 25)])

    def test_all_rpc_streaming_combinations_and_signature_type_changes(self):
        for incoming in (False, True):
            for outgoing in (False, True):
                with self.subTest(incoming=incoming, outgoing=outgoing):
                    body = (
                        "message Request {} message Reply {} service Example { rpc Read ("
                        + ("stream " if incoming else "")
                        + "Request) returns ("
                        + ("stream " if outgoing else "")
                        + "Reply); }"
                    )
                    content = source(body)
                    self.assertEqual(self.analyze(content, content).to_dict()["observations"], [])
        before = source(
            "message Request {} message Reply {} "
            "service Example { rpc Read (Request) returns (Reply); }"
        )
        after = before.replace(b"Read (Request) returns (Reply)", b"Read (Reply) returns (Request)")
        observations = self.analyze(before, after).to_dict()["observations"]
        self.assertEqual([item["change"] for item in observations], ["rpc_signature_changed"])

    def test_source_order_comments_and_utf8_are_byte_bound(self):
        before = source("message First {} message Second { First value = 1; }")
        after = source(
            "/* supplied inert comment: \u00e9 */ message Second { First value = 1; } "
            "// no dispatch\n message First {}"
        )
        report = self.analyze(before, after)
        self.assertEqual(report.to_dict()["observations"], [])
        self.assertNotEqual(
            report.to_dict()["previous_source"]["sha256"],
            report.to_dict()["current_source"]["sha256"],
        )
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(report, before, before)

    def test_unsupported_constructs_fail_before_hashing(self):
        bodies = [
            'import "other.proto"; message Root {}',
            'option java_package = "x"; message Root {}',
            "enum State { OK = 0; }",
            "message Root { oneof choice { string value = 1; } }",
            "message Root { map<string, string> values = 1; }",
            "message Root { message Child {} Child value = 1; }",
            "message Root { int32 value = 1 [packed=true]; }",
            "message Root {} service Example { rpc Read (Root) returns (Root) {} }",
            "message Root { required string value = 1; }",
            "message Root {} service Example { rpc Read (string) returns (Root); }",
            'message Root { reserved "escaped\\name"; }',
            "message Root { reserved 'name'; }",
            "message Root { string _value = 1; }",
            "message Root { demo.Root value = 1; }",
        ]
        for body in bodies:
            with (
                self.subTest(body=body),
                patch(MODULE + "._sha", side_effect=AssertionError("hash")),
            ):
                with self.assertRaises(ProtobufAnalysisError):
                    self.analyze(current=source(body))
        for content in (
            b"message Root {}",
            b'syntax = "proto2"; message Root {}',
            b'edition = "2023"; message Root {}',
            b'\xef\xbb\xbfsyntax = "proto3";',
            b"/* unterminated",
            b'/* outer /* nested */ syntax = "proto3";',
            b'syntax = "proto3"; \xff',
        ):
            with self.subTest(content=content), self.assertRaises(ProtobufAnalysisError):
                self.analyze(current=content)

    def test_duplicate_definitions_fields_rpcs_and_packages(self):
        bodies = [
            "message Root {} message Root {}",
            "message Root {} service Root {}",
            "message Root { string value = 1; bytes value = 2; }",
            "message Root { string first = 1; string second = 1; }",
            "message Root {} service Example { rpc Read (Root) returns (Root); "
            "rpc Read (Root) returns (Root); }",
            "package second; message Root {}",
            'syntax = "proto3"; message Root {}',
            'message Root { reserved "old", "old"; }',
            "message Root { reserved 1 to 5, 4 to 8; }",
            "message Root { reserved 1; reserved 1; }",
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ProtobufAnalysisError):
                self.analyze(current=source(body))

    def test_undefined_types_and_rpc_source_types_fail_closed(self):
        for body in (
            "message Root { Missing value = 1; }",
            "message Root {} service Example { rpc Read (Missing) returns (Root); }",
            "message Root {} service Example { rpc Read (Root) returns (.other.Root); }",
        ):
            with self.subTest(body=body), self.assertRaises(ProtobufAnalysisError):
                self.analyze(current=source(body))

    def test_tags_reserved_names_ranges_and_decimal_subset(self):
        bodies = [
            "message Root { string value = 0; }",
            "message Root { string value = 19000; }",
            "message Root { string value = 19999; }",
            "message Root { string value = 536870912; }",
            "message Root { string value = 01; }",
            "message Root { string value = -1; }",
            "message Root { string value = 0x1; }",
            "message Root { reserved 4 to 3; }",
            "message Root { reserved 0; }",
            'message Root { reserved 1, "old"; }',
            'message Root { reserved "old", 1; }',
            "message Root { reserved 1; string value = 1; }",
            'message Root { reserved "value"; string value = 1; }',
            "message Root { string value = " + "9" * 129 + "; }",
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ProtobufAnalysisError):
                self.analyze(current=source(body))
        content = source("message Root { string value = 536870911; reserved 19000 to 19999; }")
        self.assertEqual(self.analyze(content, content).to_dict()["observations"], [])

    def test_malformed_eof_and_closed_name_bounds(self):
        for body in (
            "message Root {",
            "message Root { string value = 1",
            "service Example {",
            "message Root { ;",
            "message " + "A" * 129 + " {}",
            "message Root { string returns = 1; }",
        ):
            with self.subTest(body=body), self.assertRaises(ProtobufAnalysisError):
                self.analyze(current=source(body))
        empty = b'syntax = "proto3"; ;'
        self.assertEqual(self.analyze(empty, empty).to_dict()["observations"], [])

    def test_explicit_cost_limits_fail_without_partial_report(self):
        cases = [
            replace(LIMITS, max_previous_bytes=len(PREVIOUS) - 1),
            replace(LIMITS, max_current_bytes=len(CURRENT) - 1),
            replace(LIMITS, max_tokens=5),
            replace(LIMITS, max_nodes=3),
            replace(LIMITS, max_observations=1),
        ]
        for limits in cases:
            with (
                self.subTest(limits=limits),
                patch(MODULE + "._sha", side_effect=AssertionError("hash")),
            ):
                with self.assertRaises(ProtobufAnalysisError):
                    self.analyze(limits=limits)
        exact = self.analyze()
        stats = exact.to_dict()["statistics"]
        bounded = replace(
            LIMITS,
            max_previous_bytes=len(PREVIOUS),
            max_current_bytes=len(CURRENT),
            max_tokens=max(stats["previous_token_count"], stats["current_token_count"]),
            max_nodes=max(stats["previous_ast_node_count"], stats["current_ast_node_count"]),
            max_observations=exact.to_dict()["observation_count"],
        )
        self.assertEqual(
            self.analyze(limits=bounded).to_dict()["observations"], exact.to_dict()["observations"]
        )

    def test_native_limits_types_ceilings_and_incomplete_slots(self):
        for field, ceiling in (
            ("max_previous_bytes", 1_048_576),
            ("max_current_bytes", 1_048_576),
            ("max_tokens", 50_000),
            ("max_nodes", 50_000),
            ("max_observations", 2_048),
        ):
            for value in (True, 1.0, IntegerAlias(1), 0, -1, ceiling + 1):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ProtobufAnalysisError),
                ):
                    replace(LIMITS, **{field: value})
        incomplete = object.__new__(ProtobufAnalysisLimits)
        with self.assertRaises(ProtobufAnalysisError):
            self.analyze(limits=incomplete)
        late = replace(LIMITS)
        object.__setattr__(late, "max_nodes", True)
        with self.assertRaises(ProtobufAnalysisError):
            self.analyze(limits=late)

    def test_native_source_and_id_aliases_are_rejected_before_hash(self):
        for field in ("previous_content", "current_content"):
            for value in (BytesAlias(PREVIOUS), bytearray(PREVIOUS), PREVIOUS.decode(), b"", None):
                with (
                    self.subTest(field=field, value=type(value)),
                    self.assertRaises(ProtobufAnalysisError),
                ):
                    self.analyze(**{field: value})
        for field in ("previous_source_id", "current_source_id"):
            for value in (StringAlias("fixture.id"), "../file", "", "a" * 129, True):
                with (
                    self.subTest(field=field, value=value),
                    patch(MODULE + "._sha", side_effect=AssertionError("hash")),
                ):
                    with self.assertRaises(ProtobufAnalysisError):
                        self.analyze(**{field: value})

    def test_exact_source_id_configuration_and_orientation_replay(self):
        report = self.analyze()
        changes = [
            dict(previous_content=PREVIOUS + b"\n"),
            dict(current_content=CURRENT + b"\n"),
            dict(previous_source_id="fixture.other"),
            dict(current_source_id="fixture.other"),
            dict(limits=replace(LIMITS, max_nodes=1_025)),
            dict(previous_content=CURRENT, current_content=PREVIOUS),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ProtobufAnalysisError):
                self.verify(report, **change)

    def test_rehashed_false_observations_require_source_replay(self):
        document = self.analyze().to_dict()
        document["observations"] = []
        document["observation_count"] = 0
        forged = ProtobufAnalysisReport.from_dict(readdress(document))
        with self.assertRaisesRegex(ProtobufAnalysisError, "does not reproduce"):
            self.verify(forged)
        for section, key, value in (
            ("previous_source", "sha256", "sha256:" + "0" * 64),
            ("statistics", "current_field_count", 6),
            ("limits", "max_tokens", 4_097),
        ):
            changed = self.analyze().to_dict()
            changed[section][key] = value
            parsed = ProtobufAnalysisReport.from_dict(readdress(changed))
            with self.subTest(section=section), self.assertRaises(ProtobufAnalysisError):
                self.verify(parsed)

    def test_public_report_forgery_and_missing_slots_are_revalidated(self):
        incomplete = object.__new__(ProtobufAnalysisReport)
        with self.assertRaises(ProtobufAnalysisError):
            incomplete.to_dict()
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(incomplete)
        late = self.analyze()
        object.__setattr__(late, "document_json", StringAlias(late.document_json))
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(late)

        class ReportSubclass(ProtobufAnalysisReport):
            pass

        subclass = ReportSubclass(self.analyze().to_json())
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(subclass)
        with self.assertRaises(ProtobufAnalysisError):
            self.verify(self.analyze().to_dict())

    def test_native_report_integer_boolean_and_artifact_aliases(self):
        base = self.analyze().to_dict()
        for key, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("observation_count", float(base["observation_count"])),
            ("offline_only", 1),
            ("positive_use_approved", 0),
            ("profile_id", StringAlias(base["profile_id"])),
            ("observations", ListAlias(base["observations"])),
        ):
            document = self.analyze().to_dict()
            document[key] = value
            with self.subTest(key=key, kind=type(value)), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(readdress(document))
        for field, value in (
            ("number", True),
            ("number", 1.0),
            ("base_wire_type", False),
            ("packed_by_default", 0),
            ("presence", "repeated"),
        ):
            document = self.analyze().to_dict()
            artifact = next(
                item["current"]
                for item in document["observations"]
                if item["current"] is not None and item["current"]["kind"] == "field"
            )
            artifact[field] = value
            with self.subTest(field=field), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(readdress(document))
        for key in (True, StringAlias("schema_version")):
            document = self.analyze().to_dict()
            document[key] = document.pop("schema_version")
            with self.subTest(key=key), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(document)

    def test_duplicate_float_nonfinite_depth_and_malformed_json(self):
        for text in (
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":1.0}',
            '{"schema_version":NaN}',
            '{"schema_version":Infinity}',
            "[" * 33 + "0" + "]" * 33,
            '{"number":' + "9" * 20 + "}",
            "{",
            '"\\ud800"',
            "x" * 1_048_577,
        ):
            with self.subTest(text=text[:60]), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_json(text)

    def test_closed_report_fields_order_addresses_and_claims(self):
        for mutation in ("unknown", "wrong_address", "positive", "duplicate", "order", "both_none"):
            document = self.analyze().to_dict()
            if mutation == "unknown":
                document["authority"] = "none"
            elif mutation == "wrong_address":
                document["report_sha256"] = "sha256:" + "0" * 64
            elif mutation == "positive":
                document["wire_compatibility_certified"] = True
            elif mutation == "duplicate":
                document["observations"].append(document["observations"][0])
                document["observation_count"] += 1
            elif mutation == "order":
                document["observations"].reverse()
            else:
                document["observations"][0]["previous"] = None
                document["observations"][0]["current"] = None
            if mutation != "wrong_address":
                document = readdress(document)
            with self.subTest(mutation=mutation), self.assertRaises(ProtobufAnalysisError):
                ProtobufAnalysisReport.from_dict(document)

    def test_native_aggregate_bounds_precede_serialization(self):
        shared = ["\\" * 8_192] * 100
        graphs = [
            shared * 10,
            [None] * 50_001,
            ["x" * 8_193],
            [2**100],
            DictAlias({}),
            {"key": object()},
        ]
        depth = 0
        for _ in range(33):
            depth = [depth]
        graphs.append(depth)
        for graph in graphs:
            with (
                self.subTest(kind=type(graph)),
                patch(MODULE + ".json.dumps", side_effect=AssertionError("serialization")),
            ):
                with self.assertRaises(ProtobufAnalysisError):
                    ProtobufAnalysisReport.from_dict(graph)

    def test_source_bytes_are_untouched_and_no_optional_runtime_dependency(self):
        original_previous, original_current = bytes(PREVIOUS), bytes(CURRENT)
        first = self.analyze()
        second = self.analyze()
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(PREVIOUS, original_previous)
        self.assertEqual(CURRENT, original_current)
        self.assertEqual(first.to_dict()["profile_id"], "AOE-GB-D06-S03")
        self.assertEqual(first.to_dict()["capability_id"], "army.gb.d06.s03")
        self.assertEqual(first.to_dict()["vector_id"], "AV-GB-D06-S03-01")


if __name__ == "__main__":
    unittest.main()
