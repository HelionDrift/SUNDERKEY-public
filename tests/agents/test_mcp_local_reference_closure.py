"""Local MCP schema references are checked without fetching or serving tools."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_local_reference_closure import (
    MCPLocalReferenceClosureError,
    build_mcp_local_reference_closure,
    verify_mcp_local_reference_closure,
)
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import build_mcp_schema_semantic_preflight

from .test_mcp_schema_byte_preflight import digest, sources


def _with_schema(schema, *, field="input_schema"):
    manifest, _, bundle = sources()
    raw = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")
    manifest["tools"][0][field + "_sha256"] = digest(raw)
    bundle["tools"][0][field + "_base64"] = base64.b64encode(raw).decode("ascii")
    preflight = build_mcp_catalog_preflight(manifest)
    byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
    semantic_result = build_mcp_schema_semantic_preflight(
        manifest, preflight, bundle, byte_result
    )
    return manifest, preflight, bundle, byte_result, semantic_result


class MCPLocalReferenceClosureTests(unittest.TestCase):
    def test_report_matches_registry_schema(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/mcp-local-reference-closure-v1.schema.json"
        )
        report_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(report_schema)
        report = build_mcp_local_reference_closure(
            *_with_schema({"type": "object", "$defs": {"self": {"$ref": "#"}}})
        )
        Draft202012Validator(report_schema).validate(report)

    def test_local_pointer_escapes_and_boolean_output_reproduce(self) -> None:
        sources_ = _with_schema({
            "type": "object",
            "$defs": {"a/b": {"type": "string"}},
            "properties": {"item": {"$ref": "#/$defs/a~1b"}},
        })
        result = build_mcp_local_reference_closure(*sources_)
        self.assertEqual(
            result["tools"][0]["schemas"][0]["local_reference_count"], 1
        )
        self.assertEqual(result["closure_status"], "local_json_pointer_targets_checked_only")
        self.assertFalse(result["external_references_resolved"])
        self.assertFalse(result["live_server_schema_verified"])
        self.assertEqual(result["effects"]["tool_execution"], "none")
        self.assertEqual(
            verify_mcp_local_reference_closure(*sources_, result)["status"], "valid"
        )
        boolean = _with_schema(True, field="output_schema")
        self.assertEqual(
            build_mcp_local_reference_closure(*boolean)["tools"][0]["schemas"][1]
            ["local_reference_count"],
            0,
        )

    def test_invalid_pointer_external_and_dynamic_references_fail(self) -> None:
        for reference in (
            "#/$defs/missing", "https://example.test/schema", "#/$defs/a~2b",
            "#/$defs/a%2Fb", "#/$defs/a/1", "#/$defs/a/type",
        ):
            with self.subTest(reference=reference):
                source = _with_schema({
                    "type": "object",
                    "$defs": {"a": {"type": "string"}},
                    "properties": {"item": {"$ref": reference}},
                })
                with self.assertRaises(MCPLocalReferenceClosureError):
                    build_mcp_local_reference_closure(*source)
        large_index = _with_schema({
            "type": "object", "allOf": [{"type": "object"}],
            "properties": {"item": {"$ref": "#/allOf/" + "9" * 5000}},
        })
        with self.assertRaisesRegex(MCPLocalReferenceClosureError, "array target"):
            build_mcp_local_reference_closure(*large_index)
        for schema in (
            {"type": "object", "$dynamicRef": "#meta"},
            {"type": "object", "$anchor": "meta"},
            {"type": "object", "$recursiveRef": "#"},
            {
                "type": "object",
                "properties": {"item": {"$id": "https://example.test/other"}},
            },
        ):
            with self.subTest(schema=schema):
                with self.assertRaises(MCPLocalReferenceClosureError):
                    build_mcp_local_reference_closure(*_with_schema(schema))

    def test_const_data_is_not_interpreted_as_a_reference(self) -> None:
        source = _with_schema({
            "type": "object",
            "properties": {
                "item": {"const": {"$ref": "https://example.test/data"}}
            },
        })
        result = build_mcp_local_reference_closure(*source)
        self.assertEqual(
            result["tools"][0]["schemas"][0]["local_reference_count"], 0
        )
        source = _with_schema({
            "type": "object",
            "$defs": {"data": {"const": {"type": "string"}}},
            "properties": {"item": {"$ref": "#/$defs/data/const"}},
        })
        with self.assertRaisesRegex(MCPLocalReferenceClosureError, "schema location"):
            build_mcp_local_reference_closure(*source)

    def test_pointer_to_nested_any_of_branch_is_a_schema_location(self) -> None:
        source = _with_schema({
            "type": "object",
            "$defs": {"choice": {"anyOf": [
                {"type": "string"}, {"type": "integer"},
            ]}},
            "properties": {"item": {"$ref": "#/$defs/choice/anyOf/0"}},
        })
        result = build_mcp_local_reference_closure(*source)
        self.assertEqual(
            result["tools"][0]["schemas"][0]["local_reference_count"], 1
        )

    def test_changed_semantic_source_and_result_fail_reproduction(self) -> None:
        source = _with_schema({"type": "object"})
        result = build_mcp_local_reference_closure(*source)
        changed = copy.deepcopy(result)
        changed["live_server_schema_verified"] = True
        with self.assertRaises(MCPLocalReferenceClosureError):
            verify_mcp_local_reference_closure(*source, changed)
        changed_source = list(source)
        changed_source[4] = copy.deepcopy(source[4])
        changed_source[4]["tools"][0]["input_schema"]["reference_count"] = 1
        with self.assertRaises(MCPLocalReferenceClosureError):
            build_mcp_local_reference_closure(*changed_source)


if __name__ == "__main__":
    unittest.main()
