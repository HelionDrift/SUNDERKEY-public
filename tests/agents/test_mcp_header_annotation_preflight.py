"""MCP header annotations are statically bounded and non-authorizing."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_header_annotation_preflight import (
    MCPHeaderAnnotationPreflightError,
    build_mcp_header_annotation_preflight,
    verify_mcp_header_annotation_preflight,
)
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import build_mcp_schema_semantic_preflight
from tests.agents.test_mcp_schema_byte_preflight import sources
from tests.agents.test_mcp_schema_semantic_preflight import replace_schema


def fixture(input_schema: object, output_schema: object = None) -> tuple[dict, ...]:
    manifest, _, bundle = sources()
    replace_schema(manifest, bundle, field="input_schema", schema=input_schema)
    if output_schema is not None:
        replace_schema(manifest, bundle, field="output_schema", schema=output_schema)
    preflight = build_mcp_catalog_preflight(manifest)
    byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
    semantic_result = build_mcp_schema_semantic_preflight(
        manifest, preflight, bundle, byte_result
    )
    return manifest, preflight, bundle, byte_result, semantic_result


class MCPHeaderAnnotationPreflightTests(unittest.TestCase):
    def test_reachable_primitive_headers_and_range_obligation(self) -> None:
        inputs = fixture({
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "x-mcp-header": "Tenant"},
                "nested": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                    },
                },
                "bounded": {
                    "type": "integer", "minimum": -(2**53 - 1),
                    "maximum": 2**53 - 1, "x-mcp-header": "Bounded",
                },
                "unbounded": {"type": "integer", "x-mcp-header": "Unbounded"},
            },
        })
        result = build_mcp_header_annotation_preflight(*inputs)
        tool = result["tools"][0]
        self.assertEqual(tool["header_count"], 4)
        self.assertEqual(tool["runtime_integer_range_check_required_count"], 1)
        self.assertIn(
            ["nested", "enabled"],
            [item["property_path"] for item in tool["headers"]],
        )
        self.assertFalse(result["streamable_http_client_validation_performed"])
        self.assertFalse(result["server_header_body_parity_verified"])
        self.assertEqual(result["effects"]["network"], "none")
        self.assertEqual(
            verify_mcp_header_annotation_preflight(*inputs, result)["status"],
            "valid",
        )

    def test_duplicate_header_names_and_invalid_tokens_fail(self) -> None:
        for name in ("bad name", "bad\r\nname", ""):
            with self.subTest(name=name):
                inputs = fixture({
                    "type": "object",
                    "properties": {"value": {"type": "string", "x-mcp-header": name}},
                })
                with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "invalid"):
                    build_mcp_header_annotation_preflight(*inputs)
        inputs = fixture({
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-mcp-header": "Tenant"},
                "b": {"type": "string", "x-mcp-header": "tenant"},
            },
        })
        with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "unique"):
            build_mcp_header_annotation_preflight(*inputs)

    def test_nonprimitive_or_unreachable_annotation_fails(self) -> None:
        candidates = (
            {"type": "object", "x-mcp-header": "Root"},
            {"type": "object", "properties": {
                "value": {"type": "number", "x-mcp-header": "Value"},
            }},
            {"type": "object", "properties": {
                "value": {"type": ["string", "null"], "x-mcp-header": "Value"},
            }},
            {"type": "object", "allOf": [{"properties": {
                "value": {"type": "string", "x-mcp-header": "Value"},
            }}]},
            {"type": "object", "properties": {"values": {
                "type": "array", "items": {
                    "type": "string", "x-mcp-header": "Value",
                },
            }}},
            {"type": "object", "$defs": {
                "value": {"type": "string", "x-mcp-header": "Value"},
            }},
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "invalid"):
                    build_mcp_header_annotation_preflight(*fixture(candidate))

    def test_output_annotation_fails_but_literal_example_does_not(self) -> None:
        inputs = fixture(
            {"type": "object"},
            {"type": "object", "properties": {
                "value": {"type": "string", "x-mcp-header": "Value"},
            }},
        )
        with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "invalid"):
            build_mcp_header_annotation_preflight(*inputs)
        inputs = fixture({
            "type": "object",
            "properties": {"value": {
                "type": "string", "examples": [{"x-mcp-header": "sample data"}],
            }},
        })
        result = build_mcp_header_annotation_preflight(*inputs)
        self.assertEqual(result["tools"][0]["header_count"], 0)

    def test_source_or_result_rebinding_fails(self) -> None:
        inputs = fixture({
            "type": "object",
            "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}},
        })
        changed = copy.deepcopy(inputs[4])
        changed["tool_count"] = 2
        with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "semantic"):
            build_mcp_header_annotation_preflight(*inputs[:4], changed)
        result = build_mcp_header_annotation_preflight(*inputs)
        result["server_header_body_parity_verified"] = True
        with self.assertRaisesRegex(MCPHeaderAnnotationPreflightError, "reproduce"):
            verify_mcp_header_annotation_preflight(*inputs, result)

    def test_cli_build_and_verify(self) -> None:
        inputs = fixture({
            "type": "object",
            "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}},
        })
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in (
                "manifest.json", "preflight.json", "schemas.json", "byte.json",
                "semantic.json", "headers.json",
            )]
            for path, value in zip(paths[:5], inputs, strict=True):
                path.write_text(json.dumps(value), encoding="utf-8")
            args = [
                "--manifest", str(paths[0]), "--preflight", str(paths[1]),
                "--schemas", str(paths[2]), "--byte-result", str(paths[3]),
                "--semantic-result", str(paths[4]),
            ]
            selected = parser.parse_args(["mcp-header-annotation-preflight", *args])
            with redirect_stdout(output := io.StringIO()):
                selected.handler(selected)
            paths[5].write_text(output.getvalue(), encoding="utf-8")
            selected = parser.parse_args([
                "mcp-header-annotation-preflight-verify", *args,
                "--result", str(paths[5]),
            ])
            with redirect_stdout(output := io.StringIO()):
                selected.handler(selected)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
