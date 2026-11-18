"""Bounded JSON Schema checks stay separate from MCP tool authorization."""

from __future__ import annotations

import base64
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import (
    MCPSchemaSemanticPreflightError,
    build_mcp_schema_semantic_preflight,
    verify_mcp_schema_semantic_preflight,
)
from tests.agents.test_mcp_schema_byte_preflight import digest, sources


def replace_schema(
    manifest: dict, bundle: dict, *, field: str, schema: object,
) -> None:
    raw = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")
    manifest["tools"][0][field + "_sha256"] = digest(raw)
    bundle["tools"][0][field + "_base64"] = base64.b64encode(raw).decode("ascii")


class MCPSchemaSemanticPreflightTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, dict, dict, dict]:
        manifest, preflight, bundle = sources()
        return manifest, preflight, bundle, build_mcp_schema_byte_preflight(
            manifest, preflight, bundle
        )

    def test_full_vocabulary_local_schema_and_boolean_output_are_bounded(self) -> None:
        manifest, _, bundle = sources()
        replace_schema(
            manifest, bundle, field="input_schema",
            schema={
                "type": "object",
                "$defs": {"id": {"type": "string", "minLength": 1}},
                "properties": {"id": {"$ref": "#/$defs/id"}},
                "oneOf": [{"required": ["id"]}, {"maxProperties": 0}],
            },
        )
        replace_schema(manifest, bundle, field="output_schema", schema=True)
        preflight = build_mcp_catalog_preflight(manifest)
        byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
        result = build_mcp_schema_semantic_preflight(
            manifest, preflight, bundle, byte_result
        )
        self.assertEqual(result["tools"][0]["input_schema"]["reference_count"], 1)
        self.assertEqual(result["tools"][0]["input_schema"]["external_reference_count"], 0)
        self.assertEqual(result["tools"][0]["output_schema"]["root_type"], "unrestricted")
        self.assertFalse(result["external_references_resolved"])
        self.assertFalse(result["live_server_schema_verified"])
        self.assertEqual(result["effects"]["tool_execution"], "none")
        self.assertEqual(
            verify_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, byte_result, result
            )["status"],
            "valid",
        )

    def test_invalid_metaschema_object_root_and_dialect_fail(self) -> None:
        for schema, expected in (
            ({"type": "not-a-type"}, "object root"),
            ({"type": "object", "properties": []}, "metaschema"),
            ({"type": "object", "$schema": "https://example.test/dialect"}, "dialect"),
        ):
            with self.subTest(schema=schema):
                manifest, _, bundle = sources()
                replace_schema(manifest, bundle, field="input_schema", schema=schema)
                preflight = build_mcp_catalog_preflight(manifest)
                byte_result = build_mcp_schema_byte_preflight(
                    manifest, preflight, bundle
                )
                with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, expected):
                    build_mcp_schema_semantic_preflight(
                        manifest, preflight, bundle, byte_result
                    )

    def test_invalid_nested_keyword_and_excessive_depth_fail(self) -> None:
        manifest, _, bundle = sources()
        replace_schema(
            manifest, bundle, field="input_schema",
            schema={"type": "object", "properties": {"id": {"minLength": -1}}},
        )
        preflight = build_mcp_catalog_preflight(manifest)
        byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "metaschema"):
            build_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, byte_result
            )
        schema: dict = {"type": "string"}
        for _ in range(36):
            schema = {"properties": {"next": schema}}
        schema["type"] = "object"
        manifest, _, bundle = sources()
        replace_schema(manifest, bundle, field="input_schema", schema=schema)
        preflight = build_mcp_catalog_preflight(manifest)
        byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "bounds"):
            build_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, byte_result
            )

    def test_external_reference_is_reported_but_never_dereferenced(self) -> None:
        manifest, _, bundle = sources()
        replace_schema(
            manifest, bundle, field="input_schema",
            schema={
                "type": "object",
                "properties": {"id": {"$ref": "https://example.test/schema"}},
            },
        )
        preflight = build_mcp_catalog_preflight(manifest)
        byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
        result = build_mcp_schema_semantic_preflight(
            manifest, preflight, bundle, byte_result
        )
        self.assertEqual(result["tools"][0]["input_schema"]["external_reference_count"], 1)
        self.assertEqual(
            result["tools"][0]["input_schema"]["reference_resolution"],
            "not_performed",
        )

    def test_stale_byte_result_and_semantic_claim_tampering_fail(self) -> None:
        manifest, preflight, bundle, byte_result = self.fixture()
        changed = copy.deepcopy(byte_result)
        changed["tools"][0]["input_schema_byte_count"] += 1
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "byte preflight"):
            build_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, changed
            )
        result = build_mcp_schema_semantic_preflight(
            manifest, preflight, bundle, byte_result
        )
        result["live_server_schema_verified"] = True
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "reproduce"):
            verify_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, byte_result, result
            )

    def test_cli_build_and_verify(self) -> None:
        manifest, preflight, bundle, byte_result = self.fixture()
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in (
                "manifest.json", "preflight.json", "schemas.json", "byte.json",
                "semantic.json",
            )]
            for path, value in zip(
                paths[:4], (manifest, preflight, bundle, byte_result), strict=True
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
            arguments = [
                "--manifest", str(paths[0]), "--preflight", str(paths[1]),
                "--schemas", str(paths[2]), "--byte-result", str(paths[3]),
            ]
            args = parser.parse_args(["mcp-schema-semantic-preflight", *arguments])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            paths[4].write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "mcp-schema-semantic-preflight-verify", *arguments,
                "--result", str(paths[4]),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
