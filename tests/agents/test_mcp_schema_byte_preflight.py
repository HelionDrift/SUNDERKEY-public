"""Exact supplied schema bytes cannot be substituted under an MCP catalog."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_schema_byte_preflight import (
    MAX_SCHEMA_BYTES,
    MCPSchemaBytePreflightError,
    build_mcp_schema_byte_preflight,
    verify_mcp_schema_byte_preflight,
)
from tests.agents.test_mcp_catalog_preflight import manifest

INPUT_SCHEMA = b'{"type":"object","properties":{"id":{"type":"string"}}}'
OUTPUT_SCHEMA = b'{"type":"object","properties":{"status":{"type":"string"}}}'


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sources() -> tuple[dict, dict, dict]:
    proposed = manifest()
    proposed["tools"][0]["input_schema_sha256"] = digest(INPUT_SCHEMA)
    proposed["tools"][0]["output_schema_sha256"] = digest(OUTPUT_SCHEMA)
    preflight = build_mcp_catalog_preflight(proposed)
    bundle = {
        "schema_version": 1,
        "tools": [{
            "tool_name": proposed["tools"][0]["name"],
            "input_schema_base64": base64.b64encode(INPUT_SCHEMA).decode("ascii"),
            "output_schema_base64": base64.b64encode(OUTPUT_SCHEMA).decode("ascii"),
        }],
    }
    return proposed, preflight, bundle


class MCPSchemaBytePreflightTests(unittest.TestCase):
    def test_exact_bytes_bind_all_declared_digests_without_effects(self) -> None:
        proposed, preflight, bundle = sources()
        result = build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        self.assertEqual(
            result["schema_byte_status"], "declared_digests_match_supplied_bytes",
        )
        self.assertEqual(result["tools"][0]["input_schema_sha256"], digest(INPUT_SCHEMA))
        self.assertEqual(result["tools"][0]["input_schema_byte_count"], len(INPUT_SCHEMA))
        self.assertEqual(result["effects"]["mcp_server"], "none")
        self.assertEqual(result["effects"]["tool_execution"], "none")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(
            result["catalog_control_status"], "declared_controls_complete_for_review",
        )
        self.assertNotIn("input_schema_base64", str(result))
        self.assertEqual(
            verify_mcp_schema_byte_preflight(proposed, preflight, bundle, result)["status"],
            "valid",
        )

    def test_schema_match_does_not_hide_catalog_control_gaps(self) -> None:
        proposed, _, bundle = sources()
        proposed["list_is_principal_scoped"] = False
        preflight = build_mcp_catalog_preflight(proposed)
        result = build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        self.assertEqual(result["catalog_control_status"], "declaration_gaps")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(result["effects"]["authorization"], "none")

    def test_semantically_equal_but_different_bytes_do_not_match(self) -> None:
        proposed, preflight, bundle = sources()
        alternate = b'{ "type":"object","properties":{"id":{"type":"string"}}}'
        self.assertEqual(json.loads(alternate), json.loads(INPUT_SCHEMA))
        bundle["tools"][0]["input_schema_base64"] = base64.b64encode(
            alternate,
        ).decode("ascii")
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "do not match"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)

    def test_boolean_output_schema_is_json_schema_but_input_remains_object(self) -> None:
        proposed, _, bundle = sources()
        output = b'true'
        proposed["tools"][0]["output_schema_sha256"] = digest(output)
        bundle["tools"][0]["output_schema_base64"] = base64.b64encode(output).decode("ascii")
        preflight = build_mcp_catalog_preflight(proposed)
        result = build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        self.assertEqual(result["tools"][0]["output_schema_sha256"], digest(output))
        proposed["tools"][0]["input_schema_sha256"] = digest(output)
        bundle["tools"][0]["input_schema_base64"] = base64.b64encode(output).decode("ascii")
        preflight = build_mcp_catalog_preflight(proposed)
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "input schema must"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)

    def test_incomplete_reordered_and_extra_schema_entries_fail(self) -> None:
        proposed, preflight, bundle = sources()
        proposed["tools"].append(copy.deepcopy(proposed["tools"][0]))
        proposed["tools"][0]["name"] = "sunderkey.alpha"
        proposed["tools"][1]["name"] = "sunderkey.beta"
        preflight = build_mcp_catalog_preflight(proposed)
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "cover every"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        bundle["tools"] = [
            {**bundle["tools"][0], "tool_name": name}
            for name in ("sunderkey.beta", "sunderkey.alpha")
        ]
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "order or name"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        bundle["tools"].reverse()
        bundle["tools"][0]["unexpected"] = True
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "fields"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)

    def test_bad_base64_invalid_json_duplicate_keys_and_size_fail(self) -> None:
        proposed, preflight, bundle = sources()
        entry = bundle["tools"][0]
        for raw in ("bad!", "AA==A"):
            entry["input_schema_base64"] = raw
            with self.assertRaises(MCPSchemaBytePreflightError):
                build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        for raw in (
            b'{"type":"object","type":"array"}',
            b'not JSON',
            b'[1,2]',
            b'{"value":NaN}',
            b'\xff',
            b'{"value":1e999}',
            b'{"value":"' + b'a' * MAX_SCHEMA_BYTES + b'"}',
        ):
            entry["input_schema_base64"] = base64.b64encode(raw).decode("ascii")
            with self.assertRaises(MCPSchemaBytePreflightError):
                build_mcp_schema_byte_preflight(proposed, preflight, bundle)

    def test_total_bundle_size_is_bounded_after_individual_schema_checks(self) -> None:
        proposed, _, bundle = sources()
        large_schema = b'{"description":"' + b'a' * 200_000 + b'"}'
        proposed["tools"] = [copy.deepcopy(proposed["tools"][0]) for _ in range(2)]
        for index, name in enumerate(("sunderkey.alpha", "sunderkey.beta")):
            proposed["tools"][index]["name"] = name
            proposed["tools"][index]["input_schema_sha256"] = digest(large_schema)
            proposed["tools"][index]["output_schema_sha256"] = digest(large_schema)
        encoded = base64.b64encode(large_schema).decode("ascii")
        bundle["tools"] = [
            {
                "tool_name": name,
                "input_schema_base64": encoded,
                "output_schema_base64": encoded,
            }
            for name in ("sunderkey.alpha", "sunderkey.beta")
        ]
        preflight = build_mcp_catalog_preflight(proposed)
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "size limit"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)

    def test_source_and_result_tampering_fail_reproduction(self) -> None:
        proposed, preflight, bundle = sources()
        preflight["tool_count"] = 2
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "not reproducible"):
            build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        proposed, preflight, bundle = sources()
        result = build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        result["qualification_effect"] = "qualified"
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "does not reproduce"):
            verify_mcp_schema_byte_preflight(proposed, preflight, bundle, result)
        result = build_mcp_schema_byte_preflight(proposed, preflight, bundle)
        result["tools"][0]["input_schema_byte_count"] = True
        with self.assertRaisesRegex(MCPSchemaBytePreflightError, "does not reproduce"):
            verify_mcp_schema_byte_preflight(proposed, preflight, bundle, result)

    def test_cli_build_verify_and_duplicate_outer_keys(self) -> None:
        proposed, preflight, bundle = sources()
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in (
                "manifest.json", "preflight.json", "schemas.json", "result.json",
            )]
            for path, value in zip(paths[:3], (proposed, preflight, bundle), strict=True):
                path.write_text(json.dumps(value), encoding="utf-8")
            arguments = [
                "--manifest", str(paths[0]), "--preflight", str(paths[1]),
                "--schemas", str(paths[2]),
            ]
            args = parser.parse_args(["mcp-schema-byte-preflight", *arguments])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            paths[3].write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "mcp-schema-byte-preflight-verify", *arguments,
                "--result", str(paths[3]),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")
            paths[2].write_text('{"schema_version":1,"tools":[],"tools":[]}', encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                args.handler(args)


if __name__ == "__main__":
    unittest.main()
