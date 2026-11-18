"""The offline MCP read-tool chain must replay all declared source checks."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_header_annotation_preflight import build_mcp_header_annotation_preflight
from sunderkey.mcp_local_reference_closure import build_mcp_local_reference_closure
from sunderkey.mcp_read_tool_closure import (
    MCPReadToolClosureError,
    build_mcp_read_tool_closure,
    verify_mcp_read_tool_closure,
)
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import build_mcp_schema_semantic_preflight
from sunderkey.mcp_api_read_bindings import build_mcp_api_read_bindings

from .test_mcp_api_read_bindings import source


def sources() -> tuple[dict, ...]:
    manifest, _, request = source()
    input_schema = (
        b'{"$defs":{"id":{"type":"string"}},"properties":'
        b'{"id":{"$ref":"#/$defs/id"}},"type":"object"}'
    )
    output_schema = b'{"properties":{"status":{"type":"string"}},"type":"object"}'
    manifest["tools"][0]["input_schema_sha256"] = (
        "sha256:" + hashlib.sha256(input_schema).hexdigest()
    )
    manifest["tools"][0]["output_schema_sha256"] = (
        "sha256:" + hashlib.sha256(output_schema).hexdigest()
    )
    catalog = build_mcp_catalog_preflight(manifest)
    bindings = build_mcp_api_read_bindings(manifest, catalog, request)
    bundle = {
        "schema_version": 1,
        "tools": [{
            "tool_name": manifest["tools"][0]["name"],
            "input_schema_base64": base64.b64encode(input_schema).decode("ascii"),
            "output_schema_base64": base64.b64encode(output_schema).decode("ascii"),
        }],
    }
    byte = build_mcp_schema_byte_preflight(manifest, catalog, bundle)
    semantic = build_mcp_schema_semantic_preflight(manifest, catalog, bundle, byte)
    reference = build_mcp_local_reference_closure(
        manifest, catalog, bundle, byte, semantic
    )
    header = build_mcp_header_annotation_preflight(
        manifest, catalog, bundle, byte, semantic
    )
    return manifest, catalog, request, bindings, bundle, byte, semantic, reference, header


class MCPReadToolClosureTests(unittest.TestCase):
    def test_replays_complete_read_chain_without_runtime_claims(self) -> None:
        chain = sources()
        result = build_mcp_read_tool_closure(*chain)
        self.assertEqual(result["tool_count"], 1)
        self.assertEqual(result["tools"][0]["api_operation"], "get_status")
        self.assertEqual(result["tools"][0]["input_local_reference_count"], 1)
        self.assertFalse(result["api_argument_mapping_verified"])
        self.assertFalse(result["api_response_mapping_verified"])
        self.assertFalse(result["principal_authenticated"])
        self.assertFalse(result["tenant_scope_enforced"])
        self.assertEqual(result["effects"]["api_call"], "none")
        self.assertEqual(
            verify_mcp_read_tool_closure(*chain, result)["status"], "valid"
        )
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/mcp-read-tool-closure-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

    def test_source_substitution_and_changed_result_fail_closed(self) -> None:
        chain = list(sources())
        result = build_mcp_read_tool_closure(*chain)
        changed = copy.deepcopy(result)
        changed["tenant_scope_enforced"] = True
        with self.assertRaises(MCPReadToolClosureError):
            verify_mcp_read_tool_closure(*chain, changed)
        changed = copy.deepcopy(result)
        changed["tools"][0]["api_operation"] = "emergency_stop"
        with self.assertRaises(MCPReadToolClosureError):
            verify_mcp_read_tool_closure(*chain, changed)
        changed_source = copy.deepcopy(chain)
        changed_source[3]["bindings"][0]["api_operation"] = "list_findings"
        with self.assertRaises(MCPReadToolClosureError):
            build_mcp_read_tool_closure(*changed_source)
        changed_source = copy.deepcopy(chain)
        changed_source[7]["tools"][0]["schemas"][0]["local_reference_count"] = 0
        with self.assertRaises(MCPReadToolClosureError):
            build_mcp_read_tool_closure(*changed_source)

    def test_action_tool_is_not_eligible_for_read_closure(self) -> None:
        chain = list(sources())
        chain[0]["tools"][0]["effect_class"] = "action"
        chain[0]["tools"][0]["human_confirmation_required"] = True
        chain[0]["tools"][0]["independent_action_admission_required"] = True
        chain[1] = build_mcp_catalog_preflight(chain[0])
        with self.assertRaises(MCPReadToolClosureError):
            build_mcp_read_tool_closure(*chain)

    def test_multiple_tools_keep_exact_order_and_operation(self) -> None:
        manifest, _, request, _, bundle, *_ = sources()
        second_tool = copy.deepcopy(manifest["tools"][0])
        second_tool["name"] = "sunderkey.list_findings"
        manifest["tools"].append(second_tool)
        request["bindings"].append({
            "tool_name": "sunderkey.list_findings",
            "api_operation": "list_findings",
        })
        second_bundle = copy.deepcopy(bundle["tools"][0])
        second_bundle["tool_name"] = second_tool["name"]
        bundle["tools"].append(second_bundle)
        catalog = build_mcp_catalog_preflight(manifest)
        bindings = build_mcp_api_read_bindings(manifest, catalog, request)
        byte = build_mcp_schema_byte_preflight(manifest, catalog, bundle)
        semantic = build_mcp_schema_semantic_preflight(manifest, catalog, bundle, byte)
        reference = build_mcp_local_reference_closure(
            manifest, catalog, bundle, byte, semantic
        )
        header = build_mcp_header_annotation_preflight(
            manifest, catalog, bundle, byte, semantic
        )
        chain = (
            manifest, catalog, request, bindings, bundle, byte, semantic,
            reference, header,
        )
        result = build_mcp_read_tool_closure(*chain)
        self.assertEqual(
            [tool["api_operation"] for tool in result["tools"]],
            ["get_status", "list_findings"],
        )
        changed_header = copy.deepcopy(header)
        changed_header["tools"].reverse()
        with self.assertRaises(MCPReadToolClosureError):
            build_mcp_read_tool_closure(*chain[:-1], changed_header)


if __name__ == "__main__":
    unittest.main()
