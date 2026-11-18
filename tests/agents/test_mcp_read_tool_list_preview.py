"""MCP read-tool list previews never serve or authorize caller-declared tools."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.mcp_read_tool_closure import build_mcp_read_tool_closure
from sunderkey.mcp_read_tool_list_preview import (
    MCPReadToolListPreviewError,
    build_mcp_read_tool_list_preview,
    verify_mcp_read_tool_list_preview,
)

from .test_mcp_read_tool_closure import sources


class MCPReadToolListPreviewTests(unittest.TestCase):
    def test_complete_private_zero_ttl_preview_is_replayed(self) -> None:
        chain = sources()
        read_closure = build_mcp_read_tool_closure(*chain)
        result = build_mcp_read_tool_list_preview(*chain, read_closure)
        listing = result["list_result_preview"]
        self.assertEqual(listing["resultType"], "complete")
        self.assertEqual(listing["cacheScope"], "private")
        self.assertEqual(listing["ttlMs"], 0)
        self.assertEqual(listing["tools"][0]["name"], "sunderkey.get_status")
        self.assertEqual(
            listing["tools"][0]["inputSchema"]["properties"]["id"]["$ref"],
            "#/$defs/id",
        )
        self.assertFalse(result["principal_authenticated"])
        self.assertFalse(result["api_argument_mapping_verified"])
        self.assertFalse(result["api_response_mapping_verified"])
        self.assertFalse(result["tenant_scope_enforced"])
        self.assertFalse(result["tool_list_served"])
        self.assertEqual(result["effects"]["network"], "none")
        self.assertEqual(
            verify_mcp_read_tool_list_preview(*chain, read_closure, result)["status"],
            "valid",
        )
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/mcp-read-tool-list-preview-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

    def test_modified_schema_cache_claim_or_source_fails(self) -> None:
        chain = sources()
        read_closure = build_mcp_read_tool_closure(*chain)
        result = build_mcp_read_tool_list_preview(*chain, read_closure)
        for field, value in (("ttlMs", 300000), ("cacheScope", "public")):
            changed = copy.deepcopy(result)
            changed["list_result_preview"][field] = value
            with self.subTest(field=field), self.assertRaises(MCPReadToolListPreviewError):
                verify_mcp_read_tool_list_preview(*chain, read_closure, changed)
        changed = copy.deepcopy(result)
        changed["list_result_preview"]["tools"][0]["inputSchema"]["type"] = "string"
        with self.assertRaises(MCPReadToolListPreviewError):
            verify_mcp_read_tool_list_preview(*chain, read_closure, changed)
        changed = copy.deepcopy(read_closure)
        changed["tools"][0]["api_operation"] = "emergency_stop"
        with self.assertRaises(MCPReadToolListPreviewError):
            build_mcp_read_tool_list_preview(*chain, changed)


if __name__ == "__main__":
    unittest.main()
