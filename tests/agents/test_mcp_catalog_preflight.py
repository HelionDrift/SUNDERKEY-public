"""A proposed MCP catalog cannot imply authority or server operation."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.mcp_catalog_preflight import (
    MCPCatalogPreflightError,
    build_mcp_catalog_preflight,
    verify_mcp_catalog_preflight,
)

DIGEST = "sha256:" + "a" * 64


def manifest() -> dict:
    return {
        "schema_version": 1,
        "protocol_revision": "2026-07-28",
        "server_ref": "serverref:proposed",
        "tenant_ref": "tenantref:example",
        "scope_sha256": DIGEST,
        "list_is_principal_scoped": True,
        "list_cache_ttl_ms": 0,
        "tools": [{
            "name": "sunderkey.read_status",
            "effect_class": "read",
            "input_schema_sha256": DIGEST,
            "output_schema_sha256": DIGEST,
            "principal_authentication_required": True,
            "audience_validation_required": True,
            "tenant_scope_filter_required": True,
            "human_confirmation_required": False,
            "independent_action_admission_required": False,
            "audit_event_required": True,
            "token_passthrough_allowed": False,
            "model_self_authorization_allowed": False,
            "annotations_authoritative": False,
            "maximum_calls_per_minute": 30,
        }],
    }


class MCPCatalogPreflightTests(unittest.TestCase):
    def test_bounded_read_catalog_reproduces_with_no_effects(self) -> None:
        source = manifest()
        result = build_mcp_catalog_preflight(source)
        self.assertEqual(result["preflight_status"], "declared_controls_complete_for_review")
        self.assertEqual(result["effects"]["mcp_server"], "none")
        self.assertEqual(result["effects"]["tool_execution"], "none")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(verify_mcp_catalog_preflight(source, result)["status"], "valid")

    def test_action_tool_needs_independent_admission_and_confirmation(self) -> None:
        source = manifest()
        tool = source["tools"][0]
        tool["effect_class"] = "action"
        codes = {item["code"] for item in build_mcp_catalog_preflight(source)["issues"]}
        self.assertIn("action_human_confirmation_missing", codes)
        self.assertIn("independent_action_admission_missing", codes)
        tool["human_confirmation_required"] = True
        tool["independent_action_admission_required"] = True
        self.assertEqual(build_mcp_catalog_preflight(source)["issues"], [])

    def test_auth_scope_audit_token_and_self_authorization_gaps_are_visible(self) -> None:
        source = manifest()
        source["list_is_principal_scoped"] = False
        source["list_cache_ttl_ms"] = 1000
        tool = source["tools"][0]
        for name in (
            "principal_authentication_required", "audience_validation_required",
            "tenant_scope_filter_required", "audit_event_required",
        ):
            tool[name] = False
        for name in (
            "token_passthrough_allowed", "model_self_authorization_allowed",
            "annotations_authoritative",
        ):
            tool[name] = True
        tool["maximum_calls_per_minute"] = 0
        result = build_mcp_catalog_preflight(source)
        codes = {item["code"] for item in result["issues"]}
        self.assertEqual(result["preflight_status"], "declaration_gaps")
        self.assertIn("tool_list_not_principal_scoped", codes)
        self.assertIn("tool_list_cache_not_disabled", codes)
        self.assertIn("token_audience_validation_missing", codes)
        self.assertIn("token_passthrough_allowed", codes)
        self.assertIn("model_self_authorization_allowed", codes)
        self.assertIn("untrusted_annotations_used_for_authority", codes)
        self.assertIn("rate_limit_missing", codes)

    def test_unknown_fields_duplicate_tools_and_wrong_revision_fail(self) -> None:
        source = manifest()
        source["tools"][0]["arguments"] = {"target": "example"}
        with self.assertRaises(MCPCatalogPreflightError):
            build_mcp_catalog_preflight(source)
        source = manifest()
        source["tools"].append(copy.deepcopy(source["tools"][0]))
        with self.assertRaises(MCPCatalogPreflightError):
            build_mcp_catalog_preflight(source)
        source = manifest()
        source["protocol_revision"] = "2025-11-25"
        with self.assertRaises(MCPCatalogPreflightError):
            build_mcp_catalog_preflight(source)

    def test_tampered_preflight_fails(self) -> None:
        source = manifest()
        result = build_mcp_catalog_preflight(source)
        result["tool_count"] = 100
        with self.assertRaises(MCPCatalogPreflightError):
            verify_mcp_catalog_preflight(source, result)

    def test_cli_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            preflight_path = Path(directory) / "preflight.json"
            manifest_path.write_text(json.dumps(manifest()), encoding="utf-8")
            parser = build_parser()
            args = parser.parse_args([
                "mcp-catalog-preflight", "--manifest", str(manifest_path),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            preflight_path.write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "mcp-catalog-preflight-verify", "--manifest", str(manifest_path),
                "--preflight", str(preflight_path),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
