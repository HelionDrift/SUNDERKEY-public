"""MCP read bindings remain closed to known nonmutating API operations."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.mcp_api_read_bindings import (
    MCPApiReadBindingError,
    build_mcp_api_read_bindings,
    verify_mcp_api_read_bindings,
)
from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight

DIGEST = "sha256:" + "a" * 64


def source() -> tuple[dict, dict, dict]:
    manifest = {
        "schema_version": 1,
        "protocol_revision": "2026-07-28",
        "server_ref": "serverref:proposed",
        "tenant_ref": "tenantref:example",
        "scope_sha256": DIGEST,
        "list_is_principal_scoped": True,
        "list_cache_ttl_ms": 0,
        "tools": [{
            "name": "sunderkey.get_status",
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
    preflight = build_mcp_catalog_preflight(manifest)
    request = {"schema_version": 1, "bindings": [{
        "tool_name": "sunderkey.get_status", "api_operation": "get_status",
    }]}
    return manifest, preflight, request


class MCPApiReadBindingTests(unittest.TestCase):
    def test_known_read_binding_reproduces_without_execution(self) -> None:
        manifest, preflight, request = source()
        plan = build_mcp_api_read_bindings(manifest, preflight, request)
        self.assertEqual(plan["binding_status"], "static_read_only_mapping_for_review")
        self.assertEqual(plan["effects"]["api_call"], "none")
        self.assertEqual(plan["qualification_effect"], "none")
        self.assertEqual(
            verify_mcp_api_read_bindings(manifest, preflight, request, plan)["status"],
            "valid",
        )

    def test_all_four_curated_read_operations_are_accepted(self) -> None:
        for name, operation in (
            ("sunderkey.get_status", "get_status"),
            ("sunderkey.list_evidence", "list_evidence"),
            ("sunderkey.list_findings", "list_findings"),
            ("sunderkey.get_report", "get_report"),
        ):
            manifest, _, request = source()
            manifest["tools"][0]["name"] = name
            request["bindings"][0] = {"tool_name": name, "api_operation": operation}
            with self.subTest(name=name):
                plan = build_mcp_api_read_bindings(
                    manifest, build_mcp_catalog_preflight(manifest), request,
                )
                self.assertEqual(plan["bindings"][0]["api_operation"], operation)

    def test_action_tool_or_mutation_alias_is_rejected(self) -> None:
        manifest, _, request = source()
        manifest["tools"][0]["effect_class"] = "action"
        manifest["tools"][0]["human_confirmation_required"] = True
        manifest["tools"][0]["independent_action_admission_required"] = True
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(
                manifest, build_mcp_catalog_preflight(manifest), request,
            )
        manifest, preflight, request = source()
        request["bindings"][0]["api_operation"] = "create_assessment"
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(manifest, preflight, request)

    def test_missing_or_arbitrary_tool_binding_is_rejected(self) -> None:
        manifest, preflight, request = source()
        request["bindings"] = []
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(manifest, preflight, request)
        manifest, preflight, request = source()
        request["bindings"][0]["tool_name"] = "sunderkey.other"
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(manifest, preflight, request)

    def test_control_gap_or_tampered_source_is_rejected(self) -> None:
        manifest, preflight, request = source()
        manifest["tools"][0]["audience_validation_required"] = False
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(
                manifest, build_mcp_catalog_preflight(manifest), request,
            )
        manifest, preflight, request = source()
        preflight["tool_count"] = 0
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(manifest, preflight, request)
        manifest, preflight, request = source()
        plan = build_mcp_api_read_bindings(manifest, preflight, request)
        altered = copy.deepcopy(plan)
        altered["bindings"][0]["api_operation"] = "emergency_stop"
        with self.assertRaises(MCPApiReadBindingError):
            verify_mcp_api_read_bindings(manifest, preflight, request, altered)

    def test_cli_roundtrip(self) -> None:
        manifest, preflight, request = source()
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (
                ("manifest", manifest), ("preflight", preflight),
                ("bindings", request),
            ):
                paths[name] = Path(directory) / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            options = [
                token for name, path in paths.items()
                for token in ("--" + name, str(path))
            ]
            parser = build_parser()
            args = parser.parse_args(["mcp-api-read-bindings", *options])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "mcp-api-read-bindings-verify", *options, "--plan", str(plan_path),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
