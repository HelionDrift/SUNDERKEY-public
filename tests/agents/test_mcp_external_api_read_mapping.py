"""Offline MCP read projections must use exact external API contracts."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from sunderkey.api_service_contracts import (
    ApiError,
    ApiResponseEnvelope,
    PageResult,
    RequestBudget,
    ResourceReference,
    TenantPrincipalBinding,
)
from sunderkey.json_contract_integrity import canonical_json_bytes
from sunderkey.mcp_api_read_bindings import build_mcp_api_read_bindings
from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_external_api_read_mapping import (
    MCPExternalApiReadMappingError,
    expected_mcp_read_input_schema,
    expected_mcp_read_output_schema,
    project_api_read_response_to_mcp_result,
    project_mcp_jsonrpc_read_exchange,
    project_mcp_jsonrpc_read_request,
    project_mcp_jsonrpc_read_tool_list,
    project_mcp_read_arguments_to_api_request,
    project_mcp_tools_call_exchange,
    project_mcp_tools_call_to_api_request,
)
from sunderkey.mcp_header_annotation_preflight import build_mcp_header_annotation_preflight
from sunderkey.mcp_local_reference_closure import build_mcp_local_reference_closure
from sunderkey.mcp_read_tool_closure import build_mcp_read_tool_closure
from sunderkey.mcp_read_tool_list_preview import build_mcp_read_tool_list_preview
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import build_mcp_schema_semantic_preflight

from .test_mcp_api_read_bindings import source
from .test_mcp_read_tool_closure import sources as generic_sources

TOOLS = {
    "sunderkey.get_status": ("get_status", "status", "statusref:"),
    "sunderkey.list_evidence": ("list_evidence", "evidence", "evidref:"),
    "sunderkey.list_findings": ("list_findings", "finding", "findingref:"),
    "sunderkey.get_report": ("get_report", "report", "reportref:"),
}
DIGEST = "sha256:" + "a" * 64


def _schema_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _chain(tool_names: str | tuple[str, ...]) -> tuple[tuple[dict, ...], dict, dict]:
    names = (tool_names,) if isinstance(tool_names, str) else tuple(sorted(tool_names))
    manifest, _, request = source()
    template = manifest["tools"][0]
    manifest["tools"] = []
    request["bindings"] = []
    bundle_tools = []
    for tool_name in names:
        tool = copy.deepcopy(template)
        tool["name"] = tool_name
        request["bindings"].append({
            "tool_name": tool_name,
            "api_operation": TOOLS[tool_name][0],
        })
        input_bytes = _schema_bytes(expected_mcp_read_input_schema(tool_name))
        output_bytes = _schema_bytes(expected_mcp_read_output_schema())
        tool["input_schema_sha256"] = (
            "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        )
        tool["output_schema_sha256"] = (
            "sha256:" + hashlib.sha256(output_bytes).hexdigest()
        )
        manifest["tools"].append(tool)
        bundle_tools.append({
            "tool_name": tool_name,
            "input_schema_base64": base64.b64encode(input_bytes).decode("ascii"),
            "output_schema_base64": base64.b64encode(output_bytes).decode("ascii"),
        })
    catalog = build_mcp_catalog_preflight(manifest)
    bindings = build_mcp_api_read_bindings(manifest, catalog, request)
    bundle = {"schema_version": 1, "tools": bundle_tools}
    byte = build_mcp_schema_byte_preflight(manifest, catalog, bundle)
    semantic = build_mcp_schema_semantic_preflight(manifest, catalog, bundle, byte)
    reference = build_mcp_local_reference_closure(
        manifest, catalog, bundle, byte, semantic,
    )
    header = build_mcp_header_annotation_preflight(
        manifest, catalog, bundle, byte, semantic,
    )
    sources = (
        manifest, catalog, request, bindings, bundle, byte, semantic,
        reference, header,
    )
    closure = build_mcp_read_tool_closure(*sources)
    preview = build_mcp_read_tool_list_preview(*sources, closure)
    return sources, closure, preview


def _binding(tenant: str = "tenantref:example") -> TenantPrincipalBinding:
    return TenantPrincipalBinding(
        tenant_id=tenant,
        principal_id="principal.operator",
        principal_role="assessment_operator",
        authentication_context_ref="authctx.session-01",
    )


def _budget() -> RequestBudget:
    return RequestBudget(65_536, 100, 50, 120)


def _response(request, *, empty: bool = False, rejected: bool = False):
    _, kind, prefix = TOOLS[next(
        name for name, (operation, _, _) in TOOLS.items()
        if operation == request.operation.value
    )]
    return ApiResponseEnvelope(
        operation=request.operation,
        request_contract_id=request.request_contract_id,
        request_sha256=request.request_sha256,
        binding=request.binding,
        responded_at="2026-10-15T12:00:01Z",
        status="rejected" if rejected else "completed",
        resources=(
            () if empty or rejected else
            (ResourceReference(kind, prefix + "resource-1", DIGEST, 1),)
        ),
        page=(
            None if rejected or request.page is None else
            PageResult(0 if empty else 1)
        ),
        error=ApiError("not_found", "Private message", False, "error.detail")
        if rejected else None,
    )


class MCPExternalApiReadMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chains = {name: _chain(name) for name in TOOLS}

    def request(self, name: str, arguments: dict | None = None):
        sources, closure, preview = self.chains[name]
        if arguments is None:
            arguments = {"resource_id": "assessment.001"}
            if name.startswith("sunderkey.list_"):
                arguments["page_size"] = 25
        return project_mcp_read_arguments_to_api_request(
            sources, closure, preview, name, arguments,
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001",
            issued_at="2026-10-15T12:00:00Z",
        )

    def test_all_four_reads_project_to_exact_api_request_and_result(self) -> None:
        for name, (operation, _, _) in TOOLS.items():
            with self.subTest(name=name):
                sources, closure, preview = self.chains[name]
                input_schema = expected_mcp_read_input_schema(name)
                output_schema = expected_mcp_read_output_schema()
                Draft202012Validator.check_schema(input_schema)
                Draft202012Validator.check_schema(output_schema)
                request = self.request(name)
                self.assertEqual(request.operation.value, operation)
                self.assertEqual(request.binding, _binding())
                self.assertEqual(request.body_size_bytes, 0)
                if "list_" in name:
                    self.assertEqual(request.page.size, 25)
                else:
                    self.assertIsNone(request.page)
                result = project_api_read_response_to_mcp_result(
                    sources, closure, preview, name, request, _response(request),
                )
                self.assertEqual(
                    set(result),
                    {"resultType", "content", "structuredContent", "isError"},
                )
                self.assertEqual(result["resultType"], "complete")
                self.assertFalse(result["isError"])
                self.assertEqual(
                    json.loads(result["content"][0]["text"]),
                    result["structuredContent"],
                )
                Draft202012Validator(output_schema).validate(result["structuredContent"])
                self.assertNotIn("principal.operator", json.dumps(result))
                self.assertNotIn("authctx.session-01", json.dumps(result))

    def test_complete_four_tool_catalog_selects_each_exact_binding(self) -> None:
        sources, closure, preview = _chain(tuple(TOOLS))
        self.assertEqual(preview["tool_count"], 4)
        for name, (operation, _, _) in TOOLS.items():
            arguments = {"resource_id": "assessment.001"}
            if "list_" in name:
                arguments["page_size"] = 10
            with self.subTest(name=name):
                request = project_mcp_tools_call_to_api_request(
                    sources, closure, preview,
                    {"name": name, "arguments": arguments},
                    binding=_binding(), budget=_budget(),
                    request_id="request.mcp-read-001",
                    issued_at="2026-10-15T12:00:00Z",
                )
                self.assertEqual(request.operation.value, operation)

    def test_jsonrpc_read_envelope_keeps_client_metadata_out_of_api_context(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        message = {
            "jsonrpc": "2.0",
            "id": "client.17",
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": {"resource_id": "assessment.001"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": sources[0]["protocol_revision"],
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "test-client", "version": "1.0",
                    },
                },
            },
        }
        client_id, selected, request = project_mcp_jsonrpc_read_request(
            sources, closure, preview, message,
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001", issued_at="2026-10-15T12:00:00Z",
        )
        self.assertEqual((client_id, selected), ("client.17", name))
        self.assertEqual(request, self.request(name))
        self.assertNotEqual(request.request_id, client_id)
        envelope = project_mcp_jsonrpc_read_exchange(
            sources, closure, preview, message, _response(request),
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001", issued_at="2026-10-15T12:00:00Z",
        )
        self.assertEqual(set(envelope), {"jsonrpc", "id", "result"})
        self.assertEqual(envelope["id"], client_id)
        self.assertEqual(envelope["result"]["resultType"], "complete")
        self.assertNotIn("test-client", json.dumps(envelope))
        self.assertNotIn("principal.operator", json.dumps(envelope))
        rejected = project_mcp_jsonrpc_read_exchange(
            sources, closure, preview, message, _response(request, rejected=True),
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001", issued_at="2026-10-15T12:00:00Z",
        )
        self.assertTrue(rejected["result"]["isError"])
        self.assertNotIn("error", rejected)

    def test_jsonrpc_read_envelope_rejects_missing_metadata_and_spoofed_authority(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        base = {
            "jsonrpc": "2.0", "id": 17, "method": "tools/call",
            "params": {
                "name": name, "arguments": {"resource_id": "assessment.001"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": sources[0]["protocol_revision"],
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
        changes = []
        for field, value in (
            ("id", None), ("id", True), ("id", 1.5),
            ("id", 2**53), ("id", "bad/id"),
            ("jsonrpc", "1.0"), ("method", "tools/list"),
        ):
            changed = copy.deepcopy(base)
            changed[field] = value
            changes.append(changed)
        changed = copy.deepcopy(base)
        del changed["id"]
        changes.append(changed)
        changed = copy.deepcopy(base)
        del changed["params"]["_meta"]
        changes.append(changed)
        changed = copy.deepcopy(base)
        del changed["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2025-11-25"
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = []
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] = []
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] = {}
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["_meta"]["scope"] = "caller-claim"
        changes.append(changed)
        changed = copy.deepcopy(base)
        changed["params"]["binding"] = _binding().to_dict()
        changes.append(changed)
        for changed in changes:
            with self.subTest(message=changed), self.assertRaises(
                MCPExternalApiReadMappingError,
            ):
                project_mcp_jsonrpc_read_request(
                    sources, closure, preview, changed,
                    binding=_binding(), budget=_budget(),
                    request_id="request.mcp-read-001", issued_at="2026-10-15T12:00:00Z",
                )

    def test_jsonrpc_tool_list_replays_only_the_four_read_profiles(self) -> None:
        sources, closure, preview = _chain(tuple(TOOLS))
        message = {
            "jsonrpc": "2.0", "id": 21, "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": sources[0]["protocol_revision"],
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "test-client", "version": "1.0",
                },
            }},
        }
        envelope = project_mcp_jsonrpc_read_tool_list(
            sources, closure, preview, message, binding=_binding(),
        )
        self.assertEqual(set(envelope), {"jsonrpc", "id", "result"})
        self.assertEqual(envelope["id"], 21)
        self.assertEqual(envelope["result"], preview["list_result_preview"])
        self.assertEqual(envelope["result"]["resultType"], "complete")
        self.assertEqual(
            {tool["name"] for tool in envelope["result"]["tools"]}, set(TOOLS),
        )
        self.assertNotIn("principal.operator", json.dumps(envelope))
        self.assertNotIn("test-client", json.dumps(envelope))
        preview["list_result_preview"]["tools"][0]["name"] = "changed"
        self.assertEqual(
            {tool["name"] for tool in envelope["result"]["tools"]}, set(TOOLS),
        )

    def test_jsonrpc_tool_list_rejects_cursor_authority_and_substitution(self) -> None:
        sources, closure, preview = _chain(tuple(TOOLS))
        message = {
            "jsonrpc": "2.0", "id": "list.21", "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": sources[0]["protocol_revision"],
                "io.modelcontextprotocol/clientCapabilities": {},
            }},
        }
        for changed in (
            {**message, "method": "tools/call"},
            {**message, "id": None},
            {**message, "params": {**message["params"], "cursor": "next"}},
            {**message, "params": {**message["params"], "binding": _binding().to_dict()}},
            {**message, "params": {}},
        ):
            with self.subTest(message=changed), self.assertRaises(
                MCPExternalApiReadMappingError,
            ):
                project_mcp_jsonrpc_read_tool_list(
                    sources, closure, preview, changed, binding=_binding(),
                )
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_mcp_jsonrpc_read_tool_list(
                sources, closure, preview, message, binding=_binding("tenantref:other"),
            )
        changed_preview = copy.deepcopy(preview)
        changed_preview["list_result_preview"]["tools"][0]["name"] = "changed"
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_mcp_jsonrpc_read_tool_list(
                sources, closure, changed_preview, message, binding=_binding(),
            )

    def test_declared_schema_matches_api_identifier_and_result_limits(self) -> None:
        name = "sunderkey.list_findings"
        argument_validator = Draft202012Validator(expected_mcp_read_input_schema(name))
        valid = {"resource_id": "assessment.001", "page_size": 10}
        self.assertTrue(argument_validator.is_valid(valid))
        for changed in (
            {**valid, "resource_id": ""},
            {**valid, "resource_id": "a" * 257},
            {**valid, "resource_id": "assessment?001"},
            {**valid, "resource_id": "assessment.001\n"},
            {**valid, "cursor": "cursor:short"},
            {**valid, "cursor": "cursor:" + "A" * 513},
            {**valid, "cursor": "cursor:" + "A" * 16 + "\n"},
            {**valid, "page_size": 1_001},
        ):
            with self.subTest(arguments=changed):
                self.assertFalse(argument_validator.is_valid(changed))
                with self.assertRaises(MCPExternalApiReadMappingError):
                    self.request(name, changed)

        sources, closure, preview = self.chains[name]
        request = self.request(name)
        result = project_api_read_response_to_mcp_result(
            sources, closure, preview, name, request, _response(request),
        )
        output_validator = Draft202012Validator(expected_mcp_read_output_schema())
        base = result["structuredContent"]
        self.assertTrue(output_validator.is_valid(base))
        changed = copy.deepcopy(base)
        changed["resources"][0]["reference"] = "reportref:wrong-kind"
        self.assertFalse(output_validator.is_valid(changed))
        changed = copy.deepcopy(base)
        changed["resources"][0]["reference"] += "\n"
        self.assertFalse(output_validator.is_valid(changed))
        changed = copy.deepcopy(base)
        changed["resources"][0]["content_sha256"] = "sha256:bad"
        self.assertFalse(output_validator.is_valid(changed))
        changed = copy.deepcopy(base)
        changed["resources"][0]["resource_version"] = 0
        self.assertFalse(output_validator.is_valid(changed))
        changed = copy.deepcopy(base)
        changed["page"]["returned_count"] = 1_001
        self.assertFalse(output_validator.is_valid(changed))
        rejected = project_api_read_response_to_mcp_result(
            sources, closure, preview, name, request, _response(request, rejected=True),
        )["structuredContent"]
        rejected["error"]["code"] = "unlisted_error"
        self.assertFalse(output_validator.is_valid(rejected))

    def test_empty_list_page_and_sanitized_rejection(self) -> None:
        name = "sunderkey.list_findings"
        sources, closure, preview = self.chains[name]
        request = self.request(name, {
            "resource_id": "assessment.001", "page_size": 10,
            "cursor": "cursor:ABCDEFGHIJKLMNOP",
        })
        self.assertEqual(request.page.cursor, "cursor:ABCDEFGHIJKLMNOP")
        empty = project_api_read_response_to_mcp_result(
            sources, closure, preview, name, request, _response(request, empty=True),
        )
        self.assertEqual(empty["structuredContent"]["resources"], [])
        self.assertEqual(empty["structuredContent"]["page"]["returned_count"], 0)
        Draft202012Validator(expected_mcp_read_output_schema()).validate(
            empty["structuredContent"],
        )
        rejected = project_api_read_response_to_mcp_result(
            sources, closure, preview, name, request, _response(request, rejected=True),
        )
        self.assertTrue(rejected["isError"])
        self.assertEqual(rejected["resultType"], "complete")
        self.assertEqual(rejected["structuredContent"]["error"], {
            "code": "not_found", "retryable": False,
        })
        Draft202012Validator(expected_mcp_read_output_schema()).validate(
            rejected["structuredContent"],
        )
        self.assertNotIn("Private message", json.dumps(rejected))
        self.assertNotIn("error.detail", json.dumps(rejected))

    def test_closed_tools_call_params_leave_authority_with_host(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        params = {"name": name, "arguments": {"resource_id": "assessment.001"}}
        request = project_mcp_tools_call_to_api_request(
            sources, closure, preview, params,
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001",
            issued_at="2026-10-15T12:00:00Z",
        )
        self.assertEqual(request, self.request(name))
        for changed in (
            {**params, "binding": _binding().to_dict()},
            {**params, "_meta": {"auth": "caller-claim"}},
            {"name": name},
            {**params, "name": 1},
            {**params, "arguments": {**params["arguments"], "token": "caller-claim"}},
        ):
            with self.subTest(params=changed), self.assertRaises(
                MCPExternalApiReadMappingError,
            ):
                project_mcp_tools_call_to_api_request(
                    sources, closure, preview, changed,
                    binding=_binding(), budget=_budget(),
                    request_id="request.mcp-read-001",
                    issued_at="2026-10-15T12:00:00Z",
                )

    def test_supplied_exchange_replays_against_exact_call_arguments(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        params = {"name": name, "arguments": {"resource_id": "assessment.001"}}
        response = _response(self.request(name))
        result = project_mcp_tools_call_exchange(
            sources, closure, preview, params, response,
            binding=_binding(), budget=_budget(),
            request_id="request.mcp-read-001",
            issued_at="2026-10-15T12:00:00Z",
        )
        self.assertFalse(result["isError"])
        changed = copy.deepcopy(params)
        changed["arguments"]["resource_id"] = "assessment.002"
        with self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "response does not match",
        ):
            project_mcp_tools_call_exchange(
                sources, closure, preview, changed, response,
                binding=_binding(), budget=_budget(),
                request_id="request.mcp-read-001",
                issued_at="2026-10-15T12:00:00Z",
            )

    def test_complete_result_limit_counts_text_and_structured_copy(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        request = self.request(name)
        response = _response(request)
        result = project_api_read_response_to_mcp_result(
            sources, closure, preview, name, request, response,
        )
        structured_size = len(canonical_json_bytes(
            result["structuredContent"], max_bytes=1_000_000,
        ))
        complete_size = len(canonical_json_bytes(result, max_bytes=1_000_000))
        self.assertGreater(complete_size, structured_size)
        with patch(
            "sunderkey.mcp_external_api_read_mapping.MAX_RESULT_BYTES",
            (structured_size + complete_size) // 2,
        ), self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "complete result exceeds",
        ):
            project_api_read_response_to_mcp_result(
                sources, closure, preview, name, request, response,
            )

    def test_arguments_and_host_context_fail_closed(self) -> None:
        name = "sunderkey.list_findings"
        sources, closure, preview = self.chains[name]
        base = {"resource_id": "assessment.001", "page_size": 10}
        for changed in (
            {**base, "page_size": True},
            {**base, "cursor": None},
            {**base, "operation": "emergency_stop"},
            {"resource_id": "assessment.001"},
            {**base, "page_size": 51},
            {**base, "page_size": 1001},
        ):
            with self.subTest(arguments=changed), self.assertRaises(
                MCPExternalApiReadMappingError,
            ):
                self.request(name, changed)
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_mcp_read_arguments_to_api_request(
                sources, closure, preview, name, base,
                binding=_binding("tenant.other"), budget=_budget(),
                request_id="request.mcp-read-001",
                issued_at="2026-10-15T12:00:00Z",
            )
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_mcp_read_arguments_to_api_request(
                sources, closure, preview, "sunderkey.emergency_stop", base,
                binding=_binding(), budget=_budget(),
                request_id="request.mcp-read-001",
                issued_at="2026-10-15T12:00:00Z",
            )

    def test_source_tamper_and_wrong_api_exchange_fail_closed(self) -> None:
        name = "sunderkey.get_status"
        sources, closure, preview = self.chains[name]
        changed = copy.deepcopy(preview)
        changed["list_result_preview"]["tools"][0]["inputSchema"]["required"] = []
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_mcp_read_arguments_to_api_request(
                sources, closure, changed, name, {"resource_id": "assessment.001"},
                binding=_binding(), budget=_budget(),
                request_id="request.mcp-read-001",
                issued_at="2026-10-15T12:00:00Z",
            )
        request = self.request(name)
        wrong = self.request("sunderkey.get_report")
        with self.assertRaises(MCPExternalApiReadMappingError):
            project_api_read_response_to_mcp_result(
                sources, closure, preview, name, request, _response(wrong),
            )
        mutated_response = _response(request)
        object.__setattr__(
            mutated_response,
            "resources",
            (ResourceReference("status", "statusref:substituted", DIGEST, 1),),
        )
        with self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "response does not match",
        ):
            project_api_read_response_to_mcp_result(
                sources, closure, preview, name, request, mutated_response,
            )
        mutated_request = self.request(name)
        object.__setattr__(mutated_request, "binding", "substituted")
        with self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "response does not match",
        ):
            project_api_read_response_to_mcp_result(
                sources, closure, preview, name, mutated_request, _response(request),
            )

    def test_valid_generic_read_declaration_is_not_the_mapping_profile(self) -> None:
        sources = generic_sources()
        closure = build_mcp_read_tool_closure(*sources)
        preview = build_mcp_read_tool_list_preview(*sources, closure)
        with self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "input schema is not",
        ):
            project_mcp_read_arguments_to_api_request(
                sources, closure, preview, "sunderkey.get_status",
                {"resource_id": "assessment.001"},
                binding=_binding(), budget=_budget(),
                request_id="request.mcp-read-001",
                issued_at="2026-10-15T12:00:00Z",
            )
        message = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": sources[0]["protocol_revision"],
                "io.modelcontextprotocol/clientCapabilities": {},
            }},
        }
        with self.assertRaisesRegex(
            MCPExternalApiReadMappingError, "input schema is not",
        ):
            project_mcp_jsonrpc_read_tool_list(
                sources, closure, preview, message,
                binding=_binding(sources[0]["tenant_ref"]),
            )


if __name__ == "__main__":
    unittest.main()
