"""Pure MCP read-tool projections over the external API contract.

These helpers do not authenticate a host, serve a tool, or call an API.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .api_service_contracts import (
    PAGINATED_OPERATIONS,
    ApiContractError,
    ApiOperation,
    ApiRequestEnvelope,
    ApiResponseEnvelope,
    ErrorCode,
    PageRequest,
    RequestBudget,
    ResponseStatus,
    TenantPrincipalBinding,
    verify_api_exchange,
)
from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes
from .mcp_read_tool_list_preview import (
    MCPReadToolListPreviewError,
    verify_mcp_read_tool_list_preview,
)

MAX_ARGUMENT_BYTES = 16_384
MAX_RESULT_BYTES = 1_000_000
MAX_JSONRPC_REQUEST_BYTES = 32_768
MCP_PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
MCP_CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
MCP_CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
JSONRPC_STRING_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$(?![\s\S])"
CURSOR_PATTERN = r"^cursor:[A-Za-z0-9_-]{16,512}$(?![\s\S])"
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$(?![\s\S])"
OPERATIONS = {
    "sunderkey.get_status": ApiOperation.GET_STATUS,
    "sunderkey.list_evidence": ApiOperation.LIST_EVIDENCE,
    "sunderkey.list_findings": ApiOperation.LIST_FINDINGS,
    "sunderkey.get_report": ApiOperation.GET_REPORT,
}


class MCPExternalApiReadMappingError(ValueError):
    """The offline read projection does not match its exact source contracts."""


def expected_mcp_read_input_schema(tool_name: str) -> dict[str, Any]:
    """Return the closed argument profile for one external API read operation."""

    operation = OPERATIONS.get(tool_name)
    if operation is None:
        raise MCPExternalApiReadMappingError("tool has no external API read profile")
    properties: dict[str, Any] = {
        "resource_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "pattern": IDENTIFIER_PATTERN,
        }
    }
    required = ["resource_id"]
    if operation in PAGINATED_OPERATIONS:
        properties["page_size"] = {"type": "integer", "minimum": 1, "maximum": 1000}
        properties["cursor"] = {
            "type": "string",
            "minLength": 23,
            "maxLength": 519,
            "pattern": CURSOR_PATTERN,
        }
        required.append("page_size")
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def expected_mcp_read_output_schema() -> dict[str, Any]:
    """Return the closed, principal-free API reference projection profile."""

    resources = []
    for kind, prefix in (
        ("status", "statusref"),
        ("evidence", "evidref"),
        ("finding", "findingref"),
        ("report", "reportref"),
    ):
        resources.append({
            "type": "object",
            "properties": {
                "kind": {"const": kind},
                "reference": {
                    "type": "string",
                    "pattern": (
                        rf"^{prefix}:[A-Za-z0-9][A-Za-z0-9._:/-]{{0,247}}$(?![\s\S])"
                    ),
                },
                "content_sha256": {
                    "type": "string", "pattern": SHA256_PATTERN,
                },
                "resource_version": {
                    "type": "integer", "minimum": 1, "maximum": 2_147_483_647,
                },
            },
            "required": ["kind", "reference", "content_sha256", "resource_version"],
            "additionalProperties": False,
        })
    page = {
        "type": "object",
        "properties": {
            "returned_count": {"type": "integer", "minimum": 0, "maximum": 1_000},
            "next_cursor": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "string", "minLength": 23, "maxLength": 519,
                        "pattern": CURSOR_PATTERN,
                    },
                ],
            },
        },
        "required": ["returned_count", "next_cursor"],
        "additionalProperties": False,
    }
    error = {
        "type": "object",
        "properties": {
            "code": {"enum": [code.value for code in ErrorCode]},
            "retryable": {"type": "boolean"},
        },
        "required": ["code", "retryable"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["accepted", "completed", "rejected"]},
            "resources": {
                "type": "array", "items": {"oneOf": resources}, "maxItems": 1_000,
            },
            "page": {"anyOf": [{"type": "null"}, page]},
            "error": {"anyOf": [{"type": "null"}, error]},
        },
        "required": ["status", "resources", "page", "error"],
        "additionalProperties": False,
    }


def _selected_tool(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    tool_name: str,
) -> tuple[ApiOperation, dict[str, Any], dict[str, Any]]:
    if not isinstance(sources, tuple) or len(sources) != 9:
        raise MCPExternalApiReadMappingError("exact read-tool sources are required")
    try:
        verify_mcp_read_tool_list_preview(*sources, closure, list_preview)
    except (MCPReadToolListPreviewError, KeyError, TypeError) as exc:
        raise MCPExternalApiReadMappingError("read-tool list does not reproduce") from exc
    operation = OPERATIONS.get(tool_name)
    if operation is None:
        raise MCPExternalApiReadMappingError("tool is outside the read mapping")
    matching = [
        (entry, bound)
        for entry, bound in zip(
            list_preview["list_result_preview"]["tools"],
            closure["tools"],
            strict=True,
        )
        if entry["name"] == tool_name and bound["tool_name"] == tool_name
    ]
    if len(matching) != 1 or matching[0][1]["api_operation"] != operation.value:
        raise MCPExternalApiReadMappingError("tool has no exact external API binding")
    declared = matching[0][0]
    if declared["inputSchema"] != expected_mcp_read_input_schema(tool_name):
        raise MCPExternalApiReadMappingError("input schema is not the read mapping profile")
    if declared["outputSchema"] != expected_mcp_read_output_schema():
        raise MCPExternalApiReadMappingError("output schema is not the read mapping profile")
    return operation, sources[0], declared


def project_mcp_read_arguments_to_api_request(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    tool_name: str,
    arguments: Any,
    *,
    binding: TenantPrincipalBinding,
    budget: RequestBudget,
    request_id: str,
    issued_at: str,
) -> ApiRequestEnvelope:
    """Build an untrusted API request candidate from closed MCP arguments.

    A future host must independently authenticate and authorize the binding,
    budget, request identity, and current scope before using this candidate.
    """

    operation, manifest, _ = _selected_tool(sources, closure, list_preview, tool_name)
    if not isinstance(arguments, dict):
        raise MCPExternalApiReadMappingError("arguments must be a JSON object")
    try:
        canonical_json_bytes(arguments, max_bytes=MAX_ARGUMENT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("arguments are not bounded exact JSON") from exc
    allowed = {"resource_id"}
    required = {"resource_id"}
    if operation in PAGINATED_OPERATIONS:
        allowed.update({"page_size", "cursor"})
        required.add("page_size")
    if not required.issubset(arguments) or not set(arguments).issubset(allowed):
        raise MCPExternalApiReadMappingError("arguments do not match the read profile")
    if not isinstance(arguments["resource_id"], str):
        raise MCPExternalApiReadMappingError("resource_id must be a string")
    if operation in PAGINATED_OPERATIONS:
        if type(arguments["page_size"]) is not int:
            raise MCPExternalApiReadMappingError("page_size must be an integer")
        if "cursor" in arguments and not isinstance(arguments["cursor"], str):
            raise MCPExternalApiReadMappingError("cursor must be a string")
    if not isinstance(binding, TenantPrincipalBinding) or not isinstance(budget, RequestBudget):
        raise MCPExternalApiReadMappingError("trusted-host context types are required")
    if binding.tenant_id != manifest["tenant_ref"]:
        raise MCPExternalApiReadMappingError("binding tenant differs from catalog tenant")
    try:
        return ApiRequestEnvelope(
            operation=operation,
            request_id=request_id,
            binding=binding,
            issued_at=issued_at,
            body_size_bytes=0,
            budget=budget,
            resource_id=arguments["resource_id"],
            page=(
                PageRequest(arguments["page_size"], arguments.get("cursor"))
                if operation in PAGINATED_OPERATIONS else None
            ),
        )
    except ApiContractError as exc:
        raise MCPExternalApiReadMappingError("API request candidate is invalid") from exc


def project_mcp_tools_call_to_api_request(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    params: Any,
    *,
    binding: TenantPrincipalBinding,
    budget: RequestBudget,
    request_id: str,
    issued_at: str,
) -> ApiRequestEnvelope:
    """Map the closed ``tools/call`` params shape, not client authority claims."""

    if not isinstance(params, dict) or set(params) != {"name", "arguments"}:
        raise MCPExternalApiReadMappingError("tools/call params must be exact")
    try:
        canonical_json_bytes(params, max_bytes=MAX_ARGUMENT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("tools/call params are not bounded JSON") from exc
    if not isinstance(params["name"], str):
        raise MCPExternalApiReadMappingError("tool name must be a string")
    return project_mcp_read_arguments_to_api_request(
        sources, closure, list_preview, params["name"], params["arguments"],
        binding=binding, budget=budget, request_id=request_id, issued_at=issued_at,
    )


def project_api_read_response_to_mcp_result(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    tool_name: str,
    request: ApiRequestEnvelope,
    response: ApiResponseEnvelope,
) -> dict[str, Any]:
    """Project a supplied matching API response to an unserved MCP result."""

    operation, manifest, _ = _selected_tool(sources, closure, list_preview, tool_name)
    if not isinstance(request, ApiRequestEnvelope) or not isinstance(response, ApiResponseEnvelope):
        raise MCPExternalApiReadMappingError("API exchange inputs are invalid")
    try:
        request = ApiRequestEnvelope.from_dict(request.to_dict())
        response = ApiResponseEnvelope.from_dict(response.to_dict())
    except (ApiContractError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise MCPExternalApiReadMappingError("API response does not match the request") from exc
    if request.operation is not operation:
        raise MCPExternalApiReadMappingError("API request does not match the tool")
    if request.binding.tenant_id != manifest["tenant_ref"]:
        raise MCPExternalApiReadMappingError("request tenant differs from catalog tenant")
    try:
        verify_api_exchange(request, response)
    except ApiContractError as exc:
        raise MCPExternalApiReadMappingError("API response does not match the request") from exc
    structured = {
        "status": response.status.value,
        "resources": [resource.to_dict() for resource in response.resources],
        "page": None if response.page is None else response.page.to_dict(),
        "error": (
            None if response.error is None else {
                "code": response.error.code.value,
                "retryable": response.error.retryable,
            }
        ),
    }
    try:
        encoded = canonical_json_bytes(structured, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("projected result exceeds its byte limit") from exc
    result = {
        "resultType": "complete",
        "content": [{"type": "text", "text": encoded.decode("ascii")}],
        "structuredContent": structured,
        "isError": response.status is ResponseStatus.REJECTED,
    }
    try:
        canonical_json_bytes(result, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("complete result exceeds its byte limit") from exc
    return result


def project_mcp_tools_call_exchange(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    params: Any,
    response: ApiResponseEnvelope,
    *,
    binding: TenantPrincipalBinding,
    budget: RequestBudget,
    request_id: str,
    issued_at: str,
) -> dict[str, Any]:
    """Replay a supplied response against the exact unserved call candidate."""

    request = project_mcp_tools_call_to_api_request(
        sources, closure, list_preview, params,
        binding=binding, budget=budget, request_id=request_id, issued_at=issued_at,
    )
    return project_api_read_response_to_mcp_result(
        sources, closure, list_preview, params["name"], request, response,
    )


def project_mcp_jsonrpc_read_request(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    message: Any,
    *,
    binding: TenantPrincipalBinding,
    budget: RequestBudget,
    request_id: str,
    issued_at: str,
) -> tuple[str | int, str, ApiRequestEnvelope]:
    """Validate a narrow MCP JSON-RPC read request without serving it."""

    client_id, params = _validated_jsonrpc_request(
        message, expected_method="tools/call",
        protocol_revision=sources[0]["protocol_revision"],
        required_params={"name", "arguments", "_meta"},
    )
    tool_name = params["name"]
    candidate = project_mcp_tools_call_to_api_request(
        sources, closure, list_preview,
        {"name": tool_name, "arguments": params["arguments"]},
        binding=binding, budget=budget, request_id=request_id, issued_at=issued_at,
    )
    return client_id, tool_name, candidate


def _validated_jsonrpc_request(
    message: Any,
    *,
    expected_method: str,
    protocol_revision: str,
    required_params: set[str],
) -> tuple[str | int, dict[str, Any]]:
    """Snapshot and validate the closed read-only JSON-RPC request profile."""

    if not isinstance(message, dict) or set(message) != {
        "jsonrpc", "id", "method", "params",
    }:
        raise MCPExternalApiReadMappingError("JSON-RPC request fields are invalid")
    try:
        encoded = canonical_json_bytes(message, max_bytes=MAX_JSONRPC_REQUEST_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("JSON-RPC request is not bounded JSON") from exc
    message = json.loads(encoded)
    if message["jsonrpc"] != "2.0" or message["method"] != expected_method:
        raise MCPExternalApiReadMappingError("JSON-RPC method or version is invalid")
    client_id = message["id"]
    if not (
        (type(client_id) is int and -(2**53 - 1) <= client_id <= 2**53 - 1)
        or (isinstance(client_id, str) and JSONRPC_STRING_ID_RE.fullmatch(client_id))
    ):
        raise MCPExternalApiReadMappingError("JSON-RPC request id is invalid")
    params = message["params"]
    if not isinstance(params, dict) or set(params) != required_params:
        raise MCPExternalApiReadMappingError("JSON-RPC read params are invalid")
    meta = params["_meta"]
    if not isinstance(meta, dict) or not {
        MCP_PROTOCOL_VERSION_KEY, MCP_CLIENT_CAPABILITIES_KEY,
    }.issubset(meta) or not set(meta).issubset({
        MCP_PROTOCOL_VERSION_KEY, MCP_CLIENT_CAPABILITIES_KEY, MCP_CLIENT_INFO_KEY,
    }):
        raise MCPExternalApiReadMappingError("JSON-RPC per-request metadata is invalid")
    if not isinstance(meta[MCP_CLIENT_CAPABILITIES_KEY], dict):
        raise MCPExternalApiReadMappingError("JSON-RPC client metadata is invalid")
    if MCP_CLIENT_INFO_KEY in meta:
        info = meta[MCP_CLIENT_INFO_KEY]
        if not isinstance(info, dict) or any(
            not isinstance(info.get(field), str)
            or not 1 <= len(info[field]) <= 128
            or any(ord(character) < 32 for character in info[field])
            for field in ("name", "version")
        ):
            raise MCPExternalApiReadMappingError("JSON-RPC client info is invalid")
    if meta[MCP_PROTOCOL_VERSION_KEY] != protocol_revision:
        raise MCPExternalApiReadMappingError("JSON-RPC protocol revision differs from catalog")
    return client_id, params


def project_mcp_jsonrpc_read_tool_list(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    message: Any,
    *,
    binding: TenantPrincipalBinding,
) -> dict[str, Any]:
    """Wrap the exact unserved read catalog in a bounded tools/list result."""

    if not isinstance(sources, tuple) or len(sources) != 9:
        raise MCPExternalApiReadMappingError("exact read-tool sources are required")
    client_id, _ = _validated_jsonrpc_request(
        message, expected_method="tools/list",
        protocol_revision=sources[0]["protocol_revision"],
        required_params={"_meta"},
    )
    if not isinstance(binding, TenantPrincipalBinding):
        raise MCPExternalApiReadMappingError("trusted-host binding type is required")
    if binding.tenant_id != sources[0]["tenant_ref"]:
        raise MCPExternalApiReadMappingError("binding tenant differs from catalog tenant")
    try:
        snapshot = json.loads(canonical_json_bytes(
            list_preview, max_bytes=MAX_RESULT_BYTES,
        ))
        verify_mcp_read_tool_list_preview(*sources, closure, snapshot)
    except (JsonContractIntegrityError, MCPReadToolListPreviewError, KeyError, TypeError) as exc:
        raise MCPExternalApiReadMappingError("read-tool list does not reproduce") from exc
    for tool in snapshot["list_result_preview"]["tools"]:
        name = tool["name"]
        _selected_tool(sources, closure, snapshot, name)
    envelope = {
        "jsonrpc": "2.0", "id": client_id,
        "result": snapshot["list_result_preview"],
    }
    try:
        canonical_json_bytes(envelope, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("JSON-RPC list exceeds its byte limit") from exc
    return envelope


def project_mcp_jsonrpc_read_exchange(
    sources: tuple[Any, ...],
    closure: Any,
    list_preview: Any,
    message: Any,
    response: ApiResponseEnvelope,
    *,
    binding: TenantPrincipalBinding,
    budget: RequestBudget,
    request_id: str,
    issued_at: str,
) -> dict[str, Any]:
    """Wrap an exact supplied API response in an unserved JSON-RPC result."""

    client_id, tool_name, request = project_mcp_jsonrpc_read_request(
        sources, closure, list_preview, message,
        binding=binding, budget=budget, request_id=request_id, issued_at=issued_at,
    )
    result = project_api_read_response_to_mcp_result(
        sources, closure, list_preview, tool_name, request, response,
    )
    envelope = {"jsonrpc": "2.0", "id": client_id, "result": result}
    try:
        canonical_json_bytes(envelope, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPExternalApiReadMappingError("JSON-RPC result exceeds its byte limit") from exc
    return envelope


__all__ = [
    "MCPExternalApiReadMappingError",
    "expected_mcp_read_input_schema",
    "expected_mcp_read_output_schema",
    "project_mcp_read_arguments_to_api_request",
    "project_mcp_tools_call_to_api_request",
    "project_api_read_response_to_mcp_result",
    "project_mcp_tools_call_exchange",
    "project_mcp_jsonrpc_read_request",
    "project_mcp_jsonrpc_read_exchange",
    "project_mcp_jsonrpc_read_tool_list",
]
