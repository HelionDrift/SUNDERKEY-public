"""Build an inert MCP tools/list result preview from replayed read declarations."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes
from .mcp_read_tool_closure import (
    MCPReadToolClosureError,
    verify_mcp_read_tool_closure,
)

DOMAIN = b"sunderkey.mcp-read-tool-list-preview.v1"
MAX_PREVIEW_BYTES = 2_000_000
NO_EFFECTS = {
    "api_call": "none",
    "authorization": "none",
    "catalog_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPReadToolListPreviewError(ValueError):
    """The proposed list result cannot be replayed from the exact sources."""


def build_mcp_read_tool_list_preview(
    manifest: Any,
    catalog_preflight: Any,
    binding_request: Any,
    binding_plan: Any,
    schema_bundle: Any,
    byte_preflight: Any,
    semantic_preflight: Any,
    reference_closure: Any,
    header_preflight: Any,
    read_closure: Any,
) -> dict[str, Any]:
    """Preview a complete, private, immediately stale read-only tool list."""

    try:
        checked = verify_mcp_read_tool_closure(
            manifest, catalog_preflight, binding_request, binding_plan,
            schema_bundle, byte_preflight, semantic_preflight, reference_closure,
            header_preflight, read_closure,
        )
    except MCPReadToolClosureError as exc:
        raise MCPReadToolListPreviewError("read-tool closure does not reproduce") from exc
    tools = []
    try:
        for entry, checked_tool in zip(
            schema_bundle["tools"], read_closure["tools"], strict=True
        ):
            if entry["tool_name"] != checked_tool["tool_name"]:
                raise MCPReadToolListPreviewError("schema and closure tool order differs")
            input_schema = json.loads(
                base64.b64decode(entry["input_schema_base64"], validate=True).decode("utf-8")
            )
            output_schema = json.loads(
                base64.b64decode(entry["output_schema_base64"], validate=True).decode("utf-8")
            )
            tools.append({
                "name": checked_tool["tool_name"],
                "inputSchema": input_schema,
                "outputSchema": output_schema,
            })
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise MCPReadToolListPreviewError("schema bytes cannot form a tool preview") from exc
    body = {
        "schema_version": 1,
        "protocol_revision": manifest["protocol_revision"],
        "read_closure_sha256": checked["closure_sha256"],
        "tenant_ref": manifest["tenant_ref"],
        "scope_sha256": manifest["scope_sha256"],
        "tool_count": len(tools),
        "list_result_preview": {
            "resultType": "complete",
            "tools": tools,
            "ttlMs": 0,
            "cacheScope": "private",
        },
        "preview_status": "unserved_read_tool_list_shape_only",
        "api_argument_mapping_verified": False,
        "api_response_mapping_verified": False,
        "principal_authenticated": False,
        "tenant_scope_enforced": False,
        "tool_list_served": False,
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    try:
        encoded = canonical_json_bytes(body, max_bytes=MAX_PREVIEW_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPReadToolListPreviewError("tool list preview exceeds its byte limit") from exc
    digest = "sha256:" + hashlib.sha256(DOMAIN + b"\0" + encoded).hexdigest()
    return {
        **body,
        "preview_id": "MLP-" + digest[7:39].upper(),
        "preview_sha256": digest,
    }


def verify_mcp_read_tool_list_preview(
    manifest: Any,
    catalog_preflight: Any,
    binding_request: Any,
    binding_plan: Any,
    schema_bundle: Any,
    byte_preflight: Any,
    semantic_preflight: Any,
    reference_closure: Any,
    header_preflight: Any,
    read_closure: Any,
    result: Any,
) -> dict[str, Any]:
    """Recreate the preview and reject substituted schemas or result fields."""

    expected = build_mcp_read_tool_list_preview(
        manifest, catalog_preflight, binding_request, binding_plan,
        schema_bundle, byte_preflight, semantic_preflight, reference_closure,
        header_preflight, read_closure,
    )
    try:
        supplied = canonical_json_bytes(result, max_bytes=MAX_PREVIEW_BYTES)
        reproduced = canonical_json_bytes(expected, max_bytes=MAX_PREVIEW_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPReadToolListPreviewError("tool list preview is not bounded JSON") from exc
    if supplied != reproduced:
        raise MCPReadToolListPreviewError("tool list preview does not reproduce")
    return {
        "status": "valid",
        "preview_id": expected["preview_id"],
        "preview_sha256": expected["preview_sha256"],
        "qualification_effect": "none",
    }
