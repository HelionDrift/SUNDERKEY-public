"""Compose offline MCP read-tool declarations into one source-replayed review."""

from __future__ import annotations

import hashlib
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes
from .mcp_api_read_bindings import MCPApiReadBindingError, verify_mcp_api_read_bindings
from .mcp_header_annotation_preflight import (
    MCPHeaderAnnotationPreflightError,
    verify_mcp_header_annotation_preflight,
)
from .mcp_local_reference_closure import (
    MCPLocalReferenceClosureError,
    verify_mcp_local_reference_closure,
)
from .mcp_schema_byte_preflight import (
    MCPSchemaBytePreflightError,
    verify_mcp_schema_byte_preflight,
)
from .mcp_schema_semantic_preflight import (
    MCPSchemaSemanticPreflightError,
    verify_mcp_schema_semantic_preflight,
)

DOMAIN = b"sunderkey.mcp-read-tool-closure.v1"
MAX_RESULT_BYTES = 1_000_000
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


class MCPReadToolClosureError(ValueError):
    """The supplied source chain does not support a read-only review packet."""


def build_mcp_read_tool_closure(
    manifest: Any,
    catalog_preflight: Any,
    binding_request: Any,
    binding_plan: Any,
    schema_bundle: Any,
    byte_preflight: Any,
    semantic_preflight: Any,
    reference_closure: Any,
    header_preflight: Any,
) -> dict[str, Any]:
    """Replay every source and join the read bindings to their schema checks."""

    try:
        binding = verify_mcp_api_read_bindings(
            manifest, catalog_preflight, binding_request, binding_plan
        )
        byte = verify_mcp_schema_byte_preflight(
            manifest, catalog_preflight, schema_bundle, byte_preflight
        )
        semantic = verify_mcp_schema_semantic_preflight(
            manifest, catalog_preflight, schema_bundle, byte_preflight,
            semantic_preflight,
        )
        reference = verify_mcp_local_reference_closure(
            manifest, catalog_preflight, schema_bundle, byte_preflight,
            semantic_preflight, reference_closure,
        )
        header = verify_mcp_header_annotation_preflight(
            manifest, catalog_preflight, schema_bundle, byte_preflight,
            semantic_preflight, header_preflight,
        )
    except (
        MCPApiReadBindingError,
        MCPSchemaBytePreflightError,
        MCPSchemaSemanticPreflightError,
        MCPLocalReferenceClosureError,
        MCPHeaderAnnotationPreflightError,
    ) as exc:
        raise MCPReadToolClosureError("MCP read-tool source chain does not reproduce") from exc

    tools = []
    for declared, bound, checked, references, headers in zip(
        manifest["tools"], binding_plan["bindings"], byte_preflight["tools"],
        reference_closure["tools"], header_preflight["tools"], strict=True,
    ):
        name = declared["name"]
        if not all(
            value == name for value in (
                bound["tool_name"], checked["tool_name"],
                references["tool_name"], headers["tool_name"],
            )
        ):
            raise MCPReadToolClosureError("tool order differs across source checks")
        tools.append({
            "tool_name": name,
            "api_operation": bound["api_operation"],
            "input_schema_sha256": checked["input_schema_sha256"],
            "output_schema_sha256": checked["output_schema_sha256"],
            "input_local_reference_count": references["schemas"][0][
                "local_reference_count"
            ],
            "output_local_reference_count": references["schemas"][1][
                "local_reference_count"
            ],
            "input_header_count": headers["header_count"],
        })

    body = {
        "schema_version": 1,
        "protocol_revision": manifest["protocol_revision"],
        "manifest_sha256": catalog_preflight["manifest_sha256"],
        "binding_plan_sha256": binding["plan_sha256"],
        "schema_byte_preflight_sha256": byte["schema_preflight_sha256"],
        "semantic_preflight_sha256": semantic["semantic_preflight_sha256"],
        "reference_closure_sha256": reference["closure_sha256"],
        "header_preflight_sha256": header["header_preflight_sha256"],
        "tool_count": len(tools),
        "tools": tools,
        "review_status": "read_declarations_source_replayed_only",
        "api_argument_mapping_verified": False,
        "api_response_mapping_verified": False,
        "principal_authenticated": False,
        "tenant_scope_enforced": False,
        "live_server_schema_verified": False,
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    try:
        encoded = canonical_json_bytes(body, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPReadToolClosureError("read-tool closure exceeds its byte limit") from exc
    digest = "sha256:" + hashlib.sha256(DOMAIN + b"\0" + encoded).hexdigest()
    return {
        **body,
        "closure_id": "MRC-" + digest[7:39].upper(),
        "closure_sha256": digest,
    }


def verify_mcp_read_tool_closure(
    manifest: Any,
    catalog_preflight: Any,
    binding_request: Any,
    binding_plan: Any,
    schema_bundle: Any,
    byte_preflight: Any,
    semantic_preflight: Any,
    reference_closure: Any,
    header_preflight: Any,
    result: Any,
) -> dict[str, Any]:
    """Rebuild the review packet from the exact nine caller-supplied sources."""

    expected = build_mcp_read_tool_closure(
        manifest, catalog_preflight, binding_request, binding_plan,
        schema_bundle, byte_preflight, semantic_preflight, reference_closure,
        header_preflight,
    )
    try:
        supplied = canonical_json_bytes(result, max_bytes=MAX_RESULT_BYTES)
        reproduced = canonical_json_bytes(expected, max_bytes=MAX_RESULT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPReadToolClosureError("read-tool closure is not bounded JSON") from exc
    if supplied != reproduced:
        raise MCPReadToolClosureError("read-tool closure does not reproduce")
    return {
        "status": "valid",
        "closure_id": expected["closure_id"],
        "closure_sha256": expected["closure_sha256"],
        "qualification_effect": "none",
    }
