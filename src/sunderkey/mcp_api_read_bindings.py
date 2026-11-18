"""Reproducible, read-only MCP-to-API operation binding plan.

This is a static plan. It neither lists tools to a client nor calls an API.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .api_service_contracts import MUTATING_OPERATIONS, ApiOperation
from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes
from .mcp_catalog_preflight import (
    MCPCatalogPreflightError,
    verify_mcp_catalog_preflight,
)

SCHEMA_VERSION = 1
MAX_BINDINGS_BYTES = 1_000_000
MAX_PLAN_BYTES = 1_000_000
DOMAIN = "sunderkey.mcp-api-read-bindings.v1"
READ_BINDINGS = {
    "sunderkey.get_status": ApiOperation.GET_STATUS,
    "sunderkey.list_evidence": ApiOperation.LIST_EVIDENCE,
    "sunderkey.list_findings": ApiOperation.LIST_FINDINGS,
    "sunderkey.get_report": ApiOperation.GET_REPORT,
}
NO_EFFECTS = {
    "api_call": "none",
    "authorization": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPApiReadBindingError(ValueError):
    """Binding request or reproduction failed closed."""


def _sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MCPApiReadBindingError(f"{label} fields do not match the contract")
    return value


def _operation_catalog_sha256() -> str:
    return _sha({
        "operations": sorted(operation.value for operation in ApiOperation),
        "mutating": sorted(operation.value for operation in MUTATING_OPERATIONS),
    })


def build_mcp_api_read_bindings(
    manifest: Any,
    preflight: Any,
    request: Any,
) -> dict[str, Any]:
    """Bind a complete declared read catalog to closed API read operations."""
    try:
        verify_mcp_catalog_preflight(manifest, preflight)
    except MCPCatalogPreflightError as exc:
        raise MCPApiReadBindingError("source MCP preflight is not reproducible") from exc
    if preflight["preflight_status"] != "declared_controls_complete_for_review":
        raise MCPApiReadBindingError("MCP catalog has declared control gaps")
    tools = manifest["tools"]
    if any(tool["effect_class"] != "read" for tool in tools):
        raise MCPApiReadBindingError("action tools are not permitted in a read binding plan")
    try:
        canonical_json_bytes(request, max_bytes=MAX_BINDINGS_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPApiReadBindingError("binding request must be bounded exact JSON") from exc
    source = _exact(request, {"schema_version", "bindings"}, "request")
    if type(source["schema_version"]) is not int or source["schema_version"] != SCHEMA_VERSION:
        raise MCPApiReadBindingError("unsupported binding request version")
    values = source["bindings"]
    if not isinstance(values, list) or len(values) != len(tools):
        raise MCPApiReadBindingError("bindings must cover every declared tool exactly once")
    bindings = []
    for index, value in enumerate(values):
        entry = _exact(value, {"tool_name", "api_operation"}, f"binding {index}")
        name = entry["tool_name"]
        operation = entry["api_operation"]
        if not isinstance(name, str) or not isinstance(operation, str):
            raise MCPApiReadBindingError("binding values must be strings")
        if name != tools[index]["name"]:
            raise MCPApiReadBindingError("binding order or tool name does not match catalog")
        if name not in READ_BINDINGS or operation != READ_BINDINGS[name].value:
            raise MCPApiReadBindingError("binding is outside the approved read mapping")
        if ApiOperation(operation) in MUTATING_OPERATIONS:
            raise MCPApiReadBindingError("mutating API operation cannot be read-bound")
        bindings.append({"tool_name": name, "api_operation": operation})
    body = {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": preflight["manifest_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "request_sha256": _sha(source),
        "api_operation_catalog_sha256": _operation_catalog_sha256(),
        "server_ref": manifest["server_ref"],
        "tenant_ref": manifest["tenant_ref"],
        "scope_sha256": manifest["scope_sha256"],
        "bindings": bindings,
        "binding_status": "static_read_only_mapping_for_review",
        "source_assurance": "caller_declared_catalog_only",
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    digest = _sha({"domain": DOMAIN, "content": body})
    return {**body, "plan_id": "MRB-" + digest[7:39].upper(), "plan_sha256": digest}


def verify_mcp_api_read_bindings(
    manifest: Any,
    preflight: Any,
    request: Any,
    plan: Any,
) -> dict[str, Any]:
    """Reproduce the exact static plan from its three source artifacts."""
    expected = build_mcp_api_read_bindings(manifest, preflight, request)
    try:
        supplied = canonical_json_bytes(plan, max_bytes=MAX_PLAN_BYTES)
        reproduced = canonical_json_bytes(expected, max_bytes=MAX_PLAN_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPApiReadBindingError("binding plan must be bounded exact JSON") from exc
    if supplied != reproduced:
        raise MCPApiReadBindingError("binding plan does not reproduce from sources")
    return {
        "status": "valid",
        "plan_id": expected["plan_id"],
        "plan_sha256": expected["plan_sha256"],
        "binding_status": expected["binding_status"],
        "qualification_effect": "none",
    }
