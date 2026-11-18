"""Effect-free preflight for a proposed governed MCP tool catalog.

The preflight checks declarations, not an MCP server or its implementation.
No tool is listed to a client or invoked by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes

SCHEMA_VERSION = 1
PROTOCOL_REVISION = "2026-07-28"
MAX_TOOLS = 64
MAX_INPUT_BYTES = 1_000_000
MAX_PREFLIGHT_BYTES = 1_000_000
DOMAIN = "sunderkey.mcp-catalog-preflight.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REF_RE = re.compile(r"(?:serverref|tenantref):[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
CONTROL_FIELDS = (
    "principal_authentication_required",
    "audience_validation_required",
    "tenant_scope_filter_required",
    "human_confirmation_required",
    "independent_action_admission_required",
    "audit_event_required",
    "token_passthrough_allowed",
    "model_self_authorization_allowed",
    "annotations_authoritative",
)
TOOL_FIELDS = set(CONTROL_FIELDS) | {
    "name", "effect_class", "input_schema_sha256", "output_schema_sha256",
    "maximum_calls_per_minute",
}
NO_EFFECTS = {
    "authorization": "none",
    "catalog_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPCatalogPreflightError(ValueError):
    """Catalog shape or reproduction is invalid."""


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MCPCatalogPreflightError(f"{label} fields do not match the contract")
    return value


def _ref(value: Any, namespace: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or REF_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise MCPCatalogPreflightError(f"{label} must be an opaque {namespace} reference")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise MCPCatalogPreflightError(f"{label} must be a SHA-256 digest")
    return value


def _sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _validate_manifest(raw: Any) -> Mapping[str, Any]:
    try:
        canonical_json_bytes(raw, max_bytes=MAX_INPUT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPCatalogPreflightError("manifest must be bounded exact JSON") from exc
    manifest = _exact(raw, {
        "schema_version", "protocol_revision", "server_ref", "tenant_ref",
        "scope_sha256", "list_is_principal_scoped", "list_cache_ttl_ms", "tools",
    }, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise MCPCatalogPreflightError("unsupported schema version")
    if manifest["protocol_revision"] != PROTOCOL_REVISION:
        raise MCPCatalogPreflightError("protocol revision is not pinned")
    _ref(manifest["server_ref"], "serverref", "server_ref")
    _ref(manifest["tenant_ref"], "tenantref", "tenant_ref")
    _digest(manifest["scope_sha256"], "scope_sha256")
    if type(manifest["list_is_principal_scoped"]) is not bool:
        raise MCPCatalogPreflightError("list_is_principal_scoped must be boolean")
    if (
        type(manifest["list_cache_ttl_ms"]) is not int
        or not 0 <= manifest["list_cache_ttl_ms"] <= 3_600_000
    ):
        raise MCPCatalogPreflightError("list_cache_ttl_ms is invalid")
    tools = manifest["tools"]
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        raise MCPCatalogPreflightError("tools must be a bounded list")
    names = []
    for index, value in enumerate(tools):
        tool = _exact(value, TOOL_FIELDS, f"tool {index}")
        name = tool["name"]
        if not isinstance(name, str) or TOOL_NAME_RE.fullmatch(name) is None:
            raise MCPCatalogPreflightError("tool name is invalid")
        names.append(name)
        if tool["effect_class"] not in ("read", "action"):
            raise MCPCatalogPreflightError("tool effect_class is invalid")
        _digest(tool["input_schema_sha256"], "input_schema_sha256")
        _digest(tool["output_schema_sha256"], "output_schema_sha256")
        for field in CONTROL_FIELDS:
            if type(tool[field]) is not bool:
                raise MCPCatalogPreflightError(f"{field} must be boolean")
        maximum = tool["maximum_calls_per_minute"]
        if type(maximum) is not int or not 0 <= maximum <= 1000:
            raise MCPCatalogPreflightError("maximum_calls_per_minute is invalid")
    if names != sorted(set(names)):
        raise MCPCatalogPreflightError("tool names must be sorted and unique")
    return manifest


def build_mcp_catalog_preflight(raw: Any) -> dict[str, Any]:
    """Report missing declared controls without treating declarations as proof."""
    manifest = _validate_manifest(raw)
    issues: list[dict[str, str]] = []

    def issue(name: str, code: str) -> None:
        issues.append({"tool_name": name, "code": code})

    if not manifest["tools"]:
        issue("", "empty_catalog")
    if not manifest["list_is_principal_scoped"]:
        issue("", "tool_list_not_principal_scoped")
    if manifest["list_cache_ttl_ms"] != 0:
        issue("", "tool_list_cache_not_disabled")
    for tool in manifest["tools"]:
        name = tool["name"]
        for field, code in (
            ("principal_authentication_required", "principal_authentication_missing"),
            ("audience_validation_required", "token_audience_validation_missing"),
            ("tenant_scope_filter_required", "tenant_scope_filter_missing"),
            ("audit_event_required", "audit_requirement_missing"),
        ):
            if not tool[field]:
                issue(name, code)
        if tool["maximum_calls_per_minute"] == 0:
            issue(name, "rate_limit_missing")
        if tool["token_passthrough_allowed"]:
            issue(name, "token_passthrough_allowed")
        if tool["model_self_authorization_allowed"]:
            issue(name, "model_self_authorization_allowed")
        if tool["annotations_authoritative"]:
            issue(name, "untrusted_annotations_used_for_authority")
        if tool["effect_class"] == "action":
            if not tool["human_confirmation_required"]:
                issue(name, "action_human_confirmation_missing")
            if not tool["independent_action_admission_required"]:
                issue(name, "independent_action_admission_missing")
    body = {
        "schema_version": SCHEMA_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "manifest_sha256": _sha(manifest),
        "server_ref": manifest["server_ref"],
        "tenant_ref": manifest["tenant_ref"],
        "scope_sha256": manifest["scope_sha256"],
        "tool_count": len(manifest["tools"]),
        "action_tool_count": sum(
            tool["effect_class"] == "action" for tool in manifest["tools"]
        ),
        "issues": issues,
        "preflight_status": (
            "declaration_gaps" if issues else "declared_controls_complete_for_review"
        ),
        "source_assurance": "caller_declared_policy_only",
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    digest = _sha({"domain": DOMAIN, "content": body})
    return {**body, "preflight_id": "MCP-" + digest[7:39].upper(), "preflight_sha256": digest}


def verify_mcp_catalog_preflight(raw: Any, preflight: Any) -> dict[str, Any]:
    """Reproduce a preflight from its exact proposed manifest."""
    expected = build_mcp_catalog_preflight(raw)
    try:
        supplied = canonical_json_bytes(preflight, max_bytes=MAX_PREFLIGHT_BYTES)
        reproduced = canonical_json_bytes(expected, max_bytes=MAX_PREFLIGHT_BYTES)
    except JsonContractIntegrityError as exc:
        raise MCPCatalogPreflightError("preflight must be bounded exact JSON") from exc
    if supplied != reproduced:
        raise MCPCatalogPreflightError("preflight does not reproduce from manifest")
    return {
        "status": "valid",
        "preflight_id": expected["preflight_id"],
        "preflight_sha256": expected["preflight_sha256"],
        "preflight_status": expected["preflight_status"],
        "qualification_effect": "none",
    }
