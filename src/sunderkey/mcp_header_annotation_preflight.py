"""Check static MCP x-mcp-header declarations without constructing requests."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .mcp_schema_semantic_preflight import (
    MCPSchemaSemanticPreflightError,
    verify_mcp_schema_semantic_preflight,
)

DOMAIN = "sunderkey.mcp-header-annotation-preflight.v1"
TOKEN_RE = re.compile(r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+\Z")
SAFE_INTEGER = 2**53 - 1
LITERAL_KEYWORDS = frozenset({"const", "default", "enum", "example", "examples"})
PRIMITIVE_TYPES = frozenset({"boolean", "integer", "string"})
NO_EFFECTS = {
    "authorization": "none",
    "header_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPHeaderAnnotationPreflightError(ValueError):
    """A static MCP header annotation or replay binding is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise MCPHeaderAnnotationPreflightError("header result is not JSON data") from exc


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _has_static_integer_range(schema: Mapping[str, Any]) -> bool:
    def bound(name: str, threshold: int, *, lower: bool) -> bool:
        value = schema.get(name)
        if type(value) not in (int, float):
            return False
        return value >= threshold if lower else value <= threshold

    lower = bound("minimum", -SAFE_INTEGER, lower=True) or bound(
        "exclusiveMinimum", -SAFE_INTEGER, lower=True
    )
    upper = bound("maximum", SAFE_INTEGER, lower=False) or bound(
        "exclusiveMaximum", SAFE_INTEGER, lower=False
    )
    return lower and upper


def _annotations(schema: Any, *, input_schema: bool) -> list[dict[str, Any]]:
    seen: set[str] = set()
    found = []
    pending: list[tuple[Any, tuple[str, ...], bool]] = [
        (schema, (), input_schema)
    ]
    while pending:
        value, path, reachable = pending.pop()
        if isinstance(value, list):
            pending.extend((item, (), False) for item in value)
            continue
        if not isinstance(value, dict):
            continue
        if "x-mcp-header" in value:
            name = value["x-mcp-header"]
            primitive = value.get("type")
            if (
                not reachable or not path
                or not isinstance(name, str)
                or TOKEN_RE.fullmatch(name) is None
                or not isinstance(primitive, str)
                or primitive not in PRIMITIVE_TYPES
            ):
                raise MCPHeaderAnnotationPreflightError(
                    "header annotation is invalid or not statically reachable"
                )
            lowered = name.lower()
            if lowered in seen:
                raise MCPHeaderAnnotationPreflightError(
                    "header names must be unique without case distinctions"
                )
            seen.add(lowered)
            found.append({
                "header_name": "Mcp-Param-" + name,
                "property_path": list(path),
                "primitive_type": primitive,
                "runtime_integer_range_check_required": (
                    primitive == "integer" and not _has_static_integer_range(value)
                ),
            })
        for key, child in value.items():
            if key in LITERAL_KEYWORDS or key == "x-mcp-header":
                continue
            if key == "properties" and isinstance(child, dict):
                pending.extend(
                    (item, path + (name,), reachable)
                    for name, item in child.items()
                )
            elif isinstance(child, (dict, list)):
                pending.append((child, (), False))
    return sorted(found, key=lambda item: (item["property_path"], item["header_name"]))


def build_mcp_header_annotation_preflight(
    manifest: Any, preflight: Any, bundle: Any, byte_result: Any,
    semantic_result: Any,
) -> dict[str, Any]:
    """Check exact semantic sources and static HTTP header annotations."""

    try:
        verified = verify_mcp_schema_semantic_preflight(
            manifest, preflight, bundle, byte_result, semantic_result
        )
    except MCPSchemaSemanticPreflightError as exc:
        raise MCPHeaderAnnotationPreflightError(
            "schema semantic preflight does not reproduce"
        ) from exc
    tools = []
    for entry in bundle["tools"]:
        input_schema = json.loads(
            base64.b64decode(entry["input_schema_base64"]).decode("utf-8")
        )
        output_schema = json.loads(
            base64.b64decode(entry["output_schema_base64"]).decode("utf-8")
        )
        _annotations(output_schema, input_schema=False)
        annotations = _annotations(input_schema, input_schema=True)
        tools.append({
            "tool_name": entry["tool_name"],
            "header_count": len(annotations),
            "headers": annotations,
            "runtime_integer_range_check_required_count": sum(
                item["runtime_integer_range_check_required"] for item in annotations
            ),
        })
    body = {
        "schema_version": 1,
        "protocol_revision": manifest["protocol_revision"],
        "manifest_sha256": preflight["manifest_sha256"],
        "semantic_preflight_sha256": verified["semantic_preflight_sha256"],
        "tool_count": len(tools),
        "tools": tools,
        "header_schema_status": "static_annotations_valid_runtime_values_unchecked",
        "streamable_http_client_validation_performed": False,
        "server_header_body_parity_verified": False,
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "header_preflight_sha256": _sha256({"domain": DOMAIN, "body": body}),
    }


def verify_mcp_header_annotation_preflight(
    manifest: Any, preflight: Any, bundle: Any, byte_result: Any,
    semantic_result: Any, result: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_mcp_header_annotation_preflight(
        manifest, preflight, bundle, byte_result, semantic_result
    )
    if not isinstance(result, Mapping) or _canonical(result) != _canonical(expected):
        raise MCPHeaderAnnotationPreflightError("header preflight does not reproduce")
    return {
        "status": "valid",
        "header_preflight_sha256": expected["header_preflight_sha256"],
        "header_schema_status": expected["header_schema_status"],
        "qualification_effect": "none",
    }


__all__ = [
    "MCPHeaderAnnotationPreflightError",
    "build_mcp_header_annotation_preflight",
    "verify_mcp_header_annotation_preflight",
]
