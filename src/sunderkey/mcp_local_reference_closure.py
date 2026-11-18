"""Check local JSON Pointer targets in caller-supplied MCP tool schemas."""

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

DOMAIN = "sunderkey.mcp-local-reference-closure.v1"
SCHEMA_ARRAY_KEYWORDS = ("prefixItems", "allOf", "anyOf", "oneOf")
SCHEMA_MAP_KEYWORDS = (
    "$defs", "properties", "patternProperties", "dependentSchemas", "definitions"
)
SCHEMA_SINGLE_KEYWORDS = (
    "additionalProperties", "unevaluatedProperties", "propertyNames", "items",
    "contains", "unevaluatedItems", "not", "if", "then", "else", "contentSchema",
)
NO_EFFECTS = {
    "authorization": "none",
    "catalog_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPLocalReferenceClosureError(ValueError):
    """A source or a bounded local reference closure is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise MCPLocalReferenceClosureError("closure is not JSON data") from exc


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _pointer_target(root: Any, reference: str) -> tuple[Any, str]:
    if reference == "#":
        return root, "#"
    if not reference.startswith("#/") or "%" in reference:
        raise MCPLocalReferenceClosureError("nonlocal or encoded reference is unsupported")
    current = root
    normalized = "#"
    for token in reference[2:].split("/"):
        if re.search(r"~(?![01])", token) is not None:
            raise MCPLocalReferenceClosureError("reference pointer escape is invalid")
        key = token.replace("~1", "/").replace("~0", "~")
        normalized += "/" + _escape_pointer_token(key)
        if isinstance(current, dict):
            if key not in current:
                raise MCPLocalReferenceClosureError("reference target is absent")
            current = current[key]
        elif isinstance(current, list):
            if re.fullmatch(r"0|[1-9][0-9]*", key) is None:
                raise MCPLocalReferenceClosureError("reference array index is invalid")
            if len(key) > 5:
                raise MCPLocalReferenceClosureError("reference array target is absent")
            index = int(key)
            if index >= len(current):
                raise MCPLocalReferenceClosureError("reference array target is absent")
            current = current[index]
        else:
            raise MCPLocalReferenceClosureError("reference traverses a scalar")
    if type(current) is not dict and type(current) is not bool:
        raise MCPLocalReferenceClosureError("reference target is not a schema")
    return current, normalized


def _local_reference_count(schema: Any) -> int:
    references: list[str] = []
    schema_paths: set[str] = set()
    pending: list[tuple[Any, bool, str]] = [(schema, True, "#")]
    while pending:
        node, root, path = pending.pop()
        schema_paths.add(path)
        if type(node) is bool:
            continue
        if type(node) is not dict:
            raise MCPLocalReferenceClosureError("schema node is invalid")
        if any(
            key in node for key in (
                "$dynamicRef", "$dynamicAnchor", "$anchor",
                "$recursiveRef", "$recursiveAnchor",
            )
        ):
            raise MCPLocalReferenceClosureError("dynamic or named anchors are unsupported")
        if not root and "$id" in node:
            raise MCPLocalReferenceClosureError("nested base URI is unsupported")
        if "$ref" in node:
            reference = node["$ref"]
            if type(reference) is not str:
                raise MCPLocalReferenceClosureError("reference is not text")
            references.append(reference)
        for key in SCHEMA_SINGLE_KEYWORDS:
            if key in node:
                pending.append((node[key], False, path + "/" + key))
        for key in SCHEMA_ARRAY_KEYWORDS:
            children = node.get(key)
            if isinstance(children, list):
                pending.extend(
                    (child, False, path + "/" + key + "/" + str(index))
                    for index, child in enumerate(children)
                )
        for key in SCHEMA_MAP_KEYWORDS:
            children = node.get(key)
            if isinstance(children, dict):
                pending.extend(
                    (child, False, path + "/" + key + "/" + _escape_pointer_token(name))
                    for name, child in children.items()
                )
        dependencies = node.get("dependencies")
        if isinstance(dependencies, dict):
            pending.extend(
                (
                    child, False,
                    path + "/dependencies/" + _escape_pointer_token(name),
                )
                for name, child in dependencies.items()
                if type(child) is dict or type(child) is bool
            )
    for reference in references:
        _, target_path = _pointer_target(schema, reference)
        if target_path not in schema_paths:
            raise MCPLocalReferenceClosureError(
                "reference target is not a recognized schema location"
            )
    return len(references)


def build_mcp_local_reference_closure(
    manifest: Any,
    preflight: Any,
    bundle: Any,
    byte_result: Any,
    semantic_result: Any,
) -> dict[str, Any]:
    """Replay exact schema sources and check only local JSON Pointer targets."""

    try:
        verified = verify_mcp_schema_semantic_preflight(
            manifest, preflight, bundle, byte_result, semantic_result
        )
    except MCPSchemaSemanticPreflightError as exc:
        raise MCPLocalReferenceClosureError("semantic source does not reproduce") from exc
    tools = []
    for entry, semantic_tool in zip(
        bundle["tools"], semantic_result["tools"], strict=True
    ):
        schemas = []
        for field in ("input_schema", "output_schema"):
            schema = json.loads(base64.b64decode(entry[field + "_base64"]).decode("utf-8"))
            count = _local_reference_count(schema)
            semantic_schema = semantic_tool[field]
            if (
                count != semantic_schema["reference_count"]
                or semantic_schema["external_reference_count"] != 0
            ):
                raise MCPLocalReferenceClosureError(
                    "local reference count differs from semantic source"
                )
            schemas.append({
                "schema_kind": field,
                "local_reference_count": count,
                "status": "local_pointer_targets_checked",
            })
        tools.append({"tool_name": entry["tool_name"], "schemas": schemas})
    body = {
        "schema_version": 1,
        "protocol_revision": manifest["protocol_revision"],
        "manifest_sha256": preflight["manifest_sha256"],
        "semantic_preflight_sha256": verified["semantic_preflight_sha256"],
        "tool_count": len(tools),
        "tools": tools,
        "closure_status": "local_json_pointer_targets_checked_only",
        "external_references_resolved": False,
        "full_json_schema_evaluation": False,
        "live_server_schema_verified": False,
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    digest = "sha256:" + hashlib.sha256(
        DOMAIN.encode() + b"\0" + _canonical(body)
    ).hexdigest()
    return {
        **body,
        "closure_id": "MLR-" + digest[7:39].upper(),
        "closure_sha256": digest,
    }


def verify_mcp_local_reference_closure(
    manifest: Any,
    preflight: Any,
    bundle: Any,
    byte_result: Any,
    semantic_result: Any,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reproduce the complete non-authorizing local-pointer report."""

    expected = build_mcp_local_reference_closure(
        manifest, preflight, bundle, byte_result, semantic_result
    )
    if not isinstance(result, Mapping) or _canonical(result) != _canonical(expected):
        raise MCPLocalReferenceClosureError("local reference closure does not reproduce")
    return {
        "status": "valid",
        "closure_id": expected["closure_id"],
        "closure_sha256": expected["closure_sha256"],
        "qualification_effect": "none",
    }
