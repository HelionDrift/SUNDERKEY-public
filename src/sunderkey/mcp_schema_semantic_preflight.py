"""Check bounded MCP tool schemas against the pinned JSON Schema dialect.

This is a local metaschema check, not server, client, or tool validation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .mcp_schema_byte_preflight import (
    MCPSchemaBytePreflightError,
    verify_mcp_schema_byte_preflight,
)

DOMAIN = "sunderkey.mcp-schema-semantic-preflight.v1"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
MAX_SCHEMA_DEPTH = 64
MAX_SCHEMA_NODES = 10_000
NO_EFFECTS = {
    "authorization": "none",
    "catalog_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}

_SINGLE_SCHEMA_KEYWORDS = (
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "items",
    "contains",
    "unevaluatedItems",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
)
_SCHEMA_ARRAY_KEYWORDS = ("prefixItems", "allOf", "anyOf", "oneOf")
_SCHEMA_MAP_KEYWORDS = (
    "$defs",
    "properties",
    "patternProperties",
    "dependentSchemas",
    "definitions",
)


class MCPSchemaSemanticPreflightError(ValueError):
    """The bounded schema or its exact reproduction is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise MCPSchemaSemanticPreflightError(
            "semantic result is not JSON data"
        ) from exc


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _check_json_structure(schema: Any) -> None:
    """Bound every JSON value, including literal and extension metadata."""

    count = 0
    pending: list[tuple[Any, int]] = [(schema, 0)]
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_SCHEMA_NODES or depth > MAX_SCHEMA_DEPTH:
            raise MCPSchemaSemanticPreflightError(
                "schema structure exceeds local bounds"
            )
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def _schema_reference_counts(schema: Any) -> tuple[int, int]:
    """Inspect known subschemas without interpreting data or resolving refs.

    The pinned metaschema also permits deprecated definitions and dependencies.
    A dependencies entry can be a schema or an array of property-name strings.
    Unknown extension values have no schema semantics in this local check.
    """

    references = 0
    external_references = 0
    pending = [schema]
    while pending:
        value = pending.pop()
        if not isinstance(value, dict):
            continue
        if "$schema" in value and value["$schema"] != DIALECT:
            raise MCPSchemaSemanticPreflightError("schema dialect is unsupported")
        for key in ("$ref", "$dynamicRef"):
            if key in value:
                references += 1
                if isinstance(value[key], str) and not value[key].startswith("#"):
                    external_references += 1
        for key in _SINGLE_SCHEMA_KEYWORDS:
            if key in value:
                pending.append(value[key])
        for key in _SCHEMA_ARRAY_KEYWORDS:
            children = value.get(key)
            if isinstance(children, list):
                pending.extend(children)
        for key in _SCHEMA_MAP_KEYWORDS:
            children = value.get(key)
            if isinstance(children, dict):
                pending.extend(children.values())
        dependencies = value.get("dependencies")
        if isinstance(dependencies, dict):
            pending.extend(
                child
                for child in dependencies.values()
                if isinstance(child, (dict, bool))
            )
    return references, external_references


def _schema_summary(encoded: str, *, input_schema: bool) -> dict[str, Any]:
    schema = json.loads(base64.b64decode(encoded).decode("utf-8"))
    if input_schema and (
        not isinstance(schema, dict) or schema.get("type") != "object"
    ):
        raise MCPSchemaSemanticPreflightError(
            "MCP input schema requires an explicit object root"
        )
    _check_json_structure(schema)
    references, external_references = _schema_reference_counts(schema)
    try:
        Draft202012Validator.check_schema(schema)
    except (SchemaError, RecursionError) as exc:
        raise MCPSchemaSemanticPreflightError(
            "schema fails the Draft 2020-12 metaschema"
        ) from exc
    return {
        "dialect": "json_schema_2020_12",
        "metaschema_status": "valid",
        "root_type": "object" if input_schema else "unrestricted",
        "reference_count": references,
        "external_reference_count": external_references,
        "reference_resolution": "not_performed",
    }


def build_mcp_schema_semantic_preflight(
    manifest: Any,
    preflight: Any,
    bundle: Any,
    byte_result: Any,
) -> dict[str, Any]:
    """Recheck exact bytes, then check bounded Draft 2020-12 structure."""

    try:
        verified = verify_mcp_schema_byte_preflight(
            manifest, preflight, bundle, byte_result
        )
    except MCPSchemaBytePreflightError as exc:
        raise MCPSchemaSemanticPreflightError(
            "schema byte preflight does not reproduce"
        ) from exc
    tools = []
    for entry in bundle["tools"]:
        tools.append(
            {
                "tool_name": entry["tool_name"],
                "input_schema": _schema_summary(
                    entry["input_schema_base64"], input_schema=True
                ),
                "output_schema": _schema_summary(
                    entry["output_schema_base64"], input_schema=False
                ),
            }
        )
    body = {
        "schema_version": 1,
        "protocol_revision": manifest["protocol_revision"],
        "manifest_sha256": preflight["manifest_sha256"],
        "schema_byte_preflight_sha256": verified["schema_preflight_sha256"],
        "tool_count": len(tools),
        "tools": tools,
        "semantic_status": "bounded_draft_2020_12_metaschema_checked",
        "external_references_resolved": False,
        "live_server_schema_verified": False,
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "semantic_preflight_sha256": _sha256({"domain": DOMAIN, "body": body}),
    }


def verify_mcp_schema_semantic_preflight(
    manifest: Any,
    preflight: Any,
    bundle: Any,
    byte_result: Any,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_mcp_schema_semantic_preflight(
        manifest, preflight, bundle, byte_result
    )
    if not isinstance(result, Mapping) or _canonical(result) != _canonical(expected):
        raise MCPSchemaSemanticPreflightError("semantic preflight does not reproduce")
    return {
        "status": "valid",
        "semantic_preflight_sha256": expected["semantic_preflight_sha256"],
        "semantic_status": expected["semantic_status"],
        "qualification_effect": "none",
    }


__all__ = [
    "MCPSchemaSemanticPreflightError",
    "build_mcp_schema_semantic_preflight",
    "verify_mcp_schema_semantic_preflight",
]
