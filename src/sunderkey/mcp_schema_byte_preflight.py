"""Bind proposed MCP tool schema digests to exact caller-supplied JSON bytes.

This module does not serve tools or validate a live MCP server.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .mcp_catalog_preflight import (
    MCPCatalogPreflightError,
    verify_mcp_catalog_preflight,
)

SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 1_000_000
MAX_RESULT_BYTES = 1_000_000
MAX_SCHEMA_BYTES = 256_000
DOMAIN = "sunderkey.mcp-schema-byte-preflight.v1"
NO_EFFECTS = {
    "authorization": "none",
    "catalog_publication": "none",
    "mcp_server": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "tool_execution": "none",
}


class MCPSchemaBytePreflightError(ValueError):
    """The schema bundle or its reproduction is invalid."""


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MCPSchemaBytePreflightError(f"{label} fields do not match the contract")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MCPSchemaBytePreflightError("schema JSON has a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise MCPSchemaBytePreflightError("schema JSON has a non-finite number")


def _schema_digest(
    encoded: Any, label: str, *, allow_boolean: bool = False,
) -> tuple[str, int]:
    maximum_encoded = 4 * ((MAX_SCHEMA_BYTES + 2) // 3)
    if not isinstance(encoded, str) or not encoded or len(encoded) > maximum_encoded:
        raise MCPSchemaBytePreflightError(f"{label} is not a bounded base64 string")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MCPSchemaBytePreflightError(f"{label} is not valid base64") from exc
    if (
        not raw or len(raw) > MAX_SCHEMA_BYTES
        or base64.b64encode(raw).decode("ascii") != encoded
    ):
        raise MCPSchemaBytePreflightError(f"{label} is not canonical bounded base64")
    try:
        schema = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
        _canonical_bytes(schema)
    except MCPSchemaBytePreflightError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise MCPSchemaBytePreflightError(f"{label} is not valid JSON") from exc
    if not isinstance(schema, dict) and not (allow_boolean and type(schema) is bool):
        raise MCPSchemaBytePreflightError(
            f"{label} must be a JSON schema object"
            + (" or boolean" if allow_boolean else "")
        )
    return _sha256(raw), len(raw)


def build_mcp_schema_byte_preflight(
    manifest: Any,
    preflight: Any,
    bundle: Any,
) -> dict[str, Any]:
    """Compare exact schema bytes with every digest in a proposed catalog."""
    try:
        verify_mcp_catalog_preflight(manifest, preflight)
    except MCPCatalogPreflightError as exc:
        raise MCPSchemaBytePreflightError("source preflight is not reproducible") from exc
    source = _exact(bundle, {"schema_version", "tools"}, "schema bundle")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise MCPSchemaBytePreflightError("unsupported schema bundle version")
    supplied = source["tools"]
    declared = manifest["tools"]
    if not isinstance(supplied, list) or not declared or len(supplied) != len(declared):
        raise MCPSchemaBytePreflightError("schema bundle must cover every tool")
    items = []
    for index, (tool, value) in enumerate(zip(declared, supplied, strict=True)):
        entry = _exact(
            value,
            {"tool_name", "input_schema_base64", "output_schema_base64"},
            f"schema entry {index}",
        )
        if entry["tool_name"] != tool["name"]:
            raise MCPSchemaBytePreflightError("schema tool order or name differs")
        input_digest, input_size = _schema_digest(
            entry["input_schema_base64"], "input schema",
        )
        output_digest, output_size = _schema_digest(
            entry["output_schema_base64"], "output schema", allow_boolean=True,
        )
        if (
            input_digest != tool["input_schema_sha256"]
            or output_digest != tool["output_schema_sha256"]
        ):
            raise MCPSchemaBytePreflightError("schema bytes do not match declared digests")
        items.append({
            "tool_name": tool["name"],
            "input_schema_sha256": input_digest,
            "input_schema_byte_count": input_size,
            "output_schema_sha256": output_digest,
            "output_schema_byte_count": output_size,
        })

    try:
        bundle_bytes = _canonical_bytes(source)
    except (TypeError, ValueError, RecursionError) as exc:
        raise MCPSchemaBytePreflightError("schema bundle is not valid JSON data") from exc
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise MCPSchemaBytePreflightError("schema bundle exceeds its size limit")

    body = {
        "schema_version": SCHEMA_VERSION,
        "protocol_revision": manifest["protocol_revision"],
        "manifest_sha256": preflight["manifest_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "catalog_control_status": preflight["preflight_status"],
        "bundle_sha256": _sha256(bundle_bytes),
        "server_ref": manifest["server_ref"],
        "tenant_ref": manifest["tenant_ref"],
        "scope_sha256": manifest["scope_sha256"],
        "tools": items,
        "schema_byte_status": "declared_digests_match_supplied_bytes",
        "source_assurance": "caller_supplied_schema_bytes_only",
        "qualification_effect": "none",
        "effects": dict(NO_EFFECTS),
    }
    digest = _sha256(_canonical_bytes({"domain": DOMAIN, "content": body}))
    return {
        **body,
        "schema_preflight_id": "MSB-" + digest[7:39].upper(),
        "schema_preflight_sha256": digest,
    }


def verify_mcp_schema_byte_preflight(
    manifest: Any,
    preflight: Any,
    bundle: Any,
    result: Any,
) -> dict[str, Any]:
    """Reproduce the exact schema-byte preflight from its sources."""
    expected = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
    try:
        actual_bytes = _canonical_bytes(result)
    except (TypeError, ValueError, RecursionError) as exc:
        raise MCPSchemaBytePreflightError("result is not valid JSON data") from exc
    if actual_bytes != _canonical_bytes(expected):
        raise MCPSchemaBytePreflightError("schema preflight does not reproduce")
    return {
        "status": "valid",
        "schema_preflight_id": expected["schema_preflight_id"],
        "schema_preflight_sha256": expected["schema_preflight_sha256"],
        "schema_byte_status": expected["schema_byte_status"],
        "qualification_effect": "none",
    }
