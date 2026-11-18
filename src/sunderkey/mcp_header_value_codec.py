"""Pure MCP parameter-header encoding and body-parity rehearsal.

No header is sent and no caller identity or tool authority is established.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from .mcp_header_annotation_preflight import SAFE_INTEGER, TOKEN_RE

MAX_VALUE_BYTES = 8_192
SENTINEL_PREFIX = "=?base64?"
SENTINEL_SUFFIX = "?="
DECIMAL_RE = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?\Z")
ANNOTATION_FIELDS = {
    "header_name", "property_path", "primitive_type",
    "runtime_integer_range_check_required",
}


class MCPHeaderValueCodecError(ValueError):
    """A proposed header value is unsafe or differs from its body value."""


def _integer(value: Any) -> int:
    if type(value) is int:
        result = value
    elif type(value) is float and math.isfinite(value) and value.is_integer():
        result = int(value)
    else:
        raise MCPHeaderValueCodecError("integer parameter has an invalid JSON type")
    if abs(result) > SAFE_INTEGER:
        raise MCPHeaderValueCodecError("integer parameter exceeds the safe range")
    return result


def _text(value: Any, primitive_type: str) -> str:
    if primitive_type == "string" and isinstance(value, str):
        return value
    if primitive_type == "boolean" and type(value) is bool:
        return "true" if value else "false"
    if primitive_type == "integer":
        return str(_integer(value))
    raise MCPHeaderValueCodecError("parameter does not match its primitive type")


def _plain_safe(value: str) -> bool:
    return (
        bool(value)
        and value[0] not in " \t"
        and value[-1] not in " \t"
        and not (value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX))
        and all(character == "\t" or 0x20 <= ord(character) <= 0x7E for character in value)
    )


def encode_mcp_parameter_header_value(value: Any, primitive_type: str) -> str:
    """Return one inert header value under the pinned MCP encoding rules."""

    text = _text(value, primitive_type)
    raw = text.encode("utf-8")
    if len(raw) > MAX_VALUE_BYTES:
        raise MCPHeaderValueCodecError("parameter value exceeds the local byte limit")
    if _plain_safe(text):
        return text
    return SENTINEL_PREFIX + base64.b64encode(raw).decode("ascii") + SENTINEL_SUFFIX


def decode_mcp_parameter_header_value(value: Any, primitive_type: str) -> Any:
    """Decode a proposed value without trusting it as a received HTTP header."""

    if not isinstance(value, str) or not value:
        raise MCPHeaderValueCodecError("header value is invalid")
    if value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX):
        encoded = value[len(SENTINEL_PREFIX):-len(SENTINEL_SUFFIX)]
        if len(encoded) > 4 * ((MAX_VALUE_BYTES + 2) // 3):
            raise MCPHeaderValueCodecError("encoded header value is too large")
        try:
            raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(raw).decode("ascii") != encoded:
                raise ValueError("noncanonical base64")
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeError, ValueError) as exc:
            raise MCPHeaderValueCodecError("encoded header value is invalid") from exc
    else:
        if not _plain_safe(value):
            raise MCPHeaderValueCodecError("plain header value is unsafe")
        raw = value.encode("ascii")
        decoded = value
    if len(raw) > MAX_VALUE_BYTES:
        raise MCPHeaderValueCodecError("header value exceeds the local byte limit")
    if primitive_type == "string":
        return decoded
    if primitive_type == "boolean":
        if decoded == "true":
            return True
        if decoded == "false":
            return False
        raise MCPHeaderValueCodecError("boolean header value is invalid")
    if primitive_type == "integer":
        if DECIMAL_RE.fullmatch(decoded) is None:
            raise MCPHeaderValueCodecError("integer header value is invalid")
        try:
            number = Decimal(decoded)
        except InvalidOperation as exc:
            raise MCPHeaderValueCodecError("integer header value is invalid") from exc
        if number != number.to_integral_value() or abs(number) > SAFE_INTEGER:
            raise MCPHeaderValueCodecError("integer header value is outside its range")
        return int(number)
    raise MCPHeaderValueCodecError("header primitive type is invalid")


def check_mcp_parameter_header_body_parity(
    *, annotation: Mapping[str, Any], arguments: Mapping[str, Any],
    header_value: str | None,
) -> dict[str, Any]:
    """Compare one asserted header with one local argument property path."""

    if (
        not isinstance(annotation, Mapping)
        or set(annotation) != ANNOTATION_FIELDS
        or not isinstance(arguments, Mapping)
        or not isinstance(annotation["header_name"], str)
        or not annotation["header_name"].startswith("Mcp-Param-")
        or TOKEN_RE.fullmatch(annotation["header_name"][len("Mcp-Param-"):]) is None
        or not isinstance(annotation["property_path"], list)
        or not annotation["property_path"]
        or any(not isinstance(item, str) for item in annotation["property_path"])
        or not isinstance(annotation["primitive_type"], str)
        or annotation["primitive_type"] not in {"string", "boolean", "integer"}
        or type(annotation["runtime_integer_range_check_required"]) is not bool
        or (
            annotation["primitive_type"] != "integer"
            and annotation["runtime_integer_range_check_required"]
        )
    ):
        raise MCPHeaderValueCodecError("header annotation is invalid")
    current: Any = arguments
    for part in annotation["property_path"]:
        if not isinstance(current, Mapping) or part not in current:
            current = None
            break
        current = current[part]
    if current is None:
        if header_value is not None:
            raise MCPHeaderValueCodecError("header must be omitted for absent or null value")
        return {
            "status": "matches",
            "body_value_present": False,
            "header_present": False,
            "network_call_performed": False,
            "positive_use_approved": False,
        }
    if header_value is None:
        raise MCPHeaderValueCodecError("header is missing for present body value")
    expected = _text(current, annotation["primitive_type"])
    actual = decode_mcp_parameter_header_value(
        header_value, annotation["primitive_type"]
    )
    if annotation["primitive_type"] == "integer":
        matches = actual == int(expected)
    else:
        matches = actual == current
    if not matches:
        raise MCPHeaderValueCodecError("header and body values differ")
    return {
        "status": "matches",
        "body_value_present": True,
        "header_present": True,
        "network_call_performed": False,
        "positive_use_approved": False,
    }


__all__ = [
    "MCPHeaderValueCodecError",
    "check_mcp_parameter_header_body_parity",
    "decode_mcp_parameter_header_value",
    "encode_mcp_parameter_header_value",
]
