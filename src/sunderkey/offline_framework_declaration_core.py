"""Shared bounded JSON and report primitives for inert framework declarations."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_ITEMS = 512
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class FrameworkDeclarationError(ValueError):
    """A closed declaration, bounded source, or replay check failed."""


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise FrameworkDeclarationError(f"{label} fields are invalid")
    return value


def identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise FrameworkDeclarationError(f"{label} must be bounded native ASCII text")
    return value


def path(value: Any) -> str:
    if type(value) is not str or _PATH.fullmatch(value) is None:
        raise FrameworkDeclarationError("route path must be an inert exact ASCII path")
    if len(value) > 256 or any(segment in (".", "..") for segment in value.split("/")):
        raise FrameworkDeclarationError("route path is ambiguous or too long")
    return value


def boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise FrameworkDeclarationError(f"{label} must be a native Boolean")
    return value


def choice(value: Any, options: set[str], label: str) -> str:
    if type(value) is not str or value not in options:
        raise FrameworkDeclarationError(f"{label} is unsupported")
    return value


def bounded_list(value: Any, maximum: int, label: str) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise FrameworkDeclarationError(f"{label} must be a bounded native array")
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise FrameworkDeclarationError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise FrameworkDeclarationError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise FrameworkDeclarationError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise FrameworkDeclarationError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise FrameworkDeclarationError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise FrameworkDeclarationError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise FrameworkDeclarationError("unsupported JSON value family")
    if len(canonical(value).encode("ascii")) > maximum:
        raise FrameworkDeclarationError("canonical JSON byte bound exceeded")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FrameworkDeclarationError("duplicate JSON key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise FrameworkDeclarationError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise FrameworkDeclarationError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise FrameworkDeclarationError("floating and nonfinite numbers are unsupported")


def decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise FrameworkDeclarationError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FrameworkDeclarationError("source must be UTF-8") from exc
    nesting = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            nesting += 1
            if nesting > MAX_DEPTH:
                raise FrameworkDeclarationError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise FrameworkDeclarationError("malformed JSON nesting")
    if nesting or quoted:
        raise FrameworkDeclarationError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, FrameworkDeclarationError):
            raise
        raise FrameworkDeclarationError("malformed JSON source") from exc
    validate_tree(result, maximum=maximum)
    return result


def report_address(document: dict[str, Any], *, domain: str, prefix: str) -> tuple[str, str]:
    body = {
        key: value for key, value in document.items() if key not in ("report_id", "report_sha256")
    }
    sha256 = digest(canonical({"domain": domain, "analysis": body}).encode("ascii"))
    return prefix + sha256[7:39].upper(), sha256


def validate_source(source: Any) -> None:
    item = exact(source, {"source_id", "sha256", "byte_count"}, "source")
    identifier(item["source_id"], "source ID")
    if type(item["sha256"]) is not str or _DIGEST.fullmatch(item["sha256"]) is None:
        raise FrameworkDeclarationError("source digest is invalid")
    if type(item["byte_count"]) is not int or not 1 <= item["byte_count"] <= MAX_SOURCE_BYTES:
        raise FrameworkDeclarationError("source byte count is invalid")
