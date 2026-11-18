"""Strict offline endpoint extraction for OpenAPI, Swagger, and WSDL contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

BUNDLE_DOMAIN = "sunderkey.service-contract-endpoint-bundle.v1"
ENDPOINT_DOMAIN = "sunderkey.service-contract-endpoint.v1"
SCHEMA_VERSION = 1
HARD_MAX_BYTES = 2 * 1024 * 1024
HARD_MAX_DEPTH = 64
HARD_MAX_ITEMS = 100_000
HARD_MAX_STRING_LENGTH = 16_384
HARD_MAX_ENDPOINTS = 10_000
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
BUNDLE_ID_PATTERN = re.compile(r"SCEB-[0-9A-F]{32}\Z")
OPENAPI_VERSION_PATTERN = re.compile(r"3\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?\Z")
SAFE_PROVENANCE_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
FORBIDDEN_PROVENANCE_WORDS = frozenset(
    {"api_key", "apikey", "authorization", "cookie", "credential", "password", "secret", "token"}
)
SENSITIVE_QUERY_WORDS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "key",
        "password",
        "secret",
        "signature",
        "token",
    }
)
XINCLUDE_NAMESPACE = "http://www.w3.org/2001/XInclude"
WSDL11_NAMESPACE = "http://schemas.xmlsoap.org/wsdl/"
WSDL20_NAMESPACE = "http://www.w3.org/ns/wsdl"
SOAP11_NAMESPACE = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP12_NAMESPACE = "http://schemas.xmlsoap.org/wsdl/soap12/"
JSON_MEDIA_TYPES = frozenset({"application/json", "application/openapi+json"})
YAML_MEDIA_TYPES = frozenset(
    {"application/yaml", "application/x-yaml", "text/yaml", "application/openapi+yaml"}
)
XML_MEDIA_TYPES = frozenset({"application/xml", "text/xml", "application/wsdl+xml"})
SUPPORTED_MEDIA_TYPES = JSON_MEDIA_TYPES | YAML_MEDIA_TYPES | XML_MEDIA_TYPES


class ServiceContractExtractionError(QualificationError):
    """Raised when an offline service contract cannot be extracted safely."""


@dataclass(frozen=True)
class ServiceContractExtractionLimits:
    """Hard resource ceilings applied before and during parsing."""

    max_bytes: int = HARD_MAX_BYTES
    max_depth: int = HARD_MAX_DEPTH
    max_items: int = HARD_MAX_ITEMS
    max_string_length: int = HARD_MAX_STRING_LENGTH
    max_endpoints: int = HARD_MAX_ENDPOINTS

    def __post_init__(self) -> None:
        ceilings = {
            "max_bytes": HARD_MAX_BYTES,
            "max_depth": HARD_MAX_DEPTH,
            "max_items": HARD_MAX_ITEMS,
            "max_string_length": HARD_MAX_STRING_LENGTH,
            "max_endpoints": HARD_MAX_ENDPOINTS,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ServiceContractExtractionError(f"{name} must be a positive integer")
            if value > ceiling:
                raise ServiceContractExtractionError(
                    f"{name} exceeds the hard maximum of {ceiling}"
                )


ExtractionLimits = ServiceContractExtractionLimits


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing:
        raise ServiceContractExtractionError(
            f"{label} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise ServiceContractExtractionError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ServiceContractExtractionError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ServiceContractExtractionError(f"{label} must be a list")
    return value


def _safe_text(
    value: Any,
    label: str,
    *,
    limit: int = 16_384,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ServiceContractExtractionError(f"{label} must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if not allow_empty and not normalized:
        raise ServiceContractExtractionError(f"{label} must not be empty")
    if len(normalized) > limit:
        raise ServiceContractExtractionError(f"{label} exceeds the string limit")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in normalized):
        raise ServiceContractExtractionError(f"{label} contains control characters")
    return normalized


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _safe_text(value, label)


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _normalize_reference(value: Any, label: str) -> str:
    reference = _safe_text(value, label)
    decoded = unquote(reference).replace("\\", "/")
    if not reference.startswith("#"):
        raise ServiceContractExtractionError(f"{label} must be a local fragment reference")
    if reference != "#" and not reference.startswith("#/"):
        raise ServiceContractExtractionError(f"{label} is not a valid local fragment reference")
    if any(part == ".." for part in decoded.split("/")):
        raise ServiceContractExtractionError(f"{label} contains traversal")
    return reference


def _check_references(value: Any) -> None:
    stack: list[tuple[Any, str]] = [(value, "service contract")]
    while stack:
        current, label = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                if key == "$ref":
                    _normalize_reference(child, f"{label} $ref")
                else:
                    stack.append((child, f"{label}.{key}"))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append((child, f"{label}[{index}]"))


def _json_pointer_token(value: str, label: str) -> str:
    if re.search(r"~(?:[^01]|$)", value):
        raise ServiceContractExtractionError(f"{label} has invalid JSON Pointer escaping")
    return value.replace("~1", "/").replace("~0", "~")


def _resolve_local_mapping(
    document: dict[str, Any],
    value: Any,
    label: str,
    limits: ServiceContractExtractionLimits,
    seen: tuple[str, ...] = (),
) -> dict[str, Any]:
    current = _mapping(value, label)
    reference_value = current.get("$ref")
    if reference_value is None:
        return current
    reference = _normalize_reference(reference_value, f"{label} $ref")
    if reference in seen:
        raise ServiceContractExtractionError(f"{label} contains a reference cycle")
    if len(seen) >= limits.max_depth:
        raise ServiceContractExtractionError("Service contract exceeds the reference depth limit")
    target: Any = document
    if reference != "#":
        for raw_token in reference[2:].split("/"):
            token = _json_pointer_token(unquote(raw_token), f"{label} $ref")
            if isinstance(target, dict) and token in target:
                target = target[token]
            elif isinstance(target, list) and token.isdigit() and int(token) < len(target):
                target = target[int(token)]
            else:
                raise ServiceContractExtractionError(f"{label} $ref does not resolve locally")
    resolved = _resolve_local_mapping(document, target, label, limits, (*seen, reference))
    merged = dict(resolved)
    merged.update({key: child for key, child in current.items() if key != "$ref"})
    return merged


def _validate_structure(value: Any, limits: ServiceContractExtractionLimits) -> None:
    count = 0
    stack: list[tuple[Any, int, str]] = [(value, 1, "service contract")]
    while stack:
        current, depth, label = stack.pop()
        if depth > limits.max_depth:
            raise ServiceContractExtractionError("Service contract exceeds the nesting depth limit")
        count += 1
        if count > limits.max_items:
            raise ServiceContractExtractionError("Service contract exceeds the item limit")
        if isinstance(current, str):
            _safe_text(current, label, limit=limits.max_string_length, allow_empty=True)
        elif isinstance(current, dict):
            for key, child in current.items():
                _safe_text(key, f"{label} key", limit=limits.max_string_length)
                stack.append((child, depth + 1, f"{label}.{key}"))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append((child, depth + 1, f"{label}[{index}]"))
        elif current is not None and not isinstance(current, (bool, int, float)):
            raise ServiceContractExtractionError(f"{label} has an unsupported value type")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ServiceContractExtractionError(f"{label} must be finite")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceContractExtractionError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(content: bytes, limits: ServiceContractExtractionLimits) -> dict[str, Any]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ServiceContractExtractionError("JSON service contract must be UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ServiceContractExtractionError(f"Unsupported JSON number: {value}")
            ),
        )
    except ServiceContractExtractionError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ServiceContractExtractionError("Service contract JSON is invalid") from exc
    document = _mapping(parsed, "service contract")
    _validate_structure(document, limits)
    return document


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    text: str
    number: int


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if character == "\\":
                index += 2
                continue
            if character == '"':
                quote = None
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        elif character == "#" and depth == 0 and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    return value.rstrip()


def _split_yaml_mapping(value: str, line_number: int) -> tuple[str, str] | None:
    quote: str | None = None
    depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if character == "\\":
                index += 2
                continue
            if character == '"':
                quote = None
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ServiceContractExtractionError(
                    f"Invalid YAML collection on line {line_number}"
                )
        elif character == ":" and depth == 0:
            if index + 1 == len(value) or value[index + 1].isspace():
                return value[:index].strip(), value[index + 1 :].strip()
        index += 1
    if quote is not None or depth != 0:
        raise ServiceContractExtractionError(f"Unclosed YAML value on line {line_number}")
    return None


def _yaml_scalar(value: str, line_number: int) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("&") or value.startswith("*") or value.startswith("!"):
        raise ServiceContractExtractionError(
            f"YAML anchors, aliases, and tags are not supported on line {line_number}"
        )
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ServiceContractExtractionError(
                f"Invalid YAML string on line {line_number}"
            ) from exc
        if not isinstance(parsed, str):
            raise ServiceContractExtractionError(f"Invalid YAML key on line {line_number}")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ServiceContractExtractionError(f"Invalid YAML string on line {line_number}")
        return value[1:-1].replace("''", "'")
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered in {"true", "false"}:
        return lowered == "true"
    if re.fullmatch(r"[-+]?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if re.fullmatch(r"[-+]?(?:[0-9]+\.[0-9]+|[0-9]+[eE][-+]?[0-9]+)", value):
        number = float(value)
        if not math.isfinite(number):
            raise ServiceContractExtractionError(f"Non-finite YAML number on line {line_number}")
        return number
    if lowered in {".inf", "+.inf", "-.inf", ".nan"}:
        raise ServiceContractExtractionError(f"Non-finite YAML number on line {line_number}")
    return value


class _FlowYamlParser:
    def __init__(self, value: str, line_number: int) -> None:
        self.value = value
        self.line_number = line_number
        self.index = 0

    def parse(self) -> Any:
        result = self._value()
        self._space()
        if self.index != len(self.value):
            raise ServiceContractExtractionError(
                f"Unexpected YAML flow content on line {self.line_number}"
            )
        return result

    def _space(self) -> None:
        while self.index < len(self.value) and self.value[self.index].isspace():
            self.index += 1

    def _value(self) -> Any:
        self._space()
        if self.index >= len(self.value):
            raise ServiceContractExtractionError(f"Missing YAML value on line {self.line_number}")
        if self.value[self.index] == "[":
            return self._list()
        if self.value[self.index] == "{":
            return self._mapping()
        start = self.index
        quote = self.value[self.index] if self.value[self.index] in {'"', "'"} else None
        if quote is not None:
            self.index += 1
            while self.index < len(self.value):
                character = self.value[self.index]
                if quote == '"' and character == "\\":
                    self.index += 2
                    continue
                if character == quote:
                    if (
                        quote == "'"
                        and self.index + 1 < len(self.value)
                        and self.value[self.index + 1] == "'"
                    ):
                        self.index += 2
                        continue
                    self.index += 1
                    break
                self.index += 1
            else:
                raise ServiceContractExtractionError(
                    f"Unclosed YAML string on line {self.line_number}"
                )
        else:
            while self.index < len(self.value) and self.value[self.index] not in ",]}":
                self.index += 1
        return _yaml_scalar(self.value[start : self.index].strip(), self.line_number)

    def _list(self) -> list[Any]:
        self.index += 1
        result: list[Any] = []
        while True:
            self._space()
            if self.index < len(self.value) and self.value[self.index] == "]":
                self.index += 1
                return result
            result.append(self._value())
            self._space()
            if self.index >= len(self.value) or self.value[self.index] not in ",]":
                raise ServiceContractExtractionError(
                    f"Invalid YAML list on line {self.line_number}"
                )
            if self.value[self.index] == "]":
                self.index += 1
                return result
            self.index += 1

    def _mapping(self) -> dict[str, Any]:
        self.index += 1
        result: dict[str, Any] = {}
        while True:
            self._space()
            if self.index < len(self.value) and self.value[self.index] == "}":
                self.index += 1
                return result
            if self.index >= len(self.value):
                raise ServiceContractExtractionError(
                    f"Unclosed YAML mapping on line {self.line_number}"
                )
            if self.value[self.index] in {'"', "'"}:
                key_value = self._value()
            else:
                start = self.index
                while self.index < len(self.value) and self.value[self.index] != ":":
                    if self.value[self.index] in ",}":
                        break
                    self.index += 1
                key_value = _yaml_scalar(self.value[start : self.index].strip(), self.line_number)
            if not isinstance(key_value, str) or not key_value:
                raise ServiceContractExtractionError(f"Invalid YAML key on line {self.line_number}")
            self._space()
            if self.index >= len(self.value) or self.value[self.index] != ":":
                raise ServiceContractExtractionError(
                    f"Missing YAML colon on line {self.line_number}"
                )
            self.index += 1
            if key_value in result:
                raise ServiceContractExtractionError(f"Duplicate YAML key: {key_value}")
            result[key_value] = self._value()
            self._space()
            if self.index >= len(self.value) or self.value[self.index] not in ",}":
                raise ServiceContractExtractionError(
                    f"Invalid YAML mapping on line {self.line_number}"
                )
            if self.value[self.index] == "}":
                self.index += 1
                return result
            self.index += 1


def _yaml_value(value: str, line_number: int) -> Any:
    stripped = value.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return _FlowYamlParser(stripped, line_number).parse()
    return _yaml_scalar(stripped, line_number)


class _YamlParser:
    def __init__(self, text: str, limits: ServiceContractExtractionLimits) -> None:
        self.limits = limits
        self.lines: list[_YamlLine] = []
        raw_lines = text.splitlines()
        if len(raw_lines) > limits.max_items:
            raise ServiceContractExtractionError("Service contract exceeds the item limit")
        document_started = False
        document_ended = False
        for number, raw in enumerate(raw_lines, 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise ServiceContractExtractionError(
                    f"YAML indentation uses a tab on line {number}"
                )
            stripped = _strip_yaml_comment(raw).rstrip()
            marker = stripped.strip()
            if not marker:
                continue
            if marker == "---":
                if document_started:
                    raise ServiceContractExtractionError(
                        f"Multiple YAML documents are not supported on line {number}"
                    )
                document_started = True
                continue
            if marker == "...":
                if document_ended:
                    raise ServiceContractExtractionError(
                        f"Repeated YAML document end on line {number}"
                    )
                document_ended = True
                continue
            if document_ended:
                raise ServiceContractExtractionError(
                    f"YAML content follows the document end on line {number}"
                )
            document_started = True
            if stripped.lstrip().startswith("%"):
                raise ServiceContractExtractionError(
                    f"YAML directives are not supported on line {number}"
                )
            indent = len(stripped) - len(stripped.lstrip(" "))
            self.lines.append(_YamlLine(indent, stripped[indent:], number))

    def parse(self) -> dict[str, Any]:
        if not self.lines:
            raise ServiceContractExtractionError("Service contract content is empty")
        if self.lines[0].indent != 0:
            raise ServiceContractExtractionError("YAML root must start at indentation zero")
        value, index = self._block(0, 0, 1)
        if index != len(self.lines):
            raise ServiceContractExtractionError(
                f"Unexpected YAML indentation on line {self.lines[index].number}"
            )
        document = _mapping(value, "service contract")
        _validate_structure(document, self.limits)
        return document

    def _block(self, index: int, indent: int, depth: int) -> tuple[Any, int]:
        if depth > self.limits.max_depth:
            raise ServiceContractExtractionError("Service contract exceeds the nesting depth limit")
        if self.lines[index].indent != indent:
            raise ServiceContractExtractionError(
                f"Unexpected YAML indentation on line {self.lines[index].number}"
            )
        if self.lines[index].text == "-" or self.lines[index].text.startswith("- "):
            return self._sequence(index, indent, depth)
        return self._mapping(index, indent, depth)

    def _nested(self, index: int, indent: int, depth: int, line_number: int) -> tuple[Any, int]:
        if index >= len(self.lines) or self.lines[index].indent <= indent:
            raise ServiceContractExtractionError(f"Missing nested YAML value on line {line_number}")
        return self._block(index, self.lines[index].indent, depth + 1)

    def _block_scalar(self, index: int, indent: int, folded: bool) -> tuple[str, int]:
        values: list[str] = []
        while index < len(self.lines) and self.lines[index].indent > indent:
            values.append(self.lines[index].text)
            index += 1
        result = (" " if folded else "\n").join(values)
        if len(result) > self.limits.max_string_length:
            raise ServiceContractExtractionError("YAML block scalar exceeds the string limit")
        return result, index

    def _mapping(self, index: int, indent: int, depth: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(self.lines) and self.lines[index].indent == indent:
            line = self.lines[index]
            if line.text == "-" or line.text.startswith("- "):
                break
            pair = _split_yaml_mapping(line.text, line.number)
            if pair is None:
                raise ServiceContractExtractionError(f"Invalid YAML mapping on line {line.number}")
            raw_key, raw_value = pair
            key = _yaml_scalar(raw_key, line.number)
            if not isinstance(key, str) or not key or key == "<<":
                raise ServiceContractExtractionError(f"Invalid YAML key on line {line.number}")
            if key in result:
                raise ServiceContractExtractionError(f"Duplicate YAML key: {key}")
            index += 1
            if raw_value in {"|", ">"}:
                result[key], index = self._block_scalar(index, indent, raw_value == ">")
            elif raw_value:
                result[key] = _yaml_value(raw_value, line.number)
            else:
                result[key], index = self._nested(index, indent, depth, line.number)
        return result, index

    def _sequence(self, index: int, indent: int, depth: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines) and self.lines[index].indent == indent:
            line = self.lines[index]
            if line.text != "-" and not line.text.startswith("- "):
                break
            rest = line.text[1:].strip()
            index += 1
            if not rest:
                item, index = self._nested(index, indent, depth, line.number)
                result.append(item)
                continue
            pair = _split_yaml_mapping(rest, line.number)
            if pair is None:
                result.append(_yaml_value(rest, line.number))
                continue
            raw_key, raw_value = pair
            key = _yaml_scalar(raw_key, line.number)
            if not isinstance(key, str) or not key or key == "<<":
                raise ServiceContractExtractionError(f"Invalid YAML key on line {line.number}")
            item_map: dict[str, Any] = {}
            if raw_value:
                item_map[key] = _yaml_value(raw_value, line.number)
            else:
                item_map[key], index = self._nested(index, indent, depth, line.number)
            if index < len(self.lines) and self.lines[index].indent > indent:
                continuation_indent = self.lines[index].indent
                continuation, index = self._mapping(index, continuation_indent, depth + 1)
                for extra_key, extra_value in continuation.items():
                    if extra_key in item_map:
                        raise ServiceContractExtractionError(f"Duplicate YAML key: {extra_key}")
                    item_map[extra_key] = extra_value
            result.append(item_map)
        return result, index


def _parse_yaml(content: bytes, limits: ServiceContractExtractionLimits) -> dict[str, Any]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ServiceContractExtractionError("YAML service contract must be UTF-8") from exc
    try:
        return _YamlParser(text, limits).parse()
    except RecursionError as exc:
        raise ServiceContractExtractionError(
            "Service contract exceeds the nesting depth limit"
        ) from exc


def _xml_local(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _xml_namespace(value: str) -> str:
    if value.startswith("{") and "}" in value:
        return value[1:].split("}", 1)[0]
    return ""


def _parse_xml(content: bytes, limits: ServiceContractExtractionLimits) -> ET.Element:
    try:
        xml_text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ServiceContractExtractionError("WSDL service contract must be UTF-8") from exc
    lowered = xml_text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ServiceContractExtractionError("XML DTD and entity declarations are forbidden")
    if "xinclude" in lowered or XINCLUDE_NAMESPACE.lower() in lowered:
        raise ServiceContractExtractionError("XML XInclude is forbidden")
    parser = ET.XMLPullParser(events=("start", "end"))
    depth = 0
    items = 0
    root: ET.Element | None = None
    try:
        for offset in range(0, len(content), 8192):
            parser.feed(content[offset : offset + 8192])
            for event, element in parser.read_events():
                if event == "start":
                    if root is None:
                        root = element
                    depth += 1
                    items += 1 + len(element.attrib)
                    if depth > limits.max_depth:
                        raise ServiceContractExtractionError(
                            "Service contract exceeds the nesting depth limit"
                        )
                    if items > limits.max_items:
                        raise ServiceContractExtractionError(
                            "Service contract exceeds the item limit"
                        )
                    for name, value in element.attrib.items():
                        _safe_text(name, "XML attribute name", limit=limits.max_string_length)
                        _safe_text(
                            value,
                            "XML attribute value",
                            limit=limits.max_string_length,
                            allow_empty=True,
                        )
                else:
                    if element.text:
                        _safe_text(
                            element.text,
                            "XML text",
                            limit=limits.max_string_length,
                            allow_empty=True,
                        )
                    if element.tail:
                        _safe_text(
                            element.tail,
                            "XML tail",
                            limit=limits.max_string_length,
                            allow_empty=True,
                        )
                    depth -= 1
        parser.close()
    except ServiceContractExtractionError:
        raise
    except (ET.ParseError, UnicodeError) as exc:
        raise ServiceContractExtractionError("Service contract XML is invalid") from exc
    if root is None:
        raise ServiceContractExtractionError("Service contract XML is empty")
    for element in root.iter():
        local = _xml_local(element.tag).lower()
        if local in {"import", "include", "redefine", "override"}:
            reference = element.attrib.get("location") or element.attrib.get("schemaLocation")
            if reference:
                raise ServiceContractExtractionError(
                    "External and traversal-like WSDL references are forbidden"
                )
    return root


def _normalize_url(value: Any, label: str, *, allow_relative: bool = True) -> str:
    raw = _safe_text(value, label)
    if "\\" in raw:
        raise ServiceContractExtractionError(f"{label} contains a backslash")
    decoded = unquote(raw)
    if any(part == ".." for part in decoded.replace("\\", "/").split("/")):
        raise ServiceContractExtractionError(f"{label} contains traversal")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ServiceContractExtractionError(f"{label} is not a valid URL") from exc
    if parts.username is not None or parts.password is not None:
        raise ServiceContractExtractionError(f"{label} contains credentials")
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        raise ServiceContractExtractionError(f"{label} uses an unsupported scheme")
    if not parts.scheme and not allow_relative and not parts.netloc:
        raise ServiceContractExtractionError(f"{label} must be an absolute HTTP URL")
    for key, _ in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower().replace("-", "_") in SENSITIVE_QUERY_WORDS:
            raise ServiceContractExtractionError(f"{label} contains a credential-like query field")
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or ("/" if netloc else "")
    return urlunsplit((scheme, netloc, path, "", ""))


def _normalize_path(value: Any, label: str) -> str:
    path = _safe_text(value, label)
    if not path.startswith("/"):
        path = "/" + path
    if "\\" in path or any(part == ".." for part in unquote(path).split("/")):
        raise ServiceContractExtractionError(f"{label} contains traversal")
    return path


def _join_url(server: str, path: str) -> str:
    if not server:
        return path
    if server == "/":
        return path
    return server.rstrip("/") + "/" + path.lstrip("/")


def _transport(value: str, *, soap: str | None = None) -> str:
    if soap is not None:
        return soap
    scheme = urlsplit(value).scheme.lower()
    return scheme if scheme in {"http", "https"} else "unspecified"


def _security_requirements(value: Any, label: str) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    raw_requirements = _list(value, label)
    normalized: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_requirements):
        requirement = _mapping(raw, f"{label}[{index}]")
        schemes: list[dict[str, Any]] = []
        for name, raw_scopes in requirement.items():
            scheme_name = _safe_text(name, f"{label}[{index}] scheme")
            scopes = tuple(
                sorted(
                    {
                        _safe_text(scope, f"{label}[{index}] scope")
                        for scope in _list(raw_scopes, f"{label}[{index}].{name}")
                    }
                )
            )
            schemes.append({"name": scheme_name, "scopes": list(scopes)})
        item = {"schemes": sorted(schemes, key=lambda scheme: scheme["name"])}
        normalized[_canonical_json(item)] = item
    return tuple(normalized[key] for key in sorted(normalized))


def _endpoint_security_requirements(value: Any, label: str) -> tuple[dict[str, Any], ...]:
    normalized: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(_list(value, label)):
        requirement = _mapping(raw, f"{label}[{index}]")
        _exact_fields(requirement, {"schemes"}, f"{label}[{index}]")
        schemes_by_name: dict[str, dict[str, Any]] = {}
        for scheme_index, raw_scheme in enumerate(
            _list(requirement["schemes"], f"{label}[{index}].schemes")
        ):
            scheme = _mapping(raw_scheme, f"{label}[{index}].schemes[{scheme_index}]")
            _exact_fields(
                scheme,
                {"name", "scopes"},
                f"{label}[{index}].schemes[{scheme_index}]",
            )
            name = _safe_text(scheme["name"], f"{label}[{index}] scheme name")
            scopes = sorted(
                {
                    _safe_text(scope, f"{label}[{index}] scope")
                    for scope in _list(scheme["scopes"], f"{label}[{index}] scopes")
                }
            )
            if name in schemes_by_name:
                raise ServiceContractExtractionError(
                    f"{label}[{index}] contains a duplicate scheme"
                )
            schemes_by_name[name] = {"name": name, "scopes": scopes}
        item = {"schemes": [schemes_by_name[name] for name in sorted(schemes_by_name)]}
        normalized[_canonical_json(item)] = item
    return tuple(normalized[key] for key in sorted(normalized))


@dataclass(frozen=True)
class ServiceContractEndpoint:
    """One normalized operation endpoint with no execution authority."""

    document_kind: str
    transport: str
    address: str
    server: str
    path: str
    method: str | None
    operation_id: str | None
    service: str | None
    port: str | None
    binding: str | None
    soap_action: str | None
    security_requirements: tuple[dict[str, Any], ...]
    endpoint_sha256: str

    def _body(self) -> dict[str, Any]:
        return {
            "document_kind": self.document_kind,
            "transport": self.transport,
            "address": self.address,
            "server": self.server,
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "service": self.service,
            "port": self.port,
            "binding": self.binding,
            "soap_action": self.soap_action,
            "security_requirements": [dict(item) for item in self.security_requirements],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "endpoint_sha256": self.endpoint_sha256}

    @classmethod
    def build(
        cls,
        *,
        document_kind: str,
        transport: str,
        address: str,
        server: str,
        path: str,
        method: str | None = None,
        operation_id: str | None = None,
        service: str | None = None,
        port: str | None = None,
        binding: str | None = None,
        soap_action: str | None = None,
        security_requirements: tuple[dict[str, Any], ...] = (),
    ) -> ServiceContractEndpoint:
        body = {
            "document_kind": document_kind,
            "transport": transport,
            "address": address,
            "server": server,
            "path": path,
            "method": method,
            "operation_id": operation_id,
            "service": service,
            "port": port,
            "binding": binding,
            "soap_action": soap_action,
            "security_requirements": [dict(item) for item in security_requirements],
        }
        digest = _canonical_sha256({"domain": ENDPOINT_DOMAIN, "endpoint": body})
        return cls.from_dict({**body, "endpoint_sha256": digest})

    @classmethod
    def from_dict(cls, raw: Any) -> ServiceContractEndpoint:
        value = _mapping(raw, "service contract endpoint")
        expected = {
            "document_kind",
            "transport",
            "address",
            "server",
            "path",
            "method",
            "operation_id",
            "service",
            "port",
            "binding",
            "soap_action",
            "security_requirements",
            "endpoint_sha256",
        }
        _exact_fields(value, expected, "service contract endpoint")
        document_kind = _safe_text(value["document_kind"], "endpoint document_kind")
        if document_kind not in {"openapi", "swagger", "wsdl"}:
            raise ServiceContractExtractionError("Endpoint document_kind is unsupported")
        transport = _safe_text(value["transport"], "endpoint transport")
        if transport not in {"http", "https", "soap11", "soap12", "unspecified"}:
            raise ServiceContractExtractionError("Endpoint transport is unsupported")
        address = _safe_text(value["address"], "endpoint address")
        server = _safe_text(value["server"], "endpoint server", allow_empty=True)
        path = _safe_text(value["path"], "endpoint path", allow_empty=True)
        method = _optional_text(value["method"], "endpoint method")
        if method is not None and method not in {item.upper() for item in HTTP_METHODS}:
            raise ServiceContractExtractionError("Endpoint method is unsupported")
        operation_id = _optional_text(value["operation_id"], "endpoint operation_id")
        service = _optional_text(value["service"], "endpoint service")
        port = _optional_text(value["port"], "endpoint port")
        binding = _optional_text(value["binding"], "endpoint binding")
        soap_action = _optional_text(value["soap_action"], "endpoint soap_action")
        security = _endpoint_security_requirements(
            value["security_requirements"], "endpoint security_requirements"
        )
        digest = value["endpoint_sha256"]
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise ServiceContractExtractionError("Endpoint hash is invalid")
        canonical = {
            "document_kind": document_kind,
            "transport": transport,
            "address": address,
            "server": server,
            "path": path,
            "method": method,
            "operation_id": operation_id,
            "service": service,
            "port": port,
            "binding": binding,
            "soap_action": soap_action,
            "security_requirements": [dict(item) for item in security],
        }
        if _normalize_url(address, "endpoint address") != address:
            raise ServiceContractExtractionError("Endpoint address is not canonical")
        if not server or _normalize_url(server, "endpoint server") != server:
            raise ServiceContractExtractionError("Endpoint server is not canonical")
        if _normalize_path(path, "endpoint path") != path:
            raise ServiceContractExtractionError("Endpoint path is not canonical")
        if method is None:
            raise ServiceContractExtractionError("Endpoint method is required")
        if document_kind in {"openapi", "swagger"}:
            if transport != _transport(server):
                raise ServiceContractExtractionError("Endpoint transport is inconsistent")
            if any(item is not None for item in (service, port, binding, soap_action)):
                raise ServiceContractExtractionError("HTTP endpoint contains SOAP-only fields")
            if document_kind == "openapi" and address != _join_url(server, path):
                raise ServiceContractExtractionError("OpenAPI endpoint address is inconsistent")
            if document_kind == "swagger":
                address_parts = urlsplit(address)
                server_parts = urlsplit(server)
                if (
                    address_parts.path != path
                    or address_parts.scheme != server_parts.scheme
                    or address_parts.netloc != server_parts.netloc
                ):
                    raise ServiceContractExtractionError("Swagger endpoint address is inconsistent")
        else:
            if transport not in {"soap11", "soap12"}:
                raise ServiceContractExtractionError("WSDL endpoint transport is inconsistent")
            if address != server or (urlsplit(address).path or "/") != path:
                raise ServiceContractExtractionError("WSDL endpoint address is inconsistent")
            if method != "POST" or not service or not port or not binding or security:
                raise ServiceContractExtractionError("WSDL endpoint fields are inconsistent")
            if (
                soap_action
                and "://" in soap_action
                and _normalize_url(soap_action, "endpoint soap_action") != soap_action
            ):
                raise ServiceContractExtractionError("WSDL SOAP action is not canonical")
        expected_digest = _canonical_sha256({"domain": ENDPOINT_DOMAIN, "endpoint": canonical})
        if digest != expected_digest or canonical != {key: value[key] for key in canonical}:
            raise ServiceContractExtractionError(
                "Endpoint content does not match its hash or canonical form"
            )
        return cls(
            document_kind,
            transport,
            address,
            server,
            path,
            method,
            operation_id,
            service,
            port,
            binding,
            soap_action,
            security,
            digest,
        )


def _endpoint_sort_key(endpoint: ServiceContractEndpoint) -> str:
    return _canonical_json(endpoint.to_dict())


def _openapi_servers(raw: Any, label: str) -> tuple[str, ...]:
    if raw is None:
        return ("/",)
    servers = _list(raw, label)
    if not servers:
        return ("/",)
    values: set[str] = set()
    for index, item in enumerate(servers):
        server = _mapping(item, f"{label}[{index}]")
        if "url" not in server:
            raise ServiceContractExtractionError(f"{label}[{index}] is missing url")
        values.add(_normalize_url(server["url"], f"{label}[{index}].url"))
    return tuple(sorted(values))


def _extract_openapi(
    document: dict[str, Any], limits: ServiceContractExtractionLimits
) -> tuple[str, list[ServiceContractEndpoint]]:
    raw_version = document.get("openapi")
    version = _safe_text(str(raw_version), "OpenAPI version") if raw_version is not None else ""
    if OPENAPI_VERSION_PATTERN.fullmatch(version) is None:
        raise ServiceContractExtractionError(
            f"Unsupported OpenAPI version: {version or '<missing>'}"
        )
    root_servers = _openapi_servers(document.get("servers"), "OpenAPI servers")
    root_security = _security_requirements(document.get("security"), "OpenAPI security")
    paths = _mapping(document.get("paths"), "OpenAPI paths")
    endpoints: list[ServiceContractEndpoint] = []
    for raw_path in sorted(paths):
        path = _normalize_path(raw_path, "OpenAPI path")
        path_item = _resolve_local_mapping(
            document,
            paths[raw_path],
            f"OpenAPI path {raw_path}",
            limits,
        )
        path_servers = (
            _openapi_servers(path_item.get("servers"), f"OpenAPI path {raw_path} servers")
            if "servers" in path_item
            else root_servers
        )
        for method in sorted(HTTP_METHODS & set(path_item)):
            operation = _mapping(path_item[method], f"OpenAPI operation {method} {raw_path}")
            servers = (
                _openapi_servers(
                    operation.get("servers"), f"OpenAPI operation {method} {raw_path} servers"
                )
                if "servers" in operation
                else path_servers
            )
            security = (
                _security_requirements(
                    operation.get("security"), f"OpenAPI operation {method} {raw_path} security"
                )
                if "security" in operation
                else root_security
            )
            operation_id = _optional_text(
                operation.get("operationId"), f"OpenAPI operation {method} {raw_path} operationId"
            )
            for server in servers:
                endpoints.append(
                    ServiceContractEndpoint.build(
                        document_kind="openapi",
                        transport=_transport(server),
                        address=_join_url(server, path),
                        server=server,
                        path=path,
                        method=method.upper(),
                        operation_id=operation_id,
                        security_requirements=security,
                    )
                )
                if len(endpoints) > limits.max_endpoints:
                    raise ServiceContractExtractionError(
                        "Service contract exceeds the endpoint limit"
                    )
    return version, endpoints


def _extract_swagger(
    document: dict[str, Any], limits: ServiceContractExtractionLimits
) -> tuple[str, list[ServiceContractEndpoint]]:
    raw_version = document.get("swagger")
    version = str(raw_version) if raw_version is not None else ""
    if version != "2.0":
        raise ServiceContractExtractionError(
            f"Unsupported Swagger version: {version or '<missing>'}"
        )
    host = document.get("host", "")
    host_text = _safe_text(host, "Swagger host", allow_empty=True)
    if "@" in host_text or "/" in host_text or "\\" in host_text:
        raise ServiceContractExtractionError("Swagger host is invalid or contains credentials")
    base_path = _normalize_path(document.get("basePath", "/"), "Swagger basePath")
    raw_schemes = document.get("schemes", [])
    schemes: tuple[str | None, ...]
    if raw_schemes:
        parsed_schemes = {
            _safe_text(item, "Swagger scheme").lower()
            for item in _list(raw_schemes, "Swagger schemes")
        }
        if not parsed_schemes <= {"http", "https"}:
            raise ServiceContractExtractionError("Swagger schemes contain an unsupported scheme")
        schemes = tuple(sorted(parsed_schemes))
    else:
        schemes = (None,)
    root_security = _security_requirements(document.get("security"), "Swagger security")
    paths = _mapping(document.get("paths"), "Swagger paths")
    endpoints: list[ServiceContractEndpoint] = []
    for raw_path in sorted(paths):
        path = _normalize_path(raw_path, "Swagger path")
        path_item = _resolve_local_mapping(
            document,
            paths[raw_path],
            f"Swagger path {raw_path}",
            limits,
        )
        for method in sorted(HTTP_METHODS & set(path_item)):
            operation = _mapping(path_item[method], f"Swagger operation {method} {raw_path}")
            operation_schemes = schemes
            if operation.get("schemes"):
                selected = {
                    _safe_text(item, "Swagger operation scheme").lower()
                    for item in _list(operation["schemes"], "Swagger operation schemes")
                }
                if not selected <= {"http", "https"}:
                    raise ServiceContractExtractionError(
                        "Swagger operation uses an unsupported scheme"
                    )
                operation_schemes = tuple(sorted(selected))
            security = (
                _security_requirements(
                    operation.get("security"), f"Swagger operation {method} {raw_path} security"
                )
                if "security" in operation
                else root_security
            )
            operation_id = _optional_text(
                operation.get("operationId"), f"Swagger operation {method} {raw_path} operationId"
            )
            full_path = _join_url(base_path, path)
            for scheme in operation_schemes:
                if host_text:
                    server = f"{scheme + ':' if scheme else ''}//{host_text}{base_path.rstrip('/')}"
                else:
                    server = base_path
                server = _normalize_url(server, "Swagger server")
                endpoints.append(
                    ServiceContractEndpoint.build(
                        document_kind="swagger",
                        transport=scheme or "unspecified",
                        address=_join_url(server, path),
                        server=server,
                        path=full_path,
                        method=method.upper(),
                        operation_id=operation_id,
                        security_requirements=security,
                    )
                )
                if len(endpoints) > limits.max_endpoints:
                    raise ServiceContractExtractionError(
                        "Service contract exceeds the endpoint limit"
                    )
    return version, endpoints


def _qname_local(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rsplit(":", 1)[-1]


def _soap_binding_transport(binding: ET.Element) -> str | None:
    for child in binding:
        namespace = _xml_namespace(child.tag)
        if _xml_local(child.tag) == "binding":
            if namespace == SOAP12_NAMESPACE:
                return "soap12"
            if namespace == SOAP11_NAMESPACE:
                return "soap11"
    return None


def _wsdl_action(operation: ET.Element) -> str | None:
    candidates: list[str] = []
    for name, value in operation.attrib.items():
        if _xml_local(name).lower() in {"action", "soapaction"} and value:
            candidates.append(value)
    for child in operation:
        for name, value in child.attrib.items():
            if _xml_local(name).lower() in {"action", "soapaction"} and value:
                candidates.append(value)
    if not candidates:
        return None
    action = _safe_text(sorted(candidates)[0], "WSDL SOAP action")
    if "://" in action:
        return _normalize_url(action, "WSDL SOAP action")
    return action


def _extract_wsdl11(
    root: ET.Element, limits: ServiceContractExtractionLimits
) -> list[ServiceContractEndpoint]:
    bindings: dict[str, tuple[str | None, tuple[tuple[str, str | None], ...]]] = {}
    port_types: dict[str, tuple[str, ...]] = {}
    for child in root:
        local = _xml_local(child.tag)
        if local == "portType":
            name = _safe_text(child.attrib.get("name"), "WSDL portType name")
            operations = tuple(
                sorted(
                    {
                        _safe_text(item.attrib.get("name"), "WSDL operation name")
                        for item in child
                        if _xml_local(item.tag) == "operation"
                    }
                )
            )
            port_types[name] = operations
    for child in root:
        if _xml_local(child.tag) == "binding":
            name = _safe_text(child.attrib.get("name"), "WSDL binding name")
            binding_type = _qname_local(child.attrib.get("type")) or ""
            operations = tuple(
                sorted(
                    (
                        _safe_text(item.attrib.get("name"), "WSDL binding operation name"),
                        _wsdl_action(item),
                    )
                    for item in child
                    if _xml_local(item.tag) == "operation"
                )
            )
            if not operations and binding_type in port_types:
                operations = tuple((item, None) for item in port_types[binding_type])
            bindings[name] = (_soap_binding_transport(child), operations)
    endpoints: list[ServiceContractEndpoint] = []
    for service_element in sorted(
        (item for item in root if _xml_local(item.tag) == "service"),
        key=lambda item: item.attrib.get("name", ""),
    ):
        service = _safe_text(service_element.attrib.get("name"), "WSDL service name")
        for port_element in sorted(
            (item for item in service_element if _xml_local(item.tag) == "port"),
            key=lambda item: item.attrib.get("name", ""),
        ):
            port = _safe_text(port_element.attrib.get("name"), "WSDL port name")
            binding = _qname_local(port_element.attrib.get("binding"))
            if binding is None:
                raise ServiceContractExtractionError("WSDL port is missing a binding")
            address_values = [
                item.attrib.get("location")
                for item in port_element
                if _xml_local(item.tag) == "address"
                and _xml_namespace(item.tag) in {SOAP11_NAMESPACE, SOAP12_NAMESPACE}
                and item.attrib.get("location")
            ]
            if not address_values:
                continue
            address = _normalize_url(sorted(address_values)[0], "WSDL port address")
            transport, operations = bindings.get(binding, (None, ()))
            if transport is None:
                continue
            operation_rows = operations or ((None, None),)
            for operation, action in operation_rows:
                endpoints.append(
                    ServiceContractEndpoint.build(
                        document_kind="wsdl",
                        transport=transport,
                        address=address,
                        server=address,
                        path=urlsplit(address).path or "/",
                        method="POST",
                        operation_id=operation,
                        service=service,
                        port=port,
                        binding=binding,
                        soap_action=action,
                    )
                )
                if len(endpoints) > limits.max_endpoints:
                    raise ServiceContractExtractionError(
                        "Service contract exceeds the endpoint limit"
                    )
    return endpoints


def _extract_wsdl20(
    root: ET.Element, limits: ServiceContractExtractionLimits
) -> list[ServiceContractEndpoint]:
    interfaces: dict[str, tuple[str, ...]] = {}
    bindings: dict[str, tuple[str | None, tuple[tuple[str, str | None], ...], str | None]] = {}
    for child in root:
        local = _xml_local(child.tag)
        if local == "interface":
            name = _safe_text(child.attrib.get("name"), "WSDL interface name")
            interfaces[name] = tuple(
                sorted(
                    {
                        _qname_local(item.attrib.get("name") or item.attrib.get("ref")) or ""
                        for item in child
                        if _xml_local(item.tag) == "operation"
                    }
                    - {""}
                )
            )
    for child in root:
        if _xml_local(child.tag) == "binding":
            name = _safe_text(child.attrib.get("name"), "WSDL binding name")
            interface = _qname_local(child.attrib.get("interface"))
            binding_type = child.attrib.get("type", "")
            transport = "soap12" if "soap" in binding_type.lower() else None
            operations: list[tuple[str, str | None]] = []
            for item in child:
                if _xml_local(item.tag) != "operation":
                    continue
                operation = _qname_local(item.attrib.get("ref") or item.attrib.get("name"))
                if operation:
                    operations.append((operation, _wsdl_action(item)))
            if not operations and interface in interfaces:
                operations = [(item, None) for item in interfaces[interface]]
            bindings[name] = (interface, tuple(sorted(operations)), transport)
    endpoints: list[ServiceContractEndpoint] = []
    for service_element in sorted(
        (item for item in root if _xml_local(item.tag) == "service"),
        key=lambda item: item.attrib.get("name", ""),
    ):
        service = _safe_text(service_element.attrib.get("name"), "WSDL service name")
        service_interface = _qname_local(service_element.attrib.get("interface"))
        for endpoint_element in sorted(
            (item for item in service_element if _xml_local(item.tag) == "endpoint"),
            key=lambda item: item.attrib.get("name", ""),
        ):
            port = _safe_text(endpoint_element.attrib.get("name"), "WSDL endpoint name")
            binding = _qname_local(endpoint_element.attrib.get("binding"))
            if binding is None:
                raise ServiceContractExtractionError("WSDL endpoint is missing a binding")
            address = _normalize_url(
                endpoint_element.attrib.get("address"), "WSDL endpoint address"
            )
            interface, operations, transport = bindings.get(binding, (service_interface, (), None))
            if transport is None:
                continue
            if not operations and interface in interfaces:
                operations = tuple((item, None) for item in interfaces[interface])
            operation_rows = operations or ((None, None),)
            for operation, action in operation_rows:
                endpoints.append(
                    ServiceContractEndpoint.build(
                        document_kind="wsdl",
                        transport=transport,
                        address=address,
                        server=address,
                        path=urlsplit(address).path or "/",
                        method="POST",
                        operation_id=operation,
                        service=service,
                        port=port,
                        binding=binding,
                        soap_action=action,
                    )
                )
                if len(endpoints) > limits.max_endpoints:
                    raise ServiceContractExtractionError(
                        "Service contract exceeds the endpoint limit"
                    )
    return endpoints


def _extract_wsdl(
    root: ET.Element, limits: ServiceContractExtractionLimits
) -> tuple[str, list[ServiceContractEndpoint]]:
    namespace = _xml_namespace(root.tag)
    local = _xml_local(root.tag)
    if namespace == WSDL11_NAMESPACE and local == "definitions":
        return "1.1", _extract_wsdl11(root, limits)
    if namespace == WSDL20_NAMESPACE and local == "description":
        return "2.0", _extract_wsdl20(root, limits)
    raise ServiceContractExtractionError("Unsupported WSDL version or root element")


def _canonical_provenance(value: Mapping[str, str] | None) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ServiceContractExtractionError("provenance must be an object")
    if len(value) > 64:
        raise ServiceContractExtractionError("provenance exceeds the field limit")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _safe_text(raw_key, "provenance key").lower()
        if SAFE_PROVENANCE_KEY_PATTERN.fullmatch(key) is None:
            raise ServiceContractExtractionError(f"Invalid provenance key: {key}")
        words = set(key.split("_")) | {key}
        if words & FORBIDDEN_PROVENANCE_WORDS:
            raise ServiceContractExtractionError(
                f"Credential-bearing provenance field is forbidden: {key}"
            )
        result[key] = _safe_text(raw_value, f"provenance {key}")
    return dict(sorted(result.items()))


@dataclass(frozen=True)
class ServiceContractEndpointBundle:
    """Canonical content-addressed output of an offline extraction."""

    bundle_id: str
    bundle_sha256: str
    content_sha256: str
    document_kind: str
    document_version: str
    endpoints: tuple[ServiceContractEndpoint, ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def source(self) -> dict[str, Any]:
        return self.to_dict()["source"]

    @property
    def extraction_status(self) -> str:
        return self.to_dict()["extraction_status"]

    @classmethod
    def build(
        cls,
        *,
        source_id: str,
        media_type: str,
        content: bytes,
        provenance: Mapping[str, str] | None,
        document_kind: str,
        document_version: str,
        endpoints: list[ServiceContractEndpoint],
    ) -> ServiceContractEndpointBundle:
        canonical_endpoints = tuple(
            sorted(
                {item.endpoint_sha256: item for item in endpoints}.values(), key=_endpoint_sort_key
            )
        )
        source = {
            "source_id": _safe_text(source_id, "source_id"),
            "media_type": _safe_text(media_type, "media_type"),
            "byte_size": len(content),
            "content_sha256": _bytes_sha256(content),
            "provenance": _canonical_provenance(provenance),
        }
        body = {
            "schema_version": SCHEMA_VERSION,
            "source": source,
            "document_kind": document_kind,
            "document_version": document_version,
            "endpoints": [item.to_dict() for item in canonical_endpoints],
            "endpoint_count": len(canonical_endpoints),
            "extraction_status": "complete" if canonical_endpoints else "complete_empty",
            "offline_only": True,
            "target_authority_effect": "none",
        }
        digest = _canonical_sha256({"domain": BUNDLE_DOMAIN, "bundle": body})
        bundle_id = f"SCEB-{digest.removeprefix('sha256:')[:32].upper()}"
        return cls.from_dict(
            {**body, "bundle_id": bundle_id, "bundle_sha256": digest}, content=content
        )

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        content: bytes | bytearray | memoryview | str | None = None,
    ) -> ServiceContractEndpointBundle:
        value = _mapping(raw, "service contract endpoint bundle")
        expected = {
            "schema_version",
            "bundle_id",
            "bundle_sha256",
            "source",
            "document_kind",
            "document_version",
            "endpoints",
            "endpoint_count",
            "extraction_status",
            "offline_only",
            "target_authority_effect",
        }
        _exact_fields(value, expected, "service contract endpoint bundle")
        if (
            not isinstance(value["schema_version"], int)
            or isinstance(value["schema_version"], bool)
            or value["schema_version"] != SCHEMA_VERSION
        ):
            raise ServiceContractExtractionError("Bundle schema_version is unsupported")
        source = _mapping(value["source"], "bundle source")
        _exact_fields(
            source,
            {"source_id", "media_type", "byte_size", "content_sha256", "provenance"},
            "bundle source",
        )
        _safe_text(source["source_id"], "bundle source_id")
        source_media_type = _safe_text(source["media_type"], "bundle media_type")
        if source_media_type not in SUPPORTED_MEDIA_TYPES:
            raise ServiceContractExtractionError("Bundle media_type is unsupported")
        if (
            not isinstance(source["byte_size"], int)
            or isinstance(source["byte_size"], bool)
            or source["byte_size"] < 1
            or source["byte_size"] > HARD_MAX_BYTES
        ):
            raise ServiceContractExtractionError("Bundle byte_size is outside the hard limit")
        content_sha256 = source["content_sha256"]
        if not isinstance(content_sha256, str) or SHA256_PATTERN.fullmatch(content_sha256) is None:
            raise ServiceContractExtractionError("Bundle content hash is invalid")
        canonical_provenance = _canonical_provenance(
            _mapping(source["provenance"], "bundle provenance")
        )
        if canonical_provenance != source["provenance"]:
            raise ServiceContractExtractionError("Bundle provenance is not canonical")
        document_kind = _safe_text(value["document_kind"], "bundle document_kind")
        if document_kind not in {"openapi", "swagger", "wsdl"}:
            raise ServiceContractExtractionError("Bundle document_kind is unsupported")
        document_version = _safe_text(value["document_version"], "bundle document_version")
        if (
            document_kind == "openapi"
            and OPENAPI_VERSION_PATTERN.fullmatch(document_version) is None
        ):
            raise ServiceContractExtractionError("Bundle OpenAPI version is unsupported")
        if document_kind == "swagger" and document_version != "2.0":
            raise ServiceContractExtractionError("Bundle Swagger version is unsupported")
        if document_kind == "wsdl" and document_version not in {"1.1", "2.0"}:
            raise ServiceContractExtractionError("Bundle WSDL version is unsupported")
        if document_kind == "wsdl" and source_media_type not in XML_MEDIA_TYPES:
            raise ServiceContractExtractionError("Bundle media type does not match WSDL")
        if document_kind != "wsdl" and source_media_type in XML_MEDIA_TYPES:
            raise ServiceContractExtractionError("Bundle media type does not match HTTP contract")
        endpoints = tuple(
            ServiceContractEndpoint.from_dict(item)
            for item in _list(value["endpoints"], "bundle endpoints")
        )
        if len(endpoints) > HARD_MAX_ENDPOINTS:
            raise ServiceContractExtractionError("Bundle exceeds the endpoint hard limit")
        if any(item.document_kind != document_kind for item in endpoints):
            raise ServiceContractExtractionError("Bundle endpoint document kind is inconsistent")
        if endpoints != tuple(sorted(endpoints, key=_endpoint_sort_key)):
            raise ServiceContractExtractionError("Bundle endpoints are not in canonical order")
        if len({item.endpoint_sha256 for item in endpoints}) != len(endpoints):
            raise ServiceContractExtractionError("Bundle endpoints contain duplicates")
        if (
            not isinstance(value["endpoint_count"], int)
            or isinstance(value["endpoint_count"], bool)
            or value["endpoint_count"] != len(endpoints)
        ):
            raise ServiceContractExtractionError("Bundle endpoint_count is inconsistent")
        status = "complete" if endpoints else "complete_empty"
        if value["extraction_status"] != status:
            raise ServiceContractExtractionError("Bundle extraction_status is inconsistent")
        if value["offline_only"] is not True or value["target_authority_effect"] != "none":
            raise ServiceContractExtractionError(
                "Bundle must not grant network or target authority"
            )
        bundle_id = value["bundle_id"]
        bundle_sha256 = value["bundle_sha256"]
        if not isinstance(bundle_id, str) or BUNDLE_ID_PATTERN.fullmatch(bundle_id) is None:
            raise ServiceContractExtractionError("Bundle ID is invalid")
        if not isinstance(bundle_sha256, str) or SHA256_PATTERN.fullmatch(bundle_sha256) is None:
            raise ServiceContractExtractionError("Bundle hash is invalid")
        body = {key: value[key] for key in value if key not in {"bundle_id", "bundle_sha256"}}
        expected_digest = _canonical_sha256({"domain": BUNDLE_DOMAIN, "bundle": body})
        expected_id = f"SCEB-{expected_digest.removeprefix('sha256:')[:32].upper()}"
        if bundle_sha256 != expected_digest or bundle_id != expected_id:
            raise ServiceContractExtractionError("Bundle identity does not match its content")
        if content is not None:
            content_bytes = _coerce_content(content)
            if (
                len(content_bytes) != source["byte_size"]
                or _bytes_sha256(content_bytes) != content_sha256
            ):
                raise ServiceContractExtractionError(
                    "Bundle source content does not match provenance"
                )
        return cls(
            bundle_id,
            bundle_sha256,
            content_sha256,
            document_kind,
            document_version,
            endpoints,
            _canonical_json(value),
        )


def _coerce_content(content: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (bytes, bytearray, memoryview)):
        return bytes(content)
    raise ServiceContractExtractionError(
        "Service contract content must be bytes or already-ingested text"
    )


def extract_service_contract_endpoints(
    content: bytes | bytearray | memoryview | str,
    *,
    source_id: str = "inline",
    source_name: str | None = None,
    media_type: str | None = None,
    provenance: Mapping[str, str] | None = None,
    limits: ServiceContractExtractionLimits | None = None,
) -> ServiceContractEndpointBundle:
    """Extract an endpoint bundle without file, network, or target access."""

    selected_limits = limits or ServiceContractExtractionLimits()
    if not isinstance(selected_limits, ServiceContractExtractionLimits):
        raise ServiceContractExtractionError("limits must be ServiceContractExtractionLimits")
    payload = _coerce_content(content)
    if not payload or not payload.strip():
        raise ServiceContractExtractionError("Service contract content is empty")
    if len(payload) > selected_limits.max_bytes:
        raise ServiceContractExtractionError("Service contract exceeds the byte limit")
    if source_name is not None:
        if source_id != "inline":
            raise ServiceContractExtractionError("Use source_id or source_name, not both")
        source_id = source_name
    stripped = payload.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    if media_type is not None and not isinstance(media_type, str):
        raise ServiceContractExtractionError("media_type must be text")
    explicit_type = media_type.lower().split(";", 1)[0].strip() if media_type else None
    if explicit_type is not None and explicit_type not in SUPPORTED_MEDIA_TYPES:
        raise ServiceContractExtractionError(
            f"Unsupported service contract media type: {explicit_type}"
        )
    parse_as_xml = explicit_type in XML_MEDIA_TYPES or (
        explicit_type is None and stripped.startswith(b"<")
    )
    parse_as_json = explicit_type in JSON_MEDIA_TYPES or (
        explicit_type is None and stripped.startswith((b"{", b"["))
    )
    if parse_as_xml:
        root = _parse_xml(payload, selected_limits)
        document_version, endpoints = _extract_wsdl(root, selected_limits)
        document_kind = "wsdl"
        normalized_media_type = explicit_type or "application/wsdl+xml"
    else:
        if parse_as_json:
            document = _parse_json(payload, selected_limits)
            normalized_media_type = explicit_type or "application/json"
        elif explicit_type is None or explicit_type in YAML_MEDIA_TYPES:
            document = _parse_yaml(payload, selected_limits)
            normalized_media_type = explicit_type or "application/yaml"
        else:
            raise ServiceContractExtractionError("Service contract media type is inconsistent")
        _check_references(document)
        has_openapi = "openapi" in document
        has_swagger = "swagger" in document
        if has_openapi == has_swagger:
            raise ServiceContractExtractionError(
                "Service contract must declare exactly one supported document version"
            )
        if has_openapi:
            document_kind = "openapi"
            document_version, endpoints = _extract_openapi(document, selected_limits)
        else:
            document_kind = "swagger"
            document_version, endpoints = _extract_swagger(document, selected_limits)
    return ServiceContractEndpointBundle.build(
        source_id=source_id,
        media_type=normalized_media_type,
        content=payload,
        provenance=provenance,
        document_kind=document_kind,
        document_version=document_version,
        endpoints=endpoints,
    )


extract_service_contract_endpoint_bundle = extract_service_contract_endpoints
extract_service_contract = extract_service_contract_endpoints


__all__ = [
    "BUNDLE_DOMAIN",
    "ENDPOINT_DOMAIN",
    "ExtractionLimits",
    "ServiceContractEndpoint",
    "ServiceContractEndpointBundle",
    "ServiceContractExtractionError",
    "ServiceContractExtractionLimits",
    "extract_service_contract",
    "extract_service_contract_endpoint_bundle",
    "extract_service_contract_endpoints",
]
