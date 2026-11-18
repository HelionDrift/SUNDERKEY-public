"""Pure, bounded proto3 structural schema-evolution analysis."""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S03"
CAPABILITY_ID = "army.gb.d06.s03"
VECTOR_ID = "AV-GB-D06-S03-01"
DOMAIN = "sunderkey.offline-protobuf-analysis.v1"
SYNTAX_PROFILE = "top-level-proto3-evolution-subset.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_ITEMS = 50_000
MAX_DEPTH = 32
MAX_OBSERVATIONS = 2_048
MAX_FIELD_NUMBER = 536_870_911
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}\Z")
_LEX_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_LEX_NUMBER = re.compile(r"[0-9]+")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCALARS = {
    "double": 1,
    "float": 5,
    "int32": 0,
    "int64": 0,
    "uint32": 0,
    "uint64": 0,
    "sint32": 0,
    "sint64": 0,
    "fixed32": 5,
    "fixed64": 1,
    "sfixed32": 5,
    "sfixed64": 1,
    "bool": 0,
    "string": 2,
    "bytes": 2,
}
_KEYWORDS = {
    "syntax",
    "edition",
    "package",
    "message",
    "service",
    "rpc",
    "returns",
    "stream",
    "reserved",
    "to",
    "max",
    "optional",
    "repeated",
    "required",
    "import",
    "option",
    "enum",
    "oneof",
    "map",
    "extend",
    "extensions",
    "group",
    "public",
    "weak",
} | set(_SCALARS)
_LIMIT_CEILINGS = {
    "max_previous_bytes": MAX_DOCUMENT_BYTES,
    "max_current_bytes": MAX_DOCUMENT_BYTES,
    "max_tokens": MAX_ITEMS,
    "max_nodes": MAX_ITEMS,
    "max_observations": MAX_OBSERVATIONS,
}
_STATISTICS = {
    f"{side}_{item}"
    for side in ("previous", "current")
    for item in (
        "message_count",
        "field_count",
        "service_count",
        "rpc_count",
        "token_count",
        "ast_node_count",
    )
}
_CHANGES = {
    "message_added",
    "message_removed",
    "service_added",
    "service_removed",
    "field_added",
    "field_removed",
    "field_number_changed",
    "field_name_changed_at_number",
    "field_base_wire_type_changed",
    "field_type_changed_same_base_wire_type",
    "field_cardinality_changed",
    "field_presence_changed",
    "removed_field_number_not_reserved",
    "removed_field_name_not_reserved",
    "reserved_number_reused",
    "reserved_name_reused",
    "reserved_numbers_added",
    "reserved_numbers_released",
    "reserved_name_added",
    "reserved_name_released",
    "rpc_added",
    "rpc_removed",
    "rpc_signature_changed",
}
_EFFECTS = {
    key: "none"
    for key in ("authority", "target", "execution", "routing", "qualification", "deployment")
}


class ProtobufAnalysisError(ValueError):
    """Invalid, unsupported, inconsistent or over-budget supplied metadata."""


def _integer(value: Any, maximum: int, label: str, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtobufAnalysisError(f"{label} must be a bounded native integer")
    return value


def _name(value: Any) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None or value in _KEYWORDS:
        raise ProtobufAnalysisError("identifier is outside the supported native name subset")
    return value


def _full_name(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise ProtobufAnalysisError("qualified name is invalid")
    for part in value.split("."):
        _name(part)
    return value


def _source_id(value: Any) -> str:
    if type(value) is not str or _SOURCE_ID.fullmatch(value) is None:
        raise ProtobufAnalysisError("source ID must be a bounded native identifier")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != keys:
        raise ProtobufAnalysisError(f"{label} fields are invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProtobufAnalysisLimits:
    """Explicit local software-cost ceilings, never RPC or target budgets."""

    max_previous_bytes: int
    max_current_bytes: int
    max_tokens: int
    max_nodes: int
    max_observations: int

    def __post_init__(self) -> None:
        _limits(self)

    def to_dict(self) -> dict[str, int]:
        return _limits(self)


def _limits(value: Any) -> dict[str, int]:
    if type(value) is not ProtobufAnalysisLimits:
        raise ProtobufAnalysisError("limits must be the exact ProtobufAnalysisLimits family")
    try:
        return {
            key: _integer(getattr(value, key), ceiling, key)
            for key, ceiling in _LIMIT_CEILINGS.items()
        }
    except AttributeError as exc:
        raise ProtobufAnalysisError("limits have incomplete native slots") from exc


def _native_budget(value: Any) -> None:
    """Charge repeated subtrees and JSON escapes before dumps or hash work."""
    pending = [(value, 1)]
    nodes = size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_ITEMS or depth > MAX_DEPTH:
            raise ProtobufAnalysisError("native document exceeds node or depth limit")
        kind = type(item)
        if kind is dict:
            if nodes + len(pending) + 2 * len(item) > MAX_ITEMS:
                raise ProtobufAnalysisError("native document exceeds node limit")
            if any(type(key) is not str for key in item):
                raise ProtobufAnalysisError("native document keys must be strings")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                pending.append((child, depth + 1))
                pending.append((key, depth + 1))
        elif kind is list:
            if nodes + len(pending) + len(item) > MAX_ITEMS:
                raise ProtobufAnalysisError("native document exceeds node limit")
            size += 2 + max(0, len(item) - 1)
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item) > 8192 or not item.isascii():
                raise ProtobufAnalysisError("native document string exceeds supported bounds")
            size += 2
            for char in item:
                size += 2 if char in '\\"\b\f\n\r\t' else 6 if ord(char) < 32 else 1
                if size > MAX_DOCUMENT_BYTES:
                    raise ProtobufAnalysisError("native document exceeds byte limit")
        elif kind is int:
            if item.bit_length() > 63:
                raise ProtobufAnalysisError("native integer exceeds supported bounds")
            size += len(str(item))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise ProtobufAnalysisError("native document contains an unsupported primitive")
        if size > MAX_DOCUMENT_BYTES:
            raise ProtobufAnalysisError("native document exceeds byte limit")


def _canonical(value: Any) -> str:
    _native_budget(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtobufAnalysisError("JSON contains duplicate keys")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise ProtobufAnalysisError("JSON integer exceeds supported bounds")
    result = int(value)
    if result.bit_length() > 63:
        raise ProtobufAnalysisError("JSON integer exceeds supported bounds")
    return result


def _bad_number(value: str) -> None:
    raise ProtobufAnalysisError("JSON floats and nonfinite numbers are unsupported")


def _json(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES:
        raise ProtobufAnalysisError("report JSON must be bounded native text")
    try:
        if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ProtobufAnalysisError("report JSON exceeds byte limit")
    except UnicodeEncodeError as exc:
        raise ProtobufAnalysisError("report JSON must be UTF-8") from exc
    depth = 0
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
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtobufAnalysisError("report JSON exceeds depth limit")
        elif char in "]}":
            depth -= 1
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_bad_number,
            parse_constant=_bad_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ProtobufAnalysisError):
            raise
        raise ProtobufAnalysisError("report JSON is malformed") from exc
    _native_budget(result)
    return result


def _tokens(content: Any, maximum: int, token_limit: int) -> list[str]:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise ProtobufAnalysisError("proto source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtobufAnalysisError("proto source must be UTF-8") from exc
    result: list[str] = []
    offset = 0
    while offset < len(text):
        char = text[offset]
        if char in " \t\r\n\f\v":
            offset += 1
            continue
        if text.startswith("//", offset):
            end = text.find("\n", offset + 2)
            offset = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", offset):
            end = text.find("*/", offset + 2)
            if end < 0 or "/*" in text[offset + 2 : end]:
                raise ProtobufAnalysisError("block comment is unterminated or unsupported")
            offset = end + 2
            continue
        if len(result) >= token_limit:
            raise ProtobufAnalysisError("proto source exceeds token limit")
        if char in "{}=;,.()":
            token = char
            offset += 1
        elif char == '"':
            end = text.find('"', offset + 1)
            if end < 0:
                raise ProtobufAnalysisError("string literal is unterminated")
            token = text[offset : end + 1]
            if len(token) > 130 or any(
                c in "\\\r\n" or ord(c) < 32 or ord(c) > 126 for c in token[1:-1]
            ):
                raise ProtobufAnalysisError("string literal is outside the closed subset")
            offset = end + 1
        else:
            match = _LEX_NAME.match(text, offset) or _LEX_NUMBER.match(text, offset)
            if match is None:
                raise ProtobufAnalysisError("source contains unsupported syntax")
            token = match.group()
            if len(token) > 128:
                raise ProtobufAnalysisError("token exceeds supported length")
            offset = match.end()
        result.append(token)
    return result


def _normalize_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if result and start <= result[-1][1]:
            raise ProtobufAnalysisError("reserved ranges overlap or duplicate")
        if result and start == result[-1][1] + 1:
            result[-1] = (result[-1][0], end)
        else:
            result.append((start, end))
    return result


def _range_at(ranges: list[tuple[int, int]], number: int) -> tuple[int, int] | None:
    offset = bisect_right(ranges, (number, MAX_FIELD_NUMBER)) - 1
    return ranges[offset] if offset >= 0 and number <= ranges[offset][1] else None


def _subtract(left: list[tuple[int, int]], right: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Linear interval subtraction without expanding numeric field numbers."""
    result: list[tuple[int, int]] = []
    position = 0
    for start, end in left:
        while position < len(right) and right[position][1] < start:
            position += 1
        cursor = start
        index = position
        while index < len(right) and right[index][0] <= end:
            other_start, other_end = right[index]
            if cursor < other_start:
                result.append((cursor, min(end, other_start - 1)))
            cursor = max(cursor, other_end + 1)
            if cursor > end:
                break
            index += 1
        if cursor <= end:
            result.append((cursor, end))
        position = index
    return result


class _Parser:
    def __init__(self, content: bytes, maximum: int, limits: ProtobufAnalysisLimits):
        self.tokens = _tokens(content, maximum, limits.max_tokens)
        self.offset = self.nodes = 0
        self.limit = limits.max_nodes
        self.package = ""
        self.messages: dict[str, dict[str, Any]] = {}
        self.services: dict[str, dict[str, Any]] = {}

    def peek(self) -> str:
        return self.tokens[self.offset] if self.offset < len(self.tokens) else ""

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if not token or (expected is not None and token != expected):
            raise ProtobufAnalysisError("proto source is malformed or unsupported")
        self.offset += 1
        return token

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > self.limit:
            raise ProtobufAnalysisError("proto source exceeds AST node limit")

    def identifier(self) -> str:
        return _name(self.take())

    def qualified(self, *, absolute: bool = False) -> str:
        prefix = ""
        if absolute and self.peek() == ".":
            self.take(".")
            prefix = "."
        parts = [self.identifier()]
        while self.peek() == ".":
            self.take(".")
            parts.append(self.identifier())
        return prefix + _full_name(".".join(parts))

    def number(self, *, field: bool = False) -> int:
        token = self.take()
        if not token.isascii() or not token.isdecimal() or len(token) > 9 or token[0] == "0":
            raise ProtobufAnalysisError("tag must use a bounded positive decimal literal")
        number = int(token)
        if number > MAX_FIELD_NUMBER or (field and 19000 <= number <= 19999):
            raise ProtobufAnalysisError("field number is invalid or implementation-reserved")
        return number

    def type_name(self) -> str:
        if self.peek() in _SCALARS:
            return self.take()
        return self.qualified(absolute=True)

    def definition_name(self) -> str:
        name = self.identifier()
        full = _full_name(self.package + "." + name if self.package else name)
        if full in self.messages or full in self.services:
            raise ProtobufAnalysisError("top-level definition is duplicated")
        return full

    def message(self) -> None:
        self.take("message")
        self.node()
        name = self.definition_name()
        self.take("{")
        fields: dict[str, dict[str, Any]] = {}
        numbers: set[int] = set()
        ranges: list[tuple[int, int]] = []
        reserved_names: set[str] = set()
        while self.peek() != "}":
            if self.peek() == ";":
                self.take(";")
                continue
            if self.peek() == "reserved":
                self.take("reserved")
                names = self.peek().startswith('"')
                while True:
                    self.node()
                    if names:
                        token = self.take()
                        if not token.startswith('"') or not token.endswith('"'):
                            raise ProtobufAnalysisError("reserved names and numbers cannot mix")
                        selected = _name(token[1:-1])
                        if selected in reserved_names:
                            raise ProtobufAnalysisError("reserved name is duplicated")
                        reserved_names.add(selected)
                    else:
                        start = end = self.number()
                        if self.peek() == "to":
                            self.take("to")
                            if self.peek() == "max":
                                self.take("max")
                                end = MAX_FIELD_NUMBER
                            else:
                                end = self.number()
                        if start > end:
                            raise ProtobufAnalysisError("reserved range is reversed")
                        ranges.append((start, end))
                    if self.peek() != ",":
                        break
                    self.take(",")
                self.take(";")
                continue
            self.node()
            modifier = self.take() if self.peek() in {"optional", "repeated"} else "implicit"
            field_type = self.type_name()
            field_name = self.identifier()
            self.take("=")
            number = self.number(field=True)
            self.take(";")
            if field_name in fields or number in numbers:
                raise ProtobufAnalysisError("field name or number is duplicated")
            fields[field_name] = {
                "kind": "field",
                "name": field_name,
                "number": number,
                "type": field_type,
                "modifier": modifier,
            }
            numbers.add(number)
        self.take("}")
        ranges = _normalize_ranges(ranges)
        if any(
            key in reserved_names or _range_at(ranges, field["number"]) is not None
            for key, field in fields.items()
        ):
            raise ProtobufAnalysisError("field uses its own reserved name or number")
        self.messages[name] = {
            "name": name,
            "fields": fields,
            "ranges": ranges,
            "reserved_names": reserved_names,
        }

    def service(self) -> None:
        self.take("service")
        self.node()
        name = self.definition_name()
        self.take("{")
        methods: dict[str, dict[str, Any]] = {}
        while self.peek() != "}":
            if self.peek() == ";":
                self.take(";")
                continue
            self.take("rpc")
            self.node()
            method = self.identifier()
            self.take("(")
            client = self.peek() == "stream"
            if client:
                self.take("stream")
            input_type = self.qualified(absolute=True)
            self.take(")")
            self.take("returns")
            self.take("(")
            server = self.peek() == "stream"
            if server:
                self.take("stream")
            output_type = self.qualified(absolute=True)
            self.take(")")
            self.take(";")
            if method in methods:
                raise ProtobufAnalysisError("RPC name is duplicated")
            methods[method] = {
                "kind": "rpc",
                "name": method,
                "input_type": input_type,
                "output_type": output_type,
                "client_streaming": client,
                "server_streaming": server,
            }
        self.take("}")
        self.services[name] = {"name": name, "methods": methods}

    def resolve(self, token: str) -> str:
        if token.startswith("."):
            name = token[1:]
        elif "." in token:
            raise ProtobufAnalysisError("relative qualified type references are unsupported")
        else:
            name = self.package + "." + token if self.package else token
        if name not in self.messages:
            raise ProtobufAnalysisError("type must resolve to a local top-level message")
        return name

    def parse(self) -> _Parser:
        self.node()
        self.take("syntax")
        self.take("=")
        self.take('"proto3"')
        self.take(";")
        while self.peek() == ";":
            self.take(";")
        if self.peek() == "package":
            self.take("package")
            self.node()
            self.package = self.qualified()
            self.take(";")
        while self.peek():
            if self.peek() == ";":
                self.take(";")
            elif self.peek() == "message":
                self.message()
            elif self.peek() == "service":
                self.service()
            else:
                raise ProtobufAnalysisError("top-level construct is unsupported")
        for message in self.messages.values():
            for field in message["fields"].values():
                scalar = field["type"] in _SCALARS
                if not scalar:
                    field["type"] = self.resolve(field["type"])
                modifier = field.pop("modifier")
                repeated = modifier == "repeated"
                field.update(
                    {
                        "type_kind": "scalar" if scalar else "message",
                        "cardinality": "repeated" if repeated else "singular",
                        "presence": "repeated"
                        if repeated
                        else "explicit"
                        if not scalar or modifier == "optional"
                        else "implicit",
                        "base_wire_type": _SCALARS[field["type"]] if scalar else 2,
                        "packed_by_default": repeated
                        and scalar
                        and field["type"] not in {"string", "bytes"},
                    }
                )
        for service in self.services.values():
            for method in service["methods"].values():
                method["input_type"] = self.resolve(method["input_type"])
                method["output_type"] = self.resolve(method["output_type"])
        return self

    def statistics(self) -> dict[str, int]:
        return {
            "message_count": len(self.messages),
            "field_count": sum(len(item["fields"]) for item in self.messages.values()),
            "service_count": len(self.services),
            "rpc_count": sum(len(item["methods"]) for item in self.services.values()),
            "token_count": len(self.tokens),
            "ast_node_count": self.nodes,
        }


def _interval(pair: tuple[int, int]) -> dict[str, Any]:
    return {"kind": "reserved_range", "start": pair[0], "end": pair[1]}


def _reserved_name(name: str) -> dict[str, str]:
    return {"kind": "reserved_name", "name": name}


def _summary(item: dict[str, Any], kind: str) -> dict[str, Any]:
    if kind == "message":
        return {
            "kind": kind,
            "name": item["name"],
            "field_count": len(item["fields"]),
            "reserved_ranges": [list(pair) for pair in item["ranges"]],
            "reserved_names": sorted(item["reserved_names"]),
        }
    return {"kind": kind, "name": item["name"], "rpc_count": len(item["methods"])}


def _compare(previous: _Parser, current: _Parser, maximum: int) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []

    def add(change: str, symbol: str, old: Any, new: Any) -> None:
        if len(observations) >= maximum:
            raise ProtobufAnalysisError("analysis exceeds observation limit")
        observations.append({"change": change, "symbol": symbol, "previous": old, "current": new})

    def attributes(symbol: str, before: dict[str, Any], after: dict[str, Any]) -> None:
        if before["type"] != after["type"] or before["type_kind"] != after["type_kind"]:
            change = (
                "field_base_wire_type_changed"
                if before["base_wire_type"] != after["base_wire_type"]
                else "field_type_changed_same_base_wire_type"
            )
            add(change, symbol, before, after)
        for attribute in ("cardinality", "presence"):
            if before[attribute] != after[attribute]:
                add("field_" + attribute + "_changed", symbol, before, after)

    for kind, old_items, new_items in (
        ("message", previous.messages, current.messages),
        ("service", previous.services, current.services),
    ):
        for name in sorted(old_items.keys() - new_items.keys()):
            add(kind + "_removed", name, _summary(old_items[name], kind), None)
        for name in sorted(new_items.keys() - old_items.keys()):
            add(kind + "_added", name, None, _summary(new_items[name], kind))
    for name in sorted(previous.messages.keys() & current.messages.keys()):
        old = previous.messages[name]
        new = current.messages[name]
        old_fields, new_fields = old["fields"], new["fields"]
        old_tags = {field["number"]: field for field in old_fields.values()}
        new_tags = {field["number"]: field for field in new_fields.values()}
        for field_name in sorted(old_fields.keys() - new_fields.keys()):
            field = old_fields[field_name]
            add("field_removed", name + "." + field_name, field, None)
            if field_name not in new["reserved_names"]:
                add("removed_field_name_not_reserved", name + "." + field_name, field, None)
        for field_name in sorted(new_fields.keys() - old_fields.keys()):
            field = new_fields[field_name]
            add("field_added", name + "." + field_name, None, field)
        for field_name in sorted(old_fields.keys() & new_fields.keys()):
            before, after = old_fields[field_name], new_fields[field_name]
            symbol = name + "." + field_name
            if before["number"] != after["number"]:
                add("field_number_changed", symbol, before, after)
            attributes(symbol, before, after)
        for number in sorted(old_tags.keys() & new_tags.keys()):
            if old_tags[number]["name"] != new_tags[number]["name"]:
                symbol = name + ".#" + str(number)
                add(
                    "field_name_changed_at_number",
                    symbol,
                    old_tags[number],
                    new_tags[number],
                )
                attributes(symbol, old_tags[number], new_tags[number])
        for number in sorted(old_tags.keys() - new_tags.keys()):
            if _range_at(new["ranges"], number) is None:
                add(
                    "removed_field_number_not_reserved",
                    name + ".#" + str(number),
                    old_tags[number],
                    None,
                )
        for field in sorted(new_fields.values(), key=lambda item: item["number"]):
            reserved = _range_at(old["ranges"], field["number"])
            if reserved is not None:
                add(
                    "reserved_number_reused",
                    name + ".#" + str(field["number"]),
                    _interval(reserved),
                    field,
                )
            if field["name"] in old["reserved_names"]:
                add(
                    "reserved_name_reused",
                    name + "." + field["name"],
                    _reserved_name(field["name"]),
                    field,
                )
        for pair in _subtract(old["ranges"], new["ranges"]):
            add("reserved_numbers_released", name, _interval(pair), None)
        for pair in _subtract(new["ranges"], old["ranges"]):
            add("reserved_numbers_added", name, None, _interval(pair))
        for reserved in sorted(old["reserved_names"] - new["reserved_names"]):
            add("reserved_name_released", name, _reserved_name(reserved), None)
        for reserved in sorted(new["reserved_names"] - old["reserved_names"]):
            add("reserved_name_added", name, None, _reserved_name(reserved))
    for name in sorted(previous.services.keys() & current.services.keys()):
        old = previous.services[name]["methods"]
        new = current.services[name]["methods"]
        for method in sorted(old.keys() - new.keys()):
            add("rpc_removed", name + "." + method, old[method], None)
        for method in sorted(new.keys() - old.keys()):
            add("rpc_added", name + "." + method, None, new[method])
        for method in sorted(old.keys() & new.keys()):
            if old[method] != new[method]:
                add("rpc_signature_changed", name + "." + method, old[method], new[method])
    observations.sort(
        key=lambda item: (
            item["symbol"],
            item["change"],
            _canonical(item["previous"]),
            _canonical(item["current"]),
        )
    )
    return observations


def _artifact(raw: Any) -> None:
    if raw is None:
        return
    if type(raw) is not dict or type(raw.get("kind")) is not str:
        raise ProtobufAnalysisError("observation artifact is invalid")
    kind = raw["kind"]
    if kind == "field":
        _exact(
            raw,
            {
                "kind",
                "name",
                "number",
                "type",
                "type_kind",
                "cardinality",
                "presence",
                "base_wire_type",
                "packed_by_default",
            },
            "field artifact",
        )
        _name(raw["name"])
        number = _integer(raw["number"], MAX_FIELD_NUMBER, "field number")
        if 19000 <= number <= 19999:
            raise ProtobufAnalysisError("artifact uses implementation-reserved field number")
        scalar = raw["type_kind"] == "scalar"
        if type(raw["type_kind"]) is not str or raw["type_kind"] not in {"scalar", "message"}:
            raise ProtobufAnalysisError("field type kind is invalid")
        if scalar:
            if type(raw["type"]) is not str or raw["type"] not in _SCALARS:
                raise ProtobufAnalysisError("scalar type is invalid")
        else:
            _full_name(raw["type"])
        if type(raw["cardinality"]) is not str or raw["cardinality"] not in {
            "singular",
            "repeated",
        }:
            raise ProtobufAnalysisError("field cardinality is invalid")
        repeated = raw["cardinality"] == "repeated"
        if (
            type(raw["presence"]) is not str
            or raw["presence"] not in {"implicit", "explicit", "repeated"}
            or (repeated and raw["presence"] != "repeated")
            or (
                not repeated
                and (
                    raw["presence"] == "repeated" or (not scalar and raw["presence"] != "explicit")
                )
            )
        ):
            raise ProtobufAnalysisError("field presence is invalid")
        _integer(raw["base_wire_type"], 5, "base wire type", minimum=0)
        expected = _SCALARS[raw["type"]] if scalar else 2
        if raw["base_wire_type"] != expected or raw["packed_by_default"] is not (
            repeated and scalar and raw["type"] not in {"string", "bytes"}
        ):
            raise ProtobufAnalysisError("field encoding declaration is inconsistent")
    elif kind == "rpc":
        _exact(
            raw,
            {"kind", "name", "input_type", "output_type", "client_streaming", "server_streaming"},
            "RPC artifact",
        )
        _name(raw["name"])
        _full_name(raw["input_type"])
        _full_name(raw["output_type"])
        if any(type(raw[key]) is not bool for key in ("client_streaming", "server_streaming")):
            raise ProtobufAnalysisError("RPC streaming flags must be native booleans")
    elif kind in {"message", "service"}:
        count = "field_count" if kind == "message" else "rpc_count"
        keys = {"kind", "name", count}
        if kind == "message":
            keys |= {"reserved_ranges", "reserved_names"}
        _exact(raw, keys, "definition artifact")
        _full_name(raw["name"])
        _integer(raw[count], MAX_ITEMS, count, minimum=0)
        if kind == "message":
            ranges = raw["reserved_ranges"]
            names = raw["reserved_names"]
            if type(ranges) is not list or type(names) is not list:
                raise ProtobufAnalysisError("reservation summaries must be native lists")
            pairs = []
            for pair in ranges:
                if type(pair) is not list or len(pair) != 2:
                    raise ProtobufAnalysisError("reserved range is invalid")
                start = _integer(pair[0], MAX_FIELD_NUMBER, "range start")
                end = _integer(pair[1], MAX_FIELD_NUMBER, "range end")
                if start > end:
                    raise ProtobufAnalysisError("reserved range is reversed")
                pairs.append((start, end))
            if pairs != _normalize_ranges(pairs):
                raise ProtobufAnalysisError("reserved ranges are not canonical")
            for name in names:
                _name(name)
            if names != sorted(set(names)):
                raise ProtobufAnalysisError("reserved names are not canonical")
    elif kind == "reserved_range":
        _exact(raw, {"kind", "start", "end"}, "range artifact")
        start = _integer(raw["start"], MAX_FIELD_NUMBER, "range start")
        end = _integer(raw["end"], MAX_FIELD_NUMBER, "range end")
        if start > end:
            raise ProtobufAnalysisError("reserved range is reversed")
    elif kind == "reserved_name":
        _exact(raw, {"kind", "name"}, "reserved name artifact")
        _name(raw["name"])
    else:
        raise ProtobufAnalysisError("artifact kind is unsupported")


def _body(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in document.items() if key not in {"report_id", "report_sha256"}
    }


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _sha(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    return {**body, "report_id": "PBA-" + digest[7:39].upper(), "report_sha256": digest}


def _validate_report(raw: Any) -> dict[str, Any]:
    _exact(
        raw,
        {
            "schema_version",
            "profile_id",
            "capability_id",
            "vector_id",
            "syntax_profile",
            "analysis_kind",
            "previous_source",
            "current_source",
            "limits",
            "statistics",
            "observation_count",
            "observations",
            "offline_only",
            "positive_use_approved",
            "qualification_claimed",
            "wire_compatibility_certified",
            "security_findings_verified",
            "effects",
            "report_id",
            "report_sha256",
        },
        "report",
    )
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ProtobufAnalysisError("report schema version must be native integer one")
    for key, expected in {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
        "analysis_kind": "schema_evolution_structure",
    }.items():
        if type(raw[key]) is not str or raw[key] != expected:
            raise ProtobufAnalysisError("report specialist or syntax binding is invalid")
    if raw["offline_only"] is not True or any(
        raw[key] is not False
        for key in (
            "positive_use_approved",
            "qualification_claimed",
            "wire_compatibility_certified",
            "security_findings_verified",
        )
    ):
        raise ProtobufAnalysisError("report makes a prohibited positive claim")
    if _exact(raw["effects"], set(_EFFECTS), "effects") != _EFFECTS:
        raise ProtobufAnalysisError("report effects must remain none")
    limits = ProtobufAnalysisLimits(**_exact(raw["limits"], set(_LIMIT_CEILINGS), "limits"))
    for side, ceiling in (
        ("previous", limits.max_previous_bytes),
        ("current", limits.max_current_bytes),
    ):
        source = _exact(raw[side + "_source"], {"source_id", "byte_count", "sha256"}, "source")
        _source_id(source["source_id"])
        _integer(source["byte_count"], ceiling, "source byte count")
        if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
            raise ProtobufAnalysisError("source digest is invalid")
    stats = _exact(raw["statistics"], _STATISTICS, "statistics")
    for key, value in stats.items():
        _integer(
            value,
            limits.max_tokens if key.endswith("token_count") else limits.max_nodes,
            key,
            minimum=1 if key.endswith(("token_count", "ast_node_count")) else 0,
        )
    count = _integer(
        raw["observation_count"], limits.max_observations, "observation count", minimum=0
    )
    observations = raw["observations"]
    if type(observations) is not list or len(observations) != count:
        raise ProtobufAnalysisError("observation count is inconsistent")
    keys = []
    for item in observations:
        _exact(item, {"change", "symbol", "previous", "current"}, "observation")
        if type(item["change"]) is not str or item["change"] not in _CHANGES:
            raise ProtobufAnalysisError("change classification is invalid")
        if type(item["symbol"]) is not str or not item["symbol"] or len(item["symbol"]) > 512:
            raise ProtobufAnalysisError("observation symbol is invalid")
        if item["previous"] is None and item["current"] is None:
            raise ProtobufAnalysisError("observation must retain structural evidence")
        _artifact(item["previous"])
        _artifact(item["current"])
        keys.append(
            (
                item["symbol"],
                item["change"],
                _canonical(item["previous"]),
                _canonical(item["current"]),
            )
        )
    if keys != sorted(set(keys)):
        raise ProtobufAnalysisError("observations must be unique and canonically ordered")
    expected = _address(_body(raw))
    if _canonical(raw) != _canonical(expected):
        raise ProtobufAnalysisError("report content address is invalid")
    return raw


@dataclass(frozen=True, slots=True)
class ProtobufAnalysisReport:
    """Unsigned metadata integrity, not source authentication or safe evolution."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise ProtobufAnalysisError("report has incomplete native slots") from exc
        return _validate_report(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> ProtobufAnalysisReport:
        return cls(_canonical(document))

    @classmethod
    def from_json(cls, document: str) -> ProtobufAnalysisReport:
        return cls(document)


def analyze_protobuf_schema_evolution(
    *,
    previous_content: bytes,
    current_content: bytes,
    previous_source_id: str,
    current_source_id: str,
    limits: ProtobufAnalysisLimits,
) -> ProtobufAnalysisReport:
    """Compare two supplied closed-subset sources without callbacks or RPCs."""
    values = _limits(limits)
    owned_limits = ProtobufAnalysisLimits(**values)
    previous_id = _source_id(previous_source_id)
    current_id = _source_id(current_source_id)
    previous = _Parser(previous_content, owned_limits.max_previous_bytes, owned_limits).parse()
    current = _Parser(current_content, owned_limits.max_current_bytes, owned_limits).parse()
    observations = _compare(previous, current, owned_limits.max_observations)
    _native_budget(observations)
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
        "analysis_kind": "schema_evolution_structure",
        "previous_source": {
            "source_id": previous_id,
            "byte_count": len(previous_content),
            "sha256": _sha(previous_content),
        },
        "current_source": {
            "source_id": current_id,
            "byte_count": len(current_content),
            "sha256": _sha(current_content),
        },
        "limits": values,
        "statistics": {
            **{"previous_" + key: value for key, value in previous.statistics().items()},
            **{"current_" + key: value for key, value in current.statistics().items()},
        },
        "observation_count": len(observations),
        "observations": observations,
        "offline_only": True,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "wire_compatibility_certified": False,
        "security_findings_verified": False,
        "effects": dict(_EFFECTS),
    }
    return ProtobufAnalysisReport.from_dict(_address(body))


def verify_protobuf_schema_evolution(
    *,
    report: ProtobufAnalysisReport,
    previous_content: bytes,
    current_content: bytes,
    previous_source_id: str,
    current_source_id: str,
    limits: ProtobufAnalysisLimits,
) -> ProtobufAnalysisReport:
    """Reproduce exactly the report from byte-current supplied sources/config."""
    if type(report) is not ProtobufAnalysisReport:
        raise ProtobufAnalysisError("report must be the exact ProtobufAnalysisReport family")
    # Source/config validation occurs before report replay or new source hashing.
    values = _limits(limits)
    for content, maximum in (
        (previous_content, values["max_previous_bytes"]),
        (current_content, values["max_current_bytes"]),
    ):
        if type(content) is not bytes or not content or len(content) > maximum:
            raise ProtobufAnalysisError("proto source must be bounded nonempty native bytes")
    _source_id(previous_source_id)
    _source_id(current_source_id)
    actual = report.to_json()
    expected = analyze_protobuf_schema_evolution(
        previous_content=previous_content,
        current_content=current_content,
        previous_source_id=previous_source_id,
        current_source_id=current_source_id,
        limits=ProtobufAnalysisLimits(**values),
    )
    if actual != expected.to_json():
        raise ProtobufAnalysisError("report does not reproduce supplied sources and configuration")
    return ProtobufAnalysisReport.from_json(actual)


__all__ = [
    "ProtobufAnalysisError",
    "ProtobufAnalysisLimits",
    "ProtobufAnalysisReport",
    "analyze_protobuf_schema_evolution",
    "verify_protobuf_schema_evolution",
]
