"""Bounded structural analysis of supplied query and local output-type sources."""

from __future__ import annotations

import hashlib
import heapq
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S02"
CAPABILITY_ID = "army.gb.d06.s02"
VECTOR_ID = "AV-GB-D06-S02-01"
DOMAIN = "sunderkey.offline-graphql-analysis.v1"
SYNTAX_PROFILE = "query-object-selection-subset.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_ITEMS = 50_000
MAX_EXPANDED_SELECTIONS = 1_000_000
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,127}\Z")
_LEX_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LIMIT_FIELDS = {
    "max_schema_bytes",
    "max_query_bytes",
    "max_depth",
    "max_tokens",
    "max_nodes",
    "max_expanded_selections",
}
_METRIC_FIELDS = {
    "schema_type_count",
    "schema_field_count",
    "operation_count",
    "fragment_count",
    "selected_ast_field_count",
    "expanded_field_count",
    "expanded_alias_count",
    "expanded_fragment_spread_count",
    "max_field_depth",
    "max_list_layers_on_path",
    "max_sibling_field_occurrences",
}
_EFFECTS = {
    "authority": "none",
    "target": "none",
    "execution": "none",
    "routing": "none",
    "qualification": "none",
    "deployment": "none",
}


class GraphQLAnalysisError(ValueError):
    """A source, unsupported construct, replay or software bound was rejected."""


def _integer(value: Any, maximum: int, label: str, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GraphQLAnalysisError(f"{label} must be a bounded native integer")
    return value


def _name(value: Any, label: str) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None or value.startswith("__"):
        raise GraphQLAnalysisError(f"{label} must be a supported native GraphQL name")
    return value


def _source_id(value: Any, label: str) -> str:
    if type(value) is not str or _SOURCE_ID.fullmatch(value) is None:
        raise GraphQLAnalysisError(f"{label} must be a bounded native source identifier")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != keys:
        raise GraphQLAnalysisError(f"{label} fields are invalid")
    return value


@dataclass(frozen=True, slots=True)
class GraphQLAnalysisLimits:
    """Explicit local software-cost limits, not server or target budgets."""

    max_schema_bytes: int
    max_query_bytes: int
    max_depth: int
    max_tokens: int
    max_nodes: int
    max_expanded_selections: int

    def __post_init__(self) -> None:
        _limits(self)

    def to_dict(self) -> dict[str, int]:
        return _limits(self)


def _limits(value: Any) -> dict[str, int]:
    if type(value) is not GraphQLAnalysisLimits:
        raise GraphQLAnalysisError("limits must be the exact GraphQLAnalysisLimits family")
    ceilings = {
        "max_schema_bytes": MAX_DOCUMENT_BYTES,
        "max_query_bytes": MAX_DOCUMENT_BYTES,
        "max_depth": MAX_DEPTH,
        "max_tokens": MAX_ITEMS,
        "max_nodes": MAX_ITEMS,
        "max_expanded_selections": MAX_EXPANDED_SELECTIONS,
    }
    try:
        return {
            key: _integer(getattr(value, key), maximum, key) for key, maximum in ceilings.items()
        }
    except AttributeError as exc:
        raise GraphQLAnalysisError("limits have incomplete native slots") from exc


def _native_budget(value: Any, *, max_bytes: int, max_depth: int, max_nodes: int) -> None:
    """Charge repeated subtrees and escaped ASCII bytes before serialization."""
    stack = [(value, 1)]
    nodes = 0
    size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise GraphQLAnalysisError("native document exceeds node or depth limit")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > max_nodes:
                raise GraphQLAnalysisError("native document exceeds node limit")
            if any(type(key) is not str for key in item):
                raise GraphQLAnalysisError("native document keys must be strings")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > max_nodes:
                raise GraphQLAnalysisError("native document exceeds node limit")
            size += 2 + max(0, len(item) - 1)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item) > 8192 or not item.isascii():
                raise GraphQLAnalysisError("native document string exceeds supported bounds")
            size += 2
            for character in item:
                size += 2 if character in '\\"\b\f\n\r\t' else 6 if ord(character) < 32 else 1
                if size > max_bytes:
                    raise GraphQLAnalysisError("native document exceeds byte limit")
        elif kind is int:
            if item.bit_length() > 63:
                raise GraphQLAnalysisError("native document integer exceeds supported bounds")
            size += len(str(item))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise GraphQLAnalysisError("native document contains an unsupported primitive")
        if size > max_bytes:
            raise GraphQLAnalysisError("native document exceeds byte limit")


def _canonical(value: Any) -> str:
    _native_budget(value, max_bytes=MAX_DOCUMENT_BYTES, max_depth=MAX_DEPTH, max_nodes=MAX_ITEMS)
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise GraphQLAnalysisError("JSON contains duplicate keys")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise GraphQLAnalysisError("JSON integer exceeds supported bounds")
    result = int(value)
    if result.bit_length() > 63:
        raise GraphQLAnalysisError("JSON integer exceeds supported bounds")
    return result


def _unsupported_number(value: str) -> None:
    raise GraphQLAnalysisError("JSON floats and nonfinite numbers are unsupported")


def _json(content: bytes, *, maximum: int, depth: int, nodes: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise GraphQLAnalysisError("JSON source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GraphQLAnalysisError("JSON source must be UTF-8") from exc
    # Guard native JSON recursion before invoking the decoder.
    nesting = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            nesting += 1
            if nesting > depth:
                raise GraphQLAnalysisError("JSON source exceeds depth limit")
        elif character in "]}":
            nesting -= 1
    try:
        document = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, GraphQLAnalysisError):
            raise
        raise GraphQLAnalysisError("JSON source is malformed") from exc
    _native_budget(document, max_bytes=maximum, max_depth=depth, max_nodes=nodes)
    return document


@dataclass(frozen=True, slots=True)
class _Type:
    base: str
    lists: int


def _type_text(value: Any, limits: GraphQLAnalysisLimits) -> _Type:
    if type(value) is not str or not value or len(value) > 512:
        raise GraphQLAnalysisError("field type must be bounded native text")
    offset = 0

    def parse(level: int) -> _Type:
        nonlocal offset
        if level > limits.max_depth:
            raise GraphQLAnalysisError("field type exceeds depth limit")
        if offset < len(value) and value[offset] == "[":
            offset += 1
            inner = parse(level + 1)
            if offset >= len(value) or value[offset] != "]":
                raise GraphQLAnalysisError("field list type is malformed")
            offset += 1
            result = _Type(inner.base, inner.lists + 1)
        else:
            match = _LEX_NAME.match(value, offset)
            if match is None:
                raise GraphQLAnalysisError("field type is malformed")
            offset += len(match.group())
            result = _Type(_name(match.group(), "field type"), 0)
        if offset < len(value) and value[offset] == "!":
            offset += 1
        return result

    result = parse(1)
    if offset != len(value):
        raise GraphQLAnalysisError("field type contains unsupported syntax")
    return result


def _schema(content: bytes, limits: GraphQLAnalysisLimits) -> tuple[str, dict[str, Any], int]:
    raw = _exact(
        _json(
            content,
            maximum=limits.max_schema_bytes,
            depth=limits.max_depth,
            nodes=limits.max_nodes,
        ),
        {"query_type", "types"},
        "local output-type schema",
    )
    query_type = _name(raw["query_type"], "query_type")
    if type(raw["types"]) is not list or not raw["types"]:
        raise GraphQLAnalysisError("schema types must be a nonempty native list")
    types: dict[str, Any] = {}
    field_count = 0
    for definition in raw["types"]:
        _exact(definition, {"name", "kind", "fields"}, "schema type")
        name = _name(definition["name"], "type name")
        kind = definition["kind"]
        if type(kind) is not str or kind not in {"OBJECT", "SCALAR", "ENUM"}:
            raise GraphQLAnalysisError("abstract and input schema kinds are unsupported")
        if name in types:
            raise GraphQLAnalysisError("schema type names must be unique")
        if type(definition["fields"]) is not list:
            raise GraphQLAnalysisError("type fields must be a native list")
        if (kind == "OBJECT") != bool(definition["fields"]):
            raise GraphQLAnalysisError("objects require fields and leaf types cannot have fields")
        fields: dict[str, _Type] = {}
        for field in definition["fields"]:
            _exact(field, {"name", "type"}, "schema field")
            field_name = _name(field["name"], "field name")
            if field_name in fields:
                raise GraphQLAnalysisError("schema field names must be unique")
            fields[field_name] = _type_text(field["type"], limits)
            field_count += 1
        types[name] = (kind, fields)
    if query_type not in types or types[query_type][0] != "OBJECT":
        raise GraphQLAnalysisError("query root must be a declared object")
    for _kind, fields in types.values():
        if any(item.base not in types for item in fields.values()):
            raise GraphQLAnalysisError("field type references an undefined local type")
    return query_type, types, field_count


@dataclass(frozen=True, slots=True)
class _Selection:
    name: str
    alias: str | None
    children: tuple[_Selection, ...]
    spread: bool = False


class _Parser:
    def __init__(self, content: bytes, limits: GraphQLAnalysisLimits) -> None:
        if type(content) is not bytes or not content or len(content) > limits.max_query_bytes:
            raise GraphQLAnalysisError("query source must be bounded nonempty native bytes")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GraphQLAnalysisError("query source must be UTF-8") from exc
        self.limits = limits
        self.tokens: list[str] = []
        self.offset = 0
        self.nodes = 0
        position = 0
        while position < len(text):
            character = text[position]
            if character in " \t\r\n,\ufeff":
                position += 1
                continue
            if character == "#":
                while position < len(text) and text[position] not in "\r\n":
                    position += 1
                continue
            if text.startswith("...", position):
                token = "..."
            elif character in "{}:":
                token = character
            else:
                match = _LEX_NAME.match(text, position)
                if match is None:
                    raise GraphQLAnalysisError("query contains unsupported syntax")
                token = _name(match.group(), "query name")
            self.tokens.append(token)
            if len(self.tokens) > limits.max_tokens:
                raise GraphQLAnalysisError("query exceeds token limit")
            position += len(token)

    def _peek(self) -> str | None:
        return self.tokens[self.offset] if self.offset < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> str:
        value = self._peek()
        if value is None or (expected is not None and value != expected):
            raise GraphQLAnalysisError("query syntax is malformed or unsupported")
        self.offset += 1
        return value

    def _node(self) -> None:
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise GraphQLAnalysisError("query exceeds node limit")

    def _selection_set(self, depth: int) -> tuple[_Selection, ...]:
        if depth > self.limits.max_depth:
            raise GraphQLAnalysisError("query exceeds selection depth limit")
        self._take("{")
        selections: list[_Selection] = []
        while self._peek() != "}":
            self._node()
            if self._peek() == "...":
                self._take("...")
                name = _name(self._take(), "fragment spread")
                if name == "on":
                    raise GraphQLAnalysisError("inline fragments are unsupported")
                selections.append(_Selection(name, None, (), True))
            else:
                name = _name(self._take(), "selected field")
                alias = None
                if self._peek() == ":":
                    self._take(":")
                    alias, name = name, _name(self._take(), "selected field")
                children = self._selection_set(depth + 1) if self._peek() == "{" else ()
                selections.append(_Selection(name, alias, children))
        self._take("}")
        if not selections:
            raise GraphQLAnalysisError("selection sets must not be empty")
        return tuple(selections)

    def document(self) -> tuple[dict[str | None, Any], dict[str, Any]]:
        operations: dict[str | None, Any] = {}
        fragments: dict[str, Any] = {}
        while self._peek() is not None:
            self._node()
            token = self._peek()
            if token == "{":
                name = None
                selections = self._selection_set(1)
            elif token == "query":
                self._take("query")
                name = None if self._peek() == "{" else _name(self._take(), "operation name")
                selections = self._selection_set(1)
            elif token == "fragment":
                self._take("fragment")
                name = _name(self._take(), "fragment name")
                if name == "on" or name in fragments:
                    raise GraphQLAnalysisError("fragment names are invalid or duplicated")
                self._take("on")
                type_name = _name(self._take(), "fragment type condition")
                fragments[name] = (type_name, self._selection_set(1))
                continue
            else:
                raise GraphQLAnalysisError(
                    "only query operations and named fragments are supported"
                )
            if name in operations:
                raise GraphQLAnalysisError("operation names must be unique")
            operations[name] = selections
        if not operations or (None in operations and len(operations) != 1):
            raise GraphQLAnalysisError("a lone anonymous or selected named query is required")
        return operations, fragments


def _spreads(selections: tuple[_Selection, ...]) -> set[str]:
    names: set[str] = set()
    stack = list(selections)
    while stack:
        selection = stack.pop()
        if selection.spread:
            names.add(selection.name)
        else:
            stack.extend(selection.children)
    return names


def _fragment_order(
    operations: dict[str | None, Any], fragments: dict[str, Any], maximum: int
) -> list[str]:
    dependencies = {name: _spreads(value[1]) for name, value in fragments.items()}
    operation_spreads = set().union(*(_spreads(value) for value in operations.values()))
    all_spreads = operation_spreads | set().union(*dependencies.values())
    if all_spreads - set(fragments):
        raise GraphQLAnalysisError("query references an undefined fragment")
    parents: dict[str, set[str]] = {name: set() for name in fragments}
    degree = {name: len(children) for name, children in dependencies.items()}
    for name, children in dependencies.items():
        for child in children:
            parents[child].add(name)
    ready = [name for name, count in degree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[str] = []
    depths: dict[str, int] = {}
    while ready:
        name = heapq.heappop(ready)
        ordered.append(name)
        depths[name] = 1 + max((depths[child] for child in dependencies[name]), default=0)
        if depths[name] > maximum:
            raise GraphQLAnalysisError("fragment dependency graph exceeds depth limit")
        for parent in sorted(parents[name]):
            degree[parent] -= 1
            if degree[parent] == 0:
                heapq.heappush(ready, parent)
    if len(ordered) != len(fragments):
        raise GraphQLAnalysisError("fragment graph contains a cycle, including unused fragments")
    reachable = set(operation_spreads)
    stack = list(reachable)
    while stack:
        name = stack.pop()
        for child in dependencies[name] - reachable:
            reachable.add(child)
            stack.append(child)
    if reachable != set(fragments):
        raise GraphQLAnalysisError("unused fragments are unsupported")
    return ordered


@dataclass(frozen=True, slots=True)
class _Summary:
    fields: int
    aliases: int
    spreads: int
    depth: int
    lists: int
    direct: int
    siblings: int
    depth_path: tuple[str, ...]
    list_path: tuple[str, ...]
    shapes: dict[str, tuple[str, str]]
    shape_hash: str


class _Analyzer:
    def __init__(
        self, types: dict[str, Any], fragments: dict[str, Any], limits: GraphQLAnalysisLimits
    ) -> None:
        self.types = types
        self.fragments = fragments
        self.limits = limits
        self.memo: dict[str, _Summary] = {}
        self.work = 0

    def _charge(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > self.limits.max_nodes:
            raise GraphQLAnalysisError("analysis exceeds deterministic work limit")

    def summarize(self, selections: tuple[_Selection, ...], type_name: str) -> _Summary:
        fields = aliases = spreads = depth = layers = direct = siblings = 0
        depth_path: tuple[str, ...] = ()
        list_path: tuple[str, ...] = ()
        shapes: dict[str, tuple[str, str]] = {}
        for selection in selections:
            self._charge()
            if selection.spread:
                condition = self.fragments[selection.name][0]
                if condition != type_name:
                    raise GraphQLAnalysisError(
                        "fragment type condition does not match object scope"
                    )
                part = self.memo[selection.name]
                add_spreads = part.spreads + 1
            else:
                declared = self.types[type_name][1]
                if selection.name not in declared:
                    raise GraphQLAnalysisError("query selects an undefined field")
                field_type = declared[selection.name]
                is_object = self.types[field_type.base][0] == "OBJECT"
                if bool(selection.children) != is_object:
                    raise GraphQLAnalysisError("object and leaf field selection shapes are invalid")
                child = self.summarize(selection.children, field_type.base) if is_object else None
                label = (
                    selection.name
                    if selection.alias is None
                    else f"{selection.alias}:{selection.name}"
                )
                child_hash = child.shape_hash if child else "leaf"
                part = _Summary(
                    1 + (child.fields if child else 0),
                    int(selection.alias is not None) + (child.aliases if child else 0),
                    child.spreads if child else 0,
                    1 + (child.depth if child else 0),
                    field_type.lists + (child.lists if child else 0),
                    1,
                    child.siblings if child else 0,
                    (label,) + (child.depth_path if child else ()),
                    (label,) + (child.list_path if child else ()),
                    {selection.alias or selection.name: (selection.name, child_hash)},
                    "",
                )
                add_spreads = part.spreads
            fields += part.fields
            aliases += part.aliases
            spreads += add_spreads
            direct += part.direct
            if max(fields, aliases, spreads, direct) > self.limits.max_expanded_selections:
                raise GraphQLAnalysisError("fragment expansion exceeds selection ceiling")
            if part.depth > depth or (part.depth == depth and part.depth_path < depth_path):
                depth, depth_path = part.depth, part.depth_path
            if part.lists > layers or (
                part.lists == layers and (not list_path or part.list_path < list_path)
            ):
                layers, list_path = part.lists, part.list_path
            siblings = max(siblings, part.siblings)
            for response_name, shape in part.shapes.items():
                self._charge()
                if response_name in shapes and shapes[response_name] != shape:
                    raise GraphQLAnalysisError(
                        "incompatible repeated response-key shapes are unsupported"
                    )
                shapes[response_name] = shape
        if depth > self.limits.max_depth or layers > self.limits.max_depth:
            raise GraphQLAnalysisError("expanded field or list-layer path exceeds depth limit")
        digest = hashlib.sha256()
        for response_name, (field_name, child_hash) in sorted(shapes.items()):
            self._charge()
            digest.update(f"{response_name}\0{field_name}\0{child_hash}\0".encode("ascii"))
        return _Summary(
            fields,
            aliases,
            spreads,
            depth,
            layers,
            direct,
            max(siblings, direct),
            depth_path,
            list_path,
            shapes,
            digest.hexdigest(),
        )


def _ast_field_count(selections: tuple[_Selection, ...]) -> int:
    count = 0
    stack = list(selections)
    while stack:
        selection = stack.pop()
        if not selection.spread:
            count += 1
            stack.extend(selection.children)
    return count


def _report_body(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in document.items() if key not in {"report_id", "report_sha256"}
    }


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _sha(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    return {**body, "report_id": "GQA-" + digest[7:39].upper(), "report_sha256": digest}


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
            "schema_source",
            "query_source",
            "operation_selection",
            "limits",
            "metrics",
            "witnesses",
            "offline_only",
            "positive_use_approved",
            "qualification_claimed",
            "server_cost_estimated",
            "effects",
            "report_id",
            "report_sha256",
        },
        "GraphQL analysis report",
    )
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise GraphQLAnalysisError("report schema version must be native integer one")
    fixed = {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
        "analysis_kind": "syntactic_structure",
    }
    if any(type(raw[key]) is not str or raw[key] != value for key, value in fixed.items()):
        raise GraphQLAnalysisError("report specialist or syntax binding is invalid")
    if raw["offline_only"] is not True or any(
        raw[key] is not False
        for key in ("positive_use_approved", "qualification_claimed", "server_cost_estimated")
    ):
        raise GraphQLAnalysisError("report makes a prohibited positive claim")
    if _exact(raw["effects"], set(_EFFECTS), "report effects") != _EFFECTS:
        raise GraphQLAnalysisError("report effects must remain none")
    limits = GraphQLAnalysisLimits(**_exact(raw["limits"], _LIMIT_FIELDS, "report limits"))
    for key, maximum in (
        ("schema_source", limits.max_schema_bytes),
        ("query_source", limits.max_query_bytes),
    ):
        source = _exact(raw[key], {"source_id", "byte_count", "sha256"}, key)
        _source_id(source["source_id"], key)
        _integer(source["byte_count"], maximum, key + " byte_count")
        if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
            raise GraphQLAnalysisError("report source digest is invalid")
    selected = _exact(
        raw["operation_selection"], {"requested_name", "selected_name"}, "operation selection"
    )
    for value in selected.values():
        if value is not None:
            _name(value, "operation selection")
    if (
        selected["requested_name"] is not None
        and selected["requested_name"] != selected["selected_name"]
    ):
        raise GraphQLAnalysisError("report operation selection contradicts request")
    metrics = _exact(raw["metrics"], _METRIC_FIELDS, "report metrics")
    count_fields = {
        "schema_type_count",
        "schema_field_count",
        "operation_count",
        "fragment_count",
        "selected_ast_field_count",
    }
    depth_fields = {"max_field_depth", "max_list_layers_on_path"}
    positive_fields = {
        "schema_type_count",
        "schema_field_count",
        "operation_count",
        "expanded_field_count",
        "max_field_depth",
        "max_sibling_field_occurrences",
    }
    for key, value in metrics.items():
        maximum = (
            limits.max_nodes
            if key in count_fields
            else limits.max_depth
            if key in depth_fields
            else limits.max_expanded_selections
        )
        _integer(value, maximum, key, minimum=int(key in positive_fields))
    if metrics["expanded_alias_count"] > metrics["expanded_field_count"]:
        raise GraphQLAnalysisError("alias count exceeds expanded fields")
    if metrics["max_sibling_field_occurrences"] > metrics["expanded_field_count"]:
        raise GraphQLAnalysisError("sibling count exceeds expanded fields")
    witnesses = _exact(
        raw["witnesses"], {"deepest_field_path", "most_list_layers_path"}, "report witnesses"
    )
    for path in witnesses.values():
        if type(path) is not list or len(path) > limits.max_depth:
            raise GraphQLAnalysisError("report witness path is invalid")
        for label in path:
            if type(label) is not str or len(label.split(":")) not in {1, 2}:
                raise GraphQLAnalysisError("report witness label is invalid")
            for part in label.split(":"):
                _name(part, "witness label")
    if len(witnesses["deepest_field_path"]) != metrics["max_field_depth"]:
        raise GraphQLAnalysisError("deepest witness contradicts declared depth")
    expected = _address(_report_body(raw))
    if _canonical(raw) != _canonical(expected):
        raise GraphQLAnalysisError("report content address is invalid")
    return raw


@dataclass(frozen=True, slots=True)
class GraphQLAnalysisReport:
    """Unsigned metadata integrity; source replay is a separate required check."""

    document_json: str

    def __post_init__(self) -> None:
        document = self._read()
        object.__setattr__(self, "document_json", _canonical(document))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise GraphQLAnalysisError("report has incomplete native slots") from exc
        if type(text) is not str or len(text) > MAX_DOCUMENT_BYTES:
            raise GraphQLAnalysisError("report document must be bounded native text")
        try:
            content = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise GraphQLAnalysisError("report document is not valid UTF-8 text") from exc
        return _validate_report(
            _json(content, maximum=MAX_DOCUMENT_BYTES, depth=MAX_DEPTH, nodes=MAX_ITEMS)
        )

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> GraphQLAnalysisReport:
        return cls(_canonical(document))

    @classmethod
    def from_json(cls, document: str) -> GraphQLAnalysisReport:
        return cls(document)


def analyze_graphql_operation(
    *,
    schema_content: bytes,
    query_content: bytes,
    schema_source_id: str,
    query_source_id: str,
    operation_name: str | None,
    limits: GraphQLAnalysisLimits,
) -> GraphQLAnalysisReport:
    """Analyze a closed query subset without dispatch or server-cost inference."""
    limit_values = _limits(limits)
    owned_limits = GraphQLAnalysisLimits(**limit_values)
    schema_id = _source_id(schema_source_id, "schema_source_id")
    query_id = _source_id(query_source_id, "query_source_id")
    if operation_name is not None:
        _name(operation_name, "operation_name")
    query_type, types, field_count = _schema(schema_content, owned_limits)
    operations, fragments = _Parser(query_content, owned_limits).document()
    if operation_name is None:
        if len(operations) != 1:
            raise GraphQLAnalysisError("multiple query operations require an explicit selection")
        selected_name = next(iter(operations))
    elif operation_name not in operations:
        raise GraphQLAnalysisError("selected query operation is undefined")
    else:
        selected_name = operation_name
    order = _fragment_order(operations, fragments, owned_limits.max_depth)
    analyzer = _Analyzer(types, fragments, owned_limits)
    for name in order:
        condition, selections = fragments[name]
        if condition not in types or types[condition][0] != "OBJECT":
            raise GraphQLAnalysisError("fragment condition must name a declared object")
        analyzer.memo[name] = analyzer.summarize(selections, condition)
    summaries = {
        name: analyzer.summarize(selections, query_type) for name, selections in operations.items()
    }
    summary = summaries[selected_name]
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
        "analysis_kind": "syntactic_structure",
        "schema_source": {
            "source_id": schema_id,
            "byte_count": len(schema_content),
            "sha256": _sha(schema_content),
        },
        "query_source": {
            "source_id": query_id,
            "byte_count": len(query_content),
            "sha256": _sha(query_content),
        },
        "operation_selection": {"requested_name": operation_name, "selected_name": selected_name},
        "limits": limit_values,
        "metrics": {
            "schema_type_count": len(types),
            "schema_field_count": field_count,
            "operation_count": len(operations),
            "fragment_count": len(fragments),
            "selected_ast_field_count": _ast_field_count(operations[selected_name]),
            "expanded_field_count": summary.fields,
            "expanded_alias_count": summary.aliases,
            "expanded_fragment_spread_count": summary.spreads,
            "max_field_depth": summary.depth,
            "max_list_layers_on_path": summary.lists,
            "max_sibling_field_occurrences": summary.siblings,
        },
        "witnesses": {
            "deepest_field_path": list(summary.depth_path),
            "most_list_layers_path": list(summary.list_path),
        },
        "offline_only": True,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "server_cost_estimated": False,
        "effects": dict(_EFFECTS),
    }
    return GraphQLAnalysisReport.from_dict(_address(body))


def verify_graphql_operation_analysis(
    report: GraphQLAnalysisReport,
    *,
    schema_content: bytes,
    query_content: bytes,
    schema_source_id: str,
    query_source_id: str,
    operation_name: str | None,
    limits: GraphQLAnalysisLimits,
) -> GraphQLAnalysisReport:
    """Reproduce exact source/configuration-bound metadata, not live authority."""
    if type(report) is not GraphQLAnalysisReport:
        raise GraphQLAnalysisError("report must be the exact GraphQLAnalysisReport family")
    captured = report.to_json()
    expected = analyze_graphql_operation(
        schema_content=schema_content,
        query_content=query_content,
        schema_source_id=schema_source_id,
        query_source_id=query_source_id,
        operation_name=operation_name,
        limits=limits,
    )
    if captured != expected.to_json():
        raise GraphQLAnalysisError(
            "GraphQL analysis does not reproduce supplied sources and limits"
        )
    return GraphQLAnalysisReport.from_json(expected.to_json())


__all__ = [
    "CAPABILITY_ID",
    "DOMAIN",
    "GraphQLAnalysisError",
    "GraphQLAnalysisLimits",
    "GraphQLAnalysisReport",
    "PROFILE_ID",
    "SYNTAX_PROFILE",
    "VECTOR_ID",
    "analyze_graphql_operation",
    "verify_graphql_operation_analysis",
]
