"""Pure MQTT 3.1.1 supplied topic/filter matching and symbolic overlap arithmetic."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "mqtt_supplied_topic_filter_arithmetic"
PROFILE_ID = "AOE-GD-D18-S15"
CAPABILITY_ID = "army.gd.d18.s15"
VECTOR_ID = "AV-GD-D18-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S15"
WAVE_ID = "IW2-019"
COMMANDER_PROFILE_ID = "AOE-GD-D18-CMD"
GROUP_COMMANDER_PROFILE_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:a3e9ff84eaf62017510d6009eb674c0e8790538e96ad8a9bd86a99b0c4c9af3b"
SEMANTICS_PROFILE = "oasis-mqtt-3.1.1-topic-filter-arithmetic.v1"
DOMAIN = "sunderkey.offline-mqtt-topic-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-mqtt-topic-model.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 12_288
MAX_DEPTH = 16
MAX_STRING_BYTES = 4096
MAX_LEVELS = 64
MAX_FILTERS = 128
MAX_TOPICS = 128
MAX_MATCH_QUERIES = 512
MAX_OVERLAP_QUERIES = 256
MAX_WORK = 33_554_432
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "MQT-" + "0" * 32
_FIELDS = {
    "schema_version",
    "protocol_version",
    "filters",
    "topics",
    "match_queries",
    "overlap_queries",
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "network",
        "provider",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "broker_behavior_proven",
        "topic_authorization_proven",
        "subscription_or_delivery_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "All source strings and identities are caller supplied, not authenticated broker data.",
    "Only MQTT 3.1.1 topic-name and topic-filter arithmetic is evaluated.",
    "MQTT 5 shared subscriptions are not interpreted; their text remains ordinary 3.1.1 text.",
    "No broker ACL, authentication, session, QoS, delivery, CoAP or network behavior is proven.",
    "Case, empty levels and exact Unicode spelling are preserved without normalization.",
    "Controls and noncharacters carry SHOULD-level cautions, not universal protocol invalidity.",
    "No bounded witness is distinct from mathematical filter disjointness.",
    "The source address binds canonical parsed JSON, not original raw JSON byte provenance.",
    "Software byte, level, result and work ceilings are narrower than full protocol limits.",
    "Simultaneous maximum combinations need not fit all public operation budgets.",
    "No current authority, external effects, qualification or complete specialist is claimed.",
)


class MqttTopicAnalysisError(ValueError):
    """An exact supplied contract, software ceiling or complete source replay was rejected."""


@dataclass
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise MqttTopicAnalysisError("Cumulative operation work budget exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _width(code: int) -> int:
    if code <= 0x7F:
        return 1
    if code <= 0x7FF:
        return 2
    return 3 if code <= 0xFFFF else 4


def _string_size(value: str, budget: _Budget) -> tuple[int, int]:
    if len(value) > MAX_STRING_BYTES:
        raise MqttTopicAnalysisError("String codepoint software ceiling exceeded")
    utf8 = 0
    escaped = 2
    for char in value:
        budget.charge(1)
        code = ord(char)
        if code == 0 or 0xD800 <= code <= 0xDFFF:
            raise MqttTopicAnalysisError("NUL and surrogate codepoints are rejected")
        utf8 += _width(code)
        if utf8 > MAX_STRING_BYTES:
            raise MqttTopicAnalysisError("String UTF-8 software ceiling exceeded")
        if char in '\\"' or char in "\b\t\n\f\r":
            escaped += 2
        elif 32 <= code <= 126:
            escaped += 1
        else:
            escaped += 6 if code <= 0xFFFF else 12
    return utf8, escaped


def _capture(
    value: Any,
    budget: _Budget,
    *,
    report: bool = False,
    byte_limit: int | None = None,
    node_limit: int | None = None,
) -> tuple[Any, int, int]:
    """Bound repeated native occurrences before copying or canonical serialization."""
    bytes_left = (
        (MAX_REPORT_BYTES if report else MAX_MODEL_BYTES) if byte_limit is None else byte_limit
    )
    nodes_left = (
        (MAX_REPORT_NODES if report else MAX_MODEL_NODES) if node_limit is None else node_limit
    )
    size = nodes = 0
    active: set[int] = set()

    def charge_size(amount: int) -> None:
        nonlocal size
        if amount > bytes_left - size:
            raise MqttTopicAnalysisError("Canonical escaped document byte ceiling exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > nodes_left or depth > MAX_DEPTH:
            raise MqttTopicAnalysisError("Native node/depth software ceiling exceeded")
        kind = type(item)
        if kind is str:
            _, escaped = _string_size(item, budget)
            charge_size(escaped)
            return item
        if kind is bool:
            charge_size(4 if item else 5)
            return item
        if item is None:
            charge_size(4)
            return None
        if kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise MqttTopicAnalysisError("Signed 64-bit native integers required")
            budget.charge(20)
            charge_size(len(str(item)))
            return item
        if kind not in (list, dict):
            raise MqttTopicAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise MqttTopicAnalysisError("Cyclic native documents are rejected")
        children = len(item) * (2 if kind is dict else 1)
        if children > nodes_left - nodes:
            raise MqttTopicAnalysisError("Collection exceeds remaining native node ceiling")
        charge_size(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise MqttTopicAnalysisError("Exact native text keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise MqttTopicAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise MqttTopicAnalysisError("Raw signed 64-bit integer ceiling exceeded")
    return int(text)


def _hex(text: str, start: int) -> int:
    digits = text[start : start + 4]
    if len(digits) != 4 or any(char not in "0123456789abcdefABCDEF" for char in digits):
        raise MqttTopicAnalysisError("Malformed JSON Unicode escape")
    return int(digits, 16)


def _raw_string(text: str, start: int, budget: _Budget) -> int:
    index = start + 1
    utf8 = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        budget.charge(1)
        if char == "\\":
            index += 1
            if index >= len(text):
                raise MqttTopicAnalysisError("Incomplete JSON escape")
            escape = text[index]
            if escape == "u":
                code = _hex(text, index + 1)
                index += 4
                if 0xD800 <= code <= 0xDBFF:
                    if text[index + 1 : index + 3] != "\\u":
                        raise MqttTopicAnalysisError("Unpaired high JSON surrogate")
                    low = _hex(text, index + 3)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise MqttTopicAnalysisError("Invalid JSON surrogate pair")
                    code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                    index += 6
                elif 0xDC00 <= code <= 0xDFFF:
                    raise MqttTopicAnalysisError("Unpaired low JSON surrogate")
            else:
                escapes = {
                    '"': 34,
                    "\\": 92,
                    "/": 47,
                    "b": 8,
                    "f": 12,
                    "n": 10,
                    "r": 13,
                    "t": 9,
                }
                if escape not in escapes:
                    raise MqttTopicAnalysisError("Malformed JSON escape")
                code = escapes[escape]
        else:
            code = ord(char)
            if code < 32 or 0xD800 <= code <= 0xDFFF:
                raise MqttTopicAnalysisError("Invalid literal JSON string character")
        if code == 0:
            raise MqttTopicAnalysisError("NUL in JSON strings is rejected")
        utf8 += _width(code)
        if utf8 > MAX_STRING_BYTES:
            raise MqttTopicAnalysisError("Pre-decoder UTF-8 string ceiling exceeded")
        index += 1
    raise MqttTopicAnalysisError("Unterminated JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    nodes_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > limit:
        raise MqttTopicAnalysisError("Bounded exact native JSON text required")
    raw_size = 0
    for char in text:
        budget.charge(1)
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise MqttTopicAnalysisError("Raw JSON text is not well-formed UTF-8")
        raw_size += _width(code)
        if raw_size > limit:
            raise MqttTopicAnalysisError("Raw JSON byte ceiling exceeded")
    budget.charge(raw_size)
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise MqttTopicAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > nodes_limit or len(stack) + 1 > MAX_DEPTH:
            raise MqttTopicAnalysisError("Pre-decoder node/depth ceiling exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index, budget)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise MqttTopicAnalysisError("Pre-decoder scalar lexical ceiling exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise MqttTopicAnalysisError("Unterminated raw JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in rows:
            if key in owned:
                raise MqttTopicAnalysisError("Duplicate JSON key")
            owned[key] = child
        return owned

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise MqttTopicAnalysisError("Invalid bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _fields(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != expected:
        raise MqttTopicAnalysisError(f"{label} requires exact closed fields")


def _rows(value: Any, maximum: int, label: str) -> None:
    if type(value) is not list or len(value) > maximum:
        raise MqttTopicAnalysisError(f"{label} exceeds its exact native array ceiling")


def _identifier(value: Any) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise MqttTopicAnalysisError("Bounded native ASCII identifiers required")


@dataclass(frozen=True)
class _Filter:
    prefix: tuple[str, ...]
    tail: bool
    root_wildcard: bool


def _levels(text: Any, budget: _Budget, *, topic: bool) -> tuple[str, ...]:
    if type(text) is not str or not text:
        raise MqttTopicAnalysisError("Nonempty native topic/filter text required")
    _string_size(text, budget)
    budget.charge(len(text))
    levels = 1
    for char in text:
        if char == "/":
            levels += 1
            if levels > MAX_LEVELS:
                raise MqttTopicAnalysisError("Topic/filter level software ceiling exceeded")
        if topic and char in "+#":
            raise MqttTopicAnalysisError("Topic names cannot contain wildcard characters")
    budget.charge(2 * (levels + len(text)))
    return tuple(text.split("/"))


def _filter(text: Any, budget: _Budget) -> _Filter:
    parts = _levels(text, budget, topic=False)
    for index, part in enumerate(parts):
        budget.charge(1 + len(part))
        if "+" in part and part != "+":
            raise MqttTopicAnalysisError("Plus must occupy a complete topic-filter level")
        if "#" in part and (part != "#" or index != len(parts) - 1):
            raise MqttTopicAnalysisError("Hash must occupy the final complete filter level")
    tail = parts[-1] == "#"
    return _Filter(parts[:-1] if tail else parts, tail, parts[0] in {"+", "#"})


def _matches(pattern: _Filter, parts: tuple[str, ...], budget: _Budget) -> bool:
    budget.charge(2 + len(parts))
    if pattern.root_wildcard and parts[0].startswith("$"):
        return False
    if len(parts) < len(pattern.prefix):
        return False
    if not pattern.tail and len(parts) != len(pattern.prefix):
        return False
    for expected, actual in zip(pattern.prefix, parts, strict=False):
        budget.charge(1 + len(expected) + len(actual))
        if expected != "+" and expected != actual:
            return False
    return True


def _overlap(left: _Filter, right: _Filter, budget: _Budget) -> dict:
    """Unify aligned literal constraints; only terminal hashes have repetition."""
    count = max(1, len(left.prefix), len(right.prefix))
    for pattern in (left, right):
        budget.charge(1)
        if not pattern.tail and count != len(pattern.prefix):
            return _overlap_row("disjoint")
    budget.charge(count)
    selected = []
    for index in range(count):
        a = left.prefix[index] if index < len(left.prefix) else "+"
        b = right.prefix[index] if index < len(right.prefix) else "+"
        budget.charge(2 + len(a) + len(b))
        if a != "+" and b != "+" and a != b:
            return _overlap_row("disjoint")
        literal = a if a != "+" else (b if b != "+" else None)
        if (
            index == 0
            and literal is not None
            and literal.startswith("$")
            and (left.root_wildcard or right.root_wildcard)
        ):
            return _overlap_row("disjoint")
        selected.append(literal)
    # A one-level empty string is not a Topic Name. Choose a shortest legal alternative.
    if count == 1 and selected[0] is None:
        selected[0] = "a"
    elif count == 1 and selected[0] == "":
        if not left.tail or not right.tail:
            return _overlap_row("disjoint")
        budget.charge(1)
        selected.append("")
        count += 1
    width = count - 1
    for part in selected:
        if part is not None:
            part_width, _ = _string_size(part, budget)
            width += part_width
    if count > MAX_LEVELS or width > MAX_STRING_BYTES:
        return _overlap_row("no_witness_within_software_topic_bounds", minimum_bytes=width)
    budget.charge(count + width)
    witness = "/".join("" if part is None else part for part in selected)
    witness_parts = _levels(witness, budget, topic=True)
    if not _matches(left, witness_parts, budget) or not _matches(right, witness_parts, budget):
        raise MqttTopicAnalysisError("Internal symbolic witness failed both mathematical matchers")
    return _overlap_row("overlap_witness", witness=witness, minimum_bytes=width, levels=count)


def _overlap_row(
    status: str,
    *,
    witness: str | None = None,
    minimum_bytes: int | None = None,
    levels: int | None = None,
) -> dict:
    return {
        "status": status,
        "witness_topic": witness,
        "minimum_witness_utf8_bytes": minimum_bytes,
        "witness_level_count": levels,
    }


@dataclass
class _Retained:
    budget: _Budget
    size: int
    nodes: int

    def append(self, rows: list, row: dict) -> None:
        punctuation = 1 if rows else 0
        self.budget.charge(punctuation)
        owned, size, nodes = _capture(
            row,
            self.budget,
            report=True,
            byte_limit=MAX_REPORT_BYTES - self.size - punctuation,
            node_limit=MAX_REPORT_NODES - self.nodes,
        )
        self.size += size + punctuation
        self.nodes += nodes
        rows.append(owned)


def _validated(model: dict, budget: _Budget) -> tuple[dict, dict, dict]:
    _fields(model, _FIELDS, "Model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MqttTopicAnalysisError("Exact native schema version one required")
    if type(model["protocol_version"]) is not str or model["protocol_version"] != "3.1.1":
        raise MqttTopicAnalysisError("Exact MQTT 3.1.1 projection required")
    filters = {}
    topics = {}
    text_sources = {}
    for field, maximum, identity, text in (
        ("filters", MAX_FILTERS, "filter_id", "topic_filter"),
        ("topics", MAX_TOPICS, "topic_id", "topic_name"),
    ):
        _rows(model[field], maximum, field)
        index = filters if field == "filters" else topics
        for row in model[field]:
            budget.charge(256)
            _fields(row, {identity, text}, field)
            _identifier(row[identity])
            if row[identity] in index:
                raise MqttTopicAnalysisError("Duplicate declared source identity")
            index[row[identity]] = (
                _filter(row[text], budget)
                if field == "filters"
                else _levels(row[text], budget, topic=True)
            )
            text_sources[(field, row[identity])] = row[text]
    query_ids = set()
    for field, maximum, refs in (
        ("match_queries", MAX_MATCH_QUERIES, {"filter_id": filters, "topic_id": topics}),
        (
            "overlap_queries",
            MAX_OVERLAP_QUERIES,
            {"left_filter_id": filters, "right_filter_id": filters},
        ),
    ):
        _rows(model[field], maximum, field)
        for row in model[field]:
            budget.charge(256)
            _fields(row, {"query_id", *refs}, field)
            _identifier(row["query_id"])
            if row["query_id"] in query_ids:
                raise MqttTopicAnalysisError("Query identities must be globally distinct")
            query_ids.add(row["query_id"])
            for ref, index in refs.items():
                _identifier(row[ref])
                if row[ref] not in index:
                    raise MqttTopicAnalysisError("Dangling exact source reference")
    return filters, topics, text_sources


def _bounds() -> dict:
    return {
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "depth": MAX_DEPTH,
        "string_utf8_bytes": MAX_STRING_BYTES,
        "topic_or_filter_levels": MAX_LEVELS,
        "filters": MAX_FILTERS,
        "topics": MAX_TOPICS,
        "match_queries": MAX_MATCH_QUERIES,
        "overlap_queries": MAX_OVERLAP_QUERIES,
        "cumulative_work_per_public_operation": MAX_WORK,
    }


@dataclass
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    owned, source_size, _ = _capture(model, budget)
    filters, topics, sources = _validated(owned, budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": COMMANDER_PROFILE_ID,
        "group_commander_profile_id": GROUP_COMMANDER_PROFILE_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": owned,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "match_results": [],
        "overlap_results": [],
        "unicode_cautions": [],
    }
    document, size, nodes = _capture(document, budget, report=True)
    retained = _Retained(budget, size, nodes)
    for count in (len(sources), len(owned["match_queries"]), len(owned["overlap_queries"])):
        # Fund key comparisons and temporary ordering arrays before any sorting allocation.
        budget.charge(256 * (count + 1) * (count.bit_length() + 1))
    for (kind, identity), text in sorted(sources.items()):
        codes = set()
        for char in text:
            budget.charge(1)
            code = ord(char)
            if 1 <= code <= 31 or 127 <= code <= 159:
                codes.add("control_character_should_not")
            if 0xFDD0 <= code <= 0xFDEF or code & 0xFFFF in {0xFFFE, 0xFFFF}:
                codes.add("noncharacter_should_not")
        if codes:
            retained.append(
                document["unicode_cautions"],
                {"source_kind": kind, "source_id": identity, "codes": sorted(codes)},
            )
    for row in sorted(owned["match_queries"], key=lambda item: item["query_id"]):
        retained.append(
            document["match_results"],
            {
                **row,
                "matches": _matches(filters[row["filter_id"]], topics[row["topic_id"]], budget),
            },
        )
    for row in sorted(owned["overlap_queries"], key=lambda item: item["query_id"]):
        retained.append(
            document["overlap_results"],
            {
                **row,
                **_overlap(filters[row["left_filter_id"]], filters[row["right_filter_id"]], budget),
            },
        )
    # Reserve the full retained output and every final encoding/hash pass before ANY digest.
    document, size, _ = _capture(document, budget, report=True)
    budget.charge(4 * size + 2 * source_size + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, size)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "MQT-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size, _ = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise MqttTopicAnalysisError("Report requires its exact embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(3 * size + expected.size)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if actual != expected or text != actual:
        raise MqttTopicAnalysisError("Canonical report does not replay its full embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not MqttTopicAnalysis or not hasattr(report, "document_json"):
        raise MqttTopicAnalysisError("Exact complete native report wrapper required")
    text = report.document_json
    if type(text) is not str:
        raise MqttTopicAnalysisError("Exact native report text required")
    return text


@dataclass(frozen=True, slots=True)
class MqttTopicAnalysis:
    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not MqttTopicAnalysis:
            raise MqttTopicAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> MqttTopicAnalysis:
        if cls is not MqttTopicAnalysis:
            raise MqttTopicAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> MqttTopicAnalysis:
        if cls is not MqttTopicAnalysis:
            raise MqttTopicAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> MqttTopicAnalysis:
    report = object.__new__(MqttTopicAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


def analyze_supplied_mqtt_topics(model: Any) -> MqttTopicAnalysis:
    """Produce detached mathematical results over supplied topic/filter declarations."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_mqtt_topics_bytes(*, model_bytes: Any) -> MqttTopicAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise MqttTopicAnalysisError("Bounded exact native UTF-8 model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MqttTopicAnalysisError("Model bytes must be well-formed UTF-8") from exc
    model, _, _ = _decode(text, budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_mqtt_topic_analysis(report: Any, *, model: Any) -> MqttTopicAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(embedded.size + original.size)
    expected = _materialize(embedded)
    original_expected = _materialize(original)
    _compare(text, document, expected)
    if expected != original_expected:
        raise MqttTopicAnalysisError("Report does not match separately supplied original model")
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh inert Unicode-preserving topics and filters, not a broker snapshot."""
    return {
        "schema_version": 1,
        "protocol_version": "3.1.1",
        "filters": [
            {"filter_id": "sensor", "topic_filter": "sensors/+/temperature"},
            {"filter_id": "branch", "topic_filter": "sensors/#"},
            {"filter_id": "root", "topic_filter": "#"},
            {"filter_id": "system", "topic_filter": "$SYS/#"},
            {"filter_id": "unicode", "topic_filter": "caf\u00e9/+"},
        ],
        "topics": [
            {"topic_id": "sensor-a", "topic_name": "sensors/a/temperature"},
            {"topic_id": "sensor-empty", "topic_name": "sensors//temperature"},
            {"topic_id": "parent", "topic_name": "sensors"},
            {"topic_id": "status", "topic_name": "$SYS/status"},
            {"topic_id": "accent", "topic_name": "caf\u00e9/"},
        ],
        "match_queries": [
            {"query_id": "sensor-a", "filter_id": "sensor", "topic_id": "sensor-a"},
            {"query_id": "empty-level", "filter_id": "sensor", "topic_id": "sensor-empty"},
            {"query_id": "parent", "filter_id": "branch", "topic_id": "parent"},
            {"query_id": "wildcard-system", "filter_id": "root", "topic_id": "status"},
            {"query_id": "literal-system", "filter_id": "system", "topic_id": "status"},
            {"query_id": "unicode", "filter_id": "unicode", "topic_id": "accent"},
        ],
        "overlap_queries": [
            {"query_id": "sensors", "left_filter_id": "sensor", "right_filter_id": "branch"},
            {"query_id": "system-root", "left_filter_id": "system", "right_filter_id": "root"},
            {"query_id": "system-self", "left_filter_id": "system", "right_filter_id": "system"},
        ],
    }
