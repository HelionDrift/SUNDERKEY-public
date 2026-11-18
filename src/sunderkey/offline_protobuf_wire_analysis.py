"""Finite Protobuf wire occurrences under separately supplied local type declarations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "protobuf_supplied_wire_occurrences"
PROFILE_ID = "AOE-GB-D06-S03"
CAPABILITY_ID = "army.gb.d06.s03"
VECTOR_ID = "AV-GB-D06-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D06-S03"
WAVE_ID = "IW2-010"
BLUEPRINT_SHA256 = "sha256:933977df53abe136c91adee12ebcd6af32865ce42d274194cddd55a3a50a9990"
SEMANTICS_PROFILE = "supplied-protobuf-tag-value-occurrences.v1"
DOMAIN = "sunderkey.offline-protobuf-wire-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-protobuf-wire-model.v1"
MAX_PAYLOAD_BYTES = 262_144
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 32_768
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_STRING_BYTES = 349_528
MAX_MESSAGES = 64
MAX_FIELDS = 4_096
MAX_OCCURRENCES = 16_384
MAX_PACKED_VALUES = 65_536
MAX_MESSAGE_DEPTH = 16
MAX_RETAINED_ANALYSIS_BYTES = 1_048_576
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_UINT64 = 2**64 - 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "root_message", "messages", "payload_base64"}
_TYPES = {
    "uint32": 0,
    "uint64": 0,
    "int32": 0,
    "int64": 0,
    "sint32": 0,
    "sint64": 0,
    "bool": 0,
    "fixed32": 5,
    "sfixed32": 5,
    "fixed64": 1,
    "sfixed64": 1,
    "string": 2,
    "bytes": 2,
    "message": 2,
}
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "PWA-" + "0" * 32
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
        "schema_authenticated",
        "canonical_protobuf_proven",
        "generated_object_equivalence_proven",
        "rpc_executed",
        "vulnerability_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "A supplied declaration supplies conditional types, not authenticated interface identity.",
    "Occurrences and original bytes are retained; no last-one-wins or message merge is applied.",
    "Repeated numeric fields accept packed, unpacked and multiple packed chunks in source order.",
    "Unknown length-delimited values stay opaque rather than being guessed to be messages.",
    "Groups, enums, floats, maps, oneof and compiler/generated-object semantics "
    "are not implemented.",
    "Tag and length varints have a five-byte supported ceiling; scalar varints have ten bytes.",
    "Nonminimal supported varints are retained, not labeled canonical or normalized.",
    "Out-of-subset typed values retain unsigned wire arithmetic and withheld interpretation.",
    "UTF-8 byte validation does not infer application meaning, URI identity or target access.",
    "The report binds exact supplied message bytes, not semantic Protobuf object equivalence.",
    "No gRPC framing, RPC request, provider call, filesystem acquisition or execution occurs.",
    "Individual input, occurrence and report maxima do not promise simultaneous publication.",
)


class ProtobufWireAnalysisError(ValueError):
    """A closed input, finite software ceiling or complete source replay was rejected."""


@dataclass
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise ProtobufWireAnalysisError("Cumulative operation work ceiling exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _string_size(value: str, budget: _Budget) -> int:
    if len(value) > MAX_STRING_BYTES:
        raise ProtobufWireAnalysisError("Native string software ceiling exceeded")
    size = 2
    for char in value:
        budget.charge(1)
        code = ord(char)
        if code > 127:
            raise ProtobufWireAnalysisError("The closed projection requires ASCII strings")
        size += 2 if char in '\\"\b\t\n\f\r' else 6 if code < 32 or code == 127 else 1
    return size


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    """Bound repeated occurrences before copying or canonical serialization."""
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def reserve(amount: int) -> None:
        nonlocal size
        if amount > maximum - size:
            raise ProtobufWireAnalysisError("Escaped native document byte ceiling exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > maximum_nodes or depth > MAX_DEPTH:
            raise ProtobufWireAnalysisError("Native node/depth ceiling exceeded")
        kind = type(item)
        if kind is str:
            reserve(_string_size(item, budget))
            return item
        if kind is bool:
            reserve(4 if item else 5)
            return item
        if item is None:
            reserve(4)
            return None
        if kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise ProtobufWireAnalysisError("Exact signed 64-bit native integer required")
            budget.charge(20)
            reserve(len(str(item)))
            return item
        if kind not in (dict, list):
            raise ProtobufWireAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise ProtobufWireAnalysisError("Cyclic native documents are rejected")
        children = len(item) * (2 if kind is dict else 1)
        if children > maximum_nodes - nodes:
            raise ProtobufWireAnalysisError("Collection exceeds remaining native node ceiling")
        reserve(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise ProtobufWireAnalysisError("Exact native text keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise ProtobufWireAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise ProtobufWireAnalysisError("Raw signed 64-bit integer ceiling exceeded")
    return int(text)


def _raw_string(text: str, start: int, budget: _Budget) -> int:
    index = start + 1
    count = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        budget.charge(1)
        if char == "\\":
            index += 1
            if index >= len(text):
                raise ProtobufWireAnalysisError("Incomplete raw JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise ProtobufWireAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise ProtobufWireAnalysisError("The closed projection requires ASCII strings")
                index += 4
            elif escape not in '\\"/bfnrt':
                raise ProtobufWireAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise ProtobufWireAnalysisError("Invalid literal JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise ProtobufWireAnalysisError("Pre-decoder string ceiling exceeded")
        index += 1
    raise ProtobufWireAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > maximum or not text.isascii():
        raise ProtobufWireAnalysisError("Bounded exact native ASCII JSON text required")
    budget.charge(2 * len(text))
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise ProtobufWireAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > maximum_nodes or len(stack) + 1 > MAX_DEPTH:
            raise ProtobufWireAnalysisError("Pre-decoder node/depth ceiling exceeded")
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
                    raise ProtobufWireAnalysisError("Pre-decoder scalar lexical ceiling exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise ProtobufWireAnalysisError("Unterminated raw JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in rows:
            if key in owned:
                raise ProtobufWireAnalysisError("Duplicate raw JSON key")
            owned[key] = child
        return owned

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ProtobufWireAnalysisError("Invalid bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_PAYLOAD_BYTES + 2) // 3):
        raise ProtobufWireAnalysisError("Bounded exact native canonical base64 required")
    budget.charge(3 * len(text) + MAX_PAYLOAD_BYTES)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtobufWireAnalysisError("Invalid supplied base64") from exc
    if len(raw) > MAX_PAYLOAD_BYTES or base64.b64encode(raw).decode("ascii") != text:
        raise ProtobufWireAnalysisError("Canonical base64 or payload software ceiling rejected")
    return raw


def _label(value: Any, budget: _Budget) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ProtobufWireAnalysisError("Bounded exact ASCII source/message label required")
    budget.charge(2 * len(value))
    if _IDENTIFIER.fullmatch(value) is None:
        raise ProtobufWireAnalysisError("Bounded exact ASCII source/message label required")
    return value


def _compile(model: dict, budget: _Budget) -> dict[str, dict[int, dict]]:
    if type(model) is not dict or set(model) != _MODEL_FIELDS:
        raise ProtobufWireAnalysisError("Exact closed wire source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ProtobufWireAnalysisError("Exact native schema version 1 required")
    _label(model["source_id"], budget)
    root = _label(model["root_message"], budget)
    messages = model["messages"]
    if type(messages) is not list or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ProtobufWireAnalysisError("Bounded nonempty finite message declarations required")
    compiled: dict[str, dict[int, dict]] = {}
    references: list[str] = []
    total_fields = 0
    for message in messages:
        budget.charge(32)
        if type(message) is not dict or set(message) != {"message_id", "fields"}:
            raise ProtobufWireAnalysisError("Exact closed message declaration required")
        name = _label(message["message_id"], budget)
        if name in compiled:
            raise ProtobufWireAnalysisError("Duplicate supplied message identity")
        fields = message["fields"]
        if type(fields) is not list or len(fields) > MAX_FIELDS - total_fields:
            raise ProtobufWireAnalysisError("Aggregate field declaration ceiling exceeded")
        total_fields += len(fields)
        indexed: dict[int, dict] = {}
        for field in fields:
            budget.charge(64)
            if type(field) is not dict or set(field) != {
                "field_number",
                "field_type",
                "repeated",
                "message_type",
            }:
                raise ProtobufWireAnalysisError("Exact closed field declaration required")
            number = field["field_number"]
            if type(number) is not int or not 1 <= number <= 536_870_911:
                raise ProtobufWireAnalysisError("Supported nonzero 29-bit field number required")
            if number in indexed:
                raise ProtobufWireAnalysisError("Duplicate field number in supplied message")
            kind = field["field_type"]
            if type(kind) is not str or kind not in _TYPES or type(field["repeated"]) is not bool:
                raise ProtobufWireAnalysisError(
                    "Supported field type and exact repeated boolean required"
                )
            nested = field["message_type"]
            if kind == "message":
                references.append(_label(nested, budget))
            elif nested is not None:
                raise ProtobufWireAnalysisError("Only message fields may name a message type")
            indexed[number] = field
        compiled[name] = indexed
    if root not in compiled or any(name not in compiled for name in references):
        raise ProtobufWireAnalysisError("All supplied message references must resolve locally")
    return compiled


def _varint(raw: bytes, offset: int, end: int, budget: _Budget, width: int = 10) -> tuple[int, int]:
    value = 0
    for count in range(width):
        budget.charge(2)
        if offset >= end:
            raise ProtobufWireAnalysisError("Truncated supplied varint")
        byte = raw[offset]
        offset += 1
        if count == 9 and byte > 1:
            raise ProtobufWireAnalysisError("Scalar varint exceeds unsigned 64-bit arithmetic")
        value |= (byte & 127) << (7 * count)
        if not byte & 128:
            return value, offset
    raise ProtobufWireAnalysisError("Varint exceeds the supported byte-width ceiling")


def _scalar(value: int, kind: str | None) -> dict:
    result = {
        "wire_unsigned_decimal": str(value),
        "declared_value_decimal": None,
        "declared_boolean": None,
        "interpretation_status": "undeclared_or_mismatched_type",
    }
    interpreted: int | None = None
    if kind in ("uint64", "fixed64") or kind in ("uint32", "fixed32") and value <= 2**32 - 1:
        interpreted = value
    elif kind == "int64" or kind == "sfixed64":
        interpreted = value if value < 2**63 else value - 2**64
    elif kind == "sfixed32":
        interpreted = value if value < 2**31 else value - 2**32
    elif kind == "int32":
        if value <= 2**31 - 1:
            interpreted = value
        elif value >= 2**64 - 2**31:
            interpreted = value - 2**64
    elif kind == "sint64" or kind == "sint32" and value <= 2**32 - 1:
        interpreted = (value >> 1) ^ -(value & 1)
    elif kind == "bool":
        if value in (0, 1):
            result["declared_boolean"] = bool(value)
            result["interpretation_status"] = "interpreted_under_supplied_declaration"
        else:
            result["interpretation_status"] = "boolean_value_outside_selected_subset"
        return result
    if interpreted is not None:
        result["declared_value_decimal"] = str(interpreted)
        result["interpretation_status"] = "interpreted_under_supplied_declaration"
    elif kind is not None:
        result["interpretation_status"] = "numeric_value_outside_selected_subset"
    return result


@dataclass
class _Scan:
    rows: list[dict]
    packed_count: int = 0
    retained_bytes: int = 0

    def retain(self, value: dict, budget: _Budget) -> dict:
        owned, size = _capture(value, budget, report=True)
        if size > MAX_RETAINED_ANALYSIS_BYTES - self.retained_bytes:
            raise ProtobufWireAnalysisError(
                "Cumulative derived observation retention ceiling exceeded"
            )
        budget.charge(size)
        self.retained_bytes += size
        return owned


def _fixed(raw: bytes, start: int, end: int, wire: int, budget: _Budget) -> tuple[int, int]:
    length = 8 if wire == 1 else 4
    budget.charge(length)
    if length > end - start:
        raise ProtobufWireAnalysisError("Truncated supplied fixed-width value")
    return int.from_bytes(raw[start : start + length], "little"), start + length


def _packed(
    raw: bytes, start: int, end: int, kind: str, scan: _Scan, budget: _Budget
) -> list[dict]:
    values: list[dict] = []
    wire = _TYPES[kind]
    while start < end:
        if scan.packed_count >= MAX_PACKED_VALUES:
            raise ProtobufWireAnalysisError("Aggregate packed scalar ceiling exceeded")
        offset = start
        if wire == 0:
            value, start = _varint(raw, start, end, budget)
        else:
            value, start = _fixed(raw, start, end, wire, budget)
        budget.charge(96)
        observation = {"value_offset": offset, "value_end_offset": start, **_scalar(value, kind)}
        values.append(scan.retain(observation, budget))
        scan.packed_count += 1
    return values


def _walk(
    raw: bytes,
    start: int,
    end: int,
    message_id: str,
    parent: int | None,
    depth: int,
    compiled: dict,
    scan: _Scan,
    budget: _Budget,
) -> None:
    if depth > MAX_MESSAGE_DEPTH:
        raise ProtobufWireAnalysisError("Supplied message nesting ceiling exceeded")
    field_counts: dict[int, int] = {}
    while start < end:
        if len(scan.rows) >= MAX_OCCURRENCES:
            raise ProtobufWireAnalysisError("Aggregate wire occurrence ceiling exceeded")
        tag_start = start
        tag, start = _varint(raw, start, end, budget, width=5)
        number, wire = tag >> 3, tag & 7
        if tag > 2**32 - 1 or not 1 <= number <= 536_870_911:
            raise ProtobufWireAnalysisError(
                "Supplied tag is outside nonzero 29-bit field arithmetic"
            )
        if wire not in (0, 1, 2, 5):
            raise ProtobufWireAnalysisError(
                "Groups or unknown wire types are outside the selected subset"
            )
        field = compiled[message_id].get(number)
        kind = None if field is None else field["field_type"]
        expected = None if kind is None else _TYPES[kind]
        compatible = expected == wire
        is_packed = field is not None and field["repeated"] and expected in (0, 1, 5) and wire == 2
        field_counts[number] = field_counts.get(number, 0) + 1
        index = len(scan.rows)
        value_start = start
        numeric = None
        if wire == 0:
            numeric, start = _varint(raw, start, end, budget)
        elif wire in (1, 5):
            numeric, start = _fixed(raw, start, end, wire, budget)
        else:
            length, start = _varint(raw, start, end, budget, width=5)
            if length > 2**31 - 1 or length > end - start:
                raise ProtobufWireAnalysisError(
                    "Length-delimited value exceeds its supplied message boundary"
                )
            value_start = start
            start += length
        budget.charge(192)
        row = {
            "occurrence_index": index,
            "parent_occurrence_index": parent,
            "message_id": message_id,
            "field_number": number,
            "occurrence_for_field": field_counts[number],
            "declared_type": kind,
            "declared_repeated": None if field is None else field["repeated"],
            "wire_type": wire,
            "tag_offset": tag_start,
            "value_offset": value_start,
            "value_end_offset": start,
            "typing_status": "unknown_field_opaque"
            if field is None
            else "declared_wire_type_mismatch",
            "numeric_value": None,
            "packed_values": [],
            "utf8_valid": None,
        }
        if compatible:
            row["typing_status"] = "interpreted_under_supplied_declaration"
        if numeric is not None:
            row["numeric_value"] = _scalar(numeric, kind if compatible else None)
            if (
                compatible
                and row["numeric_value"]["interpretation_status"]
                != "interpreted_under_supplied_declaration"
            ):
                row["typing_status"] = row["numeric_value"]["interpretation_status"]
        elif is_packed:
            row["typing_status"] = "packed_under_supplied_repeated_declaration"
            row["packed_values"] = _packed(raw, value_start, start, kind, scan, budget)
            if any(
                value["interpretation_status"] != "interpreted_under_supplied_declaration"
                for value in row["packed_values"]
            ):
                row["typing_status"] = "packed_value_outside_selected_subset"
        elif compatible and kind == "string":
            budget.charge(4 * (start - value_start))
            try:
                raw[value_start:start].decode("utf-8", errors="strict")
                row["utf8_valid"] = True
            except UnicodeDecodeError:
                row["utf8_valid"] = False
                row["typing_status"] = "invalid_utf8_under_supplied_string_declaration"
        scan.rows.append(scan.retain(row, budget))
        if compatible and kind == "message":
            _walk(
                raw,
                value_start,
                start,
                field["message_type"],
                index,
                depth + 1,
                compiled,
                scan,
                budget,
            )


@dataclass
class _Plan:
    document: dict
    size: int
    payload: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    owned, source_size = _capture(model, budget)
    compiled = _compile(owned, budget)
    raw = _wire(owned["payload_base64"], budget)
    scan = _Scan([])
    _walk(raw, 0, len(raw), owned["root_message"], None, 1, compiled, scan, budget)
    budget.charge(64 * len(scan.rows) + 512)
    unknown = sum(
        row["typing_status"]
        not in (
            "interpreted_under_supplied_declaration",
            "packed_under_supplied_repeated_declaration",
        )
        for row in scan.rows
    )
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GB-D06-CMD",
        "group_commander_profile_id": "AOE-HQ-04",
        "independent_validator_id": "AOE-HQ-34",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A2.10", "A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": owned,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "source_payload_sha256": _SHA_PLACEHOLDER,
        "source_payload_bytes": len(raw),
        "wire_occurrences": scan.rows,
        "summary": {
            "occurrences": len(scan.rows),
            "packed_values": scan.packed_count,
            "unassessed_occurrences": unknown,
        },
        "typing_status": "contains_unassessed_occurrences"
        if unknown
        else "interpreted_supplied_subset",
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": {
            "payload_bytes": MAX_PAYLOAD_BYTES,
            "model_bytes": MAX_MODEL_BYTES,
            "report_bytes": MAX_REPORT_BYTES,
            "model_nodes": MAX_MODEL_NODES,
            "report_nodes": MAX_REPORT_NODES,
            "native_depth": MAX_DEPTH,
            "string_bytes": MAX_STRING_BYTES,
            "messages": MAX_MESSAGES,
            "fields": MAX_FIELDS,
            "occurrences": MAX_OCCURRENCES,
            "packed_values": MAX_PACKED_VALUES,
            "message_depth": MAX_MESSAGE_DEPTH,
            "retained_analysis_bytes": MAX_RETAINED_ANALYSIS_BYTES,
            "cumulative_operation_work": MAX_WORK,
        },
    }
    document, size = _capture(document, budget, report=True)
    budget.charge(4 * size + 2 * source_size + len(raw) + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, size, raw)


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
    document["source_payload_sha256"] = "sha256:" + hashlib.sha256(plan.payload).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "PWA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise ProtobufWireAnalysisError("Report requires its exact embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(3 * size + expected.size)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise ProtobufWireAnalysisError(
            "Canonical report does not replay complete embedded sources"
        )


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not ProtobufWireAnalysis or not hasattr(report, "document_json"):
        raise ProtobufWireAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise ProtobufWireAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class ProtobufWireAnalysis:
    """Owned unsigned byte/type observations, not canonical message-object equivalence."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ProtobufWireAnalysis:
            raise ProtobufWireAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> ProtobufWireAnalysis:
        if cls is not ProtobufWireAnalysis:
            raise ProtobufWireAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> ProtobufWireAnalysis:
        if cls is not ProtobufWireAnalysis:
            raise ProtobufWireAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> ProtobufWireAnalysis:
    result = object.__new__(ProtobufWireAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_protobuf_wire(model: Any) -> ProtobufWireAnalysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_protobuf_wire_bytes(*, model_bytes: Any) -> ProtobufWireAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ProtobufWireAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtobufWireAnalysisError("Closed model JSON must be ASCII") from exc
    model, _ = _decode(text, budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_protobuf_wire_analysis(report: Any, *, model: Any) -> ProtobufWireAnalysis:
    budget = _Budget()
    text = _stored(report)
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(embedded.size + original.size)
    expected = _materialize(embedded)
    original_expected = _materialize(original)
    _compare(text, document, expected)
    if expected != original_expected:
        raise ProtobufWireAnalysisError("Report differs from separately supplied original model")
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh literal tag-value bytes with an opaque unknown field, never an RPC request."""

    def field(number: int, kind: str, repeated: bool = False, nested: str | None = None) -> dict:
        return {
            "field_number": number,
            "field_type": kind,
            "repeated": repeated,
            "message_type": nested,
        }

    return {
        "schema_version": 1,
        "source_id": "synthetic.protobuf-wire",
        "root_message": "Root",
        "messages": [
            {
                "message_id": "Root",
                "fields": [
                    field(1, "uint32"),
                    field(2, "string"),
                    field(3, "sint64", True),
                    field(4, "message", nested="Child"),
                ],
            },
            {"message_id": "Child", "fields": [field(1, "uint64")]},
        ],
        "payload_base64": base64.b64encode(
            bytes.fromhex("089601120774657374696e671a03010203220208074a02ff00")
        ).decode("ascii"),
    }


__all__ = [
    "ProtobufWireAnalysis",
    "ProtobufWireAnalysisError",
    "analyze_supplied_protobuf_wire",
    "analyze_supplied_protobuf_wire_bytes",
    "verify_supplied_protobuf_wire_analysis",
    "component_fixture",
]
