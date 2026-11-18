"""Bounded DEX035 header/map ranges and raw MUTF-8 UTF-16-unit observations.

This is supplied-file structure arithmetic, not APK authentication or bytecode validation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "android_supplied_dex035_structure"
PROFILE_ID = "AOE-GB-D08-S01"
CAPABILITY_ID = "army.gb.d08.s01"
VECTOR_ID = "AV-GB-D08-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S01"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ac670888f02a931e64507b0ad52d933ae6091e81ebc166b0ddec02b51fed04c2"
SEMANTICS_PROFILE = "aosp-dex035-little-endian-header-map-string-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-android-dex-model.v1"
DOMAIN = "sunderkey.offline-android-dex-analysis.v1"
MAX_FILE_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_BASE64_BYTES = 4 * ((MAX_FILE_BYTES + 2) // 3)
MAX_MAP_ITEMS = 128
MAX_STRINGS = 4_096
MAX_STRING_UNITS = 4_096
MAX_TOTAL_UNITS = 65_536
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "source_id", "dex_file_base64"}
_HEADER_FIELDS = (
    "file_size",
    "header_size",
    "endian_tag",
    "link_size",
    "link_off",
    "map_off",
    "string_ids_size",
    "string_ids_off",
    "type_ids_size",
    "type_ids_off",
    "proto_ids_size",
    "proto_ids_off",
    "field_ids_size",
    "field_ids_off",
    "method_ids_size",
    "method_ids_off",
    "class_defs_size",
    "class_defs_off",
    "data_size",
    "data_off",
)
_FIXED = {
    0x0001: ("string_ids", 4),
    0x0002: ("type_ids", 4),
    0x0003: ("proto_ids", 12),
    0x0004: ("field_ids", 8),
    0x0005: ("method_ids", 8),
    0x0006: ("class_defs", 32),
}
_ALIGNMENT = {0x1001: 4, 0x1002: 4, 0x1003: 4, 0x2001: 4, 0x2006: 4}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "apk_signature_verified",
        "bytecode_validated",
        "class_semantics_validated",
        "name_syntax_validated",
        "full_map_nonoverlap_verified",
        "full_dex_validity_verified",
        "runtime_installability_verified",
        "vulnerability_claimed",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "file_acquisition",
        "apk_installation",
        "device",
        "network",
        "credential",
        "provider",
        "process",
        "execution",
        "authority",
        "qualification",
        "deployment",
    ),
    "none",
)
_LIMITATIONS = (
    "The source is caller-supplied canonical base64, not authenticated APK or device evidence.",
    "Only unlinked little-endian DEX035 with a 112-byte header is supported.",
    "Fixed arrays have range/alignment checks, not type/prototype/field/method/class semantics.",
    "Unknown and unparsed variable map sections have unassessed extents and contents.",
    "Known extents and referenced string spans cannot cross later mapped starts.",
    "MUTF-8 is preserved as ordered integer UTF-16 units, including NUL and isolated surrogates.",
    "String-ID order/duplicates use raw UTF-16 units; higher-level name syntax is not checked.",
    "Adler32 and SHA1 detect corruption/identify content; neither authenticates signing or origin.",
    "No bytecode, APK signature, runtime, installation, vulnerability or qualification verdict.",
    "Canonical model identity is distinct from the exact decoded-file SHA256 identity.",
    "Budgets are local software limits; simultaneous maxima need not fit a replay operation.",
)


class AndroidDexAnalysisError(ValueError):
    """The supported structure, exact source replay or a software ceiling was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise AndroidDexAnalysisError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise AndroidDexAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise AndroidDexAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES:
                raise AndroidDexAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise AndroidDexAnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise AndroidDexAnalysisError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise AndroidDexAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise AndroidDexAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise AndroidDexAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise AndroidDexAnalysisError("Exact integer-only native JSON families required")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _clone(value), size, nodes


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise AndroidDexAnalysisError("Raw bounded integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    limit = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise AndroidDexAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise AndroidDexAnalysisError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise AndroidDexAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise AndroidDexAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise AndroidDexAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            count = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise AndroidDexAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise AndroidDexAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise AndroidDexAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise AndroidDexAnalysisError("Printable ASCII JSON strings required")
                count += 1
                if count > MAX_BASE64_BYTES:
                    raise AndroidDexAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise AndroidDexAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise AndroidDexAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise AndroidDexAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        document = {}
        for key, child in items:
            if key in document:
                raise AndroidDexAnalysisError("Duplicate raw JSON key")
            document[key] = child
        return document

    def unsupported(_: str) -> None:
        raise AndroidDexAnalysisError("Integer-only raw JSON required")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AndroidDexAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _file(model: dict, budget: _Budget) -> bytes:
    if type(model) is not dict or model.keys() != _MODEL_FIELDS:
        raise AndroidDexAnalysisError("Exact closed source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AndroidDexAnalysisError("Exact native schema version one required")
    identity = model["source_id"]
    if type(identity) is not str or _ID.fullmatch(identity) is None:
        raise AndroidDexAnalysisError("Bounded native source identity required")
    encoded = model["dex_file_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise AndroidDexAnalysisError("Bounded exact native base64 required")
    budget.charge(3 * len(encoded))
    if len(encoded) % 4 or _BASE64.fullmatch(encoded) is None:
        raise AndroidDexAnalysisError("Canonical padded base64 required")
    padding = len(encoded) - len(encoded.rstrip("="))
    declared = len(encoded) // 4 * 3 - padding
    if not 112 <= declared <= MAX_FILE_BYTES:
        raise AndroidDexAnalysisError("Supplied file byte ceiling or header truncation")
    budget.charge(3 * len(encoded) + 4 * declared)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AndroidDexAnalysisError("Malformed canonical base64") from exc
    if len(data) != declared or base64.b64encode(data).decode("ascii") != encoded:
        raise AndroidDexAnalysisError("Noncanonical base64 padding bits")
    return data


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _range(offset: int, width: int, minimum: int, maximum: int, alignment: int = 1) -> int:
    if offset < minimum or offset % alignment or width <= 0 or width > maximum - offset:
        raise AndroidDexAnalysisError("Declared range/alignment contradicts supplied bytes")
    return offset + width


def _header(data: bytes, budget: _Budget) -> dict:
    budget.charge(256)
    if data[:8] != b"dex\n035\x00":
        raise AndroidDexAnalysisError("Only exact DEX035 magic is supported")
    header = dict(zip(_HEADER_FIELDS, struct.unpack_from("<20I", data, 32), strict=True))
    if header["file_size"] != len(data) or header["header_size"] != 112:
        raise AndroidDexAnalysisError("File/header size contradicts supplied DEX035 bytes")
    if header["endian_tag"] != 0x12345678:
        raise AndroidDexAnalysisError("Only little-endian DEX035 is supported")
    if header["link_size"] or header["link_off"]:
        raise AndroidDexAnalysisError("Only unlinked DEX035 is supported")
    data_off, data_size = header["data_off"], header["data_size"]
    if data_size % 4 or _range(data_off, data_size, 112, len(data), 4) != len(data):
        raise AndroidDexAnalysisError("Unlinked data extent contradicts supplied bytes")
    previous_end = 112
    for name, width in _FIXED.values():
        count, offset = header[name + "_size"], header[name + "_off"]
        if name in {"type_ids", "proto_ids"} and count > 65_535:
            raise AndroidDexAnalysisError("DEX type/prototype count exceeds format bound")
        if count == 0:
            if offset != 0:
                raise AndroidDexAnalysisError("Empty fixed section must have zero offset")
        else:
            previous_end = _range(offset, count * width, previous_end, data_off, 4)
    if header["string_ids_size"] > MAX_STRINGS:
        raise AndroidDexAnalysisError("String count software ceiling exhausted")
    _range(header["map_off"], 4, data_off, len(data), 4)
    header["checksum"] = _u32(data, 8)
    header["signature_sha1_hex"] = data[12:32].hex()
    return header


def _map(data: bytes, header: dict, budget: _Budget) -> list[dict]:
    offset = header["map_off"]
    count = _u32(data, offset)
    if not 2 <= count <= MAX_MAP_ITEMS:
        raise AndroidDexAnalysisError("Map count software ceiling or required entries absent")
    end = _range(offset, 4 + 12 * count, header["data_off"], len(data), 4)
    budget.charge(512 * count)
    rows = []
    seen = set()
    previous = -1
    for index in range(count):
        code, unused, size, start = struct.unpack_from("<HHII", data, offset + 4 + 12 * index)
        if code in seen or start <= previous or unused != 0 or size == 0:
            raise AndroidDexAnalysisError(
                "Map types/starts/counts/unused violate the closed subset"
            )
        seen.add(code)
        previous = start
        if code == 0:
            if size != 1 or start != 0:
                raise AndroidDexAnalysisError("Header map entry contradicts header")
            known_end, alignment, content = 112, 4, "header_fields_checked"
        elif code in _FIXED:
            name, width = _FIXED[code]
            if (size, start) != (header[name + "_size"], header[name + "_off"]):
                raise AndroidDexAnalysisError("Fixed map entry contradicts header")
            known_end = _range(start, size * width, 112, header["data_off"], 4)
            alignment, content = 4, "unassessed_fixed_contents"
        elif code == 0x1000:
            if size != 1 or start != offset:
                raise AndroidDexAnalysisError("Map self-entry contradicts header/list")
            known_end, alignment, content = end, 4, "map_entries_checked"
        else:
            alignment = _ALIGNMENT.get(code, 1 if code in range(0x2000, 0x2006) else None)
            _range(start, 1, header["data_off"], len(data), alignment or 1)
            known_end, content = None, "unassessed_variable_contents"
        rows.append(
            {
                "type_code": code,
                "item_count": size,
                "offset": start,
                "end_offset": known_end,
                "alignment": alignment,
                "content_check": content,
                "extent_check": "known_range_checked"
                if known_end is not None
                else "unassessed_variable_extent",
            }
        )
    expected = {0, 0x1000}
    expected.update(code for code, (name, _) in _FIXED.items() if header[name + "_size"])
    if not expected <= seen or any(code in seen and code not in expected for code in _FIXED):
        raise AndroidDexAnalysisError("Map/header section presence mismatch")
    for index, row in enumerate(rows):
        next_start = rows[index + 1]["offset"] if index + 1 < len(rows) else len(data)
        if row["end_offset"] is not None and row["end_offset"] > next_start:
            raise AndroidDexAnalysisError("Known mapped extents overlap subsequent starts")
    return rows


def _uleb(data: bytes, offset: int, limit: int, budget: _Budget) -> tuple[int, int]:
    value = 0
    for index in range(5):
        budget.charge(8)
        if offset + index >= limit:
            raise AndroidDexAnalysisError("Truncated unsigned LEB128")
        octet = data[offset + index]
        if index == 4 and octet & 0xF0:
            raise AndroidDexAnalysisError("Unsigned LEB128 exceeds 32 bits/five bytes")
        value |= (octet & 0x7F) << (7 * index)
        if not octet & 0x80:
            return value, index + 1
    raise AndroidDexAnalysisError("Unterminated unsigned LEB128")


def _string(data: bytes, offset: int, limit: int, budget: _Budget, remaining: int) -> dict:
    declared, width = _uleb(data, offset, limit, budget)
    if declared > MAX_STRING_UNITS or declared > remaining:
        raise AndroidDexAnalysisError("Declared UTF16 unit software ceiling exhausted")
    budget.charge(64 + 16 * declared)
    position = offset + width
    begin = position
    units = []
    while position < limit:
        budget.charge(8)
        first = data[position]
        position += 1
        if first == 0:
            if len(units) != declared:
                raise AndroidDexAnalysisError("Declared UTF16 length contradicts decoded MUTF8")
            return {
                "data_offset": offset,
                "end_offset": position,
                "utf16_size": declared,
                "uleb128_byte_count": width,
                "mutf8_byte_count": position - begin - 1,
                "utf16_units": units,
            }
        if 1 <= first <= 0x7F:
            value = first
        elif 0xC0 <= first <= 0xDF:
            if position >= limit or data[position] & 0xC0 != 0x80:
                raise AndroidDexAnalysisError("Truncated/invalid two-byte MUTF8")
            value = ((first & 0x1F) << 6) | (data[position] & 0x3F)
            position += 1
            if value < 0x80 and not (first == 0xC0 and value == 0):
                raise AndroidDexAnalysisError("Unsupported overlong MUTF8")
        elif 0xE0 <= first <= 0xEF:
            if position + 1 >= limit or any(
                data[p] & 0xC0 != 0x80 for p in (position, position + 1)
            ):
                raise AndroidDexAnalysisError("Truncated/invalid three-byte MUTF8")
            value = (
                ((first & 0x0F) << 12)
                | ((data[position] & 0x3F) << 6)
                | (data[position + 1] & 0x3F)
            )
            position += 2
            if value < 0x800:
                raise AndroidDexAnalysisError("Unsupported overlong MUTF8")
        else:
            raise AndroidDexAnalysisError("Unsupported MUTF8 leading octet/four-byte encoding")
        if len(units) >= declared:
            raise AndroidDexAnalysisError("Decoded UTF16 exceeds declared length")
        units.append(value)
    raise AndroidDexAnalysisError("String terminator absent within its mapped range")


def _strings(
    data: bytes,
    header: dict,
    maps: list[dict],
    budget: _Budget,
    retained_size: int,
    retained_nodes: int,
) -> list[dict]:
    count = header["string_ids_size"]
    section = next((row for row in maps if row["type_code"] == 0x2002), None)
    if count == 0:
        if section is not None:
            raise AndroidDexAnalysisError("String data map exists without declared string IDs")
        return []
    if section is None or section["item_count"] != count:
        raise AndroidDexAnalysisError("String map/header count mismatch")
    budget.charge(256 * count * (count.bit_length() + 1))
    offsets = [_u32(data, header["string_ids_off"] + 4 * index) for index in range(count)]
    if len(set(offsets)) != count or min(offsets) != section["offset"]:
        raise AndroidDexAnalysisError(
            "Referenced string starts are duplicated or miss mapped start"
        )
    index = maps.index(section)
    section_end = maps[index + 1]["offset"] if index + 1 < len(maps) else len(data)
    ordered = sorted(offsets)
    decoded = {}
    total = 0
    for index, offset in enumerate(ordered):
        limit = ordered[index + 1] if index + 1 < count else section_end
        _range(offset, 1, section["offset"], section_end)
        row = _string(data, offset, limit, budget, MAX_TOTAL_UNITS - total)
        total += row["utf16_size"]
        decoded[offset] = row
    rows = []
    previous = None
    for index, offset in enumerate(offsets):
        row = decoded[offset]
        units = row["utf16_units"]
        budget.charge(32 + 4 * len(units))
        if previous is not None:
            budget.charge(2 * min(len(previous), len(units)))
            if previous >= units:
                raise AndroidDexAnalysisError(
                    "String IDs must be strictly UTF16-unit sorted/unique"
                )
        previous = units
        observation = {"string_index": index, **row}
        size, nodes = _measure(observation, budget, report=True)
        punctuation = 1 if rows else 0
        if (
            size + punctuation > MAX_REPORT_BYTES - retained_size
            or nodes > MAX_REPORT_NODES - retained_nodes
        ):
            raise AndroidDexAnalysisError("Cumulative string report retention ceiling exhausted")
        budget.charge(size + nodes + punctuation)
        retained_size += size + punctuation
        retained_nodes += nodes
        rows.append(observation)
    section["end_offset"] = max(row["end_offset"] for row in rows)
    section["extent_check"] = "referenced_string_spans_checked"
    section["content_check"] = "mutf8_units_checked"
    section["alignment"] = 1
    return rows


def _bounds() -> dict:
    return {
        "file_bytes": MAX_FILE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "map_items": MAX_MAP_ITEMS,
        "strings": MAX_STRINGS,
        "utf16_units_per_string": MAX_STRING_UNITS,
        "aggregate_utf16_units": MAX_TOTAL_UNITS,
        "cumulative_work_per_public_operation": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    file: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size, _ = _capture(model, budget)
    data = _file(source, budget)
    header = _header(data, budget)
    maps = _map(data, header, budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "source_file_sha256": _PLACEHOLDER,
        "source_file_bytes": len(data),
        "header": header,
        "map_observations": maps,
        "string_observations": [],
        "aggregate_utf16_units": 0,
        "analysis_status": "supported_structure_subset_consistent",
        "integrity": {"adler32_matches": True, "sha1_matches": True, "authenticates_origin": False},
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "DXA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    base_size, base_nodes = _measure(document, budget, report=True)
    # Reserve the bounded map-end/status and aggregate-counter changes before
    # retaining any per-string output, without inventing variable-section extents.
    budget.charge(128)
    strings = _strings(data, header, maps, budget, base_size + 128, base_nodes)
    document["string_observations"] = strings
    document["aggregate_utf16_units"] = sum(row["utf16_size"] for row in strings)
    # Complete repeated report retention/copy and every encoding/digest buffer are
    # funded before any DEX SHA1/Adler32, raw-file SHA256 or metadata address occurs.
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        8 * size + 4 * source_size + 8 * len(data) + 4 * nodes + len(DOMAIN) + len(MODEL_DOMAIN) + 2
    )
    return _Plan(document, data, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    data, document = plan.file, plan.document
    if hashlib.sha1(data[32:], usedforsecurity=False).digest() != data[12:32]:
        raise AndroidDexAnalysisError("DEX SHA1 identity field contradicts supplied bytes")
    if zlib.adler32(data[12:]) != document["header"]["checksum"]:
        raise AndroidDexAnalysisError("DEX Adler32 field contradicts supplied bytes")
    document["source_file_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "DXA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise AndroidDexAnalysisError("Report requires its complete embedded source model")
    actual_size, actual_nodes = _measure(document, budget, report=True)
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * actual_size + expected.size + actual_nodes)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise AndroidDexAnalysisError("Canonical report does not fully replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not AndroidDexAnalysis or not hasattr(report, "document_json"):
        raise AndroidDexAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise AndroidDexAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class AndroidDexAnalysis:
    """Owned unsigned metadata with full embedded replay on every export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not AndroidDexAnalysis:
            raise AndroidDexAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> AndroidDexAnalysis:
        if cls is not AndroidDexAnalysis:
            raise AndroidDexAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> AndroidDexAnalysis:
        if cls is not AndroidDexAnalysis:
            raise AndroidDexAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _owned(text: str) -> AndroidDexAnalysis:
    result = object.__new__(AndroidDexAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_android_dex(model: Any) -> AndroidDexAnalysis:
    """Check the closed supplied-file subset, without runtime or authority effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_android_dex_bytes(*, model_bytes: Any) -> AndroidDexAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise AndroidDexAnalysisError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AndroidDexAnalysisError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_android_dex_analysis(report: Any, *, model: Any) -> AndroidDexAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise AndroidDexAnalysisError("Report does not replay the separately supplied original")
    return _owned(separate)


# Independently encoded benign unlinked file, with NUL and one raw surrogate unit.
_FIXTURE_BASE64 = (
    "ZGV4CjAzNQD3FS1t5S7ivxkCH/FeUpMP1MMgiCyIfnvEAAAAcAAAAHhWNBIAAAAAAAAAAJAAAAADAAAA"
    "cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAfAAAAHwAAACBAAAAi"
    "AAAAALAgEEABUhlbGxvAAHtoIAAAAAABAAAAAAAAAABAAAAAAAAAAEAAAADAAAAcAAAAAIgAAADAAAAfAAA"
    "AAAQAAABAAAAkAAAAA=="
)


def component_fixture() -> dict:
    """Fresh inert DEX035 file metadata, not an acquired APK or device observation."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-dex035",
        "dex_file_base64": _FIXTURE_BASE64,
    }


__all__ = [
    "AndroidDexAnalysis",
    "AndroidDexAnalysisError",
    "analyze_supplied_android_dex",
    "analyze_supplied_android_dex_bytes",
    "verify_supplied_android_dex_analysis",
    "component_fixture",
]
