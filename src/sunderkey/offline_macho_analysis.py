"""Supplied thin Mach-O64 layout arithmetic, not loader or signing validation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "ios_supplied_macho64_layout"
PROFILE_ID = "AOE-GB-D08-S05"
CAPABILITY_ID = "army.gb.d08.s05"
VECTOR_ID = "AV-GB-D08-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S05"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5390c215a247ebe2692e62bf9cf63554271141e778580f51afa7f61d9ef4397d"
APPLE_REVISION = "e6231be02a03711ca404e5121a151b24afbff733"
SEMANTICS_PROFILE = "apple-thin-le-macho64-command-segment-section-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-macho-model.v1"
DOMAIN = "sunderkey.offline-macho-analysis.v1"
MAX_FILE_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_BASE64_BYTES = 4 * ((MAX_FILE_BYTES + 2) // 3)
MAX_COMMANDS = 256
MAX_SEGMENTS = 64
MAX_SECTIONS = 1_024
MAX_ALIGNMENT_EXPONENT = 63
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
MAX_U64 = 2**64 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "source_id", "macho_file_base64"}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "symbols_normalized",
        "code_signature_verified",
        "encryption_validated",
        "relocations_validated",
        "machine_code_validated",
        "full_macho_validity_verified",
        "loader_compatibility_verified",
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
    "Caller-supplied file bytes and source labels are not authenticated iOS or device evidence.",
    "Only thin little-endian Mach-O64 headers and a bounded command/layout subset are parsed.",
    "CPU, header flags and reserved words are observed, not a supported-machine assertion.",
    "Raw names retain all sixteen bytes as hex; no NUL stripping or symbol normalization.",
    "LC_UUID is structural raw identity only, not uniqueness, provenance or authentication.",
    "Unknown commands, section types, attributes and nonzero segment flags stay unassessed.",
    "High-VM and unknown mappings never use the ordinary file-to-VM containment interpretation.",
    "Only nonempty regular sections have supplied file ranges; zero-fill has no file extent.",
    "Known geometry uses only flags-zero MH_OBJECT/MH_EXECUTE; other file types stay unassessed.",
    "Relocation fields, protections, fixups, entry points and command payloads are not validated.",
    "Interval ends must fit uint64 and alignment exponents at most 63 in this narrow profile.",
    "No signature, installability, loader, machine-code, vulnerability or qualification verdict.",
    "Retained source is unsanitized; no file extraction, rendering, execution or target access.",
    "Software ceilings cover complete public passes; simultaneous maxima need not fit replay.",
)


class MachOAnalysisError(ValueError):
    """A closed-input, supported-layout, exact-replay or software-limit refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise MachOAnalysisError("Cumulative software work ceiling exhausted")
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
            raise MachOAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise MachOAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES:
                raise MachOAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise MachOAnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise MachOAnalysisError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise MachOAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise MachOAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise MachOAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise MachOAnalysisError("Exact integer-only native JSON families required")

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
        raise MachOAnalysisError("Raw bounded integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    limit = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise MachOAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise MachOAnalysisError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise MachOAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise MachOAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise MachOAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                        raise MachOAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise MachOAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise MachOAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise MachOAnalysisError("Printable ASCII JSON strings required")
                count += 1
                if count > MAX_BASE64_BYTES:
                    raise MachOAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise MachOAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise MachOAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise MachOAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise MachOAnalysisError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise MachOAnalysisError("Integer-only raw JSON required")

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
        raise MachOAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _file(model: dict, budget: _Budget) -> bytes:
    if type(model) is not dict or model.keys() != _MODEL_FIELDS:
        raise MachOAnalysisError("Exact closed source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MachOAnalysisError("Exact native schema version one required")
    identity = model["source_id"]
    if type(identity) is not str or _ID.fullmatch(identity) is None:
        raise MachOAnalysisError("Bounded native source identity required")
    encoded = model["macho_file_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise MachOAnalysisError("Bounded exact native base64 required")
    budget.charge(3 * len(encoded))
    if len(encoded) % 4 or _BASE64.fullmatch(encoded) is None:
        raise MachOAnalysisError("Canonical padded base64 required")
    padding = len(encoded) - len(encoded.rstrip("="))
    declared = len(encoded) // 4 * 3 - padding
    if not 32 <= declared <= MAX_FILE_BYTES:
        raise MachOAnalysisError("Supplied file byte ceiling or header truncation")
    budget.charge(3 * len(encoded) + 4 * declared)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise MachOAnalysisError("Malformed canonical base64") from exc
    if len(data) != declared or base64.b64encode(data).decode("ascii") != encoded:
        raise MachOAnalysisError("Noncanonical base64 padding bits")
    return data


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _end(offset: int, width: int) -> int:
    if width > MAX_U64 - offset:
        raise MachOAnalysisError("Interval end exceeds the supported uint64 arithmetic profile")
    return offset + width


def _file_end(offset: int, width: int, size: int) -> int:
    end = _end(offset, width)
    if offset > size or width > size - offset:
        raise MachOAnalysisError("Declared nonempty file range contradicts supplied bytes")
    return end


def _header(data: bytes, budget: _Budget) -> dict:
    budget.charge(256)
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise MachOAnalysisError("Only thin little-endian Mach-O64 magic is supported")
    values = struct.unpack_from("<IiiIIIII", data, 0)
    header = dict(
        zip(
            (
                "magic",
                "cpu_type",
                "cpu_subtype",
                "file_type",
                "command_count",
                "command_bytes",
                "flags",
                "reserved",
            ),
            values,
            strict=True,
        )
    )
    count, size = header["command_count"], header["command_bytes"]
    if count > MAX_COMMANDS:
        raise MachOAnalysisError("Declared command software ceiling exhausted")
    if size % 8 or size < 8 * count or size > len(data) - 32:
        raise MachOAnalysisError("Header command count/size contradicts supplied bytes")
    header["commands_end_offset"] = 32 + size
    header["known_geometry_file_type"] = header["file_type"] in (1, 2)
    return header


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int

    def reserve(self, size: int, nodes: int, budget: _Budget) -> None:
        if size > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise MachOAnalysisError("Cumulative retained report ceiling exhausted")
        budget.charge(size + nodes)
        self.size += size
        self.nodes += nodes


def _section(
    data: bytes,
    offset: int,
    index: int,
    segment: dict,
    header: dict,
    budget: _Budget,
) -> dict:
    budget.charge(1024)
    values = struct.unpack_from("<16s16sQQIIIIIIII", data, offset)
    name, declared_segment, address, size, file_offset, exponent = values[:6]
    relocation_offset, relocations, flags, reserved1, reserved2, reserved3 = values[6:]
    if exponent > MAX_ALIGNMENT_EXPONENT:
        raise MachOAnalysisError("Alignment exponent software ceiling exhausted before shift")
    vm_end = _end(address, size)
    kind = flags & 255
    known = kind in (0, 1)
    geometry = known and segment["flags"] == 0 and header["known_geometry_file_type"]
    file_end = None
    if kind == 0 and size:
        file_end = _file_end(file_offset, size, len(data))
        if file_offset < header["commands_end_offset"]:
            raise MachOAnalysisError("Regular section overlaps header/command bytes")
    elif kind == 0:
        file_end = _end(file_offset, size)
    if geometry and size:
        alignment = 1 << exponent
        if address % alignment or (kind == 0 and file_offset % alignment):
            raise MachOAnalysisError("Known section address/file alignment contradicts declaration")
        if not segment["vm_address"] <= address or vm_end > segment["vm_end"]:
            raise MachOAnalysisError("Known section VM range is outside its segment")
        if kind == 0 and (file_offset < segment["file_offset"] or file_end > segment["file_end"]):
            raise MachOAnalysisError("Regular section file range is outside its segment")
    return {
        "section_index": index,
        "record_offset": offset,
        "name_hex": name.hex(),
        "declared_segment_name_hex": declared_segment.hex(),
        "declared_segment_name_matches": declared_segment.hex() == segment["name_hex"],
        "vm_address": _hex(address),
        "vm_size": _hex(size),
        "vm_end": _hex(vm_end),
        "file_offset": file_offset,
        "file_end": _hex(file_end) if file_end is not None else None,
        "alignment_exponent": exponent,
        "relocation_offset": relocation_offset,
        "relocation_count": relocations,
        "flags": flags,
        "section_type": kind,
        "reserved1": reserved1,
        "reserved2": reserved2,
        "reserved3": reserved3,
        "file_extent_check": "regular_nonempty_range_checked"
        if kind == 0 and size
        else (
            "empty_regular_no_bytes"
            if kind == 0
            else ("zero_fill_no_file_extent" if kind == 1 else "unassessed_section_type")
        ),
        "geometry_check": "known_nonempty_containment_checked"
        if geometry and size
        else ("empty_no_content_range" if geometry else "unassessed_mapping_or_type"),
        "attributes_check": "no_attributes_declared"
        if flags >> 8 == 0
        else "unassessed_attributes",
        "relocation_contents_check": "unassessed",
    }


def _commands(
    data: bytes, header: dict, budget: _Budget, retained: _Retained
) -> tuple[list[dict], list[dict], list[str]]:
    commands: list[dict] = []
    segments: list[dict] = []
    reasons: set[str] = set()
    position = 32
    end = header["commands_end_offset"]
    total_sections = 0
    if not header["known_geometry_file_type"]:
        reasons.add("unassessed_file_type")
    for index in range(header["command_count"]):
        if position > end - 8:
            raise MachOAnalysisError("Truncated declared command header")
        code, width = struct.unpack_from("<II", data, position)
        if width < 8 or width % 8 or width > end - position:
            raise MachOAnalysisError("Command size/alignment contradicts declared command block")
        retained.reserve(512, 40, budget)
        row = {
            "command_index": index,
            "offset": position,
            "end_offset": position + width,
            "command_code": code,
            "command_bytes": width,
            "requires_dyld": bool(code & 0x80000000),
            "kind": "unassessed_command",
            "segment_index": None,
            "uuid_hex": None,
            "payload_check": "unassessed",
        }
        if code == 0x19:
            if width < 72:
                raise MachOAnalysisError("Truncated LC_SEGMENT_64 structure")
            values = struct.unpack_from("<16sQQQQiiII", data, position + 8)
            name, vm_address, vm_size, file_offset, file_size, maximum, initial, count, flags = (
                values
            )
            if count > MAX_SECTIONS - total_sections:
                raise MachOAnalysisError("Declared aggregate section software ceiling exhausted")
            if len(segments) >= MAX_SEGMENTS:
                raise MachOAnalysisError("Declared segment software ceiling exhausted")
            if width != 72 + 80 * count:
                raise MachOAnalysisError("LC_SEGMENT_64 count/command geometry mismatch")
            vm_end = _end(vm_address, vm_size)
            file_end = _end(file_offset, file_size)
            if file_size:
                _file_end(file_offset, file_size, len(data))
            ordinary = flags == 0 and header["known_geometry_file_type"]
            if ordinary and file_size > vm_size:
                raise MachOAnalysisError("Ordinary segment file size exceeds its VM size")
            if ordinary and header["file_type"] == 1 and file_size and file_offset < end:
                raise MachOAnalysisError("MH_OBJECT file-backed segment includes header/commands")
            retained.reserve(1024, 60, budget)
            segment = {
                "command_index": index,
                "segment_index": len(segments),
                "name_hex": name.hex(),
                "vm_address": vm_address,
                "vm_size": vm_size,
                "vm_end": vm_end,
                "file_offset": file_offset,
                "file_size": file_size,
                "file_end": file_end,
                "maximum_protection": maximum,
                "initial_protection": initial,
                "section_count": count,
                "flags": flags,
                "contains_header_and_commands": bool(
                    file_size and file_offset == 0 and file_end >= end
                ),
                "geometry_check": "ordinary_subset_checked" if ordinary else "unassessed_mapping",
                "sections": [],
            }
            if flags:
                reasons.add("unassessed_segment_flags")
            zero_seen = False
            for section_index in range(count):
                # Fixed upper reservations fund allocation and cumulative retention
                # before building/appending each bounded section observation.
                retained.reserve(1536, 64, budget)
                section = _section(
                    data, position + 72 + 80 * section_index, section_index, segment, header, budget
                )
                kind = section["section_type"]
                if ordinary and kind == 0 and zero_seen:
                    raise MachOAnalysisError("Known regular section follows zero-fill section")
                zero_seen = zero_seen or kind == 1
                if kind not in (0, 1):
                    reasons.add("unassessed_section_type")
                if section["flags"] >> 8:
                    reasons.add("unassessed_section_attributes")
                segment["sections"].append(section)
            total_sections += count
            for key in ("vm_address", "vm_size", "vm_end", "file_offset", "file_size", "file_end"):
                segment[key] = _hex(segment[key])
            row["kind"] = "segment64"
            row["segment_index"] = len(segments)
            row["payload_check"] = "fixed_segment_section_records_checked"
            segments.append(segment)
        elif code == 0x1B:
            if width != 24:
                raise MachOAnalysisError("LC_UUID must have the exact 24-byte supported structure")
            budget.charge(64)
            row["kind"] = "uuid"
            row["uuid_hex"] = data[position + 8 : position + 24].hex()
            row["payload_check"] = "raw_uuid_observed_not_authenticated"
        else:
            reasons.add("unassessed_command")
        commands.append(row)
        position += width
    if position != end:
        raise MachOAnalysisError("Declared command count does not consume exact command bytes")
    budget.charge(256 * len(reasons))
    return commands, segments, sorted(reasons)


def _bounds() -> dict:
    return {
        "file_bytes": MAX_FILE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "commands": MAX_COMMANDS,
        "segments": MAX_SEGMENTS,
        "aggregate_sections": MAX_SECTIONS,
        "maximum_alignment_exponent": MAX_ALIGNMENT_EXPONENT,
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
        "primary_source_revision": APPLE_REVISION,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "source_file_sha256": _PLACEHOLDER,
        "source_file_bytes": len(data),
        "header": header,
        "command_observations": [],
        "segment_observations": [],
        "unassessed_reasons": [],
        "analysis_status": "supported_layout_subset_consistent",
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "MCA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    base_size, base_nodes = _measure(document, budget, report=True)
    retained = _Retained(base_size + 512, base_nodes + 32)
    commands, segments, reasons = _commands(data, header, budget, retained)
    document["command_observations"] = commands
    document["segment_observations"] = segments
    document["unassessed_reasons"] = reasons
    if reasons:
        document["analysis_status"] = "layout_semantics_unassessed"
    # Reserve complete fixed-width identities, all encodings, repeated copies,
    # equality/export and digest buffers before the first digest in this pass.
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        8 * size + 4 * source_size + 4 * len(data) + 4 * nodes + len(DOMAIN) + len(MODEL_DOMAIN) + 2
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
    document = plan.document
    document["source_file_sha256"] = "sha256:" + hashlib.sha256(plan.file).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "MCA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise MachOAnalysisError("Report requires its complete embedded source model")
    size, nodes = _measure(document, budget, report=True)
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size + nodes)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise MachOAnalysisError("Canonical report does not fully replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not MachOAnalysis or not hasattr(report, "document_json"):
        raise MachOAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise MachOAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class MachOAnalysis:
    """Owned unsigned content with full embedded-byte replay on every export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not MachOAnalysis:
            raise MachOAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> MachOAnalysis:
        if cls is not MachOAnalysis:
            raise MachOAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> MachOAnalysis:
        if cls is not MachOAnalysis:
            raise MachOAnalysisError("Exact native report family required")
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


def _owned(text: str) -> MachOAnalysis:
    result = object.__new__(MachOAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_macho_layout(model: Any) -> MachOAnalysis:
    """Analyze the supplied layout subset without loader, device or authority effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_macho_layout_bytes(*, model_bytes: Any) -> MachOAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise MachOAnalysisError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MachOAnalysisError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_macho_layout_analysis(report: Any, *, model: Any) -> MachOAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise MachOAnalysisError("Report does not replay the separately supplied original")
    return _owned(separate)


_FIXTURE_BASE64 = (
    "z/rt/gwAAAEAAAAAAQAAAAEAAACYAAAAAAAAAAAAAAAZAAAAmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAQAAAAAAAAAuAAAAAAAAAAEAAAAAAAAAAcAAAADAAAAAQAAAAAAAABfX2RhdGEAAAAAAAAAAAAA"
    "X19EQVRBAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAC4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAERBVEE="
)


def component_fixture() -> dict:
    """Fresh wholly synthetic object layout, not an acquired iOS executable."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-macho64",
        "macho_file_base64": _FIXTURE_BASE64,
    }


__all__ = [
    "MachOAnalysis",
    "MachOAnalysisError",
    "analyze_supplied_macho_layout",
    "analyze_supplied_macho_layout_bytes",
    "verify_supplied_macho_layout_analysis",
    "component_fixture",
]
