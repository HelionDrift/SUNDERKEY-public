"""Supplied little-endian ELF64 layout arithmetic, not loader or execution validation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "linux_supplied_elf64_layout"
PROFILE_ID = "AOE-GB-D08-S17"
CAPABILITY_ID = "army.gb.d08.s17"
VECTOR_ID = "AV-GB-D08-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S17"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9dbac95bc302d6311b253e6363f050eed885ca20826e09df1aa172c337098ef1"
PRIMARY_SOURCE_PROFILE = "gabi-elf-4.3-draft-2026-09-29"
SEMANTICS_PROFILE = "gabi-little-endian-elf64-layout-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-elf64-model.v1"
DOMAIN = "sunderkey.offline-elf64-layout-analysis.v1"
MAX_FILE_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_BASE64_BYTES = 4 * ((MAX_FILE_BYTES + 2) // 3)
MAX_PROGRAMS = 128
MAX_SECTIONS = 1_024
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
MAX_U64 = 2**64 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "source_id", "elf_file_base64"}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "section_names_resolved",
        "symbols_normalized",
        "relocations_validated",
        "dynamic_linking_validated",
        "machine_code_validated",
        "full_elf_validity_verified",
        "loader_compatibility_verified",
        "runtime_execution_verified",
        "vulnerability_claimed",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "file_acquisition",
        "host",
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
    "Caller-supplied file bytes and source labels are not authenticated Linux or host evidence.",
    "Only little-endian ELF64 and bounded ordinary header counts are accepted.",
    "Extended numbering, compressed contents and processor-specific semantics are not supported.",
    "Raw uint64 fields and interval ends remain fixed-width hex, not signed64 coercions.",
    "PT_NULL and inactive sections retain undefined fields without interpreting their ranges.",
    "PT_LOAD geometry is assessed only for declared executable or shared-object file types.",
    "Only nonempty file-backed sections have file extents; SHT_NOBITS has no supplied file extent.",
    "Section address alignment is not a file-offset alignment or operating-system page-size claim.",
    "Segment overlaps are not rejected merely because multiple mappings reference shared bytes.",
    "Unknown types, flags and ABI metadata remain unassessed rather than clean.",
    "Names, string tables, symbols, entry points, relocations and linker state are not resolved.",
    "No loader, runtime permission, executable authenticity, vulnerability "
    "or qualification verdict.",
    "Retained source is unsanitized; no file extraction, rendering, execution or target access.",
    "Software ceilings cover complete public passes; simultaneous maxima need not fit replay.",
)


class Elf64LayoutAnalysisError(ValueError):
    """A closed-input, supported-layout, exact-replay or software-limit refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise Elf64LayoutAnalysisError("Cumulative software work ceiling exhausted")
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
            raise Elf64LayoutAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise Elf64LayoutAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES:
                raise Elf64LayoutAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise Elf64LayoutAnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise Elf64LayoutAnalysisError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise Elf64LayoutAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise Elf64LayoutAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise Elf64LayoutAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise Elf64LayoutAnalysisError("Exact integer-only native JSON families required")

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
        raise Elf64LayoutAnalysisError("Raw bounded integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    limit = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise Elf64LayoutAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise Elf64LayoutAnalysisError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise Elf64LayoutAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise Elf64LayoutAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise Elf64LayoutAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                        raise Elf64LayoutAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise Elf64LayoutAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise Elf64LayoutAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise Elf64LayoutAnalysisError("Printable ASCII JSON strings required")
                count += 1
                if count > MAX_BASE64_BYTES:
                    raise Elf64LayoutAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise Elf64LayoutAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise Elf64LayoutAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise Elf64LayoutAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise Elf64LayoutAnalysisError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise Elf64LayoutAnalysisError("Integer-only raw JSON required")

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
        raise Elf64LayoutAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _file(model: dict, budget: _Budget) -> bytes:
    if type(model) is not dict or model.keys() != _MODEL_FIELDS:
        raise Elf64LayoutAnalysisError("Exact closed source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise Elf64LayoutAnalysisError("Exact native schema version one required")
    identity = model["source_id"]
    if type(identity) is not str or _ID.fullmatch(identity) is None:
        raise Elf64LayoutAnalysisError("Bounded native source identity required")
    encoded = model["elf_file_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise Elf64LayoutAnalysisError("Bounded exact native base64 required")
    budget.charge(3 * len(encoded))
    if len(encoded) % 4 or _BASE64.fullmatch(encoded) is None:
        raise Elf64LayoutAnalysisError("Canonical padded base64 required")
    padding = len(encoded) - len(encoded.rstrip("="))
    declared = len(encoded) // 4 * 3 - padding
    if not 64 <= declared <= MAX_FILE_BYTES:
        raise Elf64LayoutAnalysisError("Supplied file byte ceiling or header truncation")
    budget.charge(3 * len(encoded) + 4 * declared)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Elf64LayoutAnalysisError("Malformed canonical base64") from exc
    if len(data) != declared or base64.b64encode(data).decode("ascii") != encoded:
        raise Elf64LayoutAnalysisError("Noncanonical base64 padding bits")
    return data


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _end(offset: int, width: int) -> int:
    if width > MAX_U64 - offset:
        raise Elf64LayoutAnalysisError(
            "Interval end exceeds the supported uint64 arithmetic profile"
        )
    return offset + width


def _file_end(offset: int, width: int, size: int) -> int:
    end = _end(offset, width)
    if offset > size or width > size - offset:
        raise Elf64LayoutAnalysisError("Declared nonempty file range contradicts supplied bytes")
    return end


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int

    def reserve(self, size: int, nodes: int, budget: _Budget) -> None:
        if size > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise Elf64LayoutAnalysisError("Cumulative retained report ceiling exhausted")
        budget.charge(size + nodes)
        self.size += size
        self.nodes += nodes


def _bounds() -> dict:
    return {
        "file_bytes": MAX_FILE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "native_depth": MAX_DEPTH,
        "program_headers": MAX_PROGRAMS,
        "section_headers": MAX_SECTIONS,
        "cumulative_work": MAX_WORK,
    }


def _table(offset: int, count: int, width: int, data_size: int) -> int | None:
    if not count:
        return None
    if offset < 64:
        raise Elf64LayoutAnalysisError("Nonempty header table overlaps the ELF header")
    return _file_end(offset, count * width, data_size)


def _header(data: bytes, budget: _Budget) -> tuple[dict, int, int, int, int]:
    budget.charge(256)
    values = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, kind, machine, version, entry, phoff, shoff, flags = values[:8]
    ehsize, phsize, phnum, shsize, shnum, shstr = values[8:]
    if ident[:7] != b"\x7fELF\x02\x01\x01" or version != 1:
        raise Elf64LayoutAnalysisError("Only version-one little-endian ELF64 is supported")
    if ehsize != 64:
        raise Elf64LayoutAnalysisError("The supported ELF64 header size is 64")
    if phnum > MAX_PROGRAMS or shnum > MAX_SECTIONS:
        raise Elf64LayoutAnalysisError("Ordinary header count software ceiling exhausted")
    if (phnum and phsize != 56) or (not phnum and phsize not in (0, 56)):
        raise Elf64LayoutAnalysisError("The supported program header width is 56")
    if (shnum and shsize != 64) or (not shnum and shsize not in (0, 64)):
        raise Elf64LayoutAnalysisError("The supported section header width is 64")
    if not shnum and shoff:
        raise Elf64LayoutAnalysisError("Extended section numbering is outside this subset")
    if shstr >= 0xFF00 or (shstr and shstr >= shnum):
        raise Elf64LayoutAnalysisError("Ordinary section-name table index required")
    phend = _table(phoff, phnum, 56, len(data))
    shend = _table(shoff, shnum, 64, len(data))
    if phend is not None and shend is not None and max(phoff, shoff) < min(phend, shend):
        raise Elf64LayoutAnalysisError("Nonempty program and section header tables overlap")
    return (
        {
            "ident_hex": ident.hex(),
            "file_type": kind,
            "machine": machine,
            "version": version,
            "entry_address_hex": _hex(entry),
            "program_header_offset_hex": _hex(phoff),
            "section_header_offset_hex": _hex(shoff),
            "flags_hex": f"0x{flags:08x}",
            "header_bytes": ehsize,
            "program_header_bytes": phsize,
            "program_header_count": phnum,
            "section_header_bytes": shsize,
            "section_header_count": shnum,
            "section_name_table_index": shstr,
            "program_header_file_end_hex": None if phend is None else _hex(phend),
            "section_header_file_end_hex": None if shend is None else _hex(shend),
        },
        phoff,
        phnum,
        shoff,
        shnum,
    )


def _aligned(value: int, alignment: int) -> bool:
    return alignment in (0, 1) or (alignment & (alignment - 1) == 0 and value % alignment == 0)


def _reason(reasons: set[str], message: str, retained: _Retained, budget: _Budget) -> None:
    budget.charge(len(message))
    if message not in reasons:
        retained.reserve(len(message) + 8, 2, budget)
        reasons.add(message)


def _programs(
    data: bytes,
    header: dict,
    offset: int,
    count: int,
    reasons: set[str],
    retained: _Retained,
    budget: _Budget,
) -> list[dict]:
    result = []
    previous_load = None
    for index in range(count):
        retained.reserve(1_024, 64, budget)
        budget.charge(256)
        kind, flags, start, address, physical, file_size, memory_size, alignment = (
            struct.unpack_from("<IIQQQQQQ", data, offset + 56 * index)
        )
        file_end = memory_end = None
        status = "inactive_fields_uninterpreted" if kind == 0 else "semantics_unassessed"
        if kind:
            if file_size:
                file_end = _file_end(start, file_size, len(data))
            if kind == 1 and header["file_type"] in (2, 3):
                if file_size > memory_size:
                    raise Elf64LayoutAnalysisError("PT_LOAD file size exceeds memory size")
                memory_end = _end(address, memory_size)
                if alignment not in (0, 1) and (
                    alignment & (alignment - 1) or address % alignment != start % alignment
                ):
                    raise Elf64LayoutAnalysisError("PT_LOAD address/offset alignment contradicts")
                if previous_load is not None and address < previous_load:
                    raise Elf64LayoutAnalysisError("PT_LOAD virtual addresses are not ascending")
                previous_load = address
                status = "declared_load_geometry_consistent"
                if flags & ~7:
                    status = "geometry_consistent_flags_unassessed"
                    _reason(
                        reasons, "Unknown program flag meanings are not assessed.", retained, budget
                    )
            elif kind == 1:
                _reason(
                    reasons,
                    "PT_LOAD mapping semantics require a declared EXEC or DYN type.",
                    retained,
                    budget,
                )
            else:
                _reason(
                    reasons, "Non-PT_LOAD program semantics are not assessed.", retained, budget
                )
        result.append(
            {
                "program_index": index,
                "header_file_offset": offset + 56 * index,
                "program_type": kind,
                "flags_hex": f"0x{flags:08x}",
                "file_offset_hex": _hex(start),
                "virtual_address_hex": _hex(address),
                "physical_address_hex": _hex(physical),
                "file_size_hex": _hex(file_size),
                "memory_size_hex": _hex(memory_size),
                "alignment_hex": _hex(alignment),
                "file_end_hex": None if file_end is None else _hex(file_end),
                "memory_end_hex": None if memory_end is None else _hex(memory_end),
                "file_backed": kind != 0 and file_size != 0,
                "geometry_status": status,
            }
        )
    return result


def _sections(
    data: bytes,
    offset: int,
    count: int,
    header_ranges: list[tuple[int, int]],
    reasons: set[str],
    retained: _Retained,
    budget: _Budget,
) -> list[dict]:
    result = []
    ranges = []
    for index in range(count):
        retained.reserve(1_024, 64, budget)
        budget.charge(256)
        values = struct.unpack_from("<IIQQQQIIQQ", data, offset + 64 * index)
        name, kind, flags, address, start, size, link, info, alignment, entry_size = values
        if index == 0 and any(values):
            raise Elf64LayoutAnalysisError(
                "Only an all-zero initial section entry with ordinary numbering is supported"
            )
        file_end = memory_end = None
        status = "inactive_fields_uninterpreted" if kind == 0 else "generic_geometry_consistent"
        if kind:
            if not _aligned(address, alignment):
                raise Elf64LayoutAnalysisError("Section address alignment contradicts")
            if flags & 2:
                memory_end = _end(address, size)
            if kind != 8 and size:
                file_end = _file_end(start, size, len(data))
                if any(max(start, lower) < min(file_end, upper) for lower, upper in header_ranges):
                    raise Elf64LayoutAnalysisError("File-backed section overlaps a header or table")
                ranges.append((start, file_end))
            if kind not in (1, 3, 8):
                status = "geometry_consistent_contents_unassessed"
                _reason(
                    reasons,
                    "Section types outside PROGBITS, STRTAB and NOBITS stay unassessed.",
                    retained,
                    budget,
                )
            if flags & ~7:
                status = "geometry_consistent_flags_unassessed"
                _reason(
                    reasons, "Unknown section flag meanings are not assessed.", retained, budget
                )
            if link or info or entry_size:
                _reason(
                    reasons,
                    "Section links, auxiliary information and entry semantics are not resolved.",
                    retained,
                    budget,
                )
        result.append(
            {
                "section_index": index,
                "header_file_offset": offset + 64 * index,
                "name_offset": name,
                "section_type": kind,
                "flags_hex": _hex(flags),
                "address_hex": _hex(address),
                "file_offset_hex": _hex(start),
                "size_hex": _hex(size),
                "link": link,
                "info": info,
                "address_alignment_hex": _hex(alignment),
                "entry_size_hex": _hex(entry_size),
                "file_end_hex": None if file_end is None else _hex(file_end),
                "memory_end_hex": None if memory_end is None else _hex(memory_end),
                "file_backed": kind not in (0, 8) and size != 0,
                "geometry_status": status,
            }
        )
    budget.charge(64 * len(ranges) * (len(ranges).bit_length() + 1))
    previous_end = 0
    for start, end in sorted(ranges):
        if start < previous_end:
            raise Elf64LayoutAnalysisError("Nonempty file-backed sections overlap")
        previous_end = end
    return result


@dataclass(slots=True)
class _Plan:
    document: dict
    file: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise Elf64LayoutAnalysisError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    data = _file(source, budget)
    header, phoff, phnum, shoff, shnum = _header(data, budget)
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
        "primary_source_profile": PRIMARY_SOURCE_PROFILE,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "source_file_sha256": _PLACEHOLDER,
        "source_file_bytes": len(data),
        "header": header,
        "program_observations": [],
        "section_observations": [],
        "unassessed_reasons": [],
        "analysis_status": "supported_layout_subset_consistent",
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "ELA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    base_size, base_nodes = _measure(document, budget, report=True)
    retained = _Retained(base_size + 512, base_nodes + 32)
    reasons: set[str] = set()
    if header["file_type"] not in (1, 2, 3):
        _reason(
            reasons,
            "File type semantics outside REL, EXEC and DYN stay unassessed.",
            retained,
            budget,
        )
    if data[7:16] != bytes(9) or header["flags_hex"] != "0x00000000":
        _reason(
            reasons,
            "Nonzero ABI metadata, padding or header flags stay unassessed.",
            retained,
            budget,
        )
    programs = _programs(data, header, phoff, phnum, reasons, retained, budget)
    header_ranges = [(0, 64)]
    if phnum:
        header_ranges.append((phoff, phoff + 56 * phnum))
    if shnum:
        header_ranges.append((shoff, shoff + 64 * shnum))
    sections = _sections(data, shoff, shnum, header_ranges, reasons, retained, budget)
    document["program_observations"] = programs
    document["section_observations"] = sections
    document["unassessed_reasons"] = sorted(reasons)
    if reasons:
        document["analysis_status"] = "layout_semantics_unassessed"
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
    document["analysis_id"] = "ELA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise Elf64LayoutAnalysisError("Report requires its complete embedded source model")
    size, nodes = _measure(document, budget, report=True)
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size + nodes)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise Elf64LayoutAnalysisError("Canonical report does not fully replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not Elf64LayoutAnalysis or not hasattr(report, "document_json"):
        raise Elf64LayoutAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise Elf64LayoutAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class Elf64LayoutAnalysis:
    """Owned unsigned content with full embedded-byte replay on every export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not Elf64LayoutAnalysis:
            raise Elf64LayoutAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> Elf64LayoutAnalysis:
        if cls is not Elf64LayoutAnalysis:
            raise Elf64LayoutAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> Elf64LayoutAnalysis:
        if cls is not Elf64LayoutAnalysis:
            raise Elf64LayoutAnalysisError("Exact native report family required")
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


def _owned(text: str) -> Elf64LayoutAnalysis:
    result = object.__new__(Elf64LayoutAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_elf64_layout(model: Any) -> Elf64LayoutAnalysis:
    """Analyze the supplied layout subset without loader, host or authority effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_elf64_layout_bytes(*, model_bytes: Any) -> Elf64LayoutAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise Elf64LayoutAnalysisError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Elf64LayoutAnalysisError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_elf64_layout_analysis(report: Any, *, model: Any) -> Elf64LayoutAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise Elf64LayoutAnalysisError("Report does not replay the separately supplied original")
    return _owned(separate)


_FIXTURE_BASE64 = (
    "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAAEAAAAAAAABAAAAAAAAAAHgAAAAAAAAAAAAAAEAAOAAB"
    "AEAAAwAAAAEAAAAGAAAAOAEAAAAAAAAAQAAAAAAAAAAAAAAAAAAABAAAAAAAAAAIAAAAAAAAAAQA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAQAAAAAAAADgBAAAAAAAABAAAAAAAAAAAAAAA"
    "AAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAIAAAAAAAAABEAAAAAAAAA8AQAAAAAAAAQAAAAA"
    "AAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAREFUQQ=="
)


def component_fixture() -> dict:
    """Fresh wholly synthetic geometry, not an acquired Linux executable."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-elf64",
        "elf_file_base64": _FIXTURE_BASE64,
    }


__all__ = [
    "Elf64LayoutAnalysis",
    "Elf64LayoutAnalysisError",
    "analyze_supplied_elf64_layout",
    "analyze_supplied_elf64_layout_bytes",
    "verify_supplied_elf64_layout_analysis",
    "component_fixture",
]
