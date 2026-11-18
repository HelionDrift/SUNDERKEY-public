"""Bounded supplied PE32+ geometry, not loading, authenticity or execution proof."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "windows_supplied_pe32plus_layout"
PROFILE_ID = "AOE-GB-D08-S15"
CAPABILITY_ID = "army.gb.d08.s15"
VECTOR_ID = "AV-GB-D08-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S15"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e17edd936887b65ab10f39ee99a24783d1d68c4f97ec2258b1d43a11e1a6c21c"
PRIMARY_SOURCE_PROFILE = "microsoft-pe-format-reviewed-2026-09-29"
SEMANTICS_PROFILE = "supplied-amd64-pe32plus-geometry-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-pe32plus-model.v1"
DOMAIN = "sunderkey.offline-pe32plus-layout-analysis.v1"
MAX_FILE_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_BASE64_BYTES = 4 * ((MAX_FILE_BYTES + 2) // 3)
MAX_SECTIONS = 96
MAX_DIRECTORIES = 32
MAX_CERTIFICATES = 64
MAX_WORK = 134_217_728
AMD64_ALIGNMENT_BOUNDARY = 4_096
MIN_INTEGER = -(1 << 63)
MAX_INTEGER = (1 << 63) - 1
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "PLA-" + "0" * 32
_MODEL_FIELDS = {"schema_version", "source_id", "pe_file_base64"}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "dos_stub_validated",
        "directory_contents_validated",
        "imports_resolved",
        "relocations_validated",
        "checksum_verified",
        "certificate_payload_validated",
        "certificate_signature_verified",
        "authenticode_verified",
        "mitigations_verified",
        "full_pe_validity_verified",
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
        "publication",
    ),
    "none",
)
_LIMITATIONS = (
    "Supplied bytes and labels are unsigned declarations, not authenticated Windows evidence.",
    "Only bounded PE32+ headers and the named AMD64 geometry profile are assessed.",
    "4096 is a chosen profile boundary, not a measured or universal runtime page size.",
    "Unknown machines do not inherit the AMD64 alignment or directory-mapping profile.",
    "Logical VirtualSize is distinct from raw size, alignment padding and zero-filled tails.",
    "Zero VirtualSize is unassessed; no implicit loader fallback is invented.",
    "Ordinary directory bodies, symbols, imports, relocations and debug data are not parsed.",
    "Certificate addresses are file offsets; only rounded entry envelope occupancy is walked.",
    "Certificate lengths and padding are opaque, not exact payload lengths or signature proof.",
    "The exact whole-file SHA256 is not an Authenticode image hash or a trust decision.",
    "Unknown flags and metadata stay unassessed, not clean or universally malformed.",
    "No loader, runtime permission, executable authenticity, vulnerability or qualification claim.",
    "Complete supplied source is retained unsanitized; the report is not safe for publication.",
    "Software ceilings fund complete public passes, not global lifetime or OS containment.",
)
_DIRECTORY_NAMES = (
    "export",
    "import",
    "resource",
    "exception",
    "certificate",
    "base_relocation",
    "debug",
    "architecture_reserved",
    "global_pointer",
    "tls",
    "load_configuration",
    "bound_import",
    "import_address",
    "delay_import",
    "clr",
    "reserved",
)


class Pe32PlusLayoutAnalysisError(ValueError):
    """Closed input, supplied-geometry, exact-replay or finite software refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise Pe32PlusLayoutAnalysisError("Cumulative software work ceiling exhausted")
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
            raise Pe32PlusLayoutAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise Pe32PlusLayoutAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES:
                raise Pe32PlusLayoutAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise Pe32PlusLayoutAnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise Pe32PlusLayoutAnalysisError("Exact native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise Pe32PlusLayoutAnalysisError("Cyclic native document")
            queued = len(item) * (2 if kind is dict else 1)
            if queued > node_limit - nodes:
                raise Pe32PlusLayoutAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise Pe32PlusLayoutAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise Pe32PlusLayoutAnalysisError("Exact native integer-only JSON families required")

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
        raise Pe32PlusLayoutAnalysisError("Raw bounded integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise Pe32PlusLayoutAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise Pe32PlusLayoutAnalysisError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise Pe32PlusLayoutAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise Pe32PlusLayoutAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise Pe32PlusLayoutAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise Pe32PlusLayoutAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise Pe32PlusLayoutAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise Pe32PlusLayoutAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise Pe32PlusLayoutAnalysisError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_BASE64_BYTES:
                    raise Pe32PlusLayoutAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise Pe32PlusLayoutAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise Pe32PlusLayoutAnalysisError(
                        "Pre-decoder scalar lexical ceiling exhausted"
                    )
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise Pe32PlusLayoutAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise Pe32PlusLayoutAnalysisError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise Pe32PlusLayoutAnalysisError("Integer-only raw JSON required")

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
        raise Pe32PlusLayoutAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _file(source: dict, budget: _Budget) -> bytes:
    if source.keys() != _MODEL_FIELDS:
        raise Pe32PlusLayoutAnalysisError("Exact closed source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise Pe32PlusLayoutAnalysisError("Exact native schema one required")
    identifier = source["source_id"]
    if type(identifier) is not str or _IDENTIFIER.fullmatch(identifier) is None:
        raise Pe32PlusLayoutAnalysisError("Bounded exact native source identity required")
    encoded = source["pe_file_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise Pe32PlusLayoutAnalysisError("Bounded exact native base64 required")
    budget.charge(3 * len(encoded))
    if len(encoded) % 4 or _BASE64.fullmatch(encoded) is None:
        raise Pe32PlusLayoutAnalysisError("Canonical padded base64 required")
    padding = len(encoded) - len(encoded.rstrip("="))
    declared = len(encoded) // 4 * 3 - padding
    if not 64 <= declared <= MAX_FILE_BYTES:
        raise Pe32PlusLayoutAnalysisError("Supplied file byte ceiling or DOS header truncation")
    budget.charge(3 * len(encoded) + 4 * declared)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Pe32PlusLayoutAnalysisError("Malformed canonical base64") from exc
    if len(data) != declared or base64.b64encode(data).decode("ascii") != encoded:
        raise Pe32PlusLayoutAnalysisError("Noncanonical base64 padding bits")
    return data


def _hex(value: int, width: int = 16) -> str:
    return f"0x{value:0{width}x}"


def _end(start: int, size: int, maximum: int = MAX_U32) -> int:
    if size > maximum - start:
        raise Pe32PlusLayoutAnalysisError("Extent exceeds selected unsigned arithmetic profile")
    return start + size


def _file_end(start: int, size: int, data_size: int) -> int:
    if start > data_size or size > data_size - start:
        raise Pe32PlusLayoutAnalysisError("Nonempty file extent contradicts supplied bytes")
    return start + size


def _round(value: int, alignment: int) -> int:
    return _end(value, (-value) % alignment)


def _power_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int

    def reserve(self, size: int, nodes: int, budget: _Budget) -> None:
        if size > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise Pe32PlusLayoutAnalysisError("Cumulative retained report ceiling exhausted")
        budget.charge(size + nodes)
        self.size += size
        self.nodes += nodes


def _reason(reasons: set[str], reason: str, retained: _Retained, budget: _Budget) -> None:
    budget.charge(len(reason))
    if reason not in reasons:
        retained.reserve(len(reason) + 8, 2, budget)
        reasons.add(reason)


def _header(data: bytes, budget: _Budget) -> tuple[dict, int, bool]:
    budget.charge(1_024)
    if data[:2] != b"MZ":
        raise Pe32PlusLayoutAnalysisError("Supplied DOS signature is not MZ")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe < 64:
        raise Pe32PlusLayoutAnalysisError("PE header overlaps fixed DOS header")
    _file_end(pe, 24, len(data))
    if data[pe : pe + 4] != b"PE\0\0":
        raise Pe32PlusLayoutAnalysisError("Supplied PE signature differs")
    machine, count, timestamp, symbols, symbol_count, optional_size, characteristics = (
        struct.unpack_from("<HHIIIHH", data, pe + 4)
    )
    if count > MAX_SECTIONS:
        raise Pe32PlusLayoutAnalysisError("Section count software ceiling exhausted")
    optional = pe + 24
    _file_end(optional, optional_size, len(data))
    if optional_size < 112:
        raise Pe32PlusLayoutAnalysisError("PE32+ optional header is truncated")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise Pe32PlusLayoutAnalysisError("Non-PE32+ format is outside the selected subset")
    count_directories = struct.unpack_from("<I", data, optional + 108)[0]
    if count_directories > MAX_DIRECTORIES:
        raise Pe32PlusLayoutAnalysisError("Directory count software ceiling exhausted")
    if 112 + 8 * count_directories > optional_size:
        raise Pe32PlusLayoutAnalysisError("Directory table exceeds declared optional header")
    section_table = optional + optional_size
    table_end = _file_end(section_table, count * 40, len(data))
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    image_size, headers_size = struct.unpack_from("<II", data, optional + 56)
    if headers_size < table_end or headers_size > len(data) or image_size < headers_size:
        raise Pe32PlusLayoutAnalysisError("Header/image extents contradict supplied header table")
    if image_size > 0x80000000:
        raise Pe32PlusLayoutAnalysisError("Image size exceeds the selected PE32+ size subset")
    image_end = _end(image_base, image_size, MAX_U64)
    known_machine = machine == 0x8664
    alignment_profile = "machine_unassessed"
    if known_machine:
        if pe % 8 or image_base % 65_536:
            raise Pe32PlusLayoutAnalysisError(
                "Header/ImageBase alignment contradicts named profile"
            )
        if not _power_two(section_alignment) or not _power_two(file_alignment):
            raise Pe32PlusLayoutAnalysisError("Alignment is outside named power-of-two profile")
        if section_alignment < AMD64_ALIGNMENT_BOUNDARY:
            if file_alignment != section_alignment:
                raise Pe32PlusLayoutAnalysisError("Low-alignment profile requires equal alignments")
            alignment_profile = "amd64_selected_low_alignment"
        else:
            if not 512 <= file_alignment <= 65_536 or section_alignment < file_alignment:
                raise Pe32PlusLayoutAnalysisError("Ordinary file/section alignment contradicts")
            alignment_profile = "amd64_selected_ordinary_alignment"
        if headers_size % file_alignment or headers_size < _round(table_end, file_alignment):
            raise Pe32PlusLayoutAnalysisError("SizeOfHeaders does not cover aligned header table")
        if not image_size or image_size % section_alignment:
            raise Pe32PlusLayoutAnalysisError("SizeOfImage is not section-aligned")
    stack_reserve, stack_commit, heap_reserve, heap_commit = struct.unpack_from(
        "<QQQQ", data, optional + 72
    )
    return (
        {
            "dos_signature": "MZ",
            "pe_header_file_offset": pe,
            "pe_signature_hex": "50450000",
            "coff_file_offset": pe + 4,
            "machine_hex": _hex(machine, 4),
            "section_count": count,
            "timestamp_raw": timestamp,
            "symbol_table_file_offset": symbols,
            "symbol_count": symbol_count,
            "optional_header_file_offset": optional,
            "optional_header_bytes": optional_size,
            "coff_characteristics_hex": _hex(characteristics, 4),
            "optional_magic_hex": "0x020b",
            "linker_major": data[optional + 2],
            "linker_minor": data[optional + 3],
            "code_bytes": struct.unpack_from("<I", data, optional + 4)[0],
            "initialized_data_bytes": struct.unpack_from("<I", data, optional + 8)[0],
            "uninitialized_data_bytes": struct.unpack_from("<I", data, optional + 12)[0],
            "entry_rva": struct.unpack_from("<I", data, optional + 16)[0],
            "code_rva": struct.unpack_from("<I", data, optional + 20)[0],
            "image_base_hex": _hex(image_base),
            "image_end_hex": _hex(image_end),
            "section_alignment": section_alignment,
            "file_alignment": file_alignment,
            "alignment_profile": alignment_profile,
            "image_bytes": image_size,
            "header_bytes": headers_size,
            "checksum_raw": struct.unpack_from("<I", data, optional + 64)[0],
            "subsystem": struct.unpack_from("<H", data, optional + 68)[0],
            "dll_characteristics_hex": _hex(struct.unpack_from("<H", data, optional + 70)[0], 4),
            "os_major": struct.unpack_from("<H", data, optional + 40)[0],
            "os_minor": struct.unpack_from("<H", data, optional + 42)[0],
            "image_major": struct.unpack_from("<H", data, optional + 44)[0],
            "image_minor": struct.unpack_from("<H", data, optional + 46)[0],
            "subsystem_major": struct.unpack_from("<H", data, optional + 48)[0],
            "subsystem_minor": struct.unpack_from("<H", data, optional + 50)[0],
            "win32_version_raw": struct.unpack_from("<I", data, optional + 52)[0],
            "stack_reserve_hex": _hex(stack_reserve),
            "stack_commit_hex": _hex(stack_commit),
            "heap_reserve_hex": _hex(heap_reserve),
            "heap_commit_hex": _hex(heap_commit),
            "loader_flags_raw": struct.unpack_from("<I", data, optional + 104)[0],
            "directory_count": count_directories,
            "directory_table_file_offset": optional + 112,
            "optional_extension_bytes": optional_size - (112 + 8 * count_directories),
            "section_table_file_offset": section_table,
            "section_table_file_end": table_end,
        },
        section_table,
        known_machine,
    )


def _sections(
    data: bytes,
    header: dict,
    start: int,
    known: bool,
    reasons: set[str],
    retained: _Retained,
    budget: _Budget,
) -> list[dict]:
    rows = []
    raw_ranges = []
    for index in range(header["section_count"]):
        retained.reserve(2_048, 128, budget)
        budget.charge(512)
        offset = start + index * 40
        (
            name,
            virtual_size,
            rva,
            raw_size,
            raw_pointer,
            relocations,
            lines,
            reloc_count,
            line_count,
            flags,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, offset)
        raw_end = None
        virtual_end = None if not virtual_size else _end(rva, virtual_size)
        if virtual_end is not None and virtual_end > header["image_bytes"]:
            raise Pe32PlusLayoutAnalysisError("Logical virtual extent exceeds declared image")
        if raw_size:
            raw_end = _file_end(raw_pointer, raw_size, len(data))
            if raw_pointer < header["header_bytes"]:
                raise Pe32PlusLayoutAnalysisError("Section raw extent overlaps supplied headers")
            if known and raw_ranges and raw_pointer < raw_ranges[-1][1]:
                raise Pe32PlusLayoutAnalysisError(
                    "Raw section data is not in declared section order"
                )
            raw_ranges.append((raw_pointer, raw_end))
            if known:
                if raw_pointer % header["file_alignment"] or raw_size % header["file_alignment"]:
                    raise Pe32PlusLayoutAnalysisError(
                        "Nonempty raw section extent is not file-aligned"
                    )
                if (
                    header["alignment_profile"] == "amd64_selected_low_alignment"
                    and raw_pointer != rva
                ):
                    raise Pe32PlusLayoutAnalysisError("Low-alignment raw offset differs from RVA")
        if known and virtual_size and rva % header["section_alignment"]:
            raise Pe32PlusLayoutAnalysisError("Nonempty logical section RVA is not aligned")
        if not virtual_size:
            _reason(
                reasons,
                "Zero VirtualSize and its loader interpretation remain unassessed.",
                retained,
                budget,
            )
        if not raw_size and raw_pointer:
            _reason(
                reasons,
                "A no-file-data raw pointer is retained without a file extent.",
                retained,
                budget,
            )
        if flags & ~0xFE0000E0:
            _reason(
                reasons,
                "Section flags outside the declared image subset stay unassessed.",
                retained,
                budget,
            )
        if relocations or lines or reloc_count or line_count:
            _reason(
                reasons,
                "Section relocation and line-number contents stay unassessed.",
                retained,
                budget,
            )
        rows.append(
            {
                "section_index": index + 1,
                "header_file_offset": offset,
                "name_hex": name.hex(),
                "virtual_rva": rva,
                "logical_virtual_bytes": virtual_size,
                "logical_virtual_end": virtual_end,
                "raw_file_offset": raw_pointer,
                "raw_file_bytes": raw_size,
                "raw_file_end": raw_end,
                "declared_zero_fill_bytes": max(0, virtual_size - raw_size)
                if virtual_size
                else None,
                "raw_beyond_logical_bytes": max(0, raw_size - virtual_size)
                if virtual_size
                else None,
                "relocation_file_offset": relocations,
                "line_number_file_offset": lines,
                "relocation_count": reloc_count,
                "line_number_count": line_count,
                "characteristics_hex": _hex(flags, 8),
                "geometry_status": "logical_size_unassessed"
                if not virtual_size
                else (
                    "declared_section_geometry_consistent"
                    if known
                    else "machine_geometry_unassessed"
                ),
            }
        )
    budget.charge(64 * len(raw_ranges) * (len(raw_ranges).bit_length() + 1))
    previous_end = header["header_bytes"]
    for lower, upper in sorted(raw_ranges):
        if lower < previous_end:
            raise Pe32PlusLayoutAnalysisError("Nonempty section raw extents overlap")
        previous_end = upper
    if known and rows and all(row["logical_virtual_bytes"] for row in rows):
        expected = _round(header["header_bytes"], header["section_alignment"])
        for row in rows:
            if row["virtual_rva"] != expected:
                raise Pe32PlusLayoutAnalysisError("Logical sections are not ascending and adjacent")
            expected = _round(row["logical_virtual_end"], header["section_alignment"])
        if expected > header["image_bytes"]:
            raise Pe32PlusLayoutAnalysisError("Aligned section end exceeds declared image")
    else:
        _reason(reasons, "Full virtual section topology stays unassessed.", retained, budget)
    return rows


def _certificate_entries(
    data: bytes,
    offset: int,
    size: int,
    header: dict,
    sections: list[dict],
    reasons: set[str],
    retained: _Retained,
    budget: _Budget,
) -> list[dict]:
    end = _file_end(offset, size, len(data))
    if offset % 8 or offset < header["header_bytes"]:
        raise Pe32PlusLayoutAnalysisError("Certificate file offset contradicts envelope profile")
    budget.charge(32 * len(sections))
    if any(
        row["raw_file_bytes"]
        and max(offset, row["raw_file_offset"]) < min(end, row["raw_file_end"])
        for row in sections
    ):
        raise Pe32PlusLayoutAnalysisError("Certificate file extent overlaps section data")
    rows = []
    cursor = offset
    while cursor < end:
        if len(rows) >= MAX_CERTIFICATES:
            raise Pe32PlusLayoutAnalysisError("Certificate entry software ceiling exhausted")
        retained.reserve(512, 32, budget)
        budget.charge(256)
        if end - cursor < 8:
            raise Pe32PlusLayoutAnalysisError("Certificate envelope header is truncated")
        length, revision, kind = struct.unpack_from("<IHH", data, cursor)
        if length < 8:
            raise Pe32PlusLayoutAnalysisError("Certificate dwLength cannot cover its header")
        rounded = _round(length, 8)
        if rounded > end - cursor:
            raise Pe32PlusLayoutAnalysisError("Rounded certificate occupancy exceeds table")
        rows.append(
            {
                "entry_index": len(rows) + 1,
                "file_offset": cursor,
                "dw_length": length,
                "rounded_occupied_bytes": rounded,
                "occupied_file_end": cursor + rounded,
                "revision_hex": _hex(revision, 4),
                "certificate_type_hex": _hex(kind, 4),
                "contents_status": "opaque_length_padding_and_certificate_payload",
            }
        )
        if revision not in (0x100, 0x200) or kind != 2:
            _reason(
                reasons, "Certificate revision/type semantics stay unassessed.", retained, budget
            )
        cursor += rounded
    if cursor != end:
        raise Pe32PlusLayoutAnalysisError("Certificate rounded walk does not fill table")
    _reason(
        reasons,
        "Certificate payloads, padding semantics and signatures stay unassessed.",
        retained,
        budget,
    )
    return rows


def _directories(
    data: bytes,
    header: dict,
    sections: list[dict],
    known: bool,
    reasons: set[str],
    retained: _Retained,
    budget: _Budget,
) -> tuple[list[dict], list[dict]]:
    rows = []
    certificates = []
    for index in range(header["directory_count"]):
        retained.reserve(1_024, 64, budget)
        budget.charge(256 + 64 * len(sections))
        offset = header["directory_table_file_offset"] + 8 * index
        address, size = struct.unpack_from("<II", data, offset)
        row = {
            "directory_index": index,
            "header_file_offset": offset,
            "directory_name": _DIRECTORY_NAMES[index] if index < 16 else "extension_unassessed",
            "address_raw": address,
            "size_raw": size,
            "address_kind": "file_offset"
            if index == 4
            else ("rva" if index < 16 else "unassessed"),
            "declared_end": None,
            "file_backing_offset": None,
            "geometry_status": "absent_declared_pair"
            if not address and not size
            else "semantics_unassessed",
        }
        if address or size:
            if index >= 16 or index in (7, 15):
                _reason(
                    reasons,
                    "Reserved/extension directory semantics stay unassessed.",
                    retained,
                    budget,
                )
            elif index == 8:
                if known and address and not size and address < header["image_bytes"]:
                    row["geometry_status"] = "declared_global_pointer_rva_only"
                else:
                    _reason(
                        reasons, "Global-pointer declaration stays unassessed.", retained, budget
                    )
            elif not address or not size:
                _reason(
                    reasons,
                    "A partial directory address/size pair stays unassessed.",
                    retained,
                    budget,
                )
            elif index == 4:
                row["declared_end"] = _file_end(address, size, len(data))
                certificates = _certificate_entries(
                    data, address, size, header, sections, reasons, retained, budget
                )
                row["file_backing_offset"] = address
                row["geometry_status"] = "certificate_file_envelopes_only"
            else:
                end = _end(address, size)
                row["declared_end"] = end
                if end > header["image_bytes"]:
                    raise Pe32PlusLayoutAnalysisError("Directory RVA extent exceeds declared image")
                backed = []
                if known:
                    if end <= header["header_bytes"]:
                        backed.append(address)
                    for section in sections:
                        delta = address - section["virtual_rva"]
                        if (
                            delta >= 0
                            and section["logical_virtual_bytes"]
                            and end <= section["logical_virtual_end"]
                            and delta + size <= section["raw_file_bytes"]
                        ):
                            backed.append(section["raw_file_offset"] + delta)
                if len(backed) == 1:
                    row["file_backing_offset"] = backed[0]
                    row["geometry_status"] = "unique_logical_raw_backing_contents_unassessed"
                else:
                    _reason(
                        reasons,
                        "Directory mapping across padding/zero-fill/unknown regions "
                        "stays unassessed.",
                        retained,
                        budget,
                    )
                _reason(
                    reasons,
                    "Advertised directory payload contents stay unassessed.",
                    retained,
                    budget,
                )
        rows.append(row)
    return rows, certificates


def _bounds() -> dict:
    return {
        "file_bytes": MAX_FILE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "native_depth": MAX_DEPTH,
        "section_headers": MAX_SECTIONS,
        "directory_entries": MAX_DIRECTORIES,
        "certificate_entries": MAX_CERTIFICATES,
        "cumulative_work": MAX_WORK,
        "amd64_selected_alignment_boundary": AMD64_ALIGNMENT_BOUNDARY,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    file: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise Pe32PlusLayoutAnalysisError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    data = _file(source, budget)
    header, section_table, known = _header(data, budget)
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
        "roadmap_package_ids": ["A7.4"],
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "source_file_sha256": _PLACEHOLDER,
        "source_file_bytes": len(data),
        "header": header,
        "section_observations": [],
        "directory_observations": [],
        "certificate_observations": [],
        "trailing_file_extent": None,
        "unassessed_reasons": [],
        "analysis_status": "supported_layout_subset_consistent",
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    initial_size, initial_nodes = _measure(document, budget, report=True)
    retained = _Retained(initial_size + 1_024, initial_nodes + 64)
    reasons: set[str] = set()
    if not known:
        _reason(
            reasons,
            "Machine semantics and AMD64 geometry are unassessed for this machine.",
            retained,
            budget,
        )
    if (
        int(header["coff_characteristics_hex"], 16) & ~0x2023
        or not int(header["coff_characteristics_hex"], 16) & 2
    ):
        _reason(
            reasons, "COFF image flags outside the named subset stay unassessed.", retained, budget
        )
    if int(header["dll_characteristics_hex"], 16) & ~0xFFE0:
        _reason(reasons, "Unknown/reserved DLL flags stay unassessed.", retained, budget)
    if header["subsystem"] not in (2, 3):
        _reason(reasons, "Subsystem semantics outside GUI/CUI stay unassessed.", retained, budget)
    if header["symbol_table_file_offset"] or header["symbol_count"]:
        _reason(reasons, "COFF symbol contents stay unassessed.", retained, budget)
    if (
        header["win32_version_raw"]
        or header["loader_flags_raw"]
        or header["optional_extension_bytes"]
    ):
        _reason(
            reasons,
            "Reserved/extended optional-header metadata stays unassessed.",
            retained,
            budget,
        )
    sections = _sections(data, header, section_table, known, reasons, retained, budget)
    directories, certificates = _directories(
        data, header, sections, known, reasons, retained, budget
    )
    used = max(
        [header["header_bytes"]]
        + [row["raw_file_end"] for row in sections if row["raw_file_end"] is not None]
        + [row["occupied_file_end"] for row in certificates]
    )
    if used < len(data):
        document["trailing_file_extent"] = {"file_offset": used, "bytes": len(data) - used}
        _reason(
            reasons,
            "Trailing supplied bytes may be overlay/debug data and stay unassessed.",
            retained,
            budget,
        )
    document["section_observations"] = sections
    document["directory_observations"] = directories
    document["certificate_observations"] = certificates
    document["unassessed_reasons"] = sorted(reasons)
    if reasons:
        document["analysis_status"] = "layout_semantics_unassessed"
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        12 * size
        + 6 * source_size
        + 4 * len(data)
        + 8 * nodes
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, data, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()
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
    document["analysis_id"] = "PLA-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise Pe32PlusLayoutAnalysisError("Exact complete native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise Pe32PlusLayoutAnalysisError("Report requires complete embedded original source")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "source_file_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise Pe32PlusLayoutAnalysisError("Exact report SHA256 address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "PLA-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise Pe32PlusLayoutAnalysisError("Exact report identity/address join required")
    budget.charge(12 * size + 4 * expected.size + 8 * nodes)
    placeholder = {
        **owned,
        "source_model_sha256": _PLACEHOLDER,
        "source_file_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    if _canonical(placeholder) != _canonical(expected.document):
        raise Pe32PlusLayoutAnalysisError(
            "Report metadata does not replay original supplied geometry"
        )
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise Pe32PlusLayoutAnalysisError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise Pe32PlusLayoutAnalysisError("Report addresses do not replay complete original source")
    return document


def _stored(report: Any) -> str:
    if type(report) is not Pe32PlusLayoutAnalysis:
        raise Pe32PlusLayoutAnalysisError("Exact complete native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise Pe32PlusLayoutAnalysisError("Exact native retained report text required")
    return text


@dataclass(frozen=True, slots=True)
class Pe32PlusLayoutAnalysis:
    """Unsigned detached source-backed metadata, not a trusted Windows executable."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not Pe32PlusLayoutAnalysis:
            raise Pe32PlusLayoutAnalysisError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> Pe32PlusLayoutAnalysis:
        if cls is not Pe32PlusLayoutAnalysis:
            raise Pe32PlusLayoutAnalysisError("Exact native report family required")
        budget = _Budget()
        _document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise Pe32PlusLayoutAnalysisError("Report addresses do not replay source")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> Pe32PlusLayoutAnalysis:
        if cls is not Pe32PlusLayoutAnalysis:
            raise Pe32PlusLayoutAnalysisError("Exact native report family required")
        _replay_text(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay_text(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay_text(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _owned(text: str) -> Pe32PlusLayoutAnalysis:
    result = object.__new__(Pe32PlusLayoutAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_pe32plus_layout(model: Any) -> Pe32PlusLayoutAnalysis:
    """Calculate the named supplied layout subset with no loader or target effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_pe32plus_layout_bytes(*, model_bytes: Any) -> Pe32PlusLayoutAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise Pe32PlusLayoutAnalysisError("Bounded exact native model JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Pe32PlusLayoutAnalysisError("ASCII model JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_pe32plus_layout_analysis(report: Any, *, model: Any) -> Pe32PlusLayoutAnalysis:
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    if text != canonical:
        raise Pe32PlusLayoutAnalysisError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise Pe32PlusLayoutAnalysisError(
            "Report differs from embedded or separately original source"
        )
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh inert synthetic header/data bytes; nothing is acquired or executed."""
    data = bytearray(1_024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 8, 512)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 4_096, 512)
    struct.pack_into("<II", data, optional + 56, 8_192, 512)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<QQQQ", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into(
        "<8sIIIIIIHHI", data, 0x188, b".data\0\0\0", 32, 0x1000, 512, 512, 0, 0, 0, 0, 0xC0000040
    )
    data[512:516] = b"DATA"
    return {
        "schema_version": 1,
        "source_id": "synthetic-pe32plus",
        "pe_file_base64": base64.b64encode(data).decode("ascii"),
    }


__all__ = [
    "Pe32PlusLayoutAnalysis",
    "Pe32PlusLayoutAnalysisError",
    "analyze_supplied_pe32plus_layout",
    "analyze_supplied_pe32plus_layout_bytes",
    "verify_supplied_pe32plus_layout_analysis",
    "component_fixture",
]
