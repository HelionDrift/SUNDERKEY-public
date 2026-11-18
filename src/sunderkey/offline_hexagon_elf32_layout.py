"""Check synthetic Hexagon ELF32 program-header geometry without loading."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_engineering_supplied_hexagon_elf32_layout"
PROFILE_ID = "AOE-GE-D21-S06"
CAPABILITY_ID = "army.ge.d21.s06"
VECTOR_ID = "AV-GE-D21-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S06"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f85cd2f600bf68f8b163a7961771e041307776e60472273cc068f8567fdd3f18"
DOMAIN = "sunderkey.offline-hexagon-elf32-layout.v1"
MAX_FILE_BYTES = 65_536
MAX_MODEL_BYTES = 100_000
MAX_REPORT_BYTES = 131_072
MAX_PROGRAM_HEADERS = 32
ELF32_HEADER_SIZE = 52
ELF32_PROGRAM_HEADER_SIZE = 32
EM_HEXAGON = 164
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class HexagonElf32LayoutError(ValueError):
    """A supplied ELF32 model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise HexagonElf32LayoutError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise HexagonElf32LayoutError("Model exceeds byte bound")
    return result


def _file(value: Any) -> bytes:
    if type(value) is not str or len(value) > 4 * ((MAX_FILE_BYTES + 2) // 3):
        raise HexagonElf32LayoutError("Bounded base64 ELF file is required")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HexagonElf32LayoutError("ELF file base64 is invalid") from exc
    if not ELF32_HEADER_SIZE <= len(data) <= MAX_FILE_BYTES:
        raise HexagonElf32LayoutError("ELF file size is outside bound")
    return data


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "elf_file_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HexagonElf32LayoutError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise HexagonElf32LayoutError("Only synthetic fixtures are accepted")
    data = _file(model["elf_file_base64"])
    if data[:7] != b"\x7fELF\x01\x01\x01":
        raise HexagonElf32LayoutError("Only little-endian ELF32 version one is supported")
    fields = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    (
        file_type, machine, file_version, entry, program_offset, section_offset,
        flags, header_size, program_entry_size, program_count, section_entry_size,
        section_count, section_name_index,
    ) = fields
    if file_version != 1 or header_size != ELF32_HEADER_SIZE:
        raise HexagonElf32LayoutError("ELF32 header version or size is invalid")
    if not 1 <= program_count <= MAX_PROGRAM_HEADERS:
        raise HexagonElf32LayoutError("Program-header count is outside bound")
    if program_entry_size != ELF32_PROGRAM_HEADER_SIZE:
        raise HexagonElf32LayoutError("Program-header entry size is unsupported")
    if (
        program_offset < ELF32_HEADER_SIZE
        or program_offset > len(data)
        or program_count * program_entry_size > len(data) - program_offset
    ):
        raise HexagonElf32LayoutError("Program-header table exceeds supplied bytes")
    segments = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        (
            segment_type, file_offset, virtual_address, physical_address,
            file_size, memory_size, segment_flags, alignment,
        ) = struct.unpack_from("<IIIIIIII", data, offset)
        if file_offset > len(data) or file_size > len(data) - file_offset:
            raise HexagonElf32LayoutError("Segment file extent exceeds supplied bytes")
        if segment_type == 1:
            if file_size > memory_size:
                raise HexagonElf32LayoutError("Load segment file size exceeds memory size")
            if alignment > 1 and (
                alignment & (alignment - 1)
                or virtual_address % alignment != file_offset % alignment
            ):
                raise HexagonElf32LayoutError("Load segment alignment is inconsistent")
        if virtual_address + memory_size > 2**32:
            raise HexagonElf32LayoutError("Segment virtual range exceeds ELF32 address space")
        segments.append({
            "index": index,
            "segment_type": segment_type,
            "file_offset_hex": f"0x{file_offset:x}",
            "file_size": file_size,
            "virtual_address_hex": f"0x{virtual_address:x}",
            "physical_address_hex": f"0x{physical_address:x}",
            "memory_size": memory_size,
            "flags_hex": f"0x{segment_flags:x}",
            "alignment": alignment,
            "file_extent_bounded": True,
        })
    uncertainty = ["supplied_file_origin_unverified"]
    if machine != EM_HEXAGON:
        uncertainty.append("machine_not_hexagon")
    if file_type not in {2, 3}:
        uncertainty.append("file_type_outside_executable_shared_subset")
    if section_offset or section_count or section_entry_size or section_name_index:
        uncertainty.append("section_table_not_analyzed")
    body = {
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "source_file_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "synthetic_fixture_asserted": True,
        "source_file_bytes": len(data),
        "file_type": file_type,
        "machine": machine,
        "hexagon_machine_marker": machine == EM_HEXAGON,
        "entry_address_hex": f"0x{entry:x}",
        "header_flags_hex": f"0x{flags:x}",
        "program_header_offset_hex": f"0x{program_offset:x}",
        "section_header_offset_hex": f"0x{section_offset:x}",
        "program_header_count": program_count,
        "load_segment_count": sum(row["segment_type"] == 1 for row in segments),
        "segment_observations": segments,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown",
        "source_authenticated": False,
        "baseband_firmware_identity_verified": False,
        "dsp_code_validated": False,
        "firmware_loadability_verified": False,
        "firmware_executed": False,
        "exploitability_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "ELF bytes are synthetic caller-supplied assertions, not authenticated firmware.",
            "Only ELF32 little-endian header and bounded program extents are checked.",
            "The Hexagon machine ID is a header marker, not processor compatibility proof.",
            "Sections, relocations, signatures, loaders and DSP instructions are not assessed.",
            "No firmware is acquired, loaded, executed or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HEL-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class HexagonElf32LayoutReport:
    """Unsigned geometry projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HexagonElf32LayoutError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HexagonElf32LayoutReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hexagon_elf32_layout(model: Any) -> HexagonElf32LayoutReport:
    return HexagonElf32LayoutReport._owned(_derive(model))


def verify_supplied_hexagon_elf32_layout(
    report: Any, *, model: Any
) -> HexagonElf32LayoutReport:
    if type(report) is not HexagonElf32LayoutReport:
        raise HexagonElf32LayoutError("Exact Hexagon ELF32 wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HexagonElf32LayoutError("Report differs from separate original model")
    return HexagonElf32LayoutReport._owned(expected)


def component_fixture() -> dict:
    data = bytearray(256)
    data[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
    struct.pack_into(
        "<HHIIIIIHHHHHH", data, 16,
        2, EM_HEXAGON, 1, 0x1000, 52, 0, 0, 52, 32, 1, 0, 0, 0,
    )
    struct.pack_into("<IIIIIIII", data, 52, 1, 0x80, 0x1000, 0, 16, 32, 5, 16)
    data[0x80:0x90] = b"synthetic-elf32!"
    return {
        "schema_version": 1,
        "source_id": "synthetic-hexagon-elf32",
        "synthetic_fixture": True,
        "elf_file_base64": base64.b64encode(data).decode("ascii"),
    }
