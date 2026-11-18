"""Project bounded .modinfo tag presence from a supplied synthetic ELF64 file."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_elf64_layout_analysis import analyze_supplied_elf64_layout

COMPONENT_ID = "exploit_engineering_supplied_linux_module_info_projection"
PROFILE_ID = "AOE-GE-D21-S04"
CAPABILITY_ID = "army.ge.d21.s04"
VECTOR_ID = "AV-GE-D21-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S04"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:50fcc3c463f0c2c4ca5c24596a271900968c22ad1f62f799d2a41bd67823e6d5"
DOMAIN = "sunderkey.offline-linux-module-info.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 131_072
MAX_MODINFO_BYTES = 16_384
MAX_MODINFO_RECORDS = 128
MAX_RECORD_BYTES = 256
TAG = re.compile(rb"[a-z][a-z0-9_]{0,63}\Z")
KNOWN_REQUIRED_TAGS = {"license", "vermagic", "depends", "name", "description"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class LinuxModuleInfoError(ValueError):
    """A supplied module-info model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise LinuxModuleInfoError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise LinuxModuleInfoError("Model exceeds byte bound")
    return result


def _section_bytes(data: bytes, row: dict) -> bytes:
    start = int(row["file_offset_hex"], 16)
    size = int(row["size_hex"], 16)
    if not row["file_backed"] or size == 0 or size > MAX_MODINFO_BYTES:
        raise LinuxModuleInfoError("Required section must be bounded and file-backed")
    if start > len(data) or size > len(data) - start:
        raise LinuxModuleInfoError("Section extent exceeds supplied file")
    return data[start:start + size]


def _name(table: bytes, offset: int) -> str:
    if offset >= len(table):
        raise LinuxModuleInfoError("Section name offset exceeds name table")
    end = table.find(b"\x00", offset)
    if end < 0 or end - offset > 64:
        raise LinuxModuleInfoError("Section name is unterminated or oversized")
    value = table[offset:end]
    if any(byte < 32 or byte > 126 for byte in value):
        raise LinuxModuleInfoError("Section name must be printable ASCII")
    return value.decode("ascii")


def _parse_records(data: bytes) -> dict[str, int]:
    if not data.endswith(b"\x00"):
        raise LinuxModuleInfoError("Module-info records must be NUL terminated")
    values = data[:-1].split(b"\x00")
    if not 1 <= len(values) <= MAX_MODINFO_RECORDS:
        raise LinuxModuleInfoError("Module-info record count exceeds bound")
    counts: dict[str, int] = {}
    for record in values:
        if not 1 <= len(record) <= MAX_RECORD_BYTES or b"=" not in record:
            raise LinuxModuleInfoError("Module-info record is malformed")
        key, content = record.split(b"=", 1)
        if TAG.fullmatch(key) is None:
            raise LinuxModuleInfoError("Module-info tag is malformed")
        if any(byte < 32 or byte > 126 for byte in content):
            raise LinuxModuleInfoError("Module-info value must be printable ASCII")
        label = key.decode("ascii")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {
            "schema_version", "source_id", "synthetic_fixture",
            "elf_layout_model", "required_tag_ids",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise LinuxModuleInfoError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise LinuxModuleInfoError("Only synthetic fixtures are accepted")
    required = [
        core.choice(item, KNOWN_REQUIRED_TAGS, "required tag")
        for item in core.bounded_list(
            model["required_tag_ids"], len(KNOWN_REQUIRED_TAGS), "required tags"
        )
    ]
    if not required or len(required) != len(set(required)):
        raise LinuxModuleInfoError("Distinct required tags are needed")
    layout = analyze_supplied_elf64_layout(model["elf_layout_model"]).to_dict()
    header = layout["header"]
    sections = layout["section_observations"]
    data = base64.b64decode(model["elf_layout_model"]["elf_file_base64"], validate=True)
    table_index = header["section_name_table_index"]
    if table_index == 0 or table_index >= len(sections):
        raise LinuxModuleInfoError("Ordinary section-name table is required")
    table_section = sections[table_index]
    if table_section["section_type"] != 3:
        raise LinuxModuleInfoError("Section-name table must be a string table")
    names = _section_bytes(data, table_section)
    module_sections = [
        row for row in sections
        if row["section_type"] and _name(names, row["name_offset"]) == ".modinfo"
    ]
    if len(module_sections) > 1:
        raise LinuxModuleInfoError("Multiple module-info sections are unsupported")
    tag_counts: dict[str, int] = {}
    section_sha256 = None
    if module_sections:
        module_section = module_sections[0]
        if module_section["section_type"] != 1:
            raise LinuxModuleInfoError("Module-info section must be PROGBITS")
        content = _section_bytes(data, module_section)
        tag_counts = _parse_records(content)
        section_sha256 = "sha256:" + hashlib.sha256(content).hexdigest()
    missing = [tag for tag in sorted(required) if tag not in tag_counts]
    uncertainty = []
    if header["file_type"] != 1:
        uncertainty.append("file_type_not_relocatable")
    if header["machine"] != 62:
        uncertainty.append("machine_outside_amd64_profile")
    if layout["analysis_status"] != "supported_layout_subset_consistent":
        uncertainty.append("base_elf_layout_not_fully_assessed")
    if not module_sections:
        uncertainty.append("module_info_section_absent")
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
        "base_elf_analysis_id": layout["analysis_id"],
        "base_elf_analysis_sha256": layout["analysis_sha256"],
        "base_elf_source_file_sha256": layout["source_file_sha256"],
        "synthetic_fixture_asserted": True,
        "file_type": header["file_type"],
        "machine": header["machine"],
        "module_info_section_present": bool(module_sections),
        "module_info_section_sha256": section_sha256,
        "tag_counts": dict(sorted(tag_counts.items())),
        "required_tag_ids": sorted(required),
        "missing_required_tag_ids": missing,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_module_info_projection",
        "source_authenticated": False,
        "kernel_module_identity_verified": False,
        "module_signature_verified": False,
        "kernel_compatibility_verified": False,
        "module_loaded": False,
        "kernel_exploitability_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "ELF bytes and required tags are synthetic caller-supplied assertions.",
            "Only bounded ELF64 section geometry and printable .modinfo tags are read.",
            "Tag values are not retained; tag presence does not prove module compatibility.",
            "No signature, module loading, kernel behavior or exploitability is verified.",
            "No binary is acquired, executed or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="LMI-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class LinuxModuleInfoReport:
    """Unsigned tag-presence projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise LinuxModuleInfoError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> LinuxModuleInfoReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_linux_module_info(model: Any) -> LinuxModuleInfoReport:
    return LinuxModuleInfoReport._owned(_derive(model))


def verify_supplied_linux_module_info(
    report: Any, *, model: Any
) -> LinuxModuleInfoReport:
    if type(report) is not LinuxModuleInfoReport:
        raise LinuxModuleInfoError("Exact module-info wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise LinuxModuleInfoError("Report differs from separate original model")
    return LinuxModuleInfoReport._owned(expected)


def component_fixture() -> dict:
    data = bytearray(0x1C0)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<HHIQQQIHHHHHH", data, 16,
        1, 62, 1, 0, 0, 0x100, 0, 64, 0, 0, 64, 3, 1,
    )
    names = b"\x00.shstrtab\x00.modinfo\x00"
    info = b"license=GPL\x00vermagic=synthetic\x00depends=\x00"
    data[0x40:0x40 + len(names)] = names
    data[0x80:0x80 + len(info)] = info
    struct.pack_into("<IIQQQQIIQQ", data, 0x100 + 64, 1, 3, 0, 0, 0x40,
                     len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x100 + 128, 11, 1, 0, 0, 0x80,
                     len(info), 0, 0, 1, 0)
    return {
        "schema_version": 1,
        "source_id": "synthetic-linux-module-info",
        "synthetic_fixture": True,
        "elf_layout_model": {
            "schema_version": 1,
            "source_id": "synthetic-elf64-module",
            "elf_file_base64": base64.b64encode(data).decode("ascii"),
        },
        "required_tag_ids": ["license", "vermagic", "depends"],
    }
