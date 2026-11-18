"""Compare supplied AArch64 ELF section flags with a synthetic W+X policy."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_elf64_layout_analysis import analyze_supplied_elf64_layout

COMPONENT_ID = "exploit_engineering_supplied_aarch64_elf_section_permission_projection"
PROFILE_ID = "AOE-GE-D21-S02"
CAPABILITY_ID = "army.ge.d21.s02"
VECTOR_ID = "AV-GE-D21-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S02"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b571df3c5058882bf49df2407865c5e9650abbb27e10fdd3a2b7faa705ae2bbb"
DOMAIN = "sunderkey.offline-elf-section-permission-policy.v1"
MACHINE_AARCH64 = 183
ALLOC_FLAG = 0x2
WRITE_FLAG = 0x1
EXECUTE_FLAG = 0x4
MAX_MODEL_BYTES = 1_048_576
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class ElfSectionPermissionPolicyError(ValueError):
    """A supplied ELF policy model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ElfSectionPermissionPolicyError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise ElfSectionPermissionPolicyError("Model exceeds the byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = json.loads(model_text)
    if type(model) is not dict or set(model) != {
        "schema_version", "source_id", "synthetic_fixture", "allocated_wx_allowed",
        "elf_layout_model",
    }:
        raise ElfSectionPermissionPolicyError("Model fields are invalid")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ElfSectionPermissionPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise ElfSectionPermissionPolicyError("Only synthetic fixtures are accepted")
    allowed = core.boolean(model["allocated_wx_allowed"], "allocated W+X policy")
    layout = analyze_supplied_elf64_layout(model["elf_layout_model"]).to_dict()
    sections = layout["section_observations"]
    rows = []
    for section in sections:
        flags = int(section["flags_hex"], 16)
        allocated = bool(flags & ALLOC_FLAG)
        writable = bool(flags & WRITE_FLAG)
        executable = bool(flags & EXECUTE_FLAG)
        rows.append({
            "section_index": section["section_index"],
            "flags_hex": section["flags_hex"],
            "allocated_flag_declared": allocated,
            "write_flag_declared": writable,
            "execute_flag_declared": executable,
            "outside_supplied_policy": allocated and writable and executable and not allowed,
        })
    unknown = []
    if layout["header"]["machine"] != MACHINE_AARCH64:
        unknown.append("machine_outside_aarch64_profile")
    if layout["analysis_status"] != "supported_layout_subset_consistent":
        unknown.append("base_elf_layout_not_fully_assessed")
    if any(
        section["section_type"] != 0
        and section["geometry_status"] != "generic_geometry_consistent"
        for section in sections
    ):
        unknown.append("section_geometry_unassessed")
    flagged = [row["section_index"] for row in rows if row["outside_supplied_policy"]]
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
        "allocated_wx_allowed": allowed,
        "section_flag_projections": rows,
        "outside_supplied_policy_section_indexes": flagged,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_elf_section_policy_projection",
        "source_authenticated": False,
        "loader_execution_performed": False,
        "runtime_permissions_verified": False,
        "exploitability_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The ELF bytes and allocated W+X policy are caller-supplied and unauthenticated.",
            "Section flags are static declarations, not measured runtime permissions.",
            "The base parser assesses a bounded little-endian ELF64 layout subset only.",
            "A flagged section does not establish exploitability or vulnerability impact.",
            "No binary is loaded, executed, acquired, or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ESP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ElfSectionPermissionPolicyReport:
    """Unsigned ELF policy projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ElfSectionPermissionPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ElfSectionPermissionPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_elf_section_permissions(model: Any) -> ElfSectionPermissionPolicyReport:
    return ElfSectionPermissionPolicyReport._owned(_derive(model))


def verify_supplied_elf_section_permissions(
    report: Any, *, model: Any
) -> ElfSectionPermissionPolicyReport:
    if type(report) is not ElfSectionPermissionPolicyReport:
        raise ElfSectionPermissionPolicyError("Exact ELF policy wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ElfSectionPermissionPolicyError("Report differs from separate original model")
    return ElfSectionPermissionPolicyReport._owned(expected)


def component_fixture() -> dict:
    from .offline_elf64_layout_analysis import component_fixture as elf_fixture

    layout_model = elf_fixture()
    data = bytearray(base64.b64decode(layout_model["elf_file_base64"]))
    data[18:20] = MACHINE_AARCH64.to_bytes(2, "little")
    layout_model["elf_file_base64"] = base64.b64encode(data).decode("ascii")
    return {
        "schema_version": 1,
        "source_id": "synthetic-aarch64-elf-permission-policy",
        "synthetic_fixture": True,
        "allocated_wx_allowed": False,
        "elf_layout_model": layout_model,
    }
