"""Project synthetic Apple kernel Mach-O markers without signing claims."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_macho_analysis import analyze_supplied_macho_layout

COMPONENT_ID = "exploit_engineering_supplied_apple_kernel_macho_markers"
PROFILE_ID = "AOE-GE-D21-S05"
CAPABILITY_ID = "army.ge.d21.s05"
VECTOR_ID = "AV-GE-D21-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S05"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:34b988eac4056175d8d82f49b7147bed5689ec525d46e83a7797f9105441c847"
DOMAIN = "sunderkey.offline-apple-kernel-macho-markers.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 131_072
KNOWN_MARKERS = {
    "kext_bundle_file_type", "fileset_file_type", "x86_64_cpu", "arm64_cpu",
    "code_signature_command", "code_signature_extent_bounded", "uuid_command",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class AppleKernelMachoMarkerError(ValueError):
    """A supplied Mach-O marker model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AppleKernelMachoMarkerError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise AppleKernelMachoMarkerError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "macho_layout_model",
         "required_marker_ids"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AppleKernelMachoMarkerError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise AppleKernelMachoMarkerError("Only synthetic fixtures are accepted")
    required = [
        core.choice(item, KNOWN_MARKERS, "required marker")
        for item in core.bounded_list(
            model["required_marker_ids"], len(KNOWN_MARKERS), "required markers"
        )
    ]
    if not required or len(required) != len(set(required)):
        raise AppleKernelMachoMarkerError("Distinct required markers are needed")
    layout = analyze_supplied_macho_layout(model["macho_layout_model"]).to_dict()
    header = layout["header"]
    commands = layout["command_observations"]
    data = base64.b64decode(model["macho_layout_model"]["macho_file_base64"], validate=True)
    signature_rows = [row for row in commands if row["command_code"] == 0x1D]
    if len(signature_rows) > 1:
        raise AppleKernelMachoMarkerError("Multiple code-signature commands are unsupported")
    signature_extent = None
    signature_extent_bounded = False
    if signature_rows:
        row = signature_rows[0]
        if row["command_bytes"] != 16:
            raise AppleKernelMachoMarkerError("Code-signature command size is unsupported")
        start, size = struct.unpack_from("<II", data, row["offset"] + 8)
        signature_extent_bounded = bool(
            size and start >= header["commands_end_offset"]
            and start <= len(data) and size <= len(data) - start
        )
        signature_extent = {
            "file_offset_hex": f"0x{start:x}",
            "byte_count": size,
            "within_supplied_file": signature_extent_bounded,
        }
    markers = {
        "kext_bundle_file_type": header["file_type"] == 0xB,
        "fileset_file_type": header["file_type"] == 0xC,
        "x86_64_cpu": header["cpu_type"] == 0x01000007,
        "arm64_cpu": header["cpu_type"] == 0x0100000C,
        "code_signature_command": bool(signature_rows),
        "code_signature_extent_bounded": signature_extent_bounded,
        "uuid_command": any(row["command_code"] == 0x1B for row in commands),
    }
    missing = [item for item in sorted(required) if not markers[item]]
    uncertainty = ["base_macho_file_type_semantics_unassessed"]
    if layout["analysis_status"] != "supported_layout_subset_consistent":
        uncertainty.append("base_macho_layout_has_unassessed_semantics")
    if signature_rows and not signature_extent_bounded:
        uncertainty.append("code_signature_extent_not_bounded")
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
        "base_macho_analysis_id": layout["analysis_id"],
        "base_macho_analysis_sha256": layout["analysis_sha256"],
        "base_macho_source_file_sha256": layout["source_file_sha256"],
        "synthetic_fixture_asserted": True,
        "file_type": header["file_type"],
        "cpu_type": header["cpu_type"],
        "marker_flags_declared": markers,
        "required_marker_ids": sorted(required),
        "missing_required_marker_ids": missing,
        "code_signature_extent": signature_extent,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown",
        "source_authenticated": False,
        "kernel_artifact_identity_verified": False,
        "code_signature_verified": False,
        "kernel_loading_verified": False,
        "kernel_exploitability_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Mach-O bytes and required markers are synthetic caller-supplied assertions.",
            "The base parser does not assess kext or fileset loader semantics.",
            "A code-signature command and bounded blob are not signature verification.",
            "No kernel loading, device behavior, exploitability or finding is established.",
            "No binary is acquired, executed or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="AKM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class AppleKernelMachoMarkerReport:
    """Unsigned marker projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AppleKernelMachoMarkerError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AppleKernelMachoMarkerReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_apple_kernel_macho_markers(
    model: Any,
) -> AppleKernelMachoMarkerReport:
    return AppleKernelMachoMarkerReport._owned(_derive(model))


def verify_supplied_apple_kernel_macho_markers(
    report: Any, *, model: Any
) -> AppleKernelMachoMarkerReport:
    if type(report) is not AppleKernelMachoMarkerReport:
        raise AppleKernelMachoMarkerError("Exact Apple kernel marker wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AppleKernelMachoMarkerError("Report differs from separate original model")
    return AppleKernelMachoMarkerReport._owned(expected)


def component_fixture() -> dict:
    data = bytearray(128)
    struct.pack_into("<IiiIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, 0xB, 2, 40, 0, 0)
    struct.pack_into("<II16s", data, 32, 0x1B, 24, b"synthetic-uuid-id")
    struct.pack_into("<IIII", data, 56, 0x1D, 16, 96, 16)
    data[96:112] = b"synthetic-sign!!"
    return {
        "schema_version": 1,
        "source_id": "synthetic-apple-kernel-macho-markers",
        "synthetic_fixture": True,
        "macho_layout_model": {
            "schema_version": 1,
            "source_id": "synthetic-macho64-kext",
            "macho_file_base64": base64.b64encode(data).decode("ascii"),
        },
        "required_marker_ids": [
            "kext_bundle_file_type", "x86_64_cpu", "code_signature_command",
            "code_signature_extent_bounded", "uuid_command",
        ],
    }
