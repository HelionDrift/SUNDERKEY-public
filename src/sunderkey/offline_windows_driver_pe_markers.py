"""Project supplied PE32+ header markers without driver or kernel claims."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_pe32_layout_analysis import analyze_supplied_pe32plus_layout

COMPONENT_ID = "exploit_engineering_supplied_windows_driver_pe_marker_projection"
PROFILE_ID = "AOE-GE-D21-S03"
CAPABILITY_ID = "army.ge.d21.s03"
VECTOR_ID = "AV-GE-D21-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S03"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4b8ef60dcb8bddeff409065ca4f9e75bf7c394e9746932930e38a6341c92f1bc"
DOMAIN = "sunderkey.offline-windows-driver-pe-markers.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 131_072
NATIVE_SUBSYSTEM = 1
COFF_SYSTEM = 0x1000
WDM_DRIVER = 0x2000
DYNAMIC_BASE = 0x0040
NX_COMPAT = 0x0100
FORCE_INTEGRITY = 0x0080
MARKERS = {
    "native_subsystem", "coff_system", "wdm_driver", "dynamic_base",
    "nx_compatible", "force_integrity",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsDriverPeMarkerError(ValueError):
    """A supplied PE marker model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise WindowsDriverPeMarkerError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise WindowsDriverPeMarkerError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {
            "schema_version", "source_id", "synthetic_fixture",
            "pe_layout_model", "required_marker_ids",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsDriverPeMarkerError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise WindowsDriverPeMarkerError("Only synthetic fixtures are accepted")
    required = [
        core.choice(item, MARKERS, "marker ID")
        for item in core.bounded_list(model["required_marker_ids"], len(MARKERS), "markers")
    ]
    if not required or len(required) != len(set(required)):
        raise WindowsDriverPeMarkerError("Distinct required markers are needed")
    layout = analyze_supplied_pe32plus_layout(model["pe_layout_model"]).to_dict()
    header = layout["header"]
    coff = int(header["coff_characteristics_hex"], 16)
    dll = int(header["dll_characteristics_hex"], 16)
    observed = {
        "native_subsystem": header["subsystem"] == NATIVE_SUBSYSTEM,
        "coff_system": bool(coff & COFF_SYSTEM),
        "wdm_driver": bool(dll & WDM_DRIVER),
        "dynamic_base": bool(dll & DYNAMIC_BASE),
        "nx_compatible": bool(dll & NX_COMPAT),
        "force_integrity": bool(dll & FORCE_INTEGRITY),
    }
    missing = [marker for marker in sorted(required) if not observed[marker]]
    uncertainty = []
    if header["machine_hex"] != "0x8664":
        uncertainty.append("machine_outside_amd64_profile")
    if layout["analysis_status"] != "supported_layout_subset_consistent":
        uncertainty.append("base_pe_layout_not_fully_assessed")
    if any(
        section["geometry_status"] != "declared_section_geometry_consistent"
        for section in layout["section_observations"]
    ):
        uncertainty.append("section_geometry_unassessed")
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
        "base_pe_analysis_id": layout["analysis_id"],
        "base_pe_analysis_sha256": layout["analysis_sha256"],
        "base_pe_source_file_sha256": layout["source_file_sha256"],
        "synthetic_fixture_asserted": True,
        "machine_hex": header["machine_hex"],
        "subsystem_number": header["subsystem"],
        "coff_characteristics_hex": header["coff_characteristics_hex"],
        "dll_characteristics_hex": header["dll_characteristics_hex"],
        "marker_flags_declared": observed,
        "required_marker_ids": sorted(required),
        "missing_required_marker_ids": missing,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_pe_marker_projection",
        "source_authenticated": False,
        "driver_identity_verified": False,
        "signature_verified": False,
        "kernel_loading_verified": False,
        "kernel_exploitability_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "PE bytes and required markers are synthetic caller-supplied assertions.",
            "Native subsystem includes drivers and native processes; it is not driver proof.",
            "Header flags do not prove valid signing, mitigations or kernel loading.",
            "The base parser leaves native subsystem semantics outside its layout subset.",
            "No binary is acquired, loaded, executed or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WDM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsDriverPeMarkerReport:
    """Unsigned PE marker projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsDriverPeMarkerError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsDriverPeMarkerReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_windows_driver_pe_markers(model: Any) -> WindowsDriverPeMarkerReport:
    return WindowsDriverPeMarkerReport._owned(_derive(model))


def verify_supplied_windows_driver_pe_markers(
    report: Any, *, model: Any
) -> WindowsDriverPeMarkerReport:
    if type(report) is not WindowsDriverPeMarkerReport:
        raise WindowsDriverPeMarkerError("Exact PE marker wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsDriverPeMarkerError("Report differs from separate original model")
    return WindowsDriverPeMarkerReport._owned(expected)


def component_fixture() -> dict:
    from .offline_pe32_layout_analysis import component_fixture as pe_fixture

    pe_model = pe_fixture()
    data = bytearray(base64.b64decode(pe_model["pe_file_base64"]))
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20
    characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
    struct.pack_into("<H", data, coff_offset + 18, characteristics | COFF_SYSTEM)
    struct.pack_into("<H", data, optional_offset + 68, NATIVE_SUBSYSTEM)
    dll_characteristics = struct.unpack_from("<H", data, optional_offset + 70)[0]
    struct.pack_into(
        "<H", data, optional_offset + 70,
        dll_characteristics | WDM_DRIVER | DYNAMIC_BASE | NX_COMPAT,
    )
    pe_model["pe_file_base64"] = base64.b64encode(data).decode("ascii")
    return {
        "schema_version": 1,
        "source_id": "synthetic-windows-driver-pe-markers",
        "synthetic_fixture": True,
        "pe_layout_model": pe_model,
        "required_marker_ids": [
            "native_subsystem", "coff_system", "wdm_driver", "dynamic_base", "nx_compatible",
        ],
    }
