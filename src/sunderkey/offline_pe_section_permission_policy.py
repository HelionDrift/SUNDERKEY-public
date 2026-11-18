"""Compare supplied AMD64 PE section flags with a synthetic W+X policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_pe32_layout_analysis import analyze_supplied_pe32plus_layout

COMPONENT_ID = "exploit_engineering_supplied_pe_section_permission_projection"
PROFILE_ID = "AOE-GE-D21-S01"
CAPABILITY_ID = "army.ge.d21.s01"
VECTOR_ID = "AV-GE-D21-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S01"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:56e1dca7d1013c182feca80c74798cb98c562f38351a7b523ee28f04428666d2"
DOMAIN = "sunderkey.offline-pe-section-permission-policy.v1"
EXECUTE_FLAG = 0x20000000
WRITE_FLAG = 0x80000000
MAX_MODEL_BYTES = 1_048_576
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PeSectionPermissionPolicyError(ValueError):
    """A supplied PE policy model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise PeSectionPermissionPolicyError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise PeSectionPermissionPolicyError("Model exceeds the byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = json.loads(model_text)
    if type(model) is not dict or set(model) != {
        "schema_version", "source_id", "synthetic_fixture", "writable_executable_allowed",
        "pe_layout_model",
    }:
        raise PeSectionPermissionPolicyError("Model fields are invalid")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PeSectionPermissionPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PeSectionPermissionPolicyError("Only synthetic fixtures are accepted")
    allowed = core.boolean(model["writable_executable_allowed"], "W+X policy")
    layout = analyze_supplied_pe32plus_layout(model["pe_layout_model"]).to_dict()
    sections = layout["section_observations"]
    rows = []
    for section in sections:
        flags = int(section["characteristics_hex"], 16)
        writable = bool(flags & WRITE_FLAG)
        executable = bool(flags & EXECUTE_FLAG)
        rows.append({
            "section_index": section["section_index"],
            "characteristics_hex": section["characteristics_hex"],
            "write_flag_declared": writable,
            "execute_flag_declared": executable,
            "outside_supplied_policy": writable and executable and not allowed,
        })
    unknown = []
    if layout["header"]["machine_hex"] != "0x8664":
        unknown.append("machine_outside_amd64_profile")
    if layout["analysis_status"] != "supported_layout_subset_consistent":
        unknown.append("base_pe_layout_not_fully_assessed")
    if any(
        section["geometry_status"] != "declared_section_geometry_consistent"
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
        "base_pe_analysis_id": layout["analysis_id"],
        "base_pe_analysis_sha256": layout["analysis_sha256"],
        "base_pe_source_file_sha256": layout["source_file_sha256"],
        "synthetic_fixture_asserted": True,
        "writable_executable_allowed": allowed,
        "section_flag_projections": rows,
        "outside_supplied_policy_section_indexes": flagged,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_pe_section_policy_projection",
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
            "The PE bytes and W+X policy are caller-supplied and unauthenticated.",
            "Section flags are static declarations, not measured runtime permissions.",
            "The base parser assesses a bounded AMD64 PE32+ layout subset only.",
            "A flagged section does not establish exploitability or vulnerability impact.",
            "No binary is loaded, executed, acquired, or sent to a target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PeSectionPermissionPolicyReport:
    """Unsigned PE policy projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PeSectionPermissionPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PeSectionPermissionPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pe_section_permissions(model: Any) -> PeSectionPermissionPolicyReport:
    return PeSectionPermissionPolicyReport._owned(_derive(model))


def verify_supplied_pe_section_permissions(
    report: Any, *, model: Any
) -> PeSectionPermissionPolicyReport:
    if type(report) is not PeSectionPermissionPolicyReport:
        raise PeSectionPermissionPolicyError("Exact PE policy wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PeSectionPermissionPolicyError("Report differs from separate original model")
    return PeSectionPermissionPolicyReport._owned(expected)


def component_fixture() -> dict:
    from .offline_pe32_layout_analysis import component_fixture as pe_fixture

    return {
        "schema_version": 1,
        "source_id": "synthetic-pe-permission-policy",
        "synthetic_fixture": True,
        "writable_executable_allowed": False,
        "pe_layout_model": pe_fixture(),
    }
