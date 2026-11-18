"""Compare synthetic TCC, SIP, and Gatekeeper states with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_security_control_policy_projection"
PROFILE_ID = "AOE-GC-D12-S10"
CAPABILITY_ID = "army.gc.d12.s10"
VECTOR_ID = "AV-GC-D12-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:036b971e77240e5f5b1fc66736ddb0002a97cc32effd9b9890d085f637521e86"
DOMAIN = "sunderkey.offline-macos-security-controls.v1"
CONTROL_IDS = frozenset({"tcc", "sip", "gatekeeper"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosSecurityControlError(ValueError):
    """A supplied macOS security-control model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "required_enabled_control_ids", "controls",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosSecurityControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosSecurityControlError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    required = [
        core.identifier(item, "required control ID")
        for item in core.bounded_list(
            model["required_enabled_control_ids"], 3, "required controls"
        )
    ]
    if len(required) != len(set(required)) or not set(required).issubset(CONTROL_IDS):
        raise MacosSecurityControlError("Required controls must be unique and known")
    controls = core.bounded_list(model["controls"], 3, "controls")
    if not controls:
        raise MacosSecurityControlError("At least one control is required")
    rows = []
    seen = set()
    for item in controls:
        row = core.exact(item, {"control_id", "enabled_declared"}, "control")
        control_id = core.identifier(row["control_id"], "control ID")
        if control_id in seen or control_id not in CONTROL_IDS:
            raise MacosSecurityControlError("Duplicate or unknown control")
        seen.add(control_id)
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = (
            ["required_control_declared_disabled"]
            if control_id in required and not enabled else []
        )
        rows.append({
            "control_id": control_id,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["control_id"])
    missing_required = sorted(set(required) - seen)
    deviations = [row["control_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_macos_control_inventory_incomplete"]
    if missing_required:
        unknown.append("required_control_absent_from_supplied_inventory")
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "control_projections": rows,
        "missing_required_control_ids": missing_required,
        "declared_policy_deviation_control_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_macos_control_projection",
        "source_authenticated": False,
        "host_connected": False,
        "control_state_verified": False,
        "control_changed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Required TCC, SIP, Gatekeeper states and completeness are assertions.",
            "The model does not read or alter effective macOS control state.",
            "A declared mismatch does not prove control bypass or impairment.",
            "No host, control service, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MSC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosSecurityControlReport:
    """Unsigned control projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosSecurityControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosSecurityControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_macos_controls(model: Any) -> MacosSecurityControlReport:
    return MacosSecurityControlReport._owned(_derive(model))


def verify_supplied_macos_controls(
    report: Any, *, model: Any
) -> MacosSecurityControlReport:
    if type(report) is not MacosSecurityControlReport:
        raise MacosSecurityControlError("Exact macOS control wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosSecurityControlError("Report differs from separate original model")
    return MacosSecurityControlReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-macos-controls",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "required_enabled_control_ids": ["sip", "gatekeeper"],
        "controls": [
            {"control_id": "sip", "enabled_declared": False},
            {"control_id": "gatekeeper", "enabled_declared": True},
        ],
    }
