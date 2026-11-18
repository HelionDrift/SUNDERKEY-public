"""Compare synthetic Windows security-control states with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_security_control_state_projection"
PROFILE_ID = "AOE-GC-D11-S13"
CAPABILITY_ID = "army.gc.d11.s13"
VECTOR_ID = "AV-GC-D11-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S13"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:196dcfafdfe3246353eb73de6cb7201519d55a9bd4a27c4b08a6d7f9b008b4ce"
DOMAIN = "sunderkey.offline-windows-control-state.v1"
CONTROL_KINDS = frozenset({
    "endpoint_protection", "tamper_protection", "host_firewall", "audit",
})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsControlStateError(ValueError):
    """A supplied security-control state model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "required_enabled_control_ids", "controls",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsControlStateError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsControlStateError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    required = [
        core.identifier(item, "required control ID")
        for item in core.bounded_list(
            model["required_enabled_control_ids"], 64, "required controls"
        )
    ]
    if len(required) != len(set(required)):
        raise WindowsControlStateError("Required control IDs must be unique")
    controls = core.bounded_list(model["controls"], 64, "controls")
    if not controls:
        raise WindowsControlStateError("At least one control is required")
    rows = []
    seen = set()
    for item in controls:
        row = core.exact(item, {
            "control_id", "control_kind", "enabled_declared",
        }, "control")
        control_id = core.identifier(row["control_id"], "control ID")
        kind = core.identifier(row["control_kind"], "control kind")
        if control_id in seen or kind not in CONTROL_KINDS:
            raise WindowsControlStateError("Duplicate control or unknown kind")
        seen.add(control_id)
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = (
            ["required_control_declared_disabled"]
            if control_id in required and not enabled else []
        )
        rows.append({
            "control_id": control_id,
            "control_kind": kind,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["control_id"])
    deviations = [row["control_id"] for row in rows if row["declared_policy_flags"]]
    missing_required = sorted(set(required) - seen)
    unknown = [] if complete else ["supplied_security_control_inventory_incomplete"]
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
        "declared_policy_deviation_control_ids": deviations,
        "missing_required_control_ids": missing_required,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_security_control_projection",
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
            "Required controls, states, and completeness are assertions.",
            "The model does not read or alter Windows or EDR control state.",
            "A state mismatch is a review signal, not proof of impairment.",
            "No host, control agent, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WCS-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsControlStateReport:
    """Unsigned control-state projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsControlStateError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsControlStateReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_control_states(model: Any) -> WindowsControlStateReport:
    return WindowsControlStateReport._owned(_derive(model))


def verify_supplied_control_states(
    report: Any, *, model: Any
) -> WindowsControlStateReport:
    if type(report) is not WindowsControlStateReport:
        raise WindowsControlStateError("Exact control state wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsControlStateError("Report differs from separate original model")
    return WindowsControlStateReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-control-states",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "required_enabled_control_ids": ["control-a"],
        "controls": [{
            "control_id": "control-a",
            "control_kind": "endpoint_protection",
            "enabled_declared": False,
        }],
    }
