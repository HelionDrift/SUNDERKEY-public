"""Compare synthetic protected-material access declarations with approval."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_protected_material_access_projection"
PROFILE_ID = "AOE-GC-D11-S11"
CAPABILITY_ID = "army.gc.d11.s11"
VECTOR_ID = "AV-GC-D11-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:86c8be7ac03339b429e56339fcea5cfea902fe05d9a31aa3bea8c79822c694e9"
DOMAIN = "sunderkey.offline-windows-material-access.v1"
MATERIAL_KINDS = frozenset({"lsass_memory", "dpapi_protected_blob"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsMaterialAccessError(ValueError):
    """A supplied protected-material model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_access_ids", "access_declarations",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsMaterialAccessError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsMaterialAccessError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved access ID")
        for item in core.bounded_list(model["approved_access_ids"], 64, "approvals")
    ]
    if len(approved) != len(set(approved)):
        raise WindowsMaterialAccessError("Approved access IDs must be unique")
    declarations = core.bounded_list(model["access_declarations"], 64, "declarations")
    if not declarations:
        raise WindowsMaterialAccessError("At least one declaration is required")
    rows = []
    seen = set()
    for item in declarations:
        row = core.exact(item, {
            "access_id", "material_kind", "access_declared",
        }, "access declaration")
        access_id = core.identifier(row["access_id"], "access ID")
        kind = core.identifier(row["material_kind"], "material kind")
        if access_id in seen or kind not in MATERIAL_KINDS:
            raise WindowsMaterialAccessError("Duplicate access or unknown material kind")
        seen.add(access_id)
        declared = core.boolean(row["access_declared"], "access declaration")
        flags = (
            ["protected_material_access_outside_supplied_approval"]
            if declared and access_id not in approved else []
        )
        rows.append({
            "access_id": access_id,
            "material_kind": kind,
            "access_declared": declared,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["access_id"])
    deviations = [row["access_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_protected_material_inventory_incomplete"]
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
        "access_projections": rows,
        "declared_policy_deviation_access_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_material_access_projection",
        "source_authenticated": False,
        "host_connected": False,
        "process_memory_read": False,
        "protected_blob_read": False,
        "secret_extracted": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Access declarations, approvals, and completeness are assertions.",
            "The model contains no process memory, protected blobs, or secret values.",
            "An approval mismatch is a review signal, not credential access proof.",
            "No host, process, credential, protected blob, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WMA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsMaterialAccessReport:
    """Unsigned protected-material projection requiring source replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsMaterialAccessError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsMaterialAccessReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_material_access(model: Any) -> WindowsMaterialAccessReport:
    return WindowsMaterialAccessReport._owned(_derive(model))


def verify_supplied_material_access(
    report: Any, *, model: Any
) -> WindowsMaterialAccessReport:
    if type(report) is not WindowsMaterialAccessReport:
        raise WindowsMaterialAccessError("Exact material access wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsMaterialAccessError("Report differs from separate original model")
    return WindowsMaterialAccessReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-protected-material",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_access_ids": ["approved-access"],
        "access_declarations": [{
            "access_id": "review-access",
            "material_kind": "lsass_memory",
            "access_declared": True,
        }],
    }
