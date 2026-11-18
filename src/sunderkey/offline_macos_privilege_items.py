"""Project synthetic macOS privileged item write declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_privileged_item_policy_projection"
PROFILE_ID = "AOE-GC-D12-S09"
CAPABILITY_ID = "army.gc.d12.s09"
VECTOR_ID = "AV-GC-D12-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5a67544e98c413d435b2124bc1bbdec87589dc16f0f52ba1f842c21be9da45ab"
DOMAIN = "sunderkey.offline-macos-privilege-items.v1"
ITEM_KINDS = frozenset({"launch_daemon", "privileged_helper", "startup_item"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosPrivilegeItemError(ValueError):
    """A supplied macOS privilege item model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "items",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosPrivilegeItemError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosPrivilegeItemError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    items = core.bounded_list(model["items"], 64, "items")
    if not items:
        raise MacosPrivilegeItemError("At least one item is required")
    rows = []
    seen = set()
    for item in items:
        row = core.exact(item, {
            "item_id", "item_kind", "root_execution_declared",
            "user_writable_declared",
        }, "item")
        item_id = core.identifier(row["item_id"], "item ID")
        kind = core.identifier(row["item_kind"], "item kind")
        if item_id in seen or kind not in ITEM_KINDS:
            raise MacosPrivilegeItemError("Duplicate item or unknown kind")
        seen.add(item_id)
        root = core.boolean(row["root_execution_declared"], "root execution declaration")
        writable = core.boolean(row["user_writable_declared"], "user write declaration")
        flags = ["declared_user_write_root_execution_overlap"] if root and writable else []
        rows.append({
            "item_id": item_id,
            "item_kind": kind,
            "root_execution_declared": root,
            "user_writable_declared": writable,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["item_id"])
    deviations = [row["item_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_macos_privilege_item_inventory_incomplete"]
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
        "item_projections": rows,
        "declared_policy_deviation_item_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_macos_privilege_item_projection",
        "source_authenticated": False,
        "host_connected": False,
        "permissions_verified": False,
        "item_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Item kinds, permissions, execution context, and completeness are assertions.",
            "The model does not inspect launchd items or verify macOS file permissions.",
            "A declared overlap does not prove local privilege escalation.",
            "No host, process, credential, item, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPI-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosPrivilegeItemReport:
    """Unsigned item projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosPrivilegeItemError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosPrivilegeItemReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_macos_privilege_items(model: Any) -> MacosPrivilegeItemReport:
    return MacosPrivilegeItemReport._owned(_derive(model))


def verify_supplied_macos_privilege_items(
    report: Any, *, model: Any
) -> MacosPrivilegeItemReport:
    if type(report) is not MacosPrivilegeItemReport:
        raise MacosPrivilegeItemError("Exact macOS privilege item wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosPrivilegeItemError("Report differs from separate original model")
    return MacosPrivilegeItemReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-macos-privilege-items",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "items": [{
            "item_id": "helper-a",
            "item_kind": "privileged_helper",
            "root_execution_declared": True,
            "user_writable_declared": True,
        }],
    }
