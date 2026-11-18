"""Project supplied NVIDIA MIG configuration capability grants."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "gpu_supplied_management_node_permissions"
PROFILE_ID = "AOE-GD-D24-S05"
CAPABILITY_ID = "army.gd.d24.s05"
VECTOR_ID = "AV-GD-D24-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:10b255485eb9350eec3ab972557496b0dc1c92c15324262b49307c4bbdad0071"
DOMAIN = "sunderkey.offline-gpu-management-node-permissions.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class GpuManagementNodePermissionsError(ValueError):
    """A supplied MIG capability model or original replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "interface", "principals"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GpuManagementNodePermissionsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    interface = model["interface"]
    if type(interface) is not str or interface not in {"devfs", "procfs"}:
        raise GpuManagementNodePermissionsError("Unsupported capability interface")
    principals = core.bounded_list(model["principals"], 64, "principals")
    if not principals:
        raise GpuManagementNodePermissionsError("At least one principal is required")
    seen: set[str] = set()
    grant_keys = (
        {"cgroup_device_read", "device_node_read"}
        if interface == "devfs"
        else {"proc_capability_visible", "proc_capability_read"}
    )
    for item in principals:
        row = core.exact(
            item,
            {"principal_id", "root_or_cap_sys_admin", "grant", "expected_capability"},
            "principal",
        )
        principal_id = core.identifier(row["principal_id"], "principal ID")
        if principal_id in seen:
            raise GpuManagementNodePermissionsError("Duplicate principal ID")
        seen.add(principal_id)
        core.boolean(row["root_or_cap_sys_admin"], "elevated privilege")
        core.boolean(row["expected_capability"], "expected capability")
        grant = core.exact(row["grant"], grant_keys, "interface grant")
        for key in grant_keys:
            core.boolean(grant[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    mismatches = []
    for principal in model["principals"]:
        grant = principal["grant"]
        projected = principal["root_or_cap_sys_admin"] or all(grant.values())
        row = {
            "principal_id": principal["principal_id"],
            "root_or_cap_sys_admin": principal["root_or_cap_sys_admin"],
            "grant": grant,
            "projected_mig_config_capability": projected,
            "expected_capability": principal["expected_capability"],
        }
        rows.append(row)
        if projected != principal["expected_capability"]:
            mismatches.append({
                "principal_id": principal["principal_id"],
                "issue": "unexpected_capability_grant"
                if projected else "unexpected_capability_denial",
            })
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_mig_config_capability_mismatch"
        if mismatches
        else "supplied_mig_config_capabilities_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "interface": model["interface"],
        "principal_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "gpu_contacted": False,
        "device_nodes_inspected": False,
        "management_action_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All principal privileges, interface grants and expectations are caller-supplied.",
            "The check models MIG configuration capability, not successful MIG changes.",
            "GPU nodes, cgroups, namespaces, driver state and identity are not verified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="GMP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class GpuManagementNodePermissionsReport:
    """Unsigned MIG capability projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise GpuManagementNodePermissionsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> GpuManagementNodePermissionsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_gpu_management_node_permissions(
    model: Any,
) -> GpuManagementNodePermissionsReport:
    return GpuManagementNodePermissionsReport._owned(_derive(model))


def verify_supplied_gpu_management_node_permissions(
    report: Any, *, model: Any
) -> GpuManagementNodePermissionsReport:
    if type(report) is not GpuManagementNodePermissionsReport:
        raise GpuManagementNodePermissionsError("Exact GPU management wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise GpuManagementNodePermissionsError("Report differs from separate original model")
    return GpuManagementNodePermissionsReport._owned(expected)


def verify_supplied_gpu_management_node_permissions_bytes(
    report_bytes: bytes, *, model: Any
) -> GpuManagementNodePermissionsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise GpuManagementNodePermissionsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise GpuManagementNodePermissionsError("Exported report differs from original replay")
    return GpuManagementNodePermissionsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-mig-grants",
        "inventory_complete": True,
        "interface": "devfs",
        "principals": [{
            "principal_id": "tenant-a",
            "root_or_cap_sys_admin": False,
            "grant": {"cgroup_device_read": True, "device_node_read": True},
            "expected_capability": False,
        }],
    }
