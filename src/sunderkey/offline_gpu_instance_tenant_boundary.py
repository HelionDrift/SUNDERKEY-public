"""Check tenant sharing within supplied GPU and compute instance declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "gpu_supplied_instance_tenant_boundary"
PROFILE_ID = "AOE-GD-D24-S06"
CAPABILITY_ID = "army.gd.d24.s06"
VECTOR_ID = "AV-GD-D24-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:2312f56b1c7c2d2e5b28f1097afde0bd8d320f103594f523d12430c2450f1f3b"
DOMAIN = "sunderkey.offline-gpu-instance-tenant-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class GpuInstanceTenantBoundaryError(ValueError):
    """A supplied GPU partition model or original replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "gpu_instances"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GpuInstanceTenantBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    instances = core.bounded_list(model["gpu_instances"], 64, "GPU instances")
    if not instances:
        raise GpuInstanceTenantBoundaryError("At least one GPU instance is required")
    instance_ids: set[str] = set()
    compute_ids: set[str] = set()
    for item in instances:
        row = core.exact(
            item, {"gpu_instance_id", "compute_instances", "expected_single_tenant"},
            "GPU instance",
        )
        instance_id = core.identifier(row["gpu_instance_id"], "GPU instance ID")
        core.boolean(row["expected_single_tenant"], "expected single-tenant boundary")
        if instance_id in instance_ids:
            raise GpuInstanceTenantBoundaryError("Duplicate GPU instance ID")
        instance_ids.add(instance_id)
        compute_instances = core.bounded_list(
            row["compute_instances"], 64, "compute instances"
        )
        if not compute_instances:
            raise GpuInstanceTenantBoundaryError("GPU instance requires compute instances")
        for compute in compute_instances:
            assigned = core.exact(
                compute, {"compute_instance_id", "tenant_id"}, "compute instance"
            )
            compute_id = core.identifier(
                assigned["compute_instance_id"], "compute instance ID"
            )
            core.identifier(assigned["tenant_id"], "tenant ID")
            if compute_id in compute_ids:
                raise GpuInstanceTenantBoundaryError("Duplicate compute instance ID")
            compute_ids.add(compute_id)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    mismatches = []
    for instance in model["gpu_instances"]:
        tenants = sorted({item["tenant_id"] for item in instance["compute_instances"]})
        single_tenant = len(tenants) == 1
        row = {
            "gpu_instance_id": instance["gpu_instance_id"],
            "compute_instance_count": len(instance["compute_instances"]),
            "tenant_ids": tenants,
            "single_tenant": single_tenant,
            "expected_single_tenant": instance["expected_single_tenant"],
        }
        rows.append(row)
        if single_tenant != instance["expected_single_tenant"]:
            mismatches.append({
                "gpu_instance_id": instance["gpu_instance_id"],
                "issue": "unexpected_shared_gpu_instance"
                if not single_tenant else "unexpected_single_tenant_gpu_instance",
            })
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_gpu_tenant_boundary_mismatch"
        if mismatches
        else "supplied_gpu_tenant_boundaries_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "gpu_instance_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "gpu_contacted": False,
        "hardware_isolation_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "GPU and compute instance topology and tenants are caller-supplied.",
            "Physical GPU, driver, scheduler and hardware isolation are not verified.",
            "Sharing a GPU instance is a declared co-tenancy signal, not an exploit proof.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="GPU-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class GpuInstanceTenantBoundaryReport:
    """Unsigned tenant-boundary projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise GpuInstanceTenantBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> GpuInstanceTenantBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_gpu_tenant_boundary(model: Any) -> GpuInstanceTenantBoundaryReport:
    return GpuInstanceTenantBoundaryReport._owned(_derive(model))


def verify_supplied_gpu_tenant_boundary(
    report: Any, *, model: Any
) -> GpuInstanceTenantBoundaryReport:
    if type(report) is not GpuInstanceTenantBoundaryReport:
        raise GpuInstanceTenantBoundaryError("Exact GPU tenant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise GpuInstanceTenantBoundaryError("Report differs from separate original model")
    return GpuInstanceTenantBoundaryReport._owned(expected)


def verify_supplied_gpu_tenant_boundary_bytes(
    report_bytes: bytes, *, model: Any
) -> GpuInstanceTenantBoundaryReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise GpuInstanceTenantBoundaryError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise GpuInstanceTenantBoundaryError("Exported report differs from original replay")
    return GpuInstanceTenantBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-gpu-topology",
        "inventory_complete": True,
        "gpu_instances": [{
            "gpu_instance_id": "gi-a",
            "expected_single_tenant": True,
            "compute_instances": [
                {"compute_instance_id": "ci-a", "tenant_id": "tenant-a"},
                {"compute_instance_id": "ci-b", "tenant_id": "tenant-b"},
            ],
        }],
    }
