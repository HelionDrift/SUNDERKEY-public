"""Project synthetic namespace and cgroup policy declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_namespace_cgroup_policy_projection"
PROFILE_ID = "AOE-GC-D12-S07"
CAPABILITY_ID = "army.gc.d12.s07"
VECTOR_ID = "AV-GC-D12-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:15bb9e20a94f0d0348db8d5785e17f1aae3615bcad637b64e3aa374c816cb4f8"
DOMAIN = "sunderkey.offline-namespace-cgroup-policy.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class NamespaceCgroupPolicyError(ValueError):
    """A supplied isolation model or replay is invalid."""


def _integer(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise NamespaceCgroupPolicyError(f"{label} is outside the declared bound")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "tenant_policies", "workloads",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise NamespaceCgroupPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise NamespaceCgroupPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    tenants = {}
    for item in core.bounded_list(model["tenant_policies"], 16, "tenant policies"):
        row = core.exact(item, {
            "tenant_id", "namespace_separation_required", "maximum_memory_mib",
        }, "tenant policy")
        tenant_id = core.identifier(row["tenant_id"], "tenant ID")
        if tenant_id in tenants:
            raise NamespaceCgroupPolicyError("Duplicate tenant policy")
        tenants[tenant_id] = {
            "separation": core.boolean(
                row["namespace_separation_required"], "namespace separation"
            ),
            "maximum_memory_mib": _integer(
                row["maximum_memory_mib"], minimum=1, maximum=1 << 30,
                label="policy memory limit",
            ),
        }
    if not tenants:
        raise NamespaceCgroupPolicyError("At least one tenant policy is required")
    workloads = []
    seen = set()
    namespace_tenants: dict[str, set[str]] = {}
    for item in core.bounded_list(model["workloads"], 64, "workloads"):
        row = core.exact(item, {
            "workload_id", "tenant_id", "namespace_id", "memory_limit_mib",
        }, "workload")
        workload_id = core.identifier(row["workload_id"], "workload ID")
        tenant_id = core.identifier(row["tenant_id"], "tenant ID")
        namespace_id = core.identifier(row["namespace_id"], "namespace ID")
        if workload_id in seen or tenant_id not in tenants:
            raise NamespaceCgroupPolicyError("Duplicate workload or unknown tenant")
        seen.add(workload_id)
        namespace_tenants.setdefault(namespace_id, set()).add(tenant_id)
        workloads.append({
            "workload_id": workload_id,
            "tenant_id": tenant_id,
            "namespace_id": namespace_id,
            "memory_limit_mib": _integer(
                row["memory_limit_mib"], minimum=1, maximum=1 << 30,
                label="declared memory limit",
            ),
        })
    if not workloads:
        raise NamespaceCgroupPolicyError("At least one workload is required")
    rows = []
    for row in workloads:
        tenant = tenants[row["tenant_id"]]
        flags = []
        if tenant["separation"] and len(namespace_tenants[row["namespace_id"]]) > 1:
            flags.append("namespace_shared_across_supplied_tenants")
        if row["memory_limit_mib"] > tenant["maximum_memory_mib"]:
            flags.append("declared_memory_limit_exceeds_supplied_policy")
        rows.append({**row, "declared_policy_flags": flags})
    rows.sort(key=lambda row: row["workload_id"])
    deviations = [row["workload_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_namespace_inventory_incomplete"]
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
        "workload_projections": rows,
        "declared_policy_deviation_workload_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_namespace_cgroup_projection",
        "source_authenticated": False,
        "host_configuration_read": False,
        "namespace_entered": False,
        "cgroup_modified": False,
        "process_started": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Tenants, namespaces, memory limits, and completeness are supplied assertions.",
            "A shared namespace label does not prove shared kernel isolation or escape.",
            "A memory policy mismatch does not prove resource usage or denial of service.",
            "No host, container, namespace, cgroup, process, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="NCP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class NamespaceCgroupPolicyReport:
    """Unsigned isolation projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise NamespaceCgroupPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> NamespaceCgroupPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_namespace_cgroups(model: Any) -> NamespaceCgroupPolicyReport:
    return NamespaceCgroupPolicyReport._owned(_derive(model))


def verify_supplied_namespace_cgroups(
    report: Any, *, model: Any
) -> NamespaceCgroupPolicyReport:
    if type(report) is not NamespaceCgroupPolicyReport:
        raise NamespaceCgroupPolicyError("Exact namespace wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise NamespaceCgroupPolicyError("Report differs from separate original model")
    return NamespaceCgroupPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-namespace-policy",
        "synthetic_fixture": True, "inventory_complete": True,
        "tenant_policies": [
            {"tenant_id": "alpha", "namespace_separation_required": True,
             "maximum_memory_mib": 512},
            {"tenant_id": "beta", "namespace_separation_required": True,
             "maximum_memory_mib": 512},
        ],
        "workloads": [
            {"workload_id": "a", "tenant_id": "alpha", "namespace_id": "ns-shared",
             "memory_limit_mib": 1024},
            {"workload_id": "b", "tenant_id": "beta", "namespace_id": "ns-shared",
             "memory_limit_mib": 256},
        ],
    }
