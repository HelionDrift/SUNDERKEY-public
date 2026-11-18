"""Compare supplied enterprise hypervisor management declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hypervisor_supplied_management_posture_projection"
PROFILE_ID = "AOE-GC-D16-S06"
CAPABILITY_ID = "army.gc.d16.s06"
VECTOR_ID = "AV-GC-D16-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S06"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:79aabb501ed6f6f5cf8f1da551ad26546693551b4aee41e92f519f2375090ed6"
DOMAIN = "sunderkey.offline-hypervisor-management-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_MANAGERS = 32
PLATFORMS = {"esxi_vcenter", "hyper_v", "kvm", "xen"}
REACHABILITY = {"internal", "partner", "public", "unknown"}
SNAPSHOT_SCOPES = {"restricted", "broad", "unknown"}
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class HypervisorManagementPostureError(ValueError):
    """The reduced management declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "managers"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HypervisorManagementPostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["managers"], MAX_MANAGERS, "managers"):
        manager = core.exact(
            row,
            {
                "manager_id",
                "platform",
                "management_reachability",
                "admin_mfa_enforced",
                "snapshot_mutation_role_scope",
                "scope_assertions_complete",
            },
            "manager",
        )
        manager_id = core.identifier(manager["manager_id"], "manager ID")
        if manager_id in seen:
            raise HypervisorManagementPostureError("Duplicate manager ID")
        seen.add(manager_id)
        core.choice(manager["platform"], PLATFORMS, "platform")
        core.choice(manager["management_reachability"], REACHABILITY, "reachability")
        if manager["admin_mfa_enforced"] is not None:
            core.boolean(manager["admin_mfa_enforced"], "admin MFA assertion")
        core.choice(manager["snapshot_mutation_role_scope"], SNAPSHOT_SCOPES, "role scope")
        core.boolean(manager["scope_assertions_complete"], "scope completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    managers = sorted(model["managers"], key=lambda row: row["manager_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for manager in managers:
        manager_id = manager["manager_id"]
        if not manager["scope_assertions_complete"]:
            uncertainty.append(
                {"issue": "incomplete_declared_management_scope", "manager_id": manager_id}
            )
            continue
        reach = manager["management_reachability"]
        if reach == "public":
            signals.append(
                {"issue": "declared_public_management_reachability", "manager_id": manager_id}
            )
        elif reach == "unknown":
            uncertainty.append(
                {"issue": "management_reachability_unknown", "manager_id": manager_id}
            )
        if manager["admin_mfa_enforced"] is None:
            uncertainty.append({"issue": "admin_mfa_not_asserted", "manager_id": manager_id})
        elif reach == "public" and not manager["admin_mfa_enforced"]:
            signals.append({"issue": "declared_public_admin_without_mfa", "manager_id": manager_id})
        scope = manager["snapshot_mutation_role_scope"]
        if scope == "broad":
            signals.append(
                {"issue": "declared_broad_snapshot_mutation_scope", "manager_id": manager_id}
            )
        elif scope == "unknown":
            uncertainty.append(
                {"issue": "snapshot_mutation_scope_unknown", "manager_id": manager_id}
            )
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "manager_id": "none"})
    signals.sort(key=lambda row: (row["manager_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["manager_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_hypervisor_review"
    elif uncertainty or not managers:
        disposition = "unknown"
    else:
        disposition = "no_declared_hypervisor_review_signal"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "inventory_complete_asserted": model["inventory_complete"],
        "manager_count": len(managers),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not managers),
        "disposition": disposition,
        "source_authenticated": False,
        "reachability_verified": False,
        "admin_authorization_verified": False,
        "hypervisor_contacted": False,
        "vm_state_changed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Platform, reachability, MFA and role scope are supplied assertions.",
            "No API, firewall, directory, privilege or snapshot policy is parsed or checked.",
            "A public or broad scope is a review hypothesis, not effective-access proof.",
            "No hypervisor, manager, VM or target is contacted or changed.",
            "An absent signal does not establish virtualization control safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HMP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class HypervisorManagementPostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HypervisorManagementPostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HypervisorManagementPostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hypervisor_management_posture(
    model: Any,
) -> HypervisorManagementPostureReport:
    return HypervisorManagementPostureReport._owned(_derive(model))


def verify_supplied_hypervisor_management_posture(
    report: Any, *, model: Any
) -> HypervisorManagementPostureReport:
    if type(report) is not HypervisorManagementPostureReport:
        raise HypervisorManagementPostureError("Exact hypervisor wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HypervisorManagementPostureError("Report differs from separate original model")
    return HypervisorManagementPostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-hypervisor-management",
        "inventory_complete": True,
        "managers": [
            {
                "manager_id": "manager_a",
                "platform": "esxi_vcenter",
                "management_reachability": "public",
                "admin_mfa_enforced": False,
                "snapshot_mutation_role_scope": "broad",
                "scope_assertions_complete": True,
            }
        ],
    }
