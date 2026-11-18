"""Compare supplied IOMMU group membership with declared device trust roles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "iommu_supplied_group_separation"
PROFILE_ID = "AOE-GD-D24-S04"
CAPABILITY_ID = "army.gd.d24.s04"
VECTOR_ID = "AV-GD-D24-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:037ead1485a456a9d0ea2c27b60c74d43167222c8c5149ea9c481e5005bd5bb1"
DOMAIN = "sunderkey.offline-iommu-group-separation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ROLES = {"protected", "untrusted_dma", "other"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class IommuGroupSeparationError(ValueError):
    """A supplied IOMMU declaration or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "inventory_complete", "iommu_declared_enabled",
            "devices",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise IommuGroupSeparationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    core.boolean(model["iommu_declared_enabled"], "IOMMU declaration")
    devices = core.bounded_list(model["devices"], 128, "devices")
    if not devices:
        raise IommuGroupSeparationError("At least one device is required")
    seen: set[str] = set()
    for item in devices:
        row = core.exact(item, {"device_id", "group_id", "security_role"}, "device")
        device_id = core.identifier(row["device_id"], "device ID")
        core.identifier(row["group_id"], "group ID")
        if type(row["security_role"]) is not str or row["security_role"] not in ROLES:
            raise IommuGroupSeparationError("Unsupported security role")
        if device_id in seen:
            raise IommuGroupSeparationError("Duplicate device ID")
        seen.add(device_id)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    groups: dict[str, list[dict]] = {}
    for row in model["devices"]:
        groups.setdefault(row["group_id"], []).append(row)
    gaps = []
    for group_id, rows in sorted(groups.items()):
        untrusted = sorted(
            row["device_id"] for row in rows if row["security_role"] == "untrusted_dma"
        )
        protected = sorted(row["device_id"] for row in rows if row["security_role"] == "protected")
        if untrusted and protected:
            gaps.append({
                "group_id": group_id,
                "issue": "mixed_protected_and_untrusted_dma_roles",
                "protected_device_ids": protected,
                "untrusted_dma_device_ids": untrusted,
            })
    if not model["iommu_declared_enabled"]:
        untrusted = sorted(
            row["device_id"] for row in model["devices"]
            if row["security_role"] == "untrusted_dma"
        )
        if untrusted:
            gaps.append({
                "group_id": "none",
                "issue": "iommu_declared_disabled_with_untrusted_dma",
                "protected_device_ids": [],
                "untrusted_dma_device_ids": untrusted,
            })
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_iommu_separation_gap"
        if gaps
        else "no_supplied_iommu_separation_gap"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "device_count": len(model["devices"]),
        "group_count": len(groups),
        "gaps": gaps,
        "disposition": disposition,
        "candidate_count": len(gaps) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "hardware_contacted": False,
        "iommu_topology_verified": False,
        "dma_access_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "IOMMU state, group IDs, device trust roles and completeness are caller-supplied.",
            "The model does not account for ACS, bridge topology or platform-specific isolation.",
            "No PCIe, Thunderbolt, DMA, IOMMU or host interface is touched.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IGS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class IommuGroupSeparationReport:
    """Unsigned group projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise IommuGroupSeparationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> IommuGroupSeparationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_iommu_groups(model: Any) -> IommuGroupSeparationReport:
    return IommuGroupSeparationReport._owned(_derive(model))


def verify_supplied_iommu_groups(
    report: Any, *, model: Any
) -> IommuGroupSeparationReport:
    if type(report) is not IommuGroupSeparationReport:
        raise IommuGroupSeparationError("Exact IOMMU group wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise IommuGroupSeparationError("Report differs from separate original model")
    return IommuGroupSeparationReport._owned(expected)


def verify_supplied_iommu_groups_bytes(
    report_bytes: bytes, *, model: Any
) -> IommuGroupSeparationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise IommuGroupSeparationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise IommuGroupSeparationError("Exported report differs from original replay")
    return IommuGroupSeparationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-iommu-groups",
        "inventory_complete": True,
        "iommu_declared_enabled": True,
        "devices": [
            {"device_id": "dma-a", "group_id": "group-7", "security_role": "untrusted_dma"},
            {"device_id": "protected-a", "group_id": "group-7", "security_role": "protected"},
        ],
    }
