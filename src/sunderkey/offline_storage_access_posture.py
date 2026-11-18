"""Compare supplied SAN and NAS exposure and write-grant declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "storage_supplied_access_posture_projection"
PROFILE_ID = "AOE-GC-D16-S09"
CAPABILITY_ID = "army.gc.d16.s09"
VECTOR_ID = "AV-GC-D16-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S09"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8be98fcd0c0f7c522a8f7c8ac35bb679ebf155703ca45b41421d8120755fa342"
DOMAIN = "sunderkey.offline-storage-access-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_RESOURCES = 32
PROTOCOLS = {"nfs", "smb", "iscsi", "fc", "other"}
EXPOSURE_SCOPES = {"internal", "partner", "public", "unknown"}
WRITE_SCOPES = {"none", "approved", "public", "unknown"}
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


class StorageAccessPostureError(ValueError):
    """The reduced storage declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "resources"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise StorageAccessPostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["resources"], MAX_RESOURCES, "resources"):
        resource = core.exact(
            row,
            {
                "resource_id",
                "protocol",
                "data_sensitive",
                "exposure_scope",
                "write_scope",
                "scope_assertions_complete",
            },
            "resource",
        )
        resource_id = core.identifier(resource["resource_id"], "resource ID")
        if resource_id in seen:
            raise StorageAccessPostureError("Duplicate resource ID")
        seen.add(resource_id)
        core.choice(resource["protocol"], PROTOCOLS, "protocol")
        core.boolean(resource["data_sensitive"], "sensitive data assertion")
        core.choice(resource["exposure_scope"], EXPOSURE_SCOPES, "exposure scope")
        core.choice(resource["write_scope"], WRITE_SCOPES, "write scope")
        core.boolean(resource["scope_assertions_complete"], "scope completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    resources = sorted(model["resources"], key=lambda row: row["resource_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for resource in resources:
        resource_id = resource["resource_id"]
        if not resource["scope_assertions_complete"]:
            uncertainty.append(
                {"issue": "incomplete_declared_access_scope", "resource_id": resource_id}
            )
            continue
        if resource["exposure_scope"] == "unknown":
            uncertainty.append({"issue": "exposure_scope_unknown", "resource_id": resource_id})
        elif resource["data_sensitive"] and resource["exposure_scope"] == "public":
            signals.append(
                {"issue": "declared_sensitive_public_exposure", "resource_id": resource_id}
            )
        if resource["write_scope"] == "unknown":
            uncertainty.append({"issue": "write_scope_unknown", "resource_id": resource_id})
        elif resource["write_scope"] == "public":
            signals.append({"issue": "declared_public_write_scope", "resource_id": resource_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "resource_id": "none"})
    signals.sort(key=lambda row: (row["resource_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["resource_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_storage_access_review"
    elif uncertainty or not resources:
        disposition = "unknown"
    else:
        disposition = "no_declared_storage_access_review_signal"
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
        "resource_count": len(resources),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not resources),
        "disposition": disposition,
        "source_authenticated": False,
        "storage_access_verified": False,
        "storage_contacted": False,
        "data_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Protocol, sensitivity and scope labels are supplied and unauthenticated.",
            "No ACL, export, zone, initiator or authentication policy is parsed or evaluated.",
            "A public scope is an asserted review hypothesis, not verified reachability.",
            "No storage system is contacted and no data or credential is read or written.",
            "An absent signal does not establish access restriction or data safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SAP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class StorageAccessPostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise StorageAccessPostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> StorageAccessPostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_storage_access_posture(model: Any) -> StorageAccessPostureReport:
    return StorageAccessPostureReport._owned(_derive(model))


def verify_supplied_storage_access_posture(
    report: Any, *, model: Any
) -> StorageAccessPostureReport:
    if type(report) is not StorageAccessPostureReport:
        raise StorageAccessPostureError("Exact storage posture wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise StorageAccessPostureError("Report differs from separate original model")
    return StorageAccessPostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-storage-access",
        "inventory_complete": True,
        "resources": [
            {
                "resource_id": "share_a",
                "protocol": "nfs",
                "data_sensitive": True,
                "exposure_scope": "public",
                "write_scope": "unknown",
                "scope_assertions_complete": True,
            }
        ],
    }
