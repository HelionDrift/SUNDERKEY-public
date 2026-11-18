"""Compare supplied synthetic GATT access declarations with local policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_ble_gatt_permission_projection"
PROFILE_ID = "AOE-GC-D13-S09"
CAPABILITY_ID = "army.gc.d13.s09"
VECTOR_ID = "AV-GC-D13-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S09"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5d3f7e65e46739e03d4fe53bf34ae425ef686fdc70aaa8cd1de8b74249fa4df2"
DOMAIN = "sunderkey.offline-ble-gatt-permissions.v1"
OPERATIONS = {"read", "write", "notify"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class BleGattPermissionError(ValueError):
    """The supplied declaration or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "services", "policies", "characteristics",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BleGattPermissionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise BleGattPermissionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    services = set()
    for item in core.bounded_list(model["services"], 32, "services"):
        service_id = core.identifier(item, "service ID")
        if service_id in services:
            raise BleGattPermissionError("Duplicate service ID")
        services.add(service_id)
    if not services:
        raise BleGattPermissionError("At least one service is required")
    policies = {}
    for item in core.bounded_list(model["policies"], 16, "policies"):
        row = core.exact(item, {
            "policy_id", "data_class", "encryption_required", "authentication_required",
        }, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in policies:
            raise BleGattPermissionError("Duplicate policy ID")
        policies[policy_id] = {
            "data_class": core.choice(row["data_class"], {
                "public", "internal", "sensitive", "credential_material",
            }, "data class"),
            "encryption": core.boolean(row["encryption_required"], "encryption policy"),
            "authentication": core.boolean(
                row["authentication_required"], "authentication policy"
            ),
        }
    if not policies:
        raise BleGattPermissionError("At least one policy is required")
    rows = []
    seen = set()
    for item in core.bounded_list(model["characteristics"], 64, "characteristics"):
        row = core.exact(item, {
            "characteristic_id", "service_id", "policy_id", "operation_ids",
            "encryption_declared", "authentication_declared",
        }, "characteristic")
        characteristic_id = core.identifier(row["characteristic_id"], "characteristic ID")
        if characteristic_id in seen:
            raise BleGattPermissionError("Duplicate characteristic ID")
        seen.add(characteristic_id)
        service_id = core.identifier(row["service_id"], "service ID")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if service_id not in services or policy_id not in policies:
            raise BleGattPermissionError("Characteristic references unknown service or policy")
        operations = [
            core.choice(operation, OPERATIONS, "operation")
            for operation in core.bounded_list(row["operation_ids"], 3, "operations")
        ]
        if not operations or len(operations) != len(set(operations)):
            raise BleGattPermissionError("Operations must be nonempty and unique")
        encrypted = core.boolean(row["encryption_declared"], "declared encryption")
        authenticated = core.boolean(row["authentication_declared"], "declared authentication")
        missing = []
        if policies[policy_id]["encryption"] and not encrypted:
            missing.append("encryption")
        if policies[policy_id]["authentication"] and not authenticated:
            missing.append("authentication")
        rows.append({
            "characteristic_id": characteristic_id,
            "service_id": service_id,
            "policy_id": policy_id,
            "data_class": policies[policy_id]["data_class"],
            "declared_operation_ids": sorted(operations),
            "missing_declared_control_keys": sorted(missing),
        })
    if not rows:
        raise BleGattPermissionError("At least one characteristic is required")
    rows.sort(key=lambda row: row["characteristic_id"])
    unknown = [] if complete else ["supplied_gatt_inventory_incomplete"]
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
        "supplied_service_count": len(services),
        "supplied_policy_count": len(policies),
        "supplied_characteristic_count": len(rows),
        "characteristic_projections": rows,
        "declared_control_gap_characteristic_ids": sorted(
            row["characteristic_id"] for row in rows if row["missing_declared_control_keys"]
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_gatt_permission_projection",
        "source_authenticated": False,
        "device_connected": False,
        "gatt_discovery_performed": False,
        "link_security_verified": False,
        "operation_exercised": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Services, operations, policies, and security are supplied assertions.",
            "A declared control gap is not proof of GATT access or a security vulnerability.",
            "No device, radio, GATT service, characteristic, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BGP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class BleGattPermissionReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BleGattPermissionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BleGattPermissionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ble_gatt(model: Any) -> BleGattPermissionReport:
    return BleGattPermissionReport._owned(_derive(model))


def verify_supplied_ble_gatt(
    report: Any, *, model: Any
) -> BleGattPermissionReport:
    if type(report) is not BleGattPermissionReport:
        raise BleGattPermissionError("Exact GATT wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BleGattPermissionError("Report differs from separate original model")
    return BleGattPermissionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-ble-gatt",
        "synthetic_fixture": True, "inventory_complete": True,
        "services": ["service-a"],
        "policies": [{
            "policy_id": "sensitive-data", "data_class": "sensitive",
            "encryption_required": True, "authentication_required": True,
        }],
        "characteristics": [{
            "characteristic_id": "char-a", "service_id": "service-a",
            "policy_id": "sensitive-data", "operation_ids": ["read"],
            "encryption_declared": True, "authentication_declared": False,
        }],
    }
