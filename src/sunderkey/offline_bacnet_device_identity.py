"""Compare supplied BACnet Device object identifiers within one declared internetwork."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "bacnet_supplied_device_identifier_collision"
PROFILE_ID = "AOE-GD-D19-S17"
CAPABILITY_ID = "army.gd.d19.s17"
VECTOR_ID = "AV-GD-D19-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S17"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:dfd187438f495f81e36fbab651f0f952f5cde3c4e3e564d53fae54b33992a336"
DOMAIN = "sunderkey.offline-bacnet-device-identity.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
DEVICE_OBJECT_TYPE = 8
INSTANCE_BITS = 22
MAX_INSTANCE = (1 << INSTANCE_BITS) - 1
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


class BacnetDeviceIdentityError(ValueError):
    """A supplied BACnet inventory or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "internetwork_id", "inventory_complete", "devices"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BacnetDeviceIdentityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["internetwork_id"], "internetwork ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    devices = core.bounded_list(model["devices"], 64, "devices")
    if not devices:
        raise BacnetDeviceIdentityError("At least one device is required")
    seen: set[str] = set()
    for item in devices:
        row = core.exact(item, {"device_id", "object_identifier"}, "device")
        device_id = core.identifier(row["device_id"], "device ID")
        if device_id in seen:
            raise BacnetDeviceIdentityError("Duplicate device ID")
        seen.add(device_id)
        identifier = row["object_identifier"]
        if type(identifier) is not int or not 0 <= identifier < (1 << 32):
            raise BacnetDeviceIdentityError("Device Object_Identifier must be unsigned32")
        if identifier >> INSTANCE_BITS != DEVICE_OBJECT_TYPE:
            raise BacnetDeviceIdentityError("Object_Identifier must name a Device object")
        if (identifier & MAX_INSTANCE) == MAX_INSTANCE:
            raise BacnetDeviceIdentityError("Reserved instance number is unsupported")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    groups: dict[int, list[str]] = {}
    for row in model["devices"]:
        instance = row["object_identifier"] & MAX_INSTANCE
        groups.setdefault(instance, []).append(row["device_id"])
    collisions = [
        {"instance": instance, "device_ids": sorted(device_ids)}
        for instance, device_ids in sorted(groups.items())
        if len(device_ids) > 1
    ]
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_declared_device_identifier_collision"
        if collisions
        else "no_declared_device_identifier_collision"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "internetwork_id": model["internetwork_id"],
        "device_count": len(model["devices"]),
        "duplicate_instance_groups": collisions,
        "disposition": disposition,
        "candidate_count": len(collisions) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "network_contacted": False,
        "device_identity_verified": False,
        "spoofing_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Internetwork membership, device rows and completeness are caller-supplied.",
            "Repeated identifiers may reflect duplicate records or proxying, not distinct devices.",
            "No BACnet frame is sent, parsed or authenticated; spoofing is not proven.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BDI-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class BacnetDeviceIdentityReport:
    """Unsigned device identity projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BacnetDeviceIdentityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BacnetDeviceIdentityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_bacnet_device_identity(model: Any) -> BacnetDeviceIdentityReport:
    return BacnetDeviceIdentityReport._owned(_derive(model))


def verify_supplied_bacnet_device_identity(
    report: Any, *, model: Any
) -> BacnetDeviceIdentityReport:
    if type(report) is not BacnetDeviceIdentityReport:
        raise BacnetDeviceIdentityError("Exact BACnet identity wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BacnetDeviceIdentityError("Report differs from separate original model")
    return BacnetDeviceIdentityReport._owned(expected)


def verify_supplied_bacnet_device_identity_bytes(
    report_bytes: bytes, *, model: Any
) -> BacnetDeviceIdentityReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise BacnetDeviceIdentityError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise BacnetDeviceIdentityError("Exported report differs from original replay")
    return BacnetDeviceIdentityReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-bacnet-inventory",
        "internetwork_id": "lab-internetwork",
        "inventory_complete": True,
        "devices": [
            {"device_id": "controller-a", "object_identifier": (8 << 22) | 17},
            {"device_id": "controller-b", "object_identifier": (8 << 22) | 17},
            {"device_id": "controller-c", "object_identifier": (8 << 22) | 18},
        ],
    }
