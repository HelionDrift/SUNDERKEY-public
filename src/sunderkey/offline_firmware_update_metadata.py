"""Compare supplied ESRT device-firmware metadata with proposed versions offline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "esrt_supplied_device_firmware_version_projection"
PROFILE_ID = "AOE-GD-D24-S09"
CAPABILITY_ID = "army.gd.d24.s09"
VECTOR_ID = "AV-GD-D24-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:795157ed5d8c556b145464361f111c01db5d91ee2e9e354109963d22d52f5352"
DOMAIN = "sunderkey.offline-firmware-update-metadata.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_UINT32_MAX = (1 << 32) - 1
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class FirmwareUpdateMetadataError(ValueError):
    """The supplied ESRT model or an original-model replay is invalid."""


def _uint32(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _UINT32_MAX:
        raise FirmwareUpdateMetadataError(f"{label} must be a UINT32")
    return value


def _guid(value: Any, label: str) -> str:
    if type(value) is not str or _GUID.fullmatch(value) is None:
        raise FirmwareUpdateMetadataError(f"{label} must be a lowercase GUID")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "resource", "proposed_updates"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FirmwareUpdateMetadataError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    resource = core.exact(
        model["resource"],
        {
            "fw_class", "fw_type", "fw_version", "lowest_supported_fw_version",
            "last_attempt_version", "last_attempt_status",
        },
        "ESRT resource",
    )
    _guid(resource["fw_class"], "resource firmware class")
    if _uint32(resource["fw_type"], "resource firmware type") != 2:
        raise FirmwareUpdateMetadataError("Only ESRT device firmware type 2 is supported")
    for field in (
        "fw_version", "lowest_supported_fw_version", "last_attempt_version",
        "last_attempt_status",
    ):
        _uint32(resource[field], f"resource {field}")
    proposals = core.bounded_list(model["proposed_updates"], 64, "proposed updates")
    if not proposals:
        raise FirmwareUpdateMetadataError("At least one proposed update is required")
    seen: set[str] = set()
    for item in proposals:
        row = core.exact(
            item, {"proposal_id", "target_fw_class", "proposed_version"}, "proposal"
        )
        proposal_id = core.identifier(row["proposal_id"], "proposal ID")
        _guid(row["target_fw_class"], "proposal target firmware class")
        _uint32(row["proposed_version"], "proposed version")
        if proposal_id in seen:
            raise FirmwareUpdateMetadataError("Duplicate proposal ID")
        seen.add(proposal_id)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    resource = model["resource"]
    observations = []
    for proposal in model["proposed_updates"]:
        matches = proposal["target_fw_class"] == resource["fw_class"]
        proposed = proposal["proposed_version"]
        if not matches:
            disposition = "unknown_target_not_in_supplied_resource"
            direction = "unknown"
        else:
            direction = (
                "downgrade" if proposed < resource["fw_version"] else
                "same_version" if proposed == resource["fw_version"] else "upgrade"
            )
            disposition = (
                "candidate_below_declared_rollback_floor"
                if proposed < resource["lowest_supported_fw_version"]
                else "not_below_declared_rollback_floor"
            )
        observations.append({
            "proposal_id": proposal["proposal_id"],
            "target_matches_supplied_resource": matches,
            "proposed_version": proposed,
            "direction_from_supplied_current_version": direction,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "fw_class": resource["fw_class"],
        "fw_type": resource["fw_type"],
        "fw_version": resource["fw_version"],
        "lowest_supported_fw_version": resource["lowest_supported_fw_version"],
        "last_attempt_version": resource["last_attempt_version"],
        "last_attempt_status": resource["last_attempt_status"],
        "observations": observations,
        "candidate_count": sum(
            row["disposition"] == "candidate_below_declared_rollback_floor"
            for row in observations
        ),
        "unknown_count": sum(
            row["disposition"] == "unknown_target_not_in_supplied_resource"
            for row in observations
        ),
        "source_authenticated": False,
        "device_contacted": False,
        "capsule_parsed": False,
        "signature_verified": False,
        "firmware_update_attempted": False,
        "firmware_acceptance_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The ESRT resource and proposed versions are supplied and unauthenticated.",
            "A below-floor comparison is a review candidate, not observed enforcement.",
            "Current-version direction does not prove update or downgrade acceptance.",
            "Last-attempt fields are reported without interpreting temporal state.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ESR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class FirmwareUpdateMetadataReport:
    """Unsigned ESRT metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FirmwareUpdateMetadataError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FirmwareUpdateMetadataReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_esrt_update_metadata(model: Any) -> FirmwareUpdateMetadataReport:
    return FirmwareUpdateMetadataReport._owned(_derive(model))


def verify_supplied_esrt_update_metadata(
    report: Any, *, model: Any
) -> FirmwareUpdateMetadataReport:
    if type(report) is not FirmwareUpdateMetadataReport:
        raise FirmwareUpdateMetadataError("Exact ESRT metadata wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise FirmwareUpdateMetadataError("Report differs from separate original model")
    return FirmwareUpdateMetadataReport._owned(expected)


def verify_supplied_esrt_update_metadata_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareUpdateMetadataReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise FirmwareUpdateMetadataError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise FirmwareUpdateMetadataError("Exported report differs from original replay")
    return FirmwareUpdateMetadataReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-esrt-device-resource",
        "resource": {
            "fw_class": "12345678-1234-1234-1234-123456789abc",
            "fw_type": 2,
            "fw_version": 12,
            "lowest_supported_fw_version": 9,
            "last_attempt_version": 0,
            "last_attempt_status": 0,
        },
        "proposed_updates": [
            {
                "proposal_id": "example-below-floor",
                "target_fw_class": "12345678-1234-1234-1234-123456789abc",
                "proposed_version": 8,
            }
        ],
    }
