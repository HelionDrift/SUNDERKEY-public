"""Project bounded, synthetic flash-region declarations without device access."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_flash_region_map_projection"
PROFILE_ID = "AOE-GD-D18-S07"
CAPABILITY_ID = "army.gd.d18.s07"
VECTOR_ID = "AV-GD-D18-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S07"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:a47e6c4e7b3dd7771cbaa94a9e7348e98425bd8480c10931939c3b40fc052b89"
DOMAIN = "sunderkey.offline-flash-region-map.v1"
CLASSES = {"public", "internal", "sensitive", "credential_material"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class FlashRegionMapError(ValueError):
    """A supplied flash map or original-model replay is invalid."""


def _bounded_integer(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FlashRegionMapError(f"{label} is outside the declared integer bound")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "flash_size_bytes", "regions",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FlashRegionMapError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise FlashRegionMapError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    flash_size = _bounded_integer(
        model["flash_size_bytes"], minimum=1, maximum=1 << 40, label="flash size"
    )
    supplied = core.bounded_list(model["regions"], 64, "regions")
    if not supplied:
        raise FlashRegionMapError("At least one region is required")
    regions = []
    seen = set()
    for item in supplied:
        row = core.exact(item, {
            "region_id", "offset_bytes", "length_bytes", "data_class",
            "protection_declared",
        }, "region")
        region_id = core.identifier(row["region_id"], "region ID")
        if region_id in seen:
            raise FlashRegionMapError("Duplicate region ID")
        seen.add(region_id)
        offset = _bounded_integer(
            row["offset_bytes"], minimum=0, maximum=1 << 40, label="region offset"
        )
        length = _bounded_integer(
            row["length_bytes"], minimum=1, maximum=1 << 40, label="region length"
        )
        regions.append({
            "region_id": region_id,
            "offset_bytes": offset,
            "end_exclusive_bytes": offset + length,
            "data_class": core.choice(row["data_class"], CLASSES, "data class"),
            "protection_declared": core.boolean(
                row["protection_declared"], "declared protection"
            ),
        })
    regions.sort(key=lambda row: (row["offset_bytes"], row["region_id"]))
    out_of_bounds = sorted(
        row["region_id"] for row in regions if row["end_exclusive_bytes"] > flash_size
    )
    overlaps = []
    for index, left in enumerate(regions):
        for right in regions[index + 1:]:
            if right["offset_bytes"] >= left["end_exclusive_bytes"]:
                break
            overlaps.append([left["region_id"], right["region_id"]])
    protection_gaps = sorted(
        row["region_id"] for row in regions
        if row["data_class"] in {"sensitive", "credential_material"}
        and not row["protection_declared"]
    )
    unknown = [] if complete else ["supplied_flash_region_inventory_incomplete"]
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
        "flash_size_bytes_asserted": flash_size,
        "region_projections": regions,
        "declared_out_of_bounds_region_ids": out_of_bounds,
        "declared_overlap_region_pairs": overlaps,
        "declared_protection_gap_region_ids": protection_gaps,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_flash_region_projection",
        "source_authenticated": False,
        "device_connected": False,
        "flash_read_performed": False,
        "chip_off_performed": False,
        "hardware_protection_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Region bounds, data classes, protections, and completeness are supplied assertions.",
            "Declared overlap or protection gaps are not verified device vulnerabilities.",
            "No flash image, chip, bus, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="FRM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class FlashRegionMapReport:
    """Unsigned region projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FlashRegionMapError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FlashRegionMapReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_flash_regions(model: Any) -> FlashRegionMapReport:
    return FlashRegionMapReport._owned(_derive(model))


def verify_supplied_flash_regions(
    report: Any, *, model: Any
) -> FlashRegionMapReport:
    if type(report) is not FlashRegionMapReport:
        raise FlashRegionMapError("Exact flash-region wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise FlashRegionMapError("Report differs from separate original model")
    return FlashRegionMapReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-flash-map",
        "synthetic_fixture": True, "inventory_complete": True,
        "flash_size_bytes": 4096,
        "regions": [
            {"region_id": "boot", "offset_bytes": 0, "length_bytes": 1024,
             "data_class": "internal", "protection_declared": True},
            {"region_id": "config", "offset_bytes": 1024, "length_bytes": 512,
             "data_class": "sensitive", "protection_declared": False},
        ],
    }
