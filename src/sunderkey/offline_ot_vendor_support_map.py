"""Project supplied synthetic OT vendor-to-asset support relationships."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "industrial_supplied_ot_vendor_support_map"
PROFILE_ID = "AOE-GD-D19-S07"
CAPABILITY_ID = "army.gd.d19.s07"
VECTOR_ID = "AV-GD-D19-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S07"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:980505a9371469a7a4c0731d3030a9c8b8c94d3b79add0a47986e2c80a836b4f"
DOMAIN = "sunderkey.offline-ot-vendor-support-map.v1"
MAX_MODEL_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
ASSET_CLASSES = {"engineering_workstation", "bpcs", "sis"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OtVendorSupportMapError(ValueError):
    """A synthetic vendor support map or original-model replay is invalid."""


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _rows(value: Any, maximum: int, label: str) -> list:
    result = core.bounded_list(value, maximum, label)
    if not result:
        raise OtVendorSupportMapError(f"Nonempty {label} required")
    return result


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "vendors", "assets",
         "support_paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtVendorSupportMapError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise OtVendorSupportMapError("Only synthetic fixtures are accepted")
    vendors: set[str] = set()
    for row in _rows(model["vendors"], 16, "vendors"):
        vendor = core.identifier(core.exact(row, {"vendor_id"}, "vendor")["vendor_id"],
                                 "vendor ID")
        if vendor in vendors:
            raise OtVendorSupportMapError("Duplicate vendor ID")
        vendors.add(vendor)
    assets: dict[str, str] = {}
    for row in _rows(model["assets"], 32, "assets"):
        asset = core.exact(row, {"asset_id", "asset_class"}, "asset")
        asset_id = core.identifier(asset["asset_id"], "asset ID")
        if (asset_id in assets or type(asset["asset_class"]) is not str
                or asset["asset_class"] not in ASSET_CLASSES):
            raise OtVendorSupportMapError("Duplicate asset or unknown class")
        assets[asset_id] = asset["asset_class"]
    paths: list[dict] = []
    seen_paths: set[str] = set()
    linked_vendors: dict[str, set[str]] = {key: set() for key in assets}
    for row in _rows(model["support_paths"], 64, "support paths"):
        path = core.exact(
            row,
            {"path_id", "vendor_id", "asset_id", "site_initiated",
             "time_bounded", "operator_aware", "session_monitored"},
            "support path",
        )
        path_id = core.identifier(path["path_id"], "path ID")
        vendor = core.identifier(path["vendor_id"], "path vendor ID")
        asset = core.identifier(path["asset_id"], "path asset ID")
        if path_id in seen_paths or vendor not in vendors or asset not in assets:
            raise OtVendorSupportMapError("Duplicate path or unknown endpoint")
        seen_paths.add(path_id)
        missing = []
        for field in ("site_initiated", "time_bounded", "operator_aware", "session_monitored"):
            if type(path[field]) is not bool:
                raise OtVendorSupportMapError("Boolean support-control declarations required")
            if not path[field]:
                missing.append(field)
        linked_vendors[asset].add(vendor)
        paths.append({
            "path_id_sha256": _digest(path_id),
            "vendor_id_sha256": _digest(vendor),
            "asset_id_sha256": _digest(asset),
            "asset_class": assets[asset],
            "missing_declared_controls": missing,
            "review_cue": bool(missing),
        })
    paths.sort(key=lambda row: row["path_id_sha256"])
    shared_assets = sorted(_digest(asset) for asset, linked in linked_vendors.items()
                           if len(linked) > 1)
    class_counts = Counter(row["asset_class"] for row in paths)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "vendor_count": len(vendors),
        "asset_count": len(assets),
        "support_path_count": len(paths),
        "paths_by_asset_class": {key: class_counts.get(key, 0) for key in sorted(ASSET_CLASSES)},
        "shared_asset_id_sha256": shared_assets,
        "review_cue_count": sum(row["review_cue"] for row in paths),
        "paths": paths,
        "candidate_count": 0,
        "uncertainty": [
            "vendor_and_asset_inventory_completeness_unverified",
            "declared_paths_and_controls_not_observed",
            "site_safety_and_access_authority_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "network_reachability_verified": False,
        "safety_boundary_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only supplied synthetic vendor, asset, and support-path declarations are compared.",
            "A missing declared safeguard or shared asset is a review cue, not a finding.",
            "No vendor credentials, network path, process control, or safety system is tested.",
            "Operator approval, containment, and restoration remain outside this component.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OVM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OtVendorSupportMapReport:
    """Unsigned support-map projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtVendorSupportMapError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtVendorSupportMapReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_vendor_support_map(model: Any) -> OtVendorSupportMapReport:
    return OtVendorSupportMapReport._owned(_derive(model))


def verify_supplied_ot_vendor_support_map(
    report: Any, *, model: Any
) -> OtVendorSupportMapReport:
    if type(report) is not OtVendorSupportMapReport:
        raise OtVendorSupportMapError("Exact OT vendor map wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtVendorSupportMapError("Report differs from separate original model")
    return OtVendorSupportMapReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ot-vendor-support",
        "synthetic_fixture": True,
        "vendors": [{"vendor_id": "vendor-a"}, {"vendor_id": "vendor-b"}],
        "assets": [
            {"asset_id": "engineering-a", "asset_class": "engineering_workstation"},
            {"asset_id": "safety-a", "asset_class": "sis"},
        ],
        "support_paths": [
            {
                "path_id": "path-a", "vendor_id": "vendor-a", "asset_id": "engineering-a",
                "site_initiated": True, "time_bounded": True,
                "operator_aware": True, "session_monitored": True,
            },
            {
                "path_id": "path-b", "vendor_id": "vendor-b", "asset_id": "engineering-a",
                "site_initiated": False, "time_bounded": True,
                "operator_aware": True, "session_monitored": False,
            },
        ],
    }
