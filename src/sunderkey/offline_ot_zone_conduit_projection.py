"""Project supplied OT flows against declared zones and conduits."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ot_supplied_zone_conduit_flow_projection"
PROFILE_ID = "AOE-GD-D19-S01"
CAPABILITY_ID = "army.gd.d19.s01"
VECTOR_ID = "AV-GD-D19-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S01"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:f66620f1afa4c871a84f8bb2fc47492f53e831c07c3b088246d34f4fc58cbe0f"
DOMAIN = "sunderkey.offline-ot-zone-conduit-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class OtZoneConduitProjectionError(ValueError):
    """A supplied OT topology or original replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "topology_complete", "assets", "conduits", "flows"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtZoneConduitProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["topology_complete"], "topology completeness")
    assets = core.bounded_list(model["assets"], 128, "assets")
    conduits = core.bounded_list(model["conduits"], 128, "conduits")
    flows = core.bounded_list(model["flows"], 128, "flows")
    if not assets or not flows:
        raise OtZoneConduitProjectionError("Assets and flows must be nonempty")
    asset_zones: dict[str, str] = {}
    for item in assets:
        row = core.exact(item, {"asset_id", "zone_id"}, "asset")
        asset_id = core.identifier(row["asset_id"], "asset ID")
        zone_id = core.identifier(row["zone_id"], "zone ID")
        if asset_id in asset_zones:
            raise OtZoneConduitProjectionError("Duplicate asset ID")
        asset_zones[asset_id] = zone_id
    conduit_ids: set[str] = set()
    for item in conduits:
        row = core.exact(
            item, {"conduit_id", "from_zone", "to_zone", "services"}, "conduit"
        )
        conduit_id = core.identifier(row["conduit_id"], "conduit ID")
        from_zone = core.identifier(row["from_zone"], "from zone")
        to_zone = core.identifier(row["to_zone"], "to zone")
        if conduit_id in conduit_ids or from_zone == to_zone:
            raise OtZoneConduitProjectionError("Duplicate conduit or same-zone conduit")
        conduit_ids.add(conduit_id)
        services = core.bounded_list(row["services"], 32, "conduit services")
        if not services:
            raise OtZoneConduitProjectionError("Conduit services must be nonempty")
        service_ids = [core.identifier(service, "service ID") for service in services]
        if len(set(service_ids)) != len(service_ids):
            raise OtZoneConduitProjectionError("Duplicate conduit service")
    flow_ids: set[str] = set()
    for item in flows:
        row = core.exact(
            item,
            {"flow_id", "source_asset", "destination_asset", "service_id", "expected_allowed"},
            "flow",
        )
        flow_id = core.identifier(row["flow_id"], "flow ID")
        if flow_id in flow_ids:
            raise OtZoneConduitProjectionError("Duplicate flow ID")
        flow_ids.add(flow_id)
        for key in ("source_asset", "destination_asset"):
            if core.identifier(row[key], key) not in asset_zones:
                raise OtZoneConduitProjectionError("Flow references missing asset")
        core.identifier(row["service_id"], "service ID")
        core.boolean(row["expected_allowed"], "expected allowed")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    asset_zones = {item["asset_id"]: item["zone_id"] for item in model["assets"]}
    rows = []
    mismatches = []
    for flow in model["flows"]:
        source_zone = asset_zones[flow["source_asset"]]
        destination_zone = asset_zones[flow["destination_asset"]]
        matching = sorted(
            conduit["conduit_id"]
            for conduit in model["conduits"]
            if conduit["from_zone"] == source_zone
            and conduit["to_zone"] == destination_zone
            and flow["service_id"] in conduit["services"]
        )
        allowed = source_zone == destination_zone or bool(matching)
        rows.append({
            "flow_id": flow["flow_id"],
            "source_zone": source_zone,
            "destination_zone": destination_zone,
            "matching_conduit_ids": matching,
            "projected_allowed": allowed,
            "expected_allowed": flow["expected_allowed"],
        })
        if allowed != flow["expected_allowed"]:
            mismatches.append({
                "flow_id": flow["flow_id"],
                "issue": "unexpected_declared_path" if allowed else "missing_declared_path",
            })
    disposition = (
        "unknown"
        if not model["topology_complete"]
        else "candidate_supplied_zone_conduit_mismatch"
        if mismatches
        else "supplied_zone_conduit_flows_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "asset_count": len(model["assets"]),
        "conduit_count": len(model["conduits"]),
        "flow_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if model["topology_complete"] else 0,
        "unknown_count": int(not model["topology_complete"]),
        "source_authenticated": False,
        "ot_network_contacted": False,
        "actual_reachability_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Assets, zones, conduits, services and expected flows are supplied.",
            "Same-zone flows are assumed allowed only within this simple model.",
            "No firewall, routing, OT protocol or physical reachability is tested.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OTZ-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OtZoneConduitProjectionReport:
    """Unsigned OT flow projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtZoneConduitProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtZoneConduitProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_zone_conduits(model: Any) -> OtZoneConduitProjectionReport:
    return OtZoneConduitProjectionReport._owned(_derive(model))


def verify_supplied_ot_zone_conduits(
    report: Any, *, model: Any
) -> OtZoneConduitProjectionReport:
    if type(report) is not OtZoneConduitProjectionReport:
        raise OtZoneConduitProjectionError("Exact OT zone wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtZoneConduitProjectionError("Report differs from separate original model")
    return OtZoneConduitProjectionReport._owned(expected)


def verify_supplied_ot_zone_conduits_bytes(
    report_bytes: bytes, *, model: Any
) -> OtZoneConduitProjectionReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise OtZoneConduitProjectionError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise OtZoneConduitProjectionError("Exported report differs from original replay")
    return OtZoneConduitProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-zone-plan",
        "topology_complete": True,
        "assets": [
            {"asset_id": "historian", "zone_id": "enterprise"},
            {"asset_id": "controller", "zone_id": "control"},
        ],
        "conduits": [],
        "flows": [{
            "flow_id": "historian-to-controller",
            "source_asset": "historian",
            "destination_asset": "controller",
            "service_id": "telemetry",
            "expected_allowed": True,
        }],
    }
