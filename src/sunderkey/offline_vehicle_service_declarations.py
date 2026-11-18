"""Compare supplied vehicle service and zone-policy declarations without traffic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "vehicle_supplied_service_zone_declarations"
PROFILE_ID = "AOE-GD-D25-S03"
CAPABILITY_ID = "army.gd.d25.s03"
VECTOR_ID = "AV-GD-D25-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GD-D25-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:2f795115e6a1905d608f5ee0a388926143a7a66d423b677b5d020049fc4ff090"
DOMAIN = "sunderkey.offline-vehicle-service-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class VehicleServiceDeclarationsError(ValueError):
    """A supplied vehicle service declaration or replay is invalid."""


def _version(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 65_535:
        raise VehicleServiceDeclarationsError(f"{label} must be a native bounded integer")
    return value


def _model(
    value: Any,
) -> tuple[dict, str, dict[str, dict], set[str], dict[tuple[str, str], bool]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "service_inventory_complete",
            "route_inventory_complete", "zones", "services", "routes", "consumers",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VehicleServiceDeclarationsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["service_inventory_complete"], "service inventory completeness")
    core.boolean(model["route_inventory_complete"], "route inventory completeness")
    zones: set[str] = set()
    for row in core.bounded_list(model["zones"], 32, "zones"):
        zone = core.exact(row, {"zone_id"}, "zone")
        zone_id = core.identifier(zone["zone_id"], "zone ID")
        if zone_id in zones:
            raise VehicleServiceDeclarationsError("Duplicate zone ID")
        zones.add(zone_id)
    if not zones:
        raise VehicleServiceDeclarationsError("At least one supplied zone is required")
    services: dict[str, dict] = {}
    for row in core.bounded_list(model["services"], 64, "services"):
        service = core.exact(
            row,
            {
                "service_id", "provider_zone_id", "interface_id",
                "major_version", "minor_version", "enabled",
            },
            "service",
        )
        service_id = core.identifier(service["service_id"], "service ID")
        if service_id in services:
            raise VehicleServiceDeclarationsError("Duplicate service ID")
        if core.identifier(service["provider_zone_id"], "provider zone") not in zones:
            raise VehicleServiceDeclarationsError("Service names an unknown zone")
        core.identifier(service["interface_id"], "interface ID")
        _version(service["major_version"], "major version")
        _version(service["minor_version"], "minor version")
        core.boolean(service["enabled"], "service enabled state")
        services[service_id] = service
    routes: dict[tuple[str, str], bool] = {}
    for row in core.bounded_list(model["routes"], 128, "routes"):
        route = core.exact(row, {"source_zone_id", "destination_zone_id", "allowed"}, "route")
        source = core.identifier(route["source_zone_id"], "source zone")
        destination = core.identifier(route["destination_zone_id"], "destination zone")
        if source not in zones or destination not in zones:
            raise VehicleServiceDeclarationsError("Route names an unknown zone")
        core.boolean(route["allowed"], "route allowed state")
        key = (source, destination)
        if key in routes:
            raise VehicleServiceDeclarationsError("Duplicate directed route")
        routes[key] = route["allowed"]
    consumers: set[str] = set()
    for row in core.bounded_list(model["consumers"], 64, "consumers"):
        consumer = core.exact(
            row,
            {
                "consumer_id", "requester_zone_id", "service_id", "interface_id",
                "required_major", "minimum_minor", "claimed_allowed", "context_complete",
            },
            "consumer",
        )
        consumer_id = core.identifier(consumer["consumer_id"], "consumer ID")
        if consumer_id in consumers:
            raise VehicleServiceDeclarationsError("Duplicate consumer ID")
        consumers.add(consumer_id)
        if core.identifier(consumer["requester_zone_id"], "requester zone") not in zones:
            raise VehicleServiceDeclarationsError("Consumer names an unknown zone")
        core.identifier(consumer["service_id"], "requested service ID")
        core.identifier(consumer["interface_id"], "requested interface ID")
        _version(consumer["required_major"], "required major version")
        _version(consumer["minimum_minor"], "minimum minor version")
        core.boolean(consumer["claimed_allowed"], "claimed allowed state")
        core.boolean(consumer["context_complete"], "consumer context completeness")
    return model, core.canonical(model), services, zones, routes


def _derive(value: Any) -> dict:
    model, source_text, services, _zones, routes = _model(value)
    rows = []
    for consumer in sorted(model["consumers"], key=lambda row: row["consumer_id"]):
        service = services.get(consumer["service_id"])
        reasons = []
        unknown = not consumer["context_complete"]
        if service is None:
            if model["service_inventory_complete"]:
                reasons.append("service_absent_from_complete_inventory")
            else:
                unknown = True
        else:
            if not service["enabled"]:
                reasons.append("service_declared_disabled")
            if service["interface_id"] != consumer["interface_id"]:
                reasons.append("interface_id_mismatch")
            if service["major_version"] != consumer["required_major"]:
                reasons.append("major_version_mismatch")
            if service["minor_version"] < consumer["minimum_minor"]:
                reasons.append("below_local_minimum_minor")
            route_key = (consumer["requester_zone_id"], service["provider_zone_id"])
            if route_key not in routes:
                if model["route_inventory_complete"]:
                    reasons.append("route_absent_from_complete_inventory")
                else:
                    unknown = True
            elif not routes[route_key]:
                reasons.append("route_declared_denied")
        expected = None if unknown else not reasons
        disposition = (
            "unknown_supplied_context" if expected is None else
            "candidate_claim_conflict" if expected != consumer["claimed_allowed"] else
            "supplied_claim_consistent"
        )
        rows.append({
            "consumer_id": consumer["consumer_id"],
            "service_id": consumer["service_id"],
            "reasons": reasons,
            "projected_allowed": expected,
            "claimed_allowed": consumer["claimed_allowed"],
            "disposition": disposition,
        })
    candidate_count = sum(row["disposition"] == "candidate_claim_conflict" for row in rows)
    unknown_count = sum(row["disposition"] == "unknown_supplied_context" for row in rows)
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "service_count": len(services),
        "consumer_count": len(rows),
        "rows": rows,
        "candidate_count": candidate_count,
        "unknown_count": unknown_count,
        "source_authenticated": False,
        "someip_message_parsed": False,
        "vehicle_contacted": False,
        "network_contacted": False,
        "route_enacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All zones, services, routes, consumers and completeness flags are supplied.",
            "Version and route comparisons are local policy conventions, not protocol conformance.",
            "No SOME/IP message, service discovery, vehicle network or endpoint is observed.",
            "A claim conflict is an unsigned review candidate, not proof of vehicle access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VSD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class VehicleServiceDeclarationsReport:
    """Unsigned vehicle service projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VehicleServiceDeclarationsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VehicleServiceDeclarationsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_vehicle_service_declarations(model: Any) -> VehicleServiceDeclarationsReport:
    return VehicleServiceDeclarationsReport._owned(_derive(model))


def verify_supplied_vehicle_service_declarations(
    report: Any, *, model: Any
) -> VehicleServiceDeclarationsReport:
    if type(report) is not VehicleServiceDeclarationsReport:
        raise VehicleServiceDeclarationsError("Exact vehicle service wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VehicleServiceDeclarationsError("Report differs from separate original model")
    return VehicleServiceDeclarationsReport._owned(expected)


def verify_supplied_vehicle_service_declarations_bytes(
    report_bytes: bytes, *, model: Any
) -> VehicleServiceDeclarationsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise VehicleServiceDeclarationsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise VehicleServiceDeclarationsError("Exported report differs from original replay")
    return VehicleServiceDeclarationsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-vehicle-service-declarations",
        "service_inventory_complete": True,
        "route_inventory_complete": True,
        "zones": [{"zone_id": "telematics"}, {"zone_id": "diagnostics"}],
        "services": [{
            "service_id": "service-a",
            "provider_zone_id": "telematics",
            "interface_id": "interface-a",
            "major_version": 1,
            "minor_version": 2,
            "enabled": True,
        }],
        "routes": [{
            "source_zone_id": "diagnostics",
            "destination_zone_id": "telematics",
            "allowed": False,
        }],
        "consumers": [{
            "consumer_id": "client-a",
            "requester_zone_id": "diagnostics",
            "service_id": "service-a",
            "interface_id": "interface-a",
            "required_major": 1,
            "minimum_minor": 1,
            "claimed_allowed": True,
            "context_complete": True,
        }],
    }
