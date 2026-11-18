"""Project supplied synthetic ADC routes and declared transport boundaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_adc_route_projection"
PROFILE_ID = "AOE-GC-D13-S16"
CAPABILITY_ID = "army.gc.d13.s16"
VECTOR_ID = "AV-GC-D13-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S16"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c82a2261ca931d23eab5d9bc9d0588b24ad2574f60dded29eebba2be81b2e5cb"
DOMAIN = "sunderkey.offline-adc-route-projection.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class AdcRouteProjectionError(ValueError):
    """The supplied declaration or original-model replay is invalid."""


def _overlap(left: str, right: str) -> bool:
    return (
        left == "/" or right == "/" or left == right
        or left.startswith(right + "/") or right.startswith(left + "/")
    )


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "listeners", "backends", "routes",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AdcRouteProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise AdcRouteProjectionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    listeners = {}
    for item in core.bounded_list(model["listeners"], 16, "listeners"):
        row = core.exact(item, {
            "listener_id", "public", "tls_terminated_at_edge",
        }, "listener")
        listener_id = core.identifier(row["listener_id"], "listener ID")
        if listener_id in listeners:
            raise AdcRouteProjectionError("Duplicate listener ID")
        listeners[listener_id] = {
            "public": core.boolean(row["public"], "public listener"),
            "edge_tls": core.boolean(row["tls_terminated_at_edge"], "edge TLS"),
        }
    if not listeners:
        raise AdcRouteProjectionError("At least one listener is required")
    backends = {}
    for item in core.bounded_list(model["backends"], 32, "backends"):
        row = core.exact(item, {"backend_id", "zone"}, "backend")
        backend_id = core.identifier(row["backend_id"], "backend ID")
        if backend_id in backends:
            raise AdcRouteProjectionError("Duplicate backend ID")
        backends[backend_id] = core.choice(
            row["zone"], {"public", "shared", "private"}, "backend zone"
        )
    if not backends:
        raise AdcRouteProjectionError("At least one backend is required")
    routes = []
    seen_ids = set()
    seen_listener_paths = set()
    for item in core.bounded_list(model["routes"], 64, "routes"):
        row = core.exact(item, {
            "route_id", "listener_id", "path_prefix", "backend_id",
            "upstream_tls_declared", "forwarded_header_trusted",
            "forwarded_header_validation_declared",
        }, "route")
        route_id = core.identifier(row["route_id"], "route ID")
        listener_id = core.identifier(row["listener_id"], "route listener ID")
        backend_id = core.identifier(row["backend_id"], "route backend ID")
        prefix = core.path(row["path_prefix"])
        if route_id in seen_ids or (listener_id, prefix) in seen_listener_paths:
            raise AdcRouteProjectionError("Duplicate route ID or listener path")
        if listener_id not in listeners or backend_id not in backends:
            raise AdcRouteProjectionError("Route references unknown listener or backend")
        seen_ids.add(route_id)
        seen_listener_paths.add((listener_id, prefix))
        routes.append({
            "route_id": route_id,
            "listener_id": listener_id,
            "path_prefix": prefix,
            "backend_id": backend_id,
            "upstream_tls": core.boolean(row["upstream_tls_declared"], "upstream TLS"),
            "header_trusted": core.boolean(row["forwarded_header_trusted"], "header trust"),
            "header_validated": core.boolean(
                row["forwarded_header_validation_declared"], "header validation"
            ),
        })
    if not routes:
        raise AdcRouteProjectionError("At least one route is required")
    overlaps = [
        sorted([left["route_id"], right["route_id"]])
        for index, left in enumerate(routes)
        for right in routes[index + 1:]
        if left["listener_id"] == right["listener_id"]
        and _overlap(left["path_prefix"], right["path_prefix"])
    ]
    overlaps.sort()
    projections = []
    for route in routes:
        listener = listeners[route["listener_id"]]
        flags = []
        if listener["public"] and not listener["edge_tls"]:
            flags.append("public_listener_without_declared_edge_tls")
        if listener["edge_tls"] and not route["upstream_tls"]:
            flags.append("plaintext_declared_after_edge_termination")
        if route["header_trusted"] and not route["header_validated"]:
            flags.append("trusted_forwarded_header_without_declared_validation")
        projections.append({
            "route_id": route["route_id"],
            "listener_id": route["listener_id"],
            "backend_id": route["backend_id"],
            "public_to_private_declared": listener["public"]
            and backends[route["backend_id"]] == "private",
            "declared_boundary_flags": sorted(flags),
        })
    projections.sort(key=lambda row: row["route_id"])
    unknown = [] if complete else ["supplied_adc_route_inventory_incomplete"]
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
        "supplied_listener_count": len(listeners),
        "supplied_backend_count": len(backends),
        "supplied_route_count": len(routes),
        "route_projections": projections,
        "overlapping_route_id_pairs": overlaps,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_adc_route_projection",
        "source_authenticated": False,
        "adc_configuration_inspected": False,
        "tls_handshake_performed": False,
        "routing_behavior_verified": False,
        "header_behavior_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Listeners, routes, backends, transport, and header states are supplied assertions.",
            "Prefix overlap uses a declared path model, not vendor routing precedence.",
            "A boundary flag does not prove exposure, exploitability, or a vulnerability.",
            "No ADC, CDN, TLS endpoint, request, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ARP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class AdcRouteProjectionReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AdcRouteProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AdcRouteProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_adc_routes(model: Any) -> AdcRouteProjectionReport:
    return AdcRouteProjectionReport._owned(_derive(model))


def verify_supplied_adc_routes(
    report: Any, *, model: Any
) -> AdcRouteProjectionReport:
    if type(report) is not AdcRouteProjectionReport:
        raise AdcRouteProjectionError("Exact route wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AdcRouteProjectionError("Report differs from separate original model")
    return AdcRouteProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-adc-routes",
        "synthetic_fixture": True, "inventory_complete": True,
        "listeners": [{
            "listener_id": "edge", "public": True, "tls_terminated_at_edge": True,
        }],
        "backends": [{"backend_id": "app", "zone": "private"}],
        "routes": [{
            "route_id": "app-route", "listener_id": "edge", "path_prefix": "/app",
            "backend_id": "app", "upstream_tls_declared": False,
            "forwarded_header_trusted": True,
            "forwarded_header_validation_declared": False,
        }],
    }
