"""Project supplied vehicle interface flows against declared gateway rules."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "vehicle_supplied_gateway_flow_projection"
PROFILE_ID = "AOE-GD-D25-S01"
CAPABILITY_ID = "army.gd.d25.s01"
VECTOR_ID = "AV-GD-D25-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GD-D25-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:16ead94bee7ca83d3cec40f83da0f7407e58af6baf23f1586777f5059b5d9ea0"
DOMAIN = "sunderkey.offline-vehicle-gateway-graph.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_MATCHING_RULE_IDS_PER_FLOW = 1
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class VehicleGatewayGraphError(ValueError):
    """A supplied vehicle graph or original replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "inventory_complete", "nodes", "interfaces",
            "gateways", "allowed_flows", "flows",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VehicleGatewayGraphError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    nodes = core.bounded_list(model["nodes"], 128, "nodes")
    interfaces = core.bounded_list(model["interfaces"], 128, "interfaces")
    gateways = core.bounded_list(model["gateways"], 64, "gateways")
    rules = core.bounded_list(model["allowed_flows"], 128, "allowed flows")
    flows = core.bounded_list(model["flows"], 128, "flows")
    if not nodes or not interfaces or not flows:
        raise VehicleGatewayGraphError("Nodes, interfaces and flows must be nonempty")

    node_roles: dict[str, str] = {}
    for item in nodes:
        row = core.exact(item, {"node_id", "role"}, "node")
        node_id = core.identifier(row["node_id"], "node ID")
        role = core.choice(
            row["role"],
            {"external_service", "telematics", "gateway", "vehicle_subsystem"},
            "node role",
        )
        if node_id in node_roles:
            raise VehicleGatewayGraphError("Duplicate node ID")
        node_roles[node_id] = role

    interface_data: dict[str, tuple[str, str]] = {}
    for item in interfaces:
        row = core.exact(item, {"interface_id", "node_id", "segment_id"}, "interface")
        interface_id = core.identifier(row["interface_id"], "interface ID")
        node_id = core.identifier(row["node_id"], "interface node ID")
        segment_id = core.identifier(row["segment_id"], "segment ID")
        if interface_id in interface_data or node_id not in node_roles:
            raise VehicleGatewayGraphError("Duplicate interface or missing node")
        interface_data[interface_id] = (node_id, segment_id)

    gateway_segments: dict[str, tuple[str, str]] = {}
    for item in gateways:
        row = core.exact(
            item,
            {"gateway_id", "node_id", "ingress_interface", "egress_interface"},
            "gateway",
        )
        gateway_id = core.identifier(row["gateway_id"], "gateway ID")
        node_id = core.identifier(row["node_id"], "gateway node ID")
        ingress = core.identifier(row["ingress_interface"], "ingress interface")
        egress = core.identifier(row["egress_interface"], "egress interface")
        if gateway_id in gateway_segments or ingress == egress:
            raise VehicleGatewayGraphError("Duplicate gateway or identical interfaces")
        if node_roles.get(node_id) != "gateway":
            raise VehicleGatewayGraphError("Gateway must reference a gateway node")
        if ingress not in interface_data or egress not in interface_data:
            raise VehicleGatewayGraphError("Gateway references missing interface")
        ingress_node, ingress_segment = interface_data[ingress]
        egress_node, egress_segment = interface_data[egress]
        if ingress_node != node_id or egress_node != node_id:
            raise VehicleGatewayGraphError("Gateway interfaces must belong to its node")
        if ingress_segment == egress_segment:
            raise VehicleGatewayGraphError("Gateway must bridge distinct segments")
        gateway_segments[gateway_id] = (ingress_segment, egress_segment)

    known_segments = {segment for _, segment in interface_data.values()}
    rule_ids: set[str] = set()
    for item in rules:
        row = core.exact(
            item,
            {
                "rule_id", "source_segment", "destination_segment", "channel_id",
                "gateway_id",
            },
            "allowed flow",
        )
        rule_id = core.identifier(row["rule_id"], "rule ID")
        source_segment = core.identifier(row["source_segment"], "source segment")
        destination_segment = core.identifier(
            row["destination_segment"], "destination segment"
        )
        if source_segment not in known_segments or destination_segment not in known_segments:
            raise VehicleGatewayGraphError("Rule references missing segment")
        core.identifier(row["channel_id"], "channel ID")
        if rule_id in rule_ids:
            raise VehicleGatewayGraphError("Duplicate rule ID")
        rule_ids.add(rule_id)
        gateway_id = row["gateway_id"]
        if gateway_id is None:
            if source_segment != destination_segment:
                raise VehicleGatewayGraphError("Cross-segment rule requires a gateway")
        else:
            core.identifier(gateway_id, "rule gateway ID")
            if gateway_segments.get(gateway_id) != (source_segment, destination_segment):
                raise VehicleGatewayGraphError("Rule disagrees with directed gateway graph")

    flow_ids: set[str] = set()
    for item in flows:
        row = core.exact(
            item,
            {
                "flow_id", "source_interface", "destination_interface", "channel_id",
                "expected_allowed",
            },
            "flow",
        )
        flow_id = core.identifier(row["flow_id"], "flow ID")
        if flow_id in flow_ids:
            raise VehicleGatewayGraphError("Duplicate flow ID")
        flow_ids.add(flow_id)
        for key in ("source_interface", "destination_interface"):
            if core.identifier(row[key], key) not in interface_data:
                raise VehicleGatewayGraphError("Flow references missing interface")
        core.identifier(row["channel_id"], "flow channel ID")
        core.boolean(row["expected_allowed"], "expected allowed")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    segments = {
        item["interface_id"]: item["segment_id"] for item in model["interfaces"]
    }
    rows = []
    mismatches = []
    for flow in model["flows"]:
        source_segment = segments[flow["source_interface"]]
        destination_segment = segments[flow["destination_interface"]]
        matching = sorted(
            rule["rule_id"]
            for rule in model["allowed_flows"]
            if rule["source_segment"] == source_segment
            and rule["destination_segment"] == destination_segment
            and rule["channel_id"] == flow["channel_id"]
        )
        projected_allowed = bool(matching) if complete else None
        rows.append({
            "flow_id": flow["flow_id"],
            "source_segment": source_segment,
            "destination_segment": destination_segment,
            "matching_rule_ids": matching[:MAX_MATCHING_RULE_IDS_PER_FLOW],
            "matching_rule_count": len(matching),
            "matching_rule_ids_truncated": len(matching) > MAX_MATCHING_RULE_IDS_PER_FLOW,
            "projected_allowed": projected_allowed,
            "expected_allowed": flow["expected_allowed"],
            "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
        })
        if complete and projected_allowed != flow["expected_allowed"]:
            mismatches.append({
                "flow_id": flow["flow_id"],
                "issue": (
                    "unexpected_declared_allowance" if projected_allowed
                    else "missing_declared_allowance"
                ),
            })
    disposition = (
        "unknown"
        if not complete
        else "candidate_supplied_gateway_flow_mismatch"
        if mismatches
        else "supplied_gateway_flows_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "node_count": len(model["nodes"]),
        "interface_count": len(model["interfaces"]),
        "gateway_count": len(model["gateways"]),
        "rule_count": len(model["allowed_flows"]),
        "flow_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(not complete),
        "source_authenticated": False,
        "vehicle_contacted": False,
        "gateway_policy_applied": False,
        "actual_vehicle_behavior_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Nodes, interfaces, segments, gateways, rules and expected flows are supplied.",
            "Only one directed gateway bridge or an explicit same-segment rule is modeled.",
            "At most one matching rule ID is listed per flow; counts retain the total.",
            "Incomplete inventories do not produce settled flow projections or mismatches.",
            "No route, filtering behavior, protocol content or physical behavior is tested.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VGG-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class VehicleGatewayGraphReport:
    """Unsigned vehicle graph projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VehicleGatewayGraphError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VehicleGatewayGraphReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_vehicle_gateway_graph(model: Any) -> VehicleGatewayGraphReport:
    return VehicleGatewayGraphReport._owned(_derive(model))


def verify_supplied_vehicle_gateway_graph(
    report: Any, *, model: Any
) -> VehicleGatewayGraphReport:
    if type(report) is not VehicleGatewayGraphReport:
        raise VehicleGatewayGraphError("Exact vehicle graph wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VehicleGatewayGraphError("Report differs from separate original model")
    return VehicleGatewayGraphReport._owned(expected)


def verify_supplied_vehicle_gateway_graph_bytes(
    report_bytes: bytes, *, model: Any
) -> VehicleGatewayGraphReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise VehicleGatewayGraphError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise VehicleGatewayGraphError("Exported report differs from original replay")
    return VehicleGatewayGraphReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-vehicle-plan",
        "inventory_complete": True,
        "nodes": [
            {"node_id": "telemetry-unit", "role": "telematics"},
            {"node_id": "boundary-gateway", "role": "gateway"},
            {"node_id": "vehicle-subsystem", "role": "vehicle_subsystem"},
        ],
        "interfaces": [
            {
                "interface_id": "telemetry-if",
                "node_id": "telemetry-unit",
                "segment_id": "connected",
            },
            {
                "interface_id": "gateway-in",
                "node_id": "boundary-gateway",
                "segment_id": "connected",
            },
            {
                "interface_id": "gateway-out",
                "node_id": "boundary-gateway",
                "segment_id": "internal",
            },
            {
                "interface_id": "subsystem-if",
                "node_id": "vehicle-subsystem",
                "segment_id": "internal",
            },
        ],
        "gateways": [{
            "gateway_id": "boundary-gateway",
            "node_id": "boundary-gateway",
            "ingress_interface": "gateway-in",
            "egress_interface": "gateway-out",
        }],
        "allowed_flows": [],
        "flows": [{
            "flow_id": "declared-telemetry",
            "source_interface": "telemetry-if",
            "destination_interface": "subsystem-if",
            "channel_id": "status",
            "expected_allowed": True,
        }],
    }
