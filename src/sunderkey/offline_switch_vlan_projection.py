"""Project declared local switch VLAN paths without network interaction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_switch_vlan_projection"
PROFILE_ID = "AOE-GC-D13-S04"
CAPABILITY_ID = "army.gc.d13.s04"
VECTOR_ID = "AV-GC-D13-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S04"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:779b8ed4ddce4f344c44fe4687e36f6f4c762c39e45fd2686ee09a8c895362ba"
DOMAIN = "sunderkey.offline-switch-vlan-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_PORTS = 128
MAX_QUERIES = 256
MAX_VLANS = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class SwitchVlanProjectionError(ValueError):
    """A supplied switch model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise SwitchVlanProjectionError(f"{label} must be synthetic")
    return identifier


def _vlan(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 4094:
        raise SwitchVlanProjectionError(f"{label} must be an integer from 1 to 4094")
    return value


def _vlan_list(value: Any, label: str) -> list[int]:
    values = core.bounded_list(value, MAX_VLANS, label)
    result = [_vlan(item, label) for item in values]
    if len(set(result)) != len(result):
        raise SwitchVlanProjectionError(f"{label} contains duplicates")
    return result


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "switch_id", "topology_complete",
            "membership_complete", "stp_state_complete", "ports", "queries",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SwitchVlanProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    _synthetic(model["switch_id"], "switch ID")
    for field in ("topology_complete", "membership_complete", "stp_state_complete"):
        core.boolean(model[field], field)
    ports = core.bounded_list(model["ports"], MAX_PORTS, "ports")
    queries = core.bounded_list(model["queries"], MAX_QUERIES, "queries")
    if not ports or not queries:
        raise SwitchVlanProjectionError("Ports and queries must be nonempty")
    seen_ports: set[str] = set()
    for item in ports:
        port = core.exact(
            item,
            {
                "port_id", "mode", "access_vlan", "native_vlan", "allowed_vlans",
                "stp_forwarding_vlans",
            },
            "port",
        )
        port_id = _synthetic(port["port_id"], "port ID")
        if port_id in seen_ports:
            raise SwitchVlanProjectionError("Duplicate port ID")
        seen_ports.add(port_id)
        mode = core.choice(port["mode"], {"access", "trunk"}, "port mode")
        allowed = _vlan_list(port["allowed_vlans"], "allowed VLANs")
        forwarding = _vlan_list(port["stp_forwarding_vlans"], "STP forwarding VLANs")
        if mode == "access":
            access_vlan = _vlan(port["access_vlan"], "access VLAN")
            if port["native_vlan"] is not None or allowed:
                raise SwitchVlanProjectionError("Access port has trunk declarations")
            membership = {access_vlan}
        else:
            if port["access_vlan"] is not None or not allowed:
                raise SwitchVlanProjectionError("Trunk port membership is invalid")
            native_vlan = port["native_vlan"]
            if native_vlan is not None and _vlan(native_vlan, "native VLAN") not in allowed:
                raise SwitchVlanProjectionError("Native VLAN is not allowed on trunk")
            membership = set(allowed)
        if not set(forwarding).issubset(membership):
            raise SwitchVlanProjectionError("STP forwarding VLAN is not a port member")
    seen_queries: set[str] = set()
    for item in queries:
        query = core.exact(
            item,
            {"query_id", "ingress_port_id", "egress_port_id", "ingress_tag_vlan"},
            "query",
        )
        query_id = _synthetic(query["query_id"], "query ID")
        if query_id in seen_queries:
            raise SwitchVlanProjectionError("Duplicate query ID")
        seen_queries.add(query_id)
        ingress = _synthetic(query["ingress_port_id"], "ingress port ID")
        egress = _synthetic(query["egress_port_id"], "egress port ID")
        if ingress == egress or ingress not in seen_ports or egress not in seen_ports:
            raise SwitchVlanProjectionError("Query requires two declared distinct ports")
        if query["ingress_tag_vlan"] is not None:
            _vlan(query["ingress_tag_vlan"], "ingress tag VLAN")
    return model


def _ingress_vlan(port: dict, tag: int | None) -> int | None:
    if port["mode"] == "access":
        return port["access_vlan"] if tag is None else None
    return port["native_vlan"] if tag is None else tag


def _membership(port: dict) -> set[int]:
    if port["mode"] == "access":
        return {port["access_vlan"]}
    return set(port["allowed_vlans"])


def _derive(value: Any) -> dict:
    model = _model(value)
    ports = {port["port_id"]: port for port in model["ports"]}
    complete = all(
        model[field]
        for field in ("topology_complete", "membership_complete", "stp_state_complete")
    )
    projections: list[dict] = []
    for query in model["queries"]:
        ingress = ports[query["ingress_port_id"]]
        egress = ports[query["egress_port_id"]]
        vlan = _ingress_vlan(ingress, query["ingress_tag_vlan"])
        if not complete:
            disposition = "unknown_incomplete_declarations"
        elif vlan is None:
            disposition = "no_candidate_unsupported_ingress_tag"
        elif vlan not in _membership(ingress) or vlan not in _membership(egress):
            disposition = "no_candidate_declared_membership"
        elif (
            vlan not in ingress["stp_forwarding_vlans"]
            or vlan not in egress["stp_forwarding_vlans"]
        ):
            disposition = "no_candidate_declared_port_state"
        else:
            disposition = "candidate_declared_local_bridge"
        projections.append({
            "query_id": query["query_id"],
            "ingress_port_id": query["ingress_port_id"],
            "egress_port_id": query["egress_port_id"],
            "ingress_tag_vlan": query["ingress_tag_vlan"],
            "projected_vlan": vlan if complete else None,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "query_count": len(projections),
            "candidate_count": sum(
                row["disposition"] == "candidate_declared_local_bridge"
                for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations"
                for row in projections
            ),
        },
        "source_authenticated": False,
        "topology_observed": False,
        "port_configuration_observed": False,
        "stp_state_observed": False,
        "switch_forwarding_tested": False,
        "segmentation_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Topology, VLAN membership and port state are caller declarations.",
            "A candidate is a path in one supplied switch model, not observed forwarding.",
            "No MAC learning, ACL, private VLAN, overlay, routing or device behavior is modeled.",
            "An absent candidate does not prove isolation on a live network.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SVP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SwitchVlanProjectionReport:
    """Unsigned switch projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SwitchVlanProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SwitchVlanProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_switch_vlan(model: Any) -> SwitchVlanProjectionReport:
    try:
        return SwitchVlanProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise SwitchVlanProjectionError(str(exc)) from exc


def verify_supplied_switch_vlan(
    report: Any, *, model: Any,
) -> SwitchVlanProjectionReport:
    if type(report) is not SwitchVlanProjectionReport:
        raise SwitchVlanProjectionError("Exact report wrapper required")
    expected = analyze_supplied_switch_vlan(model)
    if report.to_json() != expected.to_json():
        raise SwitchVlanProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_switch_vlan_bytes(
    report_bytes: bytes, *, model: Any,
) -> SwitchVlanProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise SwitchVlanProjectionError(str(exc)) from exc
    expected = analyze_supplied_switch_vlan(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise SwitchVlanProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:switch-source",
        "switch_id": "synthetic:switch-one",
        "topology_complete": True,
        "membership_complete": True,
        "stp_state_complete": True,
        "ports": [
            {"port_id": "synthetic:access-one", "mode": "access", "access_vlan": 20,
             "native_vlan": None, "allowed_vlans": [], "stp_forwarding_vlans": [20]},
            {"port_id": "synthetic:trunk-one", "mode": "trunk", "access_vlan": None,
             "native_vlan": 20, "allowed_vlans": [20, 30],
             "stp_forwarding_vlans": [20, 30]},
            {"port_id": "synthetic:access-two", "mode": "access", "access_vlan": 30,
             "native_vlan": None, "allowed_vlans": [], "stp_forwarding_vlans": [30]},
        ],
        "queries": [
            {"query_id": "synthetic:bridge", "ingress_port_id": "synthetic:access-one",
             "egress_port_id": "synthetic:trunk-one", "ingress_tag_vlan": None},
            {"query_id": "synthetic:separate", "ingress_port_id": "synthetic:access-one",
             "egress_port_id": "synthetic:access-two", "ingress_tag_vlan": None},
        ],
    }


__all__ = [
    "SwitchVlanProjectionError", "SwitchVlanProjectionReport",
    "analyze_supplied_switch_vlan", "verify_supplied_switch_vlan",
    "verify_supplied_switch_vlan_bytes", "component_fixture",
]
