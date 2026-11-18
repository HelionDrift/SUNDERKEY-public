"""Compare synthetic telecom relation declarations with supplied policy edges."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

_SPECS = {
    "network_appliance": (
        "AOE-GC-D13-S06", "IW2-009",
        "sha256:b2c1656715c9afab218e0f4f20024055da0aada64eeede50827b887844909bd5",
        "telecom_supplied_appliance_management_relation_projection",
    ),
    "mobile_core": (
        "AOE-GC-D13-S11", "IW2-014",
        "sha256:09cb35efd7e54304e17f3c619d22ff060e8bfbad11b9a380e6c196ed5cd6cf12",
        "telecom_supplied_mobile_core_relation_projection",
    ),
    "signaling": (
        "AOE-GC-D13-S12", "IW2-015",
        "sha256:ca60e41b969502fa085bff546380ede3fe549f6b4994e597af98a77cd4479bb1",
        "telecom_supplied_signaling_route_projection",
    ),
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class TelecomRelationPolicyError(ValueError):
    """A supplied relation policy or original-model replay is invalid."""


def _edges(value: Any, *, label: str) -> set[tuple[str, str]]:
    edges = set()
    for item in core.bounded_list(value, 64, label):
        row = core.exact(item, {"source_ref", "destination_ref"}, label)
        pair = (
            core.identifier(row["source_ref"], "source reference"),
            core.identifier(row["destination_ref"], "destination reference"),
        )
        if pair in edges:
            raise TelecomRelationPolicyError(f"Duplicate {label} edge")
        edges.add(pair)
    return edges


def _derive(value: Any, *, relation_kind: str) -> dict:
    if relation_kind not in _SPECS:
        raise TelecomRelationPolicyError("Unknown closed relation kind")
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "relation_kind", "allowed_edges", "declared_edges",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TelecomRelationPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise TelecomRelationPolicyError("Only synthetic fixtures are accepted")
    if model["relation_kind"] != relation_kind:
        raise TelecomRelationPolicyError("Model relation kind differs from specialist")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    allowed = _edges(model["allowed_edges"], label="allowed edges")
    declared = _edges(model["declared_edges"], label="declared edges")
    if not declared:
        raise TelecomRelationPolicyError("At least one declared edge is required")
    deviations = sorted(declared - allowed)
    profile_id, wave_id, blueprint_sha256, component_id = _SPECS[relation_kind]
    segment = profile_id.rsplit("-", 1)[-1].lower()
    unknown = [] if complete else ["supplied_relation_inventory_incomplete"]
    body = {
        "schema_version": 1,
        "component_id": component_id,
        "profile_id": profile_id,
        "capability_id": f"army.gc.d13.{segment}",
        "vector_id": f"AV-GC-D13-{profile_id.rsplit('-', 1)[-1]}-01",
        "work_package_id": f"IWP2-{profile_id}",
        "wave_id": wave_id,
        "commander_id": "AOE-GC-D13-CMD",
        "group_owner_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": blueprint_sha256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "relation_kind": relation_kind,
        "declared_edge_count": len(declared),
        "outside_supplied_policy_edges": [
            {"source_ref": source, "destination_ref": destination}
            for source, destination in deviations
        ],
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_telecom_relation_projection",
        "source_authenticated": False,
        "network_connected": False,
        "packet_sent": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The edge policy, declarations, and completeness are synthetic assertions.",
            "The model does not establish actual reachability or effective access control.",
            "A mismatch does not prove exploitation or impact.",
            "No appliance, mobile network, signaling system, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(
        body, domain=f"sunderkey.offline-telecom-relations.{relation_kind}.v1",
        prefix="TRP-",
    )
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class TelecomRelationPolicyReport:
    """Unsigned declaration report requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TelecomRelationPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TelecomRelationPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_telecom_relations(
    model: Any, *, relation_kind: str
) -> TelecomRelationPolicyReport:
    return TelecomRelationPolicyReport._owned(_derive(model, relation_kind=relation_kind))


def verify_supplied_telecom_relations(
    report: Any, *, model: Any, relation_kind: str
) -> TelecomRelationPolicyReport:
    if type(report) is not TelecomRelationPolicyReport:
        raise TelecomRelationPolicyError("Exact telecom relation wrapper required")
    expected = _derive(model, relation_kind=relation_kind)
    if report.to_json() != core.canonical(expected):
        raise TelecomRelationPolicyError("Report differs from separate original model")
    return TelecomRelationPolicyReport._owned(expected)


def _fixture(kind: str) -> dict:
    return {
        "schema_version": 1,
        "source_id": f"synthetic-{kind}-relations",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "relation_kind": kind,
        "allowed_edges": [{"source_ref": "zone-a", "destination_ref": "service-a"}],
        "declared_edges": [{"source_ref": "zone-b", "destination_ref": "service-a"}],
    }


def appliance_component_fixture() -> dict:
    return _fixture("network_appliance")


def mobile_core_component_fixture() -> dict:
    return _fixture("mobile_core")


def signaling_component_fixture() -> dict:
    return _fixture("signaling")


def analyze_supplied_appliance_management(model: Any) -> TelecomRelationPolicyReport:
    return analyze_supplied_telecom_relations(model, relation_kind="network_appliance")


def analyze_supplied_mobile_core_relations(model: Any) -> TelecomRelationPolicyReport:
    return analyze_supplied_telecom_relations(model, relation_kind="mobile_core")


def analyze_supplied_signaling_routes(model: Any) -> TelecomRelationPolicyReport:
    return analyze_supplied_telecom_relations(model, relation_kind="signaling")
