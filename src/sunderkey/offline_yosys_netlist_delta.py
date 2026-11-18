"""Compare bounded synthetic Yosys-style netlist structure without simulation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_yosys_netlist_structural_delta"
PROFILE_ID = "AOE-GD-D18-S12"
CAPABILITY_ID = "army.gd.d18.s12"
VECTOR_ID = "AV-GD-D18-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S12"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:f192f9019b949d72eda26c4421f7ebd998f264527c4324b760df2da3c392725e"
DOMAIN = "sunderkey.offline-yosys-netlist-delta.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_MODULES = 4
MAX_PORTS = 32
MAX_CELLS = 256
MAX_CELL_TYPES = 64
MAX_BIT_WIDTH = 64
MAX_CELL_PORTS = 16
LABEL = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.:/-]{0,63}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class YosysNetlistDeltaError(ValueError):
    """A supplied netlist model or separate original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise YosysNetlistDeltaError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise YosysNetlistDeltaError("Model exceeds byte bound")
    return result


def _label(value: Any, name: str) -> str:
    if type(value) is not str or LABEL.fullmatch(value) is None:
        raise YosysNetlistDeltaError(f"{name} is invalid")
    return value


def _mapping(value: Any, limit: int, name: str) -> dict:
    if type(value) is not dict or len(value) > limit:
        raise YosysNetlistDeltaError(f"{name} must be a bounded object")
    for key in value:
        _label(key, name + " key")
    return value


def _bits(value: Any, name: str) -> list[int | str]:
    if type(value) is not list or not 1 <= len(value) <= MAX_BIT_WIDTH:
        raise YosysNetlistDeltaError(f"{name} must be a bounded bit vector")
    for bit in value:
        if type(bit) is int and 2 <= bit <= 1_000_000_000:
            continue
        if type(bit) is str and bit in {"0", "1", "x", "z"}:
            continue
        raise YosysNetlistDeltaError(f"{name} contains an invalid bit")
    return value


def _netlist_snapshot(value: Any, top_module_id: str) -> dict:
    if type(value) is not dict or type(value.get("modules")) is not dict:
        raise YosysNetlistDeltaError("Netlist modules are required")
    modules = _mapping(value["modules"], MAX_MODULES, "modules")
    if top_module_id not in modules:
        raise YosysNetlistDeltaError("Top module is absent")
    top = modules[top_module_id]
    if type(top) is not dict:
        raise YosysNetlistDeltaError("Top module is invalid")
    ports = _mapping(top.get("ports"), MAX_PORTS, "ports")
    cells = _mapping(top.get("cells"), MAX_CELLS, "cells")
    if not ports:
        raise YosysNetlistDeltaError("At least one public port is required")
    port_shapes: dict[str, dict] = {}
    output_bits: dict[str, list[int | str]] = {}
    for name, detail in ports.items():
        if (
            type(detail) is not dict
            or type(detail.get("direction")) is not str
            or detail["direction"] not in {"input", "output", "inout"}
        ):
            raise YosysNetlistDeltaError("Port direction is invalid")
        bits = _bits(detail.get("bits"), "port bits")
        port_shapes[name] = {"direction": detail["direction"], "bit_count": len(bits)}
        if detail["direction"] in {"output", "inout"}:
            output_bits[name] = bits
    type_counts: dict[str, int] = {}
    output_drivers: dict[int, int] = {}
    direction_metadata_complete = True
    for detail in cells.values():
        if type(detail) is not dict:
            raise YosysNetlistDeltaError("Cell detail is invalid")
        cell_type = _label(detail.get("type"), "cell type")
        type_counts[cell_type] = type_counts.get(cell_type, 0) + 1
        connections = _mapping(
            detail.get("connections"), MAX_CELL_PORTS, "cell connections"
        )
        if not connections:
            raise YosysNetlistDeltaError("Cell connections are required")
        directions = detail.get("port_directions")
        if directions is None:
            direction_metadata_complete = False
        else:
            directions = _mapping(directions, MAX_CELL_PORTS, "cell port directions")
            if set(directions) != set(connections):
                direction_metadata_complete = False
            for direction in directions.values():
                if type(direction) is not str or direction not in {
                    "input", "output", "inout"
                }:
                    raise YosysNetlistDeltaError("Cell port direction is invalid")
        for name, bits in connections.items():
            _bits(bits, "cell connection bits")
            if directions is not None and directions.get(name) in {"output", "inout"}:
                for bit in bits:
                    if type(bit) is int:
                        output_drivers[bit] = output_drivers.get(bit, 0) + 1
    if len(type_counts) > MAX_CELL_TYPES:
        raise YosysNetlistDeltaError("Cell type count exceeds bound")
    return {
        "netlist_sha256": core.digest(_canonical(value).encode("ascii")),
        "module_count": len(modules),
        "other_module_count": len(modules) - 1,
        "port_count": len(ports),
        "cell_count": len(cells),
        "port_shapes": dict(sorted(port_shapes.items())),
        "cell_type_counts": dict(sorted(type_counts.items())),
        "output_cell_driver_counts": {
            name: [output_drivers.get(bit, 0) if type(bit) is int else 0 for bit in bits]
            for name, bits in sorted(output_bits.items())
        },
        "cell_direction_metadata_complete": direction_metadata_complete,
    }


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {
            "schema_version", "source_id", "synthetic_fixture", "top_module_id",
            "approved_cell_type_ids", "baseline_netlist", "candidate_netlist",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise YosysNetlistDeltaError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise YosysNetlistDeltaError("Only synthetic fixtures are accepted")
    top = _label(model["top_module_id"], "top module ID")
    approved = model["approved_cell_type_ids"]
    if type(approved) is not list or not 1 <= len(approved) <= MAX_CELL_TYPES:
        raise YosysNetlistDeltaError("Approved cell types must be bounded")
    approved = [_label(item, "approved cell type") for item in approved]
    if len(approved) != len(set(approved)):
        raise YosysNetlistDeltaError("Approved cell types must be distinct")
    baseline = _netlist_snapshot(model["baseline_netlist"], top)
    candidate = _netlist_snapshot(model["candidate_netlist"], top)
    before_types = baseline["cell_type_counts"]
    after_types = candidate["cell_type_counts"]
    added = {
        key: after_types[key] - before_types.get(key, 0)
        for key in sorted(after_types)
        if after_types[key] > before_types.get(key, 0)
    }
    removed = {
        key: before_types[key] - after_types.get(key, 0)
        for key in sorted(before_types)
        if before_types[key] > after_types.get(key, 0)
    }
    changed_ports = sorted(
        key for key in set(baseline["port_shapes"]) | set(candidate["port_shapes"])
        if baseline["port_shapes"].get(key) != candidate["port_shapes"].get(key)
    )
    changed_output_drivers = sorted(
        key for key in (
            set(baseline["output_cell_driver_counts"])
            | set(candidate["output_cell_driver_counts"])
        )
        if baseline["output_cell_driver_counts"].get(key)
        != candidate["output_cell_driver_counts"].get(key)
    )
    unapproved = sorted(set(after_types) - set(approved))
    uncertainty = []
    if baseline["other_module_count"] or candidate["other_module_count"]:
        uncertainty.append("non_top_modules_not_analyzed")
    if not (
        baseline["cell_direction_metadata_complete"]
        and candidate["cell_direction_metadata_complete"]
    ):
        uncertainty.append("cell_port_direction_metadata_incomplete")
    uncertainty.append("structural_shape_does_not_prove_functional_equivalence")
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "top_module_id": top,
        "approved_cell_type_ids": sorted(approved),
        "baseline": baseline,
        "candidate": candidate,
        "added_cell_type_counts": added,
        "removed_cell_type_counts": removed,
        "changed_public_port_ids": changed_ports,
        "changed_output_cell_driver_port_ids": changed_output_drivers,
        "unapproved_candidate_cell_type_ids": unapproved,
        "structural_delta_present": bool(
            added or removed or changed_ports or changed_output_drivers
        ),
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "supplied_netlist_structural_projection",
        "source_authenticated": False,
        "hardware_design_identity_verified": False,
        "functional_equivalence_verified": False,
        "silicon_behavior_verified": False,
        "hardware_trojan_detected": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Both JSON netlists and the approved type list are synthetic caller assertions.",
            "Only bounded top-module ports, cells, types and declared connections are compared.",
            "Cell-driver counts depend on supplied cell port-direction metadata.",
            "A structural difference is not evidence of a hardware trojan or exploitability.",
            "No synthesis, simulation, device measurement or target interaction occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="YND-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class YosysNetlistDeltaReport:
    """Unsigned structural projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise YosysNetlistDeltaError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> YosysNetlistDeltaReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_yosys_netlist_delta(model: Any) -> YosysNetlistDeltaReport:
    return YosysNetlistDeltaReport._owned(_derive(model))


def verify_supplied_yosys_netlist_delta(
    report: Any, *, model: Any
) -> YosysNetlistDeltaReport:
    if type(report) is not YosysNetlistDeltaReport:
        raise YosysNetlistDeltaError("Exact netlist wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise YosysNetlistDeltaError("Report differs from separate original model")
    return YosysNetlistDeltaReport._owned(expected)


def component_fixture() -> dict:
    ports = {
        "A": {"direction": "input", "bits": [2]},
        "Y": {"direction": "output", "bits": [3]},
    }
    baseline_cells = {
        "u_not": {
            "type": "$not",
            "connections": {"A": [2], "Y": [3]},
            "port_directions": {"A": "input", "Y": "output"},
        }
    }
    added_cell = {
        "u_xor": {
            "type": "$xor",
            "connections": {"A": [2], "B": ["1"], "Y": [3]},
            "port_directions": {"A": "input", "B": "input", "Y": "output"},
        }
    }
    return {
        "schema_version": 1,
        "source_id": "synthetic-yosys-netlist-delta",
        "synthetic_fixture": True,
        "top_module_id": "top",
        "approved_cell_type_ids": ["$not"],
        "baseline_netlist": {
            "creator": "Yosys synthetic fixture",
            "modules": {"top": {"ports": ports, "cells": baseline_cells}},
        },
        "candidate_netlist": {
            "creator": "Yosys synthetic fixture",
            "modules": {"top": {"ports": ports, "cells": {**baseline_cells, **added_cell}}},
        },
    }
