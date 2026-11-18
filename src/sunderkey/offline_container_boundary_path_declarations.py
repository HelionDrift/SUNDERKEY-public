"""Compare supplied container-boundary paths without platform interaction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_container_boundary_path_projection"
PROFILE_ID = "AOE-GC-D15-S10"
CAPABILITY_ID = "army.gc.d15.s10"
VECTOR_ID = "AV-GC-D15-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S10"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:994b086fad914ce080cd6527a0c2d1d2f8d88651e38eecb986cb7767a0931224"
DOMAIN = "sunderkey.offline-container-boundary-path-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_NODES = 64
MAX_EDGES = 128
MAX_PATHS = 64
MAX_PATH_EDGES = 16
BOUNDARY_LABELS = {"workload", "container_boundary", "sandbox_boundary", "target_platform"}
EXPOSURE_STATES = {"declared_present", "declared_absent", "unknown"}
PREREQUISITE_STATES = {"declared_met", "declared_unmet", "unknown"}
CONTAINMENT_STATES = {"declared_effective", "declared_ineffective", "unknown"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "credentials", "execution", "filesystem", "finding_publication",
        "network", "process", "provider", "qualification", "target_interaction",
    )
}


class ContainerBoundaryPathError(ValueError):
    """Invalid or over-budget supplied model or original-source replay."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "nodes", "edges", "paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ContainerBoundaryPathError("Exact schema version 1 required")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    nodes = core.bounded_list(model["nodes"], MAX_NODES, "nodes")
    edges = core.bounded_list(model["edges"], MAX_EDGES, "edges")
    paths = core.bounded_list(model["paths"], MAX_PATHS, "paths")
    if not nodes or not edges or not paths:
        raise ContainerBoundaryPathError("Nonempty bounded nodes, edges and paths required")

    node_labels: dict[str, str] = {}
    for item in nodes:
        node = core.exact(item, {"node_id", "boundary_label"}, "node")
        node_id = core.identifier(node["node_id"], "node ID")
        if node_id in node_labels:
            raise ContainerBoundaryPathError("Duplicate node ID")
        node_labels[node_id] = core.choice(
            node["boundary_label"], BOUNDARY_LABELS, "boundary label"
        )

    edge_map: dict[str, dict] = {}
    for item in edges:
        edge = core.exact(
            item,
            {
                "edge_id", "from_id", "to_id", "exposure_state",
                "prerequisite_state", "containment_state",
            },
            "edge",
        )
        edge_id = core.identifier(edge["edge_id"], "edge ID")
        start = core.identifier(edge["from_id"], "edge source ID")
        end = core.identifier(edge["to_id"], "edge destination ID")
        if (
            edge_id in edge_map or start not in node_labels
            or end not in node_labels or start == end
        ):
            raise ContainerBoundaryPathError("Duplicate or invalid directed boundary edge")
        core.choice(edge["exposure_state"], EXPOSURE_STATES, "exposure state")
        core.choice(edge["prerequisite_state"], PREREQUISITE_STATES, "prerequisite state")
        core.choice(edge["containment_state"], CONTAINMENT_STATES, "containment state")
        edge_map[edge_id] = edge

    path_ids: set[str] = set()
    path_sequences: set[tuple[str, ...]] = set()
    for item in paths:
        path = core.exact(
            item,
            {
                "path_id", "entry_id", "destination_id", "edge_ids",
                "context_complete", "claimed_reaches_platform",
            },
            "path",
        )
        path_id = core.identifier(path["path_id"], "path ID")
        entry = core.identifier(path["entry_id"], "entry ID")
        destination = core.identifier(path["destination_id"], "destination ID")
        sequence = core.bounded_list(path["edge_ids"], MAX_PATH_EDGES, "path edges")
        for edge_id in sequence:
            core.identifier(edge_id, "path edge ID")
        if (
            path_id in path_ids or not sequence or len(sequence) != len(set(sequence))
            or tuple(sequence) in path_sequences
        ):
            raise ContainerBoundaryPathError("Unique nonempty path declaration required")
        if (
            node_labels.get(entry) != "workload"
            or node_labels.get(destination) != "target_platform"
        ):
            raise ContainerBoundaryPathError("Workload entry and target-platform label required")
        current = entry
        encountered_boundary = False
        for index, edge_id in enumerate(sequence):
            edge = edge_map.get(edge_id)
            if edge is None or edge["from_id"] != current:
                raise ContainerBoundaryPathError("Declared path must follow known directed edges")
            current = edge["to_id"]
            if node_labels[current] == "target_platform" and index != len(sequence) - 1:
                raise ContainerBoundaryPathError(
                    "Target-platform node must terminate the declared path"
                )
            encountered_boundary |= node_labels[current] in {
                "container_boundary", "sandbox_boundary"
            }
        if current != destination or not encountered_boundary:
            raise ContainerBoundaryPathError("Path must cross a declared boundary to platform")
        core.boolean(path["context_complete"], "path context completeness")
        core.boolean(path["claimed_reaches_platform"], "claimed platform reachability")
        path_ids.add(path_id)
        path_sequences.add(tuple(sequence))
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    edge_map = {edge["edge_id"]: edge for edge in model["edges"]}
    rows = []
    for path in model["paths"]:
        traversed = [edge_map[edge_id] for edge_id in path["edge_ids"]]
        unresolved = sorted(
            edge["edge_id"] for edge in traversed
            if "unknown" in (
                edge["exposure_state"], edge["prerequisite_state"], edge["containment_state"]
            )
        )
        absent_exposure = sorted(
            edge["edge_id"] for edge in traversed
            if edge["exposure_state"] == "declared_absent"
        )
        unmet_prerequisites = sorted(
            edge["edge_id"] for edge in traversed
            if edge["prerequisite_state"] == "declared_unmet"
        )
        effective_containment = sorted(
            edge["edge_id"] for edge in traversed
            if edge["containment_state"] == "declared_effective"
        )
        complete = model["inventory_complete"] and path["context_complete"] and not unresolved
        computed: bool | None = None
        if complete:
            computed = not (absent_exposure or unmet_prerequisites or effective_containment)
        mismatch = computed is not None and computed != path["claimed_reaches_platform"]
        rows.append(
            {
                "path_id": path["path_id"],
                "entry_id": path["entry_id"],
                "destination_id": path["destination_id"],
                "edge_ids": list(path["edge_ids"]),
                "unknown_edge_ids": unresolved,
                "absent_exposure_edge_ids": absent_exposure,
                "unmet_prerequisite_edge_ids": unmet_prerequisites,
                "effective_containment_edge_ids": effective_containment,
                "claimed_reaches_platform": path["claimed_reaches_platform"],
                "computed_from_declarations": computed,
                "disposition": (
                    "unknown" if computed is None else
                    "candidate_supplied_boundary_mismatch" if mismatch else
                    "matches_supplied_boundaries"
                ),
            }
        )
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "source_model": model,
        "path_count": len(rows),
        "candidate_count": sum(
            row["disposition"] == "candidate_supplied_boundary_mismatch" for row in rows
        ),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "path_observations": rows,
        "source_authenticated": False,
        "boundary_exposure_verified": False,
        "containment_enforcement_verified": False,
        "platform_access_verified": False,
        "positive_use_approved": False,
        "finding_claimed": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "bounds": {
            "model_bytes": MAX_MODEL_BYTES, "report_bytes": MAX_REPORT_BYTES,
            "nodes": MAX_NODES, "edges": MAX_EDGES, "paths": MAX_PATHS,
            "path_edges": MAX_PATH_EDGES,
        },
        "limitations": [
            "Boundary labels, exposure prerequisites, containment controls, claims and "
            "completeness are caller declarations.",
            "A candidate is a disagreement within supplied declarations, not verified "
            "platform access or a confirmed escape.",
            "Unknown edge state or incomplete inventory or context yields an unknown path "
            "result with no candidate.",
            "No container, sandbox, provider, network, process or target is contacted.",
            "No action authority, live finding, positive use or qualification is established.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CBP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ContainerBoundaryPathReport:
    """Unsigned detached projection requiring independent original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ContainerBoundaryPathError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ContainerBoundaryPathReport:
        report = object.__new__(cls)
        object.__setattr__(report, "_document_json", core.canonical(document))
        return report

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_container_boundary_paths(model: Any) -> ContainerBoundaryPathReport:
    """Compare only declared boundary paths, prerequisites and control states."""
    return ContainerBoundaryPathReport._owned(_derive(model))


def analyze_supplied_container_boundary_paths_bytes(
    *, model_bytes: bytes
) -> ContainerBoundaryPathReport:
    model = core.decode(model_bytes, maximum=MAX_MODEL_BYTES)
    return analyze_supplied_container_boundary_paths(model)


def verify_supplied_container_boundary_paths(
    report: Any, *, model: Any
) -> ContainerBoundaryPathReport:
    """Replay against separately supplied original premises, not report contents."""
    if type(report) is not ContainerBoundaryPathReport:
        raise ContainerBoundaryPathError("Exact boundary-path report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ContainerBoundaryPathError("Report differs from separately supplied original")
    return ContainerBoundaryPathReport._owned(expected)


def verify_supplied_container_boundary_paths_bytes(
    report_bytes: bytes, *, model: Any
) -> ContainerBoundaryPathReport:
    """Reject changed exported reports against separately supplied original premises."""
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ContainerBoundaryPathError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ContainerBoundaryPathError("Exported report differs from original replay")
    return ContainerBoundaryPathReport._owned(expected)


def component_fixture() -> dict:
    """Fresh fictitious boundary path with a supplied containment contradiction."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-boundary-map",
        "inventory_complete": True,
        "nodes": [
            {"node_id": "workload-a", "boundary_label": "workload"},
            {"node_id": "container-a", "boundary_label": "container_boundary"},
            {"node_id": "sandbox-a", "boundary_label": "sandbox_boundary"},
            {"node_id": "platform-a", "boundary_label": "target_platform"},
        ],
        "edges": [
            {
                "edge_id": "boundary-one", "from_id": "workload-a", "to_id": "container-a",
                "exposure_state": "declared_present", "prerequisite_state": "declared_met",
                "containment_state": "declared_ineffective",
            },
            {
                "edge_id": "boundary-two", "from_id": "container-a", "to_id": "sandbox-a",
                "exposure_state": "declared_present", "prerequisite_state": "declared_met",
                "containment_state": "declared_effective",
            },
            {
                "edge_id": "boundary-three", "from_id": "sandbox-a", "to_id": "platform-a",
                "exposure_state": "declared_present", "prerequisite_state": "declared_met",
                "containment_state": "declared_ineffective",
            },
        ],
        "paths": [
            {
                "path_id": "declared-platform-path", "entry_id": "workload-a",
                "destination_id": "platform-a",
                "edge_ids": ["boundary-one", "boundary-two", "boundary-three"],
                "context_complete": True, "claimed_reaches_platform": True,
            }
        ],
    }


__all__ = [
    "ContainerBoundaryPathError", "ContainerBoundaryPathReport",
    "analyze_supplied_container_boundary_paths",
    "analyze_supplied_container_boundary_paths_bytes",
    "verify_supplied_container_boundary_paths",
    "verify_supplied_container_boundary_paths_bytes", "component_fixture",
]
