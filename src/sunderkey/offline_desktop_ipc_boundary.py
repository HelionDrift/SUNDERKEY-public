"""Project unchecked paths in a supplied synthetic desktop IPC graph."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "desktop_supplied_ipc_boundary_projection"
PROFILE_ID = "AOE-GB-D08-S13"
CAPABILITY_ID = "army.gb.d08.s13"
VECTOR_ID = "AV-GB-D08-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S13"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:dd60b2c22ae2ac494330298174010dae58b179abaa40b428e9f04e482450bd42"
DOMAIN = "sunderkey.offline-desktop-ipc-boundary.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class DesktopIpcBoundaryError(ValueError):
    """The declaration or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "nodes", "entry_node_ids", "edges",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DesktopIpcBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise DesktopIpcBoundaryError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    nodes = {}
    for item in core.bounded_list(model["nodes"], 32, "nodes"):
        row = core.exact(item, {"node_id", "kind", "privileged"}, "node")
        node_id = core.identifier(row["node_id"], "node ID")
        if node_id in nodes:
            raise DesktopIpcBoundaryError("Duplicate node ID")
        nodes[node_id] = {
            "kind": core.choice(row["kind"], {
                "untrusted_client", "app_process", "elevated_helper", "service",
            }, "node kind"),
            "privileged": core.boolean(row["privileged"], "privileged flag"),
        }
    if not nodes:
        raise DesktopIpcBoundaryError("At least one node is required")
    entries = []
    for entry in core.bounded_list(model["entry_node_ids"], 16, "entry nodes"):
        node_id = core.identifier(entry, "entry node ID")
        if node_id not in nodes or nodes[node_id]["privileged"] or node_id in entries:
            raise DesktopIpcBoundaryError("Entry must be unique and nonprivileged")
        entries.append(node_id)
    if not entries:
        raise DesktopIpcBoundaryError("At least one entry is required")
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    seen_edges = set()
    guarded_count = 0
    for item in core.bounded_list(model["edges"], 64, "edges"):
        row = core.exact(item, {"source_id", "destination_id", "guard_declared"}, "edge")
        source = core.identifier(row["source_id"], "edge source")
        destination = core.identifier(row["destination_id"], "edge destination")
        if source not in nodes or destination not in nodes or source == destination:
            raise DesktopIpcBoundaryError("Edge endpoints are invalid")
        pair = (source, destination)
        if pair in seen_edges:
            raise DesktopIpcBoundaryError("Duplicate directed edge")
        seen_edges.add(pair)
        guarded = core.boolean(row["guard_declared"], "guard flag")
        if guarded:
            guarded_count += 1
        else:
            adjacency[source].add(destination)
    if not seen_edges:
        raise DesktopIpcBoundaryError("At least one edge is required")
    # Deterministic multi-source breadth-first search through only declared
    # unguarded edges. A declared guard is a model boundary, not verified code.
    paths = {entry: [entry] for entry in sorted(entries)}
    queue = deque(sorted(entries))
    while queue:
        source = queue.popleft()
        for destination in sorted(adjacency[source]):
            if destination not in paths:
                paths[destination] = [*paths[source], destination]
                queue.append(destination)
    privileged_paths = [
        {"node_id": node_id, "declared_unguarded_path": paths[node_id]}
        for node_id in sorted(nodes)
        if nodes[node_id]["privileged"] and node_id in paths
    ]
    unknown = [] if complete else ["supplied_ipc_graph_incomplete"]
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
        "supplied_node_count": len(nodes),
        "supplied_edge_count": len(seen_edges),
        "declared_guarded_edge_count": guarded_count,
        "declared_unguarded_privileged_paths": privileged_paths,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_ipc_boundary_projection",
        "source_authenticated": False,
        "application_inspected": False,
        "ipc_executed": False,
        "guard_enforcement_verified": False,
        "privilege_transition_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Nodes, edges, guards, privilege labels, and completeness are supplied assertions.",
            "Graph reachability is not proof that an IPC or privilege transition exists.",
            "A declared guard blocks only this abstract graph and is not verified enforcement.",
            "No app, process, IPC endpoint, device, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DIP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class DesktopIpcBoundaryReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DesktopIpcBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DesktopIpcBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_desktop_ipc(model: Any) -> DesktopIpcBoundaryReport:
    return DesktopIpcBoundaryReport._owned(_derive(model))


def verify_supplied_desktop_ipc(
    report: Any, *, model: Any
) -> DesktopIpcBoundaryReport:
    if type(report) is not DesktopIpcBoundaryReport:
        raise DesktopIpcBoundaryError("Exact IPC wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DesktopIpcBoundaryError("Report differs from separate original model")
    return DesktopIpcBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-desktop-ipc",
        "synthetic_fixture": True, "inventory_complete": True,
        "nodes": [
            {"node_id": "user", "kind": "untrusted_client", "privileged": False},
            {"node_id": "app", "kind": "app_process", "privileged": False},
            {"node_id": "helper", "kind": "elevated_helper", "privileged": True},
        ],
        "entry_node_ids": ["user"],
        "edges": [
            {"source_id": "user", "destination_id": "app", "guard_declared": False},
            {"source_id": "app", "destination_id": "helper", "guard_declared": False},
        ],
    }
