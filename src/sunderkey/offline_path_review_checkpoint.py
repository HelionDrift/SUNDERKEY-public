"""Check supplied abstract routes for review checkpoint coverage offline."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_attack_graph_model import analyze_supplied_attack_graph

COMPONENT_ID = "campaign_supplied_path_review_checkpoint_projection"
PROFILE_ID = "AOE-GA-D04-S09"
CAPABILITY_ID = "army.ga.d04.s09"
VECTOR_ID = "AV-GA-D04-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D04-S09"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GA-D04-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6ebdb2b97fde45937301d1118fb5b20cb5182f911bd2f732553eec30bab188c7"
DOMAIN = "sunderkey.offline-path-review-checkpoint.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_CHECKPOINTS = 32
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PathReviewCheckpointError(ValueError):
    """A supplied checkpoint model or original-model replay is invalid."""


def _route(
    entry: str,
    objective: str,
    outgoing: dict[str, list[dict]],
    *,
    include_hypothesized: bool,
    excluded: set[str],
) -> list[str] | None:
    if entry in excluded or objective in excluded:
        return None
    ready = deque([(entry, (entry,))])
    visited = {entry}
    while ready:
        node, route = ready.popleft()
        for edge in outgoing[node]:
            if edge["status"] == "blocked" or (
                edge["status"] == "hypothesized" and not include_hypothesized
            ):
                continue
            child = edge["to_id"]
            if child in excluded or child in visited:
                continue
            next_route = (*route, child)
            if child == objective:
                return list(next_route)
            visited.add(child)
            ready.append((child, next_route))
    return None


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "graph_model", "review_node_ids"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PathReviewCheckpointError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PathReviewCheckpointError("Only synthetic fixtures are accepted")
    graph_report = analyze_supplied_attack_graph(model["graph_model"]).to_dict()
    graph = graph_report["supplied_model"]
    if any(
        source["provenance_kind"] != "synthetic_fixture"
        for source in graph["evidence_sources"]
    ):
        raise PathReviewCheckpointError("Only synthetic graph sources are accepted")
    nodes = {row["node_id"]: row["kind"] for row in graph["nodes"]}
    checkpoints = [
        core.identifier(item, "review node ID")
        for item in core.bounded_list(
            model["review_node_ids"], MAX_CHECKPOINTS, "review nodes"
        )
    ]
    if not checkpoints or len(checkpoints) != len(set(checkpoints)):
        raise PathReviewCheckpointError("Distinct review nodes are required")
    if any(nodes.get(node_id) != "intermediate" for node_id in checkpoints):
        raise PathReviewCheckpointError("Review nodes must be intermediate graph nodes")
    outgoing: dict[str, list[dict]] = {node_id: [] for node_id in nodes}
    for edge in graph["edges"]:
        outgoing[edge["from_id"]].append(edge)
    for edges in outgoing.values():
        edges.sort(key=lambda row: (row["to_id"], row["edge_id"]))
    rows = []
    for entry in sorted(node_id for node_id, kind in nodes.items() if kind == "entry"):
        for objective in sorted(
            node_id for node_id, kind in nodes.items() if kind == "objective"
        ):
            supported = _route(
                entry, objective, outgoing, include_hypothesized=False, excluded=set()
            )
            possible = _route(
                entry, objective, outgoing, include_hypothesized=True, excluded=set()
            )
            unreviewed_supported = _route(
                entry, objective, outgoing,
                include_hypothesized=False, excluded=set(checkpoints),
            )
            unreviewed_possible = _route(
                entry, objective, outgoing,
                include_hypothesized=True, excluded=set(checkpoints),
            )
            if unreviewed_supported is not None:
                disposition = "supplied_supported_route_avoids_review"
            elif unreviewed_possible is not None:
                disposition = "unknown_hypothesized_route_avoids_review"
            elif supported is not None and graph["graph_complete"]:
                disposition = "review_on_all_supplied_supported_routes"
            elif possible is not None or not graph["graph_complete"]:
                disposition = "unknown"
            else:
                disposition = "no_supplied_route"
            rows.append({
                "entry_id": entry,
                "objective_id": objective,
                "supported_route_declared": supported is not None,
                "hypothesized_route_declared": possible is not None and supported is None,
                "unreviewed_supported_route_declared": unreviewed_supported is not None,
                "unreviewed_hypothesized_route_declared": (
                    unreviewed_possible is not None and unreviewed_supported is None
                ),
                "disposition": disposition,
            })
    uncertainty = []
    if not graph["graph_complete"]:
        uncertainty.append("supplied_graph_incomplete")
    if any(row["unreviewed_hypothesized_route_declared"] for row in rows):
        uncertainty.append("hypothesized_unreviewed_route")
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
        "base_graph_report_id": graph_report["report_id"],
        "base_graph_report_sha256": graph_report["report_sha256"],
        "synthetic_fixture_asserted": True,
        "graph_complete_asserted": graph["graph_complete"],
        "review_node_ids": sorted(checkpoints),
        "pair_checkpoint_projections": rows,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "source_authenticated": False,
        "review_authority_verified": False,
        "route_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Graph topology, edge statuses, and checkpoints are synthetic assertions.",
            "A review checkpoint in an abstract graph is not real authorization.",
            "Reachability does not establish target behavior or exploitability.",
            "No target is resolved and no network, process or credential action occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PRC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PathReviewCheckpointReport:
    """Unsigned checkpoint projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PathReviewCheckpointError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PathReviewCheckpointReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_path_review(model: Any) -> PathReviewCheckpointReport:
    return PathReviewCheckpointReport._owned(_derive(model))


def verify_supplied_path_review(
    report: Any, *, model: Any
) -> PathReviewCheckpointReport:
    if type(report) is not PathReviewCheckpointReport:
        raise PathReviewCheckpointError("Exact checkpoint wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PathReviewCheckpointError("Report differs from separate original model")
    return PathReviewCheckpointReport._owned(expected)


def component_fixture() -> dict:
    from .offline_attack_graph_model import component_fixture as graph_fixture

    return {
        "schema_version": 1,
        "source_id": "synthetic-path-review",
        "synthetic_fixture": True,
        "graph_model": graph_fixture(),
        "review_node_ids": ["boundary-b"],
    }
