"""Project supplied graph-data tenant routes without connecting to a database."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_graph_tenant_routes"
PROFILE_ID = "AOE-GB-D07-S03"
CAPABILITY_ID = "army.gb.d07.s03"
VECTOR_ID = "AV-GB-D07-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:e13875391e2817e33d2eb05acf476303596e082d905172914e5b15f9112b48ae"
SEMANTICS_PROFILE = "supplied-graph-tenant-routes-v1"
DOMAIN = "sunderkey.offline-graph-tenant-routes.v1"
MAX_NODES = 128
MAX_EDGES = 512
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_NODE = re.compile(r"node:sha256:[0-9a-f]{64}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_TRAVERSAL = frozenset(("declared_open", "declared_blocked", "unknown"))
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "database",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "query",
        "target",
    ),
    "none",
)


class GraphTenantRouteError(ValueError):
    """A supplied graph model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise GraphTenantRouteError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise GraphTenantRouteError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise GraphTenantRouteError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise GraphTenantRouteError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise GraphTenantRouteError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise GraphTenantRouteError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise GraphTenantRouteError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise GraphTenantRouteError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise GraphTenantRouteError(f"{label} must be an opaque digest reference")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "tenant_ref",
            "start_node_ref",
            "graph_complete",
            "nodes",
            "edges",
            "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GraphTenantRouteError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise GraphTenantRouteError("Semantics profile is invalid")
    tenant = _ref(model["tenant_ref"], _TENANT, "Principal tenant")
    start = _ref(model["start_node_ref"], _NODE, "Start node")
    if type(model["graph_complete"]) is not bool:
        raise GraphTenantRouteError("Graph completeness must be an exact boolean")
    nodes = model["nodes"]
    edges = model["edges"]
    objectives = model["objectives"]
    if type(nodes) is not list or not 1 <= len(nodes) <= MAX_NODES:
        raise GraphTenantRouteError("Node count is invalid")
    if type(edges) is not list or len(edges) > MAX_EDGES:
        raise GraphTenantRouteError("Edge count is invalid")
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise GraphTenantRouteError("Objective count is invalid")
    known: dict[str, str] = {}
    for row in nodes:
        _fields(row, {"node_ref", "tenant_ref"}, "node")
        node_ref = _ref(row["node_ref"], _NODE, "Node")
        if node_ref in known:
            raise GraphTenantRouteError("Duplicate node reference")
        node_tenant = row["tenant_ref"]
        if node_tenant != "shared":
            _ref(node_tenant, _TENANT, "Node tenant")
        known[node_ref] = node_tenant
    if known.get(start) != tenant:
        raise GraphTenantRouteError("Start node must be declared in the principal tenant")
    edge_ids: set[str] = set()
    for row in edges:
        _fields(row, {"edge_id", "from_node_ref", "to_node_ref", "traversal"}, "edge")
        edge_id = row["edge_id"]
        if type(edge_id) is not str or _ID.fullmatch(edge_id) is None:
            raise GraphTenantRouteError("Edge identifier is invalid")
        if edge_id in edge_ids:
            raise GraphTenantRouteError("Duplicate edge identifier")
        edge_ids.add(edge_id)
        for key in ("from_node_ref", "to_node_ref"):
            if _ref(row[key], _NODE, "Edge node") not in known:
                raise GraphTenantRouteError("Edge node is undeclared")
        if type(row["traversal"]) is not str or row["traversal"] not in _TRAVERSAL:
            raise GraphTenantRouteError("Edge traversal is invalid")
    seen_objectives: set[str] = set()
    for row in objectives:
        _fields(row, {"target_node_ref"}, "objective")
        target = _ref(row["target_node_ref"], _NODE, "Objective node")
        if target not in known or target in seen_objectives:
            raise GraphTenantRouteError("Objective node is undeclared or duplicated")
        seen_objectives.add(target)
    return model


def _paths(plan: dict, *, include_unknown: bool) -> dict[str, tuple[str, ...]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for row in plan["edges"]:
        if row["traversal"] == "declared_open" or (
            include_unknown and row["traversal"] == "unknown"
        ):
            adjacency.setdefault(row["from_node_ref"], []).append(
                (row["edge_id"], row["to_node_ref"])
            )
    paths = {plan["start_node_ref"]: ()}
    queue = deque([plan["start_node_ref"]])
    while queue:
        node = queue.popleft()
        for edge_id, target in sorted(adjacency.get(node, [])):
            if target not in paths:
                paths[target] = (*paths[node], edge_id)
                queue.append(target)
    return paths


def _derive(model: Any) -> dict:
    plan = _plan(model)
    known = {row["node_ref"]: row["tenant_ref"] for row in plan["nodes"]}
    open_paths = _paths(plan, include_unknown=False)
    possible_paths = _paths(plan, include_unknown=True)
    unknown_edges = {
        row["edge_id"] for row in plan["edges"] if row["traversal"] == "unknown"
    }
    findings = []
    for row in plan["objectives"]:
        target = row["target_node_ref"]
        if target in open_paths:
            path = open_paths[target]
            target_tenant = known[target]
            if target_tenant == "shared":
                disposition = "declared_shared_route"
            elif target_tenant == plan["tenant_ref"]:
                disposition = "declared_same_tenant_route"
            else:
                disposition = "declared_cross_tenant_route"
        elif target in possible_paths:
            path = possible_paths[target]
            disposition = "unknown_traversal"
        else:
            path = ()
            disposition = (
                "no_supplied_route" if plan["graph_complete"] else "unknown_incomplete_graph"
            )
        findings.append(
            {
                "target_node_ref": target,
                "target_tenant_ref": known[target],
                "disposition": disposition,
                "edge_ids": list(path),
                "unknown_edge_ids": [edge for edge in path if edge in unknown_edges],
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "database_state_verified": False,
            "traversal_policy_verified": False,
            "tenant_identity_verified": False,
            "cross_tenant_exposure_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Nodes, tenancy, edge direction, visibility, and completeness are caller-supplied.",
            "Only explicit directed edges and three abstract traversal labels are projected.",
            "A declared route does not prove graph-query access or document exposure.",
            "No graph database, query client, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "GTR-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class GraphTenantRoutes:
    """Immutable report replayed from a supplied graph model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise GraphTenantRouteError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise GraphTenantRouteError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_graph_tenant_routes(model: Any) -> GraphTenantRoutes:
    """Project declared graph tenancy routes without target interaction."""
    return GraphTenantRoutes(_derive(model))


def verify_supplied_graph_tenant_routes(
    report: Any, *, model: Any
) -> GraphTenantRoutes:
    if type(report) is not GraphTenantRoutes:
        raise GraphTenantRouteError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise GraphTenantRouteError("Report differs from supplied model replay")
    return GraphTenantRoutes(expected)
