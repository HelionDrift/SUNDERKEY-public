"""Review asserted synthetic scenario reachability without target interaction."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from datetime import datetime
from typing import Any

from .synthetic_scenario_planning import (
    ScenarioDisposition,
    SyntheticScenarioConsent,
    SyntheticScenarioError,
    SyntheticScenarioRequest,
    plan_synthetic_scenarios,
)
from .traffic_derived_api_inventory import _timestamp

DOMAIN = "sunderkey.synthetic-blast-radius-review.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
RESOURCE_RE = re.compile(r"synthetic-resource:sha256:[0-9a-f]{64}\Z")
MAX_NODES = 64
MAX_EDGES = 256
MAX_BYTES = 1_000_000
NODE_KINDS = frozenset({"principal", "service", "data_canary", "recovery_canary"})
IMPACT_CLASSES = frozenset({
    "none", "synthetic_service_access", "synthetic_data_canary_reach",
    "synthetic_recovery_canary_reach",
})
BOUNDARY_KINDS = frozenset({
    "same_scope", "privilege_change", "data_access", "network_segment",
})
RESULTS = frozenset({"declared_passed", "declared_blocked", "unknown"})
EFFECTS = {
    "authority": "none",
    "credential_collection": "none",
    "delivery": "none",
    "execution": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class SyntheticBlastRadiusReviewError(ValueError):
    """Synthetic reachability evidence or its replayed report is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise SyntheticBlastRadiusReviewError("evidence is not JSON") from exc
    if len(encoded) > MAX_BYTES:
        raise SyntheticBlastRadiusReviewError("evidence exceeds byte bound")
    return encoded


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(
        type(key) is not str for key in value
    ):
        raise SyntheticBlastRadiusReviewError(f"{label} fields are invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise SyntheticBlastRadiusReviewError(f"{label} is not a SHA-256 reference")
    return value


def _time(value: Any, label: str) -> datetime:
    if type(value) is not str:
        raise SyntheticBlastRadiusReviewError(f"{label} is invalid")
    try:
        return _timestamp(value, label)
    except ValueError as exc:
        raise SyntheticBlastRadiusReviewError(f"{label} is invalid") from exc


def _graph(
    value: Any, request: SyntheticScenarioRequest, planned_at: datetime,
    review_at: datetime,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    graph = _exact(value, {
        "schema_version", "seed_ref", "nodes", "edges", "source_sha256",
    }, "graph")
    if type(graph["schema_version"]) is not int or graph["schema_version"] != 1:
        raise SyntheticBlastRadiusReviewError("graph version is invalid")
    if graph["seed_ref"] != request.synthetic_principal_ref:
        raise SyntheticBlastRadiusReviewError("graph seed differs from request")
    _digest(graph["source_sha256"], "graph source")
    nodes = graph["nodes"]
    edges = graph["edges"]
    if type(nodes) is not list or not 1 <= len(nodes) <= MAX_NODES:
        raise SyntheticBlastRadiusReviewError("nodes exceed bound or are missing")
    if type(edges) is not list or len(edges) > MAX_EDGES:
        raise SyntheticBlastRadiusReviewError("edges exceed bound")
    by_ref: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        node = _exact(node, {
            "node_ref", "kind", "impact_class", "evidence_sha256",
        }, f"node {index}")
        ref = node["node_ref"]
        if ref == request.synthetic_principal_ref:
            if node["kind"] != "principal" or node["impact_class"] != "none":
                raise SyntheticBlastRadiusReviewError("seed must be a neutral principal")
        elif type(ref) is not str or RESOURCE_RE.fullmatch(ref) is None:
            raise SyntheticBlastRadiusReviewError("node is not an opaque synthetic resource")
        if (
            type(node["kind"]) is not str or node["kind"] not in NODE_KINDS
            or type(node["impact_class"]) is not str
            or node["impact_class"] not in IMPACT_CLASSES
        ):
            raise SyntheticBlastRadiusReviewError("node classification is invalid")
        if node["kind"] == "principal" and node["impact_class"] != "none":
            raise SyntheticBlastRadiusReviewError("principal cannot assert impact")
        if node["kind"] == "data_canary" and node["impact_class"] not in {
            "none", "synthetic_data_canary_reach",
        }:
            raise SyntheticBlastRadiusReviewError("data canary impact is inconsistent")
        if node["kind"] == "recovery_canary" and node["impact_class"] not in {
            "none", "synthetic_recovery_canary_reach",
        }:
            raise SyntheticBlastRadiusReviewError("recovery canary impact is inconsistent")
        if node["kind"] == "service" and node["impact_class"] not in {
            "none", "synthetic_service_access",
        }:
            raise SyntheticBlastRadiusReviewError("service impact is inconsistent")
        _digest(node["evidence_sha256"], "node evidence")
        if ref in by_ref:
            raise SyntheticBlastRadiusReviewError("node references must be unique")
        by_ref[ref] = node
    if list(by_ref) != sorted(by_ref) or request.synthetic_principal_ref not in by_ref:
        raise SyntheticBlastRadiusReviewError("nodes must be canonical and include seed")
    seen_edges: set[tuple[str, str]] = set()
    previous_pair: tuple[str, str] | None = None
    starts = _time(request.window_start, "window_start")
    ends = _time(request.window_end, "window_end")
    for index, edge in enumerate(edges):
        edge = _exact(edge, {
            "from_ref", "to_ref", "boundary_kind", "boundary_sha256",
            "declared_result", "occurred_at", "evidence_sha256",
        }, f"edge {index}")
        pair = (edge["from_ref"], edge["to_ref"])
        if type(pair[0]) is not str or type(pair[1]) is not str:
            raise SyntheticBlastRadiusReviewError("edge references invalid nodes")
        if pair[0] not in by_ref or pair[1] not in by_ref or pair[0] == pair[1]:
            raise SyntheticBlastRadiusReviewError("edge references invalid nodes")
        if pair in seen_edges or (previous_pair is not None and pair <= previous_pair):
            raise SyntheticBlastRadiusReviewError("edges must be unique and canonical")
        seen_edges.add(pair)
        previous_pair = pair
        if (
            type(edge["boundary_kind"]) is not str
            or edge["boundary_kind"] not in BOUNDARY_KINDS
            or type(edge["declared_result"]) is not str
            or edge["declared_result"] not in RESULTS
        ):
            raise SyntheticBlastRadiusReviewError("edge boundary result is invalid")
        _digest(edge["boundary_sha256"], "boundary evidence")
        _digest(edge["evidence_sha256"], "edge evidence")
        at = _time(edge["occurred_at"], "edge time")
        if not starts <= at < ends or at < planned_at or at > review_at:
            raise SyntheticBlastRadiusReviewError("edge is outside consented window")
    _canonical(graph)
    return graph, by_ref, edges


def _closure(
    value: Any, edges: list[dict[str, Any]], earliest_at: datetime,
    review_at: datetime,
) -> dict[str, Any]:
    closure = _exact(value, {
        "cleanup_status", "cleanup_at", "cleanup_evidence_sha256",
        "disclosure_status", "disclosure_at", "disclosure_evidence_sha256",
        "custody_sha256",
    }, "closure")
    _digest(closure["custody_sha256"], "custody source")
    latest_edge = max(
        (_time(edge["occurred_at"], "edge time") for edge in edges),
        default=None,
    )
    for name in ("cleanup", "disclosure"):
        status = closure[f"{name}_status"]
        at = closure[f"{name}_at"]
        evidence = closure[f"{name}_evidence_sha256"]
        if status == "pending":
            if at is not None or evidence is not None:
                raise SyntheticBlastRadiusReviewError(f"pending {name} has a receipt")
        elif status == "declared_complete":
            _digest(evidence, f"{name} evidence")
            timestamp = _time(at, f"{name} time")
            if timestamp < earliest_at or timestamp > review_at or (
                latest_edge is not None and timestamp < latest_edge
            ):
                raise SyntheticBlastRadiusReviewError(f"{name} timing is invalid")
        else:
            raise SyntheticBlastRadiusReviewError(f"{name} status is invalid")
    _canonical(closure)
    return closure


def _declared_paths(
    seed: str, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    adjacency: dict[str, list[dict[str, Any]]] = {ref: [] for ref in nodes}
    for edge in edges:
        if edge["declared_result"] == "declared_passed":
            adjacency[edge["from_ref"]].append(edge)
    paths: dict[str, tuple[str, ...]] = {seed: (seed,)}
    path_evidence: dict[str, tuple[str, ...]] = {seed: ()}
    queue: deque[str] = deque([seed])
    while queue:
        source = queue.popleft()
        for edge in adjacency[source]:
            target = edge["to_ref"]
            if target in paths:
                continue
            paths[target] = (*paths[source], target)
            path_evidence[target] = (
                *path_evidence[source], edge["evidence_sha256"],
            )
            queue.append(target)
    impacts = [
        {
            "node_ref": ref,
            "impact_class": nodes[ref]["impact_class"],
            "declared_path": list(paths[ref]),
            "path_evidence_sha256": list(path_evidence[ref]),
        }
        for ref in sorted(paths)
        if nodes[ref]["impact_class"] != "none"
    ]
    return impacts, len(paths)


def build_synthetic_blast_radius_review(
    request: SyntheticScenarioRequest,
    consent: SyntheticScenarioConsent,
    *,
    planned_at: str,
    review_at: str,
    graph: Any,
    closure: Any,
) -> dict[str, Any]:
    """Review only asserted synthetic evidence under an exact consent candidate."""

    if not isinstance(request, SyntheticScenarioRequest) or not isinstance(
        consent, SyntheticScenarioConsent,
    ):
        raise SyntheticBlastRadiusReviewError("request and consent must be typed")
    try:
        plan = plan_synthetic_scenarios(
            tenant_id=request.tenant_id,
            scope_sha256=request.scope_sha256,
            planned_at=planned_at,
            requests=(request,),
            consents=(consent,),
        )
    except SyntheticScenarioError as exc:
        raise SyntheticBlastRadiusReviewError("scenario plan is invalid") from exc
    if plan.items[0].disposition != ScenarioDisposition.REVIEW_CANDIDATE:
        raise SyntheticBlastRadiusReviewError("scenario has no current consent candidate")
    reviewed = _time(review_at, "review_at")
    planned = _time(planned_at, "planned_at")
    if reviewed < planned:
        raise SyntheticBlastRadiusReviewError("review precedes consent screening")
    checked_graph, nodes, edges = _graph(graph, request, planned, reviewed)
    checked_closure = _closure(closure, edges, planned, reviewed)
    impacts, reachable = _declared_paths(request.synthetic_principal_ref, nodes, edges)
    body = {
        "schema_version": 1,
        "scenario_id": request.scenario_id,
        "scenario_kind": request.kind.value,
        "tenant_id": request.tenant_id,
        "scope_sha256": request.scope_sha256,
        "request_sha256": request.request_sha256,
        "consent_sha256": consent.consent_sha256,
        "plan_sha256": plan.plan_sha256,
        "graph_sha256": _sha(checked_graph),
        "closure_sha256": _sha(checked_closure),
        "review_at": review_at,
        "declared_reachable_node_count": reachable,
        "declared_impact_paths": impacts,
        "declared_blocked_edge_count": sum(
            edge["declared_result"] == "declared_blocked" for edge in edges
        ),
        "unknown_edge_count": sum(
            edge["declared_result"] == "unknown" for edge in edges
        ),
        "cleanup_due": checked_closure["cleanup_status"] != "declared_complete",
        "disclosure_due": checked_closure["disclosure_status"] != "declared_complete",
        "consent_authenticated": False,
        "path_outcomes_verified": False,
        "cleanup_verified": False,
        "disclosure_verified": False,
        "custody_verified": False,
        "source_provenance": "caller_asserted_not_authenticated",
        "review_status": "independent_review_required",
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        **body,
        "review_id": "SBR-" + digest[:32].upper(),
        "review_sha256": "sha256:" + digest,
    }


def verify_synthetic_blast_radius_review(
    request: SyntheticScenarioRequest,
    consent: SyntheticScenarioConsent,
    *,
    planned_at: str,
    review_at: str,
    graph: Any,
    closure: Any,
    result: Any,
) -> dict[str, str]:
    """Reproduce the review from supplied sources, without authenticating them."""

    expected = build_synthetic_blast_radius_review(
        request, consent, planned_at=planned_at, review_at=review_at,
        graph=graph, closure=closure,
    )
    if type(result) is not dict or _canonical(result) != _canonical(expected):
        raise SyntheticBlastRadiusReviewError("blast radius review does not reproduce")
    return {
        "status": "valid",
        "review_id": expected["review_id"],
        "review_sha256": expected["review_sha256"],
        "qualification_effect": "none",
    }
